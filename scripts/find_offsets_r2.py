#!/usr/bin/env python3
# find_offsets_r3.py — iOS/arm64 fixed
import os, sys, time, struct, re, bisect, traceback
import r2pipe

WS  = os.environ.get("GITHUB_WORKSPACE", "/tmp")
BIN = os.environ.get("R2_BIN", "/tmp/brawl_bin")
OUT    = os.path.join(WS, "offsets_resolved.js")
VT     = os.path.join(WS, "vtables.js")
REPORT = os.path.join(WS, "offsets_report.txt")
DETAIL = os.path.join(WS, "ctors_detailed.log")
START  = time.time()

TARGETS = [
    # ... (список тот же, что у тебя — не трогаю)
]

CLASSES = sorted(set(t.split(".")[0] for t in TARGETS))
SINGLETON_NAMES = ("getInstance", "instance", "sharedInstance", "getInstanceCtor")

_log_fh = None
def log(m):
    line = "[%7.2f] %s" % (time.time() - START, m)
    try: sys.stdout.write(line + "\n"); sys.stdout.flush()
    except Exception: pass
    if _log_fh:
        try: _log_fh.write(line + "\n"); _log_fh.flush()
        except Exception: pass

def cmdj(r2, c):
    try: return r2.cmdj(c)
    except Exception: return None
def cmd(r2, c):
    try: return r2.cmd(c)
    except Exception: return ""

def addr_of(s, base):
    va = s.get("vaddr", 0); pa = s.get("paddr", 0)
    if va and va >= base: return va
    if pa and pa >= base: return pa
    if pa and pa > 0:     return pa + base
    return 0

def build_string_index(r2, base):
    idx = {}
    for s in (cmdj(r2, "izj") or []):
        txt = (s.get("string") or s.get("text") or "").strip()
        if not txt: continue
        a = addr_of(s, base)
        if a: idx.setdefault(txt, []).append(a)
    return idx

def get_sections(r2): return cmdj(r2, "iSj") or []

def pick_sections(sections):
    text = None; data = []
    for s in sections:
        n = s.get("name","") or ""; p = s.get("perm","") or ""
        va = s.get("vaddr",0); sz = s.get("size",0)
        if sz <= 0 or va <= 0: continue
        if ("__text" in n or ".text" in n) and "x" in p:
            text = (va, va+sz)
        elif "x" not in p and ("w" in p or "r" in p):
            if ("const" in n or "data" in n or "got" in n):
                data.append((va, sz, n))
    return text, data

def load_range(r2, va, size):
    CH = 0x400000; chunks = []; a = va; end = va+size
    while a < end:
        n = min(CH, end-a)
        hx = cmd(r2, "p8 %d @ 0x%x" % (n, a)).strip()
        if not hx: return None
        try: chunks.append(bytes.fromhex(hx))
        except Exception: return None
        a += n
    return b"".join(chunks)

# ---- ARM64 decode ----
def is_adrp(w):            return (w & 0x9F000000) == 0x90000000
def is_add_imm64(w):       return (w & 0xFF800000) == 0x91000000
def is_bl(w):              return (w & 0xFC000000) == 0x94000000
def is_str_x(w):           return (w & 0xFFC00000) == 0xF9000000
def is_stp_x29_x30_pre(w): return (w & 0xFFC07FFF) == 0xA9807BFD
def is_pacibsp(w):         return w == 0xD503237F
def is_paciasp(w):         return w == 0xD503233F
def is_bti_c(w):           return w == 0xD503245F
def is_sub_sp(w):          return (w & 0xFF8003FF) == 0xD10003FF

def is_prolog(w):
    # iOS-совместимый набор
    return (is_stp_x29_x30_pre(w) or is_pacibsp(w) or is_paciasp(w)
            or is_bti_c(w) or is_sub_sp(w))

def decode_adrp_imm(w, pc):
    immlo = (w >> 29) & 0x3; immhi = (w >> 5) & 0x7FFFF
    imm = (immhi << 2) | immlo
    if imm & (1 << 20): imm -= (1 << 21)
    return (pc & ~0xFFF) + (imm << 12)

def decode_add_imm(w):
    rd = w & 0x1F; rn = (w >> 5) & 0x1F
    imm12 = (w >> 10) & 0xFFF; sh = (w >> 22) & 1
    if sh: imm12 <<= 12
    return rd, rn, imm12

def decode_bl_target(w, pc):
    off = w & 0x3FFFFFF
    if off & (1 << 25): off -= (1 << 26)
    return pc + (off << 2)

def decode_chained(v):
    bind = (v >> 63) & 1
    return bind, (v & 0x7FFFFFFFFFF)

def scan_text(text, ts):
    n = len(text)//4
    adrp_add = []; prologs = []; bl_map = {}; str_locs = []
    for i in range(n):
        w = struct.unpack_from("<I", text, i*4)[0]
        pc = ts + i*4
        if is_prolog(w): prologs.append(pc)
        if is_adrp(w):
            rd_adrp = w & 0x1F
            page = decode_adrp_imm(w, pc)
            for j in range(i+1, min(i+6, n)):
                w2 = struct.unpack_from("<I", text, j*4)[0]
                if is_add_imm64(w2):
                    rd, rn, imm = decode_add_imm(w2)
                    if rd == rd_adrp and rn == rd_adrp:
                        adrp_add.append((pc, page + imm)); break
        if is_bl(w):
            bl_map[pc] = decode_bl_target(w, pc)
        if is_str_x(w):
            rt = w & 0x1F; rn = (w >> 5) & 0x1F; imm12 = (w >> 10) & 0xFFF
            str_locs.append((pc, rt, rn, imm12*8))
    return adrp_add, prologs, bl_map, str_locs

def build_ptr_index(data_blobs, ts, te):
    idx = {}
    for va, b in data_blobs:
        for i in range(len(b)//8):
            raw = struct.unpack_from("<Q", b, i*8)[0]
            bind, tgt = decode_chained(raw)
            if bind: continue
            if ts <= tgt < te:
                idx.setdefault(tgt, []).append(va + i*8)
    return idx

def build_slot_to_target(ptr_idx):
    out = {}
    for tgt, slots in ptr_idx.items():
        for s in slots: out[s] = tgt
    return out

def expand_vtable(slot_to_target, anchor_slot, max_back=64, max_fwd=2048):
    vt_start = anchor_slot
    cur = anchor_slot - 8
    for _ in range(max_back):
        if cur in slot_to_target: vt_start = cur; cur -= 8
        else: break
    slots = []; cur = vt_start
    for _ in range(max_fwd):
        if cur in slot_to_target:
            slots.append((cur, slot_to_target[cur])); cur += 8
        else: break
    return (vt_start, slots) if len(slots) >= 2 else None

# ---------- ИТАНИ-деманглер для _ZN... ----------
def demangle_itanium(s):
    if not s.startswith("_ZN"): return None
    rest = s[3:]; parts = []
    while rest and rest[0].isdigit():
        i = 0
        while i < len(rest) and rest[i].isdigit(): i += 1
        ln = int(rest[:i]); rest = rest[i:]
        if len(rest) < ln: return None
        parts.append(rest[:ln]); rest = rest[ln:]
    if len(parts) >= 2: return parts[-2], parts[-1]
    if len(parts) == 1: return parts[0], None
    return None

# ============================================================
def main():
    global _log_fh
    try: _log_fh = open(DETAIL, "w")
    except Exception: _log_fh = None

    log("=== find_offsets_r3 (iOS) ===")
    r2 = r2pipe.open(BIN, flags=["-2"])
    r2.cmd("e scr.color=0"); r2.cmd("e asm.arch=arm"); r2.cmd("e asm.bits=64")

    # ВАЖНО: базовый анализ функций. На 14 МБ текста ~30-90с, влезает в бюджет.
    t0 = time.time()
    log("[*] running aa ..."); r2.cmd("aa")
    log("[*] aa done %.1fs" % (time.time()-t0))

    info = cmdj(r2, "ij") or {}
    base = info.get("baddr", 0x100000000) or 0x100000000
    log("base: 0x%x" % base)

    str_index = build_string_index(r2, base)
    log("[*] strings: %d unique" % len(str_index))

    sections = get_sections(r2)
    text_b, data_secs = pick_sections(sections)
    if not text_b: return
    ts, te = text_b
    log("[*] .text: 0x%x - 0x%x" % (ts, te))

    text = load_range(r2, ts, te-ts)
    log("[*] .text %d bytes" % len(text or b""))
    if not text: return

    data_blobs = []
    for va, sz, n in data_secs:
        b = load_range(r2, va, sz)
        if b: data_blobs.append((va, b))
    log("[*] data %d bytes" % sum(len(b) for _, b in data_blobs))

    ptr_idx      = build_ptr_index(data_blobs, ts, te)
    slot_to_tgt  = build_slot_to_target(ptr_idx)
    log("[*] ptr idx: %d targets, %d slots"
        % (len(ptr_idx), sum(len(v) for v in ptr_idx.values())))

    adrp_add, prologs, bl_map, _ = scan_text(text, ts)
    prologs_sorted = sorted(prologs)
    log("[*] adrp_add=%d prologs=%d bl=%d"
        % (len(adrp_add), len(prologs), len(bl_map)))

    # ---- объединяем прологи и aflj для надёжного поиска границ функций ----
    func_addrs_set = set(prologs_sorted)
    for f in (cmdj(r2, "aflj") or []):
        a = f.get("offset") or f.get("addr") or 0
        if a: func_addrs_set.add(a)
    func_addrs = sorted(func_addrs_set)
    def find_func_start(ia):
        idx = bisect.bisect_right(func_addrs, ia) - 1
        return func_addrs[idx] if idx >= 0 else (ia & ~0xF)

    # ---- адреса строк → PC adrp ----
    str_addr_to_pc = {}
    for pc, tgt in adrp_add:
        str_addr_to_pc.setdefault(tgt, []).append(pc)

    # ============================================================
    # 1) Class::method из строк (с учётом ВСЕХ xref и выбора лучшего)
    # ============================================================
    class_method_funcs = {}
    for s, addrs in str_index.items():
        idx = s.find("::")
        if idx <= 0: continue
        cls = s[:idx]
        if not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", cls): continue
        rest = s[idx+2:]
        m = re.match(r"([A-Za-z_][A-Za-z0-9_]*)", rest)
        if not m: continue
        method = m.group(1)
        key = cls + "::" + method
        if key in class_method_funcs: continue
        best = None
        for sa in addrs:
            pcs = sorted(str_addr_to_pc.get(sa, []))
            for pc in pcs[:4]:
                f = find_func_start(pc)
                # предпочитаем функцию, у которой строка в первых ~60 инструкциях
                if f and (pc - f) < 0x400:
                    best = f; break
                if best is None: best = f
            if best is not None and (pc - best) < 0x400: break
        if best is not None:
            class_method_funcs[key] = best

    # ---- плюс C++ манга (иногда есть в __gcc_except_tab на iOS) ----
    for s, addrs in str_index.items():
        dm = demangle_itanium(s)
        if not dm: continue
        cls, method = dm
        if not method or cls is None: continue
        key = cls + "::" + method
        if key in class_method_funcs: continue
        for sa in addrs:
            for pc in str_addr_to_pc.get(sa, [])[:3]:
                f = find_func_start(pc)
                if f is not None:
                    class_method_funcs[key] = f; break
            if key in class_method_funcs: break
    log("[*] Class::method funcs: %d" % len(class_method_funcs))

    # ============================================================
    # 2) Плоские имена методов (без "::") — для fallback по vtable
    # ============================================================
    method_name_xrefs = {}
    for s, addrs in str_index.items():
        if "::" in s: continue
        if not re.match(r"^[a-zA-Z_][a-zA-Z0-9_]{2,48}$", s): continue
        if s in ("null", "true", "false", "None"): continue
        for sa in addrs:
            for pc in str_addr_to_pc.get(sa, []):
                f = find_func_start(pc)
                method_name_xrefs.setdefault(s, set()).add(f)
    log("[*] plain method-name strings: %d" % len(method_name_xrefs))

    # ============================================================
    # 3) vtable по классам (через якорные функции)
    # ============================================================
    class_to_vtable = {}
    all_vt_starts   = set()
    for cls in CLASSES:
        anchor_funcs = set()
        for key, f in class_method_funcs.items():
            if key.startswith(cls + "::"): anchor_funcs.add(f)
        for s, al in str_index.items():
            if s == cls or s.startswith(cls + "::"):
                for sa in al:
                    for pc in str_addr_to_pc.get(sa, []):
                        anchor_funcs.add(find_func_start(pc))
        if not anchor_funcs: continue
        best = None
        for af in anchor_funcs:
            for slot in ptr_idx.get(af, [])[:6]:
                vt = expand_vtable(slot_to_tgt, slot)
                if vt and (best is None or len(vt[1]) > len(best[1])):
                    best = vt
        if best:
            class_to_vtable[cls] = best
            all_vt_starts.add(best[0])
    log("[*] class→vtable (via anchors): %d" % len(class_to_vtable))

    # ============================================================
    # 4) РАСПРОСТРАНЕНИЕ ПО VTABLE
    #    Если func известен как A::m, а он же лежит в vtable класса B —
    #    значит B унаследовал A::m (или это тот же базовый) → B::m = func.
    # ============================================================
    func_to_names = {}
    for key, f in class_method_funcs.items():
        cls, method = key.split("::", 1)
        func_to_names.setdefault(f, []).append((cls, method))

    propagated = 0
    # несколько проходов, чтобы дошло по цепочке наследования
    for _ in range(3):
        added = 0
        for cls, (vt_start, slots) in class_to_vtable.items():
            for slot_addr, func in slots:
                for other_cls, method in func_to_names.get(func, ()):
                    key = cls + "::" + method
                    if key not in class_method_funcs:
                        class_method_funcs[key] = func
                        func_to_names.setdefault(func, []).append((cls, method))
                        added += 1
        propagated += added
        if added == 0: break
    log("[*] propagated class::methods via vtable: +%d" % propagated)

    # ============================================================
    # 5) ctor через xref на vtable и через operator_new
    # ============================================================
    vt_to_ctors = {}
    for pc, tgt in adrp_add:
        if tgt in all_vt_starts:
            vt_to_ctors.setdefault(tgt, set()).add(find_func_start(pc))
    log("[*] vtables with ctor xref: %d" % len(vt_to_ctors))

    # ============================================================
    # 6) Разрешение таргетов
    # ============================================================
    results = {}
    unresolved = []

    for t in TARGETS:
        if "." not in t:
            unresolved.append((t, "no_dot")); continue
        cls, method = t.split(".", 1)

        # --- ctor ---
        if method == "ctor":
            # 1. по строкам Class::Class / Class::ctor / Class::__ctor
            hit = None
            for k in (cls+"::"+cls, cls+"::ctor", cls+"::__ctor",
                      cls+"::constructor", cls+"::new"):
                if k in class_method_funcs:
                    hit = class_method_funcs[k]; break
            if hit is not None:
                results[t] = hit - base; continue
            # 2. через vtable: любой ctor-кандидат, найденный по adrp на vtable
            vt = class_to_vtable.get(cls)
            if vt:
                for c in vt_to_ctors.get(vt[0], set()):
                    # проверим что функция выглядит как ctor: много bl + str x0 где-то
                    off = (c - ts)//4
                    n = len(text)//4
                    has_str = False; has_bl = 0
                    for i in range(off, min(off+200, n)):
                        w = struct.unpack_from("<I", text, i*4)[0]
                        if is_bl(w): has_bl += 1
                        if is_str_x(w) and (w & 0x1F) == 0:  # str x0
                            has_str = True
                        if w == 0xD65F03C0 and i > off+5: break
                    if has_str or has_bl >= 3:
                        results[t] = c - base; break
            if t in results: continue
            unresolved.append((t, "no_ctor")); continue

        # --- singleton ---
        if method in SINGLETON_NAMES:
            hit = None
            for cand in (cls+"::"+method, cls+"::getInstance", cls+"::instance",
                         cls+"::sharedInstance", cls+"::getInstanceCtor"):
                if cand in class_method_funcs:
                    hit = class_method_funcs[cand]; break
            if hit is not None:
                results[t] = hit - base; continue
            # fallback: обычная строка "getInstance"/"instance", xref +
            # пересечение с vtable этого класса НЕ подходит (статика),
            # но пересечение с xref на строку ИМЕНИ класса хотя бы даёт
            # функцию-инициализатор класса — не берём.
            unresolved.append((t, "no_singleton")); continue

        # --- обычный метод ---
        # (a) прямой Class::method
        hit = class_method_funcs.get(cls + "::" + method)
        if hit is not None:
            results[t] = hit - base; continue

        # (b) регистронезависимо/по префиксу
        found = None
        for k, f in class_method_funcs.items():
            if k.startswith(cls + "::") and \
               k[len(cls)+2:].lower() == method.lower():
                found = f; break
        if found is None:
            for k, f in class_method_funcs.items():
                if k.startswith(cls + "::" + method):
                    found = f; break
        if found is not None:
            results[t] = found - base; continue

        # (c) fallback: xref плоской строки "method" ∩ vtable класса
        vt = class_to_vtable.get(cls)
        if vt:
            vt_funcs = set(f for _, f in vt[1])
            cands = method_name_xrefs.get(method, set()) & vt_funcs
            if cands:
                results[t] = next(iter(cands)) - base; continue
            # (d) vtable slot-индексы, унаследованные от известных баз:
            #     если в class_method_funcs есть OtherClass::method, и его слот
            #     совпадает по индексу в нашей vtable — берём этот слот.
            #     Ищем "другую" class::method с тем же именем и одинаковой
            #     позицией слота.
            for k, f in class_method_funcs.items():
                if not k.endswith("::" + method): continue
                other_cls = k.split("::", 1)[0]
                vt2 = class_to_vtable.get(other_cls)
                if not vt2: continue
                # индекс f в vt2
                idx2 = None
                for i, (_, tf) in enumerate(vt2[1]):
                    if tf == f: idx2 = i; break
                if idx2 is None or idx2 >= len(vt[1]): continue
                slot_func = vt[1][idx2][1]
                results[t] = slot_func - base; break
            if t in results: continue

        unresolved.append((t, "no_match"))

    r2.quit()

    # ============================================================
    # 7) Запись результатов
    # ============================================================
    try:
        with open(OUT, "w") as fh:
            fh.write("// v19 auto-resolved (SCRE format) — iOS\n")
            fh.write("// base=0x%x\n" % base)
            fh.write("// resolved=%d/%d\n\n" % (len(results), len(TARGETS)))
            fh.write("export const offsets = Object.freeze({\n")
            for t in TARGETS:
                k = t.replace(".", "_")
                if t in results: fh.write("    %s: 0x%x,\n" % (k, results[t]))
                else:            fh.write("    // %s: unresolved\n" % k)
            fh.write("\n    // --- ctors via vtable ---\n")
            for cls in sorted(class_to_vtable):
                vt_start, slots = class_to_vtable[cls]
                for c in vt_to_ctors.get(vt_start, set()):
                    fh.write("    %s_ctor: 0x%x,\n" % (cls, c - base)); break
            fh.write("\n    // --- vtable addresses ---\n")
            for cls in sorted(class_to_vtable):
                fh.write("    VTABLE_%s: 0x%x,\n"
                         % (cls.upper(), class_to_vtable[cls][0] - base))
            fh.write("});\n")
    except Exception as e: log("out: %s" % e)

    try:
        with open(VT, "w") as fh:
            fh.write("// vtables per class\n")
            for cls in sorted(class_to_vtable):
                vt_start, slots = class_to_vtable[cls]
                fh.write("\n%s: 0x%x slots=%d\n"
                         % (cls, vt_start - base, len(slots)))
                for i, (_, ta) in enumerate(slots[:96]):
                    fh.write("  [%2d] 0x%08x\n" % (i, ta - base))
    except Exception as e: log("vt: %s" % e)

    try:
        with open(REPORT, "w") as fh:
            fh.write("# v19 report (iOS)\n# base=0x%x\n# resolved=%d/%d\n\n"
                     % (base, len(results), len(TARGETS)))
            fh.write("## resolved:\n")
            for t in TARGETS:
                if t in results: fh.write("  %-55s 0x%08x\n" % (t, results[t]))
            fh.write("\n## unresolved:\n")
            for t, why in unresolved: fh.write("  %-55s (%s)\n" % (t, why))
            fh.write("\n## class→vtable:\n")
            for cls in sorted(class_to_vtable):
                vt_start, slots = class_to_vtable[cls]
                fh.write("%-40s vt=0x%08x slots=%d\n"
                         % (cls, vt_start - base, len(slots)))
    except Exception as e: log("report: %s" % e)

    log("[+] resolved %d/%d" % (len(results), len(TARGETS)))
    log("[+] wrote %s, %s, %s" % (OUT, VT, REPORT))
    log("[+] total %.1fs" % (time.time()-START))

if __name__ == "__main__":
    try: main()
    except Exception as e:
        log("FATAL: %s" % e); traceback.print_exc()