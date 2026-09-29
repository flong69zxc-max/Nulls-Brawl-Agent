#!/usr/bin/env python3
import os
import sys
import time
import struct
import traceback

import r2pipe

WS = os.environ.get("GITHUB_WORKSPACE", "/tmp")
BIN = os.environ.get("R2_BIN", "/tmp/brawl_bin")
OUT = os.path.join(WS, "offsets_resolved.js")
REPORT = os.path.join(WS, "offsets_report.txt")
DETAIL = os.path.join(WS, "ctors_detailed.log")
BUDGET = 2700
START = time.time()

CLASSES = [
    "LogicBattleModeClient", "BattleMode", "LogicGameObjectClient",
    "BattleScreen", "Gui", "GUI", "LogicProjectileData", "LogicProjectileClient",
    "LogicProjectileServer", "LogicCharacterData", "LogicCharacterClient",
    "LogicCharacterClientOwn", "LogicSkillData", "LogicSkillClient",
    "LogicTileData", "LogicTile", "LogicTileMap", "LogicDataTables",
    "LogicGameObjectManagerClient", "LogicGameObjectServer",
    "LogicGameModeUtil", "LogicData", "LogicRandom", "LogicJSONObject",
    "LogicCompressedString", "LogicPlayerMap", "LogicPlayerMapUtil",
    "LogicLongToCodeConverterUtil", "LogicAccessory",
    "GameButton", "GameSelectableButton", "CustomButton", "RadioButton",
    "GenericPopup", "PopupBase", "DropGUIContainer", "GameSliderComponent",
    "MapEditorModifierItem", "MapEditorModifierPopup",
    "Sprite", "Stage", "DisplayObject", "MovieClip", "MovieClipHelper",
    "TextField", "DecoratedTextField", "Application", "Name",
    "ClientInput", "ClientInputManager", "ClientInputMessage",
    "Projectile", "GameMain", "DecalManager", "GameObjectManager",
    "RenderSystem", "ResourceManager", "StringTable", "FramerateManager",
    "MessageManager", "AllianceManager", "CombatHUD", "Character",
    "GameScreen", "MapEditorScreen", "GameSettings", "GameStateManager",
    "HomeMode", "HomePage", "HomeScreen", "Screen", "ScrollArea",
    "GlobalID", "AnalyticEvent", "ResourceListener",
    "AreaEffectData", "TeamChatMessage", "TeamSetMemberReadyMessage",
    "StartSpectateMessage", "PiranhaMessage",
    "HashTagCodeGenerator", "CSVRow", "CSVTable",
]

_log_fh = None


def log(m):
    line = "[%7.2f] %s" % (time.time() - START, m)
    try:
        sys.stdout.write(line + "\n")
        sys.stdout.flush()
    except Exception:
        pass
    if _log_fh is not None:
        try:
            _log_fh.write(line + "\n")
            _log_fh.flush()
        except Exception:
            pass


def cmdj(r2, c):
    try:
        return r2.cmdj(c)
    except Exception:
        return None


def cmd(r2, c):
    try:
        return r2.cmd(c)
    except Exception:
        return ""


def is_logger(name):
    if not name:
        return False
    n = name.lower()
    for b in ("log", "print", "trace", "assert", "debug", "fatal", "panic", "abort"):
        if b in n:
            return True
    return False


def addr_of(s, base):
    va = s.get("vaddr", 0)
    pa = s.get("paddr", 0)
    if va and va >= base:
        return va
    if pa and pa >= base:
        return pa
    if pa and pa > 0:
        return pa + base
    return 0


def build_string_index(r2, base):
    strings = cmdj(r2, "izj")
    if not strings:
        log("[!] izj returned nothing")
        return {}
    total = 0
    idx = {}
    for s in strings:
        txt = (s.get("string") or s.get("text") or "").strip()
        if not txt:
            continue
        a = addr_of(s, base)
        if not a:
            continue
        total += 1
        idx.setdefault(txt, []).append(a)
    log("[*] strings: %d unique: %d" % (total, len(idx)))
    return idx


def get_text_bounds(r2):
    sections = cmdj(r2, "iSj")
    if not sections:
        return None
    for s in sections:
        n = s.get("name", "") or ""
        p = s.get("perm", "") or ""
        if ("__text" in n or ".text" in n) and "x" in p:
            return (s.get("vaddr", 0), s.get("vaddr", 0) + s.get("size", 0))
    return None


# --- ARM64 decoders ---

def is_adrp(w):
    return (w & 0x9F000000) == 0x90000000


def decode_adrp_imm(w, pc):
    immlo = (w >> 29) & 0x3
    immhi = (w >> 5) & 0x7FFFF
    imm = (immhi << 2) | immlo
    if imm & (1 << 20):
        imm -= (1 << 21)
    return (pc & ~0xFFF) + (imm << 12)


def is_add_imm64(w):
    return (w & 0xFF800000) == 0x91000000


def decode_add_imm(w):
    rd = w & 0x1F
    rn = (w >> 5) & 0x1F
    imm12 = (w >> 10) & 0xFFF
    sh = (w >> 22) & 1
    if sh:
        imm12 = imm12 << 12
    return (rd, rn, imm12)


def is_stp_x29_x30_preindex(w):
    # stp x29, x30, [sp, #imm]!  (64-bit, pre-index, signed offset)
    return (w & 0xFFC07FFF) == 0xA9807BFD


def is_stp_x29_x30_offset(w):
    # stp x29, x30, [sp, #imm]  (64-bit, offset)
    return (w & 0xFFC07FFF) == 0xA9007BFD


def is_sub_sp_sp(w):
    # sub sp, sp, #imm
    return (w & 0xFF8003FF) == 0xD10003FF


def is_pacibsp(w):
    return w == 0xD503237F


# --- text scan ---

def scan_text_for_adrp_add(r2, text_start, text_end, target_set):
    CHUNK = 0x100000
    overlap = 32
    results = {}
    total_pairs = 0
    total_adrp = 0
    total_add = 0
    addr = text_start
    carry = b""
    carry_addr = text_start
    while addr < text_end:
        if time.time() - START > BUDGET - 300:
            log("[!] adrp scan budget exhausted at 0x%x" % addr)
            break
        size = min(CHUNK, text_end - addr)
        hx = cmd(r2, "p8 %d @ 0x%x" % (size, addr)).strip()
        if not hx:
            log("[!] p8 returned empty at 0x%x" % addr)
            addr += size
            continue
        try:
            data = bytes.fromhex(hx)
        except Exception:
            log("[!] hex parse failed at 0x%x" % addr)
            addr += size
            continue
        data = carry + data
        data_start = carry_addr
        n = len(data) // 4
        i = 0
        while i < n:
            off = i * 4
            w = struct.unpack_from("<I", data, off)[0]
            ia = data_start + off
            if is_adrp(w):
                total_adrp += 1
                rd_adrp = w & 0x1F
                page = decode_adrp_imm(w, ia)
                for j in range(i + 1, min(i + 7, n)):
                    w2 = struct.unpack_from("<I", data, j * 4)[0]
                    if is_add_imm64(w2):
                        rd, rn, imm = decode_add_imm(w2)
                        if rd == rd_adrp and rn == rd_adrp:
                            total_add += 1
                            target = page + imm
                            if target in target_set:
                                results.setdefault(target, []).append(ia)
                            break
            i += 1
        carry = data[-overlap:] if len(data) > overlap else data
        carry_addr = addr + size - len(carry)
        addr += size
    log("[*] adrp scan done: adrp=%d add=%d pairs-to-targets=%d"
        % (total_adrp, total_add, sum(len(v) for v in results.values())))
    return results


def load_mod_init_func(r2):
    out = []
    sections = cmdj(r2, "iSj")
    if not sections:
        return out
    for s in sections:
        name = s.get("name", "") or ""
        if "__mod_init_func" in name or "__init_offsets" in name:
            va = s.get("vaddr", 0)
            sz = s.get("size", 0)
            log("[*] %s @ 0x%x size 0x%x" % (name, va, sz))
            if sz > 0 and va > 0:
                raw = cmd(r2, "p8 %d @ 0x%x" % (sz, va)).strip()
                try:
                    b = bytes.fromhex(raw)
                except Exception:
                    continue
                for k in range(0, len(b) - 7, 8):
                    p = struct.unpack_from("<Q", b, k)[0]
                    if p and p > 0x100000000:
                        out.append(p)
    log("[*] __init_offsets/__mod_init_func entries: %d" % len(out))
    return out


# --- function recovery ---

def get_function_at(r2, addr):
    f = cmdj(r2, "afij @ 0x%x" % addr)
    if isinstance(f, list) and f:
        best = None
        for f0 in f:
            off = f0.get("offset", 0)
            sz = f0.get("size", 0)
            if off <= addr < off + sz:
                if best is None or sz > best[2]:
                    best = (off, f0.get("name", ""), sz)
        if best:
            return (best[0], best[1])
        f0 = f[0]
        return (f0.get("offset", 0), f0.get("name", ""))
    if isinstance(f, dict):
        return (f.get("offset", 0), f.get("name", ""))
    return None


def find_prolog(r2, addr, max_back=0x800):
    start = max(0, addr - max_back)
    size = addr - start + 4
    hx = cmd(r2, "p8 %d @ 0x%x" % (size, start)).strip()
    if not hx:
        return None
    try:
        data = bytes.fromhex(hx)
    except Exception:
        return None
    n = len(data) // 4
    # ищем назад: первый stp x29, x30 [sp, ...]! (pre-index) — лучший кандидат
    # либо sub sp, sp, #N
    candidates_pre = []
    candidates_sub = []
    for i in range(n):
        w = struct.unpack_from("<I", data, i * 4)[0]
        ia = start + i * 4
        if ia > addr:
            break
        if is_stp_x29_x30_preindex(w):
            candidates_pre.append(ia)
        elif is_sub_sp_sp(w):
            candidates_sub.append(ia)
    if candidates_pre:
        return candidates_pre[-1]
    if candidates_sub:
        return candidates_sub[-1]
    return None


def force_function_at(r2, addr):
    f = get_function_at(r2, addr)
    if f:
        return f, "existing"
    # попробуем af без анализа
    r2.cmd("af @ 0x%x" % addr)
    f = get_function_at(r2, addr)
    if f and f[0] and f[0] <= addr:
        return f, "af"
    prolog = find_prolog(r2, addr)
    if prolog:
        r2.cmd("af @ 0x%x" % prolog)
        f = get_function_at(r2, prolog)
        if f:
            return f, "af_prolog@0x%x" % prolog
    return None, "none"


def nearest_init(mod_inits, addr, max_diff=0x400):
    best = None
    for p in mod_inits:
        d = abs(p - addr)
        if d <= max_diff and (best is None or d < best[1]):
            best = (p, d)
    return best[0] if best else None


def scan_class(r2, cls, str_index, adrp_hits, mod_inits, base):
    addrs = []
    for s, al in str_index.items():
        if s == cls or s.startswith(cls + "::") or ("::" + cls) in s \
           or s.startswith(cls + " ") or s.startswith(cls + "\t"):
            addrs.extend(al)
    if not addrs:
        log("[%s] no string anchors" % cls)
        return None

    log("[%s] string anchors: %d" % (cls, len(addrs)))

    all_hits = []
    for sa in addrs:
        if sa in adrp_hits:
            for ia in adrp_hits[sa]:
                all_hits.append((ia, sa))
    if not all_hits:
        log("[%s] no ADRP+ADD candidates" % cls)
        return {"class": cls, "method": None, "vtable": None, "ctor": None}

    log("[%s] total ADRP+ADD hits: %d" % (cls, len(all_hits)))

    # для каждого hit пытаемся получить функцию
    attempts = []
    for ia, sa in all_hits[:12]:
        f, how = force_function_at(r2, ia)
        if f:
            attempts.append((f[0], f[1], ia, sa, how))
            log("[%s]   hit 0x%x -> func 0x%x %s (%s)"
                % (cls, ia, f[0], f[1], how))
        else:
            log("[%s]   hit 0x%x -> no function (how=%s)" % (cls, ia, how))

    if not attempts:
        # fallback через __init_offsets
        for ia, sa in all_hits[:8]:
            ni = nearest_init(mod_inits, ia, max_diff=0x400)
            if ni:
                f, how = force_function_at(r2, ni)
                if f:
                    attempts.append((f[0], f[1], ia, sa, "init_offsets"))
                    log("[%s]   hit 0x%x -> init 0x%x -> func 0x%x %s"
                        % (cls, ia, ni, f[0], f[1]))

    if not attempts:
        log("[%s] UNRESOLVED (no function for any hit)" % cls)
        return {"class": cls, "method": None, "vtable": None, "ctor": None}

    # фильтр логгеров
    filtered = [a for a in attempts if not is_logger(a[1])]
    if not filtered:
        filtered = attempts

    # выбираем самый частый entry (если несколько хитов идут в один ctor)
    counts = {}
    for a in filtered:
        counts[a[0]] = counts.get(a[0], 0) + 1
    best_entry = max(counts.items(), key=lambda x: x[1])[0]
    best = None
    for a in filtered:
        if a[0] == best_entry:
            best = a
            break

    log("[%s] CHOSEN: func 0x%x %s (via %s, from hit 0x%x)"
        % (cls, best[0], best[1], best[4], best[2]))

    return {"class": cls, "method": (best[0] - base, best[1]),
            "vtable": None, "ctor": None, "src": best[4],
            "str_addr": best[3], "hit_addr": best[2]}


def main():
    global _log_fh
    try:
        _log_fh = open(DETAIL, "w")
    except Exception:
        _log_fh = None

    log("=== find_offsets_r2 v6 ===")
    log("bin: %s" % BIN)

    r2 = r2pipe.open(BIN, flags=["-2"])

    log("setting options ...")
    for opt in (
        "e scr.color=0",
        "e anal.timeout=1800",
        "e anal.hasnext=true",
        "e anal.strings=true",
        "e anal.autoname=true",
        "e anal.jmp.after=true",
        "e anal.arm64.preludes=true",
        "e anal.refstr=true",
    ):
        r2.cmd(opt)

    r2.cmd("e asm.arch=arm")
    r2.cmd("e asm.bits=64")
    try:
        r2.cmd("e anal.arch=arm")
    except Exception:
        pass

    info = cmdj(r2, "ij")
    base = (info or {}).get("baddr", 0x100000000) or 0x100000000
    log("base: 0x%x" % base)

    t0 = time.time()
    r2.cmd("aaa")
    log("aaa done in %.1fs, aflc=%s" % (time.time() - t0, cmd(r2, "aflc").strip()))
    t0 = time.time()
    r2.cmd("aac")
    log("aac done in %.1fs, aflc=%s" % (time.time() - t0, cmd(r2, "aflc").strip()))
    t0 = time.time()
    r2.cmd("aar")
    log("aar done in %.1fs" % (time.time() - t0))

    str_index = build_string_index(r2, base)
    if not str_index:
        log("[!] empty string index")
        return

    all_str_addrs = []
    for al in str_index.values():
        all_str_addrs.extend(al)
    target_set = set(all_str_addrs)
    log("[*] total string addrs: %d" % len(target_set))

    text = get_text_bounds(r2)
    if not text:
        log("[!] .text not found")
        r2.quit()
        return
    ts, te = text
    log("[*] .text: 0x%x - 0x%x (size 0x%x)" % (ts, te, te - ts))

    adrp_hits = scan_text_for_adrp_add(r2, ts, te, target_set)
    mod_inits = load_mod_init_func(r2)

    results = []
    for cls in CLASSES:
        if time.time() - START > BUDGET - 120:
            log("[!] budget exhausted before %s" % cls)
            break
        try:
            r = scan_class(r2, cls, str_index, adrp_hits, mod_inits, base)
        except Exception as e:
            log("[%s] EXCEPTION: %s" % (cls, e))
            traceback.print_exc()
            continue
        if r:
            results.append(r)

    r2.quit()

    try:
        with open(REPORT, "w") as fh:
            fh.write("# r2 ctor resolution (v6)\n")
            fh.write("# base=0x%x\n\n" % base)
            for r in results:
                fh.write("=== %s ===\n" % r["class"])
                if r.get("method"):
                    fh.write("  method: rva=0x%08x  %s\n"
                             % (r["method"][0], r["method"][1]))
                if r.get("src"):
                    fh.write("  src:    %s\n" % r["src"])
                if r.get("str_addr"):
                    fh.write("  str:    rva=0x%08x\n" % (r["str_addr"] - base))
                if r.get("hit_addr"):
                    fh.write("  hit:    rva=0x%08x\n" % (r["hit_addr"] - base))
                fh.write("\n")
    except Exception as e:
        log("write REPORT failed: %s" % e)

    try:
        n_ok = 0
        n_tot = 0
        with open(OUT, "w") as fh:
            fh.write("export const ctors = Object.freeze({\n")
            for r in results:
                n_tot += 1
                if r.get("method"):
                    fh.write("  %s: 0x%x,\n" % (r["class"], r["method"][0]))
                    n_ok += 1
                else:
                    fh.write("  // %s: unresolved\n" % r["class"])
            fh.write("});\n")
        log("[*] resolved %d/%d" % (n_ok, n_tot))
    except Exception as e:
        log("write OUT failed: %s" % e)

    log("[+] wrote %s and %s" % (OUT, REPORT))


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        log("FATAL: %s" % e)
        traceback.print_exc()