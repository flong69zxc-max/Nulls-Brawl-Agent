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
BUDGET = 1500
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
    strings = cmdj(r2, "izj") or []
    idx = {}
    total = 0
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


def get_sections(r2):
    return cmdj(r2, "iSj") or []


def pick_sections(sections):
    text = None
    data = []
    for s in sections:
        n = s.get("name", "") or ""
        p = s.get("perm", "") or ""
        va = s.get("vaddr", 0)
        sz = s.get("size", 0)
        if sz <= 0 or va <= 0:
            continue
        if ("__text" in n or ".text" in n) and "x" in p:
            text = (va, va + sz)
        elif "x" not in p and ("w" in p or "r" in p):
            if ("const" in n or "data" in n or "got" in n):
                data.append((va, sz, n))
    return text, data


def load_range(r2, va, size):
    CHUNK = 0x400000
    chunks = []
    addr = va
    end = va + size
    while addr < end:
        n = min(CHUNK, end - addr)
        hx = cmd(r2, "p8 %d @ 0x%x" % (n, addr)).strip()
        if not hx:
            return None
        try:
            chunks.append(bytes.fromhex(hx))
        except Exception:
            return None
        addr += n
    return b"".join(chunks)


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
    return (w & 0xFFC07FFF) == 0xA9807BFD


def scan_adrp_add_to_set(text, ts, target_set):
    """Возвращает dict: target -> [instr_addr]."""
    n = len(text) // 4
    out = {}
    for i in range(n):
        w = struct.unpack_from("<I", text, i * 4)[0]
        if is_adrp(w):
            rd_adrp = w & 0x1F
            ia = ts + i * 4
            page = decode_adrp_imm(w, ia)
            for j in range(i + 1, min(i + 7, n)):
                w2 = struct.unpack_from("<I", text, j * 4)[0]
                if is_add_imm64(w2):
                    rd, rn, imm = decode_add_imm(w2)
                    if rd == rd_adrp and rn == rd_adrp:
                        target = page + imm
                        if target in target_set:
                            out.setdefault(target, []).append(ia)
                        break
    return out


def build_ptr_index(data_blobs, text_start, text_end):
    """data_blobs: list of (va, bytes). Возвращает dict target_addr -> [slot_addr].
    Индексируем все 8-байтовые указатели в data на .text.
    """
    idx = {}
    for va, b in data_blobs:
        n = len(b) // 8
        for i in range(n):
            v = struct.unpack_from("<Q", b, i * 8)[0]
            if text_start <= v < text_end:
                idx.setdefault(v, []).append(va + i * 8)
    return idx


def vtable_around(ptr_idx, anchor_addr, data_blobs):
    """Проверяет, что anchor_addr стоит в vtable. Возвращает (vt_start, slots) или None."""
    slots = ptr_idx.get(anchor_addr, [])
    if not slots:
        return None
    # берём первую позицию
    anchor_slot = slots[0]
    # идём назад: пока предыдущий слот тоже валидный указатель в .text
    vt_start = anchor_slot
    cur = anchor_slot - 8
    for _ in range(64):
        prev_target = read_q_at(data_blobs, cur)
        if prev_target is None:
            break
        if prev_target in ptr_idx:
            vt_start = cur
            cur -= 8
        else:
            break
    # идём вперёд: собираем валидные слоты
    seq = []
    cur = vt_start
    for _ in range(256):
        tgt = read_q_at(data_blobs, cur)
        if tgt is None or tgt not in ptr_idx:
            break
        seq.append((cur, tgt))
        cur += 8
    if len(seq) < 2:
        return None
    return vt_start, seq


def read_q_at(data_blobs, addr):
    for va, b in data_blobs:
        if va <= addr < va + len(b):
            off = addr - va
            if off + 8 > len(b):
                return None
            return struct.unpack_from("<Q", b, off)[0]
    return None


def find_func_start_backwards(text, ts, ia, max_back=0x2000):
    off = (ia - ts) // 4
    max_words = max_back // 4
    i = off
    limit = max(0, off - max_words)
    while i >= limit:
        w = struct.unpack_from("<I", text, i * 4)[0]
        if is_stp_x29_x30_preindex(w):
            return ts + i * 4
        i -= 1
    return ia & ~0xF


def analyze_at(text, ts, func_start, max_instr=200):
    off = (func_start - ts) // 4
    n = len(text) // 4
    n_bl = 0
    n_ret = 0
    n_str_x0 = 0
    for i in range(off, min(off + max_instr, n)):
        w = struct.unpack_from("<I", text, i * 4)[0]
        pc = ts + i * 4
        if (w & 0xFC000000) == 0x94000000:
            n_bl += 1
        elif w == 0xD65F03C0:
            n_ret += 1
        elif (w & 0xFFC00000) == 0xF9000000 and (w & 0x1F) == 0:
            n_str_x0 += 1
    return {"n_bl": n_bl, "n_ret": n_ret, "n_str_x0": n_str_x0}


def scan_class(cls, str_index, adrp_str_hits, ptr_idx, data_blobs,
               adrp_vt_hits_full, text, ts, te, init_offsets, base):
    addrs = []
    for s, al in str_index.items():
        if s == cls or s.startswith(cls + "::") or ("::" + cls) in s \
           or s.startswith(cls + " ") or s.startswith(cls + "\t"):
            addrs.extend(al)
    if not addrs:
        return None

    # 1) якоря — функции, ссылающиеся на строки класса
    anchor_funcs = set()
    for sa in addrs:
        for ia in adrp_str_hits.get(sa, []):
            fstart = find_func_start_backwards(text, ts, ia)
            anchor_funcs.add(fstart)

    if not anchor_funcs:
        log("[%s] no anchor funcs" % cls)
        return {"class": cls, "method": None, "vtable": None, "ctor": None}

    log("[%s] anchors: %s" % (cls, ["0x%x" % a for a in list(anchor_funcs)[:4]]))

    # 2) vtable — где лежат указатели на якоря
    vtable_starts = set()
    for af in anchor_funcs:
        vt = vtable_around(ptr_idx, af, data_blobs)
        if vt:
            vtable_starts.add(vt[0])
            log("[%s]   vtable for 0x%x: start=0x%x slots=%d"
                % (cls, af, vt[0], len(vt[1])))

    if not vtable_starts:
        log("[%s] no vtable found" % cls)
        return {"class": cls, "method": None, "vtable": None, "ctor": None}

    # 3) ищем ctor через adrp+add на vtable_start
    ctor_candidates = []
    for vt_start in vtable_starts:
        hits = adrp_vt_hits_full.get(vt_start, [])
        for ia in hits:
            fstart = find_func_start_backwards(text, ts, ia)
            info = analyze_at(text, ts, fstart)
            score = 0
            if fstart in init_offsets:
                score += 150
            score += info["n_bl"] * 2
            if info["n_str_x0"] > 0:
                score += 20
            ctor_candidates.append({
                "func": fstart, "score": score,
                "via": "vtable_xref", "vtable": vt_start,
                "n_bl": info["n_bl"],
            })

    if not ctor_candidates:
        log("[%s] no adrp+add xref on vtable" % cls)
        # fallback: ближайший init_offset к якорю
        for af in anchor_funcs:
            for io in init_offsets:
                if abs(io - af) < 0x800:
                    ctor_candidates.append({
                        "func": io, "score": 50, "via": "init_near",
                        "vtable": list(vtable_starts)[0], "n_bl": 0,
                    })
                    break
            if ctor_candidates:
                break

    if not ctor_candidates:
        # fallback — vtable_start сам
        vt = list(vtable_starts)[0]
        return {"class": cls, "method": (vt - base, ""),
                "vtable": vt - base, "ctor": None, "score": 0,
                "src": "vtable_only", "n_call": 0}

    ctor_candidates.sort(key=lambda x: -x["score"])
    log("[%s] top-3 ctors:" % cls)
    for i, c in enumerate(ctor_candidates[:3]):
        log("[%s]   [%d] score=%d func=0x%x n_bl=%d via=%s"
            % (cls, i, c["score"], c["func"], c["n_bl"], c["via"]))

    best = ctor_candidates[0]
    return {
        "class": cls,
        "method": (best["func"] - base, ""),
        "ctor": (best["func"] - base, ""),
        "vtable": (best["vtable"] - base) if best["vtable"] else None,
        "score": best["score"],
        "src": best["via"],
        "n_call": best["n_bl"],
    }


def main():
    global _log_fh
    try:
        _log_fh = open(DETAIL, "w")
    except Exception:
        _log_fh = None

    log("=== find_offsets_r2 v10 (vtable path) ===")
    log("bin: %s" % BIN)

    r2 = r2pipe.open(BIN, flags=["-2"])
    for opt in ("e scr.color=0", "e asm.arch=arm", "e asm.bits=64"):
        r2.cmd(opt)

    info = cmdj(r2, "ij")
    base = (info or {}).get("baddr", 0x100000000) or 0x100000000
    log("base: 0x%x" % base)

    str_index = build_string_index(r2, base)
    if not str_index:
        return

    target_set = set()
    for al in str_index.values():
        for a in al:
            target_set.add(a)
    log("[*] total string addrs: %d" % len(target_set))

    sections = get_sections(r2)
    text, data_secs = pick_sections(sections)
    if not text:
        log("[!] no .text")
        return
    ts, te = text
    log("[*] .text: 0x%x - 0x%x (size 0x%x)" % (ts, te, te - ts))
    for va, sz, n in data_secs:
        log("    data: %s @ 0x%x size 0x%x" % (n, va, sz))

    t0 = time.time()
    text_bytes = load_range(r2, ts, te - ts)
    log("[*] loaded .text %d bytes in %.1fs" % (len(text_bytes or b""), time.time() - t0))
    if not text_bytes:
        return

    t0 = time.time()
    data_blobs = []
    for va, sz, n in data_secs:
        b = load_range(r2, va, sz)
        if b:
            data_blobs.append((va, b))
    total_data = sum(len(b) for _, b in data_blobs)
    log("[*] loaded data %d bytes in %.1fs" % (total_data, time.time() - t0))

    t0 = time.time()
    ptr_idx = build_ptr_index(data_blobs, ts, te)
    log("[*] ptr index: %d unique targets, %d total slots in %.1fs"
        % (len(ptr_idx), sum(len(v) for v in ptr_idx.values()), time.time() - t0))

    # adrp+add на строки
    t0 = time.time()
    adrp_str_hits = scan_adrp_add_to_set(text_bytes, ts, target_set)
    log("[*] adrp+add on strings: %d hits in %.1fs"
        % (sum(len(v) for v in adrp_str_hits.values()), time.time() - t0))

    # соберём все vtable_start, которые встречаются как указатели — их тоже просканируем
    # но сначала соберём множество vtable_starts из якорей, чтобы потом искать на них xref
    # (нужно сначала пройтись по всем классам, но проще сразу собрать все vtable_start,
    # которые могут быть найдены)
    # сделаем обратный индекс: для каждого класса — свои vtable_starts, потом соберём union
    # чтобы сэкономить, соберём по ходу

    init_offsets = []
    for s in sections:
        n = s.get("name", "") or ""
        if "__init_offsets" in n or "__mod_init_func" in n:
            va = s.get("vaddr", 0)
            sz = s.get("size", 0)
            if sz > 0:
                raw = cmd(r2, "p8 %d @ 0x%x" % (sz, va)).strip()
                try:
                    b = bytes.fromhex(raw)
                    for k in range(0, len(b) - 7, 8):
                        p = struct.unpack_from("<Q", b, k)[0]
                        if p and p > 0x100000000:
                            init_offsets.append(p)
                except Exception:
                    pass
    init_set = set(init_offsets)
    log("[*] __init_offsets: %d entries" % len(init_offsets))

    # предварительный сбор всех vtable_start
    # (пройдём по всем строкам всех классов)
    all_vtable_starts = set()
    anchor_funcs_by_class = {}
    for cls in CLASSES:
        addrs = []
        for s, al in str_index.items():
            if s == cls or s.startswith(cls + "::") or ("::" + cls) in s \
               or s.startswith(cls + " ") or s.startswith(cls + "\t"):
                addrs.extend(al)
        afs = set()
        for sa in addrs:
            for ia in adrp_str_hits.get(sa, []):
                afs.add(find_func_start_backwards(text_bytes, ts, ia))
        anchor_funcs_by_class[cls] = afs
        for af in afs:
            vt = vtable_around(ptr_idx, af, data_blobs)
            if vt:
                all_vtable_starts.add(vt[0])

    log("[*] total unique vtable_starts: %d" % len(all_vtable_starts))

    t0 = time.time()
    adrp_vt_hits = scan_adrp_add_to_set(text_bytes, ts, all_vtable_starts)
    log("[*] adrp+add on vtables: %d hits in %.1fs"
        % (sum(len(v) for v in adrp_vt_hits.values()), time.time() - t0))

    r2.quit()

    results = []
    for cls in CLASSES:
        if time.time() - START > BUDGET - 60:
            break
        try:
            r = scan_class(cls, str_index, adrp_str_hits, ptr_idx, data_blobs,
                           adrp_vt_hits, text_bytes, ts, te, init_set, base)
        except Exception as e:
            log("[%s] EXC: %s" % (cls, e))
            traceback.print_exc()
            continue
        if r:
            results.append(r)

    try:
        with open(REPORT, "w") as fh:
            fh.write("# r2 ctor resolution (v10)\n")
            fh.write("# base=0x%x\n\n" % base)
            for r in results:
                fh.write("=== %s ===\n" % r["class"])
                if r.get("ctor"):
                    fh.write("  ctor:   rva=0x%08x\n" % r["ctor"][0])
                if r.get("vtable") is not None:
                    fh.write("  vtable: rva=0x%08x\n" % r["vtable"])
                if r.get("score") is not None:
                    fh.write("  score=%d src=%s n_bl=%d\n"
                             % (r["score"], r.get("src", ""), r.get("n_call", 0)))
                fh.write("\n")
    except Exception as e:
        log("report: %s" % e)

    try:
        with open(OUT, "w") as fh:
            fh.write("export const ctors = Object.freeze({\n")
            for r in results:
                if r.get("ctor"):
                    fh.write("  %s: 0x%x,\n" % (r["class"], r["ctor"][0]))
                elif r.get("vtable") is not None:
                    fh.write("  // %s: vtable=0x%x (ctor not found)\n"
                             % (r["class"], r["vtable"]))
                else:
                    fh.write("  // %s: unresolved\n" % r["class"])
            fh.write("});\n")
    except Exception as e:
        log("out: %s" % e)

    log("[+] wrote %s and %s" % (OUT, REPORT))
    log("[+] total %.1fs" % (time.time() - START))


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        log("FATAL: %s" % e)
        traceback.print_exc()