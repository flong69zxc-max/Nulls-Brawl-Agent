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
    for s in strings:
        txt = (s.get("string") or s.get("text") or "").strip()
        if not txt:
            continue
        a = addr_of(s, base)
        if not a:
            continue
        idx.setdefault(txt, []).append(a)
    log("[*] strings: %d unique: %d" % (sum(len(v) for v in idx.values()), len(idx)))
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


def decode_chained(v):
    bind = (v >> 63) & 1
    next_ = (v >> 51) & 0xFFF
    target = v & 0x7FFFFFFFFFF
    return bind, next_, target


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


def is_bl(w):
    return (w & 0xFC000000) == 0x94000000


def decode_bl_target(w, pc):
    offset = w & 0x3FFFFFF
    if offset & (1 << 25):
        offset -= (1 << 26)
    return pc + (offset << 2)


def scan_text(text, ts):
    n = len(text) // 4
    adrp_add = []
    bl_map = {}
    prologs = []
    i = 0
    while i < n:
        w = struct.unpack_from("<I", text, i * 4)[0]
        pc = ts + i * 4
        if is_stp_x29_x30_preindex(w):
            prologs.append(pc)
        if is_adrp(w):
            rd_adrp = w & 0x1F
            page = decode_adrp_imm(w, pc)
            for j in range(i + 1, min(i + 6, n)):
                w2 = struct.unpack_from("<I", text, j * 4)[0]
                if is_add_imm64(w2):
                    rd, rn, imm = decode_add_imm(w2)
                    if rd == rd_adrp and rn == rd_adrp:
                        adrp_add.append((pc, page + imm))
                        break
        if is_bl(w):
            bl_map[pc] = decode_bl_target(w, pc)
        i += 1
    return adrp_add, bl_map, prologs


def build_ptr_index(data_blobs, text_start, text_end):
    idx = {}
    total = 0
    for va, b in data_blobs:
        n = len(b) // 8
        for i in range(n):
            raw = struct.unpack_from("<Q", b, i * 8)[0]
            bind, nxt, target = decode_chained(raw)
            if bind:
                continue
            if text_start <= target < text_end:
                idx.setdefault(target, []).append(va + i * 8)
                total += 1
    return idx, total


def build_slot_to_target(ptr_idx):
    out = {}
    for tgt, slots in ptr_idx.items():
        for s in slots:
            out[s] = tgt
    return out


def expand_vtable(slot_to_target, anchor_slot, max_back=64, max_fwd=256):
    vt_start = anchor_slot
    cur = anchor_slot - 8
    for _ in range(max_back):
        if cur in slot_to_target:
            vt_start = cur
            cur -= 8
        else:
            break
    slots = []
    cur = vt_start
    for _ in range(max_fwd):
        if cur in slot_to_target:
            slots.append((cur, slot_to_target[cur]))
            cur += 8
        else:
            break
    if len(slots) < 2:
        return None
    return vt_start, slots


def analyze_at(text, ts, func_start, max_instr=300):
    off = (func_start - ts) // 4
    n = len(text) // 4
    if off < 0 or off >= n:
        return None
    n_bl = 0
    n_ret = 0
    n_str_x0 = 0
    for i in range(off, min(off + max_instr, n)):
        w = struct.unpack_from("<I", text, i * 4)[0]
        if is_bl(w):
            n_bl += 1
        elif w == 0xD65F03C0:
            n_ret += 1
        elif (w & 0xFFC00000) == 0xF9000000 and (w & 0x1F) == 0:
            n_str_x0 += 1
    return {"n_bl": n_bl, "n_ret": n_ret, "n_str_x0": n_str_x0}


def find_func_start(prologs_sorted, ia):
    import bisect
    idx = bisect.bisect_right(prologs_sorted, ia) - 1
    if idx >= 0:
        return prologs_sorted[idx]
    return ia & ~0xF


def main():
    global _log_fh
    try:
        _log_fh = open(DETAIL, "w")
    except Exception:
        _log_fh = None

    log("=== find_offsets_r2 v13 (final) ===")

    r2 = r2pipe.open(BIN, flags=["-2"])
    r2.cmd("e scr.color=0")
    r2.cmd("e asm.arch=arm")
    r2.cmd("e asm.bits=64")

    info = cmdj(r2, "ij")
    base = (info or {}).get("baddr", 0x100000000) or 0x100000000
    log("base: 0x%x" % base)

    str_index = build_string_index(r2, base)
    if not str_index:
        return

    target_set_strings = set()
    for al in str_index.values():
        for a in al:
            target_set_strings.add(a)

    sections = get_sections(r2)
    text_b, data_secs = pick_sections(sections)
    if not text_b:
        return
    ts, te = text_b
    log("[*] .text: 0x%x - 0x%x" % (ts, te))

    t0 = time.time()
    text = load_range(r2, ts, te - ts)
    log("[*] .text loaded %d bytes %.1fs" % (len(text or b""), time.time() - t0))
    if not text:
        return

    data_blobs = []
    for va, sz, n in data_secs:
        b = load_range(r2, va, sz)
        if b:
            data_blobs.append((va, b))
    log("[*] data loaded %d bytes" % sum(len(b) for _, b in data_blobs))

    ptr_idx, total_slots = build_ptr_index(data_blobs, ts, te)
    log("[*] chained ptr idx: %d targets, %d slots" % (len(ptr_idx), total_slots))
    slot_to_target = build_slot_to_target(ptr_idx)

    t0 = time.time()
    adrp_add, bl_map, prologs = scan_text(text, ts)
    prologs_sorted = sorted(prologs)
    log("[*] adrp_add=%d bl=%d prologs=%d %.1fs"
        % (len(adrp_add), len(bl_map), len(prologs), time.time() - t0))

    # __init_offsets — читаем как u32 offset от base
    init_raw = b""
    for s in sections:
        n = s.get("name", "") or ""
        if "__init_offsets" in n or "__mod_init_func" in n:
            va = s.get("vaddr", 0)
            sz = s.get("size", 0)
            if sz > 0:
                raw = cmd(r2, "p8 %d @ 0x%x" % (sz, va)).strip()
                try:
                    init_raw = bytes.fromhex(raw)
                except Exception:
                    pass
                break

    init_funcs = []
    for i in range(len(init_raw) // 4):
        v32 = struct.unpack_from("<I", init_raw, i * 4)[0]
        va = base + v32
        if ts <= va < te:
            init_funcs.append(va)
    init_set = set(init_funcs)
    log("[*] __init_offsets: %d valid funcs" % len(init_set))

    # карта: строка -> якорь-функции (функции, ссылающиеся на строку)
    str_to_anchor_funcs = {}
    for pc, tgt in adrp_add:
        if tgt in target_set_strings:
            f = find_func_start(prologs_sorted, pc)
            str_to_anchor_funcs.setdefault(tgt, set()).add(f)

    # карта: anchor_func -> vtable_start
    anchor_to_vtable = {}
    for tgt, slots in ptr_idx.items():
        for slot in slots[:3]:
            vt = expand_vtable(slot_to_target, slot)
            if vt:
                anchor_to_vtable[tgt] = vt[0]
                break

    all_vt_starts = set(anchor_to_vtable.values())
    log("[*] anchors with vtable: %d, unique vtables: %d"
        % (len(anchor_to_vtable), len(all_vt_starts)))

    # карта: vtable_start -> ctor-функции (xref через adrp+add)
    vt_to_ctors = {}
    for pc, tgt in adrp_add:
        if tgt in all_vt_starts:
            f = find_func_start(prologs_sorted, pc)
            vt_to_ctors.setdefault(tgt, set()).add(f)
    log("[*] vtables with ctor xref: %d" % len(vt_to_ctors))

    # карта: init_func -> string_xrefs (функции из init_offsets, которые ссылаются на строки)
    init_str_xrefs = {}
    for pc, tgt in adrp_add:
        if tgt in target_set_strings:
            f = find_func_start(prologs_sorted, pc)
            if f in init_set:
                init_str_xrefs.setdefault(f, set()).add(tgt)
    log("[*] init funcs with string xrefs: %d" % len(init_str_xrefs))

    r2.quit()

    results = []
    for cls in CLASSES:
        addrs = []
        for s, al in str_index.items():
            if s == cls or s.startswith(cls + "::") or ("::" + cls) in s \
               or s.startswith(cls + " ") or s.startswith(cls + "\t"):
                addrs.extend(al)
        if not addrs:
            results.append({"class": cls, "ctor": None, "src": "no_string"})
            continue

        anchor_funcs = set()
        for sa in addrs:
            for af in str_to_anchor_funcs.get(sa, []):
                anchor_funcs.add(af)

        ctor_candidates = []

        # путь 1: anchor -> vtable -> ctor
        for af in anchor_funcs:
            vt = anchor_to_vtable.get(af)
            if not vt:
                continue
            for ctor in vt_to_ctors.get(vt, []):
                info = analyze_at(text, ts, ctor)
                if not info:
                    continue
                score = info["n_bl"] * 3
                if info["n_str_x0"] > 0:
                    score += 20
                if ctor in init_set:
                    score += 200
                if info["n_bl"] == 0:
                    score -= 50
                ctor_candidates.append({
                    "func": ctor, "score": score, "vtable": vt,
                    "via": "vtable", "n_bl": info["n_bl"],
                })

        # путь 2: init_func ссылается на строку класса напрямую
        if not ctor_candidates:
            for sa in addrs:
                for initf, strs in init_str_xrefs.items():
                    if sa in strs:
                        info = analyze_at(text, ts, initf)
                        if not info or info["n_bl"] == 0:
                            continue
                        score = 100 + info["n_bl"] * 3
                        if info["n_str_x0"] > 0:
                            score += 20
                        ctor_candidates.append({
                            "func": initf, "score": score, "vtable": None,
                            "via": "init_string", "n_bl": info["n_bl"],
                        })

        # путь 3: anchor сам есть init_func
        if not ctor_candidates:
            for af in anchor_funcs:
                if af in init_set:
                    info = analyze_at(text, ts, af)
                    if info and info["n_bl"] > 0:
                        ctor_candidates.append({
                            "func": af, "score": 80 + info["n_bl"] * 2,
                            "vtable": None, "via": "init_anchor",
                            "n_bl": info["n_bl"],
                        })

        if not ctor_candidates:
            results.append({"class": cls, "ctor": None, "src": "unresolved"})
            log("[%s] unresolved" % cls)
            continue

        ctor_candidates.sort(key=lambda x: -x["score"])
        best = ctor_candidates[0]
        results.append({
            "class": cls, "ctor": best["func"] - base, "score": best["score"],
            "vtable": (best["vtable"] - base) if best["vtable"] else None,
            "src": best["via"],
        })
        log("[%s] ctor=0x%x via=%s score=%d n_bl=%d"
            % (cls, best["func"], best["via"], best["score"], best["n_bl"]))

    try:
        with open(REPORT, "w") as fh:
            fh.write("# r2 ctor resolution (v13)\n")
            fh.write("# base=0x%x\n\n" % base)
            for r in results:
                fh.write("=== %s ===\n" % r["class"])
                if r.get("ctor") is not None:
                    fh.write("  ctor:   rva=0x%08x\n" % r["ctor"])
                if r.get("vtable") is not None:
                    fh.write("  vtable: rva=0x%08x\n" % r["vtable"])
                fh.write("  src=%s score=%d\n"
                         % (r.get("src", ""), r.get("score", 0)))
                fh.write("\n")
    except Exception as e:
        log("report: %s" % e)

    try:
        with open(OUT, "w") as fh:
            fh.write("export const ctors = Object.freeze({\n")
            for r in results:
                if r.get("ctor") is not None:
                    fh.write("  %s: 0x%x,\n" % (r["class"], r["ctor"]))
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