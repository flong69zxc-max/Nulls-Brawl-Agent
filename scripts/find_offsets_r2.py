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
    """dyld chained fixup: bits 0-50 = target, 51-62 = next, 63 = bind."""
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


def build_ptr_index(data_blobs, text_start, text_end):
    """Индексируем все chained pointers в data, target которых попадает в .text."""
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


def vtable_around(ptr_idx, anchor_addr):
    slots = ptr_idx.get(anchor_addr, [])
    if not slots:
        return None
    anchor_slot = slots[0]
    vt_start = anchor_slot
    cur = anchor_slot - 8
    for _ in range(64):
        v = None
        for _, b in [(0, None)]:
            break
        # читаем из ptr_idx обратно нельзя; нужен map slot->value
        # проверим через ptr_idx значений: ищем, есть ли в ptr_idx слот с ключом cur
        # но у нас нет обратного индекса. Поэтому: если в ptr_idx есть хоть один target,
        # чей slot == cur, то cur — часть vtable.
        # Это неэффективно. Сделаем проще: проверим, встречается ли cur среди values
        pass
    return None


def build_slot_to_target(ptr_idx):
    """Обратный индекс: slot_addr -> target."""
    out = {}
    for tgt, slots in ptr_idx.items():
        for s in slots:
            out[s] = tgt
    return out


def expand_vtable(ptr_idx, slot_to_target, anchor_slot, max_back=64, max_fwd=256):
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


def find_func_start(prologs_sorted, ia):
    import bisect
    idx = bisect.bisect_right(prologs_sorted, ia) - 1
    if idx >= 0:
        return prologs_sorted[idx]
    return ia & ~0xF


def analyze_at(text, ts, func_start, max_instr=300):
    off = (func_start - ts) // 4
    n = len(text) // 4
    n_bl = 0
    n_ret = 0
    n_str_x0 = 0
    calls = []
    for i in range(off, min(off + max_instr, n)):
        w = struct.unpack_from("<I", text, i * 4)[0]
        if is_bl(w):
            n_bl += 1
            calls.append(decode_bl_target(w, ts + i * 4))
        elif w == 0xD65F03C0:
            n_ret += 1
        elif (w & 0xFFC00000) == 0xF9000000 and (w & 0x1F) == 0:
            n_str_x0 += 1
    return {"n_bl": n_bl, "n_ret": n_ret, "n_str_x0": n_str_x0, "calls": calls}


def log_init_offsets(raw_bytes, base):
    """Залогируем первые 64 байта с несколькими интерпретациями."""
    log("__init_offsets raw sample (first 64 bytes):")
    chunk = raw_bytes[:64]
    log("  hex: %s" % chunk.hex())
    log("  as u32 LE:")
    for i in range(min(16, len(chunk)//4)):
        v32 = struct.unpack_from("<I", chunk, i*4)[0]
        va = base + v32
        in_text = 0x100004000 <= va < 0x100d8af60
        log("    [%2d] u32=0x%08x  va=0x%x  in_text=%s" % (i, v32, va, in_text))
    log("  as u64 LE with chained decode:")
    for i in range(min(8, len(chunk)//8)):
        v64 = struct.unpack_from("<Q", chunk, i*8)[0]
        bind, nxt, target = decode_chained(v64)
        log("    [%2d] u64=0x%016x  bind=%d next=0x%x target=0x%x" % (i, v64, bind, nxt, target))


def main():
    global _log_fh
    try:
        _log_fh = open(DETAIL, "w")
    except Exception:
        _log_fh = None

    log("=== find_offsets_r2 v12 (chained fixups) ===")
    log("bin: %s" % BIN)

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
    log("[*] total string addrs: %d" % len(target_set_strings))

    sections = get_sections(r2)
    text_b, data_secs = pick_sections(sections)
    if not text_b:
        return
    ts, te = text_b
    log("[*] .text: 0x%x - 0x%x (size 0x%x)" % (ts, te, te - ts))

    t0 = time.time()
    text = load_range(r2, ts, te - ts)
    log("[*] loaded .text %d bytes in %.1fs" % (len(text or b""), time.time() - t0))
    if not text:
        return

    t0 = time.time()
    data_blobs = []
    for va, sz, n in data_secs:
        b = load_range(r2, va, sz)
        if b:
            data_blobs.append((va, b))
    log("[*] loaded data %d bytes in %.1fs"
        % (sum(len(b) for _, b in data_blobs), time.time() - t0))

    t0 = time.time()
    ptr_idx, total_slots = build_ptr_index(data_blobs, ts, te)
    log("[*] ptr index (chained): %d unique targets, %d slots in %.1fs"
        % (len(ptr_idx), total_slots, time.time() - t0))
    slot_to_target = build_slot_to_target(ptr_idx)

    t0 = time.time()
    adrp_add, bl_map, prologs = scan_text(text, ts)
    prologs_sorted = sorted(prologs)
    log("[*] scan_text: adrp_add=%d bl=%d prologs=%d in %.1fs"
        % (len(adrp_add), len(bl_map), len(prologs), time.time() - t0))

    # __init_offsets — raw bytes для дампа и парсинга
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
    log("[*] __init_offsets raw size: %d" % len(init_raw))
    if init_raw:
        log_init_offsets(init_raw, base)

    # вычислим init_offsets как 4-байтные offset от base
    init_funcs = []
    for i in range(len(init_raw) // 4):
        v32 = struct.unpack_from("<I", init_raw, i * 4)[0]
        va = base + v32
        if ts <= va < te:
            init_funcs.append(va)
    log("[*] __init_offsets as u32 offset from base -> %d valid funcs" % len(init_funcs))

    # также попробуем как 8-байтные chained
    init_funcs_chained = []
    for i in range(len(init_raw) // 8):
        v64 = struct.unpack_from("<Q", init_raw, i * 8)[0]
        bind, nxt, target = decode_chained(v64)
        if bind == 0 and ts <= target < te:
            init_funcs_chained.append(target)
    log("[*] __init_offsets as u64 chained -> %d valid funcs" % len(init_funcs_chained))

    r2.quit()

    # карта: string_addr -> [func_addr, ...], где func ссылается на строку
    str_to_anchor_funcs = {}
    for pc, tgt in adrp_add:
        if tgt in target_set_strings:
            f = find_func_start(prologs_sorted, pc)
            str_to_anchor_funcs.setdefault(tgt, set()).add(f)

    # карта vtable: vt_start -> slots
    # для каждой anchor_func ищем её slot в data (ptr_idx) -> vtable
    anchor_to_vtable = {}
    all_vt_starts = set()
    for tgt, slots in ptr_idx.items():
        # пробуем расширить от каждого слота
        for slot in slots[:3]:
            vt = expand_vtable(ptr_idx, slot_to_target, slot)
            if vt:
                anchor_to_vtable[tgt] = vt[0]
                all_vt_starts.add(vt[0])
                break
    log("[*] anchors with vtable: %d, unique vtables: %d"
        % (len(anchor_to_vtable), len(all_vt_starts)))

    # ищем xref на vtable_start через adrp_add
    vt_to_ctors = {}
    for pc, tgt in adrp_add:
        if tgt in all_vt_starts:
            f = find_func_start(prologs_sorted, pc)
            vt_to_ctors.setdefault(tgt, set()).add(f)
    log("[*] vtables with ctor xref: %d" % len(vt_to_ctors))

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

        # 1) ищем anchor funcs по строкам класса
        anchor_funcs = set()
        for sa in addrs:
            for af in str_to_anchor_funcs.get(sa, []):
                anchor_funcs.add(af)

        ctor_candidates = []

        # 2) от каждой anchor_func -> vtable -> ctor
        for af in anchor_funcs:
            vt = anchor_to_vtable.get(af)
            if vt:
                for ctor in vt_to_ctors.get(vt, []):
                    info = analyze_at(text, ts, ctor)
                    score = info["n_bl"] * 3
                    if info["n_str_x0"] > 0:
                        score += 20
                    if ctor in init_funcs or ctor in init_funcs_chained:
                        score += 200
                    ctor_candidates.append({
                        "func": ctor, "score": score, "vtable": vt,
                        "via": "vtable", "n_bl": info["n_bl"],
                    })

        # 3) fallback: anchor_func из init_offsets
        if not ctor_candidates:
            for io in init_funcs + init_funcs_chained:
                for af in anchor_funcs:
                    if abs(io - af) < 0x800:
                        ctor_candidates.append({
                            "func": io, "score": 50, "vtable": None,
                            "via": "init_near", "n_bl": 0,
                        })
                        break
                if ctor_candidates:
                    break

        if not ctor_candidates:
            results.append({"class": cls, "ctor": None, "src": "unresolved"})
            log("[%s] unresolved" % cls)
            continue

        ctor_candidates.sort(key=lambda x: -x["score"])
        for i, c in enumerate(ctor_candidates[:3]):
            log("[%s]   [%d] score=%d ctor=0x%x vt=0x%x via=%s n_bl=%d"
                % (cls, i, c["score"], c["func"],
                   c.get("vtable") or 0, c["via"], c["n_bl"]))

        best = ctor_candidates[0]
        results.append({
            "class": cls, "ctor": best["func"] - base, "score": best["score"],
            "vtable": (best["vtable"] - base) if best["vtable"] else None,
            "src": best["via"],
        })
        log("[%s] ctor=0x%x via=%s" % (cls, best["func"], best["via"]))

    try:
        with open(REPORT, "w") as fh:
            fh.write("# r2 ctor resolution (v12)\n")
            fh.write("# base=0x%x\n\n" % base)
            for r in results:
                fh.write("=== %s ===\n" % r["class"])
                if r.get("ctor") is not None:
                    fh.write("  ctor:   rva=0x%08x\n" % r["ctor"])
                if r.get("vtable") is not None:
                    fh.write("  vtable: rva=0x%08x\n" % r["vtable"])
                fh.write("  src=%s score=%d\n" % (r.get("src", ""), r.get("score", 0)))
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