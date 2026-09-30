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
    """Один проход: собираем все adrp+add, bl, str xN,[x0,#imm], prolog-адреса."""
    n = len(text) // 4
    adrp_add = []  # list of (instr_addr, target)
    bl_targets = {}  # src_pc -> target
    prologs = set()
    str_x0_offsets = []  # list of (instr_addr, reg_from_adrp)
    i = 0
    while i < n:
        w = struct.unpack_from("<I", text, i * 4)[0]
        pc = ts + i * 4

        if is_stp_x29_x30_preindex(w):
            prologs.add(pc)

        if is_adrp(w):
            rd_adrp = w & 0x1F
            page = decode_adrp_imm(w, pc)
            for j in range(i + 1, min(i + 6, n)):
                w2 = struct.unpack_from("<I", text, j * 4)[0]
                if is_add_imm64(w2):
                    rd, rn, imm = decode_add_imm(w2)
                    if rd == rd_adrp and rn == rd_adrp:
                        target = page + imm
                        adrp_add.append((pc, target))
                        break
            i += 1
            continue

        if is_bl(w):
            bl_targets[pc] = decode_bl_target(w, pc)

        # str xN, [x0, #imm]   (64-bit store)
        if (w & 0xFFC00000) == 0xF9000000:
            rn = (w >> 5) & 0x1F
            rt = w & 0x1F
            imm12 = (w >> 10) & 0xFFF
            if rn == 0:
                str_x0_offsets.append((pc, rt, imm12 * 8))
        i += 1
    return adrp_add, bl_targets, prologs, str_x0_offsets


def find_func_start(prologs_sorted, ia):
    """Ищем ближайший prolog <= ia."""
    import bisect
    idx = bisect.bisect_right(prologs_sorted, ia) - 1
    if idx >= 0:
        return prologs_sorted[idx]
    return ia & ~0xF


def dump_data_sample(data_blobs, n_slots=8):
    log("[*] data dump (first %d slots each section):" % n_slots)
    for va, b in data_blobs:
        log("  section @ 0x%x size 0x%x" % (va, len(b)))
        for i in range(min(n_slots, len(b) // 8)):
            raw = b[i*8:(i+1)*8]
            v = struct.unpack_from("<Q", raw, 0)[0]
            chained_target = v & 0xFFFFFFFFF
            next_ = (v >> 51) & 0xFFF
            bind = (v >> 63) & 1
            pac_masked = v & 0x0000FFFFFFFFFFFF
            log("    [%2d] raw=%s u64=0x%016x chained_t=0x%x next=0x%x bind=%d pac_masked=0x%x"
                % (i, raw.hex(), v, chained_target, next_, bind, pac_masked))


def load_init_offsets(r2, sections):
    out = []
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
                            out.append(p)
                except Exception:
                    pass
    return out


def analyze_init_functions(text, ts, init_offsets, adrp_add, bl_map, prologs_sorted,
                           data_bounds, target_set_strings, target_set_data):
    """Для каждой init-функции: дизасм 400 инстр, собираем bl, adrp+add, str x0."""
    n = len(text) // 4
    adrp_map = {}
    for pc, tgt in adrp_add:
        adrp_map.setdefault(pc, []).append(tgt)
    bl_map_local = {}
    for src, tgt in bl_map.items():
        bl_map_local[src] = tgt

    results = []
    for f in init_offsets:
        off = (f - ts) // 4
        n_call = 0
        calls = []
        n_str_x0 = 0
        data_refs = []
        string_refs = []
        cnt = 0
        for i in range(off, min(off + 400, n)):
            pc = ts + i * 4
            if pc in adrp_map:
                for tgt in adrp_map[pc]:
                    if tgt in target_set_strings:
                        string_refs.append(tgt)
                    elif tgt in target_set_data:
                        data_refs.append(tgt)
            if pc in bl_map_local:
                tgt = bl_map_local[pc]
                n_call += 1
                calls.append(tgt)
            w = struct.unpack_from("<I", text, i * 4)[0]
            if (w & 0xFFC00000) == 0xF9000000:
                rn = (w >> 5) & 0x1F
                if rn == 0:
                    n_str_x0 += 1
            if w == 0xD65F03C0:  # ret
                break
            cnt += 1
            if cnt > 400:
                break
        results.append({
            "func": f,
            "n_call": n_call,
            "calls": calls,
            "n_str_x0": n_str_x0,
            "data_refs": data_refs,
            "string_refs": string_refs,
        })
    return results


def main():
    global _log_fh
    try:
        _log_fh = open(DETAIL, "w")
    except Exception:
        _log_fh = None

    log("=== find_offsets_r2 v11 (init_offsets ctors) ===")
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
        log("[!] no .text")
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

    dump_data_sample(data_blobs, 8)

    target_set_data = set()
    for va, b in data_blobs:
        for i in range(len(b) // 8):
            tgt = struct.unpack_from("<Q", b, i*8)[0]
            if ts <= tgt < te:
                target_set_data.add(tgt)
    log("[*] total data slots pointing to .text: %d" % len(target_set_data))

    t0 = time.time()
    adrp_add, bl_map, prologs, str_x0_offsets = scan_text(text, ts)
    prologs_sorted = sorted(prologs)
    log("[*] scan_text: adrp_add=%d bl=%d prologs=%d str_x0=%d in %.1fs"
        % (len(adrp_add), len(bl_map), len(prologs), len(str_x0_offsets),
           time.time() - t0))

    init_offsets = load_init_offsets(r2, sections)
    init_set = set(init_offsets)
    log("[*] __init_offsets: %d entries" % len(init_offsets))

    t0 = time.time()
    init_info = analyze_init_functions(text, ts, init_offsets, adrp_add,
                                       bl_map, prologs_sorted,
                                       None, target_set_strings, target_set_data)
    log("[*] analyzed %d init functions in %.1fs" % (len(init_info), time.time() - t0))

    # ctor-подобные: n_call >= 1, есть str x0, есть data_refs ИЛИ string_refs
    ctor_like = []
    for r in init_info:
        score = 0
        if r["n_str_x0"] > 0:
            score += 30
        if r["data_refs"]:
            score += 20
        if r["string_refs"]:
            score += 15
        score += min(r["n_call"], 15) * 2
        if r["n_call"] == 0:
            score -= 30
        r["score"] = score
        ctor_like.append(r)
    ctor_like.sort(key=lambda x: -x["score"])

    log("[*] top-10 init funcs by score:")
    for i, c in enumerate(ctor_like[:10]):
        log("    [%d] score=%d func=0x%x n_call=%d n_str_x0=%d data_refs=%d string_refs=%d"
            % (i, c["score"], c["func"], c["n_call"], c["n_str_x0"],
               len(c["data_refs"]), len(c["string_refs"])))

    # индексы: какая строка класса в какой init-функции встречается
    str_to_init = {}
    for c in ctor_like:
        for t in c["string_refs"]:
            str_to_init.setdefault(t, []).append(c["func"])

    # мапим класс -> ctor
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
        # ищем init-функцию, которая ссылается на одну из этих строк
        found = []
        for sa in addrs:
            for f in str_to_init.get(sa, []):
                info = next((x for x in ctor_like if x["func"] == f), None)
                found.append((f, info["score"] if info else 0, sa))
        if found:
            found.sort(key=lambda x: -x[1])
            f, score, sa = found[0]
            results.append({
                "class": cls, "ctor": f - base, "score": score,
                "src": "init_string",
            })
            log("[%s] ctor=0x%x via string=0x%x score=%d"
                % (cls, f, sa, score))
            continue
        # fallback — ищем init_offset в радиусе ±0x400 от якорь-функции
        anchor_funcs = set()
        for sa in addrs:
            for pc, tgt in adrp_add:
                if tgt == sa:
                    anchor_funcs.add(find_func_start(prologs_sorted, pc))
        nearest = None
        for af in anchor_funcs:
            for io in init_offsets:
                d = abs(io - af)
                if d < 0x400 and (nearest is None or d < nearest[1]):
                    nearest = (io, d)
            if nearest:
                break
        if nearest:
            results.append({
                "class": cls, "ctor": nearest[0] - base,
                "score": 50, "src": "init_near_anchor",
            })
            log("[%s] ctor=0x%x via init_near_anchor dist=0x%x"
                % (cls, nearest[0], nearest[1]))
            continue
        results.append({"class": cls, "ctor": None, "src": "unresolved"})
        log("[%s] unresolved" % cls)

    r2.quit()

    try:
        with open(REPORT, "w") as fh:
            fh.write("# r2 ctor resolution (v11)\n")
            fh.write("# base=0x%x\n\n" % base)
            for r in results:
                fh.write("=== %s ===\n" % r["class"])
                if r.get("ctor"):
                    fh.write("  ctor:  rva=0x%08x\n" % r["ctor"])
                fh.write("  src:   %s  score=%d\n"
                         % (r.get("src", ""), r.get("score", 0)))
                fh.write("\n")
    except Exception as e:
        log("report: %s" % e)

    try:
        with open(OUT, "w") as fh:
            fh.write("export const ctors = Object.freeze({\n")
            for r in results:
                if r.get("ctor"):
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