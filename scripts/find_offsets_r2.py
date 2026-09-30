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
TEXT = None
TEXT_ADDR = 0


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
    for b in ("log", "print", "trace", "assert", "debug", "fatal",
              "panic", "abort", "warn", "error"):
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


def get_sections(r2):
    return cmdj(r2, "iSj") or []


def get_text_bounds(sections):
    for s in sections:
        n = s.get("name", "") or ""
        p = s.get("perm", "") or ""
        if ("__text" in n or ".text" in n) and "x" in p:
            return (s.get("vaddr", 0), s.get("vaddr", 0) + s.get("size", 0))
    return None


# --- ARM64 ---

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


def is_bl(w):
    return (w & 0xFC000000) == 0x94000000


def decode_bl_target(w, pc):
    offset = w & 0x3FFFFFF
    if offset & (1 << 25):
        offset -= (1 << 26)
    return pc + (offset << 2)


def load_text(r2, ts, te):
    """Загружаем .text в память одним куском."""
    CHUNK = 0x400000
    chunks = []
    addr = ts
    while addr < te:
        n = min(CHUNK, te - addr)
        hx = cmd(r2, "p8 %d @ 0x%x" % (n, addr)).strip()
        if not hx:
            log("[!] p8 empty at 0x%x" % addr)
            return b""
        try:
            chunks.append(bytes.fromhex(hx))
        except Exception:
            log("[!] hex parse failed at 0x%x" % addr)
            return b""
        addr += n
    return b"".join(chunks)


def build_bl_index(text, ts):
    """Строит index: target_addr -> [pc_addr, ...]. Один проход по всему .text."""
    n = len(text) // 4
    idx = {}
    for i in range(n):
        w = struct.unpack_from("<I", text, i * 4)[0]
        if is_bl(w):
            pc = ts + i * 4
            tgt = decode_bl_target(w, pc)
            if tgt > 0x100000000:
                idx.setdefault(tgt, []).append(pc)
    return idx


def scan_adrp_add(text, ts, target_set):
    n = len(text) // 4
    results = {}
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
                            results.setdefault(target, []).append(ia)
                        break
    return results


def is_stp_x29_x30_preindex(w):
    return (w & 0xFFC07FFF) == 0xA9807BFD


def is_stp_x29_x30_offset(w):
    return (w & 0xFFC07FFF) == 0xA9007BFD


def find_func_start_backwards(text, ia, ts, max_back=0x2000):
    """Ищем stp x29, x30 [sp, #...]! назад от ia."""
    off = ia - ts
    max_off = min(off, max_back)
    start = off - max_off
    start = start & ~3
    i = off // 4
    j = start // 4
    while i >= j:
        w = struct.unpack_from("<I", text, i * 4)[0]
        if is_stp_x29_x30_preindex(w) or is_stp_x29_x30_offset(w):
            return ts + i * 4
        i -= 1
    return ia & ~0xF  # fallback


def analyze_at(text, ts, func_start, max_instr=200):
    """Мини-анализ: идём по инструкциям от func_start, собираем bl-таргеты, ret."""
    off = (func_start - ts) // 4
    n = len(text) // 4
    calls = []
    n_ret = 0
    n_bl = 0
    n_str_x0 = 0
    n_ctor = 0
    for i in range(off, min(off + max_instr, n)):
        w = struct.unpack_from("<I", text, i * 4)[0]
        pc = ts + i * 4
        if is_bl(w):
            tgt = decode_bl_target(w, pc)
            calls.append(tgt)
            n_bl += 1
        elif w == 0xD65F03C0:  # ret
            n_ret += 1
            if n_bl == 0 and i > off + 4:
                break
        # str x0, [xN, #imm]
        elif (w & 0xFFC00000) == 0xF9000000:
            rt = w & 0x1F
            if rt == 0:
                n_str_x0 += 1
    return {
        "n_bl": n_bl,
        "n_ret": n_ret,
        "n_str_x0": n_str_x0,
        "calls": calls,
    }


def scan_class(r2, cls, str_index, adrp_hits, bl_index, text, ts, te, init_offsets, base):
    addrs = []
    for s, al in str_index.items():
        if s == cls or s.startswith(cls + "::") or ("::" + cls) in s \
           or s.startswith(cls + " ") or s.startswith(cls + "\t"):
            addrs.extend(al)
    if not addrs:
        return None

    # якоря — функции, что ADRP+ADD ссылаются на строку класса
    anchor_addrs = set()
    for sa in addrs:
        for ia in adrp_hits.get(sa, []):
            fstart = find_func_start_backwards(text, ia, ts)
            anchor_addrs.add(fstart)

    if not anchor_addrs:
        log("[%s] no anchor funcs" % cls)
        return {"class": cls, "method": None, "vtable": None, "ctor": None}

    log("[%s] anchors: %s" % (cls, ["0x%x" % a for a in list(anchor_addrs)[:4]]))

    # для каждого якоря: кто вызывает его через bl?
    caller_funcs = {}
    for af in anchor_addrs:
        callers = bl_index.get(af, [])
        for pc in callers:
            cf = find_func_start_backwards(text, pc, ts)
            caller_funcs.setdefault(cf, set()).add(af)

    if not caller_funcs:
        log("[%s] no callers via bl" % cls)
        # fallback — сам якорь
        af = list(anchor_addrs)[0]
        info = analyze_at(text, ts, af)
        return {
            "class": cls, "method": (af - base, ""),
            "vtable": None, "ctor": (af - base, ""),
            "score": -50, "src": "anchor_fallback",
            "n_call": info["n_bl"], "size": 0,
        }

    log("[%s] callers: %d" % (cls, len(caller_funcs)))

    init_set = set(init_offsets)
    candidates = []
    for cf, targets in caller_funcs.items():
        info = analyze_at(text, ts, cf)
        # score
        score = 0
        if cf in init_set:
            score += 100
        if info["n_bl"] >= 2:
            score += 20
        if info["n_bl"] >= 5:
            score += 20
        if info["n_str_x0"] > 0:
            score += 10
        if info["n_ret"] >= 1:
            score += 5
        if info["n_bl"] == 0:
            score -= 30
        # сколько наших якорей вызывает — чем больше, тем скорее это ctor
        score += len(targets) * 15
        candidates.append({
            "func": cf, "score": score, "info": info,
            "targets": targets, "in_init": cf in init_set,
        })

    candidates.sort(key=lambda x: -x["score"])
    log("[%s] top-3:" % cls)
    for i, c in enumerate(candidates[:3]):
        log("[%s]   [%d] score=%d func=0x%x n_bl=%d in_init=%s targets=%d"
            % (cls, i, c["score"], c["func"], c["info"]["n_bl"],
               c["in_init"], len(c["targets"])))

    best = candidates[0]
    return {
        "class": cls,
        "method": (best["func"] - base, ""),
        "ctor": (best["func"] - base, ""),
        "vtable": None,
        "score": best["score"],
        "src": "init_offsets" if best["in_init"] else "caller",
        "n_call": best["info"]["n_bl"],
        "size": 0,
    }


def main():
    global _log_fh, TEXT, TEXT_ADDR
    try:
        _log_fh = open(DETAIL, "w")
    except Exception:
        _log_fh = None

    log("=== find_offsets_r2 v9 ===")
    log("bin: %s" % BIN)

    r2 = r2pipe.open(BIN, flags=["-2"])
    for opt in (
        "e scr.color=0",
        "e anal.timeout=1800",
        "e asm.arch=arm",
        "e asm.bits=64",
    ):
        r2.cmd(opt)

    info = cmdj(r2, "ij")
    base = (info or {}).get("baddr", 0x100000000) or 0x100000000
    log("base: 0x%x" % base)

    str_index = build_string_index(r2, base)
    if not str_index:
        log("[!] empty string index")
        return

    target_set = set()
    for al in str_index.values():
        for a in al:
            target_set.add(a)
    log("[*] total string addrs: %d" % len(target_set))

    sections = get_sections(r2)
    text_b = get_text_bounds(sections)
    if not text_b:
        log("[!] .text not found")
        r2.quit()
        return
    ts, te = text_b
    log("[*] .text: 0x%x - 0x%x (size 0x%x)" % (ts, te, te - ts))

    t0 = time.time()
    text = load_text(r2, ts, te)
    log("[*] loaded %d bytes in %.1fs" % (len(text), time.time() - t0))
    if not text:
        r2.quit()
        return
    TEXT = text
    TEXT_ADDR = ts

    t0 = time.time()
    bl_index = build_bl_index(text, ts)
    log("[*] bl index: %d unique targets, %d total calls in %.1fs"
        % (len(bl_index), sum(len(v) for v in bl_index.values()),
           time.time() - t0))

    t0 = time.time()
    adrp_hits = scan_adrp_add(text, ts, target_set)
    log("[*] adrp+add hits: %d in %.1fs"
        % (sum(len(v) for v in adrp_hits.values()), time.time() - t0))

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
    log("[*] __init_offsets entries: %d" % len(init_offsets))

    r2.quit()

    results = []
    for cls in CLASSES:
        if time.time() - START > BUDGET - 60:
            log("[!] budget exhausted before %s" % cls)
            break
        try:
            r = scan_class(r2, cls, str_index, adrp_hits, bl_index, text,
                           ts, te, init_offsets, base)
        except Exception as e:
            log("[%s] EXCEPTION: %s" % (cls, e))
            traceback.print_exc()
            continue
        if r:
            results.append(r)

    try:
        with open(REPORT, "w") as fh:
            fh.write("# r2 ctor resolution (v9, manual bl scan)\n")
            fh.write("# base=0x%x\n\n" % base)
            for r in results:
                fh.write("=== %s ===\n" % r["class"])
                if r.get("ctor"):
                    fh.write("  ctor:  rva=0x%08x\n" % r["ctor"][0])
                if r.get("score") is not None:
                    fh.write("  score: %d  src=%s n_bl=%d\n"
                             % (r["score"], r.get("src", ""), r.get("n_call", 0)))
                fh.write("\n")
    except Exception as e:
        log("write REPORT failed: %s" % e)

    try:
        with open(OUT, "w") as fh:
            fh.write("export const ctors = Object.freeze({\n")
            for r in results:
                if r.get("ctor"):
                    fh.write("  %s: 0x%x,\n" % (r["class"], r["ctor"][0]))
                else:
                    fh.write("  // %s: unresolved\n" % r["class"])
            fh.write("});\n")
    except Exception as e:
        log("write OUT failed: %s" % e)

    log("[+] wrote %s and %s" % (OUT, REPORT))
    log("[+] total time %.1fs" % (time.time() - START))


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        log("FATAL: %s" % e)
        traceback.print_exc()