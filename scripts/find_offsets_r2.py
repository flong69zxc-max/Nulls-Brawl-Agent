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


def get_data_bounds_list(sections):
    out = []
    for s in sections:
        n = s.get("name", "") or ""
        p = s.get("perm", "") or ""
        if "x" in p:
            continue
        if "w" not in p and "r" not in p:
            continue
        if ("const" in n or "data" in n or "got" in n):
            va = s.get("vaddr", 0)
            sz = s.get("size", 0)
            if va and sz > 0:
                out.append((va, sz, n))
    return out


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


def scan_adrp_add(r2, ts, te, target_set):
    CHUNK = 0x100000
    overlap = 32
    results = {}
    addr = ts
    carry = b""
    carry_addr = ts
    while addr < te:
        if time.time() - START > BUDGET - 500:
            break
        size = min(CHUNK, te - addr)
        hx = cmd(r2, "p8 %d @ 0x%x" % (size, addr)).strip()
        if not hx:
            addr += size
            continue
        try:
            data = bytes.fromhex(hx)
        except Exception:
            addr += size
            continue
        data = carry + data
        data_start = carry_addr
        n = len(data) // 4
        for i in range(n):
            off = i * 4
            w = struct.unpack_from("<I", data, off)[0]
            ia = data_start + off
            if is_adrp(w):
                rd_adrp = w & 0x1F
                page = decode_adrp_imm(w, ia)
                for j in range(i + 1, min(i + 7, n)):
                    w2 = struct.unpack_from("<I", data, j * 4)[0]
                    if is_add_imm64(w2):
                        rd, rn, imm = decode_add_imm(w2)
                        if rd == rd_adrp and rn == rd_adrp:
                            target = page + imm
                            if target in target_set:
                                results.setdefault(target, []).append(ia)
                            break
        carry = data[-overlap:] if len(data) > overlap else data
        carry_addr = addr + size - len(carry)
        addr += size
    return results


def find_vtable_in_data(r2, func_addr, data_secs):
    hits = []
    needle_hex = "%016x" % (func_addr & 0xFFFFFFFFFFFFFFFF)
    res = cmdj(r2, "/v8 %s" % needle_hex)
    if res and isinstance(res, list):
        for h in res:
            if isinstance(h, dict) and "addr" in h:
                hits.append((h["addr"], ""))
        return hits
    for va, sz, name in data_secs:
        res = cmdj(r2, "/v8 %s @ 0x%x" % (needle_hex, va))
        if res and isinstance(res, list):
            for h in res:
                if isinstance(h, dict) and "addr" in h:
                    hits.append((h["addr"], name))
    return hits


def expand_vtable(r2, anchor):
    PTR = 8
    back_off = 0x800
    fwd_off = 0x1000
    start = anchor

    hx = cmd(r2, "p8 %d @ 0x%x" % (back_off, anchor - back_off)).strip()
    if hx:
        try:
            b = bytes.fromhex(hx)
            n = len(b) // 8
            for i in range(n - 1, -1, -1):
                v = struct.unpack_from("<Q", b, i * 8)[0]
                if v == 0:
                    break
                if v < 0x100000000:
                    break
                start = anchor - back_off + i * 8
        except Exception:
            pass

    slots = []
    hx = cmd(r2, "p8 %d @ 0x%x" % (fwd_off, start)).strip()
    if hx:
        try:
            b = bytes.fromhex(hx)
            n = len(b) // 8
            for i in range(n):
                v = struct.unpack_from("<Q", b, i * 8)[0]
                if v == 0:
                    break
                slots.append((start + i * 8, v))
        except Exception:
            pass
    return start, slots


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
        return (f[0].get("offset", 0), f[0].get("name", ""))
    if isinstance(f, dict):
        return (f.get("offset", 0), f.get("name", ""))
    return None


def analyze_function(r2, func_addr):
    fj = cmdj(r2, "afij @ 0x%x" % func_addr)
    if not fj:
        return None
    if isinstance(fj, list):
        f0 = None
        for x in fj:
            if x.get("offset", 0) == func_addr:
                f0 = x
                break
        if f0 is None:
            f0 = fj[0]
    else:
        f0 = fj
    size = f0.get("size", 0)
    if size <= 0 or size > 0x10000:
        return None
    n_show = min(size // 4 + 4, 500)
    ops = cmdj(r2, "pdj %d @ 0x%x" % (n_show, func_addr))
    if not ops:
        return None
    n_call = 0
    n_ret = 0
    n_str_x0 = 0
    for o in ops:
        t = o.get("type", "")
        if t == "call":
            n_call += 1
        elif t == "ret":
            n_ret += 1
        dis = (o.get("disasm") or "").strip()
        if dis.startswith("str x0,"):
            n_str_x0 += 1
    return {
        "func": func_addr,
        "size": size,
        "ninstr": len(ops),
        "n_call": n_call,
        "n_ret": n_ret,
        "n_str_x0": n_str_x0,
    }


def score_function(info):
    if not info:
        return -999
    s = 0
    s += min(info["n_call"], 40) * 3
    if info["n_call"] == 0:
        s -= 30
    if info["n_ret"] > 1:
        s -= 15
    if info["ninstr"] < 20:
        s -= 25
    if info["ninstr"] > 500:
        s -= 10
    s += info["n_str_x0"] * 2
    return s


def find_xrefs_to(r2, addr):
    x = cmdj(r2, "axtj @ 0x%x" % addr)
    if x:
        return [xx.get("from") for xx in x if xx.get("from")]
    return []


def scan_class_via_vtable(r2, cls, anchor_func, data_secs, base):
    log("[%s] looking for vtable containing func 0x%x" % (cls, anchor_func))
    vt_hits = find_vtable_in_data(r2, anchor_func, data_secs)
    if not vt_hits:
        log("[%s] no vtable hits for 0x%x" % (cls, anchor_func))
        return None

    log("[%s] vtable candidates: %d" % (cls, len(vt_hits)))
    for v, name in vt_hits[:5]:
        log("[%s]   slot in %s @ 0x%x" % (cls, name or "?", v))

    start, slots = expand_vtable(r2, vt_hits[0][0])
    log("[%s] expanded vtable: start=0x%x slots=%d" % (cls, start, len(slots)))

    xrefs = find_xrefs_to(r2, start)
    if not xrefs:
        log("[%s] axtj on vtable 0x%x empty" % (cls, start))
        return None

    log("[%s] xrefs on vtable start: %d" % (cls, len(xrefs)))
    cands = []
    for xr in xrefs:
        f = get_function_at(r2, xr)
        if not f:
            continue
        if is_logger(f[1]):
            continue
        info = analyze_function(r2, f[0])
        if not info:
            continue
        info["score"] = score_function(info)
        info["via"] = "vtable"
        info["vtable"] = start
        info["name"] = f[1]
        cands.append(info)
    return cands


def scan_class_via_init(r2, cls, anchor_funcs, init_offsets, base):
    anchor_set = set(anchor_funcs)
    cands = []
    for io in init_offsets[:400]:
        if time.time() - START > BUDGET - 200:
            break
        f_io = get_function_at(r2, io)
        if not f_io:
            continue
        if is_logger(f_io[1]):
            continue
        ops = cmdj(r2, "pdj 80 @ 0x%x" % f_io[0])
        if not ops:
            continue
        calls = []
        for o in ops:
            if o.get("type") == "call":
                tgt = o.get("jump", 0) or o.get("ptr", 0)
                if tgt:
                    calls.append(tgt)
        hit_anchor = False
        for c in calls:
            if c in anchor_set:
                hit_anchor = True
                break
        if not hit_anchor:
            continue
        for c in calls:
            if c in anchor_set:
                continue
            cf = get_function_at(r2, c)
            if not cf:
                continue
            if is_logger(cf[1]):
                continue
            info = analyze_function(r2, cf[0])
            if not info:
                continue
            info["score"] = score_function(info) + 50
            info["via"] = "init_offsets"
            info["name"] = cf[1]
            cands.append(info)
    return cands


def scan_class(r2, cls, str_index, adrp_hits, data_secs, init_offsets, base):
    addrs = []
    strings_used = []
    for s, al in str_index.items():
        if s == cls or s.startswith(cls + "::") or ("::" + cls) in s \
           or s.startswith(cls + " ") or s.startswith(cls + "\t"):
            addrs.extend(al)
            strings_used.append(s)
    if not addrs:
        log("[%s] no string anchors" % cls)
        return None

    log("[%s] string anchors: %d" % (cls, len(addrs)))
    for s in strings_used[:3]:
        log("[%s]   text: %r" % (cls, s[:80]))

    anchor_funcs = []
    for sa in addrs:
        for ia in adrp_hits.get(sa, []):
            f = get_function_at(r2, ia)
            if not f:
                r2.cmd("af @ 0x%x" % ia)
                f = get_function_at(r2, ia)
            if f:
                anchor_funcs.append(f[0])

    if not anchor_funcs:
        log("[%s] no anchor funcs" % cls)
        return {"class": cls, "method": None, "vtable": None, "ctor": None}

    log("[%s] anchor funcs: %s" % (cls, ["0x%x" % a for a in anchor_funcs[:5]]))

    candidates = []
    for af in anchor_funcs[:3]:
        if time.time() - START > BUDGET - 120:
            break
        res = scan_class_via_vtable(r2, cls, af, data_secs, base)
        if res:
            candidates.extend(res)

    if not candidates:
        log("[%s] vtable path failed, trying init_offsets ..." % cls)
        res = scan_class_via_init(r2, cls, anchor_funcs, init_offsets, base)
        if res:
            candidates.extend(res)

    if not candidates:
        af = anchor_funcs[0]
        info = analyze_function(r2, af)
        if info:
            info["score"] = score_function(info) - 50
            info["via"] = "anchor_fallback"
            info["name"] = "anchor"
            candidates.append(info)

    candidates.sort(key=lambda x: -x["score"])

    log("[%s] top-3:" % cls)
    for i, c in enumerate(candidates[:3]):
        log("[%s]   [%d] score=%d func=0x%x (%s) size=%d ninstr=%d n_call=%d via=%s"
            % (cls, i, c["score"], c["func"], c["name"], c["size"],
               c["ninstr"], c["n_call"], c["via"]))

    best = candidates[0]
    return {
        "class": cls,
        "method": (best["func"] - base, best["name"]),
        "ctor": (best["func"] - base, best["name"]),
        "vtable": (best.get("vtable", 0) - base) if best.get("vtable") else None,
        "score": best["score"],
        "src": best["via"],
        "n_call": best["n_call"],
        "size": best["size"],
    }


def main():
    global _log_fh
    try:
        _log_fh = open(DETAIL, "w")
    except Exception:
        _log_fh = None

    log("=== find_offsets_r2 v8 ===")
    log("bin: %s" % BIN)

    r2 = r2pipe.open(BIN, flags=["-2"])
    for opt in (
        "e scr.color=0",
        "e anal.timeout=1800",
        "e anal.hasnext=true",
        "e anal.strings=true",
        "e anal.autoname=true",
        "e anal.arm64.preludes=true",
        "e anal.refstr=true",
        "e asm.arch=arm",
        "e asm.bits=64",
    ):
        r2.cmd(opt)
    try:
        r2.cmd("e anal.arch=arm")
    except Exception:
        pass

    info = cmdj(r2, "ij")
    base = (info or {}).get("baddr", 0x100000000) or 0x100000000
    log("base: 0x%x" % base)

    t0 = time.time()
    r2.cmd("aaa")
    log("aaa %.1fs" % (time.time() - t0))
    t0 = time.time()
    r2.cmd("aac")
    log("aac %.1fs" % (time.time() - t0))

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
    text = get_text_bounds(sections)
    if not text:
        log("[!] .text not found")
        r2.quit()
        return
    ts, te = text
    log("[*] .text: 0x%x - 0x%x (size 0x%x)" % (ts, te, te - ts))

    data_secs = get_data_bounds_list(sections)
    log("[*] data sections:")
    for va, sz, n in data_secs:
        log("    %s @ 0x%x size 0x%x" % (n, va, sz))

    t0 = time.time()
    adrp_hits = scan_adrp_add(r2, ts, te, target_set)
    log("[*] adrp+add scan %.1fs hits=%d" % (time.time() - t0,
                                             sum(len(v) for v in adrp_hits.values())))

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

    results = []
    for cls in CLASSES:
        if time.time() - START > BUDGET - 120:
            log("[!] budget exhausted before %s" % cls)
            break
        try:
            r = scan_class(r2, cls, str_index, adrp_hits, data_secs, init_offsets, base)
        except Exception as e:
            log("[%s] EXCEPTION: %s" % (cls, e))
            traceback.print_exc()
            continue
        if r:
            results.append(r)

    r2.quit()

    try:
        with open(REPORT, "w") as fh:
            fh.write("# r2 ctor resolution (v8)\n")
            fh.write("# base=0x%x\n\n" % base)
            for r in results:
                fh.write("=== %s ===\n" % r["class"])
                if r.get("method"):
                    fh.write("  method: rva=0x%08x  %s\n"
                             % (r["method"][0], r["method"][1]))
                if r.get("vtable") is not None:
                    fh.write("  vtable: rva=0x%08x\n" % r["vtable"])
                if r.get("score") is not None:
                    fh.write("  score:  %d  src=%s size=%d n_call=%d\n"
                             % (r["score"], r.get("src"), r.get("size", 0),
                                r.get("n_call", 0)))
                fh.write("\n")
    except Exception as e:
        log("write REPORT failed: %s" % e)

    try:
        with open(OUT, "w") as fh:
            fh.write("export const ctors = Object.freeze({\n")
            for r in results:
                if r.get("method"):
                    fh.write("  %s: 0x%x,\n" % (r["class"], r["method"][0]))
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