#!/usr/bin/env python3
import os, sys, json, time, struct, bisect, traceback
import r2pipe
from collections import defaultdict, Counter

WS = os.environ.get("GITHUB_WORKSPACE", "/tmp")
BIN = os.environ.get("R2_BIN", "/tmp/brawl_bin")
JSON_PATH = os.environ.get("OFFSETS_JSON", os.path.join(WS, "offsets.json"))
OUT_JS = os.path.join(WS, "renamed_offsets.js")
LOG = os.path.join(WS, "r2_rename.log")
START = time.time()
MAX_BACK = 0x400
MAX_DELTA = 0x400

_fh = None

FIELD_HINTS = (
    "_x", "_y", "_Width", "_Height", "_width", "_height",
    "_length", "_data", "_Ptr", "_ptr", "_Offset", "_offset",
    "_flags", "_count", "_index", "_size", "_id", "_port",
    "_addr", "_angle", "_speed", "_team", "_deadFlag", "_namePtr",
    "_spawnAngle", "_brawlerId", "_objectsArray", "_ptrStride",
    "_objectManagerPtr", "_clientInputManager", "_BlocksMovement",
    "_BlocksProjectiles", "_TilesArray", "_currentX", "_currentY",
    "_centerX", "_centerY", "_isDragging", "_ipPtr", "_portHi",
    "_portLo", "_screenWidth", "_screenHeight", "_viewMatrix",
    "_manualFireX", "_manualFireY", "_autoFireX", "_autoFireY",
    "_autoshootPredOff", "_PredOff", "_namePtr"
)

NON_FUNC_PREFIXES = (
    "VTABLE_", "StageInstanceGlobalPtr", "HeroData_", "TileMap_",
    "TileTypeData_", "BattleMode_object", "BattleMode_client",
    "ObjectManager_", "GameObj_", "CharData_", "Projectile_spawn",
    "Joy_", "ScString_", "ClientInput_x", "ClientInput_y",
    "Message_port", "Message_ipPtr", "SockAddr_", "ClientInput_Message"
)

def log(m):
    line = "[%7.2f] %s" % (time.time() - START, m)
    try:
        sys.stdout.write(line + "\n"); sys.stdout.flush()
    except Exception:
        pass
    if _fh:
        try:
            _fh.write(line + "\n"); _fh.flush()
        except Exception:
            pass

def cmd(r2, c):
    try: return r2.cmd(c)
    except Exception: return ""

def cmdj(r2, c):
    try: return r2.cmdj(c)
    except Exception: return None

def parse_int(v):
    if isinstance(v, bool): return None
    if isinstance(v, int): return v
    if isinstance(v, str):
        s = v.strip()
        if not s: return None
        try:
            return int(s, 16) if s.lower().startswith("0x") else int(s)
        except Exception:
            return None
    return None

def is_field_like(name):
    for h in FIELD_HINTS:
        if name.endswith(h) or h in name:
            return True
    for p in NON_FUNC_PREFIXES:
        if name.startswith(p):
            return True
    return False

def load_bytes(r2, va, size):
    chunks = []
    a = va; end = va + size; CH = 0x400000
    while a < end:
        n = min(CH, end - a)
        hx = cmd(r2, "p8 %d @ 0x%x" % (n, a)).strip()
        if not hx: return None
        try: chunks.append(bytes.fromhex(hx))
        except Exception: return None
        a += n
    return b"".join(chunks)

def scan_prologs(text, text_va):
    prologs = []
    n = len(text) // 4
    for i in range(n):
        w = struct.unpack_from("<I", text, i * 4)[0]
        if w == 0xD503237F or w == 0xD503233F:
            prologs.append(text_va + i * 4); continue
        if w == 0xD503245F or w == 0xD503249F:
            prologs.append(text_va + i * 4); continue
        if (w & 0xFFC07FFF) == 0xA9807BFD:
            prologs.append(text_va + i * 4); continue
        if (w & 0xFFC07FFF) == 0xA8807BFD:
            prologs.append(text_va + i * 4); continue
        if (w & 0xFF8003FF) == 0xD10003FF:
            prologs.append(text_va + i * 4); continue
    return prologs

def nearest_prolog(prologs, addr, max_back=MAX_BACK):
    idx = bisect.bisect_right(prologs, addr) - 1
    if idx < 0: return None
    s = prologs[idx]
    if addr - s > max_back: return None
    return s

def detect_platform(r2):
    info = cmdj(r2, "ij") or {}
    if not isinstance(info, dict): return "unknown"
    binfo = info.get("bin") or {}
    core = info.get("core") or {}
    klass = (binfo.get("class") or binfo.get("bclass") or "").lower()
    osname = (core.get("os") or "").lower()
    if "mach" in klass or osname == "darwin":
        return "ios"
    if "elf" in klass or osname == "linux":
        return "android"
    return "unknown"

def safe_name(k):
    return "Possible_" + k.replace(".", "_").replace("-", "_").replace(":", "_")

def write_out(functions, data_offsets, platform, total):
    try:
        with open(OUT_JS, "w", encoding="utf-8") as fh:
            fh.write("// auto-resolved offsets\n")
            fh.write("// platform=%s\n" % platform)
            fh.write("// funcs=%d data=%d total=%d\n\n"
                     % (len(functions), len(data_offsets), total))
            fh.write("export const resolved = Object.freeze({\n")
            for name in sorted(functions.keys()):
                fh.write("    %s: 0x%x,\n" % (name, functions[name]))
            fh.write("});\n\n")
            fh.write("export const data = Object.freeze({\n")
            for name in sorted(data_offsets.keys()):
                fh.write("    %s: 0x%x,\n" % (name, data_offsets[name]))
            fh.write("});\n")
        log("wrote %s" % OUT_JS)
    except Exception as e:
        log("out write failed: %s" % e)

def main():
    global _fh
    try: _fh = open(LOG, "w")
    except Exception: _fh = None

    log("=== rename_from_json ===")

    if not os.path.exists(JSON_PATH):
        log("json not found: %s" % JSON_PATH)
        write_out({}, {}, "unknown", 0)
        return

    with open(JSON_PATH, "r", encoding="utf-8") as f:
        raw = json.load(f)
    log("json entries=%d" % len(raw))

    r2 = r2pipe.open(BIN, flags=["-2"])
    r2.cmd("e scr.color=0")

    platform = detect_platform(r2)
    log("platform=%s" % platform)

    sections = cmdj(r2, "iSj") or []
    text_va = None; text_sz = 0
    for s in sections:
        if not isinstance(s, dict): continue
        n = (s.get("name") or ""); p = (s.get("perm") or "")
        if "__text" in n and "x" in p:
            text_va = int(s.get("vaddr") or 0)
            text_sz = int(s.get("size") or 0)
            break
    if not text_va:
        log("no __text section")
        write_out({}, {}, platform, len(raw))
        r2.quit(); return
    log("__text vaddr=0x%x size=0x%x end=0x%x"
        % (text_va, text_sz, text_va + text_sz))

    t0 = time.time()
    text = load_bytes(r2, text_va, text_sz)
    log("loaded __text in %.1fs bytes=%d" % (time.time() - t0, len(text or b"")))
    if not text:
        write_out({}, {}, platform, len(raw))
        r2.quit(); return

    t0 = time.time()
    prologs = scan_prologs(text, text_va)
    log("prologs=%d in %.1fs" % (len(prologs), time.time() - t0))

    text_end = text_va + text_sz

    candidates = {}
    data_offsets = {}
    skipped_field = 0
    skipped_nontext = 0
    skipped_delta = 0
    skipped_prolog = 0
    invalid = 0

    for name, val in raw.items():
        off = parse_int(val)
        if off is None:
            log("  [INVALID] %-48s raw=%r" % (name, val))
            invalid += 1
            continue

        if is_field_like(name):
            data_offsets[name] = off
            skipped_field += 1
            log("  [DATA]    %-48s = 0x%x" % (name, off))
            continue

        if off < 0x1000 or off > 0x10000000:
            data_offsets[name] = off
            skipped_field += 1
            log("  [DATA]    %-48s = 0x%x (small/invalid RVA)" % (name, off))
            continue

        if off >= text_sz and off < text_va:
            data_offsets[name] = off
            skipped_nontext += 1
            log("  [ABS]     %-48s = 0x%x (outside __text)" % (name, off))
            continue

        target = text_va + off
        if target < text_va or target >= text_end:
            data_offsets[name] = off
            skipped_nontext += 1
            log("  [ABS]     %-48s = 0x%x (target 0x%x outside __text)"
                % (name, off, target))
            continue

        prolog = nearest_prolog(prologs, target)
        if prolog is None:
            log("  [NOPROLOG] %-47s off=0x%x target=0x%x"
                % (name, off, target))
            skipped_prolog += 1
            continue

        delta = prolog - target
        if abs(delta) > MAX_DELTA:
            log("  [FARDELTA] %-47s off=0x%x prolog=0x%x delta=%+d"
                % (name, off, prolog - text_va, delta))
            skipped_delta += 1
            continue

        rva = prolog - text_va
        prev = candidates.get(name)
        if prev is None or abs(delta) < abs(prev[1]):
            candidates[name] = (rva, delta)

    log("")
    log("=== DEDUP ===")
    by_addr = defaultdict(list)
    for name, (rva, delta) in candidates.items():
        by_addr[rva].append((name, delta))

    funcs = {}
    dup_count = 0
    for rva, items in by_addr.items():
        if len(items) == 1:
            funcs[items[0][0]] = rva
            continue
        items.sort(key=lambda x: abs(x[1]))
        best = items[0]
        funcs[best[0]] = rva
        dup_count += len(items) - 1
        for name, delta in items[1:]:
            log("  [DUP] %s -> %s (addr=0x%x)" % (name, best[0], rva))

    for name, rva in funcs.items():
        prolog = text_va + rva
        new_name = safe_name(name)
        cmd(r2, "af @ 0x%x" % prolog)
        cmd(r2, "afn %s @ 0x%x" % (new_name, prolog))

    r2.quit()

    log("")
    log("=== SUMMARY ===")
    log("input=%d" % len(raw))
    log("  funcs resolved   = %d" % len(funcs))
    log("  data offsets     = %d" % len(data_offsets))
    log("  skipped (field)  = %d" % skipped_field)
    log("  skipped (nontext)= %d" % skipped_nontext)
    log("  skipped (prolog) = %d" % skipped_prolog)
    log("  skipped (delta)  = %d" % skipped_delta)
    log("  invalid          = %d" % invalid)
    log("  dup collapsed    = %d" % dup_count)

    if funcs:
        deltas = [abs(d) for _, d in candidates.values()]
        log("delta abs min=%d max=%d" % (min(deltas), max(deltas)))
        top = Counter([d for _, d in candidates.values()])
        log("delta top 10:")
        for d, n in top.most_common(10):
            log("  %+d : %d" % (d, n))

    write_out(funcs, data_offsets, platform, len(raw))

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        log("FATAL %s" % e)
        traceback.print_exc()
        try:
            with open(OUT_JS, "w", encoding="utf-8") as fh:
                fh.write("// auto-resolved offsets\n")
                fh.write("// failed\n")
                fh.write("export const resolved = Object.freeze({});\n")
                fh.write("export const data = Object.freeze({});\n")
        except Exception:
            pass
        sys.exit(0)