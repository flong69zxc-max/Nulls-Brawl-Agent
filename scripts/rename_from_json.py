#!/usr/bin/env python3
import os, sys, json, time, struct, bisect, traceback
import r2pipe
from collections import defaultdict, Counter

WS = os.environ.get("GITHUB_WORKSPACE", "/tmp")
BIN = os.environ.get("R2_BIN", "/tmp/brawl_bin")
JSON_PATH = os.environ.get("OFFSETS_JSON", os.path.join(WS, "offsets.json"))
OUT_JS = os.path.join(WS, "renamed_offsets.js")
OUT_JSON = os.path.join(WS, "renamed_offsets.json")
OUT_REPORT = os.path.join(WS, "r2_rename_report.md")
LOG = os.path.join(WS, "r2_rename.log")
START = time.time()

MAX_BACK = 0x8000
DELTA_HIGH = 0x100
DELTA_MEDIUM = 0x1000
DELTA_LOW = 0x8000

_fh = None
_wrote_output = False


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
    "_autoshootPredOff", "_PredOff"
)

NON_FUNC_PREFIXES = (
    "VTABLE_", "StageInstanceGlobalPtr", "HeroData_", "TileMap_",
    "TileTypeData_", "BattleMode_object", "BattleMode_client",
    "ObjectManager_", "GameObj_", "CharData_", "Projectile_spawn",
    "Joy_", "ScString_", "ClientInput_x", "ClientInput_y",
    "Message_port", "Message_ipPtr", "SockAddr_"
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


def classify(name, off):
    if name.startswith("VTABLE_"):
        return "vtable"
    if name.startswith("StageInstance"):
        return "global_ptr"
    if is_field_like(name):
        return "field"
    if off < 0x1000 or off > 0x10000000:
        return "field"
    return "func"


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
        if (w & 0xFFE07FFF) == 0xA9807BFD:
            prologs.append(text_va + i * 4); continue
    return prologs


def is_boundary(text, text_va, addr):
    off = addr - text_va
    if off < 8: return True
    if off > len(text): return False
    prev = struct.unpack_from("<I", text, off - 4)[0]
    if prev == 0xD65F03C0: return True
    if prev == 0xD503201F: return True
    if prev == 0xD4200000: return True
    if (prev & 0xFFE0001F) == 0xD6BF03E0: return True
    if (prev & 0xFFE0001F) == 0xD65F03C0: return True
    return False


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
    if "mach" in klass or osname == "darwin": return "ios"
    if "elf" in klass or osname == "linux": return "android"
    return "unknown"


def safe_name(k):
    return "Possible_" + k.replace(".", "_").replace("-", "_").replace(":", "_")


def confidence(delta):
    a = abs(delta)
    if a <= DELTA_HIGH:   return "HIGH"
    if a <= DELTA_MEDIUM: return "MEDIUM"
    if a <= DELTA_LOW:    return "LOW"
    return "REJECT"


def validate_with_r2(r2, addr, text_va, text_end):
    """Disassemble a few instructions at addr and sanity-check."""
    result = {
        "analyzed": False,
        "instr_count": 0,
        "has_frame": False,
        "has_ret_soon": False,
        "first_ops": [],
        "looks_valid": False,
        "reason": "",
    }
    try:
        ops = cmdj(r2, "pdj 12 @ 0x%x" % addr)
    except Exception:
        ops = None

    if not ops or not isinstance(ops, list):
        result["reason"] = "pd failed"
        return result

    result["analyzed"] = True
    result["instr_count"] = len(ops)

    valid_ops = 0
    for op in ops[:8]:
        if not isinstance(op, dict): continue
        op_type = (op.get("type") or "").lower()
        mnem = (op.get("opcode") or "").lower()
        if op_type in ("invalid", "ill", "unk"):
            break
        valid_ops += 1
        result["first_ops"].append(mnem)

        if "stp" in mnem and "x29" in mnem and "x30" in mnem:
            result["has_frame"] = True
        if mnem.startswith("sub") and "sp" in mnem:
            result["has_frame"] = True
        if mnem.startswith("ret"):
            result["has_ret_soon"] = True
            break
        if mnem.startswith("b ") or mnem.startswith("br "):
            result["has_ret_soon"] = True

    if valid_ops == 0:
        result["reason"] = "no valid instructions"
        return result

    if result["has_frame"] or result["has_ret_soon"]:
        result["looks_valid"] = True
    else:
        result["looks_valid"] = valid_ops >= 4

    if not result["looks_valid"]:
        result["reason"] = "no frame, no branch in first 8 ops"

    return result


def write_outputs(funcs, data, rejected, platform, total, summary,
                  valid_map=None):
    global _wrote_output
    valid_map = valid_map or {}

    try:
        with open(OUT_JS, "w", encoding="utf-8") as fh:
            fh.write("// auto-resolved offsets\n")
            fh.write("// platform=%s\n" % platform)
            fh.write("// funcs=%d data=%d total=%d\n\n"
                     % (len(funcs), len(data), total))
            fh.write("export const resolved = Object.freeze({\n")
            for name in sorted(funcs.keys()):
                fh.write("    %s: 0x%x,\n" % (name, funcs[name][0]))
            fh.write("});\n\n")
            fh.write("export const data = Object.freeze({\n")
            for name in sorted(data.keys()):
                fh.write("    %s: 0x%x,\n" % (name, data[name]))
            fh.write("});\n")
        log("wrote %s" % OUT_JS)
    except Exception as e:
        log("js write failed: %s" % e)

    try:
        payload = {
            "platform": platform,
            "total": total,
            "summary": summary,
            "funcs": {k: {"rva": v[0], "delta": v[1], "conf": v[2]}
                      for k, v in funcs.items()},
            "data": data,
            "rejected": rejected,
            "validation": valid_map,
        }
        with open(OUT_JSON, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, sort_keys=True)
        log("wrote %s" % OUT_JSON)
    except Exception as e:
        log("json write failed: %s" % e)

    try:
        with open(OUT_REPORT, "w", encoding="utf-8") as fh:
            fh.write("# Offset resolution report\n\n")
            fh.write("platform: **%s**  \n" % platform)
            fh.write("input entries: **%d**  \n" % total)
            fh.write("funcs: **%d**  \n" % len(funcs))
            fh.write("data: **%d**  \n\n" % len(data))

            fh.write("## Summary\n\n")
            for k, v in sorted(summary.items()):
                fh.write("- %s: %s\n" % (k, v))
            fh.write("\n")

            by_conf = defaultdict(list)
            for name, (rva, d, conf) in funcs.items():
                by_conf[conf].append((name, rva, d))

            for conf in ("HIGH", "MEDIUM", "LOW"):
                items = by_conf.get(conf, [])
                if not items:
                    continue
                fh.write("## %s confidence (%d)\n\n" % (conf, len(items)))
                fh.write("| name | rva | delta | r2_valid | first_ops |\n")
                fh.write("|---|---|---|---|---|\n")
                for name, rva, d in sorted(items, key=lambda x: abs(x[2])):
                    v = valid_map.get(name, {})
                    ok = "yes" if v.get("looks_valid") else "no"
                    ops = " ".join(v.get("first_ops", [])[:3])
                    fh.write("| %s | 0x%x | %+d | %s | %s |\n"
                             % (name, rva, d, ok, ops))
                fh.write("\n")

            if rejected:
                fh.write("## Rejected (%d)\n\n" % len(rejected))
                fh.write("| name | input | reason |\n|---|---|---|\n")
                for r in rejected:
                    fh.write("| %s | 0x%x | %s |\n"
                             % (r["name"], r["off"], r["reason"]))
                fh.write("\n")

            if data:
                fh.write("## Data offsets (%d)\n\n" % len(data))
                fh.write("| name | value |\n|---|---|\n")
                for name in sorted(data.keys()):
                    fh.write("| %s | 0x%x |\n" % (name, data[name]))
                fh.write("\n")

        log("wrote %s" % OUT_REPORT)
    except Exception as e:
        log("report write failed: %s" % e)

    _wrote_output = True


def main():
    global _fh
    try: _fh = open(LOG, "w")
    except Exception: _fh = None

    log("=== rename_from_json ===")

    if not os.path.exists(JSON_PATH):
        log("json not found: %s" % JSON_PATH)
        return

    with open(JSON_PATH, "r", encoding="utf-8") as f:
        raw = json.load(f)
    log("json entries=%d" % len(raw))

    r2 = r2pipe.open(BIN, flags=["-2"])
    r2.cmd("e scr.color=0")
    r2.cmd("e anal.timeout=5")

    platform = detect_platform(r2)
    log("platform=%s" % platform)

    info = cmdj(r2, "ij") or {}
    base = int((info.get("bin") or {}).get("baddr", 0) or 0x100000000)
    log("base=0x%x" % base)

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
        r2.quit()
        return

    log("__text vaddr=0x%x size=0x%x end=0x%x"
        % (text_va, text_sz, text_va + text_sz))

    t0 = time.time()
    text = load_bytes(r2, text_va, text_sz)
    log("loaded __text in %.1fs bytes=%d" % (time.time() - t0, len(text or b"")))
    if not text:
        r2.quit()
        return

    t0 = time.time()
    prologs = scan_prologs(text, text_va)
    log("prologs=%d in %.1fs" % (len(prologs), time.time() - t0))

    text_end = text_va + text_sz

    candidates = {}
    data_offsets = {}
    rejected = []
    stats = Counter()

    for name, val in raw.items():
        off = parse_int(val)
        if off is None:
            rejected.append({"name": name, "off": 0, "reason": "invalid value"})
            stats["invalid"] += 1
            continue

        cat = classify(name, off)

        if cat in ("field", "vtable", "global_ptr"):
            data_offsets[name] = off
            stats["data_" + cat] += 1
            continue

        target = base + off
        if target < text_va or target >= text_end:
            data_offsets[name] = off
            stats["abs_outside_text"] += 1
            rejected.append({"name": name, "off": off,
                             "reason": "target outside __text"})
            continue

        prolog = nearest_prolog(prologs, target)
        if prolog is None:
            stats["no_prolog"] += 1
            rejected.append({"name": name, "off": off,
                             "reason": "no prolog within 0x%x back" % MAX_BACK})
            continue

        delta = prolog - target
        conf = confidence(delta)
        if conf == "REJECT":
            stats["delta_reject"] += 1
            rejected.append({"name": name, "off": off,
                             "reason": "delta=%+d exceeds 0x%x" % (delta, DELTA_LOW)})
            continue

        boundary = is_boundary(text, text_va, prolog)

        rva = prolog - base
        prev = candidates.get(name)
        if prev is None or abs(delta) < abs(prev[1]):
            candidates[name] = (rva, delta, conf)

        tag = platform.upper()
        warn = "" if boundary else " !BOUNDARY"
        log("  [OK] [%s] %-40s src=0x%-8x dst=0x%-8x delta=%+d %s%s"
            % (tag, name, off, rva, delta, conf, warn))

    log("")
    log("=== DEDUP ===")
    by_addr = defaultdict(list)
    for name, (rva, delta, conf) in candidates.items():
        by_addr[rva].append((name, delta, conf))

    funcs = {}
    dup_count = 0
    for rva, items in by_addr.items():
        items.sort(key=lambda x: abs(x[1]))
        best = items[0]
        funcs[best[0]] = (rva, best[1], best[2])
        if len(items) > 1:
            dup_count += len(items) - 1
            for name, delta, conf in items[1:]:
                log("  [DUP] %s -> %s (rva=0x%x, delta=%+d)"
                    % (name, best[0], rva, delta))

    log("")
    log("=== VALIDATION (r2 pd) ===")
    valid_map = {}
    validated_ok = 0
    validated_bad = 0
    for name, (rva, delta, conf) in funcs.items():
        addr = base + rva
        v = validate_with_r2(r2, addr, text_va, text_end)
        valid_map[name] = v
        if v.get("looks_valid"):
            validated_ok += 1
        else:
            validated_bad += 1
            log("  [BAD] %-40s rva=0x%-8x reason=%s"
                % (name, rva, v.get("reason") or "unknown"))

    log("  valid=%d bad=%d" % (validated_ok, validated_bad))

    log("")
    log("=== R2 rename ===")
    for name, (rva, delta, conf) in funcs.items():
        prolog = base + rva
        cmd(r2, "af @ 0x%x" % prolog)
        cmd(r2, "afn %s @ 0x%x" % (safe_name(name), prolog))

    r2.quit()

    conf_counts = Counter(v[2] for v in funcs.values())

    summary = {
        "input": len(raw),
        "funcs": len(funcs),
        "data": len(data_offsets),
        "rejected": len(rejected),
        "dup_collapsed": dup_count,
        "confidence": dict(conf_counts),
        "validated_ok": validated_ok,
        "validated_bad": validated_bad,
        "no_prolog": stats.get("no_prolog", 0),
        "delta_reject": stats.get("delta_reject", 0),
        "abs_outside_text": stats.get("abs_outside_text", 0),
    }

    log("")
    log("=== SUMMARY ===")
    for k, v in summary.items():
        log("  %-22s = %s" % (k, v))

    if candidates:
        deltas = [d for _, (_, d, _) in candidates.items()]
        log("delta abs min=%d max=%d"
            % (min(abs(d) for d in deltas), max(abs(d) for d in deltas)))

    write_outputs(funcs, data_offsets, rejected, platform, len(raw),
                  summary, valid_map)


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        log("FATAL %s" % e)
        traceback.print_exc()
        if not _wrote_output:
            try:
                with open(OUT_JS, "w", encoding="utf-8") as fh:
                    fh.write("// auto-resolved offsets\n")
                    fh.write("// failed\n")
                    fh.write("export const resolved = Object.freeze({});\n")
                    fh.write("export const data = Object.freeze({});\n")
            except Exception:
                pass
        sys.exit(0)