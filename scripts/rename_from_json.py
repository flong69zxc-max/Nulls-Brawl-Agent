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

MAX_DELTA = 0x2000
SNAP_BACK = 0x40
MIN_FUNC_STARTS = 5000

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
    if name.startswith("VTABLE_"): return "vtable"
    if name.startswith("StageInstance"): return "global_ptr"
    if is_field_like(name): return "field"
    if off < 0x1000 or off > 0x10000000: return "field"
    return "func"

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

def confidence(delta):
    a = abs(delta)
    if a <= 0x40: return "HIGH"
    if a <= 0x200: return "MEDIUM"
    if a <= MAX_DELTA: return "LOW"
    return "REJECT"

def parse_macho_layout(bin_path):
    with open(bin_path, "rb") as f:
        data = f.read()
    if len(data) < 32 or struct.unpack_from("<I", data, 0)[0] != 0xFEEDFACF:
        return None
    ncmds = struct.unpack_from("<I", data, 16)[0]
    offset = 32
    text_seg = None
    text_section = None
    linkedit_seg = None
    func_starts = None
    for _ in range(ncmds):
        if offset + 8 > len(data): break
        cmd_id, cmdsize = struct.unpack_from("<II", data, offset)
        if cmdsize < 8: break
        if cmd_id == 0x19:
            segname = data[offset+8:offset+24].rstrip(b"\x00").decode("utf-8", "ignore")
            vmaddr = struct.unpack_from("<Q", data, offset+24)[0]
            vmsize = struct.unpack_from("<Q", data, offset+32)[0]
            fileoff = struct.unpack_from("<Q", data, offset+40)[0]
            filesize = struct.unpack_from("<Q", data, offset+48)[0]
            nsects = struct.unpack_from("<I", data, offset+64)[0]
            if segname == "__TEXT":
                text_seg = {"vmaddr": vmaddr, "fileoff": fileoff, "filesize": filesize}
                sec_off = offset + 72
                for _s in range(nsects):
                    if sec_off + 80 > len(data): break
                    sectname = data[sec_off:sec_off+16].rstrip(b"\x00").decode("utf-8", "ignore")
                    segn = data[sec_off+16:sec_off+32].rstrip(b"\x00").decode("utf-8", "ignore")
                    addr = struct.unpack_from("<Q", data, sec_off+32)[0]
                    size = struct.unpack_from("<Q", data, sec_off+40)[0]
                    foff = struct.unpack_from("<I", data, sec_off+48)[0]
                    if sectname == "__text" and segn == "__TEXT":
                        text_section = {"vmaddr": addr, "size": size, "fileoff": foff}
                        break
                    sec_off += 80
            elif segname == "__LINKEDIT":
                linkedit_seg = {"vmaddr": vmaddr, "fileoff": fileoff, "filesize": filesize}
        elif cmd_id == 0x26:
            dataoff = struct.unpack_from("<I", data, offset+8)[0]
            datasize = struct.unpack_from("<I", data, offset+12)[0]
            func_starts = {"dataoff": dataoff, "datasize": datasize}
        offset += cmdsize
    return {
        "raw": data, "text_seg": text_seg, "text_section": text_section,
        "linkedit_seg": linkedit_seg, "func_starts": func_starts,
    }

def parse_function_starts(macho):
    fs = macho.get("func_starts")
    text_seg = macho.get("text_seg")
    if not fs or not text_seg: return []
    if fs["datasize"] < 16: return []
    raw = macho["raw"]
    fs_off = fs["dataoff"]
    fs_sz = fs["datasize"]
    if fs_off + fs_sz > len(raw): fs_sz = len(raw) - fs_off
    blob = raw[fs_off:fs_off + fs_sz]
    text_vmaddr = text_seg["vmaddr"]
    addrs = []
    i = 0
    cur = 0
    while i < len(blob):
        result = 0
        shift = 0
        while i < len(blob):
            b = blob[i]; i += 1
            result |= (b & 0x7f) << shift
            if not (b & 0x80): break
            shift += 7
            if shift > 63: break
        if result == 0: break
        cur += result
        addrs.append(text_vmaddr + cur)
    return sorted(set(addrs))

def get_text_blob(macho):
    sect = macho.get("text_section")
    if not sect: return None, 0
    raw = macho["raw"]
    off = sect["fileoff"]
    size = sect["size"]
    if off + size > len(raw): size = len(raw) - off
    return raw[off:off + size], sect["vmaddr"]

def scan_prologs_from_blob(blob, va):
    prologs = []
    n = len(blob) // 4
    for i in range(n):
        w = struct.unpack_from("<I", blob, i * 4)[0]
        if w in (0xD503237F, 0xD503233F, 0xD503245F, 0xD503249F):
            prologs.append(va + i * 4); continue
        if (w & 0xFFC07FFF) == 0xA9807BFD:
            prologs.append(va + i * 4); continue
        if (w & 0xFFE07FFF) == 0xA9807BFD:
            prologs.append(va + i * 4); continue
        if (w & 0xFF8003FF) == 0xD10003FF:
            prologs.append(va + i * 4); continue
        if i > 0:
            prev = struct.unpack_from("<I", blob, (i - 1) * 4)[0]
            if prev in (0xD65F03C0, 0xD503201F, 0xD4200000, 0xD65F0FFF, 0xD65F0BFF):
                if (w & 0xFFC00000) == 0xB9400000:
                    prologs.append(va + i * 4); continue
                if (w & 0xFFC00000) == 0xF9400000:
                    prologs.append(va + i * 4); continue
                if (w & 0xFFE00000) == 0x39400000:
                    prologs.append(va + i * 4); continue
                if (w & 0xFFE00000) == 0x79400000:
                    prologs.append(va + i * 4); continue
                if (w & 0xFFC00000) == 0x39400000:
                    prologs.append(va + i * 4); continue
    return sorted(set(prologs))

def find_nearest(addrs, target):
    idx = bisect.bisect_right(addrs, target) - 1
    if idx < 0: return None
    return addrs[idx]

def is_boundary(text_blob, text_va, addr):
    off = addr - text_va
    if off < 4: return True
    if off + 4 > len(text_blob): return False
    prev = struct.unpack_from("<I", text_blob, off - 4)[0]
    if prev in (0xD65F03C0, 0xD503201F, 0xD4200000, 0xD65F0FFF, 0xD65F0BFF):
        return True
    return False

def validate(r2, addr):
    ops = cmdj(r2, "pdj 8 @ 0x%x" % addr)
    if not ops or not isinstance(ops, list): return False, "pd failed"
    valid = 0
    for op in ops:
        if not isinstance(op, dict): continue
        t = (op.get("type") or "").lower()
        if t in ("invalid", "ill", "unk"): break
        valid += 1
    if valid < 4: return False, "few valid (%d)" % valid
    return True, "ok"

def write_outputs(funcs, data, rejected, platform, total, summary, validation):
    global _wrote_output
    try:
        with open(OUT_JS, "w", encoding="utf-8") as fh:
            fh.write("// auto-resolved offsets\n")
            fh.write("// platform=%s\n" % platform)
            fh.write("// funcs=%d data=%d total=%d\n\n" % (len(funcs), len(data), total))
            fh.write("export const resolved = Object.freeze({\n")
            for name in sorted(funcs.keys()):
                fh.write("    %s: 0x%x,\n" % (name, funcs[name][0]))
            fh.write("});\n\n")
            fh.write("export const data = Object.freeze({\n")
            for name in sorted(data.keys()):
                fh.write("    %s: 0x%x,\n" % (name, data[name]))
            fh.write("});\n")
    except Exception as e:
        log("js write failed: %s" % e)
    try:
        payload = {
            "platform": platform, "total": total, "summary": summary,
            "funcs": {k: {"rva": v[0], "delta": v[1], "conf": v[2]} for k, v in funcs.items()},
            "data": data, "rejected": rejected, "validation": validation,
        }
        with open(OUT_JSON, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, sort_keys=True)
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
                if not items: continue
                fh.write("## %s confidence (%d)\n\n" % (conf, len(items)))
                fh.write("| name | rva | delta | valid |\n|---|---|---|---|\n")
                for name, rva, d in sorted(items, key=lambda x: abs(x[2])):
                    v = validation.get(name, {})
                    ok = "yes" if v.get("ok") else "no"
                    fh.write("| %s | 0x%x | %+d | %s |\n" % (name, rva, d, ok))
                fh.write("\n")
            if rejected:
                fh.write("## Rejected (%d)\n\n" % len(rejected))
                fh.write("| name | input | reason |\n|---|---|---|\n")
                for r in rejected:
                    fh.write("| %s | 0x%x | %s |\n" % (r["name"], r["off"], r["reason"]))
                fh.write("\n")
            if data:
                fh.write("## Data offsets (%d)\n\n" % len(data))
                fh.write("| name | value |\n|---|---|\n")
                for name in sorted(data.keys()):
                    fh.write("| %s | 0x%x |\n" % (name, data[name]))
                fh.write("\n")
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
        r2.quit(); return
    log("__text vaddr=0x%x size=0x%x end=0x%x" % (text_va, text_sz, text_va + text_sz))

    t0 = time.time()
    macho = parse_macho_layout(BIN)
    log("macho parsed in %.2fs" % (time.time() - t0))
    if not macho or not macho.get("text_section"):
        log("macho parse failed")
        r2.quit(); return

    text_blob, blob_va = get_text_blob(macho)
    if not text_blob:
        log("text blob read failed")
        r2.quit(); return
    log("text blob: %d bytes @ 0x%x" % (len(text_blob), blob_va))

    fs = macho.get("func_starts")
    if fs:
        log("LC_FUNCTION_STARTS paddr=0x%x size=0x%x" % (fs["dataoff"], fs["datasize"]))

    prologs = parse_function_starts(macho)
    log("LC_FUNCTION_STARTS -> %d entries" % len(prologs))

    if len(prologs) < MIN_FUNC_STARTS:
        log("too few, scanning __text for prolog patterns...")
        t0 = time.time()
        prologs = scan_prologs_from_blob(text_blob, blob_va)
        log("pattern scan -> %d prologs in %.1fs" % (len(prologs), time.time() - t0))

    if not prologs:
        log("no prologs, aborting")
        r2.quit(); return

    text_end = text_va + text_sz
    funcs = {}
    data_offsets = {}
    rejected = []
    validation = {}
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
            rejected.append({"name": name, "off": off, "reason": "outside __text"})
            continue

        snap_ok, snap_reason = validate(r2, target)
        target_is_boundary = is_boundary(text_blob, blob_va, target)

        prolog = find_nearest(prologs, target)
        delta = prolog - target if prolog is not None else None

        use_target = False
        if snap_ok and target_is_boundary:
            if prolog is None or abs(delta) > SNAP_BACK:
                use_target = True
                stats["snap_target"] += 1

        if use_target:
            chosen = target
            chosen_delta = 0
        elif prolog is not None:
            chosen = prolog
            chosen_delta = delta
        else:
            stats["no_func"] += 1
            rejected.append({"name": name, "off": off, "reason": "no function found"})
            continue

        conf = confidence(chosen_delta)
        if conf == "REJECT":
            stats["delta_reject"] += 1
            rejected.append({"name": name, "off": off, "reason": "delta=%+d" % chosen_delta})
            continue

        rva = chosen - base
        ok, reason = validate(r2, chosen)
        validation[name] = {"ok": ok, "reason": reason, "delta": chosen_delta, "conf": conf}
        if not ok:
            stats["validation_fail"] += 1
            rejected.append({"name": name, "off": off, "reason": reason})
            continue

        prev = funcs.get(name)
        if prev is None or abs(chosen_delta) < abs(prev[1]):
            funcs[name] = (rva, chosen_delta, conf)
        stats["resolved"] += 1
        tag = "TARGET" if use_target else "PROLOG"
        log("  [OK] [%s] %-40s src=0x%-8x dst=0x%-8x delta=%+d %s"
            % (tag, name, off, rva, chosen_delta, conf))

    log("")
    log("=== DEDUP ===")
    by_addr = defaultdict(list)
    for name, (rva, delta, conf) in funcs.items():
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
                log("  [DUP] %s -> %s (rva=0x%x)" % (name, best[0], rva))

    r2.quit()
    conf_counts = Counter(v[2] for v in funcs.values())
    summary = {
        "input": len(raw), "funcs": len(funcs), "data": len(data_offsets),
        "rejected": len(rejected), "dup_collapsed": dup_count,
        "confidence": dict(conf_counts),
        "prologs_total": len(prologs),
        "snap_target": stats.get("snap_target", 0),
        "no_func": stats.get("no_func", 0),
        "delta_reject": stats.get("delta_reject", 0),
        "abs_outside_text": stats.get("abs_outside_text", 0),
        "validation_fail": stats.get("validation_fail", 0),
    }
    log("")
    log("=== SUMMARY ===")
    for k, v in summary.items():
        log("  %-22s = %s" % (k, v))
    write_outputs(funcs, data_offsets, rejected, platform, len(raw), summary, validation)

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