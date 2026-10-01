#!/usr/bin/env python3
import os, sys, json, time, struct, bisect, traceback
import r2pipe

WS = os.environ.get("GITHUB_WORKSPACE", "/tmp")
BIN = os.environ.get("R2_BIN", "/tmp/brawl_bin")
JSON_PATH = os.environ.get("OFFSETS_JSON", os.path.join(WS, "offsets.json"))
OUT_JS = os.path.join(WS, "renamed_offsets.js")
LOG = os.path.join(WS, "r2_rename.log")
START = time.time()
MAX_BACK = 0x8000

_fh = None


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


def write_out(results, platform, total):
    try:
        with open(OUT_JS, "w", encoding="utf-8") as fh:
            fh.write("// auto-resolved offsets\n")
            fh.write("// platform=%s\n" % platform)
            fh.write("// resolved=%d/%d\n\n" % (len(results), total))
            fh.write("export const resolved = Object.freeze({\n")
            for name, rva in sorted(results.items()):
                fh.write("    %s: 0x%x,\n" % (name, rva))
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
        write_out({}, "unknown", 0)
        return

    with open(JSON_PATH, "r", encoding="utf-8") as f:
        raw_offsets = json.load(f)
    log("json entries=%d" % len(raw_offsets))

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
        write_out({}, platform, len(raw_offsets))
        r2.quit(); return
    log("__text vaddr=0x%x size=%d" % (text_va, text_sz))

    t0 = time.time()
    text = load_bytes(r2, text_va, text_sz)
    log("loaded __text in %.1fs bytes=%d" % (time.time() - t0, len(text or b"")))
    if not text:
        write_out({}, platform, len(raw_offsets))
        r2.quit(); return

    t0 = time.time()
    prologs = scan_prologs(text, text_va)
    log("prologs=%d in %.1fs" % (len(prologs), time.time() - t0))

    results = {}
    deltas = []
    miss = 0
    invalid = 0

    for name, raw in raw_offsets.items():
        off = parse_int(raw)
        if off is None:
            log("  [INVALID] %-48s raw=%r" % (name, raw))
            invalid += 1
            continue

        target = off if off >= text_va else (text_va & ~0xFFFFFFFF) + off
        if target < text_va or target >= text_va + text_sz:
            target = text_va + off
        prolog = nearest_prolog(prologs, target)
        if prolog is None:
            log("  [MISS]    %-48s off=0x%x target=0x%x" % (name, off, target))
            miss += 1
            continue

        rva = prolog - text_va
        delta = prolog - target
        results[name] = rva
        deltas.append(delta)

        new_name = safe_name(name)
        cmd(r2, "af @ 0x%x" % prolog)
        cmd(r2, "afn %s @ 0x%x" % (new_name, prolog))

        tag = "IOS" if platform == "ios" else ("ANDROID" if platform == "android" else "?")
        log("  [OK] [%s] %-40s src=0x%-8x dst=0x%-8x delta=%+d"
            % (tag, name, off, rva, delta))

    r2.quit()

    log("")
    log("=== SUMMARY ===")
    log("total=%d ok=%d miss=%d invalid=%d"
        % (len(raw_offsets), len(results), miss, invalid))
    if deltas:
        log("delta min=%+d max=%+d" % (min(deltas), max(deltas)))
        from collections import Counter
        c = Counter(deltas)
        log("delta top 10:")
        for d, n in c.most_common(10):
            log("  %+d : %d" % (d, n))

    write_out(results, platform, len(raw_offsets))


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
        except Exception:
            pass
        sys.exit(0)