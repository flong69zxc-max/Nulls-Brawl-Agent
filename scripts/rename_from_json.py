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

def to_int(v):
    if isinstance(v, bool): return None
    if isinstance(v, int): return v
    if isinstance(v, str):
        s = v.strip()
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
        if w == 0xD503237F or w == 0xD503233F:        # pacibsp / paciasp
            prologs.append(text_va + i * 4); continue
        if w == 0xD503245F or w == 0xD503249F:        # bti c / bti j
            prologs.append(text_va + i * 4); continue
        if (w & 0xFFC07FFF) == 0xA9807BFD:            # stp x29,x30,[sp,#-N]!
            prologs.append(text_va + i * 4); continue
        if (w & 0xFFC07FFF) == 0xA8807BFD:            # stp x29,x30,[sp],#N
            prologs.append(text_va + i * 4); continue
        if (w & 0xFF8003FF) == 0xD10003FF:            # sub sp, sp, #N
            prologs.append(text_va + i * 4); continue
    return prologs

def nearest_prolog(prologs, addr, max_back=MAX_BACK):
    idx = bisect.bisect_right(prologs, addr) - 1
    if idx < 0: return None
    s = prologs[idx]
    if addr - s > max_back: return None
    return s

def main():
    global _fh
    try: _fh = open(LOG, "w")
    except Exception: _fh = None

    log("=== rename_from_json ===")
    if not os.path.exists(JSON_PATH):
        log("json not found: %s" % JSON_PATH)
        return
    with open(JSON_PATH, "r") as f:
        offsets = json.load(f)
    log("json entries=%d" % len(offsets))

    r2 = r2pipe.open(BIN, flags=["-2"])
    r2.cmd("e scr.color=0")

    info = cmdj(r2, "ij") or {}
    base = info.get("baddr", 0x100000000) or 0x100000000
    log("base=0x%x" % base)

    sections = cmdj(r2, "iSj") or []
    text_va = None; text_sz = 0
    for s in sections:
        n = s.get("name", "") or ""; p = s.get("perm", "") or ""
        if "__text" in n and "x" in p:
            text_va = s.get("vaddr"); text_sz = s.get("size"); break
    if not text_va:
        log("no __text"); return
    log("__text 0x%x-0x%x size=%d" % (text_va, text_va + text_sz, text_sz))

    t0 = time.time()
    text = load_bytes(r2, text_va, text_sz)
    log("loaded __text in %.1fs bytes=%d" % (time.time() - t0, len(text or b"")))
    if not text: return

    t0 = time.time()
    prologs = scan_prologs(text, text_va)
    log("prologs=%d in %.1fs" % (len(prologs), time.time() - t0))

    text_end = text_va + len(text)
    results = {}
    renamed = 0
    no_func = 0
    invalid = 0
    deltas = []

    for name, raw in offsets.items():
        off = to_int(raw)
        if off is None:
            invalid += 1
            continue
        android_va = base + off
        prolog = nearest_prolog(prologs, android_va)
        if prolog is None:
            log("  [MISS]  %-48s android_rva=0x%x" % (name, off))
            no_func += 1
            continue

        rva = prolog - base
        delta = prolog - android_va
        results[name] = rva
        deltas.append(delta)

        new_name = "Possible" + name.replace(".", "_").replace("-", "_")
        cmd(r2, "af @ 0x%x" % prolog)
        cmd(r2, "afn %s @ 0x%x" % (new_name, prolog))
        log("  [OK]    %-48s android=0x%x ios=0x%x delta=%+d"
            % (name, off, rva, delta))
        renamed += 1

    r2.quit()

    log("")
    log("=== SUMMARY ===")
    log("total=%d renamed=%d miss=%d invalid=%d"
        % (len(offsets), renamed, no_func, invalid))
    if deltas:
        log("delta min=%+d max=%+d" % (min(deltas), max(deltas)))
        # гистограмма дельт
        from collections import Counter
        c = Counter(deltas)
        log("delta top 10:")
        for d, n in c.most_common(10):
            log("  %+d : %d" % (d, n))

    try:
        with open(OUT_JS, "w") as fh:
            fh.write("// renamed from offsets.json\n")
            fh.write("// base=0x%x\n" % base)
            fh.write("// renamed=%d/%d\n\n" % (renamed, len(offsets)))
            fh.write("export const resolved = Object.freeze({\n")
            for name, rva in sorted(results.items()):
                fh.write("    %s: 0x%x,\n" % (name, rva))
            fh.write("});\n")
        log("wrote %s" % OUT_JS)
    except Exception as e:
        log("out write failed: %s" % e)

if __name__ == "__main__":
    try: main()
    except Exception as e:
        log("FATAL %s" % e); traceback.print_exc(); sys.exit(1)