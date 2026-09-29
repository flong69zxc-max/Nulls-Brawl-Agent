# -*- coding: utf-8 -*-
# @runtime Jython

import os
import sys
import time
import traceback

WS = os.environ.get("GITHUB_WORKSPACE", "/tmp")
OUT = os.path.join(WS, "offsets_resolved.js")
REPORT = os.path.join(WS, "debug_menu_report.txt")
BASE = 0x100000000
BUDGET = 1500
START = time.time()

def log(m):
    sys.stdout.write(m + "\n")
    sys.stdout.flush()

def rva(a):
    try:
        return int(a.getOffset()) - BASE
    except:
        return -1

def to_addr(r):
    return toAddr(BASE + r)

def build_index():
    listing = currentProgram.getListing()
    idx = {}
    it = listing.getDefinedData(True)
    total = 0
    while it.hasNext():
        if time.time() - START > BUDGET - 300:
            break
        try:
            d = it.next()
        except:
            break
        try:
            if d is None or not d.hasStringValue():
                continue
            s = str(d.getValue())
            if not s:
                continue
            total += 1
            idx.setdefault(s, []).append(d.getAddress())
        except:
            continue
    log("[*] strings: %d unique: %d" % (total, len(idx)))
    return idx

def strings_with(idx, needle, limit=30):
    out = []
    for s, addrs in idx.items():
        if needle in s:
            for a in addrs:
                out.append((s, a))
                if len(out) >= limit:
                    return out
    return out

def find_refs(a):
    out = []
    try:
        rm = currentProgram.getReferenceManager()
        it = rm.getReferencesTo(a).iterator()
        while it.hasNext():
            out.append(it.next().getFromAddress())
    except:
        pass
    return out

def dump_func(f, max_instr=60):
    if f is None:
        log("    <no function>")
        return
    body = f.getBody()
    listing = currentProgram.getListing()
    it = body.getAddresses(True)
    n = 0
    while it.hasNext():
        a = it.next()
        i = listing.getInstructionAt(a)
        if i is None:
            continue
        n += 1
        if n > max_instr:
            log("    ...")
            break
        try:
            log("      +0x%04x  %s" % (rva(a) - rva(f.getEntryPoint()), i.toString()))
        except:
            continue

def analyze_entry(entry):
    f = getFunctionAt(entry)
    if f is None:
        return
    log("    --- 0x%x %s ---" % (rva(entry), f.getName()))
    dump_func(f)

def main():
    log("=== find_debug_menu ===")
    log("program: %s" % currentProgram.getName())

    idx = build_index()
    if not idx:
        log("[!] empty index")
        return

    # ТОЛЬКО реальные якоря Brawl Stars из SCRE
    ANCHORS = [
        "sc/debug.sc",
        "debug.sc",
        "debug_tex.sc",
        "debug_menu_button",
        "debug_menu_text",
        "addResourcesToLoad",
        "TID_CONNECTING_TO_SERVER",
        "OfflineMode",
        "OFFLINE_MODE",
        "GameMode",
    ]

    candidates = {}
    for key in ANCHORS:
        hits = strings_with(idx, key, 20)
        if not hits:
            log("")
            log("[*] %s: NOT FOUND" % key)
            continue
        log("")
        log("[*] %s: %d string(s)" % (key, len(hits)))
        for s, a in hits:
            log("  %r @ 0x%x" % (s[:80], rva(a)))
            for ra in find_refs(a):
                f = getFunctionContaining(ra)
                if f is None:
                    continue
                fr = rva(f.getEntryPoint())
                candidates.setdefault(fr, set()).add(key)
                log("    xref 0x%x -> func 0x%x %s" % (rva(ra), fr, f.getName()))

    log("")
    log("=== BODIES ===")
    for fr in sorted(candidates.keys()):
        log("")
        log("--- 0x%x  keys=%s ---" % (fr, ",".join(sorted(candidates[fr]))))
        analyze_entry(to_addr(fr))

    log("")
    log("=== SUMMARY ===")
    for fr in sorted(candidates.keys()):
        log("  0x%x  %s" % (fr, ",".join(sorted(candidates[fr]))))

    with open(OUT, "w") as fh:
        fh.write("export const offsets = Object.freeze({\n")
        for fr in sorted(candidates.keys()):
            keys = "_".join(sorted(candidates[fr])).replace("/", "_").replace(" ", "_")
            fh.write("  hook_%s: 0x%x,\n" % (keys, fr))
        fh.write("});\n")

    with open(REPORT, "w") as fh:
        fh.write("candidates: %d\n" % len(candidates))
        for fr in sorted(candidates.keys()):
            fh.write("  0x%x  %s\n" % (fr, ",".join(sorted(candidates[fr]))))

    log("[+] wrote %s" % OUT)

try:
    main()
except SystemExit:
    raise
except Exception as e:
    log("FATAL: %s" % e)
    traceback.print_exc()