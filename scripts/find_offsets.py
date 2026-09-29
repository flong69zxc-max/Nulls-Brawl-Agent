# -*- coding: utf-8 -*-
# @runtime Jython

import os
import sys
import time
import traceback

WS = os.environ.get("GITHUB_WORKSPACE", "/tmp")
OFF_OUT = os.path.join(WS, "offsets_resolved.js")
REPORT = os.path.join(WS, "debug_menu_report.txt")
BUDGET_SEC = 1800
START = time.time()
BASE = 0x100000000

L = []

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

def build_string_index():
    listing = currentProgram.getListing()
    idx = {}
    it = listing.getDefinedData(True)
    total = 0
    while it.hasNext():
        if time.time() - START > BUDGET_SEC - 300:
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
    log("[*] indexed strings: %d (unique: %d)" % (total, len(idx)))
    return idx

def strings_containing(idx, needle, limit=20):
    out = []
    for s, addrs in idx.items():
        if needle in s:
            for a in addrs:
                out.append((s, a))
                if len(out) >= limit:
                    return out
    return out

def find_refs(addr):
    out = []
    try:
        rm = currentProgram.getReferenceManager()
        it = rm.getReferencesTo(addr).iterator()
        while it.hasNext():
            out.append(it.next().getFromAddress())
    except:
        pass
    return out

def dump_func(f):
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
        if n > 40:
            log("    ...")
            break
        try:
            log("      +0x%04x  %s" % (rva(a) - rva(f.getEntryPoint()), i.toString()))
        except:
            continue

def analyze(entry):
    f = getFunctionAt(entry)
    if f is None:
        return
    log("    --- body of 0x%x %s ---" % (rva(entry), f.getName()))
    dump_func(f)

def main():
    log("=== find_offsets_v6 ===")
    log("program: %s" % currentProgram.getName())

    idx = build_string_index()
    if not idx:
        log("[!] string index empty")
        return

    targets = {}

    log("")
    log("[*] getBool via DisableIngameFriends")
    hits = strings_containing(idx, "DisableIngameFriends", 5)
    for s, a in hits:
        log("  string %r @ 0x%x" % (s[:40], rva(a)))
        for ra in find_refs(a):
            f = getFunctionContaining(ra)
            if f is None:
                continue
            fr = rva(f.getEntryPoint())
            log("    used in 0x%x %s" % (fr, f.getName()))
            targets.setdefault("getBool", set()).add(fr)

    for key in ["isDevBuild", "isDeveloperBuild", "isDev", "isProduction", "isProd"]:
        log("")
        log("[*] %s" % key)
        hits = strings_containing(idx, key, 10)
        if not hits:
            log("  no strings")
            continue
        for s, a in hits:
            log("  string %r @ 0x%x" % (s[:60], rva(a)))
            for ra in find_refs(a):
                f = getFunctionContaining(ra)
                if f is None:
                    continue
                fr = rva(f.getEntryPoint())
                log("    used in 0x%x %s" % (fr, f.getName()))
                targets.setdefault(key, set()).add(fr)

    log("")
    log("=== BODIES OF OLD OFFSETS ===")
    for name, val in [("old_getBool", 0xb24820), ("old_isDev", 0xd93d80), ("old_isDevBuild", 0xd93da0)]:
        log("")
        log("--- %s @ 0x%x ---" % (name, val))
        analyze(to_addr(val))

    log("")
    log("=== BODIES OF CANDIDATES ===")
    for key, entries in sorted(targets.items()):
        for fr in sorted(entries):
            log("")
            log("--- %s candidate @ 0x%x ---" % (key, fr))
            analyze(to_addr(fr))

    log("")
    log("=== SUMMARY ===")
    for key, entries in sorted(targets.items()):
        for fr in sorted(entries):
            log("  %s: 0x%x" % (key, fr))

    with open(OFF_OUT, "w") as fh:
        fh.write("export const offsets = Object.freeze({\n")
        for key, entries in sorted(targets.items()):
            fr = sorted(entries)[0]
            fh.write("  %s: 0x%x,\n" % (key, fr))
        fh.write("});\n")

    with open(REPORT, "w") as fh:
        for line in L:
            fh.write(line + "\n")

    log("")
    log("[+] wrote %s" % OFF_OUT)

try:
    main()
except SystemExit:
    raise
except Exception as e:
    log("FATAL: %s" % e)
    traceback.print_exc()