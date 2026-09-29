# -*- coding: utf-8 -*-
# @runtime Jython

import os
import sys
import json
import time
import traceback

WS = os.environ.get("GITHUB_WORKSPACE", "/tmp")
OFF_OUT = os.path.join(WS, "offsets_resolved.js")
REPORT = os.path.join(WS, "debug_menu_report.txt")

TEXT_BASE = 0x100000000
BUDGET_SEC = 1800
MAX_HITS_PER_ANCHOR = 16

L = []
START = time.time()

def log(m):
    sys.stdout.write(m + "\n")
    sys.stdout.flush()

def w(s):
    L.append(s)

STRING_ANCHORS = {
    "SCIDConfig_getBool": ["DisableIngameFriends"],
    "LogicVersion_isDev": ["isDev"],
    "LogicVersion_isDevBuild": ["isDevBuild"],
    "LogicVersion_isDeveloperBuild": ["isDeveloperBuild"],
    "LogicVersion_isProd": ["isProd"],
    "LogicVersion_isProduction": ["isProduction"],
    "DebugMenu_label": ["DebugMenu"],
    "DebugMenu_cheat": ["cheat"],
    "DebugMenu_godMode": ["GodMode"],
    "StringCtor": ["String not found:"],
}

def rva(a):
    return int(a.getOffset()) - TEXT_BASE

def index_strings():
    log("[*] indexing strings via getDefinedData...")
    listing = currentProgram.getListing()
    try:
        it = listing.getDefinedData(True)
    except Exception as e:
        log("[!] getDefinedData failed: %s" % e)
        return {}, 0
    idx = {}
    total_data = 0
    total_str = 0
    while it.hasNext():
        if time.time() - START > BUDGET_SEC - 300:
            break
        try:
            d = it.next()
        except:
            break
        total_data += 1
        try:
            if d is None or not d.hasStringValue():
                continue
            sval = str(d.getValue())
            if not sval:
                continue
            total_str += 1
            key = sval[:256]
            idx.setdefault(key, []).append(d.getAddress())
        except:
            continue
    log("[*] total data items: %d" % total_data)
    log("[*] total strings: %d" % total_str)
    log("[*] unique strings: %d" % len(idx))
    return idx, total_str

def find_anchor_addrs(string_idx, anchor):
    out = []
    for sval, addrs in string_idx.items():
        if anchor in sval:
            out.extend(addrs)
    return out

def find_xrefs_to(target_addr, limit):
    rm = currentProgram.getReferenceManager()
    refs = rm.getReferencesTo(target_addr)
    it = refs.iterator()
    out = []
    while it.hasNext() and len(out) < limit:
        r = it.next()
        fa = r.getFromAddress()
        f = getFunctionContaining(fa)
        if f is not None:
            out.append(f)
    return out

def main():
    log("=== find_debug_menu ===")
    log("program: %s" % currentProgram.getName())

    string_idx, total_str = index_strings()
    if total_str == 0:
        log("[!] NO STRINGS FOUND")
        sys.exit(1)

    results = {}
    log("")
    log("=== ANCHOR SEARCH ===")

    for tag, anchors in sorted(STRING_ANCHORS.items()):
        log("")
        log("--- %s ---" % tag)
        found_rvas = []
        for anchor in anchors:
            addrs = find_anchor_addrs(string_idx, anchor)
            log("  anchor %r -> %d string occurrence(s)" % (anchor, len(addrs)))
            for sa in addrs[:MAX_HITS_PER_ANCHOR]:
                funcs = find_xrefs_to(sa, 8)
                for f in funcs:
                    try:
                        fr = rva(f.getEntryPoint())
                        if fr < 0x10000:
                            continue
                        found_rvas.append(fr)
                        log("    %s @ 0x%x" % (str(f.getName()), fr))
                    except:
                        continue
        if found_rvas:
            found_rvas = sorted(set(found_rvas))
            results[tag] = found_rvas[0]
            log("  -> picked rva=0x%x" % results[tag])

    log("")
    log("=== SUMMARY ===")
    for tag, r in sorted(results.items()):
        log("  %s @ 0x%x" % (tag, r))

    fh = open(OFF_OUT, "w")
    fh.write("export const offsets = Object.freeze(\n{\n")
    for tag in sorted(results.keys()):
        fh.write("    %s: 0x%x,\n" % (tag, results[tag]))
    fh.write("});\n")
    fh.close()

    w("strings indexed: %d" % total_str)
    w("")
    for tag, r in sorted(results.items()):
        w("  %s @ 0x%x" % (tag, r))

    fh = open(REPORT, "w")
    for line in L:
        fh.write(line + "\n")
    fh.close()

    log("[+] wrote %s" % OFF_OUT)
    log("[+] wrote %s" % REPORT)

try:
    main()
except SystemExit:
    raise
except Exception as e:
    log("FATAL: %s" % e)
    traceback.print_exc()
    try:
        fh = open(OFF_OUT, "w")
        fh.write("export const offsets = Object.freeze(\n{\n});\n")
        fh.close()
        fh = open(REPORT, "w")
        fh.write("FATAL: %s\n%s\n" % (e, traceback.format_exc()))
        fh.close()
    except:
        pass