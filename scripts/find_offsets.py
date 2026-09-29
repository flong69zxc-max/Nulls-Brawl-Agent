# -*- coding: utf-8 -*-
# @runtime Jython

import os
import sys
import json
import time
import traceback

WS = os.environ.get("GITHUB_WORKSPACE", "/tmp")
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
    "DebugMenu_getBool": ["DisableIngameFriends"],
    "DebugMenu_DebugMenu": ["DebugMenu", "debugMenu"],
    "DebugMenu_DevMenu": ["DevMenu", "devMenu"],
    "DebugMenu_Cheat": ["Cheat", "cheat"],
    "DebugMenu_GodMode": ["GodMode", "godMode"],
    "LogicVersion_isDeveloperBuild": ["isDeveloperBuild"],
    "LogicVersion_isDev": ["isDev"],
    "LogicVersion_isProd": ["isProd"],
    "LogicVersion_isProduction": ["isProduction"],
    "SCIDConfig_isDevBuild": ["isDevBuild"],
    "SCIDConfig_getString": ["String not found:"],
}

def addr(rva_val):
    try:
        return currentProgram.getAddressFactory().getAddress("%X" % (TEXT_BASE + rva_val))
    except:
        return None

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
    sample = []
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
            if len(sample) < 40:
                sample.append(sval[:120])
            key = sval[:256]
            idx.setdefault(key, []).append(d.getAddress())
        except:
            continue
    log("[*] total data items: %d" % total_data)
    log("[*] total strings: %d" % total_str)
    log("[*] unique strings: %d" % len(idx))
    log("[*] sample strings:")
    for s in sample[:20]:
        log("    %r" % s)
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

def dump_function_info(f, tag):
    try:
        entry = f.getEntryPoint()
        r = rva(entry)
        name = str(f.getName())
        return (tag, r, name)
    except:
        return None

def main():
    log("=== find_debug_menu ===")
    log("program: %s" % currentProgram.getName())

    string_idx, total_str = index_strings()
    if total_str == 0:
        log("[!] NO STRINGS FOUND")
        sys.exit(1)

    results = []
    log("")
    log("=== ANCHOR SEARCH ===")

    for tag, anchors in STRING_ANCHORS.items():
        log("")
        log("--- %s ---" % tag)
        for anchor in anchors:
            addrs = find_anchor_addrs(string_idx, anchor)
            log("  anchor %r -> %d string occurrence(s)" % (anchor, len(addrs)))
            if not addrs:
                continue
            for sa in addrs[:MAX_HITS_PER_ANCHOR]:
                funcs = find_xrefs_to(sa, 8)
                log("    string@%s -> %d function(s)" % (fmt_addr(sa), len(funcs)))
                for f in funcs:
                    info = dump_function_info(f, tag)
                    if info is not None:
                        results.append(info)
                        log("      %s @ 0x%x" % (info[2], info[1]))

    log("")
    log("=== SUMMARY ===")
    for tag, r, name in results:
        log("  %s @ 0x%x  (%s)" % (tag, r, name))

    fh = open(REPORT, "w")
    fh.write("debug_menu_report\n")
    fh.write("generated: %s\n" % time.strftime("%Y-%m-%d %H:%M:%S"))
    fh.write("strings indexed: %d\n" % total_str)
    fh.write("\n")
    for tag, r, name in results:
        fh.write("%s @ 0x%x  (%s)\n" % (tag, r, name))
    fh.close()
    log("[+] wrote %s (%d entries)" % (REPORT, len(results)))

def fmt_addr(a):
    try:
        return "0x%X" % int(a.getOffset())
    except:
        return str(a)

try:
    main()
except SystemExit:
    raise
except Exception as e:
    log("FATAL: %s" % e)
    traceback.print_exc()
    try:
        fh = open(REPORT, "w")
        fh.write("FATAL: %s\n%s\n" % (e, traceback.format_exc()))
        fh.close()
    except:
        pass