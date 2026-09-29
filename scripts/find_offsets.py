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

def to_addr(rva_val):
    return toAddr(BASE + rva_val)

def find_strings(needle, limit=50):
    out = []
    mem = currentProgram.getMemory()
    nb = needle.encode()
    for block in mem.getBlocks():
        if not block.isInitialized():
            continue
        try:
            sz = int(block.getSize())
            if sz > 64 * 1024 * 1024:
                continue
            start = block.getStart()
            data = bytes(mem.getBytes(start, sz))
            pos = 0
            while pos < len(data):
                p = data.find(nb, pos)
                if p < 0:
                    break
                end_idx = p + len(nb)
                if end_idx < len(data) and data[end_idx:end_idx+1] == b"\x00":
                    out.append(start.add(p))
                    if len(out) >= limit:
                        return out
                pos = p + 1
        except:
            continue
    return out

def find_refs(target):
    out = []
    try:
        rm = currentProgram.getReferenceManager()
        it = rm.getReferencesTo(target).iterator()
        while it.hasNext():
            out.append(it.next().getFromAddress())
    except:
        pass
    return out

def containing(addr):
    return getFunctionContaining(addr)

def scan_data_refs(func):
    """Проходит по всем инструкциям функции и собирает адреса данных из LDR/STR."""
    out = set()
    body = func.getBody()
    it = body.getAddresses(True)
    listing = currentProgram.getListing()
    while it.hasNext():
        a = it.next()
        instr = listing.getInstructionAt(a)
        if instr is None:
            continue
        mn = instr.getMnemonicString().lower()
        if mn.startswith("ldr") or mn.startswith("str") or mn.startswith("adrp"):
            try:
                for i in range(instr.getNumOperands()):
                    objs = instr.getOpObjects(i)
                    for o in objs:
                        s = str(o)
                        if s.startswith("0x"):
                            addr = toAddr(s)
                            blk = currentProgram.getMemory().getBlock(addr)
                            if blk is not None and ("DATA" in blk.getName() or "BSS" in blk.getName()):
                                out.add(addr)
            except:
                continue
    return out

def main():
    log("=== find_flags_v5 ===")
    log("program: %s" % currentProgram.getName())

    # 1) getBool
    log("")
    log("[*] getBool via DisableIngameFriends...")
    gb_addrs = find_strings("DisableIngameFriends")
    getBool_rva = None
    for sa in gb_addrs:
        for ra in find_refs(sa):
            f = containing(ra)
            if f is not None:
                getBool_rva = rva(f.getEntryPoint())
                log("    func 0x%x  %s" % (getBool_rva, f.getName()))
                break
        if getBool_rva:
            break

    # 2) строки флагов
    FLAG_KEYS = ["isDev", "isDevBuild", "isProd", "isDeveloperBuild", "isProduction"]
    flag_funcs = {}
    for key in FLAG_KEYS:
        saddrs = find_strings(key)
        log("")
        log("--- %s : %d string(s) ---" % (key, len(saddrs)))
        for sa in saddrs:
            for ra in find_refs(sa):
                f = containing(ra)
                if f is None:
                    continue
                fe = f.getEntryPoint()
                if fe not in flag_funcs:
                    flag_funcs[fe] = set()
                flag_funcs[fe].add(key)
                log("    func 0x%x  %s  (key=%s)" % (rva(fe), f.getName(), key))

    # 3) для каждой такой функции — кандидаты на адреса флагов
    log("")
    log("=== DATA CANDIDATES ===")
    candidates = {}
    for fe, keys in flag_funcs.items():
        f = getFunctionAt(fe)
        if f is None:
            continue
        data_refs = scan_data_refs(f)
        for dr in data_refs:
            dr_rva = rva(dr)
            if dr_rva <= 0:
                continue
            candidates.setdefault(dr_rva, set()).update(keys)
    for dr_rva in sorted(candidates.keys()):
        keys = ",".join(sorted(candidates[dr_rva]))
        log("  0x%x  keys=%s" % (dr_rva, keys))

    # 4) проверка старых
    log("")
    log("=== OLD OFFSETS ===")
    for name, val in [("old_getBool", 0xb24820), ("old_isDev", 0xd93d80), ("old_isDevBuild", 0xd93da0)]:
        a = to_addr(val)
        f = getFunctionAt(a)
        blk = currentProgram.getMemory().getBlock(a)
        if f is not None:
            log("  0x%x %s -> func %s" % (val, name, f.getName()))
        elif blk is not None:
            log("  0x%x %s -> block %s" % (val, name, blk.getName()))
        else:
            log("  0x%x %s -> ?" % (val, name))

    # 5) запись
    with open(OFF_OUT, "w") as fh:
        fh.write("export const offsets = Object.freeze({\n")
        if getBool_rva:
            fh.write("  getBool: 0x%x,\n" % getBool_rva)
        for dr_rva in sorted(candidates.keys()):
            fh.write("  flag_0x%x: 0x%x, // keys=%s\n" % (dr_rva, dr_rva, ",".join(sorted(candidates[dr_rva]))))
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