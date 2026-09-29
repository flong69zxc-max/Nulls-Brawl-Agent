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
MAX_INSTR_SCAN = 20

L = []
START = time.time()

def log(m):
    sys.stdout.write(m + "\n")
    sys.stdout.flush()

def w(s):
    L.append(s)

def rva(a):
    return int(a.getOffset()) - 0x100000000

def get_segment_name(addr):
    block = currentProgram.getMemory().getBlock(addr)
    if block is None:
        return "?"
    return block.getName()

def is_function(addr):
    return getFunctionAt(addr) is not None

def get_func_entry(addr):
    f = getFunctionContaining(addr)
    if f is None:
        return None
    return f.getEntryPoint()

def find_string_addrs(string_idx, anchor):
    out = []
    for sval, addrs in string_idx.items():
        if anchor in sval:
            out.extend(addrs)
    return out

def find_code_refs(target_addr):
    rm = currentProgram.getReferenceManager()
    refs = rm.getReferencesTo(target_addr)
    it = refs.iterator()
    out = []
    while it.hasNext():
        r = it.next()
        fa = r.getFromAddress()
        f = getFunctionContaining(fa)
        if f is not None:
            out.append(fa)
    return out

def scan_instructions(start_addr, count):
    listing = currentProgram.getListing()
    out = []
    a = start_addr
    for _ in range(count):
        instr = listing.getInstructionAt(a)
        if instr is None:
            break
        out.append(instr)
        a = instr.getMaxAddress().add(1)
    return out

def find_bl_targets(instrs):
    out = []
    for instr in instrs:
        mn = instr.getMnemonicString().lower()
        if mn == "bl":
            flows = instr.getFlows()
            if flows:
                out.append(flows[0])
    return out

def has_function_prologue(addr):
    listing = currentProgram.getListing()
    instrs = scan_instructions(addr, 3)
    for instr in instrs:
        mn = instr.getMnemonicString().lower()
        if mn in ("stp", "sub"):
            return True
        if mn in ("ret", "br"):
            return False
    return False

def main():
    log("=== find_offsets ===")
    log("program: %s" % currentProgram.getName())

    listing = currentProgram.getListing()
    idx = {}
    it = listing.getDefinedData(True)
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
    log("[*] strings indexed: %d" % total_str)

    results = {}

    ANCHORS = {
        "getBool": ["DisableIngameFriends"],
        "isDev": ["isDev"],
        "isDevBuild": ["isDevBuild"],
        "isDeveloperBuild": ["isDeveloperBuild"],
        "isProd": ["isProd"],
    }

    for tag, anchors in sorted(ANCHORS.items()):
        log("")
        log("--- %s ---" % tag)
        for anchor in anchors:
            addrs = find_string_addrs(idx, anchor)
            log("  anchor %r -> %d string(s)" % (anchor, len(addrs)))
            for sa in addrs[:8]:
                code_refs = find_code_refs(sa)
                for ref_addr in code_refs[:4]:
                    instrs = scan_instructions(ref_addr, MAX_INSTR_SCAN)
                    bls = find_bl_targets(instrs)
                    # Ищем вызовы функций после загрузки адреса строки
                    if len(bls) >= 2:
                        # Первый BL обычно конструктор строки, второй — getBool
                        cand_func = bls[1]
                        if is_function(cand_func):
                            fr = rva(cand_func)
                            if fr > 0x10000:
                                results[tag] = ("func", fr)
                                log("    func @ 0x%x (prologue=%s)" % (fr, has_function_prologue(cand_func)))
                    # Если после загрузки адреса идёт LDRB — это данные
                    for instr in instrs:
                        mn = instr.getMnemonicString().lower()
                        if mn.startswith("ldr"):
                            # Адрес данных берём из ADRP+ADD
                            for prev in instrs:
                                if prev.getMnemonicString().lower() == "adrp":
                                    # Приблизительно: адрес = page + offset
                                    # Точное вычисление требует эмуляции
                                    pass
        if tag not in results:
            log("  -> NOT FOUND")

    log("")
    log("=== SUMMARY ===")
    for tag, (typ, r) in sorted(results.items()):
        log("  %s: type=%s rva=0x%x" % (tag, typ, r))

    fh = open(OFF_OUT, "w")
    fh.write("export const offsets = Object.freeze({\n")
    for tag in sorted(results.keys()):
        typ, r = results[tag]
        fh.write("  %s: 0x%x, // type=%s\n" % (tag, r, typ))
    fh.write("});\n")
    fh.close()

    fh = open(REPORT, "w")
    for line in L:
        fh.write(line + "\n")
    fh.close()

    log("[+] wrote %s" % OFF_OUT)

try:
    main()
except SystemExit:
    raise
except Exception as e:
    log("FATAL: %s" % e)
    traceback.print_exc()