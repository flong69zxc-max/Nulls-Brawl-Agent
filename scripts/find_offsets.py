# -*- coding: utf-8 -*-
# @runtime Jython

import os
import sys
import time
import traceback

WS = os.environ.get("GITHUB_WORKSPACE", "/tmp")
OUT = os.path.join(WS, "offsets_resolved.js")
REPORT = os.path.join(WS, "mod_menu_report.txt")
BASE = 0x100000000
BUDGET = 1500
START = time.time()

CLASSES = [
    "HomePage",
    "GameButton",
    "GenericPopup",
    "ResourceManager",
    "MovieClip",
    "TextField",
    "Sprite",
]

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

def find_exact_string(idx, s):
    return idx.get(s, [])

def find_data_items_at(addr):
    """Найти все data-структуры, которые начинаются по адресу."""
    out = []
    listing = currentProgram.getListing()
    d = listing.getDataAt(addr)
    if d is not None:
        out.append(d)
    # также смотрим на структуры, содержащие addr как указатель
    return out

def scan_for_vtable_refs(vtable_addr, max_results=8):
    """Ищем функции, где есть ссылка на vtable_addr — это ctor/dtor."""
    funcs = set()
    for ref in find_refs(vtable_addr):
        f = getFunctionContaining(ref)
        if f is not None:
            funcs.add(f.getEntryPoint())
    return sorted(funcs, key=lambda a: rva(a))[:max_results]

def check_vptr_write(func_addr, vtable_addr):
    """Проверяем, пишет ли функция vtable в [x0] — это признак ctor."""
    f = getFunctionAt(func_addr)
    if f is None:
        return False
    listing = currentProgram.getListing()
    it = f.getBody().getAddresses(True)
    writes = 0
    while it.hasNext():
        a = it.next()
        instr = listing.getInstructionAt(a)
        if instr is None:
            continue
        mn = instr.getMnemonicString().lower()
        if mn == "str":
            try:
                op0 = instr.getOpObjects(0)
                if op0 and "[x0]" in instr.toString():
                    writes += 1
            except:
                pass
    return writes > 0

def main():
    log("=== find_offsets (SCRE vtable method) ===")
    log("program: %s" % currentProgram.getName())

    idx = build_string_index()
    if not idx:
        log("[!] no strings")
        return

    results = {}

    for cls in CLASSES:
        log("")
        log("=== CLASS: %s ===" % cls)
        saddrs = find_exact_string(idx, cls)
        if not saddrs:
            # пробуем с префиксом/суффиксом
            for s, addrs in idx.items():
                if s == cls or s.startswith(cls + "::") or s.endswith("::" + cls):
                    saddrs.extend(addrs)
        if not saddrs:
            log("  no exact string")
            continue

        for sa in saddrs[:3]:
            log("  str @ 0x%x" % rva(sa))
            # typeinfo — data, содержащая указатель на строку
            for ra in find_refs(sa):
                blk = currentProgram.getMemory().getBlock(ra)
                if blk is None:
                    continue
                name = blk.getName()
                if "TEXT" in name:
                    continue  # это код, не typeinfo
                log("    ref @ 0x%x in %s" % (rva(ra), name))
                # это может быть typeinfo или vtable начало
                # ищем xref на addr-8 (typeinfo обычно имеет -1 перед name)
                typeinfo_addr = ra.subtract(8)
                vtable_candidates = find_refs(typeinfo_addr)
                if not vtable_candidates:
                    vtable_candidates = find_refs(ra)
                for vt in vtable_candidates[:2]:
                    vt_blk = currentProgram.getMemory().getBlock(vt)
                    if vt_blk is None:
                        continue
                    log("      vtable candidate @ 0x%x in %s" % (rva(vt), vt_blk.getName()))
                    for func_addr in scan_for_vtable_refs(vt):
                        is_ctor = check_vptr_write(func_addr, vt)
                        log("        ctor candidate @ 0x%x ctor=%s" % (rva(func_addr), is_ctor))
                        if is_ctor and cls not in results:
                            results[cls] = (rva(func_addr), vt)

    log("")
    log("=== SUMMARY ===")
    for cls in CLASSES:
        if cls in results:
            log("  %s ctor: 0x%x vtable: 0x%x" % (cls, results[cls][0], results[cls][1]))
        else:
            log("  %s: NOT FOUND" % cls)

    with open(OUT, "w") as fh:
        fh.write("export const offsets = Object.freeze({\n")
        for cls, (ctor_rva, vt_rva) in sorted(results.items()):
            fh.write("  %s_ctor: 0x%x,\n" % (cls, ctor_rva))
            fh.write("  %s_vtable: 0x%x,\n" % (cls, vt_rva))
        fh.write("});\n")

    with open(REPORT, "w") as fh:
        fh.write("classes found: %d / %d\n" % (len(results), len(CLASSES)))
        for cls, (ctor_rva, vt_rva) in sorted(results.items()):
            fh.write("  %s ctor=0x%x vtable=0x%x\n" % (cls, ctor_rva, vt_rva))

    log("[+] wrote %s" % OUT)

try:
    main()
except SystemExit:
    raise
except Exception as e:
    log("FATAL: %s" % e)
    traceback.print_exc()