# -*- coding: utf-8 -*-
# @runtime Jython

import os
import re
import sys
import json
import time
import traceback

WS = os.environ.get("GITHUB_WORKSPACE", "/tmp")
OFF_IN = os.path.join(WS, "offsets.js")
OFF_OUT = os.path.join(WS, "offsets_new.js")
REPORT = os.path.join(WS, "offsets_report.txt")
SIGDB = os.path.join(WS, "signatures.json")

TEXT_BASE = 0x100000000
SIG_INSN_COUNT = 10
MIN_FUNC_RVA = 0x10000
BUDGET_SEC = 5400

L = []
START = time.time()

def log(m):
    print(m)
    sys.stdout.flush()

def w(s):
    L.append(s)

def addr_from_rva(rva):
    s = "%X" % (TEXT_BASE + rva)
    return currentProgram.getAddressFactory().getAddress(s)

def rva_from_addr(a):
    return int(a.getOffset()) - TEXT_BASE

def read_offsets(path):
    out = {}
    if not os.path.exists(path):
        return out
    fh = open(path, "r")
    content = fh.read()
    fh.close()
    for m in re.finditer(r"([A-Za-z_][A-Za-z0-9_]*)\s*:\s*0x([0-9a-fA-F]+)", content):
        out[m.group(1)] = int(m.group(2), 16)
    return out

def is_branch_like(insn):
    try:
        mn = insn.getMnemonicString().lower()
    except Exception:
        return False
    if mn in ("b", "bl", "br", "blr", "ret", "cbz", "cbnz", "tbz", "tbnz", "adrp", "adr"):
        return True
    if mn.startswith("b."):
        return True
    return False

def function_signature(f, n=SIG_INSN_COUNT):
    out = []
    listing = currentProgram.getListing()
    a = f.getEntryPoint()
    for _ in range(n):
        insn = listing.getInstructionAt(a)
        if insn is None:
            break
        try:
            if is_branch_like(insn):
                out.append("????????")
            else:
                b = insn.getBytes()
                out.append("".join("%02X" % (int(x) & 0xFF) for x in b))
        except Exception:
            break
        try:
            a = a.add(insn.getLength())
        except Exception:
            break
    return "".join(out)

def load_sigdb():
    if not os.path.exists(SIGDB):
        return {}
    try:
        fh = open(SIGDB, "r")
        d = json.load(fh)
        fh.close()
        return d
    except Exception as e:
        log("[!] sigdb load failed: %s" % e)
        return {}

def save_sigdb(d):
    try:
        fh = open(SIGDB, "w")
        json.dump(d, fh, indent=2, sort_keys=True)
        fh.close()
    except Exception as e:
        log("[!] sigdb save failed: %s" % e)

def find_function_exact(rva):
    try:
        a = addr_from_rva(rva)
    except Exception:
        return None
    f = getFunctionAt(a)
    if f is not None:
        return f
    f = getFunctionContaining(a)
    if f is not None:
        try:
            if int(f.getEntryPoint().getOffset()) == TEXT_BASE + rva:
                return f
        except Exception:
            return None
    return None

def build_sig_index(min_len=8):
    idx = {}
    fm = currentProgram.getFunctionManager()
    it = fm.getFunctions(True)
    count = 0
    indexed = 0
    while it.hasNext():
        if time.time() - START > BUDGET_SEC - 300:
            log("[!] sig index budget hit at %d funcs" % count)
            break
        try:
            f = it.next()
        except Exception:
            break
        count += 1
        if count % 5000 == 0:
            log("[*] indexed %d funcs (%d sigs)" % (count, indexed))
        try:
            sig = function_signature(f, 6)
            if len(sig) >= min_len:
                idx.setdefault(sig, []).append(f.getEntryPoint())
                indexed += 1
        except Exception:
            continue
    log("[*] sig index built: %d funcs, %d unique sigs" % (count, len(idx)))
    return idx

def main():
    log("=== find_offsets ===")
    offs = read_offsets(OFF_IN)
    log("[*] parsed %d entries from offsets.js" % len(offs))

    sigdb = load_sigdb()
    log("[*] signatures.json entries: %d" % len(sigdb))

    resolved = {}
    verified = 0
    rematched = 0
    failures = []
    new_sigs = {}

    sig_index = None

    for name, rva in offs.items():
        if rva < MIN_FUNC_RVA:
            resolved[name] = rva
            continue
        if time.time() - START > BUDGET_SEC:
            failures.append((name, rva, "budget"))
            continue

        f = find_function_exact(rva)
        if f is not None:
            resolved[name] = rva
            verified += 1
            try:
                s = function_signature(f)
                if s:
                    new_sigs[name] = s
            except Exception:
                pass
            continue

        sig = sigdb.get(name)
        if sig:
            if sig_index is None:
                sig_index = build_sig_index()
            cands = sig_index.get(sig, [])
            if len(cands) == 1:
                nrva = rva_from_addr(cands[0])
                resolved[name] = nrva
                rematched += 1
                new_sigs[name] = sig
                continue
            elif len(cands) > 1:
                failures.append((name, rva, "ambiguous:%d" % len(cands)))
                continue
            else:
                failures.append((name, rva, "sig-miss"))
                continue

        failures.append((name, rva, "no-func"))

    fh = open(OFF_OUT, "w")
    fh.write("export const offsets = Object.freeze(\n{\n")
    for name in sorted(resolved.keys()):
        fh.write("    %s: 0x%x,\n" % (name, resolved[name]))
    fh.write("});\n")
    fh.close()

    save_sigdb(new_sigs)

    w("elapsed %.1fs" % (time.time() - START))
    w("input: %d" % len(offs))
    w("resolved: %d (verified=%d rematched=%d)" % (len(resolved), verified, rematched))
    w("failed: %d" % len(failures))
    for n, r, msg in failures:
        w("  FAIL %s @ 0x%x (%s)" % (n, r, msg))

    fh = open(REPORT, "w")
    for line in L:
        fh.write(line + "\n")
    fh.close()
    log("[+] wrote %s" % OFF_OUT)
    log("[+] wrote %s" % REPORT)
    log("[+] signatures.json entries written: %d" % len(new_sigs))

try:
    main()
except Exception as e:
    log("FATAL: %s" % e)
    traceback.print_exc()
    try:
        fh = open(REPORT, "w")
        fh.write("FATAL: %s\n%s\n" % (e, traceback.format_exc()))
        fh.close()
    except Exception:
        pass
