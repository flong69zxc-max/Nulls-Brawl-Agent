# -*- coding: utf-8 -*-
# @runtime Jython

import os
import re
import sys
import json
import time
import traceback
from jarray import zeros

WS = os.environ.get("GITHUB_WORKSPACE", "/tmp")
OFF_IN = os.path.join(WS, "offsets.js")
OFF_OUT = os.path.join(WS, "offsets_new.js")
REPORT = os.path.join(WS, "offsets_report.txt")
SIGDB = os.path.join(WS, "signatures.json")

TEXT_BASE = 0x100000000
MIN_FUNC_RVA = 0x10000
BUDGET_SEC = 5400

L = []
START = time.time()
SIGDB_CACHE = {}
FUNC_CACHE = {}
VTABLE_CACHE = {}

# Known string anchors for Brawl Stars functions.
# When a function is not found by old RVA or signature,
# the script searches for these strings and follows xrefs
# to the calling function.
STRING_ANCHORS = {
    "HomePage_startGame": ["TID_MATCHMAKE_FAILED_15"],
    "LogicBattleModeClient_update": ["LogicBattleModeClient"],
    "BattleScreen_activateSkill": ["activateSkill"],
    "Gui_showFloaterTextAtDefaultPos": ["showFloaterText"],
    "StringCtor": ["String not found:"],
    "LogicCharacterData_getCollisionRadius": ["CollisionRadius"],
    "LogicProjectileData_getRadius": ["ProjectileRadius"],
    "ClientInputManager_addInput": ["addInput"],
    "ResourceManager__isResourceLoaded": ["isResourceLoaded"],
    "MessageManager__receiveMessage": ["receiveMessage"],
    "MessageManager__sendMessage": ["sendMessage"],
    "LogicBattleModeClient_getOwnCharacter": ["getOwnCharacter"],
    "LogicGameObjectClient_getX": ["getX"],
    "LogicGameObjectClient_getY": ["getY"],
    "LogicGameObjectClient_getZ": ["getZ"],
    "Sprite_Sprite": ["Sprite"],
    "TextField_setText": ["setText"],
    "ScrollArea__scrollTo": ["scrollTo"],
    "DisplayObject__setXY": ["setXY"],
    "MovieClip__getTextFieldByName": ["getTextFieldByName"],
    "Sprite__addChild": ["addChild"],
    "Sprite__removeChild": ["removeChild"],
}

log = lambda m: (sys.stdout.write(m + "\n"), sys.stdout.flush())
w = lambda s: L.append(s)

def addr(rva):
    try:
        return currentProgram.getAddressFactory().getAddress("%X" % (TEXT_BASE + rva))
    except:
        return None

def rva(a):
    return int(a.getOffset()) - TEXT_BASE

def read_offsets():
    out = {}
    if not os.path.exists(OFF_IN):
        return out
    try:
        fh = open(OFF_IN, "r")
        for m in re.finditer(r"([A-Za-z_][A-Za-z0-9_]*)\s*:\s*0x([0-9a-fA-F]+)", fh.read()):
            out[m.group(1)] = int(m.group(2), 16)
        fh.close()
    except:
        pass
    return out

def load_sigdb():
    if not os.path.exists(SIGDB):
        return {}
    try:
        fh = open(SIGDB, "r")
        d = json.load(fh)
        fh.close()
        return d
    except:
        return {}

def save_sigdb(d):
    try:
        fh = open(SIGDB, "w")
        json.dump(d, fh, indent=2, sort_keys=True)
        fh.close()
    except:
        pass

def is_branch(insn):
    try:
        mn = insn.getMnemonicString().lower()
    except:
        return False
    if mn in ("b", "bl", "br", "blr", "ret", "cbz", "cbnz", "tbz", "tbnz", "adrp", "adr"):
        return True
    if mn.startswith("b."):
        return True
    return False

def sig(f, n=10):
    out = []
    listing = currentProgram.getListing()
    a = f.getEntryPoint()
    for _ in range(n):
        insn = listing.getInstructionAt(a)
        if insn is None:
            break
        try:
            if is_branch(insn):
                out.append("????????")
            else:
                out.append("".join("%02X" % (int(x) & 0xFF) for x in insn.getBytes()))
        except:
            break
        try:
            a = a.add(insn.getLength())
        except:
            break
    return "".join(out)

def find_exact(rva_val):
    a = addr(rva_val)
    if a is None:
        return None
    f = getFunctionAt(a)
    if f is not None:
        return f
    f = getFunctionContaining(a)
    if f is not None:
        try:
            if int(f.getEntryPoint().getOffset()) == TEXT_BASE + rva_val:
                return f
        except:
            return None
    return None

def find_by_strings(name, old_rva):
    anchors = STRING_ANCHORS.get(name)
    if not anchors:
        return None
    st = currentProgram.getSymbolTable()
    for anchor in anchors:
        try:
            for sym in st.getSymbolIterator():
                sname = str(sym.getName())
                if anchor.lower() not in sname.lower():
                    continue
                sa = sym.getAddress()
                if sa is None:
                    continue
                rm = currentProgram.getReferenceManager()
                refs = rm.getReferencesTo(sa)
                it = refs.iterator()
                while it.hasNext():
                    r = it.next()
                    fa = r.getFromAddress()
                    f = getFunctionContaining(fa)
                    if f is None:
                        continue
                    fr = rva(f.getEntryPoint())
                    if fr < MIN_FUNC_RVA:
                        continue
                    if old_rva is not None and fr == old_rva:
                        return f
                    if name in FUNC_CACHE:
                        return None
                    FUNC_CACHE[name] = f
                    return f
        except:
            continue
    return None

def build_sig_index(min_len=8):
    idx = {}
    fm = currentProgram.getFunctionManager()
    it = fm.getFunctions(True)
    count = 0
    while it.hasNext():
        if time.time() - START > BUDGET_SEC - 300:
            break
        try:
            f = it.next()
        except:
            break
        count += 1
        if count % 5000 == 0:
            log("[*] indexed %d funcs" % count)
        try:
            s = sig(f, 6)
            if len(s) >= min_len:
                idx.setdefault(s, []).append(f.getEntryPoint())
        except:
            continue
    log("[*] sig index: %d funcs, %d sigs" % (count, len(idx)))
    return idx

def find_vtable_method(name, old_rva):
    if VTABLE_CACHE.get("index") is None:
        VTABLE_CACHE["index"] = build_sig_index()
    sigdb = load_sigdb()
    s = sigdb.get(name)
    if not s:
        return None
    cands = VTABLE_CACHE["index"].get(s, [])
    if len(cands) == 1:
        return getFunctionAt(cands[0])
    return None

def main():
    log("=== find_offsets ===")
    offs = read_offsets()
    log("[*] parsed %d entries" % len(offs))
    sigdb = load_sigdb()
    log("[*] sigdb: %d entries" % len(sigdb))

    resolved = {}
    verified = 0
    rematched = 0
    found_by_string = 0
    failures = []
    new_sigs = {}
    sig_index = None

    for name, old_rva in offs.items():
        if old_rva < MIN_FUNC_RVA:
            resolved[name] = old_rva
            continue
        if time.time() - START > BUDGET_SEC:
            failures.append((name, old_rva, "budget"))
            continue

        f = find_exact(old_rva)
        if f is not None:
            resolved[name] = old_rva
            verified += 1
            try:
                s = sig(f)
                if s:
                    new_sigs[name] = s
            except:
                pass
            continue

        s = sigdb.get(name)
        if s:
            if sig_index is None:
                sig_index = build_sig_index()
            cands = sig_index.get(s, [])
            if len(cands) == 1:
                resolved[name] = rva(cands[0])
                rematched += 1
                new_sigs[name] = s
                continue
            elif len(cands) > 1:
                failures.append((name, old_rva, "ambiguous:%d" % len(cands)))
                continue

        f = find_by_strings(name, old_rva)
        if f is not None:
            nr = rva(f.getEntryPoint())
            resolved[name] = nr
            found_by_string += 1
            try:
                s = sig(f)
                if s:
                    new_sigs[name] = s
            except:
                pass
            continue

        failures.append((name, old_rva, "no-func"))

    fh = open(OFF_OUT, "w")
    fh.write("export const offsets = Object.freeze(\n{\n")
    for n in sorted(resolved.keys()):
        fh.write("    %s: 0x%x,\n" % (n, resolved[n]))
    fh.write("});\n")
    fh.close()

    save_sigdb(new_sigs)

    w("elapsed %.1fs" % (time.time() - START))
    w("input: %d" % len(offs))
    w("resolved: %d (verified=%d rematched=%d string=%d)" % (
        len(resolved), verified, rematched, found_by_string))
    w("failed: %d" % len(failures))
    for n, r, msg in failures:
        w("  FAIL %s @ 0x%x (%s)" % (n, r, msg))

    fh = open(REPORT, "w")
    for line in L:
        fh.write(line + "\n")
    fh.close()
    log("[+] wrote %s" % OFF_OUT)
    log("[+] wrote %s" % REPORT)

try:
    main()
except Exception as e:
    log("FATAL: %s" % e)
    traceback.print_exc()
    try:
        fh = open(REPORT, "w")
        fh.write("FATAL: %s\n%s\n" % (e, traceback.format_exc()))
        fh.close()
    except:
        pass