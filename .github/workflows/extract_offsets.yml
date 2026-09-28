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
OFF_OUT = os.path.join(WS, "offsets_resolved.js")
REPORT = os.path.join(WS, "offsets_report.txt")
SIGDB = os.path.join(WS, "signatures.json")

TEXT_BASE = 0x100000000
MIN_FUNC_RVA = 0x10000
BUDGET_SEC = 3600
MIN_EXPECTED_ENTRIES = 200

L = []
START = time.time()

log = lambda m: (sys.stdout.write(m + "\n"), sys.stdout.flush())
w = lambda s: L.append(s)

# --- Строковые якоря для функций (на основе SCRE и DeepWiki) ---
STRING_ANCHORS = {
    "HomePage_startGame": ["TID_MATCHMAKE_FAILED_15"],
    "LogicBattleModeClient_update": ["LogicBattleModeClient"],
    "BattleScreen_activateSkill": ["activateSkill"],
    "Gui_showFloaterTextAtDefaultPos": ["showFloaterText"],
    "StringCtor": ["String not found:"],
    "SCIDConfig__getBool": ["DisableIngameFriends"],
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

# --- Флаги разработчика (SCRE: v53, v44, DeepWiki) ---
DEVELOPER_FLAGS = {
    "LogicVersion_isDeveloperBuild": ["isDeveloperBuild"],
    "LogicVersion_isDev": ["isDev"],
    "LogicVersion_isProd": ["isProd"],
}

def addr(rva_val):
    try:
        return currentProgram.getAddressFactory().getAddress("%X" % (TEXT_BASE + rva_val))
    except:
        return None

def rva(a):
    return int(a.getOffset()) - TEXT_BASE

def read_offsets():
    out = {}
    if not os.path.exists(OFF_IN):
        log("[!] offsets.js not found")
        return out
    try:
        fh = open(OFF_IN, "r")
        content = fh.read()
        fh.close()
    except Exception as e:
        log("[!] read fail: %s" % e)
        return out
    for m in re.finditer(r"([A-Za-z_][A-Za-z0-9_]*)\s*:\s*0x([0-9a-fA-F]+)", content):
        out[m.group(1)] = int(m.group(2), 16)
    return out

def load_sigdb():
    if not os.path.exists(SIGDB):
        return {}
    try:
        fh = open(SIGDB, "r")
        d = json.load(fh)
        fh.close()
        if isinstance(d, dict):
            return d
        return {}
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

def find_by_strings(name):
    anchors = STRING_ANCHORS.get(name)
    if not anchors:
        return None
    st = currentProgram.getSymbolTable()
    rm = currentProgram.getReferenceManager()
    for anchor in anchors:
        try:
            it = st.getSymbolIterator(anchor, True)
            if it is None:
                continue
            while it.hasNext():
                sym = it.next()
                sa = sym.getAddress()
                if sa is None:
                    continue
                refs = rm.getReferencesTo(sa)
                rit = refs.iterator()
                while rit.hasNext():
                    r = rit.next()
                    fa = r.getFromAddress()
                    f = getFunctionContaining(fa)
                    if f is None:
                        continue
                    fr = rva(f.getEntryPoint())
                    if fr < MIN_FUNC_RVA:
                        continue
                    return f
        except:
            continue
    return None

def find_developer_flags():
    """Поиск флагов разработчика по строкам и символам (метод SCRE)."""
    log("[*] searching developer flags...")
    found_flags = {}
    st = currentProgram.getSymbolTable()
    rm = currentProgram.getReferenceManager()
    
    for flag_name, anchors in DEVELOPER_FLAGS.items():
        for anchor in anchors:
            try:
                it = st.getSymbolIterator(anchor, True)
                if it is None:
                    continue
                while it.hasNext():
                    sym = it.next()
                    sa = sym.getAddress()
                    if sa is None:
                        continue
                    # Ищем ссылки на символ
                    refs = rm.getReferencesTo(sa)
                    rit = refs.iterator()
                    while rit.hasNext():
                        r = rit.next()
                        fa = r.getFromAddress()
                        f = getFunctionContaining(fa)
                        if f is None:
                            continue
                        fr = rva(f.getEntryPoint())
                        if fr < MIN_FUNC_RVA:
                            continue
                        found_flags[flag_name] = fr
                        log("[+] found %s @ 0x%x" % (flag_name, fr))
                        break
                    if flag_name in found_flags:
                        break
                if flag_name in found_flags:
                    break
            except:
                continue
    return found_flags

def main():
    log("=== find_offsets (SCRE-style) ===")
    offs = read_offsets()
    log("[*] parsed %d entries from offsets.js" % len(offs))

    if len(offs) < MIN_EXPECTED_ENTRIES:
        msg = "ABORT: offsets.js has only %d entries, expected >= %d. Fix offsets.js first." % (len(offs), MIN_EXPECTED_ENTRIES)
        log("[!] " + msg)
        try:
            fh = open(REPORT, "w")
            fh.write(msg + "\n")
            fh.close()
        except:
            pass
        sys.exit(1)

    sigdb = load_sigdb()
    log("[*] sigdb: %d entries" % len(sigdb))

    resolved = {}
    verified = 0
    rematched = 0
    string_hits = 0
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

        # 1. Точное совпадение по старому RVA
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

        # 2. Поиск по сигнатуре (если есть в базе)
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

        # 3. Поиск по строковым якорям (SCRE-метод)
        f = find_by_strings(name)
        if f is not None:
            nr = rva(f.getEntryPoint())
            resolved[name] = nr
            string_hits += 1
            try:
                s = sig(f)
                if s:
                    new_sigs[name] = s
            except:
                pass
            continue

        failures.append((name, old_rva, "no-func"))

    # Поиск флагов разработчика
    dev_flags = find_developer_flags()
    for flag_name, flag_rva in dev_flags.items():
        resolved[flag_name] = flag_rva

    fh = open(OFF_OUT, "w")
    fh.write("export const offsets = Object.freeze(\n{\n")
    for n in sorted(offs.keys()):
        if n in resolved:
            fh.write("    %s: 0x%x,\n" % (n, resolved[n]))
        else:
            fh.write("    %s: 0x%x,\n" % (n, offs[n]))
    for n in sorted(dev_flags.keys()):
        fh.write("    %s: 0x%x,\n" % (n, dev_flags[n]))
    fh.write("});\n")
    fh.close()

    save_sigdb(new_sigs)

    w("elapsed %.1fs" % (time.time() - START))
    w("input: %d" % len(offs))
    w("resolved: %d (verified=%d rematched=%d string=%d)" % (
        len(resolved), verified, rematched, string_hits))
    w("developer flags found: %d" % len(dev_flags))
    for n, r in dev_flags.items():
        w("  DEV %s @ 0x%x" % (n, r))
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