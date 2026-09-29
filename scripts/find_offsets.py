# -*- coding: utf-8 -*-
# @runtime Jython

import os
import sys
import time
import traceback

WS = os.environ.get("GITHUB_WORKSPACE", "/tmp")
OUT = os.path.join(WS, "ctors_resolved.js")
REPORT = os.path.join(WS, "ctors_report.txt")
BASE = 0x100000000
BUDGET = 1500
START = time.time()

CLASSES = [
    "LogicBattleModeClient", "BattleMode", "LogicGameObjectClient",
    "BattleScreen", "Gui", "GUI", "LogicProjectileData", "LogicProjectileClient",
    "LogicProjectileServer", "LogicCharacterData", "LogicCharacterClient",
    "LogicCharacterClientOwn", "LogicSkillData", "LogicSkillClient",
    "LogicTileData", "LogicTile", "LogicTileMap", "LogicDataTables",
    "LogicGameObjectManagerClient", "LogicGameObjectServer",
    "LogicGameModeUtil", "LogicData", "LogicRandom", "LogicJSONObject",
    "LogicCompressedString", "LogicPlayerMap", "LogicPlayerMapUtil",
    "LogicLongToCodeConverterUtil", "LogicSkillData", "LogicAccessory",
    "GameButton", "GameSelectableButton", "CustomButton", "RadioButton",
    "GenericPopup", "PopupBase", "DropGUIContainer", "GameSliderComponent",
    "MapEditorModifierItem", "MapEditorModifierPopup",
    "Sprite", "Stage", "DisplayObject", "MovieClip", "MovieClipHelper",
    "TextField", "DecoratedTextField", "String", "Application", "Name",
    "ClientInput", "ClientInputManager", "ClientInputMessage",
    "Projectile", "GameMain", "DecalManager", "GameObjectManager",
    "RenderSystem", "ResourceManager", "StringTable", "FramerateManager",
    "MessageManager", "AllianceManager", "CombatHUD", "Character",
    "GameScreen", "MapEditorScreen", "GameSettings", "GameStateManager",
    "HomeMode", "HomePage", "HomeScreen", "Screen", "ScrollArea",
    "GlobalID", "AnalyticEvent", "ResourceListener",
    "AreaEffectData", "TeamChatMessage", "TeamSetMemberReadyMessage",
    "StartSpectateMessage", "PiranhaMessage",
    "HashTagCodeGenerator", "CSVRow", "CSVTable",
]

def log(m):
    sys.stdout.write(m + "\n")
    sys.stdout.flush()

def rva(a):
    try:
        return int(a.getOffset()) - BASE
    except:
        return -1

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

def func_has_str_x0(f, max_instr=60):
    if f is None:
        return 0
    listing = currentProgram.getListing()
    it = f.getBody().getAddresses(True)
    n = 0
    hits = 0
    while it.hasNext() and n < max_instr:
        a = it.next()
        i = listing.getInstructionAt(a)
        if i is None:
            continue
        n += 1
        s = i.toString()
        mn = i.getMnemonicString().lower()
        if mn == "str" and ("[x0]" in s or "[x0," in s):
            hits += 1
    return hits

def is_logger(f):
    if f is None:
        return False
    name = f.getName()
    bad = ["log", "Log", "print", "Print", "trace", "Trace", "assert", "Assert",
           "debug", "Debug", "os_log", "_os_log", "NSString", "format"]
    for b in bad:
        if b in name:
            return True
    listing = currentProgram.getListing()
    it = f.getBody().getAddresses(True)
    n = 0
    has_format = 0
    while it.hasNext() and n < 80:
        a = it.next()
        i = listing.getInstructionAt(a)
        if i is None:
            continue
        n += 1
        mn = i.getMnemonicString().lower()
        if mn == "bl":
            flows = i.getFlows()
            if flows:
                tgt = getFunctionAt(flows[0])
                if tgt is not None:
                    tn = tgt.getName()
                    if "NSString" in tn or "format" in tn or "_os_log" in tn or "printf" in tn:
                        has_format += 1
    return has_format >= 2

def score_func(f):
    if f is None:
        return -1
    score = 0
    n = func_has_str_x0(f)
    score += n * 10
    if is_logger(f):
        score -= 100
    size = f.getBody().getNumAddresses()
    if size > 400:
        score -= 20
    if size < 20:
        score -= 30
    return score

def scan_class(cls, idx):
    out = []
    saddrs = idx.get(cls, [])
    if not saddrs:
        for s, addrs in idx.items():
            if len(s) < 64 and (s == cls or ("::" + cls) in s or s.startswith(cls + "::")):
                saddrs.extend(addrs)
    if not saddrs:
        return out
    seen_funcs = set()
    for sa in saddrs[:8]:
        for ra in find_refs(sa):
            f = getFunctionContaining(ra)
            if f is None:
                continue
            fe = f.getEntryPoint()
            if fe in seen_funcs:
                continue
            seen_funcs.add(fe)
            sc = score_func(f)
            out.append((sc, rva(fe), f.getName(), rva(sa)))
    out.sort(key=lambda x: -x[0])
    return out

def main():
    log("=== find_ctors ===")
    log("program: %s" % currentProgram.getName())

    idx = build_string_index()
    if not idx:
        log("[!] no strings")
        return

    results = {}
    for cls in CLASSES:
        cands = scan_class(cls, idx)
        if not cands:
            continue
        results[cls] = cands[:5]

    with open(REPORT, "w") as r:
        r.write("# ctor candidates per class\n")
        r.write("# score rva name via_str_rva\n\n")
        for cls in sorted(results.keys()):
            r.write("=== %s ===\n" % cls)
            for sc, fe, name, srva in results[cls]:
                r.write("  score=%4d  rva=0x%08x  %-30s  str@0x%x\n" % (sc, fe, name, srva))
            r.write("\n")

    with open(OUT, "w") as fh:
        fh.write("// auto-generated by find_ctors.py\n")
        fh.write("export const ctors = Object.freeze({\n")
        for cls in sorted(results.keys()):
            cands = [c for c in results[cls] if c[0] > 0]
            if not cands:
                fh.write("  // %s: no positive-score candidate\n" % cls)
                continue
            sc, fe, name, srva = cands[0]
            fh.write("  %s: 0x%x, // score=%d %s\n" % (cls, fe, sc, name))
        fh.write("});\n")

    for cls in sorted(results.keys()):
        cands = results[cls]
        if cands:
            sc, fe, name, srva = cands[0]
            log("%-32s best: score=%4d rva=0x%08x %s" % (cls, sc, fe, name))

    log("")
    log("[+] wrote %s and %s" % (OUT, REPORT))

try:
    main()
except SystemExit:
    raise
except Exception as e:
    log("FATAL: %s" % e)
    traceback.print_exc()