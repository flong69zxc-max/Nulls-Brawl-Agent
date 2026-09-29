#!/usr/bin/env python3
import os
import sys
import json
import time
import traceback

import r2pipe

WS = os.environ.get("GITHUB_WORKSPACE", "/tmp")
BIN = os.environ.get("R2_BIN", "/tmp/brawl_bin")
OUT = os.path.join(WS, "offsets_resolved.js")
REPORT = os.path.join(WS, "offsets_report.txt")
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
    "LogicLongToCodeConverterUtil", "LogicAccessory",
    "GameButton", "GameSelectableButton", "CustomButton", "RadioButton",
    "GenericPopup", "PopupBase", "DropGUIContainer", "GameSliderComponent",
    "MapEditorModifierItem", "MapEditorModifierPopup",
    "Sprite", "Stage", "DisplayObject", "MovieClip", "MovieClipHelper",
    "TextField", "DecoratedTextField", "Application", "Name",
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

BAD_FN = ["log", "print", "trace", "assert", "debug", "os_log",
          "vsnprintf", "snprintf", "printf", "NSString", "format",
          "abort", "panic", "raise", "throw"]


def log(m):
    sys.stdout.write(m + "\n")
    sys.stdout.flush()


def rva(addr, base):
    return addr - base


def cmd(r2, c):
    try:
        return r2.cmdj(c)
    except Exception:
        return None


def is_logger(name):
    n = name or ""
    for b in BAD_FN:
        if b in n:
            return True
    return False


def main():
    log("=== find_offsets_r2 ===")
    log("bin: %s" % BIN)

    r2 = r2pipe.open(BIN, flags=["-2"])
    r2.cmd("e anal.timeout=600")
    r2.cmd("e anal.hasnext=true")
    r2.cmd("e scr.color=0")
    r2.cmd("aa")

    info = cmd(r2, "ij")
    if not info:
        log("[!] cannot get bin info")
        return
    base = info.get("baddr", 0x100000000)
    log("base: 0x%x" % base)

    strings = cmd(r2, "izj")
    if not strings:
        log("[!] no strings")
        return
    log("[*] strings: %d" % len(strings))

    str_index = {}
    for s in strings:
        v = s.get("string", "")
        if not v:
            continue
        str_index.setdefault(v, []).append(s.get("vaddr", 0))

    results = []
    for cls in CLASSES:
        if time.time() - START > BUDGET - 60:
            log("[!] budget exhausted")
            break
        try:
            r = scan_class(r2, cls, str_index, base)
        except Exception as e:
            log("[%s] EXCEPTION: %s" % (cls, e))
            traceback.print_exc()
            continue
        if r:
            results.append(r)

    r2.quit()

    with open(REPORT, "w") as fh:
        fh.write("# r2 ctor resolution\n")
        fh.write("# base=0x%x\n\n" % base)
        for r in results:
            fh.write("=== %s ===\n" % r["class"])
            if r.get("method"):
                fh.write("  method: rva=0x%08x  %s\n" % (r["method"][0], r["method"][1]))
            if r.get("vtable"):
                fh.write("  vtable: rva=0x%08x  slots=%d\n" % (r["vtable"], len(r.get("slots", []))))
            if r.get("ctor"):
                fh.write("  ctor:   rva=0x%08x  %s\n" % (r["ctor"][0], r["ctor"][1]))
            for i, (sa, ta) in enumerate(r.get("slots", [])[:64]):
                fh.write("    [%3d] 0x%08x -> 0x%08x\n" % (i, sa, ta))
            fh.write("\n")

    with open(OUT, "w") as fh:
        fh.write("export const ctors = Object.freeze({\n")
        for r in results:
            if r.get("ctor"):
                fh.write("  %s: 0x%x,\n" % (r["class"], r["ctor"][0]))
            else:
                fh.write("  // %s: unresolved\n" % r["class"])
        fh.write("});\n")

    log("[+] wrote %s and %s" % (OUT, REPORT))


def scan_class(r2, cls, str_index, base):
    addrs = []
    for s, al in str_index.items():
        if s == cls or s.startswith(cls + "::") or ("::" + cls) in s:
            addrs.extend(al)
    if not addrs:
        log("[%s] no string anchors" % cls)
        return None

    anchors = []
    seen = set()
    for sa in addrs[:32]:
        xrefs = cmd(r2, "axtj @ 0x%x" % sa)
        if not xrefs:
            continue
        for x in xrefs:
            fcn = x.get("fcn_addr")
            if not fcn or fcn in seen:
                continue
            fname = x.get("fcn_name", "")
            if is_logger(fname):
                continue
            seen.add(fcn)
            anchors.append((fcn, sa, fname))

    if not anchors:
        log("[%s] no non-logger anchors" % cls)
        return None

    log("[%s] anchors: %d" % (cls, len(anchors)))

    res = {"class": cls, "method": None, "vtable": None, "ctor": None, "slots": []}

    best_vt = None
    for fe, sa, fname in anchors:
        vt = find_vtable(r2, fe)
        if vt:
            sc, vt_start, slots = vt
            if best_vt is None or sc > best_vt[0]:
                best_vt = (sc, vt_start, slots, fe, sa, fname)

    if best_vt is None:
        fe, sa, fname = anchors[0]
        res["method"] = (rva(fe, base), fname)
        log("[%s] FAILED: no vtable" % cls)
        return res

    _, vt_start, slots, fe, sa, fname = best_vt
    res["method"] = (rva(fe, base), fname)
    res["vtable"] = rva(vt_start, base)
    res["slots"] = [(rva(a, base), rva(t, base)) for a, t in slots[:256]]

    ctors = find_ctors(r2, vt_start)
    if ctors:
        sc, c, cname = ctors[0]
        res["ctor"] = (rva(c, base), cname)
        log("[%s] ctor 0x%x %s" % (cls, rva(c, base), cname))
    else:
        log("[%s] no ctor for vtable 0x%x" % (cls, rva(vt_start, base)))

    return res


def find_vtable(r2, entry):
    cands = []
    xrefs = cmd(r2, "axtj @ 0x%x" % entry)
    if not xrefs:
        return None
    for x in xrefs:
        frm = x.get("from")
        if not frm:
            continue
        # check if from is in data section
        sec = cmd(r2, "iSj @ 0x%x" % frm)
        if not sec:
            continue
        if sec.get("perm", "") in ("r--", "rw-"):
            vt_start, slots = expand_vtable(r2, frm)
            sc = len(slots)
            if sc >= 4:
                cands.append((sc, vt_start, slots))
    if not cands:
        return None
    cands.sort(key=lambda x: -x[0])
    return cands[0]


def expand_vtable(r2, anchor):
    start = anchor
    prev = anchor - 8
    for _ in range(256):
        val = read_ptr(r2, prev)
        if not val:
            break
        if not is_code(r2, val):
            break
        start = prev
        prev -= 8
    slots = []
    cur = start
    for _ in range(512):
        val = read_ptr(r2, cur)
        if not val:
            break
        if not is_code(r2, val):
            break
        slots.append((cur, val))
        cur += 8
    return start, slots


def find_ctors(r2, vt_start):
    cands = []
    xrefs = cmd(r2, "axtj @ 0x%x" % vt_start)
    if not xrefs:
        return []
    seen = set()
    for x in xrefs:
        fcn = x.get("fcn_addr")
        if not fcn or fcn in seen:
            continue
        seen.add(fcn)
        # count bl instructions
        ops = cmd(r2, "aoj 20 @ 0x%x" % fcn)
        bl = 0
        if ops:
            for o in ops:
                if o.get("type") == "call":
                    bl += 1
        fname = x.get("fcn_name", "")
        cands.append((bl, fcn, fname))
    cands.sort(key=lambda x: -x[0])
    return cands


def read_ptr(r2, addr):
    try:
        return int(r2.cmd("pv8 @ 0x%x" % addr).strip(), 16)
    except Exception:
        return None


def is_code(r2, addr):
    try:
        sec = cmd(r2, "iSj @ 0x%x" % addr)
        if sec and "x" in sec.get("perm", ""):
            return True
    except Exception:
        pass
    return False


if __name__ == "__main__":
    main()