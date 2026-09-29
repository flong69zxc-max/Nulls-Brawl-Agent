# -*- coding: utf-8 -*-
# @runtime Jython

import os
import sys
import time
import traceback

WS = os.environ.get("GITHUB_WORKSPACE", "/tmp")
OUT = os.path.join(WS, "ctors_resolved.js")
REPORT = os.path.join(WS, "ctors_report.txt")
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


def img_base():
    try:
        return int(currentProgram.getImageBase().getOffset())
    except:
        return 0x100000000


BASE = img_base()


def rva(a):
    try:
        return int(a.getOffset()) - BASE
    except:
        return -1


def blk(a):
    try:
        return getMemoryBlock(a)
    except:
        return None


def is_code(a):
    b = blk(a)
    return b is not None and b.isExecute()


def is_data(a):
    b = blk(a)
    return b is not None and b.isRead() and not b.isExecute()


def read_ptr(a):
    try:
        return currentProgram.getMemory().getLong(a) & 0xFFFFFFFFFFFFFFFF
    except:
        return None


def find_refs(a):
    out = []
    try:
        rm = currentProgram.getReferenceManager()
        it = rm.getReferencesTo(a).iterator()
        while it.hasNext():
            try:
                out.append(it.next().getFromAddress())
            except:
                break
    except:
        pass
    return out


def build_string_index():
    listing = currentProgram.getListing()
    idx = {}
    total = 0
    for b in currentProgram.getMemory().getBlocks():
        if time.time() - START > BUDGET - 500:
            break
        n = b.getName()
        if not ("cstring" in n or "objc" in n.lower() or "ustring" in n):
            continue
        end = b.getEnd()
        try:
            it = listing.getDefinedData(b.getStart(), True)
        except:
            continue
        while it.hasNext():
            if time.time() - START > BUDGET - 500:
                break
            try:
                d = it.next()
            except:
                break
            if d is None:
                continue
            try:
                if d.getAddress().compareTo(end) > 0:
                    break
                if not d.hasStringValue():
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


BAD_FN = ["log", "Log", "print", "Print", "trace", "Trace", "assert", "Assert",
          "debug", "Debug", "os_log", "_os_log", "vsnprintf", "snprintf",
          "printf", "NSString", "format", "abort", "panic"]


def is_logger(f):
    if f is None:
        return False
    n = f.getName()
    for b in BAD_FN:
        if b in n:
            return True
    return False


def expand_vtable(anchor):
    start = anchor
    prev = anchor.subtract(8)
    for _ in range(256):
        v = read_ptr(prev)
        if v is None or v == 0:
            break
        try:
            va = toAddr(v)
        except:
            break
        if not is_code(va):
            break
        start = prev
        prev = prev.subtract(8)
    slots = []
    cur = start
    for _ in range(512):
        v = read_ptr(cur)
        if v is None or v == 0:
            break
        try:
            va = toAddr(v)
        except:
            break
        if not is_code(va):
            break
        slots.append((cur, va))
        cur = cur.add(8)
    return start, slots


def score_vtable(slots):
    n = len(slots)
    if n < 2 or n > 256:
        return -1
    s = n * 2
    if 4 <= n <= 128:
        s += 20
    addrs = [int(t.getOffset()) for _, t in slots]
    spread = max(addrs) - min(addrs)
    if spread < 0x400000:
        s += 10
    return s


def find_vtables_for_entry(entry):
    cands = []
    for ra in find_refs(entry):
        if not is_data(ra):
            continue
        vt_start, slots = expand_vtable(ra)
        sc = score_vtable(slots)
        if sc > 0:
            cands.append((sc, vt_start, slots))
    cands.sort(key=lambda x: -x[0])
    return cands


def score_ctor(f, vt_start):
    if f is None:
        return -1
    body = f.getBody()
    if body is None:
        return -1
    n = body.getNumAddresses()
    if n < 16 or n > 4096:
        return -5
    s = 0
    if 32 <= n <= 1500:
        s += 10
    listing = currentProgram.getListing()
    it = listing.getInstructions(body, True)
    bl = 0
    str_z = 0
    cnt = 0
    while it.hasNext() and cnt < 400:
        cnt += 1
        i = it.next()
        mn = i.getMnemonicString().lower()
        if mn in ("bl", "blr"):
            bl += 1
        elif mn in ("str", "stp", "stur"):
            txt = i.toString()
            if "xzr" in txt or "wzr" in txt:
                str_z += 1
    s += min(bl, 10) * 2
    s += min(str_z, 20)
    if bl == 0:
        s -= 15
    refs_inside = 0
    try:
        rm = currentProgram.getReferenceManager()
        it2 = rm.getReferencesTo(vt_start).iterator()
        while it2.hasNext():
            r = it2.next()
            fa = r.getFromAddress()
            if body.contains(fa):
                refs_inside += 1
    except:
        pass
    if refs_inside == 0:
        s -= 10
    else:
        s += refs_inside * 5
    return s


def find_ctors_for_vtable(vt_start):
    cands = []
    seen = set()
    for ra in find_refs(vt_start):
        if not is_code(ra):
            continue
        f = getFunctionContaining(ra)
        if f is None:
            continue
        k = int(f.getEntryPoint().getOffset())
        if k in seen:
            continue
        seen.add(k)
        sc = score_ctor(f, vt_start)
        cands.append((sc, f))
    cands.sort(key=lambda x: -x[0])
    return cands


def scan_class(cls, idx):
    addrs = []
    for s, al in idx.items():
        if s == cls or s.startswith(cls + "::") or ("::" + cls) in s:
            addrs.extend(al)
    if not addrs:
        return None

    anchors = []
    seen = set()
    for sa in addrs[:24]:
        for ra in find_refs(sa):
            f = getFunctionContaining(ra)
            if f is None:
                continue
            if is_logger(f):
                continue
            fe = f.getEntryPoint()
            k = int(fe.getOffset())
            if k in seen:
                continue
            seen.add(k)
            anchors.append((fe, sa, f))
    if not anchors:
        return None

    res = {"class": cls, "method": None, "vtable": None, "ctor": None, "slots": []}

    best_vt = None
    for fe, sa, f in anchors:
        cands = find_vtables_for_entry(fe)
        if not cands:
            continue
        sc, vt_start, slots = cands[0]
        if best_vt is None or sc > best_vt[0]:
            best_vt = (sc, vt_start, slots, fe, sa, f)

    if best_vt is None:
        fe, sa, f = anchors[0]
        res["method"] = (rva(fe), f.getName(), rva(sa))
        return res

    _, vt_start, slots, fe, sa, f = best_vt
    res["method"] = (rva(fe), f.getName(), rva(sa))
    res["vtable"] = rva(vt_start)
    res["slots"] = [(rva(a), rva(t)) for a, t in slots[:128]]

    ctors = find_ctors_for_vtable(vt_start)
    if ctors:
        sc, c = ctors[0]
        if sc > 0:
            res["ctor"] = (rva(c.getEntryPoint()), c.getName(), sc)

    return res


def main():
    log("=== find_ctors_ios ===")
    log("program: %s" % currentProgram.getName())
    log("image base: 0x%x" % BASE)

    idx = build_string_index()
    if not idx:
        log("[!] no strings")
        return

    results = []
    for cls in CLASSES:
        if time.time() - START > BUDGET - 60:
            log("[!] budget exhausted")
            break
        try:
            r = scan_class(cls, idx)
        except Exception as e:
            log("[!] %s: %s" % (cls, e))
            continue
        if r is None:
            continue
        results.append(r)
        if r.get("ctor"):
            log("%-34s ctor=0x%08x vt=0x%08x meth=0x%08x %s" % (
                cls, r["ctor"][0], r["vtable"], r["method"][0], r["ctor"][1]))
        elif r.get("vtable") is not None:
            log("%-34s vt=0x%08x meth=0x%08x ctor=?" % (
                cls, r["vtable"], r["method"][0]))
        elif r.get("method"):
            log("%-34s meth=0x%08x vt=?" % (cls, r["method"][0]))

    with open(REPORT, "w") as fh:
        fh.write("# iOS ctor resolution (rtti-less)\n")
        fh.write("# image_base=0x%x\n\n" % BASE)
        for r in results:
            fh.write("=== %s ===\n" % r["class"])
            if r.get("method"):
                fh.write("  method: rva=0x%08x  %s  (str@0x%x)\n" % r["method"])
            if r.get("vtable") is not None:
                fh.write("  vtable: rva=0x%08x  slots=%d\n" % (
                    r["vtable"], len(r.get("slots", []))))
            if r.get("ctor"):
                fh.write("  ctor:   rva=0x%08x  score=%d  %s\n" % r["ctor"])
            for i, (sa, ta) in enumerate(r.get("slots", [])):
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


try:
    main()
except SystemExit:
    raise
except Exception as e:
    log("FATAL: %s" % e)
    traceback.print_exc()