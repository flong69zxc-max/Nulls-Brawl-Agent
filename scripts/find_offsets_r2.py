#!/usr/bin/env python3
import os
import sys
import time
import traceback

import r2pipe

WS = os.environ.get("GITHUB_WORKSPACE", "/tmp")
BIN = os.environ.get("R2_BIN", "/tmp/brawl_bin")
OUT = os.path.join(WS, "offsets_resolved.js")
REPORT = os.path.join(WS, "offsets_report.txt")
DETAIL = os.path.join(WS, "ctors_detailed.log")
BUDGET = 2400
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

_log_fh = None


def log(m):
    line = "[%7.2f] %s" % (time.time() - START, m)
    try:
        sys.stdout.write(line + "\n")
        sys.stdout.flush()
    except Exception:
        pass
    if _log_fh is not None:
        try:
            _log_fh.write(line + "\n")
            _log_fh.flush()
        except Exception:
            pass


def cmdj(r2, c):
    try:
        return r2.cmdj(c)
    except Exception:
        return None


def cmd(r2, c):
    try:
        return r2.cmd(c)
    except Exception:
        return ""


def is_logger(name):
    if not name:
        return False
    n = name.lower()
    for b in ("log", "print", "trace", "assert", "debug", "fatal", "panic", "abort"):
        if b in n:
            return True
    return False


def addr_of(s, base):
    va = s.get("vaddr", 0)
    pa = s.get("paddr", 0)
    if va and va >= base:
        return va
    if pa and pa >= base:
        return pa
    if pa and pa > 0:
        return pa + base
    return 0


def build_string_index(r2, base):
    strings = cmdj(r2, "izj")
    if not strings:
        log("[!] izj returned nothing")
        return {}
    total = 0
    idx = {}
    for s in strings:
        txt = (s.get("string") or s.get("text") or "").strip()
        if not txt:
            continue
        a = addr_of(s, base)
        if not a:
            continue
        total += 1
        idx.setdefault(txt, []).append(a)
    log("[*] strings: %d unique: %d" % (total, len(idx)))
    return idx


def find_xrefs(r2, addr):
    xrefs = cmdj(r2, "axtj @ 0x%x" % addr)
    if xrefs:
        return xrefs
    return []


def collect_anchors(r2, cls, addrs):
    anchors = []
    seen = set()
    for sa in addrs[:64]:
        for x in find_xrefs(r2, sa):
            fcn = x.get("fcn_addr") or x.get("from")
            if not fcn:
                continue
            if fcn in seen:
                continue
            fname = x.get("fcn_name") or ""
            if is_logger(fname):
                continue
            seen.add(fcn)
            anchors.append((fcn, sa, fname))
    return anchors


def scan_class(r2, cls, str_index, base):
    addrs = []
    for s, al in str_index.items():
        if s == cls or s.startswith(cls + "::") or ("::" + cls) in s \
           or s.startswith(cls + " ") or s.startswith(cls + "\t"):
            addrs.extend(al)
    if not addrs:
        log("[%s] no string anchors" % cls)
        return None

    log("[%s] string anchors: %d" % (cls, len(addrs)))
    anchors = collect_anchors(r2, cls, addrs)
    if not anchors:
        log("[%s] no non-logger anchors (axtj empty for all strings)" % cls)
        for sa in addrs[:3]:
            raw = cmdj(r2, "axtj @ 0x%x" % sa)
            log("[%s]   axtj 0x%x -> %s" % (cls, sa, "None" if raw is None else "%d entries" % len(raw) if isinstance(raw, list) else "?"))
        return {"class": cls, "method": None, "vtable": None, "ctor": None}

    log("[%s] anchors: %d" % (cls, len(anchors)))
    for fe, sa, fname in anchors[:8]:
        log("[%s]   anchor 0x%x  %s  str@0x%x" % (cls, fe, fname, sa))

    fe, sa, fname = anchors[0]
    return {"class": cls, "method": (fe - base, fname), "vtable": None, "ctor": None,
            "str_addr": sa}


def main():
    global _log_fh
    try:
        _log_fh = open(DETAIL, "w")
    except Exception:
        _log_fh = None

    log("=== find_offsets_r2 v3 ===")
    log("bin: %s" % BIN)

    r2 = r2pipe.open(BIN, flags=["-2"])

    r2.cmd("e scr.color=0")
    r2.cmd("e anal.timeout=1800")
    r2.cmd("e anal.hasnext=true")
    r2.cmd("e anal.strings=true")
    r2.cmd("e anal.autoname=true")
    r2.cmd("e anal.jmp.after=true")
    r2.cmd("e anal.arm64.preludes=true")

    info = cmdj(r2, "ij")
    if not info:
        log("[!] cannot get bin info")
        return
    base = info.get("baddr", 0x100000000) or 0x100000000
    log("base: 0x%x" % base)

    t0 = time.time()
    log("running aaaa (full analysis) ...")
    r2.cmd("aaaa")
    log("aaaa done in %.1fs" % (time.time() - t0))

    str_index = build_string_index(r2, base)
    if not str_index:
        log("[!] empty string index")
        return

    n_shown = 0
    for s in sorted(str_index.keys()):
        if s.startswith("Logic") and n_shown < 5:
            log("  sample: %r -> %s" % (s[:60], ["0x%x" % x for x in str_index[s][:2]]))
            n_shown += 1

    results = []
    for cls in CLASSES:
        if time.time() - START > BUDGET - 120:
            log("[!] budget exhausted before %s" % cls)
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

    try:
        with open(REPORT, "w") as fh:
            fh.write("# r2 ctor resolution\n")
            fh.write("# base=0x%x\n\n" % base)
            for r in results:
                fh.write("=== %s ===\n" % r["class"])
                if r.get("method"):
                    fh.write("  method: rva=0x%08x  %s\n" % (r["method"][0], r["method"][1]))
                if r.get("vtable"):
                    fh.write("  vtable: rva=0x%08x\n" % r["vtable"])
                if r.get("ctor"):
                    fh.write("  ctor:   rva=0x%08x  %s\n" % (r["ctor"][0], r["ctor"][1]))
                fh.write("\n")
    except Exception as e:
        log("write REPORT failed: %s" % e)

    try:
        n_ok = 0
        n_tot = 0
        with open(OUT, "w") as fh:
            fh.write("export const ctors = Object.freeze({\n")
            for r in results:
                n_tot += 1
                if r.get("ctor"):
                    fh.write("  %s: 0x%x,\n" % (r["class"], r["ctor"][0]))
                    n_ok += 1
                else:
                    fh.write("  // %s: unresolved\n" % r["class"])
            fh.write("});\n")
        log("[*] resolved %d/%d" % (n_ok, n_tot))
    except Exception as e:
        log("write OUT failed: %s" % e)

    log("[+] wrote %s and %s" % (OUT, REPORT))


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        log("FATAL: %s" % e)
        traceback.print_exc()