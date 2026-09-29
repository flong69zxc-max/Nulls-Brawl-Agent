# -*- coding: utf-8 -*-
# @runtime Jython

import os
import sys
import time
import traceback

WS = os.environ.get("GITHUB_WORKSPACE", "/tmp")
OUT = os.path.join(WS, "mod_menu_offsets.js")
REPORT = os.path.join(WS, "mod_menu_report.txt")
BASE = 0x100000000
BUDGET = 1200
START = time.time()

L = []

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

# Имена символов (mangled) и подсказки-строки для поиска
TARGETS = {
    # HomePage / Lobby
    "HomePage_ctor": ["HomePage", "C1", "C2"],
    "HomePage_startGame": ["HomePage", "startGame"],

    # ResourceManager
    "ResourceManager_getMovieClip": ["ResourceManager", "getMovieClip"],

    # GameButton
    "GameButton_ctor": ["GameButton", "C1", "C2"],
    "GameButton_buttonPressed": ["GameButton", "buttonPressed"],

    # Sprite / Stage
    "Sprite_ctor": ["Sprite", "C1", "C2"],
    "Sprite_addChild": ["Sprite", "addChild"],
    "Stage_addChild": ["Stage", "addChild"],
    "Stage_instance": ["Stage", "instance"],
    "MovieClip_getMovieClipByName": ["MovieClip", "getMovieClipByName"],
    "MovieClip_getTextFieldByName": ["MovieClip", "getTextFieldByName"],
    "MovieClip_gotoAndStopFrameIndex": ["MovieClip", "gotoAndStopFrameIndex"],

    # Text
    "TextField_setText": ["TextField", "setText"],
    "TextField_fetchFont": ["TextField", "fetchFont"],
    "String_ctor": ["String", "C1", "C2"],

    # GUI / Popup
    "GenericPopup_ctor": ["GenericPopup", "C1", "C2"],
    "GenericPopup_addButton": ["GenericPopup", "addButton"],
    "GenericPopup_addButton2": ["GenericPopup", "addButton2"],
    "GenericPopup_setTitle": ["GenericPopup", "setTitle"],
    "GenericPopup_onHudCloseButton": ["GenericPopup", "onHudCloseButton"],
    "GUI_showPopup": ["GUI", "showPopup"],
    "GUI_getInstance": ["GUI", "getInstance"],
    "GUI_closePopup": ["GUI", "closePopup"],
    "GUI_showFloater": ["GUI", "showFloater"],
}

def find_functions_by_patterns():
    fm = currentProgram.getFunctionManager()
    all_funcs = []
    it = fm.getFunctions(True)
    while it.hasNext():
        f = it.next()
        all_funcs.append((f.getName(), f.getEntryPoint()))
    log("[*] total functions: %d" % len(all_funcs))

    results = {}
    for tag, patterns in sorted(TARGETS.items()):
        hits = []
        for name, entry in all_funcs:
            if all(p.lower() in name.lower() for p in patterns):
                hits.append((rva(entry), name))
        if hits:
            hits.sort()
            results[tag] = hits
            log("[+] %s -> %s" % (tag, hits[0]))
        else:
            log("[-] %s -> NOT FOUND" % tag)
    return results

def find_strings():
    listing = currentProgram.getListing()
    idx = {}
    it = listing.getDefinedData(True)
    total = 0
    while it.hasNext():
        if time.time() - START > BUDGET - 200:
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
    log("[*] strings indexed: %d" % total)
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

def main():
    log("=== find_mod_menu_offsets ===")
    log("program: %s" % currentProgram.getName())

    # 1) Поиск функций по именам символов
    log("")
    log("=== SYMBOL SEARCH ===")
    results = find_functions_by_patterns()

    # 2) Поиск по строкам, если символы не найдены
    log("")
    log("=== STRING SEARCH (fallback) ===")
    string_idx = find_strings()

    STRING_ANCHORS = {
        "HomePage_ctor": ["TID_MATCHMAKE_FAILED_15", "HomePage", "Lobby"],
        "GameButton_buttonPressed": ["GameButton", "buttonPressed"],
        "GUI_showPopup": ["GUI", "Popup"],
        "GenericPopup_ctor": ["GenericPopup", "Popup"],
    }

    for tag, anchors in sorted(STRING_ANCHORS.items()):
        if tag in results:
            continue
        log("")
        log("--- %s ---" % tag)
        for anchor in anchors:
            hits = []
            for s, addrs in string_idx.items():
                if anchor in s:
                    hits.extend(addrs)
            if not hits:
                log("  anchor %r: not found" % anchor)
                continue
            log("  anchor %r: %d string(s)" % (anchor, len(hits)))
            for sa in hits[:5]:
                for ra in find_refs(sa):
                    f = getFunctionContaining(ra)
                    if f is not None:
                        fr = rva(f.getEntryPoint())
                        if tag not in results:
                            results[tag] = []
                        results[tag].append((fr, f.getName()))
                        log("    func 0x%x %s" % (fr, f.getName()))

    # 3) Запись результатов
    log("")
    log("=== SUMMARY ===")
    for tag, hits in sorted(results.items()):
        if hits:
            log("  %s: 0x%x" % (tag, hits[0][0]))
        else:
            log("  %s: NOT FOUND" % tag)

    with open(OUT, "w") as fh:
        fh.write("export const offsets = Object.freeze({\n")
        for tag in sorted(results.keys()):
            if results[tag]:
                fr, name = results[tag][0]
                fh.write("  %s: 0x%x, // %s\n" % (tag, fr, name))
        fh.write("});\n")

    with open(REPORT, "w") as fh:
        for line in L:
            fh.write(line + "\n")

    log("")
    log("[+] wrote %s" % OUT)

try:
    main()
except SystemExit:
    raise
except Exception as e:
    log("FATAL: %s" % e)
    traceback.print_exc()