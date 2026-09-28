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
SAMPLE_LIMIT = 40

log = lambda m: (sys.stdout.write(m + "\n"), sys.stdout.flush())
w = lambda s: L.append(s)

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
    "LogicSkillData__getMsBetweenAttacks": ["MsBetweenAttacks"],
    "LogicSkillData__getActiveTime": ["ActiveTime"],
    "LogicSkillData__getCastingRange": ["CastingRange"],
    "LogicSkillData__getRechargeTime": ["RechargeTime"],
    "LogicSkillData__getMaxCharge": ["MaxCharge"],
    "LogicProjectileData_getSpeed": ["ProjectileSpeed"],
    "LogicProjectileData_getRendering": ["ProjectileRendering"],
    "LogicProjectileData__isBeam": ["isBeam"],
    "LogicProjectileData__getNumEarlyTicks": ["NumEarlyTicks"],
    "LogicTileData__blocksMovement": ["BlocksMovement"],
    "LogicTileData__blocksProjectiles": ["BlocksProjectiles"],
    "LogicBattleModeClient__getTileMap": ["getTileMap"],
    "LogicBattleModeClient__getOwnPlayerIndex": ["getOwnPlayerIndex"],
    "LogicBattleModeClient__setRandomSeed": ["setRandomSeed"],
    "LogicBattleModeClient__setPlayerAvatar": ["setPlayerAvatar"],
    "LogicCharacterClient__getWeaponSkill": ["getWeaponSkill"],
    "LogicCharacterClient__getSkillAt": ["getSkillAt"],
    "LogicCharacterClient__getCarryableData": ["getCarryableData"],
    "LogicCharacterClient__getLinkedCarryable": ["getLinkedCarryable"],
    "LogicCharacterClient__isImmuneOrUntargetable": ["isImmuneOrUntargetable"],
    "LogicGameObjectManagerClient__getGameObjects": ["getGameObjects"],
    "LogicGameObjectManagerClient__findGameObject": ["findGameObject"],
    "LogicProjectileServer__shootProjectile": ["shootProjectile"],
    "LogicProjectileServer__runEarlyTicks": ["runEarlyTicks"],
    "GlobalID__getInstanceID": ["getInstanceID"],
    "LogicPlayerMap__save": ["save"],
    "LogicPlayerMapUtil__tileDataToTileCode": ["tileDataToTileCode"],
    "LogicRandom__setIteratedRandomSeed": ["setIteratedRandomSeed"],
    "LogicLongToCodeConverterUtil__convert": ["convert"],
    "LogicLongToCodeConverterUtil__toCode": ["toCode"],
    "ResourceListener__addFile": ["addFile"],
    "String__format": ["format"],
    "FramerateManager__setSegment": ["setSegment"],
    "FramerateManager__setLimit": ["setLimit"],
    "Application__copyString": ["copyString"],
    "BattleScreen__calculateProjectilePath": ["calculateProjectilePath"],
    "BattleScreen__joystickToWorld": ["joystickToWorld"],
    "BattleScreen__shouldShowAccessoryButton": ["shouldShowAccessoryButton"],
    "BattleScreen__updateCameraParameters": ["updateCameraParameters"],
    "BattleScreen__stopWithStick": ["stopWithStick"],
    "BattleScreen__handleTouchReleased": ["handleTouchReleased"],
    "BattleScreen__updateMovement": ["updateMovement"],
    "BattleScreen__updateAutoshoot": ["updateAutoshoot"],
    "BattleScreen__tryToActivateSkill": ["tryToActivateSkill"],
    "BattleScreen_getClosestTargetForAutoshoot": ["getClosestTargetForAutoshoot"],
    "CombatHUD__toggleEditing": ["toggleEditing"],
    "CombatHUD__setShootStickState": ["setShootStickState"],
    "CombatHUD__setMoveStickState": ["setMoveStickState"],
    "CombatHUD__sendPinCommand": ["sendPinCommand"],
    "CombatHUD__sendSprayCommand": ["sendSprayCommand"],
    "Character__updateHealthBar": ["updateHealthBar"],
    "GUI__getDefaultFloaterPos": ["getDefaultFloaterPos"],
    "GUI__showFloaterTextAt": ["showFloaterTextAt"],
    "GUI__showPopup": ["showPopup"],
    "GameSliderComponent__setValueBounds": ["setValueBounds"],
    "MapEditorModifierPopup__addModifierItem": ["addModifierItem"],
    "ScrollArea__updateBounds": ["updateBounds"],
    "ScrollArea__addContent": ["addContent"],
    "ScrollArea__removeAllContent": ["removeAllContent"],
    "CSVRow__getIntegerValueAt": ["getIntegerValueAt"],
    "CSVRow__getName": ["getName"],
    "CSVRow__getValueAt": ["getValueAt"],
    "CSVRow__getBooleanValueAt": ["getBooleanValueAt"],
    "CSVTable__getColumnIndexByName": ["getColumnIndexByName"],
    "LogicJSONObject__put": ["put"],
    "GameStateManager__getInstance": ["getInstance"],
    "GameStateManager__isState": ["isState"],
    "HomeMode__getInstance": ["getInstance"],
    "StringTable__getMovieClip": ["getMovieClip"],
    "MovieClipHelper__setTextAndScaleIfNecessary": ["setTextAndScaleIfNecessary"],
    "LogicTile__setData": ["setData"],
    "LogicTileMap__isPlayerLineOfSightClear": ["isPlayerLineOfSightClear"],
    "LogicDataTables__getOpenTileData": ["getOpenTileData"],
    "LogicDataTables__getBaseTileData": ["getBaseTileData"],
    "LogicDataTables__getSiegeBoltTileData": ["getSiegeBoltTileData"],
    "LogicCharacterData_getSpeed": ["CharacterSpeed"],
    "BattleMode_getInstance": ["getInstance"],
    "BattleMode__enter": ["enter"],
    "BattleMode__addResourcesToLoad": ["addResourcesToLoad"],
    "ClientInputMessage_sendMovement": ["sendMovement"],
    "HashTagCodeGenerator__toId": ["toId"],
    "HashTagCodeGenerator__isValid": ["isValid"],
    "Name_setupDecorated": ["setupDecorated"],
    "Name_applyDecoration": ["applyDecoration"],
    "AllianceManager__startSpectate": ["startSpectate"],
    "CustomButton_onButtonPressed": ["onButtonPressed"],
    "nativeCopyToClipboard": ["copyToClipboard"],
    "LogicGameModeUtil__isTileOnPoisonArea": ["isTileOnPoisonArea"],
    "LogicData_getName": ["getName"],
    "LogicDataTable_findByName": ["findByName"],
    "AreaEffectData__getRadius": ["getRadius"],
    "AreaEffectData__getActiveTimeMs": ["getActiveTimeMs"],
    "MovieClip__getChildClipByName": ["getChildClipByName"],
    "MovieClip__setChildVisible": ["setChildVisible"],
    "MovieClip__gotoAndStopFrameIndex": ["gotoAndStopFrameIndex"],
    "Screen__getDpiClass": ["getDpiClass"],
    "Screen__getHeight": ["getHeight"],
    "Screen__getWidth": ["getWidth"],
}

DEVELOPER_FLAGS = {
    "LogicVersion_isDeveloperBuild": ["isDeveloperBuild"],
    "LogicVersion_isDev": ["isDev"],
    "LogicVersion_isProd": ["isProd"],
    "SCIDConfig_isDevBuild": ["isDevBuild"],
    "LogicVersion_isProduction": ["isProduction"],
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

def index_strings():
    """Iterate all defined data ONCE, index strings by content."""
    log("[*] indexing strings via getDefinedData...")
    listing = currentProgram.getListing()
    try:
        it = listing.getDefinedData(True)
    except Exception as e:
        log("[!] getDefinedData failed: %s" % e)
        return {}, 0, 0

    idx = {}
    total_data = 0
    total_str = 0
    sample = []
    while it.hasNext():
        if time.time() - START > BUDGET_SEC - 600:
            log("[!] string index budget exceeded")
            break
        try:
            d = it.next()
        except:
            break
        total_data += 1
        if total_data % 100000 == 0:
            log("[*] scan: %d data, %d strings" % (total_data, total_str))
        try:
            if d is None:
                continue
            if not d.hasStringValue():
                continue
            sval = str(d.getValue())
            if not sval:
                continue
            total_str += 1
            if len(sample) < SAMPLE_LIMIT:
                sample.append(sval[:120])
            key = sval[:256]
            idx.setdefault(key, []).append(d.getAddress())
        except:
            continue

    log("[*] total data items: %d" % total_data)
    log("[*] total strings: %d" % total_str)
    log("[*] unique strings: %d" % len(idx))
    log("[*] sample strings:")
    for s in sample:
        log("    %r" % s)
    return idx, total_data, total_str

def find_anchor_addrs(string_idx, anchor):
    out = []
    for sval, addrs in string_idx.items():
        if anchor in sval:
            out.extend(addrs)
    return out

def find_func_from_addrs(addrs, name):
    rm = currentProgram.getReferenceManager()
    for sa in addrs:
        try:
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
                log("[+] %s -> func @ 0x%x (from %s)" % (name, fr, sa))
                return f
        except:
            continue
    return None

def main():
    log("=== find_offsets v3 (string-index) ===")
    offs = read_offsets()
    log("[*] parsed %d entries from offsets.js" % len(offs))

    if len(offs) < MIN_EXPECTED_ENTRIES:
        msg = "ABORT: offsets.js has only %d entries, expected >= %d" % (len(offs), MIN_EXPECTED_ENTRIES)
        log("[!] " + msg)
        sys.exit(1)

    sigdb = {}
    if os.path.exists(SIGDB):
        try:
            fh = open(SIGDB, "r")
            sigdb = json.load(fh)
            fh.close()
            if not isinstance(sigdb, dict):
                sigdb = {}
        except:
            sigdb = {}
    log("[*] sigdb: %d entries" % len(sigdb))

    string_idx, total_data, total_str = index_strings()

    if total_str == 0:
        log("[!] NO STRINGS FOUND IN BINARY")
        log("[!] Possible causes:")
        log("[!]   1. COLD analysis did not run (check cold.log)")
        log("[!]   2. Strings are compressed/encoded in this build")
        log("[!]   3. Ghidra did not run the string analysis step")

    # Pre-compute anchor hits
    all_anchors = set()
    for anchors in STRING_ANCHORS.values():
        for a in anchors:
            all_anchors.add(a)
    for anchors in DEVELOPER_FLAGS.values():
        for a in anchors:
            all_anchors.add(a)

    log("[*] unique anchors to search: %d" % len(all_anchors))
    anchor_hits = {}
    for a in all_anchors:
        hits = find_anchor_addrs(string_idx, a)
        if hits:
            anchor_hits[a] = hits
            log("[*] anchor %r: %d addr(s)" % (a, len(hits)))

    log("[*] anchors with hits: %d / %d" % (len(anchor_hits), len(all_anchors)))

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
                sig_index = {}
            cands = sig_index.get(s, [])
            if len(cands) == 1:
                resolved[name] = rva(cands[0])
                rematched += 1
                new_sigs[name] = s
                continue

        anchors = STRING_ANCHORS.get(name)
        if anchors:
            for a in anchors:
                addrs = anchor_hits.get(a, [])
                if not addrs:
                    continue
                f = find_func_from_addrs(addrs, name)
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
                    break
            if name in resolved:
                continue

        failures.append((name, old_rva, "no-func"))

    dev_flags = {}
    for flag_name, anchors in DEVELOPER_FLAGS.items():
        for a in anchors:
            addrs = anchor_hits.get(a, [])
            if not addrs:
                continue
            f = find_func_from_addrs(addrs, flag_name)
            if f is not None:
                dev_flags[flag_name] = rva(f.getEntryPoint())
                break

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

    try:
        fh = open(SIGDB, "w")
        json.dump(new_sigs, fh, indent=2, sort_keys=True)
        fh.close()
    except:
        pass

    w("elapsed %.1fs" % (time.time() - START))
    w("input: %d" % len(offs))
    w("strings indexed: %d (unique: %d)" % (total_str, len(string_idx)))
    w("anchors with hits: %d / %d" % (len(anchor_hits), len(all_anchors)))
    w("resolved: %d (verified=%d rematched=%d string=%d)" % (
        len(resolved), verified, rematched, string_hits))
    w("developer flags found: %d" % len(dev_flags))
    for n, r in dev_flags.items():
        w("  DEV %s @ 0x%x" % (n, r))
    w("failed: %d" % len(failures))
    for n, r, msg in failures[:80]:
        w("  FAIL %s @ 0x%x (%s)" % (n, r, msg))
    if len(failures) > 80:
        w("  ... and %d more" % (len(failures) - 80))

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