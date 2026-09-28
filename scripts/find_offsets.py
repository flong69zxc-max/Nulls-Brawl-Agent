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

# --- Known string anchors for Nulls Brawl / Brawl Stars functions ---
# Based on SCRE tutorials and common function patterns.
STRING_ANCHORS = {
    "BattleScreen__update": ["BattleScreen::update"],
    "GameMain__update": ["GameMain::update"],
    "LogicBattleModeClient_update": ["LogicBattleModeClient::update"],
    "BattleScreen__tryToActivateSkill": ["tryToActivateSkill"],
    "BattleScreen__updateMovement": ["updateMovement"],
    "BattleScreen__updateAutoshoot": ["updateAutoshoot"],
    "BattleScreen_activateSkill": ["activateSkill"],
    "Gui_showFloaterTextAtDefaultPos": ["showFloaterTextAtDefaultPos"],
    "LogicCharacterClient__getWeaponSkill": ["getWeaponSkill"],
    "LogicProjectileData_getRadius": ["getRadius"],
    "LogicProjectileData_getSpeed": ["getSpeed"],
    "LogicCharacterData_getCollisionRadius": ["getCollisionRadius"],
    "MessageManager__receiveMessage": ["receiveMessage"],
    "MessageManager__sendMessage": ["sendMessage"],
    "ResourceManager__isResourceLoaded": ["isResourceLoaded"],
    "LogicGameObjectClient_getX": ["getX"],
    "LogicGameObjectClient_getY": ["getY"],
    "LogicGameObjectClient_getZ": ["getZ"],
    "Sprite_Sprite": ["Sprite::Sprite"],
    "TextField_setText": ["setText"],
    "ScrollArea__scrollTo": ["scrollTo"],
    "DisplayObject__setXY": ["setXY"],
    "MovieClip__getTextFieldByName": ["getTextFieldByName"],
    "Sprite__addChild": ["addChild"],
    "Sprite__removeChild": ["removeChild"],
    "ClientInputManager_addInput": ["addInput"],
    "LogicBattleModeClient_getOwnCharacter": ["getOwnCharacter"],
    "LogicBattleModeClient_getOwnPlayerTeam": ["getOwnPlayerTeam"],
    "LogicBattleModeClient_getOwnPlayerIndex": ["getOwnPlayerIndex"],
    "LogicBattleModeClient_getTileMap": ["getTileMap"],
    "LogicBattleModeClient_setRandomSeed": ["setRandomSeed"],
    "LogicBattleModeClient_setPlayerAvatar": ["setPlayerAvatar"],
    "LogicBattleModeClient_setClientPredictionMoveTo": ["setClientPredictionMoveTo"],
    "LogicCharacterClient__getCurrentActiveOrCastingSkill": ["getCurrentActiveOrCastingSkill"],
    "LogicCharacterClient__getSkillAt": ["getSkillAt"],
    "LogicCharacterClient__canMoveAndUseThisSkillSimultaneously": ["canMoveAndUseThisSkillSimultaneously"],
    "LogicCharacterClient__getCarryableData": ["getCarryableData"],
    "LogicCharacterClient__getLinkedCarryable": ["getLinkedCarryable"],
    "LogicSkillData__getActiveTime": ["getActiveTime"],
    "LogicSkillData__getRechargeTime": ["getRechargeTime"],
    "LogicSkillData__getMaxCharge": ["getMaxCharge"],
    "LogicSkillData__getMsBetweenAttacks": ["getMsBetweenAttacks"],
    "LogicSkillData__getCastingRange": ["getCastingRange"],
    "LogicSkillData__getProjectileData": ["getProjectileData"],
    "LogicSkillClient__canActivate": ["canActivate"],
    "LogicProjectileData__isBeam": ["isBeam"],
    "LogicProjectileData__getNumEarlyTicks": ["getNumEarlyTicks"],
    "LogicProjectileData__getSpawnAreaEffect": ["getSpawnAreaEffect"],
    "LogicTileData__blocksMovement": ["blocksMovement"],
    "LogicTileData__blocksProjectiles": ["blocksProjectiles"],
    "GameStateManager__getInstance": ["getInstance"],
    "GameStateManager__isState": ["isState"],
    "HomeMode__getInstance": ["getInstance"],
    "StringTable__getMovieClip": ["getMovieClip"],
    "MovieClipHelper__setTextAndScaleIfNecessary": ["setTextAndScaleIfNecessary"],
    "LogicTile__setData": ["setData"],
    "LogicTileMap__isPlayerLineOfSightClear": ["isPlayerLineOfSightClear"],
    "LogicTileMap__isPlayerLineOfSightClear1": ["isPlayerLineOfSightClear"],
    "LogicDataTables__getOpenTileData": ["getOpenTileData"],
    "LogicDataTables__getBaseTileData": ["getBaseTileData"],
    "LogicDataTables__getSiegeBoltTileData": ["getSiegeBoltTileData"],
    "LogicCharacterData_getSpeed": ["getSpeed"],
    "LogicCharacterClient__isImmuneOrUntargetable": ["isImmuneOrUntargetable"],
    "LogicGameObjectManagerClient__getGameObjects": ["getGameObjects"],
    "LogicGameObjectManagerClient__findGameObject": ["findGameObject"],
    "LogicProjectileServer__shootProjectile": ["shootProjectile"],
    "LogicProjectileServer__runEarlyTicks": ["runEarlyTicks"],
    "GlobalID__getInstanceID": ["getInstanceID"],
    "LogicPlayerMap__save": ["save"],
    "LogicPlayerMapUtil__tileDataToTileCode": ["tileDataToTileCode"],
    "AnalyticEvent__AnalyticEvent": ["AnalyticEvent"],
    "AnalyticEvent__setString": ["setString"],
    "LogicRandom__setIteratedRandomSeed": ["setIteratedRandomSeed"],
    "LogicCompressedString__LogicCompressedString": ["LogicCompressedString"],
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
    "BattleScreen__BattleScreen": ["BattleScreen"],
    "BattleScreen_getClosestTargetForAutoshoot": ["getClosestTargetForAutoshoot"],
    "BattleScreen_fireWrapperFn": ["fireWrapper"],
    "CombatHUD__toggleEditing": ["toggleEditing"],
    "CombatHUD__setShootStickState": ["setShootStickState"],
    "CombatHUD__setMoveStickState": ["setMoveStickState"],
    "CombatHUD__sendPinCommand": ["sendPinCommand"],
    "CombatHUD__sendSprayCommand": ["sendSprayCommand"],
    "CombatHUD__update": ["CombatHUD::update"],
    "Character__updateHealthBar": ["updateHealthBar"],
    "GUI__getDefaultFloaterPos": ["getDefaultFloaterPos"],
    "GUI__showFloaterTextAt": ["showFloaterTextAt"],
    "GUI__showPopup": ["showPopup"],
    "GameButtonCtor": ["GameButton"],
    "DropGUIContainer__ctorFromExport": ["ctorFromExport"],
    "GameSliderComponent__GameSliderComponent": ["GameSliderComponent"],
    "GameSliderComponent__setValueBounds": ["setValueBounds"],
    "MapEditorModifierItem__MapEditorModifierItem": ["MapEditorModifierItem"],
    "MapEditorModifierPopup__MapEditorModifierPopup": ["MapEditorModifierPopup"],
    "MapEditorModifierPopup__addModifierItem": ["addModifierItem"],
    "PopupBase__PopupBase": ["PopupBase"],
    "ScrollArea__updateBounds": ["updateBounds"],
    "ScrollArea__addContent": ["addContent"],
    "ScrollArea__removeAllContent": ["removeAllContent"],
    "CSVRow__getIntegerValueAt": ["getIntegerValueAt"],
    "CSVRow__getName": ["getName"],
    "CSVRow__getValueAt": ["getValueAt"],
    "CSVRow__getBooleanValueAt": ["getBooleanValueAt"],
    "CSVTable__getColumnIndexByName": ["getColumnIndexByName"],
    "LogicJSONObject__put": ["put"],
    "ScString_destruct": ["~ScString"],
    "GameObjectManager__GameObjectManager": ["GameObjectManager"],
    "Projectile_ctor": ["Projectile"],
    "Projectile__update": ["Projectile::update"],
    "RenderSystem__RenderSystem": ["RenderSystem"],
    "DecalManager__DecalManager": ["DecalManager"],
    "LogicTileMap__LogicTileMap": ["LogicTileMap"],
    "LogicGameObjectManagerClient__LogicGameObjectManagerClient": ["LogicGameObjectManagerClient"],
    "LogicBattleModeClient__LogicBattleModeClient": ["LogicBattleModeClient"],
    "ClientInput_constructor_int": ["ClientInput"],
    "ClientInputMessage_sendMovement": ["sendMovement"],
    "TeamChatMessage__ctor": ["TeamChatMessage"],
    "TeamSetMemberReadyMessage__ctor": ["TeamSetMemberReadyMessage"],
    "StartSpectateMessage__ctor": ["StartSpectateMessage"],
    "HashTagCodeGenerator__ctor": ["HashTagCodeGenerator"],
    "HashTagCodeGenerator__toId": ["toId"],
    "HashTagCodeGenerator__dtor": ["~HashTagCodeGenerator"],
    "HashTagCodeGenerator__isValid": ["isValid"],
    "Name_setupDecorated": ["setupDecorated"],
    "Name_applyDecoration": ["applyDecoration"],
    "PiranhaMessage_ctor": ["PiranhaMessage"],
    "AllianceManager__startSpectate": ["startSpectate"],
    "CustomButton_onButtonPressed": ["onButtonPressed"],
    "nativeCopyToClipboard": ["copyToClipboard"],
    "operator_new": ["operator new"],
    "LogicGameModeUtil__isTileOnPoisonArea": ["isTileOnPoisonArea"],
    "LogicData_getName": ["getName"],
    "LogicDataTable_findByName": ["findByName"],
    "LogicProjectileClient_ctor": ["LogicProjectileClient"],
    "LogicProjectileClient_destruct": ["~LogicProjectileClient"],
    "LogicProjectileClient_getData": ["getData"],
    "LogicProjectileClient_getTargetX": ["getTargetX"],
    "LogicProjectileClient_getTargetY": ["getTargetY"],
    "AreaEffectData__getRadius": ["getRadius"],
    "AreaEffectData__getActiveTimeMs": ["getActiveTimeMs"],
    "MapEditorScreen__updateCameraParameters": ["updateCameraParameters"],
    "MovieClip__getChildClipByName": ["getChildClipByName"],
    "MovieClip__setChildVisible": ["setChildVisible"],
    "MovieClip__gotoAndStopFrameIndex": ["gotoAndStopFrameIndex"],
    "MovieClip_gotoAndStop": ["gotoAndStop"],
    "Screen__getDpiClass": ["getDpiClass"],
    "Screen__getHeight": ["getHeight"],
    "Screen__getWidth": ["getWidth"],
    "BattleMode_getInstance": ["getInstance"],
    "BattleMode__enter": ["enter"],
    "BattleMode__addResourcesToLoad": ["addResourcesToLoad"],
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

def main():
    log("=== find_offsets ===")
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

        # 1. Try exact old RVA
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

        # 2. Try signature from sigdb
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

        # 3. Try string anchors
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

    fh = open(OFF_OUT, "w")
    fh.write("export const offsets = Object.freeze(\n{\n")
    for n in sorted(offs.keys()):
        if n in resolved:
            fh.write("    %s: 0x%x,\n" % (n, resolved[n]))
        else:
            fh.write("    %s: 0x%x,\n" % (n, offs[n]))
    fh.write("});\n")
    fh.close()

    save_sigdb(new_sigs)

    w("elapsed %.1fs" % (time.time() - START))
    w("input: %d" % len(offs))
    w("resolved: %d (verified=%d rematched=%d string=%d)" % (
        len(resolved), verified, rematched, string_hits))
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