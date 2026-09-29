# -*- coding: utf-8 -*-
# @runtime Jython

import os, sys, time, traceback

WS = os.environ.get("GITHUB_WORKSPACE", "/tmp")
OUT = os.path.join(WS, "offsets_resolved.js")
REPORT = os.path.join(WS, "offsets_report.txt")
BASE = 0x100000000
BUDGET = 1800
START = time.time()

# 1) ФУНКЦИИ (ищутся через строки-якоря классов и методов)
FUNCTION_TARGETS = {
    # LogicBattleModeClient
    "LogicBattleModeClient_update": "update",
    "LogicBattleModeClient_getOwnCharacter": "getOwnCharacter",
    "LogicBattleModeClient_getOwnPlayerTeam": "getOwnPlayerTeam",
    "LogicBattleModeClient_setClientPredictionMoveTo": "setClientPredictionMoveTo",
    "LogicBattleModeClient_getOwnPlayerIndex": "getOwnPlayerIndex",
    "LogicBattleModeClient_getTileMap": "getTileMap",
    "LogicBattleModeClient_setRandomSeed": "setRandomSeed",
    "LogicBattleModeClient_setPlayerAvatar": "setPlayerAvatar",
    "LogicBattleModeClient_ctor": "LogicBattleModeClient",

    # BattleMode
    "BattleMode_getInstance": "getInstance",
    "BattleMode_enter": "enter",
    "BattleMode_addResourcesToLoad": "addResourcesToLoad",

    # LogicGameObjectClient
    "LogicGameObjectClient_getX": "getX",
    "LogicGameObjectClient_getY": "getY",
    "LogicGameObjectClient_getZ": "getZ",
    "LogicGameObjectClient_getGlobalID": "getGlobalID",
    "LogicGameObjectClient_getData": "getData",

    # BattleScreen
    "BattleScreen_activateSkill": "activateSkill",
    "BattleScreen_updateCameraParameters": "updateCameraParameters",
    "BattleScreen_update": "update",
    "BattleScreen_stopWithStick": "stopWithStick",
    "BattleScreen_handleTouchReleased": "handleTouchReleased",
    "BattleScreen_updateAutoshoot": "updateAutoshoot",
    "BattleScreen_getClosestTargetForAutoshoot": "getClosestTargetForAutoshoot",
    "BattleScreen_updateMovement": "updateMovement",
    "BattleScreen_tryToActivateSkill": "tryToActivateSkill",
    "BattleScreen_shouldShowAccessoryButton": "shouldShowAccessoryButton",
    "BattleScreen_calculateProjectilePath": "calculateProjectilePath",
    "BattleScreen_joystickToWorld": "joystickToWorld",
    "BattleScreen_ctor": "BattleScreen",
    "BattleScreen_fireWrapperFn": "fireWrapper",

    # GUI / Popup
    "Gui_showFloaterTextAtDefaultPos": "showFloaterTextAtDefaultPos",
    "GUI_showFloaterTextAt": "showFloaterTextAt",
    "GUI_showPopup": "showPopup",
    "GUI_getDefaultFloaterPos": "getDefaultFloaterPos",
    "Gui_getInstance": "getInstance",
    "PopupBase_ctor": "PopupBase",
    "GenericPopup_ctor": "GenericPopup",
    "GenericPopup_addButton": "addButton",
    "GenericPopup_addButton2": "addButton2",
    "GenericPopup_setTitle": "setTitle",

    # GameButton
    "GameButton_ctor": "GameButton",
    "GameButton_buttonPressed": "buttonPressed",
    "GameButton_setText": "setText",
    "CustomButton_onButtonPressed": "onButtonPressed",

    # Sprite / Stage / DisplayObject
    "Sprite_ctor": "Sprite",
    "Sprite_addChild": "addChild",
    "Sprite_addChildAt": "addChildAt",
    "Sprite_removeChild": "removeChild",
    "Stage_addChild": "addChild",
    "DisplayObject_setXY": "setXY",
    "DisplayObject_removeFromParent": "removeFromParent",

    # MovieClip
    "MovieClip_getTextFieldByName": "getTextFieldByName",
    "MovieClip_getChildClipByName": "getChildClipByName",
    "MovieClip_setChildVisible": "setChildVisible",
    "MovieClip_gotoAndStopFrameIndex": "gotoAndStopFrameIndex",
    "MovieClipHelper_setTextAndScaleIfNecessary": "setTextAndScaleIfNecessary",

    # TextField / String
    "TextField_setText": "setText",
    "TextField_fetchFont": "fetchFont",
    "String_ctor": "String",
    "String_format": "format",
    "StringCtor": "String",
    "Application_copyString": "copyString",
    "decoratedTextFieldSetPlayerName": "setPlayerName",
    "Name_setupDecorated": "setupDecorated",
    "Name_applyDecoration": "applyDecoration",

    # Input
    "ClientInput_ctor": "ClientInput",
    "ClientInputManager_addInput": "addInput",
    "ClientInputMessage_sendMovement": "sendMovement",
    "handleJoystick": "handleJoystick",

    # Logic
    "LogicSkillData_getActiveTime": "getActiveTime",
    "LogicSkillData_getRechargeTime": "getRechargeTime",
    "LogicSkillData_getMaxCharge": "getMaxCharge",
    "LogicSkillData_getMsBetweenAttacks": "getMsBetweenAttacks",
    "LogicSkillData_getCastingRange": "getCastingRange",
    "LogicSkillData_getBehaviour": "getBehaviour",
    "LogicSkillData_getLinkedSkill": "getLinkedSkill",
    "LogicSkillData_getProjectileData": "getProjectileData",
    "LogicSkillClient_getData": "getData",
    "LogicSkillClient_canActivate": "canActivate",
    "LogicCharacterData_getSpeed": "getSpeed",
    "LogicCharacterData_getCollisionRadius": "getCollisionRadius",
    "LogicProjectileData_getRadius": "getRadius",
    "LogicProjectileData_getSpeed": "getSpeed",
    "LogicProjectileData_getRendering": "getRendering",
    "LogicProjectileData_isBeam": "isBeam",
    "LogicProjectileData_getNumEarlyTicks": "getNumEarlyTicks",
    "LogicProjectileData_getSpawnAreaEffect": "getSpawnAreaEffect",
    "LogicProjectileData_IsOwnTeamProjectile": "IsOwnTeamProjectile",
    "LogicTileData_blocksMovement": "blocksMovement",
    "LogicTileData_blocksProjectiles": "blocksProjectiles",
    "LogicTile_setData": "setData",
    "LogicTileMap_ctor": "LogicTileMap",
    "LogicTileMap_isPlayerLineOfSightClear": "isPlayerLineOfSightClear",
    "LogicTileMap_getTile":_get "getTile",
    "LogicOpenDataTablesTileData": "getOpenTileData",
    "LogicDataTables_getBaseTileData": "getBaseTileData",
    "LogicDataTables_getSiegeBoltTileData": "getSiegeBoltTileData",
    "LogicCharacterClient_getCarryableData": "getCarryableData",
    "LogicCharacterClient_getWeaponSkill": "getWeaponSkill",
    "LogicCharacterClient_getLinkedCarryable": "getLinkedCarryable",
    "LogicCharacterClient_getCurrentActiveOrCastingSkill": "getCurrentActiveOrCastingSkill",
    "LogicCharacterClient_getSkillAt": "getSkillAt",
    "LogicCharacterClient_canMoveAndUseThisSkillSimultaneously": "canMoveAndUseThisSkillSimultaneously",
    "LogicCharacterClient_isImmuneOrUntargetable": "isImmuneOrUntargetable",
    "LogicCharacterClientOwn_clientPredictionPauseMovementForSkillCasting": "clientPredictionPauseMovementForSkillCasting",
    "LogicCharacterClientOwn_clientPredictionUpdateAttackDirection": "clientPredictionUpdateAttackDirection",
    "LogicGameObjectManagerClient_ctor": "LogicGameObjectManagerClient",
    "LogicGameObjectManagerClient_getGameObjects": "getGameObjects",
    "LogicGameObjectManagerClient_findGameObject": "findGameObject",
    "LogicGameObjectServer_getData": "getData",
    "LogicProjectileServer_shootProjectile": "shootProjectile",
    "LogicProjectileServer_runEarlyTicks": "runEarlyTicks",
    "LogicProjectileClient_ctor": "LogicProjectileClient",
    "LogicProjectileClient_destruct": "destruct",
    "LogicProjectileClient_getData": "getData",
    "LogicProjectileClient_getTargetX": "getTargetX",
    "LogicProjectileClient_getTargetY": "getTargetY",
    "LogicProjectileClient_update": "update",
    "LogicGameModeUtil_isTileOnPoisonArea": "isTileOnPoisonArea",

    # Projectile
    "Projectile_ctor": "Projectile",
    "Projectile_update": "update",

    # Managers / Systems
    "GameMain_update": "update",
    "DecalManager_ctor": "DecalManager",
    "GameObjectManager_ctor": "GameObjectManager",
    "RenderSystem_ctor": "RenderSystem",
    "ResourceManager_getCSV": "getCSV",
    "ResourceManager_isResourceLoaded": "isResourceLoaded",
    "StringTable_getMovieClip": "getMovieClip",
    "StringTable_getMovieClip_alt": "getMovieClip",
    "FramerateManager_setSegment": "setSegment",
    "FramerateManager_setLimit": "setLimit",
    "MessageManager_receiveMessage": "receiveMessage",
    "MessageManager_sendMessage": "sendMessage",
    "AllianceManager_startSpectate": "startSpectate",

    # HUD / Screen
    "CombatHUD_toggleEditing": "toggleEditing",
    "CombatHUD_setShootStickState": "setShootStickState",
    "CombatHUD_setMoveStickState": "setMoveStickState",
    "CombatHUD_update": "update",
    "CombatHUD_sendPinCommand": "sendPinCommand",
    "CombatHUD_sendSprayCommand": "sendSprayCommand",
    "Character_updateHealthBar": "updateHealthBar",
    "GameScreen_getLogicBattle": "getLogicBattle",
    "MapEditorScreen_initRenderSystem": "initRenderSystem",
    "MapEditorScreen_initItems": "initItems",
    "MapEditorScreen_initCharacters": "initCharacters",
    "MapEditorScreen_updateCameraParameters": "updateCameraParameters",
    "GameSettings_isFixedJoystickEnabled": "isFixedJoystickEnabled",
    "GameStateManager_getInstance": "getInstance",
    "GameStateManager_isState": "isState",
    "HomeMode_getInstance": "getInstance",

    # Slider / Container / Editor
    "GameSliderComponent_ctor": "GameSliderComponent",
    "GameSliderComponent_setValueBounds": "setValueBounds",
    "DropGUIContainer_ctorFromExport": "ctorFromExport",
    "MapEditorModifierItem_ctor": "MapEditorModifierItem",
    "MapEditorModifierPopup_ctor": "MapEditorModifierPopup",
    "MapEditorModifierPopup_addModifierItem": "addModifierItem",

    # CSV
    "CSVRow_getIntegerValueAt": "getIntegerValueAt",
    "CSVRow_getName": "getName",
    "CSVRow_getValueAt": "getValueAt",
    "CSVRow_getBooleanValueAt": "getBooleanValueAt",
    "CSVTable_getColumnIndexByName": "getColumnIndexByName",

    # Messages / Chat
    "TeamChatMessage_ctor": "TeamChatMessage",
    "TeamSetMemberReadyMessage_ctor": "TeamSetMemberReadyMessage",
    "StartSpectateMessage_ctor": "StartSpectateMessage",
    "PiranhaMessage_ctor": "PiranhaMessage",

    # Hash / Code
    "HashTagCodeGenerator_ctor": "HashTagCodeGenerator",
    "HashTagCodeGenerator_toId": "toId",
    "HashTagCodeGenerator_dtor": "HashTagCodeGenerator",
    "HashTagCodeGenerator_isValid": "isValid",
    "LogicLongToCodeConverterUtil_ctor": "LogicLongToCodeConverterUtil",
    "LogicLongToCodeConverterUtil_convert": "convert",
    "LogicLongToCodeConverterUtil_toCode": "toCode",

    # Random / JSON
    "LogicRandom_setIteratedRandomSeed": "setIteratedRandomSeed",
    "LogicJSONObject_put": "put",

    # Screen
    "Screen_getDpiClass": "getDpiClass",
    "Screen_getHeight": "getHeight",
    "Screen_getWidth": "getWidth",

    # Misc
    "nativeCopyToClipboard": "copyToClipboard",
    "SetClientPrediction": "setClientPrediction",
    "ScrollArea_scrollTo": "scrollTo",
    "ScrollArea_updateBounds": "updateBounds",
    "ScrollArea_addContent": "addContent",
    "ScrollArea_removeAllContent": "removeAllContent",
    "GlobalID_getInstanceID": "getInstanceID",
    "LogicPlayerMap_save": "save",
    "LogicPlayerMapUtil_tileDataToTileCode": "tileDataToTileCode",
    "AnalyticEvent_ctor": "AnalyticEvent",
    "AnalyticEvent_setString": "setString",
    "LogicCompressedString_ctor": "LogicCompressedString",
    "ResourceListener_addFile": "addFile",
    "AreaEffectData_getRadius": "getRadius",
    "AreaEffectData_getActiveTimeMs": "getActiveTimeMs",
    "LogicData_getName": "getName",
}

# 2) ГЛОБАЛЬНЫЕ переменные (ищутся как адреса данных, у которых есть xref)
GLOBAL_TARGETS = {
    "MessageManager_instance": "MessageManager",
    "AllianceManager_instance": "AllianceManager",
    "StageInstanceGlobalPtr": "Stage",
    "Screen_widthGlobal": "Screen",
    "Screen_heightGlobal": "Screen",
    "FramerateManager_targetFps": "FramerateManager",
    "LogicDataTables_tableArray": "LogicDataTables",
    "VTABLE_PROJECTILE_DATA": "LogicProjectileData",
    "VTABLE_CHARACTER_DATA": "LogicCharacterData",
    "VTABLE_TEXT_FIELD": "TextField",
    "VTABLE_DECORATED_TEXT_FIELD": "DecoratedTextField",
    "VTABLE_GRADIENT_DATA": "GradientData",
    "ClientInput_typeConstantTable": "ClientInput",
    "SkillCommandTypeTable": "SkillCommand",
    "ClientInput_hashInnerMask": "ClientInput",
    "ClientInput_hashOuterMask": "ClientInput",
}

def log(m):
    sys.stdout.write(m + "\n"); sys.stdout.flush()

def rva(a):
    try: return int(a.getOffset()) - BASE
    except: return -1

def build_index():
    listing = currentProgram.getListing()
    idx = {}
    it = listing.getDefinedData(True)
    total = 0
    while it.hasNext():
        if time.time() - START > BUDGET - 300: break
        try: d = it.next()
        except: break
        try:
            if d is None or not d.hasStringValue(): continue
            s = str(d.getValue())
            if not s: continue
            total += 1
            idx.setdefault(s, []).append(d.getAddress())
        except: continue
    log("[*] strings: %d unique: %d" % (total, len(idx)))
    return idx

def find_refs(a):
    out = []
    try:
        rm = currentProgram.getReferenceManager()
        it = rm.getReferencesTo(a).iterator()
        while it.hasNext(): out.append(it.next().getFromAddress())
    except: pass
    return out

def funcs_via_string(idx, needle, max_str=20, max_funcs=4):
    """Все функции, которые ссылаются на любую строку, содержащую needle."""
    found = {}
    for s, addrs in idx.items():
        if needle not in s: continue
        for sa in addrs[:max_str]:
            for ra in find_refs(sa):
                f = getFunctionContaining(ra)
                if f is None: continue
                fr = rva(f.getEntryPoint())
                if fr <= 0: continue
                if fr not in found:
                    found[fr] = (f.getName(), rva(sa))
                if len(found) >= max_funcs: return found
    return found

def data_via_string(idx, needle, max_str=20, max_data=4):
    """Адреса данных (не код), ссылающихся на строку."""
    found = {}
    for s, addrs in idx.items():
        if needle not in s: continue
        for sa in addrs[:max_str]:
            for ra in find_refs(sa):
                blk = currentProgram.getMemory().getBlock(ra)
                if blk is None: continue
                bn = blk.getName()
                if "text" in bn.lower(): continue
                dr = rva(ra)
                if dr <= 0: continue
                if dr not in found:
                    found[dr] = (bn, rva(sa))
                if len(found) >= max_data: return found
    return found

def main():
    log("=== find_offsets (full list) ===")
    log("program: %s" % currentProgram.getName())

    idx = build_index()
    if not idx: return

    results = {}

    # --- FUNCTIONS ---
    log("")
    log("=== FUNCTION SEARCH (%d targets) ===" % len(FUNCTION_TARGETS))
    for tag, needle in sorted(FUNCTION_TARGETS.items()):
        hits = funcs_via_string(idx, needle, max_str=10, max_funcs=3)
        if hits:
            fr = sorted(hits.keys())[0]
            name = hits[fr][0]
            results[tag] = (fr, "func via str '%s'" % needle)
            log("  %-60s 0x%-8x %s" % (tag, fr, name))
        else:
            log("  %-60s NOT FOUND" % tag)

    # --- GLOBALS (data) ---
    log("")
    log("=== GLOBAL SEARCH (%d targets) ===" % len(GLOBAL_TARGETS))
    for tag, needle in sorted(GLOBAL_TARGETS.items()):
        hits = data_via_string(idx, needle, max_str=10, max_data=3)
        if hits:
            dr = sorted(hits.keys())[0]
            results[tag] = (dr, "data via str '%s'" % needle)
            log("  %-60s 0x%-8x (blk=%s)" % (tag, dr, hits[dr][0]))
        else:
            log("  %-60s NOT FOUND" % tag)

    log("")
    log("=== SUMMARY: %d / %d found ===" % (
        len(results), len(FUNCTION_TARGETS) + len(GLOBAL_TARGETS)))

    with open(OUT, "w") as fh:
        fh.write("export const offsets = Object.freeze({\n")
        for k in sorted(results.keys()):
            fr, note = results[k]
            fh.write("  %s: 0x%x, // %s\n" % (k, fr, note))
        fh.write("});\n")

    with open(REPORT, "w") as fh:
        for k in sorted(results.keys()):
            fr, note = results[k]
            fh.write("%s = 0x%x  # %s\n" % (k, fr, note))
    log("[+] wrote %s" % OUT)

try: main()
except SystemExit: raise
except Exception as e:
    log("FATAL: %s" % e); traceback.print_exc()