# -*- coding: utf-8 -*-
# @runtime Jython
#
# find_offsets_ios.py  --  Ghidra headless / Jython 2.7
# Порт Android-скрипта (ELF libg.so, BASE=0x100000000) на iOS (Mach-O arm64 / arm64e).
#
# НАЗНАЧЕНИЕ
#   Пройти по FUNCTION_TARGETS / GLOBAL_TARGETS и выдать готовый offsets_resolved.js
#   в формате REvengeBS: export const offsets = Object.freeze({...}).
#
# ОТЛИЧИЯ ОТ ANDROID-ВЕРСИИ
#   1. BASE не хардкодится. Берём currentProgram.getImageBase(). Android libg.so грузится
#      на 0x100000000, Mach-O main-executable обычно тоже, а dylib/framework -- на своей
#      vmaddr, поэтому хардкод 0x100000000 там даёт мусор. RVA = addr - imageBase, ровно то,
#      что ждёт scanner.js (moduleBase.add(offsets.X)).
#   2. text/data различаем по правам памяти (isExecute), а не по подстроке в имени блока:
#      на Mach-O нет .text/.data -- есть __TEXT / __DATA_CONST / __DATA / __LINKEDIT, а
#      константы (в т.ч. некоторые vtable) лежат в __TEXT,__const.
#   3. Стратегии резолва (по убыванию доверия, стратегия пишется в отчёт):
#        S0 symbol  таблица символов Ghidra (C++ demangled / exported). На iOS даже
#                   stripped-бинарь обычно сохраняет exported-символы и RTTI/vftable.
#        S1 string  xref от строки к коду -- исходная логика Android-скрипта.
#        S2 objc    селектор из __objc_methname -> method_t -> IMP.
#                   iOS15+ relative method list: imp = addr(imp_field) + int32(imp_field);
#                   classic method_t: IMP по смещению +16.
#        S3 ptr     скан data-секций на указатели в __text/__cstring со снятием PAC (arm64e):
#                   ловит вызовы через указательные таблицы, которые ReferenceManager пропустил.
#        S4 slot    адрес данных, на который ссылается тело функции (adrp/add):
#                   так достаются синглтоны (MessageManager_instance, FramerateManager_targetFps...).
#        S5 vtable  vftable класса по символу <Class>::vftable; fallback -- поиск в data
#                   указателя на <Class>::typeinfo, тогда vtable = ptr - 8 (Itanium ABI).
#   4. Бонус: секция "vtable slot map" -- для найденных vtable печатаем, какие слоты
#      указывают на уже найденные функции. Это позволяет добирать соседние методы класса
#      (слот виртуального метода стабилен), т.е. "найти все оффсеты", а не только топовые.
#
# SCRE-ЗАМЕТКИ (Supercell Reverse Engineering)
#   * Supercell iOS -- статически слинкованный main-executable, C++ (Logic*/GUI*/BattleScreen*)
#     + ObjC-прослойка. Строки лежат в __TEXT,__cstring и __TEXT,__objc_methname.
#   * Arxan: код/строки могут быть зашифрованы и разворачиваться только в рантайме (см.
#     0x410c/COC_2k18_pt2: Frida-дампы стадий расшифровки). Если скрипт на статическом
#     файле из IPA находит мало -- грузи в Ghidra ДАМП ПАМЯТИ, а не файл из IPA.
#   * Валидация результатов: RVA функции обязан попадать в исполняемый блок; RVA данных --
#     в data/__const. Проверяй на 2-3 известных оффсетах из offsets.js, прежде чем катить весь файл.
#
# ЗАПУСК
#   lipo -thin arm64 "Payload/X.app/<binary>" -output <binary>.arm64
#   $GHIDRA/support/analyzeHeadless <projDir> <projName> -import <binary>.arm64 \
#       -processor aarch64:LE:64:v8A -postScript find_offsets_ios.py
#   ASCII Strings analyzer: если в индексе подозрительно мало строк, скрипт сам до-создаёт
#   их из __cstring/__objc_methname.
#
# ВЫХОД
#   $GITHUB_WORKSPACE (или cwd) / offsets_resolved.js
#   $GITHUB_WORKSPACE (или cwd) / offsets_report.txt

import os
import re
import sys
import time
import traceback

WS = os.environ.get("GITHUB_WORKSPACE") or os.getcwd()
OUT = os.path.join(WS, "offsets_resolved.js")
REPORT = os.path.join(WS, "offsets_report.txt")
BUDGET = 1800
START = time.time()

# Всё, что зависит от конкретного образа, живёт тут (Jython: без module-level global-хаков).
G = {"BASE": 0, "TEXT": [], "DATA": [], "PTR": {}, "SADDR": {}}

PTR_MASK = 0x00FFFFFFFFFFFFFF      # снимаем PAC в старшем байте (arm64e)
MAX_STRING_ADDRS = 24              # сколько строк-кандидатов на один needle
MAX_FUNC_CANDIDATES = 8
MAX_STR_ADDRS_FOR_PTRSCAN = 6000   # сколько строк матчим в ptr-скане

FUNCTION_TARGETS = {
    "LogicBattleModeClient_update": "update",
    "LogicBattleModeClient_getOwnCharacter": "getOwnCharacter",
    "LogicBattleModeClient_getOwnPlayerTeam": "getOwnPlayerTeam",
    "LogicBattleModeClient_setClientPredictionMoveTo": "setClientPredictionMoveTo",
    "LogicBattleModeClient_getOwnPlayerIndex": "getOwnPlayerIndex",
    "LogicBattleModeClient_getTileMap": "getTileMap",
    "LogicBattleModeClient_setRandomSeed": "setRandomSeed",
    "LogicBattleModeClient_setPlayerAvatar": "setPlayerAvatar",

    "BattleMode_getInstance": "getInstance",
    "BattleMode_enter": "enter",
    "BattleMode_addResourcesToLoad": "addResourcesToLoad",

    "LogicGameObjectClient_getX": "getX",
    "LogicGameObjectClient_getY": "getY",
    "LogicGameObjectClient_getZ": "getZ",
    "LogicGameObjectClient_getGlobalID": "getGlobalID",
    "LogicGameObjectClient_getData": "getData",

    "BattleScreen_activateSkill": "activateSkill",
    "BattleScreen_updateCameraParameters": "updateCameraParameters",
    "BattleScreen_stopWithStick": "stopWithStick",
    "BattleScreen_handleTouchReleased": "handleTouchReleased",
    "BattleScreen_updateAutoshoot": "updateAutoshoot",
    "BattleScreen_getClosestTargetForAutoshoot": "getClosestTargetForAutoshoot",
    "BattleScreen_updateMovement": "updateMovement",
    "BattleScreen_tryToActivateSkill": "tryToActivateSkill",
    "BattleScreen_shouldShowAccessoryButton": "shouldShowAccessoryButton",
    "BattleScreen_calculateProjectilePath": "calculateProjectilePath",
    "BattleScreen_joystickToWorld": "joystickToWorld",

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

    "GameButton_ctor": "GameButton",
    "GameButton_buttonPressed": "buttonPressed",
    "GameButton_setText": "setText",
    "CustomButton_onButtonPressed": "onButtonPressed",

    "Sprite_ctor": "Sprite",
    "Sprite_addChild": "addChild",
    "Sprite_addChildAt": "addChildAt",
    "Sprite_removeChild": "removeChild",
    "Stage_addChild": "addChild",
    "DisplayObject_setXY": "setXY",
    "DisplayObject_removeFromParent": "removeFromParent",

    "MovieClip_getTextFieldByName": "getTextFieldByName",
    "MovieClip_getChildClipByName": "getChildClipByName",
    "MovieClip_setChildVisible": "setChildVisible",
    "MovieClip_gotoAndStopFrameIndex": "gotoAndStopFrameIndex",
    "MovieClipHelper_setTextAndScaleIfNecessary": "setTextAndScaleIfNecessary",

    "TextField_setText": "setText",
    "TextField_fetchFont": "fetchFont",
    "String_ctor": "String",
    "String_format": "format",
    "Application_copyString": "copyString",
    "decoratedTextFieldSetPlayerName": "setPlayerName",
    "Name_setupDecorated": "setupDecorated",
    "Name_applyDecoration": "applyDecoration",

    "ClientInput_ctor": "ClientInput",
    "ClientInputManager_addInput": "addInput",
    "ClientInputMessage_sendMovement": "sendMovement",
    "handleJoystick": "handleJoystick",

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
    "LogicTileMap_isPlayerLineOfSightClear": "isPlayerLineOfSightClear",
    "LogicTileMap_getTile": "getTile",
    "LogicDataTables_getOpenTileData": "getOpenTileData",
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
    "LogicGameObjectManagerClient_getGameObjects": "getGameObjects",
    "LogicGameObjectManagerClient_findGameObject": "findGameObject",
    "LogicGameObjectServer_getData": "getData",
    "LogicProjectileServer_shootProjectile": "shootProjectile",
    "LogicProjectileServer_runEarlyTicks": "runEarlyTicks",
    "LogicProjectileClient_destruct": "destruct",
    "LogicProjectileClient_getData": "getData",
    "LogicProjectileClient_getTargetX": "getTargetX",
    "LogicProjectileClient_getTargetY": "getTargetY",
    "LogicGameModeUtil_isTileOnPoisonArea": "isTileOnPoisonArea",

    "Projectile_ctor": "Projectile",
    "Projectile_update": "update",

    "GameMain_update": "update",
    "DecalManager_ctor": "DecalManager",
    "GameObjectManager_ctor": "GameObjectManager",
    "RenderSystem_ctor": "RenderSystem",
    "ResourceManager_getCSV": "getCSV",
    "ResourceManager_isResourceLoaded": "isResourceLoaded",
    "StringTable_getMovieClip": "getMovieClip",
    "FramerateManager_setSegment": "setSegment",
    "FramerateManager_setLimit": "setLimit",
    "MessageManager_receiveMessage": "receiveMessage",
    "MessageManager_sendMessage": "sendMessage",
    "AllianceManager_startSpectate": "startSpectate",

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
    "GameSettings_isFixedJoystickEnabled": "isFixedJoystickEnabled",
    "GameStateManager_getInstance": "getInstance",
    "GameStateManager_isState": "isState",
    "HomeMode_getInstance": "getInstance",

    "GameSliderComponent_ctor": "GameSliderComponent",
    "GameSliderComponent_setValueBounds": "setValueBounds",
    "DropGUIContainer_ctorFromExport": "ctorFromExport",
    "MapEditorModifierItem_ctor": "MapEditorModifierItem",
    "MapEditorModifierPopup_ctor": "MapEditorModifierPopup",
    "MapEditorModifierPopup_addModifierItem": "addModifierItem",

    "CSVRow_getIntegerValueAt": "getIntegerValueAt",
    "CSVRow_getName": "getName",
    "CSVRow_getValueAt": "getValueAt",
    "CSVRow_getBooleanValueAt": "getBooleanValueAt",
    "CSVTable_getColumnIndexByName": "getColumnIndexByName",

    "TeamChatMessage_ctor": "TeamChatMessage",
    "TeamSetMemberReadyMessage_ctor": "TeamSetMemberReadyMessage",
    "StartSpectateMessage_ctor": "StartSpectateMessage",
    "PiranhaMessage_ctor": "PiranhaMessage",

    "HashTagCodeGenerator_ctor": "HashTagCodeGenerator",
    "HashTagCodeGenerator_toId": "toId",
    "HashTagCodeGenerator_isValid": "isValid",
    "LogicLongToCodeConverterUtil_convert": "convert",
    "LogicLongToCodeConverterUtil_toCode": "toCode",

    "LogicRandom_setIteratedRandomSeed": "setIteratedRandomSeed",
    "LogicJSONObject_put": "put",

    "Screen_getDpiClass": "getDpiClass",
    "Screen_getHeight": "getHeight",
    "Screen_getWidth": "getWidth",

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
    "ClientInput_typeConstantTable": "ClientInput",
    "SkillCommandTypeTable": "SkillCommand",
    "ClientInput_hashInnerMask": "ClientInput",
    "ClientInput_hashOuterMask": "ClientInput",
}

# --------------------------------------------------------------------------- #
# утилиты
# --------------------------------------------------------------------------- #

SPLIT_RE = re.compile(r"[^A-Za-z0-9_]+")
CAMEL_RE = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")


def log(m):
    sys.stdout.write(m + "\n")
    sys.stdout.flush()


def off(a):
    """Address -> long (offset в адресном пространстве программы)."""
    try:
        return a.getOffset()
    except:
        try:
            return int(a)
        except:
            return -1


def rva(a):
    try:
        return off(a) - G["BASE"]
    except:
        return -1


def out_of_time(reserve=0):
    return (time.time() - START) > (BUDGET - reserve)


def blk_exec(b):
    for meth in ("isExecute", "isExecutable"):
        try:
            return bool(getattr(b, meth)())
        except:
            pass
    try:
        return "x" in str(b.getPermissions()).lower()
    except:
        return False


def blk_of(a):
    try:
        return currentProgram.getMemory().getBlock(a)
    except:
        return None


def blk_name(a):
    b = blk_of(a)
    if b is None:
        return ""
    try:
        return (b.getName() or "")
    except:
        return ""


def in_text(a):
    b = blk_of(a)
    return (b is not None) and blk_exec(b)


def is_code_addr(a):
    """Адрес занят функцией (а не данными)."""
    try:
        return getFunctionAt(a) is not None or getFunctionContaining(a) is not None
    except:
        return False


def tokens_of(s):
    """'LogicCharacterData_getSpeed' -> {LogicCharacterData, getSpeed, Logic, Character, Data, ...}"""
    out = set()
    if not s:
        return out
    for part in SPLIT_RE.split(s):
        if not part:
            continue
        out.add(part)
        for w in CAMEL_RE.split(part):
            w = w.strip("_")
            if w:
                out.add(w)
    return out


# --------------------------------------------------------------------------- #
# инициализация образа
# --------------------------------------------------------------------------- #

def init_image():
    p = currentProgram
    G["BASE"] = p.getImageBase().getOffset()
    mem = p.getMemory()
    for b in mem.getBlocks():
        try:
            if not b.isInitialized():
                continue
        except:
            continue
        if blk_exec(b):
            G["TEXT"].append(b)
        else:
            G["DATA"].append(b)
    log("[*] blocks: text=%d data=%d" % (len(G["TEXT"]), len(G["DATA"])))


# --------------------------------------------------------------------------- #
# индексы: строки, токены, указатели
# --------------------------------------------------------------------------- #

def build_index():
    listing = currentProgram.getListing()
    idx = {}
    saddr = {}
    total = 0
    it = listing.getDefinedData(True)
    while it.hasNext():
        if out_of_time(300):
            log("[!] build_index: budget cutoff")
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
            a = d.getAddress()
            idx.setdefault(s, []).append(a)
            saddr[off(a)] = s
        except:
            continue
    G["SADDR"] = saddr
    log("[*] strings: %d unique: %d" % (total, len(idx)))
    return idx


def define_cstrings():
    """Fallback: ASCII Strings analyzer не отработал -- создаём строки вручную."""
    mem = currentProgram.getMemory()
    made = 0
    for b in mem.getBlocks():
        if out_of_time(600):
            break
        n = ""
        try:
            n = (b.getName() or "").lower()
        except:
            continue
        if ("cstring" not in n) and ("methname" not in n) and ("str" not in n):
            continue
        try:
            a = b.getStart()
            end = b.getEnd().getOffset()
        except:
            continue
        while a.getOffset() < end:
            if out_of_time(600):
                break
            try:
                if mem.getByte(a) == 0:
                    a = a.add(1)
                    continue
            except:
                break
            try:
                d = createAsciiString(a)
                if d is not None:
                    made += 1
                    a = d.getAddress().add(d.getLength())
                    continue
            except:
                pass
            a = a.add(1)
    return made


def build_token_index(idx):
    ti = {}
    for s, addrs in idx.items():
        for tok in tokens_of(s):
            lst = ti.get(tok)
            if lst is None:
                ti[tok] = list(addrs)
            else:
                lst.extend(addrs)
    log("[*] token index: %d tokens" % len(ti))
    return ti


def needle_addrs(needle, idx, ti, limit=MAX_STRING_ADDRS):
    """Адреса строк, содержащих needle. Точные совпадения -- первыми."""
    seen = set()
    out = []

    def push(a):
        o = off(a)
        if o in seen:
            return
        seen.add(o)
        out.append(a)

    for a in idx.get(needle, [])[:limit]:
        push(a)
    for a in ti.get(needle, []):
        if len(out) >= limit:
            break
        s = G["SADDR"].get(off(a))
        if s is None or needle not in s:
            continue
        push(a)
    if len(out) < limit:
        for tok in tokens_of(needle):
            for a in ti.get(tok, []):
                if len(out) >= limit:
                    break
                s = G["SADDR"].get(off(a))
                if s is None or needle not in s:
                    continue
                push(a)
    return out[:limit]


def build_ptr_index(target_addrs):
    """Один проход по data-блокам: ищем 8-байтные указатели в text/const (PAC снят)."""
    if not target_addrs:
        return {}
    # Ключ индекса -- ПОЛНЫЙ адрес цели (не RVA), т.к. в памяти лежат полные указатели.
    tset = set(off(a) for a in target_addrs)
    hit = {}
    mem = currentProgram.getMemory()
    scanned = 0
    for b in (G["DATA"] + G["TEXT"]):
        if out_of_time(240):
            log("[!] ptr scan: budget cutoff (%d blocks scanned)" % scanned)
            break
        try:
            if not b.isInitialized():
                continue
            a = b.getStart()
            end = b.getEnd().getOffset()
        except:
            continue
        scanned += 1
        while a.getOffset() < end:
            try:
                v = mem.getLong(a) & PTR_MASK
            except:
                a = a.add(8)
                continue
            if v in tset:
                hit.setdefault(v, []).append(a)
            a = a.add(8)
    log("[*] ptr index: %d target strings referenced from data" % len(hit))
    return hit


# --------------------------------------------------------------------------- #
# refs
# --------------------------------------------------------------------------- #

def refs_via_manager(a):
    out = []
    try:
        rm = currentProgram.getReferenceManager()
        it = rm.getReferencesTo(a).iterator()
        while it.hasNext():
            out.append(it.next().getFromAddress())
    except:
        pass
    return out


def all_refs(a):
    out = []
    seen = set()
    for x in refs_via_manager(a):
        o = off(x)
        if o in seen:
            continue
        seen.add(o)
        out.append(x)
    for x in G["PTR"].get(off(a), []):
        o = off(x)
        if o in seen:
            continue
        seen.add(o)
        out.append(x)
    return out


def func_data_refs(f):
    """Адреса данных, на которые ссылается тело функции (adrp/add/pac-adrp и т.п.)."""
    res = {}
    try:
        body = f.getBody()
        it = currentProgram.getListing().getInstructions(body, True)
    except:
        return res
    while it.hasNext():
        try:
            ins = it.next()
        except:
            break
        try:
            mnem = (ins.getMnemonicString() or "").upper()
        except:
            mnem = ""
        if mnem.startswith("B") and mnem != "B.AL":
            continue          # ветвление внутри кода, не данные
        try:
            refs = ins.getReferencesFrom()
        except:
            continue
        for r in refs:
            try:
                to = r.getToAddress()
            except:
                continue
            if to is None:
                continue
            if is_code_addr(to):
                continue
            b = blk_of(to)
            if b is None:
                continue
            res[off(to)] = res.get(off(to), 0) + 1
    return res


# --------------------------------------------------------------------------- #
# стратегии: функции
# --------------------------------------------------------------------------- #

def _score_func_name(name, cls, method):
    if not name:
        return None
    ln = name.lower()
    lm = method.lower()
    if lm not in ln:
        return None
    if cls:
        lc = cls.lower()
        if lc not in ln:
            return None
        if name == cls + "::" + method:
            return 0
        if name.startswith(cls + "::" + method + "("):
            return 1
        if name.startswith(cls) and ("::" + method) in name:
            return 2
        return 3
    if name == method:
        return 0
    if name.endswith("::" + method):
        return 1
    if name.startswith(method + "("):
        return 2
    if ("::" + method + "(") in name:
        return 3
    return 4


def func_via_symbol(cls, method):
    """S0: таблица символов Ghidra (демангленные C++ / exports)."""
    fm = currentProgram.getFunctionManager()
    best = None
    best_score = 999
    it = fm.getFunctions(True)
    while it.hasNext():
        if out_of_time(600):
            break
        try:
            f = it.next()
        except:
            break
        try:
            n = f.getName()
        except:
            continue
        sc = _score_func_name(n, cls, method)
        if sc is None or sc >= best_score:
            continue
        ep = f.getEntryPoint()
        if rva(ep) <= 0 or not in_text(ep):
            continue
        best_score = sc
        best = (rva(ep), n)
        if sc == 0:
            break
    return best


def funcs_via_string(addrs, cls):
    """S1: xref от строки к содержащей функции. Ранжируем по числу совпадений + имени.

    Возвращает (rva, name, name_matches_class). Если имя найденной функции НЕ содержит
    класс из тега -- это, скорее всего, чужая функция с тем же именем метода (update/getData
    есть у сотен классов), поэтому conf понижается до low.
    """
    found = {}
    for sa in addrs:
        for ra in all_refs(sa):
            f = getFunctionContaining(ra)
            if f is None:
                continue
            ep = f.getEntryPoint()
            fr = rva(ep)
            if fr <= 0 or not in_text(ep):
                continue
            try:
                nm = f.getName()
            except:
                nm = ""
            ent = found.get(fr)
            if ent is None:
                found[fr] = [nm, off(sa), 1, _score_func_name(nm, cls, "") if cls else None]
            else:
                ent[2] += 1
    if not found:
        return None
    items = []
    for fr, (nm, sa, cnt, sc) in found.items():
        rank = (0 if sc == 0 else 1 if sc is not None else 2)
        items.append((rank, -cnt, fr, nm))
    items.sort()
    fr, nm = items[0][2], items[0][3]
    matched = bool(cls) and (cls.lower() in (nm or "").lower())
    return (fr, nm, matched)


def funcs_via_objc(addrs):
    """S2: селектор __objc_methname -> method_t -> IMP (iOS15+ rel-list и classic)."""
    mem = currentProgram.getMemory()
    for sa in addrs:
        bn = blk_name(sa).lower()
        if "methname" not in bn:
            continue
        for ra in all_refs(sa):
            bases = [off(ra)] + [off(x) for x in G["PTR"].get(off(sa), [])]
            for base in bases:
                # relative method list: name@+0, types@+4, imp@+8 (each rel to own addr)
                for field_off, rel in ((8, True), (16, False)):
                    try:
                        faddr = toAddr(base + field_off)
                        if rel:
                            v = mem.getInt(faddr)
                            target = (base + field_off) + v
                        else:
                            target = mem.getLong(faddr) & PTR_MASK
                    except:
                        continue
                    ta = toAddr(target)
                    if ta is None or not in_text(ta):
                        continue
                    f = getFunctionContaining(ta)
                    if f is None:
                        continue
                    ep = f.getEntryPoint()
                    fr = rva(ep)
                    if fr <= 0:
                        continue
                    try:
                        nm = f.getName()
                    except:
                        nm = ""
                    return (fr, nm)
    return None


def funcs_via_neighbors(addrs):
    """S3: строку адресует data-таблица; рядом (+8/+16/+24/-8) лежит указатель в код.
    Ловит dispatch-таблицы, где ReferenceManager не создал ссылку на код."""
    mem = currentProgram.getMemory()
    for sa in addrs:
        for ra in G["PTR"].get(off(sa), []):
            for delta in (8, 16, 24, -8):
                try:
                    a = ra.add(delta)
                    v = mem.getLong(a) & PTR_MASK
                except:
                    continue
                ta = toAddr(v)
                if ta is None or not in_text(ta):
                    continue
                f = getFunctionContaining(ta)
                if f is None:
                    continue
                ep = f.getEntryPoint()
                fr = rva(ep)
                if fr > 0:
                    try:
                        nm = f.getName()
                    except:
                        nm = ""
                    return (fr, nm)
    return None


def resolve_function(cls, method, idx, ti):
    sym_method = cls if method.lower() == "ctor" else method

    r = func_via_symbol(cls, sym_method)
    if r:
        return r[0], "S0:symbol", "high", r[1]
    if not cls:
        r = func_via_symbol("", sym_method)
        if r:
            return r[0], "S0:symbol", "med", r[1]

    addrs = needle_addrs(method, idx, ti)
    if not addrs:
        return None, None, None, None

    r = funcs_via_string(addrs, cls)
    if r:
        conf = "med" if r[2] else "low"
        return r[0], "S1:string", conf, r[1]

    r = funcs_via_objc(addrs)
    if r:
        return r[0], "S2:objc", "med", r[1]

    r = funcs_via_neighbors(addrs)
    if r:
        return r[0], "S3:ptr", "low", r[1]
    return None, None, None, None


# --------------------------------------------------------------------------- #
# стратегии: данные
# --------------------------------------------------------------------------- #

def data_via_symbol(needle, cls):
    """S0: символ данных (статические члены C++, глобалы, RTTI)."""
    st = currentProgram.getSymbolTable()
    best = None
    best_score = 999
    it = st.getAllSymbols(True)
    while it.hasNext():
        if out_of_time(600):
            break
        try:
            s = it.next()
        except:
            break
        try:
            n = s.getName()
            a = s.getAddress()
        except:
            continue
        if not n or a is None:
            continue
        if is_code_addr(a):
            continue
        ln = n.lower()
        if needle.lower() not in ln:
            continue
        sc = 0 if n == needle else 1
        if cls:
            if cls.lower() not in ln:
                continue
        else:
            sc += 1
        if sc >= best_score:
            continue
        best_score = sc
        best = (rva(a), n)
        if sc == 0 and cls:
            break
    return best


def data_via_string(addrs):
    """S1: refs на строку из data-блоков (исходная логика Android-скрипта)."""
    found = {}
    for sa in addrs:
        for ra in all_refs(sa):
            b = blk_of(ra)
            if b is None:
                continue
            if blk_exec(b) and is_code_addr(ra):
                continue
            dr = rva(ra)
            if dr <= 0:
                continue
            found.setdefault(dr, (blk_name(ra), off(sa)))
    if not found:
        return None
    dr = sorted(found.keys())[0]
    return (dr, found[dr][0])


def global_via_func_data(cls, method_hint):
    """S4: адрес данных из тела getInstance()/ctor класса (синглтоны)."""
    cands = {}
    for method in (method_hint, "ctor", "Ctor"):
        f = None
        r = func_via_symbol(cls, method)
        if r:
            try:
                f = getFunctionAt(toAddr(r[0] + G["BASE"]))
            except:
                f = None
        if f is None:
            continue
        for o, cnt in func_data_refs(f).items():
            cands[o] = cands.get(o, 0) + cnt
    if not cands:
        return None
    items = sorted(cands.items(), key=lambda kv: -kv[1])
    o = items[0][0]
    return (o - G["BASE"], "cands=%d" % len(cands))


def vtable_for_class(cls):
    """S5: vftable класса. Символ <Class>::vftable, иначе ptr -> <Class>::typeinfo (-8)."""
    st = currentProgram.getSymbolTable()
    lcls = cls.lower()
    typeinfo = None
    it = st.getAllSymbols(True)
    while it.hasNext():
        if out_of_time(600):
            break
        try:
            s = it.next()
            n = s.getName()
            a = s.getAddress()
        except:
            continue
        if not n or a is None or is_code_addr(a):
            continue
        ln = n.lower()
        if lcls not in ln:
            continue
        if "vftable" in ln or "vtable" in ln or "ztv" in ln:
            return (rva(a), "sym:" + n)
        if "typeinfo" in ln or "zti" in ln:
            typeinfo = a
    if typeinfo is not None:
        mem = currentProgram.getMemory()
        tset = set([off(typeinfo)])
        for b in (G["DATA"] + G["TEXT"]):
            try:
                if not b.isInitialized():
                    continue
                a = b.getStart()
                end = b.getEnd().getOffset()
            except:
                continue
            while a.getOffset() < end:
                try:
                    if (mem.getLong(a) & PTR_MASK) == off(typeinfo):
                        va = a.subtract(8)
                        return (rva(va), "rtti-8:" + str(typeinfo))
                except:
                    pass
                a = a.add(8)
                if out_of_time(240):
                    break
    return None


def resolve_global(tag, needle, idx, ti):
    if tag.startswith("VTABLE_"):
        cls = needle
        r = vtable_for_class(cls)
        if r:
            return r[0], "S5:vtable", "med", r[1]
        return None, None, None, None

    r = data_via_symbol(needle, None)
    if r:
        return r[0], "S0:symbol", "high", r[1]

    r = global_via_func_data(needle, "getInstance")
    if r:
        return r[0], "S4:slot", "med", r[1]

    addrs = needle_addrs(needle, idx, ti)
    if addrs:
        r = data_via_string(addrs)
        if r:
            return r[0], "S1:string", "low", r[1]
    return None, None, None, None


# --------------------------------------------------------------------------- #
# vtable slot map (бонус: добираем соседние методы класса)
# --------------------------------------------------------------------------- #

def vtable_slot_map(rel, resolved):
    """rel: {tag: rva}, resolved: {tag: rva} -> печать слотов vtable, совпавших с функциями."""
    mem = currentProgram.getMemory()
    by_rva = {}
    for tag, val in resolved.items():
        by_rva.setdefault(val, []).append(tag)
    lines = []
    for tag in sorted(rel.keys()):
        base = rel[tag]
        a0 = toAddr(base + G["BASE"])
        if a0 is None:
            continue
        hit = []
        for i in range(256):
            try:
                v = mem.getLong(a0.add(16 + 8 * i)) & PTR_MASK
            except:
                break
            if v == 0:
                continue
            ta = toAddr(v)
            if ta is None or not in_text(ta):
                continue
            f = getFunctionContaining(ta)
            if f is None:
                continue
            fr = rva(f.getEntryPoint())
            names = by_rva.get(fr)
            if names:
                hit.append("    slot[%3d] = %s  (0x%x)" % (i, ",".join(names), v))
        lines.append("  %s @ 0x%x" % (tag, base))
        if hit:
            lines.extend(hit)
        else:
            lines.append("    (no slots matched resolved functions)")
    return lines


# --------------------------------------------------------------------------- #
# main
# --------------------------------------------------------------------------- #

def main():
    log("=== find_offsets_ios (Mach-O / arm64) ===")
    if currentProgram is None:
        log("[!] no program loaded")
        return
    log("program : %s" % currentProgram.getName())
    try:
        log("format  : %s" % currentProgram.getExecutableFormat())
    except:
        pass
    try:
        log("language: %s" % currentProgram.getLanguageID())
    except:
        pass

    init_image()
    log("imageBase: 0x%x" % G["BASE"])
    if G["BASE"] == 0:
        log("[!] imageBase == 0 -- проверь, что загружен именно Mach-O (lipo -thin arm64)")

    idx = build_index()
    if len(idx) < 1000:
        log("[*] строк мало (%d) -- до-создаю из __cstring/__objc_methname" % len(idx))
        made = define_cstrings()
        log("[*] created strings: %d" % made)
        idx = build_index()
    if not idx:
        log("[!] строк нет вообще: бинарь, вероятно, зашифрован (Arxan) --")
        log("    снимай God-дамп памяти (Frida) и импортируй в Ghidra дамп, а не файл из IPA")
        return

    ti = build_token_index(idx)
    G["PTR"] = {}

    # какие строки вообще интересны для ptr-скана
    interesting = []
    seen = set()
    for tgt in (list(FUNCTION_TARGETS.values()) + list(GLOBAL_TARGETS.values())):
        if len(interesting) >= MAX_STR_ADDRS_FOR_PTRSCAN:
            break
        for a in needle_addrs(tgt, idx, ti, limit=8):
            o = off(a)
            if o in seen:
                continue
            seen.add(o)
            interesting.append(a)
    log("[*] interesting strings: %d" % len(interesting))
    G["PTR"] = build_ptr_index(interesting)

    results = {}     # tag -> (rva, strategy, conf, name)
    resolved = {}    # tag -> rva (только найденные)

    log("")
    log("=== FUNCTIONS (%d targets) ===" % len(FUNCTION_TARGETS))
    for tag in sorted(FUNCTION_TARGETS.keys()):
        needle = FUNCTION_TARGETS[tag]          # значение таблицы -- авторитетное имя метода
        cls = tag.rsplit("_", 1)[0] if "_" in tag else ""
        method = needle
        val, strat, conf, name = resolve_function(cls, method, idx, ti)
        if val:
            results[tag] = (val, strat, conf, name)
            resolved[tag] = val
            log("  %-58s 0x%-9x %-10s %s" % (tag, val, strat, name))
        else:
            results[tag] = (None, None, None, None)
            log("  %-58s NOT FOUND" % tag)

    log("")
    log("=== GLOBALS (%d targets) ===" % len(GLOBAL_TARGETS))
    for tag in sorted(GLOBAL_TARGETS.keys()):
        needle = GLOBAL_TARGETS[tag]
        val, strat, conf, name = resolve_global(tag, needle, idx, ti)
        if val:
            results[tag] = (val, strat, conf, name)
            resolved[tag] = val
            log("  %-58s 0x%-9x %-10s %s" % (tag, val, strat, name))
        else:
            results[tag] = (None, None, None, None)
            log("  %-58s NOT FOUND" % tag)

    found_n = len([1 for v in results.values() if v[0]])
    total_n = len(FUNCTION_TARGETS) + len(GLOBAL_TARGETS)
    log("")
    log("=== SUMMARY: %d / %d ===" % (found_n, total_n))

    # ---- offsets_resolved.js
    with open(OUT, "w") as fh:
        fh.write("// auto-generated by find_offsets_ios.py (Mach-O arm64)\n")
        fh.write("// imageBase=0x%x  program=%s\n" % (G["BASE"], currentProgram.getName()))
        fh.write("export const offsets = Object.freeze({\n")
        for k in sorted(results.keys()):
            v = results[k]
            if v[0]:
                fh.write("  %s: 0x%x, // %s %s [%s]\n" % (k, v[0], v[1], v[3] or "", v[2]))
        fh.write("\n  // --- NOT FOUND ---\n")
        for k in sorted(results.keys()):
            if not results[k][0]:
                fh.write("  // %s: NOT FOUND\n" % k)
        fh.write("});\n")

    # ---- отчёт + vtable slot map
    vt_rel = {}
    for tag in GLOBAL_TARGETS:
        if tag.startswith("VTABLE_") and results.get(tag) and results[tag][0]:
            vt_rel[tag] = results[tag][0]

    with open(REPORT, "w") as fh:
        fh.write("# find_offsets_ios report\n")
        fh.write("# imageBase = 0x%x\n" % G["BASE"])
        fh.write("# program   = %s\n" % currentProgram.getName())
        fh.write("# found     = %d / %d\n\n" % (found_n, total_n))
        for k in sorted(results.keys()):
            v = results[k]
            if v[0]:
                fh.write("%s = 0x%x  # %s %s conf=%s\n" % (k, v[0], v[1], v[3] or "", v[2]))
            else:
                fh.write("%s = NOT_FOUND\n" % k)
        fh.write("\n# === vtable slot map ===\n")
        try:
            for line in vtable_slot_map(vt_rel, resolved):
                fh.write(line + "\n")
        except Exception as e:
            fh.write("# slot map failed: %s\n" % e)
        fh.write("\n# S0=symbol S1=string S2=objc S3=ptr S4=slot S5=vtable\n")
        fh.write("# conf=high -> symвол/точное совпадение; med -> xref/objc/vtable; low -> эвристика\n")

    log("[+] wrote %s" % OUT)
    log("[+] wrote %s" % REPORT)


try:
    main()
except SystemExit:
    raise
except Exception as e:
    log("FATAL: %s" % e)
    traceback.print_exc()
