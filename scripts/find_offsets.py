# -*- coding: utf-8 -*-
# @runtime Jython
#
# find.py  --  Ghidra headless / Jython 2.7 + встроенный self-test   (v2)
# Порт Android-скрипта (ELF libg.so, BASE=0x100000000) на iOS (Mach-O arm64 / arm64e).
# ОДИН ФАЙЛ, ДВА РЕЖИМА:
#   * в Ghidra (analyzeHeadless ... -postScript find.py) -- резолвит оффсеты;
#   * без Ghidra (python3 find.py [outdir]) -- встроенный self-test: синтетический
#     Mach-O + 32 проверки (все стратегии живы, ошибки реального лога E1..E5 отброшены).
#
# ЧТО ИЗМЕНИЛОСЬ В v2 (по результатам реального прогона: "SUMMARY: 30 / 196")
#   Прогон показал три класса ошибок, из-за которых результат был почти бесполезен:
#     1) S0:symbol отдавал АДРЕСА СТРОК как "глобальные переменные":
#          LogicDataTables_tableArray -> s_LogicDataTables::initDataTable_i_100ee0c1f
#          MessageManager_instance    -> s_MessageManager::initialReceiveMe_100ec1ef9
#          Screen_widthGlobal/height  -> _TtC6Sentry18SentryScreenFrames (Swift-метаданные)
#        Причина: наивный substring-матч по имени символа + "первый подходящий побеждает".
#        На Mach-O __TEXT (в т.ч. __cstring и __objc_methname) ИСПОЛНЯЕМ, поэтому
#        проверка "не функция" их не ловила.
#        Фикс: глобал обязан лежать в НЕисполняемом data-блоке (__DATA/__DATA_CONST/__bss),
#        имя проверяется по сегментам (сегментный матч, не substring), отбрасываются
#        рантайм-неймспейсы (s_, _Tt, _$s, _OBJC_, objc_, typeinfo/vftable).
#     2) S1:string доминировал (24/30) и выдавал МУСОР с conf=low: навыки вроде "update",
#        "getName", "getData", "setText", "ctor" есть у сотен классов, а скрипт брал
#        "функцию, которая ссылается на большее число подходящих строк". Отсюда дубли:
#        0x3cc0e4 на 4 тега, 0x54332c на 3, 0xb518c на 2.
#        Фикс: строковый резолв стал сегментным и требует ОДНОЗНАЧНОСТИ:
#          T0/T1 -- квалифицированная строка "Class::method" (именно её оставляют
#                   SC-макросы логирования; в реальном логе такие строки ЕСТЬ:
#                   "LogicDataTables::initDataTable(...)", "MessageManager::...")
#          T2    -- строка, где есть и класс, и метод (оба на границе токенов)
#          bare  -- только если этот needle не используется другими тегами таблицы
#                   И строка равна методу целиком И на неё ссылается ровно одна функция.
#        Любая неоднозначность -> тег НЕ выдаётся как оффсет, а попадает в отчёт
#        в секцию candidates (чтобы не выпускать заведомо неверный хук).
#     3) S2/S3/S4/S5 не сработали НИ РАЗУ, ptr index нашёл всего 45 ссылок.
#        Причина: iOS 15+ Mach-O хранит указатели в data в формате dyld chained fixups
#        (36-битное поле target + high8), поэтому mem.getLong давал не адрес.
#        Фикс: decode_ptr() пробует 4 варианта (обычный ptr, +PAC, BASE+36bit, 36bit),
#        поэтому ptr-индекс снова наполняется; relative method list (int32 rel) в S2
#        читается корректно; S2/S3/S4 снова живые.
#
# СТРАТЕГИИ (пишутся в отчёт вместе с уликой)
#   S0:symbol  таблица функций Ghidra (демангленные C++ / ObjC). Строгий сегментный матч.
#   S1:qual    строка "Class::method" -> содержащая её функция. Основной путь на iOS.
#   S1:bare    строка == имени метода, единственная ссылающаяся функция, needle не shared.
#   S2:objc    селектор из __objc_methname -> method_t -> IMP (iOS15+ int32-relative и
#              классический layout, IMP по +16).
#   S3:ptr     строку адресует data-таблица, рядом (+8/+16/+24/-8) лежит указатель в код
#              (dispatch-таблицы, которые ReferenceManager не разметил).
#   S4:slot    data-адрес из тела Class::getInstance (синглтоны).
#   S5:vtable  vftable класса по символу <Class>::vftable, fallback ptr -> typeinfo (-8).
#   bonus      slot map + автопоиск таблиц кода, в которых встречаются найденные функции.
#
# ГЛАВНОЕ ПРО ЖЕЛЕЗО
#   * BASE берём из getImageBase() (dylib/framework грузится не на 0x100000000).
#     RVA = addr - imageBase -- ровно то, что ждёт scanner.js (moduleBase.add(offsets.X)).
#   * text/data различаем по правам блока (isExecute), а не по имени.
#   * PAC снимаем (& 0x00FFFFFFFFFFFFFF) на каждом читаемом указателе (arm64e).
#
# ЧЕСТНОЕ ОГРАНИЧЕНИЕ
#   В реальном прогоне функции назывались FUN_100xxxxx, C++-символов в таблице нет:
#   бинарь срезан (stripped). Значит S0 почти пуст, а S1:qual работает только для тех
#   классов, чьи строки "Class::method" реально остались в __cstring. Найти ВСЕ 196
#   оффсетов статически по такому файлу нельзя в принципе -- скрипт теперь вместо мусора
#   печатает улики и список кандидатов. Для полного покрытия нужен дамп ПАМЯТИ (Frida):
#   на Arxan-бинарнике имена/таблицы разворачиваются только в рантайме.
#
# ЗАПУСК
#   lipo -thin arm64 "Payload/X.app/<binary>" -output brawl.arm64
#   $GHIDRA/support/analyzeHeadless <projDir> <projName> -import brawl.arm64 \
#       -processor aarch64:LE:64:v8A -postScript find.py
#
# ВЫХОД
#   $GITHUB_WORKSPACE (или cwd) / offsets_resolved.js   -- REvengeBS-формат
#   $GITHUB_WORKSPACE (или cwd) / offsets_report.txt    -- улики + кандидаты

import os
import re
import struct   # нужен встроенному self-test (Mem.getInt/getLong)
import sys
import time
import traceback

WS = os.environ.get("GITHUB_WORKSPACE") or os.getcwd()
OUT = os.path.join(WS, "offsets_resolved.js")
REPORT = os.path.join(WS, "offsets_report.txt")
BUDGET = 1800
START = time.time()

# Состояние образа (Jython: без module-level global-хаков).
G = {"BASE": 0, "TEXT": [], "DATA": [], "PTR": {}, "SADDR": {}, "TI": {}, "FN_TOK": {}}

PTR_MASK = 0x00FFFFFFFFFFFFFF      # снятие PAC (arm64e)
CHAIN_MASK = 0xFFFFFFFFF           # 36-битное поле target в dyld chained fixups

MAX_STR_CAND = 12                  # сколько строк-кандидатов разбираем на один тег
MAX_AMB_SHOW = 4                   # сколько кандидатов печатаем в отчёт на тег
REL_SCAN_MAX = 6 * 1024 * 1024     # лимит размера блока для int32-relative скана
PTR_SCAN_MAX = 12 * 1024 * 1024    # лимит размера блока для ptr-скана
FUNC_TABLE_BUDGET = 120            # сек на автопоиск таблиц кода

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

# неймспейсы, в которых живут НЕ наши объекты (строковые лейблы Ghidra, Swift-метаданные,
# ObjC-рантайм, RTTI). Именно из-за них LogicDataTables_tableArray "находился" по строке.
BAD_PREFIX = ("s_", "s__", "_t", "_$s", "_objc_", "objc_", "___", "class_", "label_",
              "string_", "sub_", "thunk_", "fun_", "ordinal")
BAD_INFIX = ("::typeinfo", "::vftable", "::vtable", "typeinfo for ", "vtable for ")


def log(m):
    sys.stdout.write("%s\n" % m)
    sys.stdout.flush()


def off(a):
    """Address -> long."""
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


def in_data(a):
    """НЕисполняемый проинициализированный блок. На Mach-O __cstring/__objc_methname
    лежат внутри __TEXT и потому исполняемы -- это и был источник ложных "глобалов"."""
    b = blk_of(a)
    if b is None or blk_exec(b):
        return False
    try:
        return bool(b.isInitialized())
    except:
        return True


def blk_span(b):
    try:
        return off(b.getStart()), off(b.getEnd())
    except:
        return 0, 0


def is_code_addr(a):
    try:
        return getFunctionAt(a) is not None or getFunctionContaining(a) is not None
    except:
        return False


def fname(f):
    try:
        return f.getName() or ""
    except:
        return ""


def fentry_rva(f):
    """RVA функции, если она реально в исполняемой памяти, иначе -1."""
    try:
        ep = f.getEntryPoint()
    except:
        return -1
    r = rva(ep)
    if r <= 0 or not in_text(ep):
        return -1
    return r


def tokens_of(s):
    """'LogicCharacterData::getSpeed' -> {LogicCharacterData, getSpeed, Logic, ...}"""
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


def has_tok(s, w):
    """w входит в s на границе слова (регистр игнорируется).

    Строгая правая граница: 'update' НЕ матчит 'updateHealthBar' (иначе именно так
    и рождались ложные попадания). Склеенное 'initialReceiveMessage' тоже не матчит
    'receiveMessage' -- это разные методы, и молча резолвить в него нельзя."""
    if not s or not w:
        return False
    ls = s.lower()
    lw = w.lower()
    if not lw:
        return False
    i = ls.find(lw)
    while i >= 0:
        j = i + len(lw)
        left_ok = (i == 0) or (not s[i - 1].isalnum())
        right_ok = (j >= len(s)) or (not s[j].isalnum())
        if left_ok and right_ok:
            return True
        i = ls.find(lw, i + 1)
    return False


def bad_name(n):
    """Имя символа из чужого неймспейса."""
    if not n:
        return True
    ln = n.lower()
    for p in BAD_PREFIX:
        if ln.startswith(p):
            return True
    for p in BAD_INFIX:
        if p in ln:
            return True
    if ln in ("", "_"):
        return True
    return False


def decode_ptr(v):
    """Варианты расшифровки 8-байтного слова из data.

    iOS 15+ Mach-O хранит указатели как dyld chained fixups: target -- 36 бит, либо
    абсолютный vmaddr, либо смещение от imageBase (DYLD_CHAINED_PTR_64_OFFSET),
    плюс high8 в битах 36..43. Раньше скрипт читал голый long и терял почти всё
    (ptr index = 45 ссылок)."""
    if not v:
        return ()
    out = [v & PTR_MASK]
    out.append(v & CHAIN_MASK)
    out.append(G["BASE"] + (v & CHAIN_MASK))
    h8 = (v >> 56) & 0xFF
    if h8:
        out.append((h8 << 56) | (v & CHAIN_MASK))
    return tuple(out)


# --------------------------------------------------------------------------- #
# инициализация образа
# --------------------------------------------------------------------------- #

def init_image():
    p = currentProgram
    G["BASE"] = p.getImageBase().getOffset()
    for b in p.getMemory().getBlocks():
        try:
            if not b.isInitialized():
                continue
        except:
            continue
        (G["TEXT"] if blk_exec(b) else G["DATA"]).append(b)
    log("[*] blocks: text=%d data=%d" % (len(G["TEXT"]), len(G["DATA"])))


# --------------------------------------------------------------------------- #
# индексы: строки, токены строк, токены имён функций
# --------------------------------------------------------------------------- #

def build_index():
    listing = currentProgram.getListing()
    idx = {}
    saddr = {}
    ti = {}
    total = 0
    it = listing.getDefinedData(True)
    while it.hasNext():
        if out_of_time(500):
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
            if not s or len(s) > 4096:
                continue
            total += 1
            o = off(d.getAddress())
            saddr[o] = s
            idx.setdefault(s, []).append(o)
            for t in tokens_of(s):
                lst = ti.get(t.lower())
                if lst is None:
                    ti[t.lower()] = [o]
                else:
                    lst.append(o)
        except:
            continue
    G["SADDR"] = saddr
    G["TI"] = ti
    log("[*] strings: %d unique: %d tokens: %d" % (total, len(idx), len(ti)))
    return idx


def define_cstrings():
    """Fallback: ASCII Strings analyzer не отработал -- создаём строки вручную."""
    mem = currentProgram.getMemory()
    made = 0
    for b in mem.getBlocks():
        if out_of_time(700):
            break
        try:
            n = (b.getName() or "").lower()
        except:
            continue
        if ("cstring" not in n) and ("methname" not in n) and ("str" not in n):
            continue
        a, end = blk_span(b)
        if a <= 0:
            continue
        while a < end:
            if out_of_time(700):
                break
            try:
                if mem.getByte(toAddr(a)) == 0:
                    a += 1
                    continue
            except:
                break
            try:
                d = createAsciiString(toAddr(a))
                if d is not None:
                    made += 1
                    a = off(d.getAddress()) + d.getLength()
                    continue
            except:
                pass
            a += 1
    return made


def build_func_index():
    """Индекс имён функций по токенам. Раньше S0 перебирал ВСЕ функции для КАЖДОГО тега
    и брал первый substring-матч -- отсюда String_ctor = "base64String...:" .
    Сейчас: FUN_/sub_/thunk_ имена не индексируются (они не несут информации),
    а матч строго сегментный."""
    toks = {}
    n = 0
    skipped = 0
    try:
        it = currentProgram.getFunctionManager().getFunctions(True)
    except:
        return
    while it.hasNext():
        if out_of_time(500):
            break
        try:
            f = it.next()
            nm = fname(f)
            ep = off(f.getEntryPoint())
        except:
            continue
        if not nm:
            continue
        if nm.startswith("FUN_") or nm.startswith("sub_") or nm.startswith("thunk_") or nm.startswith("LAB_"):
            skipped += 1
            continue
        if bad_name(nm):
            skipped += 1
            continue
        n += 1
        for t in tokens_of(nm):
            lst = toks.get(t.lower())
            if lst is None:
                toks[t.lower()] = [(nm, ep)]
            else:
                lst.append((nm, ep))
    G["FN_TOK"] = toks
    log("[*] named functions: %d (unnamed/skipped %d, tokens %d)" % (n, skipped, len(toks)))


def tok_offsets(w):
    if not w:
        return []
    return G["TI"].get(w.lower()) or []


def strings_with_all(words):
    """Оффсеты строк, содержащих ВСЕ слова (на границах токенов). С мемоизацией:
    на 196 тегов одни и те же запросы ('update', 'getName') повторяются многократно."""
    key = "|".join([w.lower() for w in words])
    cache = G.get("SCACHE")
    if cache is None:
        cache = {}
        G["SCACHE"] = cache
    if key in cache:
        return cache[key]
    lists = []
    for w in words:
        l = tok_offsets(w)
        if not l:
            return []
        lists.append(l)
    lists.sort(key=len)
    small = lists[0]
    big = set(lists[1]) if len(lists) > 1 else None
    for l in lists[2:]:
        big &= set(l)
    out = []
    for o in small:
        if big is not None and o not in big:
            continue
        s = G["SADDR"].get(o)
        if not s:
            continue
        ok = True
        for w in words:
            if not has_tok(s, w):
                ok = False
                break
        if ok:
            out.append(o)
    out.sort()
    cache[key] = out
    return out


def build_ptr_index(targets):
    """Проход по data-блокам: где лежат ссылки на интересующие нас адреса.

    Учитываются все 4 варианта расшифровки (см. decode_ptr), иначе данные iOS 15+
    с chained fixups не читаются вообще."""
    if not targets:
        return {}
    tset = set(targets)
    hit = {}
    mem = currentProgram.getMemory()
    scanned = 0
    for b in G["DATA"]:
        if out_of_time(420):
            log("[!] ptr scan: budget cutoff (%d blocks scanned)" % scanned)
            break
        a0, a1 = blk_span(b)
        if a0 <= 0 or a0 >= a1:
            continue
        if (a1 - a0) > PTR_SCAN_MAX:
            continue
        scanned += 1
        p = a0 & ~7
        while p < a1:
            try:
                v = mem.getLong(toAddr(p))
            except:
                p += 8
                continue
            if v:
                for cand in decode_ptr(v):
                    if cand in tset:
                        lst = hit.get(cand)
                        if lst is None:
                            hit[cand] = [p]
                        else:
                            lst.append(p)
                        break
            p += 8
    log("[*] ptr index: %d интересных адресов найдено в data (%d блоков)" % (len(hit), scanned))
    return hit


def rel_target_index():
    """{адрес_цели: адрес_поля} для 32-битных ссылок "адрес = поле + int32(поле)".

    Так устроены relative method list в ObjC (iOS 15+): name/types/imp -- int32
    относительно собственного адреса. Строим лениво и только по const/objc-блокам."""
    cached = G.get("RELIDX")
    if cached is not None:
        return cached
    mem = currentProgram.getMemory()
    m = {}
    for b in G["DATA"]:
        n = ""
        try:
            n = (b.getName() or "").lower()
        except:
            pass
        if ("const" not in n) and ("objc" not in n):
            continue
        a0, a1 = blk_span(b)
        if a0 <= 0 or a0 >= a1 or (a1 - a0) > REL_SCAN_MAX:
            continue
        p = a0 & ~3
        while p < a1:
            if out_of_time(700):
                break
            try:
                v = mem.getInt(toAddr(p))
            except:
                p += 4
                continue
            t = p + v
            if t > 0:
                m[t] = p
            p += 4
    G["RELIDX"] = m
    return m


# --------------------------------------------------------------------------- #
# xrefs
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
    for o in G["PTR"].get(off(a), []):
        if o in seen:
            continue
        seen.add(o)
        out.append(toAddr(o))
    return out


def funcs_ref_by_str(o):
    """{rva: имя} функций, которые ссылаются на строку с адресом-смещением o."""
    res = {}
    for ra in all_refs(toAddr(o)):
        f = getFunctionContaining(ra)
        if f is None:
            continue
        fr = fentry_rva(f)
        if fr <= 0:
            continue
        res[fr] = fname(f)
    return res


def func_data_refs(f):
    """Адреса данных, на которые ссылается тело функции (adrp/add и т.п.)."""
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
            continue
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
            if blk_of(to) is None:
                continue
            o = off(to)
            res[o] = res.get(o, 0) + 1
    return res


# --------------------------------------------------------------------------- #
# стратегии: функции
# --------------------------------------------------------------------------- #

AMBI = []          # (tag, kind, [(rva, tier, string), ...]) -- для секции candidates


def ambiguous(tag, kind, cands):
    AMBI.append((tag, kind, list(cands)))


def score_func_name(name, cls, method):
    """Строгий сегментный матч. Раньше здесь был 'needle.lower() in name.lower()',
    из-за чего String_ctor получал base64StringWithExceptionDescription:."""
    if not name or not method:
        return None
    lo = name.lower()
    m = method.lower()
    if bad_name(name):
        return None
    if cls:
        c = cls.lower()
        if lo.startswith(c + "::" + m):
            return 0
        if ("::" + c + "::" + m) in lo:
            return 1
        if lo.startswith("_[" + c + " ") or lo.startswith("-[" + c + " ") or lo.startswith("+[" + c + " "):
            return 0
        return None
    if lo == m:
        return 0
    if lo.endswith("::" + m):
        return 1
    if lo.startswith(m + "("):
        return 2
    if ("::" + m + "(") in lo:
        return 3
    return None


def func_via_symbol(cls, method):
    """S0: имя функции из таблицы символов Ghidra (демангленный C++ / ObjC)."""
    toks = G.get("FN_TOK") or {}
    if not toks:
        return None
    if cls:
        cand = toks.get(cls.lower()) or []
    else:
        cand = toks.get(method.lower()) or []
    best = None
    bs = 999
    for nm, ep in cand:
        sc = score_func_name(nm, cls, method)
        if sc is None or sc >= bs:
            continue
        a = toAddr(ep)
        r = rva(a)
        if r <= 0 or not in_text(a):
            continue
        bs = sc
        best = (r, nm)
        if sc == 0:
            break
    return best


def qual_tier(s, cls, m2):
    l = s.lower()
    a = l.find(cls.lower() + "::" + m2.lower())
    if a >= 0:
        return 0 if a == 0 else 1
    a = l.find(cls.lower() + "." + m2.lower())
    if a >= 0:
        return 0 if a == 0 else 1
    return 2


def bare_tier(s, method):
    n = s.strip().strip(":").strip()
    if n.lower() == method.lower():
        return 0
    if n.lower().endswith("::" + method.lower()):
        return 1
    if has_tok(s, method):
        return 2
    return None


def pick_string_funcs(pairs, tier_of):
    """pairs:[(off, str)] -> ((rva, tier, s, fname, nfuncs), amb_list).

    Обязательное условие приёма: на выбранной строке (tier) висит РОВНО одна функция
    (или у лидера строго лучший tier). Иначе тег не выдаём -- именно так рождались
    'update' -> 0x3cc0e4 для четырёх разных классов."""
    tiers = {}
    for o, s in pairs:
        t = tier_of(s)
        if t is None:
            continue
        for fr, nm in funcs_ref_by_str(o).items():
            cur = tiers.get(fr)
            if cur is None or t < cur[0]:
                tiers[fr] = (t, s, nm)
    if not tiers:
        return None, []
    items = sorted(list(tiers.items()), key=lambda kv: (kv[1][0], kv[0]))
    amb = [(fr, e[0], e[1]) for fr, e in items[:MAX_AMB_SHOW]]
    if len(items) > 1 and items[1][1][0] <= items[0][1][0]:
        return None, amb
    fr, e = items[0]
    return (fr, e[0], e[1], e[2], len(items)), amb


def funcs_via_objc(offsets):
    """S2: селектор __objc_methname -> method_t -> IMP.

    Relative method list (iOS 15+): name@+0, types@+4, imp@+8 (int32 относительно
    собственного адреса). Классический layout: sel@+0, types@+8, imp@+16 (int64).
    Базой считается адрес поля name (его ищем по ptr-индексу или по int32-rel ссылке)."""
    mem = currentProgram.getMemory()
    relidx = None
    for o in offsets[:6]:
        bases = []
        for x in G["PTR"].get(o, []):
            bases.append(x)
        for ra in refs_via_manager(toAddr(o)):
            bases.append(off(ra))
        try:
            if relidx is None:
                relidx = rel_target_index()
            p = relidx.get(o)
            if p is not None:
                bases.append(p)
        except:
            pass
        for base in bases:
            ba = toAddr(base)
            if not in_data(ba):
                continue
            for fo in (8, 16):
                try:
                    ia = base + fo
                    v = mem.getInt(toAddr(ia))
                except:
                    continue
                if v == 0:
                    continue
                ta = toAddr(ia + v)
                if ta is None or not in_text(ta):
                    continue
                f = getFunctionContaining(ta)
                if f is None:
                    continue
                fr = fentry_rva(f)
                if fr > 0:
                    return (fr, fname(f), "rel+%d" % fo)
            try:
                v = mem.getLong(toAddr(base + 16)) & PTR_MASK
            except:
                v = 0
            if v:
                ta = toAddr(v)
                if ta is not None and in_text(ta):
                    f = getFunctionContaining(ta)
                    if f is not None:
                        fr = fentry_rva(f)
                        if fr > 0:
                            return (fr, fname(f), "classic")
    return None


def funcs_via_neighbors(offsets):
    """S3: строку адресует data-таблица, рядом (+8/+16/+24/-8) -- указатель в код.
    Ловит dispatch-таблицы, на которые ReferenceManager не сделал ссылку."""
    mem = currentProgram.getMemory()
    for o in offsets[:MAX_STR_CAND]:
        for w in G["PTR"].get(o, [])[:8]:
            for delta in (8, 16, 24, -8):
                try:
                    v = mem.getLong(toAddr(w + delta)) & PTR_MASK
                except:
                    continue
                if not v:
                    continue
                ta = toAddr(v)
                if ta is None or not in_text(ta):
                    continue
                f = getFunctionContaining(ta)
                if f is None:
                    continue
                fr = fentry_rva(f)
                if fr > 0:
                    return (fr, fname(f), "tab+%d" % delta)
    return None


def objc_selector_offsets(method):
    out = []
    for o in strings_with_all([method])[:MAX_STR_CAND]:
        if "methname" not in blk_name(toAddr(o)).lower():
            continue
        s = G["SADDR"].get(o) or ""
        if bare_tier(s, method) == 0:
            out.append(o)
    return out


def paired(offsets):
    out = []
    for o in offsets:
        s = G["SADDR"].get(o)
        if s:
            out.append((o, s))
    return out


def resolve_function(tag, cls, method, is_ctor, shared):
    m2 = cls if (is_ctor and cls) else method
    sym_m = cls if is_ctor else method
    all_c = []
    amb_seen = False

    # ---- S0: символ функции
    r = func_via_symbol(cls, sym_m)
    if r:
        return (r[0], "S0:symbol", "high", r[1])
    if not cls:
        r = func_via_symbol("", method)
        if r:
            return (r[0], "S0:symbol", "med", r[1])

    # ---- S1:qualified: строка "Class::method" (SC-макрос логирования)
    if cls:
        offs = strings_with_all([cls, m2])[:MAX_STR_CAND]
        all_c.extend(offs)
        best, amb = pick_string_funcs(paired(offs), lambda s: qual_tier(s, cls, m2))
        if best:
            conf = "high" if best[1] == 0 else "med"
            return (best[0], "S1:qual", conf, "'%s' refs=%d %s" % (best[2], best[4], best[3]))
        if amb:
            ambiguous(tag, "qual: '%s::%s'" % (cls, m2), amb)
            amb_seen = True

    # ---- S2: ObjC-селектор -> IMP
    sel = objc_selector_offsets(method)
    if sel:
        all_c.extend(sel)
        r = funcs_via_objc(sel)
        if r:
            return (r[0], "S2:objc", "med", "%s (%s)" % (r[1], r[2]))

    # ---- S1:bare: строка ровно равна методу, единственная ссылающаяся функция.
    if (not shared) and (not is_ctor):
        offs = [o for o in strings_with_all([method])[:MAX_STR_CAND] if bare_tier(G["SADDR"].get(o) or "", method) is not None]
        all_c.extend(offs)
        best, amb = pick_string_funcs(paired(offs), lambda s: bare_tier(s, method))
        if best:
            conf = "med" if best[1] <= 1 else "low"
            return (best[0], "S1:bare", conf, "'%s' refs=%d %s" % (best[2], best[4], best[3]))
        if amb:
            ambiguous(tag, "bare: '%s'" % method, amb)
            amb_seen = True
    elif shared and not is_ctor:
        offs = [o for o in strings_with_all([method])[:MAX_STR_CAND] if bare_tier(G["SADDR"].get(o) or "", method) == 0]
        if offs:
            ambiguous(tag, "shared needle '%s' (нет квалифицированной строки)" % method,
                      [(fr, 0, G["SADDR"].get(o) or "") for o in offs for fr in funcs_ref_by_str(o).keys()][:MAX_AMB_SHOW])
            amb_seen = True
            all_c.extend(offs)

    # ---- S3: ptr-таблица
    if all_c:
        r = funcs_via_neighbors(all_c)
        if r:
            return (r[0], "S3:ptr", "low", "%s (%s)" % (r[1], r[2]))

    # почему не нашли -- это идёт в отчёт
    if amb_seen:
        return (None, None, None, "неоднозначно: кандидаты в секции candidates")
    if not all_c:
        if m2 == method:
            return (None, None, None, "в бинаре нет строки '%s'" % method)
        return (None, None, None, "в бинаре нет ни строки '%s', ни '%s'" % (method, m2))
    return (None, None, None, "строки есть (%d), но ссылок из кода/таблиц нет" % len(all_c))


# --------------------------------------------------------------------------- #
# стратегии: данные
# --------------------------------------------------------------------------- #

def score_data_name(name, needle):
    n = name.lstrip("_")
    ln = n.lower()
    nu = needle.lower()
    if ln == nu:
        return 0
    if ln.startswith(nu + "_") or ln.startswith(nu + "::"):
        return 1
    if ln.endswith("_" + nu) or ln.endswith("::" + nu):
        return 2
    if has_tok(n, needle):
        return 3
    return None


def data_via_symbol(needle):
    """S0: символ данных. Обязательно НЕисполняемый data-блок -- иначе строковые
    лейблы Ghidra (s_...) снова уедут в результат как 'глобалы'."""
    try:
        it = currentProgram.getSymbolTable().getAllSymbols(True)
    except:
        return None
    best = None
    bs = 999
    while it.hasNext():
        if out_of_time(600):
            break
        try:
            s = it.next()
            n = s.getName()
            a = s.getAddress()
        except:
            continue
        if not n or a is None:
            continue
        if bad_name(n):
            continue
        if not in_data(a):
            continue
        if is_code_addr(a):
            continue
        sc = score_data_name(n, needle)
        if sc is None or sc >= bs:
            continue
        bs = sc
        best = (rva(a), n)
        if sc == 0:
            break
    return best


def global_via_string(needle):
    """S1 для глобалов: строка ровно равна имени класса, ссылка из data, единственная."""
    cands = []
    for o in strings_with_all([needle])[:MAX_STR_CAND]:
        s = G["SADDR"].get(o) or ""
        if s.strip().strip(":").strip().lower() == needle.lower():
            cands.append((o, s))
    if not cands:
        return None
    found = {}
    for o, s in cands:
        for ra in all_refs(toAddr(o)):
            if not in_data(ra):
                continue
            if off(ra) % 8:
                continue
            found[off(ra)] = s
    if len(found) != 1:
        return None
    o = sorted(found.keys())[0]
    return (o - G["BASE"], "str='%s'" % found[o])


def global_via_func_data(cls):
    """S4: data-адрес из тела Class::getInstance (синглтон)."""
    f = None
    r = func_via_symbol(cls, "getInstance")
    if r:
        f = getFunctionAt(toAddr(r[0] + G["BASE"]))
    if f is None:
        offs = strings_with_all([cls, "getInstance"])[:MAX_STR_CAND]
        best, amb = pick_string_funcs(paired(offs), lambda s: qual_tier(s, cls, "getInstance"))
        if best:
            f = getFunctionAt(toAddr(best[0] + G["BASE"]))
    if f is None:
        return None
    cands = func_data_refs(f)
    if not cands:
        return None
    items = sorted(list(cands.items()), key=lambda kv: -kv[1])
    o = items[0][0]
    return (o - G["BASE"], "refs=%d" % len(cands))


def vtable_for_class(cls):
    """S5: vftable класса. Символ <Class>::vftable (в data), иначе указатель на
    <Class>::typeinfo, тогда vtable = ptr - 8 (Itanium ABI)."""
    try:
        it = currentProgram.getSymbolTable().getAllSymbols(True)
    except:
        return None
    lcls = cls.lower()
    typeinfo = None
    while it.hasNext():
        if out_of_time(600):
            break
        try:
            s = it.next()
            n = s.getName()
            a = s.getAddress()
        except:
            continue
        if not n or a is None:
            continue
        ln = n.lower()
        if lcls not in ln:
            continue
        if not in_data(a) or is_code_addr(a):
            continue
        if "vftable" in ln or "vtable" in ln or "ztv" in ln:
            return (rva(a), "sym:" + n)
        if "typeinfo" in ln or "zti" in ln:
            typeinfo = a
    if typeinfo is None:
        return None
    mem = currentProgram.getMemory()
    want = off(typeinfo)
    for b in G["DATA"]:
        a0, a1 = blk_span(b)
        if a0 <= 0 or a0 >= a1 or (a1 - a0) > PTR_SCAN_MAX:
            continue
        p = a0 & ~7
        while p < a1:
            if out_of_time(500):
                break
            try:
                if (mem.getLong(toAddr(p)) & PTR_MASK) == want:
                    return (p - 8 - G["BASE"], "rtti-8")
            except:
                pass
            p += 8
    return None


def resolve_global(tag, needle):
    if tag.startswith("VTABLE_"):
        r = vtable_for_class(needle)
        if r:
            return (r[0], "S5:vtable", "med", r[1])
        return (None, None, None, "нет символа <Class>::vftable/typeinfo")

    r = data_via_symbol(needle)
    if r:
        return (r[0], "S0:symbol", "high", r[1])

    r = global_via_func_data(needle)
    if r:
        return (r[0], "S4:slot", "med", r[1])

    r = global_via_string(needle)
    if r:
        return (r[0], "S1:string", "low", r[1])

    return (None, None, None, "нет символа/слота для '%s'" % needle)


# --------------------------------------------------------------------------- #
# бонусы: slot map и автопоиск таблиц кода
# --------------------------------------------------------------------------- #

def vtable_slot_map(rel, resolved):
    """Для найденных vtable печатаем слоты, указывающие на уже найденные функции."""
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
            if not v:
                continue
            ta = toAddr(v)
            if ta is None or not in_text(ta):
                continue
            f = getFunctionContaining(ta)
            if f is None:
                continue
            names = by_rva.get(fentry_rva(f))
            if names:
                hit.append("    slot[%3d] = %s  (0x%x)" % (i, ",".join(names), v))
        lines.append("  %s @ 0x%x" % (tag, base))
        lines.extend(hit or ["    (слотов с найденными функциями нет)"])
    return lines


def discover_code_tables(resolved_rvas):
    """Автопоиск таблиц, целиком состоящих из указателей в код, в которых встречаются
    уже найденные функции. Печатаем базу + слот + сколько НЕнайденных соседей рядом
    (это и есть 'добор' соседних методов класса -- их потом можно проверить вручную)."""
    if not resolved_rvas:
        return ["# (нет найденных функций)"]
    tset = {}
    for tag, r in resolved_rvas.items():
        tset[G["BASE"] + r] = tag
    mem = currentProgram.getMemory()
    lines = []
    deadline = time.time() + FUNC_TABLE_BUDGET
    truncated = False
    for b in G["DATA"]:
        if time.time() > deadline or out_of_time(200):
            truncated = True
            break
        a0, a1 = blk_span(b)
        if a0 <= 0 or a0 >= a1 or (a1 - a0) > PTR_SCAN_MAX:
            continue
        p = a0 & ~7
        while p < a1:
            try:
                v = mem.getLong(toAddr(p)) & PTR_MASK
            except:
                p += 8
                continue
            tag = tset.get(v)
            if tag is not None:
                nb = []
                for k in (1, 2, 3, -1, -2):
                    try:
                        w2 = mem.getLong(toAddr(p + 8 * k)) & PTR_MASK
                    except:
                        continue
                    if w2 and in_text(toAddr(w2)):
                        nb.append((k, w2))
                if len(nb) >= 2:
                    base = p
                    slot = 0
                    step = -8
                    while True:
                        try:
                            w2 = mem.getLong(toAddr(base + step)) & PTR_MASK
                        except:
                            break
                        if not (w2 and in_text(toAddr(w2))):
                            break
                        base = base + step
                    slot = (p - base) / 8
                    extra = []
                    for k, w2 in nb:
                        if w2 not in tset:
                            extra.append("0x%x" % (w2 - G["BASE"]))
                    lines.append("  table 0x%x slot %d -> %s%s" % (
                        base - G["BASE"], slot, tag,
                        ("   (+соседи: %s)" % ",".join(extra[:4])) if extra else ""))
            p += 8
    if truncated:
        lines.append("# [!] автопоиск таблиц прерван по времени -- список неполный")
    return lines[:400]


# --------------------------------------------------------------------------- #
# main
# --------------------------------------------------------------------------- #

STRAT_ORDER = ("S0:symbol", "S1:qual", "S1:bare", "S2:objc", "S3:ptr", "S4:slot", "S5:vtable", "S1:string")
CONF_RANK = {"high": 0, "med": 1, "low": 2}


def shared_needles():
    c = {}
    for v in FUNCTION_TARGETS.values():
        c[v] = c.get(v, 0) + 1
    return c


def collect_candidate_strings(shared):
    """Адреса строк, интересных для ptr-индекса (нужен для S2/S3)."""
    seen = set()
    out = []
    for tag in sorted(FUNCTION_TARGETS.keys()):
        cls = tag.rsplit("_", 1)[0] if "_" in tag else ""
        method = FUNCTION_TARGETS[tag]
        is_ctor = tag.endswith("_ctor")
        m2 = cls if (is_ctor and cls) else method
        offs = []
        if cls:
            offs.extend(strings_with_all([cls, m2])[:MAX_STR_CAND])
        offs.extend(strings_with_all([method])[:MAX_STR_CAND])
        for o in offs:
            if o not in seen:
                seen.add(o)
                out.append(o)
    for tag in sorted(GLOBAL_TARGETS.keys()):
        for o in strings_with_all([GLOBAL_TARGETS[tag]])[:MAX_STR_CAND]:
            if o not in seen:
                seen.add(o)
                out.append(o)
    log("[*] интересных строк: %d" % len(out))
    return out


def dedup(results):
    """Один адрес не может быть ответом для двух разных тегов: это гарантированная
    ошибка (в прогоне 0x3cc0e4 стоял у 4 тегов). Оставляем самого уверенного,
    остальных помечаем DUP -- такие оффсеты в offsets.js не попадают."""
    by_addr = {}
    for tag in results:
        v = results[tag]
        if v[0]:
            by_addr.setdefault(v[0], []).append(tag)
    dups = {}
    for a, tags in by_addr.items():
        if len(tags) < 2:
            continue
        if len(tags) >= 3:
            # общий адрес у трёх и более тегов -- это не метод, а общий хелпер
            # (логгер/фабрика/dispatch): снимаем ВСЕ, иначе рискуем выпустить мусор.
            dups[a] = tags
            for t in tags:
                old = results[t]
                results[t] = (None, None, None,
                              "AMBIG: 0x%x делят %d тегов (общий хелпер, было %s)" % (a, len(tags), old[1]))
                ambiguous(t, "общий адрес 0x%x у %d тегов" % (a, len(tags)), [])
            continue
        tags.sort(key=lambda t: (CONF_RANK.get(results[t][2], 3),
                                 0 if results[t][1] == "S0:symbol" else 1, t))
        keep = tags[0]
        dups[keep] = tags[1:]
        for t in tags[1:]:
            old = results[t]
            results[t] = (None, None, None, "DUP: 0x%x занят %s (%s)" % (a, keep, old[1]))
    return dups


def main():
    log("=== find.py v2 (Mach-O / arm64) ===")
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
        log("[*] created strings: %d" % define_cstrings())
        idx = build_index()
    if not idx:
        log("[!] строк нет вообще: бинарь, вероятно, зашифрован (Arxan) --")
        log("    снимай дамп памяти (Frida) и импортируй в Ghidra дамп, а не файл из IPA")
        return

    build_func_index()
    shared = shared_needles()
    G["PTR"] = build_ptr_index(collect_candidate_strings(shared))

    results = {}

    log("")
    log("=== FUNCTIONS (%d targets) ===" % len(FUNCTION_TARGETS))
    for tag in sorted(FUNCTION_TARGETS.keys()):
        method = FUNCTION_TARGETS[tag]
        cls = tag.rsplit("_", 1)[0] if "_" in tag else ""
        is_ctor = tag.endswith("_ctor")
        shared_hit = shared.get(method, 0) > 1
        val, strat, conf, ev = resolve_function(tag, cls, method, is_ctor, shared_hit)
        results[tag] = (val, strat, conf, ev)
        if val:
            log("  %-58s 0x%-9x %-9s %s" % (tag, val, strat, ev))
        else:
            log("  %-58s NOT FOUND  (%s)" % (tag, ev))

    log("")
    log("=== GLOBALS (%d targets) ===" % len(GLOBAL_TARGETS))
    for tag in sorted(GLOBAL_TARGETS.keys()):
        needle = GLOBAL_TARGETS[tag]
        val, strat, conf, ev = resolve_global(tag, needle)
        results[tag] = (val, strat, conf, ev)
        if val:
            log("  %-58s 0x%-9x %-9s %s" % (tag, val, strat, ev))
        else:
            log("  %-58s NOT FOUND  (%s)" % (tag, ev))

    dups = dedup(results)

    found = [t for t in results if results[t][0]]
    total_n = len(FUNCTION_TARGETS) + len(GLOBAL_TARGETS)
    stats = {}
    for t in found:
        stats[results[t][1]] = stats.get(results[t][1], 0) + 1
    log("")
    log("=== SUMMARY: %d / %d ===" % (len(found), total_n))
    log("[*] по стратегиям: %s" % ", ".join("%s=%d" % (s, stats[s]) for s in STRAT_ORDER if s in stats))
    if dups:
        log("[*] снято как дубли адресов: %d" % sum(len(v) for v in dups.values()))
    conf_hi = len([1 for t in found if results[t][2] == "high"])
    conf_me = len([1 for t in found if results[t][2] == "med"])
    log("[*] доверие: high=%d med=%d low=%d" % (conf_hi, conf_me, len(found) - conf_hi - conf_me))
    named = len(G.get("FN_TOK") or {})
    if named == 0:
        log("[!] в таблице символов НЕТ именованных функций: бинарь stripped.")
        log("    Символьный путь (S0) мёртв, остаются строки 'Class::method' и ObjC-метаданные.")
    if len(found) < total_n / 2:
        log("[!] найдено меньше половины: для полного покрытия нужен дамп ПАМЯТЬЮ")
        log("    (Frida: строки/таблицы Arxan-бинарника живут только в рантайме).")

    # ---- offsets_resolved.js
    with open(OUT, "w") as fh:
        fh.write("// auto-generated by find.py v2 (Mach-O arm64)\n")
        fh.write("// imageBase=0x%x  program=%s\n" % (G["BASE"], currentProgram.getName()))
        fh.write("export const offsets = Object.freeze({\n")
        for k in sorted(found):
            v = results[k]
            fh.write("  %s: 0x%x, // %s %s [%s]\n" % (k, v[0], v[1], v[3] or "", v[2]))
        fh.write("\n  // --- NOT FOUND ---\n")
        for k in sorted(results.keys()):
            if not results[k][0]:
                fh.write("  // %s: NOT FOUND\n" % k)
        fh.write("});\n")

    # ---- report
    vt_rel = {}
    for tag in GLOBAL_TARGETS:
        if tag.startswith("VTABLE_") and results.get(tag) and results[tag][0]:
            vt_rel[tag] = results[tag][0]

    with open(REPORT, "w") as fh:
        fh.write("# find.py report (v2)\n")
        fh.write("# imageBase = 0x%x\n" % G["BASE"])
        fh.write("# program   = %s\n" % currentProgram.getName())
        fh.write("# found     = %d / %d\n" % (len(found), total_n))
        fh.write("# strategies = %s\n" % ", ".join("%s:%d" % (s, stats[s]) for s in STRAT_ORDER if s in stats))
        fh.write("# confidence = high:%d med:%d low:%d\n\n" % (conf_hi, conf_me, len(found) - conf_hi - conf_me))
        for k in sorted(results.keys()):
            v = results[k]
            if v[0]:
                fh.write("%s = 0x%x  # %s %s conf=%s\n" % (k, v[0], v[1], v[3] or "", v[2]))
            else:
                fh.write("%s = NOT_FOUND  # %s\n" % (k, v[3] or ""))
        fh.write("\n# === candidates (не выданы как оффсет: неоднозначно) ===\n")
        if not AMBI:
            fh.write("# (нет)\n")
        for tag, kind, cands in AMBI:
            fh.write("# %s\n#     %s\n" % (tag, kind))
            for fr, tier, s in cands:
                fh.write("#     cand 0x%x tier=%d '%s'\n" % (fr, tier, s))
        fh.write("\n# === vtable slot map ===\n")
        try:
            for line in vtable_slot_map(vt_rel, dict((t, results[t][0]) for t in found)):
                fh.write(line + "\n")
        except Exception as e:
            fh.write("# slot map failed: %s\n" % e)
        fh.write("\n# === таблицы кода (автопоиск по data) ===\n")
        try:
            for line in discover_code_tables(dict((t, results[t][0]) for t in found)):
                fh.write(line + "\n")
        except Exception as e:
            fh.write("# таблицы кода: не удалось (%s)\n" % e)
        fh.write("\n# S0=symbol S1:qual/S1:bare=строка S2=objc S3=ptr S4=slot S5=vtable\n")
        fh.write("# conf=high -> символ/точное совпадение; med -> 'Class::method'/objc/vtable; low -> эвристика\n")
        fh.write("# ВАЖНО: оффсет = RVA от imageBase; scanner.js делает moduleBase.add(offsets.X)\n")

    log("[+] wrote %s" % OUT)
    log("[+] wrote %s" % REPORT)
    log("[*] elapsed: %.1f s" % (time.time() - START))


# --------------------------------------------------------------------------- #
# ВСТРОЕННЫЙ SELF-TEST
#   Заглушка Ghidra API + синтетический Mach-O. Воспроизводит 4 ошибки реального
#   прогона (30/196), которые v2 обязан отбросить:
#     E1 строковый лейбл Ghidra (s_LogicDataTables::..., s_stage_*, вне data) и
#        Swift-символ (_TtC6Sentry18SentryScreenFrames) не становятся глобалами;
#     E2 shared needle ('update' у 4 тегов) не резолвится в одну общую функцию;
#     E3 String_ctor не находится по чужому ObjC-селектору (base64String...);
#     E4 один адрес не может быть ответом двух тегов (DUP снимается);
#     E5 один адрес у >=3 тегов = общий хелпер -> снимаются все.
# --------------------------------------------------------------------------- #

def self_test(outdir=None):
    """Возвращает число проваленных проверок (0 = всё хорошо)."""
    BASE = 0x100000000

    # ------------------------------------------------------------------ layout
    R_GETSPEED_STR = 0x1000             # "__TEXT"              (строка вне ObjC)
    R_SETCP_STR = 0x1800                # "__TEXT"
    R_SKILLTIME_STR = 0x2000            # "__TEXT"              (аналог __cstring)
    R_DPI_STR = 0x2400                  # "__TEXT"
    R_UPDATE_STR = 0x2800               # "__TEXT"              (E2)
    R_APPLY_STR = 0x2c00                # "__TEXT"              (E4)
    R_SETUP_STR = 0x3000                # "__TEXT"              (E4)
    R_GETNAME_STR = 0x3400              # "__TEXT"              (E2)
    R_TOGGLE_STR = 0x3800               # "__TEXT"              (E5 общий хелпер)
    R_PIN_STR = 0x3c00                  # "__TEXT"              (E5)
    R_SPRAY_STR = 0x4000                # "__TEXT"              (E5)
    R_ACTSTR_LABEL = 0xe4ad4e           # E1: адрес строкового лейбла SADDR(0xe4ad4e)=0xe4ad4e
    R_BADCTOR_FUNC = 0x11bfc4           # E3: функция с именем чужого селектора

    R_ACTSKILL_STR = 0x1000010          # "__TEXT.__objc_methname"
    R_UPDATE_FUNC = 0xc21a5c            # LogicBattleModeClient::update (символ)
    R_GETSPEED_FUNC = 0xc20a5c
    R_SKILLTIME_FUNC = 0xc30000         # содержит "LogicSkillData::getActiveTime"
    R_DPI_FUNC = 0xc40000               # содержит "getDpiClass"
    R_BAD_UPDATE_FUNC = 0x3cc0e4        # E2: общая функция, на которую вешались 4 тега
    R_GETNAME_FUNC = 0xc60000           # E2: общая функция для "getName"
    R_NAME_FUNC = 0xc50000              # E4: общая функция для applyDecoration/setupDecorated
    R_HELPER_FUNC = 0xc70000            # E5: один хелпер на 3 тега CombatHUD_*
    R_ACT_FUNC = 0x59c74c               # BattleScreen::activateSkill (IMP)
    R_DISPATCH_FUNC = 0x400000
    R_GETINST_FUNC = 0x710000           # AllianceManager::getInstance
    R_SINGLETON = 0x2004000
    R_OBJC_METHOD = 0x2000100
    R_DISPATCH_TAB = 0x2005000
    R_VTABLE = 0x2002000
    R_MSG_GLOBAL = 0x2003000
    R_SWIFT_META = 0x2003100            # E1: Swift-метаданные в __DATA


    def A(o):
        return Addr(o)


    class Addr(object):
        def __init__(self, o):
            self.o = o

        def getOffset(self):
            return self.o

        def add(self, d):
            return Addr(self.o + d)

        def subtract(self, d):
            return Addr(self.o - d)

        def __repr__(self):
            return "Addr(0x%x)" % self.o


    class Block(object):
        def __init__(self, name, start, end, is_exec):
            self.name = name
            self.start = Addr(start)
            self.end = Addr(end)
            self.is_exec = is_exec

        def getName(self):
            return self.name

        def getStart(self):
            return self.start

        def getEnd(self):
            return self.end

        def isInitialized(self):
            return True

        def isExecute(self):
            return self.is_exec


    BLOCKS = [
        Block("__TEXT", BASE + 0x0, BASE + 0x1000000, True),
        Block("__TEXT.__objc_methname", BASE + 0x1000000, BASE + 0x1001000, True),
        Block("__DATA", BASE + 0x2000000, BASE + 0x2400000, False),
    ]


    class Mem(object):
        def __init__(self):
            self.b = {}

        def set64(self, off, val):
            for i in range(8):
                self.b[off + i] = (val >> (8 * i)) & 0xFF

        def set32(self, off, val):
            val &= 0xFFFFFFFF
            for i in range(4):
                self.b[off + i] = (val >> (8 * i)) & 0xFF

        def getBlocks(self):
            return BLOCKS

        def getBlock(self, a):
            for b in BLOCKS:
                if b.getStart().o <= a.o < b.getEnd().o:
                    return b
            return None

        def getByte(self, a):
            return self.b.get(a.o, 0)

        def getInt(self, a):
            raw = bytes(bytearray([self.b.get(a.o + i, 0) for i in range(4)]))
            return struct.unpack("<i", raw)[0]

        def getLong(self, a):
            raw = bytes(bytearray([self.b.get(a.o + i, 0) for i in range(8)]))
            return struct.unpack("<Q", raw)[0]


    MEM = Mem()
    MEM.set64(BASE + R_OBJC_METHOD, BASE + R_ACTSKILL_STR)                                  # sel@+0
    MEM.set32(BASE + R_OBJC_METHOD + 8, (BASE + R_ACT_FUNC) - (BASE + R_OBJC_METHOD + 8))     # imp rel@+8
    MEM.set64(BASE + R_DISPATCH_TAB, BASE + R_SETCP_STR)
    MEM.set64(BASE + R_DISPATCH_TAB + 8, BASE + R_DISPATCH_FUNC)
    MEM.set64(BASE + R_VTABLE + 16, BASE + R_UPDATE_FUNC)                                     # slot[0]
    MEM.set64(BASE + R_VTABLE + 24, BASE + R_GETSPEED_FUNC)                                   # slot[1]
    MEM.set64(BASE + R_VTABLE + 32, BASE + R_ACT_FUNC)                                        # slot[2]


    class Data(object):
        def __init__(self, val, addr):
            self.val = val
            self.addr = addr

        def hasStringValue(self):
            return True

        def getValue(self):
            return self.val

        def getAddress(self):
            return self.addr


    STRINGS = [
        ("getSpeed", R_GETSPEED_STR),
        ("setClientPrediction", R_SETCP_STR),
        ("LogicSkillData::getActiveTime", R_SKILLTIME_STR),
        ("getDpiClass", R_DPI_STR),
        ("update", R_UPDATE_STR),
        ("applyDecoration", R_APPLY_STR),
        ("setupDecorated", R_SETUP_STR),
        ("getName", R_GETNAME_STR),
        ("toggleEditing", R_TOGGLE_STR),
        ("sendPinCommand", R_PIN_STR),
        ("sendSprayCommand", R_SPRAY_STR),
        ("activateSkill", R_ACTSKILL_STR),
    ]


    class JIter(object):
        def __init__(self, items):
            self.items = list(items)
            self.i = 0

        def hasNext(self):
            return self.i < len(self.items)

        def next(self):
            v = self.items[self.i]
            self.i += 1
            return v

        def iterator(self):
            return self


    class Ref(object):
        def __init__(self, to):
            self.to = to

        def getToAddress(self):
            return self.to


    class Insn(object):
        def __init__(self, mnem, refs):
            self.mnem = mnem
            self.refs = refs

        def getMnemonicString(self):
            return self.mnem

        def getReferencesFrom(self):
            return self.refs


    class Body(object):
        def __init__(self, ep):
            self.ep = ep


    class Func(object):
        def __init__(self, name, ep, size=0x1000):
            self.name = name
            self.ep = ep
            self.size = size

        def getName(self):
            return self.name

        def getEntryPoint(self):
            return Addr(self.ep)

        def getBody(self):
            return Body(self.ep)


    FUNCS = [
        Func("LogicBattleModeClient::update", BASE + R_UPDATE_FUNC),
        Func("FUN_00c20a5c", BASE + R_GETSPEED_FUNC),
        Func("FUN_00c30000", BASE + R_SKILLTIME_FUNC),
        Func("FUN_00c40000", BASE + R_DPI_FUNC),
        Func("FUN_003cc0e4", BASE + R_BAD_UPDATE_FUNC),
        Func("FUN_00c60000", BASE + R_GETNAME_FUNC),
        Func("FUN_00c50000", BASE + R_NAME_FUNC),
        Func("FUN_00c70000", BASE + R_HELPER_FUNC),
        Func("FUN_0059c74c", BASE + R_ACT_FUNC),
        Func("FUN_00400000", BASE + R_DISPATCH_FUNC),
        Func("AllianceManager::getInstance", BASE + R_GETINST_FUNC),
        Func("base64StringWithExceptionDescription:", BASE + R_BADCTOR_FUNC),   # E3
    ]

    REFS_TO = {
        (BASE + R_GETSPEED_STR): [Addr(BASE + R_GETSPEED_FUNC)],
        (BASE + R_SKILLTIME_STR): [Addr(BASE + R_SKILLTIME_FUNC)],
        (BASE + R_DPI_STR): [Addr(BASE + R_DPI_FUNC)],
        (BASE + R_UPDATE_STR): [Addr(BASE + R_BAD_UPDATE_FUNC)],
        (BASE + R_GETNAME_STR): [Addr(BASE + R_GETNAME_FUNC)],
        (BASE + R_APPLY_STR): [Addr(BASE + R_NAME_FUNC)],
        (BASE + R_SETUP_STR): [Addr(BASE + R_NAME_FUNC)],
        (BASE + R_TOGGLE_STR): [Addr(BASE + R_HELPER_FUNC)],
        (BASE + R_PIN_STR): [Addr(BASE + R_HELPER_FUNC)],
        (BASE + R_SPRAY_STR): [Addr(BASE + R_HELPER_FUNC)],
    }

    INSN_BY_BODY = {
        (BASE + R_GETINST_FUNC): [Insn("ADD", [Ref(Addr(BASE + R_SINGLETON))])],
    }


    class Listing(object):
        def getDefinedData(self, fwd):
            return JIter([Data(s, Addr(BASE + r)) for (s, r) in STRINGS])

        def getInstructions(self, body, fwd):
            return JIter(INSN_BY_BODY.get(body.ep, []))


    class CRef(object):
        def __init__(self, frm):
            self.frm = frm

        def getFromAddress(self):
            return self.frm


    class RefMgr(object):
        def getReferencesTo(self, a):
            return JIter([CRef(x) for x in REFS_TO.get(a.o, [])])


    class Sym(object):
        def __init__(self, name, addr):
            self.name = name
            self.addr = addr

        def getName(self):
            return self.name

        def getAddress(self):
            return self.addr


    SYMS = [
        Sym("LogicCharacterData::vftable", Addr(BASE + R_VTABLE)),
        Sym("MessageManager_instance", Addr(BASE + R_MSG_GLOBAL)),
        Sym("LogicBattleModeClient::update", Addr(BASE + R_UPDATE_FUNC)),
        # E1: мусор, который v1 принимал за глобалы/функции
        Sym("s_stage_100e4ad4e", Addr(BASE + R_ACTSTR_LABEL)),
        Sym("s_MessageManager::initialReceiveMe_100ec1ef9", Addr(BASE + 0xec1ef9)),
        Sym("_TtC6Sentry18SentryScreenFrames", Addr(BASE + R_SWIFT_META)),
        Sym("s_LogicDataTables::initDataTable_i_100ee0c1f", Addr(BASE + 0xee0c1f)),
    ]


    class SymTable(object):
        def getAllSymbols(self, fwd):
            return JIter(SYMS)


    class FuncMgr(object):
        def getFunctions(self, fwd):
            return JIter(FUNCS)


    class Program(object):
        name = "SyntheticBrawlStars.arm64"

        def getName(self):
            return self.name

        def getExecutableFormat(self):
            return "Mac OS X Mach-O"

        def getLanguageID(self):
            return "AARCH64:LE:64:AppleSilicon"

        def getImageBase(self):
            return Addr(BASE)

        def getMemory(self):
            return MEM

        def getListing(self):
            return Listing()

        def getReferenceManager(self):
            return RefMgr()

        def getSymbolTable(self):
            return SymTable()

        def getFunctionManager(self):
            return FuncMgr()


    def getFunctionContaining(a):
        for f in FUNCS:
            if f.ep <= a.o < f.ep + f.size:
                return f
        return None


    def getFunctionAt(a):
        for f in FUNCS:
            if f.ep == a.o:
                return f
        return None


    def toAddr(o):
        if isinstance(o, Addr):
            return o
        return Addr(int(o))


    def createAsciiString(a):
        raise RuntimeError("stub: no ascii-string creation")

    # ---- подключаем заглушку к резолверу и прогоняем его как обычно
    g = globals()
    g["currentProgram"] = Program()
    g["getFunctionContaining"] = getFunctionContaining
    g["getFunctionAt"] = getFunctionAt
    g["toAddr"] = toAddr
    g["createAsciiString"] = createAsciiString
    if outdir is None:
        outdir = os.environ.get("GITHUB_WORKSPACE") or "/tmp/find_py_selftest"
    if not os.path.isdir(outdir):
        os.makedirs(outdir)
    g["WS"] = outdir
    g["OUT"] = os.path.join(outdir, "offsets_resolved.js")
    g["REPORT"] = os.path.join(outdir, "offsets_report.txt")

    main()

    # ---- проверки
    log("")
    log("================ SELF-TEST (report + offsets_resolved.js) ================")
    cnt = [0]
    rva, strat = {}, {}
    reptxt = open(g["REPORT"]).read()
    for line in reptxt.splitlines():
        if line.startswith("#") or "=" not in line:
            continue
        tag, _, rhs = line.partition(" = ")
        tag = tag.strip()
        if not tag or " " in tag or not rhs.startswith("0x"):
            continue
        rva[tag] = int(rhs.split()[0], 16)
        if "#" in rhs:
            strat[tag] = rhs.split("#")[1].strip().split()[0]

    jstxt = open(g["OUT"]).read()
    js = {}
    for line in jstxt.splitlines():
        line = line.strip()
        if line.startswith("//") or ":" not in line:
            continue
        k, _, v = line.partition(":")
        v = v.split("//")[0].strip().rstrip(",").strip()
        if v.startswith("0x"):
            js[k.strip()] = int(v, 16)

    def ok(cond, label, detail=""):
        if cond:
            log("PASS   %s%s" % (label, detail))
        else:
            log("FAIL   %s%s" % (label, detail))
            cnt[0] += 1

    def expect(tag, want, want_strat):
        got = rva.get(tag)
        ok(got == want and strat.get(tag) == want_strat and js.get(tag) == want,
           tag, "  0x%x %s" % (want, want_strat) if got is None else
           "  got 0x%x %s js=%s" % (got, strat.get(tag), js.get(tag)))

    def expect_missing(tag, why):
        ok((tag not in rva) and (tag not in js), tag, "  отброшен (%s)" % why)

    # --- позитивные: каждая стратегия
    expect("LogicBattleModeClient_update", R_UPDATE_FUNC, "S0:symbol")
    expect("LogicSkillData_getActiveTime", R_SKILLTIME_FUNC, "S1:qual")
    expect("Screen_getDpiClass", R_DPI_FUNC, "S1:bare")
    expect("BattleScreen_activateSkill", R_ACT_FUNC, "S2:objc")
    expect("SetClientPrediction", R_DISPATCH_FUNC, "S3:ptr")
    expect("AllianceManager_instance", R_SINGLETON, "S4:slot")
    expect("VTABLE_CHARACTER_DATA", R_VTABLE, "S5:vtable")
    expect("MessageManager_instance", R_MSG_GLOBAL, "S0:symbol")

    # --- E1: строковые лейблы / Swift-метаданные не должны выдаваться за глобалы
    expect_missing("StageInstanceGlobalPtr", "E1 строковый лейбл s_stage_*, вне data")
    expect_missing("Screen_widthGlobal", "E1 Swift-символ _TtC6Sentry...")
    expect_missing("Screen_heightGlobal", "E1 Swift-символ _TtC6Sentry...")
    expect_missing("LogicDataTables_tableArray", "E1 строковый лейбл s_LogicDataTables::*, вне data")

    # --- E2: shared needle -> никаких оффсетов, но улика в отчёте
    expect_missing("GameMain_update", "E2 shared needle 'update'")
    expect_missing("CombatHUD_update", "E2 shared needle 'update'")
    expect_missing("Projectile_update", "E2 shared needle 'update'")
    expect_missing("LogicCharacterData_getSpeed", "E2 shared needle 'getSpeed'")
    expect_missing("LogicProjectileData_getSpeed", "E2 shared needle 'getSpeed'")
    expect_missing("CSVRow_getName", "E2 shared needle 'getName'")
    expect_missing("LogicData_getName", "E2 shared needle 'getName'")

    # --- E3: чужой ObjC-селектор не должен резолвить String_ctor
    expect_missing("String_ctor", "E3 чужой селектор base64StringWithExceptionDescription:")

    # --- E4: один адрес = один тег
    expect("Name_applyDecoration", R_NAME_FUNC, "S1:bare")
    expect_missing("Name_setupDecorated", "E4 DUP адреса 0x%x" % R_NAME_FUNC)

    # --- E5: один адрес у >=3 тегов -- общий хелпер, снимаются все
    expect_missing("CombatHUD_toggleEditing", "E5 общий хелпер 0x%x" % R_HELPER_FUNC)
    expect_missing("CombatHUD_sendPinCommand", "E5 общий хелпер 0x%x" % R_HELPER_FUNC)
    expect_missing("CombatHUD_sendSprayCommand", "E5 общий хелпер 0x%x" % R_HELPER_FUNC)
    ok("общий хелпер" in reptxt, "в отчёте помечен общий хелпер")

    # --- служебные секции отчёта
    ok("#     cand 0x%x tier=0 'update'" % R_BAD_UPDATE_FUNC in reptxt,
       "в отчёте есть секция candidates по 'update'")
    ok("DUP" in reptxt, "в отчёте помечен DUP")
    ok("slot[" in reptxt, "в отчёте есть vtable slot map")
    ok("table 0x2002010 slot 0" in reptxt, "в отчёте есть автопоиск таблиц кода")
    ok("export const offsets = Object.freeze({" in jstxt, "offsets_resolved.js в формате REvengeBS")
    ok(jstxt.rstrip().endswith("});"), "offsets_resolved.js закрыт корректно")

    return cnt[0]


# --------------------------------------------------------------------------- #
# диспетчер: Ghidra ищем по наличию currentProgram, иначе -- self-test
# --------------------------------------------------------------------------- #

def _has_ghidra_program():
    try:
        p = currentProgram
    except NameError:
        return False
    return p is not None


def _arg_outdir():
    for a in sys.argv[1:]:
        if a.startswith("--out="):
            return a.split("=", 1)[1]
    for a in sys.argv[1:]:
        if not a.startswith("-"):
            return a
    return None


if ("--self-test" in sys.argv) or (not _has_ghidra_program()):
    _fails = self_test(_arg_outdir())
    log("")
    log("SELF-TEST FAILURES: %d" % _fails)
    sys.exit(1 if _fails else 0)
else:
    try:
        main()
    except SystemExit:
        raise
    except Exception as e:
        log("FATAL: %s" % e)
        traceback.print_exc()
