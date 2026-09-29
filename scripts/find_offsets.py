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
DEV_REPORT = os.path.join(WS, "dev_flags_report.txt")

TEXT_BASE = 0x100000000
MIN_FUNC_RVA = 0x10000
BUDGET_SEC = 3600
MIN_EXPECTED_ENTRIES = 0
GENERIC_ANCHOR_LIMIT = 50
DUMP_DEV_STRINGS = True

L = []
START = time.time()
SAMPLE_LIMIT = 200

def log(m):
    sys.stdout.write(m + "\n")
    sys.stdout.flush()

def w(s):
    L.append(s)

STRING_ANCHORS = {
    "LogicSkillData__getMsBetweenAttacks": ["MsBetweenAttacks"],
    "LogicSkillData__getActiveTime": ["ActiveTime"],
    "LogicSkillData__getCastingRange": ["CastingRange"],
    "LogicSkillData__getRechargeTime": ["RechargeTime"],
    "LogicSkillData__getMaxCharge": ["MaxCharge"],
    "LogicProjectileData_getSpeed": ["ProjectileSpeed"],
    "LogicProjectileData_getRadius": ["ProjectileRadius"],
    "LogicProjectileData_getRendering": ["ProjectileRendering"],
    "LogicProjectileData__isBeam": ["isBeam"],
    "LogicProjectileData__getNumEarlyTicks": ["NumEarlyTicks"],
    "LogicTileData__blocksMovement": ["BlocksMovement"],
    "LogicTileData__blocksProjectiles": ["BlocksProjectiles"],
    "LogicCharacterData_getCollisionRadius": ["CollisionRadius"],
    "LogicCharacterData_getSpeed": ["CharacterSpeed"],
    "LogicBattleModeClient__getTileMap": ["getTileMap"],
    "LogicBattleModeClient__getOwnPlayerIndex": ["getOwnPlayerIndex"],
    "LogicBattleModeClient__setRandomSeed": ["setRandomSeed"],
    "LogicBattleModeClient__setPlayerAvatar": ["setPlayerAvatar"],
    "LogicBattleModeClient_getOwnCharacter": ["getOwnCharacter"],
    "LogicBattleModeClient_getOwnPlayerTeam": ["getOwnPlayerTeam"],
    "LogicCharacterClient__getWeaponSkill": ["getWeaponSkill"],
    "LogicCharacterClient__getSkillAt": ["getSkillAt"],
    "LogicCharacterClient__getCarryableData": ["getCarryableData"],
    "LogicCharacterClient__getLinkedCarryable": ["getLinkedCarryable"],
    "LogicCharacterClient__getCurrentActiveOrCastingSkill": ["getCurrentActiveOrCastingSkill"],
    "LogicCharacterClient__isImmuneOrUntargetable": ["isImmuneOrUntargetable"],
    "LogicGameObjectManagerClient__getGameObjects": ["getGameObjects"],
    "LogicGameObjectManagerClient__findGameObject": ["findGameObject"],
    "LogicProjectileServer__shootProjectile": ["shootProjectile"],
    "LogicProjectileServer__runEarlyTicks": ["runEarlyTicks"],
    "GlobalID__getInstanceID": ["getInstanceID"],
    "LogicPlayerMapUtil__tileDataToTileCode": ["tileDataToTileCode"],
    "LogicRandom__setIteratedRandomSeed": ["setIteratedRandomSeed"],
    "LogicLongToCodeConverterUtil__toCode": ["toCode"],
    "ResourceListener__addFile": ["addFile"],
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
    "StringTable__getMovieClip": ["getMovieClip"],
    "MovieClipHelper__setTextAndScaleIfNecessary": ["setTextAndScaleIfNecessary"],
    "LogicTile__setData": ["setData"],
    "LogicTileMap__isPlayerLineOfSightClear": ["isPlayerLineOfSightClear"],
    "LogicDataTables__getOpenTileData": ["getOpenTileData"],
    "LogicDataTables__getBaseTileData": ["getBaseTileData"],
    "LogicDataTables__getSiegeBoltTileData": ["getSiegeBoltTileData"],
    "ClientInputMessage_sendMovement": ["sendMovement"],
    "HashTagCodeGenerator__toId": ["toId"],
    "HashTagCodeGenerator__isValid": ["isValid"],
    "Name_setupDecorated": ["setupDecorated"],
    "Name_applyDecoration": ["applyDecoration"],
    "AllianceManager__startSpectate": ["startSpectate"],
    "CustomButton_onButtonPressed": ["onButtonPressed"],
    "nativeCopyToClipboard": ["copyToClipboard"],
    "LogicGameModeUtil__isTileOnPoisonArea": ["isTileOnPoisonArea"],
    "LogicDataTable_findByName": ["findByName"],
    "AreaEffectData__getRadius": ["getRadius"],
    "AreaEffectData__getActiveTimeMs": ["getActiveTimeMs"],
    "MovieClip__getChildClipByName": ["getChildClipByName"],
    "MovieClip__setChildVisible": ["setChildVisible"],
    "MovieClip__gotoAndStopFrameIndex": ["gotoAndStopFrameIndex"],
    "Screen__getDpiClass": ["getDpiClass"],
    "Screen__getHeight": ["getHeight"],
    "Screen__getWidth": ["getWidth"],
    "StringCtor": ["String not found:"],
    "MessageManager__receiveMessage": ["receiveMessage"],
    "MessageManager__sendMessage": ["sendMessage"],
    "TextField_setText": ["setText"],
    "BattleMode__enter": ["enter"],
    "LogicBattleModeClient_update": ["LogicBattleModeClient"],
    "LogicPlayerMap__save": ["save"],
    "String__format": ["format"],
    "LogicLongToCodeConverterUtil__convert": ["convert"],
    "Sprite_Sprite": ["Sprite"],
    "ClientInputManager_addInput": ["addInput"],
    "LogicSkillData__getProjectileData": ["getProjectileData"],
    "LogicSkillData__getBehaviour": ["getBehaviour"],
    "LogicSkillData__getLinkedSkill": ["getLinkedSkill"],
    "LogicSkillClient__canActivate": ["canActivate"],
    "LogicSkillClient__getData": ["getData"],
    "LogicGameObjectServer__getData": ["getData"],
    "LogicProjectileClient_getData": ["getData"],
    "LogicProjectileClient_getTargetX": ["getTargetX"],
    "LogicProjectileClient_getTargetY": ["getTargetY"],
    "LogicProjectileClient_destruct": ["~LogicProjectileClient"],
    "LogicProjectileClient_ctor": ["LogicProjectileClient"],
    "LogicCharacterClient__canMoveAndUseThisSkillSimultaneously": ["canMoveAndUseThisSkillSimultaneously"],
    "LogicCharacterClientOwn__clientPredictionPauseMovementForSkillCasting": ["clientPredictionPauseMovementForSkillCasting"],
    "LogicCharacterClientOwn__clientPredictionUpdateAttackDirection": ["clientPredictionUpdateAttackDirection"],
    "LogicBattleModeClient__LogicBattleModeClient": ["LogicBattleModeClient"],
    "LogicBattleModeClient_setClientPredictionMoveTo": ["setClientPredictionMoveTo"],
    "LogicGameObjectManagerClient__LogicGameObjectManagerClient": ["LogicGameObjectManagerClient"],
    "LogicTileMap__LogicTileMap": ["LogicTileMap"],
    "LogicTileMap__isPlayerLineOfSightClear1": ["isPlayerLineOfSightClear"],
    "LogicTileMap_getTile": ["getTile"],
    "GameObjectManager__GameObjectManager": ["GameObjectManager"],
    "RenderSystem__RenderSystem": ["RenderSystem"],
    "DecalManager__DecalManager": ["DecalManager"],
    "Projectile_ctor": ["Projectile"],
    "Projectile__update": ["Projectile"],
    "GameMain__update": ["GameMain"],
    "GameScreen__getLogicBattle": ["getLogicBattle"],
    "GameSettings__isFixedJoystickEnabled": ["isFixedJoystickEnabled"],
    "Gui_getInstance": ["Gui"],
    "Gui_showFloaterTextAtDefaultPos": ["showFloaterTextAtDefaultPos"],
    "handleJoystick": ["handleJoystick"],
    "ResourceManager__isResourceLoaded": ["isResourceLoaded"],
    "ResourceManager__getCSV": ["getCSV"],
    "HashTagCodeGenerator__ctor": ["HashTagCodeGenerator"],
    "HashTagCodeGenerator__dtor": ["~HashTagCodeGenerator"],
    "AnalyticEvent__AnalyticEvent": ["AnalyticEvent"],
    "AnalyticEvent__setString": ["setString"],
    "PiranhaMessage_ctor": ["PiranhaMessage"],
    "TeamChatMessage__ctor": ["TeamChatMessage"],
    "TeamSetMemberReadyMessage__ctor": ["TeamSetMemberReadyMessage"],
    "StartSpectateMessage__ctor": ["StartSpectateMessage"],
    "LogicCompressedString__LogicCompressedString": ["LogicCompressedString"],
    "LogicLongToCodeConverterUtil__LogicLongToCodeConverterUtil": ["LogicLongToCodeConverterUtil"],
    "LogicData_getName": ["getName"],
    "LogicGameObjectClient_getX": ["getX"],
    "LogicGameObjectClient_getY": ["getY"],
    "LogicGameObjectClient_getZ": ["getZ"],
    "LogicGameObjectClient_getData": ["getData"],
    "LogicGameObjectClient_getGlobalID": ["getGlobalID"],
    "LogicBattleModeClient__getOwnPlayerIndex_alias": ["getOwnPlayerIndex"],
    "GameStateManager__getInstance": ["GameStateManager"],
    "GameStateManager__isState": ["isState"],
    "HomeMode__getInstance": ["HomeMode"],
    "BattleMode_getInstance": ["BattleMode"],
}

DEVELOPER_FLAGS = {
    "LogicVersion_isDeveloperBuild": [
        "isDeveloperBuild",
        "isDeveloper",
        "DeveloperBuild",
        "isDevBuild",
        "DEV_BUILD",
        "devBuild",
    ],
    "LogicVersion_isDev": [
        "isDev",
        "isDevMode",
        "DevMode",
        "dev_mode",
        "isInternal",
        "InternalBuild",
        "isDebug",
        "DebugBuild",
    ],
    "LogicVersion_isProd": [
        "isProd",
        "isProduction",
        "isProductive",
        "isRelease",
        "isLive",
        "ReleaseBuild",
        "prodBuild",
    ],
    "SCIDConfig_isDevBuild": ["isDevBuild"],
    "LogicVersion_isProduction": ["isProduction"],
}

DEV_STR_DUMP_FILTERS = [
    "isDev", "IsDev", "isDeveloper", "IsDeveloper",
    "isProd", "IsProd", "Production",
    "DevBuild", "devBuild", "DEV_BUILD",
    "DebugMenu", "debugMenu", "Debug",
    "Internal", "internal",
    "Release", "release",
    "Frida", "frida",
]

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
        return out
    try:
        fh = open(OFF_IN, "r")
        content = fh.read()
        fh.close()
    except:
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
    except:
        pass
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
        try:
            s = sig(f, 6)
            if len(s) >= min_len:
                idx.setdefault(s, []).append(f.getEntryPoint())
        except:
            continue
    log("[*] sig index: %d funcs, %d sigs" % (count, len(idx)))
    return idx

def index_strings():
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
            break
        try:
            d = it.next()
        except:
            break
        total_data += 1
        try:
            if d is None or not d.hasStringValue():
                continue
            sval = str(d.getValue())
            if not sval:
                continue
            total_str += 1
            if len(sample) < SAMPLE_LIMIT:
                sample.append(sval[:160])
            key = sval[:256]
            idx.setdefault(key, []).append(d.getAddress())
        except:
            continue
    log("[*] total data items: %d" % total_data)
    log("[*] total strings: %d" % total_str)
    log("[*] unique strings: %d" % len(idx))
    log("[*] sample strings (first 40):")
    for s in sample[:40]:
        log("    %r" % s)
    return idx, total_data, total_str

def find_anchor_addrs(string_idx, anchor):
    out = []
    for sval, addrs in string_idx.items():
        if anchor in sval:
            out.extend(addrs)
    return out

def dump_dev_related_strings(string_idx):
    log("[*] dumping dev/prod-related strings...")
    found = {}
    for sval, addrs in string_idx.items():
        for f in DEV_STR_DUMP_FILTERS:
            if f in sval:
                found.setdefault(f, [])
                for a in addrs:
                    found[f].append((rva(a), sval[:160]))
                break
    fh = None
    try:
        fh = open(DEV_REPORT, "w")
    except:
        fh = None
    for f in sorted(found.keys()):
        items = found[f][:50]
        log("  [%s] %d hit(s):" % (f, len(found[f])))
        if fh is not None:
            fh.write("[%s] %d hit(s):\n" % (f, len(found[f])))
        for r, s in items:
            log("    rva=0x%x  %r" % (r, s))
            if fh is not None:
                fh.write("    rva=0x%x  %r\n" % (r, s))
    if fh is not None:
        try:
            fh.close()
        except:
            pass
    log("[*] wrote %s" % DEV_REPORT)

def score_functions_for_name(anchors, anchor_hits, used_addrs, rm):
    scores = {}
    addr_to_func = {}
    for anchor in anchors:
        addrs = anchor_hits.get(anchor, [])
        if not addrs:
            continue
        weight = 1
        if len(addrs) > GENERIC_ANCHOR_LIMIT:
            weight = 0
        for sa in addrs:
            sa_key = str(sa)
            if sa_key in used_addrs:
                continue
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
                    scores[fr] = scores.get(fr, 0) + weight
                    addr_to_func.setdefault(fr, []).append(sa_key)
            except:
                continue
    return scores, addr_to_func

def main():
    log("=== find_offsets v5 (dev-flags focused) ===")
    offs = read_offsets()
    log("[*] parsed %d entries from offsets.js" % len(offs))

    if MIN_EXPECTED_ENTRIES > 0 and len(offs) < MIN_EXPECTED_ENTRIES:
        log("[!] ABORT: offsets.js has only %d entries, expected >= %d" % (len(offs), MIN_EXPECTED_ENTRIES))
        sys.exit(1)

    sigdb = load_sigdb()
    log("[*] sigdb: %d entries" % len(sigdb))

    string_idx, total_data, total_str = index_strings()
    if total_str == 0:
        log("[!] NO STRINGS FOUND")
        sys.exit(1)

    all_anchors = set()
    for anchors in STRING_ANCHORS.values():
        for a in anchors:
            all_anchors.add(a)
    for anchors in DEVELOPER_FLAGS.values():
        for a in anchors:
            all_anchors.add(a)

    log("[*] unique anchors to search: %d" % len(all_anchors))
    anchor_hits = {}
    generic_anchors = set()
    for a in all_anchors:
        hits = find_anchor_addrs(string_idx, a)
        if hits:
            anchor_hits[a] = hits
            if len(hits) > GENERIC_ANCHOR_LIMIT:
                generic_anchors.add(a)
    log("[*] anchors with hits: %d / %d" % (len(anchor_hits), len(all_anchors)))
    log("[*] generic anchors (>%d hits): %d" % (GENERIC_ANCHOR_LIMIT, len(generic_anchors)))
    for a in sorted(anchor_hits.keys()):
        log("    anchor %r -> %d hit(s)" % (a, len(anchor_hits[a])))

    rm = currentProgram.getReferenceManager()
    resolved = {}
    verified = 0
    rematched = 0
    anchor_hits_count = 0
    ambiguous = 0
    failures = []
    new_sigs = {}
    sig_index = None
    used_addrs = set()

    names_sorted = sorted(offs.keys())
    for name in names_sorted:
        old_rva = offs[name]
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
                sig_index = build_sig_index()
            cands = sig_index.get(s, [])
            if len(cands) == 1:
                resolved[name] = rva(cands[0])
                rematched += 1
                new_sigs[name] = s
                continue

        anchors = STRING_ANCHORS.get(name)
        if not anchors:
            failures.append((name, old_rva, "no-anchor"))
            continue

        scores, addr_to_func = score_functions_for_name(anchors, anchor_hits, used_addrs, rm)
        if not scores:
            failures.append((name, old_rva, "anchor-miss"))
            continue

        best_score = max(scores.values())
        top = [fr for fr, sc in scores.items() if sc == best_score and sc > 0]
        if len(top) != 1:
            failures.append((name, old_rva, "ambiguous:%d" % len(top)))
            ambiguous += 1
            continue

        best_rva = top[0]
        for sa_key in addr_to_func.get(best_rva, []):
            used_addrs.add(sa_key)
        resolved[name] = best_rva
        anchor_hits_count += 1
        try:
            f = getFunctionAt(addr(best_rva))
            if f is not None:
                s = sig(f)
                if s:
                    new_sigs[name] = s
        except:
            pass

    dev_flags = {}
    log("")
    log("=== DEV FLAG RESOLUTION ===")
    for flag_name in sorted(DEVELOPER_FLAGS.keys()):
        anchors = DEVELOPER_FLAGS[flag_name]
        scores, addr_to_func = score_functions_for_name(anchors, anchor_hits, used_addrs, rm)
        if not scores:
            log("  %s -> no hits" % flag_name)
            continue
        best_score = max(scores.values())
        top = [fr for fr, sc in scores.items() if sc == best_score and sc > 0]
        if len(top) == 1:
            best_rva = top[0]
            dev_flags[flag_name] = best_rva
            for sa_key in addr_to_func.get(best_rva, []):
                used_addrs.add(sa_key)
            log("  %s -> rva=0x%x score=%d" % (flag_name, best_rva, best_score))
        else:
            log("  %s -> ambiguous (%d candidates):" % (flag_name, len(top)))
            for fr in top[:20]:
                log("      rva=0x%x score=%d" % (fr, scores[fr]))

    if DUMP_DEV_STRINGS:
        dump_dev_related_strings(string_idx)

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

    save_sigdb(new_sigs)

    w("elapsed %.1fs" % (time.time() - START))
    w("input: %d" % len(offs))
    w("strings indexed: %d (unique: %d)" % (total_str, len(string_idx)))
    w("anchors with hits: %d / %d" % (len(anchor_hits), len(all_anchors)))
    w("generic anchors: %d" % len(generic_anchors))
    w("resolved: %d (verified=%d rematched=%d anchor=%d ambiguous=%d)" % (
        len(resolved), verified, rematched, anchor_hits_count, ambiguous))
    w("developer flags found: %d" % len(dev_flags))
    for n, r in sorted(dev_flags.items()):
        w("  DEV %s @ 0x%x" % (n, r))
    w("failed: %d" % len(failures))
    for n, r, msg in failures[:100]:
        w("  FAIL %s @ 0x%x (%s)" % (n, r, msg))
    if len(failures) > 100:
        w("  ... and %d more" % (len(failures) - 100))

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