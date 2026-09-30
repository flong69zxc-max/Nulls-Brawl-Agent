#!/usr/bin/env python3
import os
import sys
import time
import struct
import re
import traceback

import r2pipe

WS = os.environ.get("GITHUB_WORKSPACE", "/tmp")
BIN = os.environ.get("R2_BIN", "/tmp/brawl_bin")
OUT = os.path.join(WS, "offsets_resolved.js")
REPORT = os.path.join(WS, "offsets_report.txt")
DETAIL = os.path.join(WS, "ctors_detailed.log")
BUDGET = 1800
START = time.time()

TARGETS = [
    "LogicBattleModeClient_update",
    "BattleMode_getInstance",
    "LogicGameObjectClient_getX",
    "LogicGameObjectClient_getY",
    "LogicGameObjectClient_getZ",
    "LogicBattleModeClient_getOwnCharacter",
    "BattleScreen_activateSkill",
    "StringCtor",
    "Gui_showFloaterTextAtDefaultPos",
    "LogicBattleModeClient_getOwnPlayerTeam",
    "LogicGameObjectClient_getGlobalID",
    "LogicGameObjectClient_getData",
    "LogicProjectileData_getRadius",
    "LogicProjectileData_getSpeed",
    "LogicProjectileData_getRendering",
    "LogicCharacterData_getCollisionRadius",
    "decoratedTextFieldSetPlayerName",
    "TextField_setText_ui",
    "TextField_setText",
    "handleJoystick",
    "ClientInput_constructor_int",
    "ClientInputManager_addInput",
    "LogicBattleModeClient_setClientPredictionMoveTo",
    "Sprite_Sprite",
    "LogicTileData__blocksProjectiles",
    "ResourceManager__isResourceLoaded",
    "GameMain__update",
    "DecalManager__DecalManager",
    "LogicProjectileData__IsOwnTeamProjectile",
    "GameObjectManager__GameObjectManager",
    "Projectile_ctor",
    "Projectile__update",
    "RenderSystem__RenderSystem",
    "CombatHUD__toggleEditing",
    "BattleScreen__updateCameraParameters",
    "Character__updateHealthBar",
    "CombatHUD__setShootStickState",
    "CombatHUD__setMoveStickState",
    "GUI__getDefaultFloaterPos",
    "GUI__showFloaterTextAt",
    "GUI__showPopup",
    "GameButtonCtor",
    "DropGUIContainer__ctorFromExport",
    "GameSliderComponent__GameSliderComponent",
    "GameSliderComponent__setValueBounds",
    "MapEditorModifierItem__MapEditorModifierItem",
    "MapEditorModifierPopup__MapEditorModifierPopup",
    "MapEditorModifierPopup__addModifierItem",
    "PopupBase__PopupBase",
    "MessageManager__receiveMessage",
    "BattleScreen__BattleScreen",
    "BattleScreen__stopWithStick",
    "BattleScreen__handleTouchReleased",
    "BattleScreen__update",
    "BattleScreen__updateAutoshoot",
    "BattleScreen_getClosestTargetForAutoshoot",
    "BattleScreen__updateMovement",
    "BattleScreen__tryToActivateSkill",
    "BattleScreen__shouldShowAccessoryButton",
    "BattleScreen__calculateProjectilePath",
    "BattleScreen__joystickToWorld",
    "GameScreen__getLogicBattle",
    "MapEditorScreen__initRenderSystem",
    "MapEditorScreen__initItems",
    "MapEditorScreen__initCharacters",
    "GameSettings__isFixedJoystickEnabled",
    "BattleMode__enter",
    "BattleMode__addResourcesToLoad",
    "GameStateManager__getInstance",
    "GameStateManager__isState",
    "HomeMode__getInstance",
    "StringTable__getMovieClip",
    "MovieClipHelper__setTextAndScaleIfNecessary",
    "LogicTile__setData",
    "LogicTileMap__LogicTileMap",
    "LogicTileMap__isPlayerLineOfSightClear",
    "LogicTileMap__isPlayerLineOfSightClear1",
    "LogicDataTables__getOpenTileData",
    "LogicDataTables__getBaseTileData",
    "LogicDataTables__getSiegeBoltTileData",
    "LogicProjectileData__isBeam",
    "LogicCharacterData_getSpeed",
    "LogicProjectileData__getNumEarlyTicks",
    "LogicSkillData__getActiveTime",
    "LogicSkillData__getRechargeTime",
    "LogicSkillData__getMaxCharge",
    "LogicSkillData__getMsBetweenAttacks",
    "LogicSkillData__getCastingRange",
    "LogicTileData__blocksMovement",
    "LogicCharacterClient__getCarryableData",
    "LogicCharacterClient__getWeaponSkill",
    "LogicCharacterClient__canMoveAndUseThisSkillSimultaneously",
    "LogicCharacterClient__getLinkedCarryable",
    "LogicCharacterClient__getCurrentActiveOrCastingSkill",
    "LogicCharacterClient__getSkillAt",
    "LogicSkillClient__getData",
    "LogicSkillClient__canActivate",
    "LogicSkillData__getBehaviour",
    "LogicSkillData__getLinkedSkill",
    "LogicCharacterClientOwn__clientPredictionPauseMovementForSkillCasting",
    "LogicCharacterClientOwn__clientPredictionUpdateAttackDirection",
    "LogicGameObjectManagerClient__LogicGameObjectManagerClient",
    "LogicGameObjectManagerClient__getGameObjects",
    "LogicGameObjectManagerClient__findGameObject",
    "LogicGameObjectServer__getData",
    "LogicProjectileServer__shootProjectile",
    "LogicProjectileServer__runEarlyTicks",
    "GlobalID__getInstanceID",
    "LogicPlayerMap__save",
    "LogicPlayerMapUtil__tileDataToTileCode",
    "AnalyticEvent__AnalyticEvent",
    "AnalyticEvent__setString",
    "LogicBattleModeClient__LogicBattleModeClient",
    "LogicBattleModeClient__setRandomSeed",
    "LogicBattleModeClient__setPlayerAvatar",
    "LogicBattleModeClient__getOwnPlayerIndex",
    "LogicBattleModeClient__getTileMap",
    "SetClientPrediction",
    "ScrollArea__scrollTo",
    "StringTable_getMovieClip",
    "DisplayObject__setXY",
    "DisplayObject__removeFromParent",
    "MovieClip__getTextFieldByName",
    "Sprite__addChild",
    "Sprite__addChildAt",
    "Sprite__removeChild",
    "ScrollArea__updateBounds",
    "ScrollArea__addContent",
    "ScrollArea__removeAllContent",
    "CSVRow__getIntegerValueAt",
    "CSVRow__getName",
    "CSVRow__getValueAt",
    "CSVRow__getBooleanValueAt",
    "CSVTable__getColumnIndexByName",
    "LogicJSONObject__put",
    "LogicRandom__setIteratedRandomSeed",
    "LogicCompressedString__LogicCompressedString",
    "LogicLongToCodeConverterUtil__LogicLongToCodeConverterUtil",
    "LogicLongToCodeConverterUtil__convert",
    "LogicLongToCodeConverterUtil__toCode",
    "ResourceListener__addFile",
    "String__format",
    "FramerateManager__setSegment",
    "FramerateManager__setLimit",
    "Application__copyString",
    "BattleScreen_fireWrapperFn",
    "Stage_addChild",
    "GameButton_setText",
    "nativeCopyToClipboard",
    "ResourceManager__getCSV",
    "MovieClip__gotoAndStopFrameIndex",
    "MovieClip_gotoAndStop",
    "LogicCharacterClient__isImmuneOrUntargetable",
    "operator_new",
    "TeamChatMessage__ctor",
    "TeamSetMemberReadyMessage__ctor",
    "MessageManager__sendMessage",
    "StartSpectateMessage__ctor",
    "HashTagCodeGenerator__ctor",
    "HashTagCodeGenerator__toId",
    "Gui_getInstance",
    "PiranhaMessage_ctor",
    "LogicSkillData__getProjectileData",
    "Name_setupDecorated",
    "Name_applyDecoration",
    "AllianceManager__startSpectate",
    "ClientInputMessage_sendMovement",
    "CombatHUD__update",
    "CombatHUD__sendPinCommand",
    "CombatHUD__sendSprayCommand",
    "CustomButton_onButtonPressed",
    "HashTagCodeGenerator__dtor",
    "HashTagCodeGenerator__isValid",
    "LogicGameModeUtil__isTileOnPoisonArea",
    "LogicTileMap_getTile",
    "LogicProjectileClient_ctor",
    "LogicProjectileClient_destruct",
    "LogicProjectileClient_getData",
    "LogicProjectileClient_getTargetX",
    "LogicProjectileClient_getTargetY",
    "LogicProjectileData__getSpawnAreaEffect",
    "AreaEffectData__getRadius",
    "AreaEffectData__getActiveTimeMs",
    "LogicData_getName",
    "MapEditorScreen__updateCameraParameters",
    "MovieClip__getChildClipByName",
    "MovieClip__setChildVisible",
    "Screen__getDpiClass",
    "Screen__getHeight",
    "Screen__getWidth",
]

# Классы, для которых через vtable-путь ищем ctors
CTOR_CLASSES = [
    "LogicBattleModeClient", "BattleMode", "LogicGameObjectClient",
    "LogicProjectileData", "LogicCharacterData",
    "GameButton", "GameSelectableButton", "RadioButton",
    "Stage", "MovieClip", "MovieClipHelper", "DecoratedTextField",
    "Application", "Name", "Projectile", "ResourceManager",
    "StringTable", "MessageManager", "AllianceManager", "CombatHUD",
    "Character", "HomePage", "HomeScreen", "Screen",
    "AnalyticEvent", "CSVTable", "LogicTileMap",
    "LogicGameObjectManagerClient", "LogicProjectileClient",
    "LogicCharacterClient", "LogicCharacterClientOwn",
    "GameStateManager", "HomeMode", "Gui", "GUI",
    "StringTable", "GameObjectManager", "RenderSystem",
    "GameMain", "DecalManager",
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
    strings = cmdj(r2, "izj") or []
    idx = {}
    for s in strings:
        txt = (s.get("string") or s.get("text") or "").strip()
        if not txt:
            continue
        a = addr_of(s, base)
        if not a:
            continue
        idx.setdefault(txt, []).append(a)
    log("[*] strings: %d unique: %d" % (sum(len(v) for v in idx.values()), len(idx)))
    return idx


def get_sections(r2):
    return cmdj(r2, "iSj") or []


def pick_sections(sections):
    text = None
    data = []
    for s in sections:
        n = s.get("name", "") or ""
        p = s.get("perm", "") or ""
        va = s.get("vaddr", 0)
        sz = s.get("size", 0)
        if sz <= 0 or va <= 0:
            continue
        if ("__text" in n or ".text" in n) and "x" in p:
            text = (va, va + sz)
        elif "x" not in p and ("w" in p or "r" in p):
            if ("const" in n or "data" in n or "got" in n):
                data.append((va, sz, n))
    return text, data


def load_range(r2, va, size):
    CHUNK = 0x400000
    chunks = []
    addr = va
    end = va + size
    while addr < end:
        n = min(CHUNK, end - addr)
        hx = cmd(r2, "p8 %d @ 0x%x" % (n, addr)).strip()
        if not hx:
            return None
        try:
            chunks.append(bytes.fromhex(hx))
        except Exception:
            return None
        addr += n
    return b"".join(chunks)


def decode_chained(v):
    bind = (v >> 63) & 1
    next_ = (v >> 51) & 0xFFF
    target = v & 0x7FFFFFFFFFF
    return bind, next_, target


def is_adrp(w):
    return (w & 0x9F000000) == 0x90000000


def decode_adrp_imm(w, pc):
    immlo = (w >> 29) & 0x3
    immhi = (w >> 5) & 0x7FFFF
    imm = (immhi << 2) | immlo
    if imm & (1 << 20):
        imm -= (1 << 21)
    return (pc & ~0xFFF) + (imm << 12)


def is_add_imm64(w):
    return (w & 0xFF800000) == 0x91000000


def decode_add_imm(w):
    rd = w & 0x1F
    rn = (w >> 5) & 0x1F
    imm12 = (w >> 10) & 0xFFF
    sh = (w >> 22) & 1
    if sh:
        imm12 = imm12 << 12
    return (rd, rn, imm12)


def is_stp_x29_x30_preindex(w):
    return (w & 0xFFC07FFF) == 0xA9807BFD


def is_bl(w):
    return (w & 0xFC000000) == 0x94000000


def decode_bl_target(w, pc):
    offset = w & 0x3FFFFFF
    if offset & (1 << 25):
        offset -= (1 << 26)
    return pc + (offset << 2)


def scan_text(text, ts):
    n = len(text) // 4
    adrp_add = []
    bl_map = {}
    prologs = []
    i = 0
    while i < n:
        w = struct.unpack_from("<I", text, i * 4)[0]
        pc = ts + i * 4
        if is_stp_x29_x30_preindex(w):
            prologs.append(pc)
        if is_adrp(w):
            rd_adrp = w & 0x1F
            page = decode_adrp_imm(w, pc)
            for j in range(i + 1, min(i + 6, n)):
                w2 = struct.unpack_from("<I", text, j * 4)[0]
                if is_add_imm64(w2):
                    rd, rn, imm = decode_add_imm(w2)
                    if rd == rd_adrp and rn == rd_adrp:
                        adrp_add.append((pc, page + imm))
                        break
        if is_bl(w):
            bl_map[pc] = decode_bl_target(w, pc)
        i += 1
    return adrp_add, bl_map, prologs


def build_ptr_index(data_blobs, text_start, text_end):
    idx = {}
    for va, b in data_blobs:
        n = len(b) // 8
        for i in range(n):
            raw = struct.unpack_from("<Q", b, i * 8)[0]
            bind, nxt, target = decode_chained(raw)
            if bind:
                continue
            if text_start <= target < text_end:
                idx.setdefault(target, []).append(va + i * 8)
    return idx


def build_slot_to_target(ptr_idx):
    out = {}
    for tgt, slots in ptr_idx.items():
        for s in slots:
            out[s] = tgt
    return out


def expand_vtable(slot_to_target, anchor_slot, max_back=64, max_fwd=256):
    vt_start = anchor_slot
    cur = anchor_slot - 8
    for _ in range(max_back):
        if cur in slot_to_target:
            vt_start = cur
            cur -= 8
        else:
            break
    slots = []
    cur = vt_start
    for _ in range(max_fwd):
        if cur in slot_to_target:
            slots.append((cur, slot_to_target[cur]))
            cur += 8
        else:
            break
    if len(slots) < 2:
        return None
    return vt_start, slots


def analyze_at(text, ts, func_start, max_instr=300):
    off = (func_start - ts) // 4
    n = len(text) // 4
    if off < 0 or off >= n:
        return None
    n_bl = 0
    n_ret = 0
    for i in range(off, min(off + max_instr, n)):
        w = struct.unpack_from("<I", text, i * 4)[0]
        if is_bl(w):
            n_bl += 1
        elif w == 0xD65F03C0:
            n_ret += 1
    return {"n_bl": n_bl, "n_ret": n_ret}


def find_func_start(prologs_sorted, ia):
    import bisect
    idx = bisect.bisect_right(prologs_sorted, ia) - 1
    if idx >= 0:
        return prologs_sorted[idx]
    return ia & ~0xF


# --- parse target list ---

def parse_target(t):
    # "LogicBattleModeClient__update" -> ("LogicBattleModeClient", "update", "method")
    # "LogicBattleModeClient_update"  -> same
    # "StringCtor"                    -> ("String", "ctor", "ctor")
    # "GameButtonCtor"                -> ("GameButton", "ctor", "ctor")
    # "operator_new"                  -> ("", "operator_new", "operator")
    # "SetClientPrediction"           -> ("", "SetClientPrediction", "unknown")
    if t == "operator_new":
        return ("", "operator_new", "operator")
    m = re.match(r"^([A-Za-z][A-Za-z0-9]+?)Ctor$", t)
    if m:
        return (m.group(1), "ctor", "ctor")
    if "__" in t:
        parts = t.split("__", 1)
        cls, method = parts[0], parts[1]
        kind = "ctor" if method == cls else "method"
        return (cls, method, kind)
    if "_" in t:
        # first underscore where left part is a KnownClass-like name
        parts = t.split("_", 1)
        cls, method = parts[0], parts[1]
        kind = "ctor" if method == "ctor" else "method"
        return (cls, method, kind)
    return ("", t, "unknown")


def main():
    global _log_fh
    try:
        _log_fh = open(DETAIL, "w")
    except Exception:
        _log_fh = None

    log("=== find_offsets_r2 v15 (targets) ===")

    r2 = r2pipe.open(BIN, flags=["-2"])
    r2.cmd("e scr.color=0")
    r2.cmd("e asm.arch=arm")
    r2.cmd("e asm.bits=64")

    info = cmdj(r2, "ij")
    base = (info or {}).get("baddr", 0x100000000) or 0x100000000
    log("base: 0x%x" % base)

    str_index = build_string_index(r2, base)
    if not str_index:
        return

    # for fast string lookup: build lookup: substring "Class::method" -> addr
    # 49300 keys, using direct dict
    pattern_addr = {}
    for s, al in str_index.items():
        if "::" in s:
            # Ключ: "Class::method" без хвоста
            idx = s.find("::")
            if idx > 0:
                # отрезаем пробелы/префиксы после ::, до не-идентификатора
                rest = s[idx+2:]
                m = re.match(r"([A-Za-z_][A-Za-z0-9_]*)", rest)
                if m:
                    key = s[:idx+2] + m.group(1)
                    pattern_addr.setdefault(key, []).append(al[0])
    log("[*] string patterns 'Class::method': %d" % len(pattern_addr))

    sections = get_sections(r2)
    text_b, data_secs = pick_sections(sections)
    if not text_b:
        return
    ts, te = text_b
    log("[*] .text: 0x%x - 0x%x" % (ts, te))

    t0 = time.time()
    text = load_range(r2, ts, te - ts)
    log("[*] .text loaded %d bytes %.1fs" % (len(text or b""), time.time() - t0))
    if not text:
        return

    data_blobs = []
    for va, sz, n in data_secs:
        b = load_range(r2, va, sz)
        if b:
            data_blobs.append((va, b))
    log("[*] data %d bytes" % sum(len(b) for _, b in data_blobs))

    ptr_idx = build_ptr_index(data_blobs, ts, te)
    slot_to_target = build_slot_to_target(ptr_idx)
    log("[*] chained ptr idx: %d targets, %d slots" % (len(ptr_idx), sum(len(v) for v in ptr_idx.values())))

    t0 = time.time()
    adrp_add, bl_map, prologs = scan_text(text, ts)
    prologs_sorted = sorted(prologs)
    log("[*] adrp_add=%d bl=%d prologs=%d %.1fs"
        % (len(adrp_add), len(bl_map), len(prologs), time.time() - t0))

    # инверт: string_addr -> [pc_ref] (только строки, к которым мы уже искали)
    str_to_pc = {}
    target_set_strings = set()
    for al in str_index.values():
        for a in al:
            target_set_strings.add(a)
    for pc, tgt in adrp_add:
        if tgt in target_set_strings:
            str_to_pc.setdefault(tgt, []).append(pc)

    r2.quit()

    results = {}
    unresolved = []

    # 1) resolve methods via string "Class::method"
    for t in TARGETS:
        cls, method, kind = parse_target(t)
        if not method:
            unresolved.append((t, "no_method"))
            continue
        if kind == "unknown":
            # попробуем как есть в строках
            found = None
            for key in (t,):
                if key in str_index:
                    found = str_index[key]
                    break
            if found:
                pcs = str_to_pc.get(found[0], [])
                if pcs:
                    f = find_func_start(prologs_sorted, pcs[0])
                    results[t] = f - base
                    log("[%s] resolved via exact string -> 0x%x" % (t, f))
                    continue
            unresolved.append((t, "unknown"))
            continue

        # строим ключ "Class::method"
        patterns = []
        if cls:
            patterns.append(cls + "::" + method)
            patterns.append(cls + "::" + method + ":")
        patterns.append(method)

        addr = None
        chosen_key = None
        for pat in patterns:
            if pat in str_index:
                addr = str_index[pat][0]
                chosen_key = pat
                break
        if addr is None:
            # ищем префиксно
            for key, al in str_index.items():
                if key.startswith((cls + "::" + method) if cls else method):
                    addr = al[0]
                    chosen_key = key
                    break

        if addr is None:
            unresolved.append((t, "no_string"))
            continue

        pcs = str_to_pc.get(addr, [])
        if not pcs:
            unresolved.append((t, "no_xref"))
            continue

        f = find_func_start(prologs_sorted, pcs[0])
        results[t] = f - base
        log("[%s] str=%r -> func 0x%x" % (t, chosen_key[:50], f))

    # 2) ctors через vtable
    # для каждого класса ищем vtable и ctor
    ctor_out = {}
    for cls in CTOR_CLASSES:
        addrs = []
        for s, al in str_index.items():
            if s == cls or s.startswith(cls + "::") or ("::" + cls) in s \
               or s.startswith(cls + " ") or s.startswith(cls + "\t"):
                addrs.extend(al)
        if not addrs:
            continue
        anchor_funcs = set()
        for sa in addrs:
            for pc in str_to_pc.get(sa, []):
                anchor_funcs.add(find_func_start(prologs_sorted, pc))
        vt_starts = set()
        for af in anchor_funcs:
            slots = ptr_idx.get(af, [])
            for slot in slots[:3]:
                vt = expand_vtable(slot_to_target, slot)
                if vt:
                    vt_starts.add(vt[0])
                    break
        if not vt_starts:
            continue
        # ищем xref на vt через adrp+add
        for pc, tgt in adrp_add:
            if tgt in vt_starts:
                f = find_func_start(prologs_sorted, pc)
                info = analyze_at(text, ts, f)
                if info and info["n_bl"] > 0:
                    ctor_out[cls] = (f, tgt, info["n_bl"])
                    break
    log("[*] ctors resolved via vtable: %d" % len(ctor_out))

    # 3) записать
    try:
        with open(OUT, "w") as fh:
            fh.write("// Auto-generated offsets (v15)\n")
            fh.write("// Resolved: %d / %d targets, ctors: %d\n\n"
                     % (len(results), len(TARGETS), len(ctor_out)))
            fh.write("export const offsets = Object.freeze({\n")
            for t in TARGETS:
                if t in results:
                    fh.write("    %s: 0x%x,\n" % (t, results[t]))
                else:
                    fh.write("    // %s: unresolved\n" % t)
            fh.write("\n    // ctors via vtable\n")
            for cls, (f, vt, nbl) in ctor_out.items():
                fh.write("    %s__ctor: 0x%x,\n" % (cls, f - base))
            fh.write("});\n")
    except Exception as e:
        log("out error: %s" % e)

    try:
        with open(REPORT, "w") as fh:
            fh.write("# v15 target resolution\n")
            fh.write("# base=0x%x\n" % base)
            fh.write("# resolved=%d/%d\n\n" % (len(results), len(TARGETS)))
            for t in TARGETS:
                if t in results:
                    fh.write("%-55s 0x%08x\n" % (t, results[t]))
                else:
                    fh.write("%-55s UNRESOLVED\n" % t)
            fh.write("\n# ctors via vtable\n")
            for cls, (f, vt, nbl) in ctor_out.items():
                fh.write("%-40s ctor=0x%08x vt=0x%08x n_bl=%d\n"
                         % (cls, f - base, vt - base, nbl))
    except Exception as e:
        log("report error: %s" % e)

    log("[+] resolved %d/%d via strings, %d ctors via vtable"
        % (len(results), len(TARGETS), len(ctor_out)))
    log("[+] total %.1fs" % (time.time() - START))


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        log("FATAL: %s" % e)
        traceback.print_exc()