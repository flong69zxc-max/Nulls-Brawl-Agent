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
VT = os.path.join(WS, "vtables.js")
REPORT = os.path.join(WS, "offsets_report.txt")
DETAIL = os.path.join(WS, "ctors_detailed.log")
BUDGET = 1800
START = time.time()

TARGETS = [
    "String.ctor", "String.equals", "NativeFont.formatString",
    "StringTable.getString", "StringTable.getCurrentLanguageCode",
    "GUI.showPopup", "GUI.closePopup", "GUI.getInstance", "GUI.showFloater",
    "LoadingScreen.exit", "LoadingScreen.enter",
    "GenericPopup.ctor", "GenericPopup.addButton", "GenericPopup.addButton2",
    "GenericPopup.setTitle", "GenericPopup.onHudCloseButton",
    "ResourceManager.getMovieClip",
    "MovieClip.gotoAndStopFrameIndex", "MovieClip.setText",
    "MovieClip.setTextAndScaleIfNecessary", "MovieClip.getMovieClipByName",
    "MovieClip.getChildByName", "MovieClip.getTextFieldByName",
    "MovieClip.playOnce", "MovieClip.setChildVisible",
    "GameButton.ctor", "GameButton.buttonPressed",
    "Sprite.ctor", "Sprite.addChild",
    "PopupBase.ctor", "PopupBase.addCloseButton",
    "GameMain.getAccountIdCtor", "GameMain.getInstanceCtor",
    "GameMain.reloadGame", "GameMain.reloadGameAfterContentUpdate",
    "GameMain.getStaticVideoAdListener", "GameMain.getFps",
    "GameMain.update", "GameMain.draw",
    "Stage.addChild", "Stage.instance",
    "CountryItem.ctor", "DisplayObject.setXY", "DisplayObject.setPixelSnappedXY",
    "TextField.setText", "TextField.fetchFont",
    "DecoratedTextField.setupDecoratedTextField",
    "TeamSearchPopup.customButtonTapped",
    "GameInputField.ctor", "GameInputField.setScaleTextIfNeeded",
    "TextInput.setMaxTextLength", "InputField.getInputText",
    "CustomButton.setButtonListener",
    "GameSliderComponent.ctor", "GameSliderComponent.setValueBounds",
    "GameSliderComponent.setMaxValueLabel",
    "DropGUIContainer.ctor", "DropGUIContainer.addGameButton",
    "ResourceListener.addFile",
    "HomeMode.enter", "HomeMode.getPlayerName",
    "LogicDailyData.isBrawlPassPremiumUnlocked",
    "LogicDataTables.getColorGradientByName",
    "Application.copyString", "Application.openUrl",
    "PlayerInfo.refreshPlayerHeader", "HashTagCodeGenerator.toCode",
    "BandMailPopup.ctor",
    "BattleScreen.activateSkill", "BattleScreen.getClosestTargetForAutoshoot",
    "BattleScreen.update", "BattleScreen.isAfk",
    "BattleScreen.enter", "BattleScreen.exit", "BattleScreen.getInstance",
    "BattleScreen.updateCameraParameters",
    "BattleMode.getInstance", "BattleMode.getInstance2",
    "BattleMode.enter", "BattleMode.exit", "BattleMode.update",
    "LogicBattleModeClient.getOwnCharacter", "LogicBattleModeClient.update",
    "LogicBattleModeClient.setClientPredictionMoveTo",
    "LogicBattleModeClient.getOwnPlayerTeam", "LogicBattleModeClient.getTileMap",
    "LogicGameObjectClient.getX", "LogicGameObjectClient.getY",
    "LogicGameObjectClient.getGlobalID", "LogicGameObjectClient.getData",
    "LogicGameObjectClient.getTileX",
    "LogicProjectileData.getSpeed", "LogicProjectileData.getRadius",
    "LogicCharacterClient.getCharacterData",
    "LogicCharacterData.getCollisionRadius", "LogicData.getName",
    "LogicConfData.getIntValue", "LogicLong.getHigherInt", "LogicLong.getLowerInt",
    "LogicClientAvatar.isTutorialState",
    "ClientInput.ctor", "ClientInputManager.addInput",
    "MessageManager.receiveMessage", "MessageManager.sendMessage",
    "MessageManager.instance",
    "TeamJoinRequestPopup.ctor", "StartLoadingMessage.ctor",
    "SimpleWebView.ctor", "SimpleWebView.loadURL",
    "TeamMemberItem.setMember", "HomePage.ctor",
    "GameScreen.getLogicBattle",
    "GameObject.getTileX", "GameObject.getTileY", "GameObject.getTileZ",
    "GameObject.getLogic",
    "LogicTileData.getBaseExportName", "LogicTileMap.getTile",
    "LogicTileMap.getTile2", "LogicGameObjectManagerClient.getGameObjects",
    "RenderSystem.destroyTile",
    "Projectile.getAngle", "Projectile.update",
    "GameStateManager.getInstance",
    "TeamManager.onTeamMessage", "TeamManager.onTeamLeftMessage",
    "TeamManager.getInstance",
    "PlayerNameColorPopup.ctor", "DownloadedImage.ctor",
    "DownloadedImage.createFromLocalFile",
    "ScrollArea.ctor", "ScrollArea.enablePinching",
    "ScrollArea.enableHorizontalDrag", "ScrollArea.enableVerticalDrag",
    "ScrollArea.setAlignment", "ScrollArea.addContent",
    "AboutScreen.ctor", "CombatHUD.ctor",
    "Character.update", "Character.updateHealthBar",
    "FramerateManager.setSegment", "FramerateManager.sm_pInstance",
    "LogicPlayer.decode", "TeamMemberEntry.decode",
    "BattleLogPlayerEntry.ctor", "FriendEntry.decode",
    "PlayerProfile.decode", "AllianceMemberEntry.decode",
]

CLASSES = sorted(set(t.split(".")[0] for t in TARGETS))
SINGLETON_NAMES = ("getInstance", "instance", "sharedInstance", "getInstanceCtor")

# Известные приоритеты имён методов в vtable (порядок не важен, важны имена)
COMMON_METHODS = [
    "update", "draw", "enter", "exit", "activateSkill", "isAfk",
    "updateCameraParameters", "getClosestTargetForAutoshoot",
    "reloadGame", "getFps", "addChild",
    "addInput", "receiveMessage", "sendMessage",
    "getLogicBattle", "getMovieClip",
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


def is_str_x(w):
    return (w & 0xFFC00000) == 0xF9000000


def decode_bl_target(w, pc):
    offset = w & 0x3FFFFFF
    if offset & (1 << 25):
        offset -= (1 << 26)
    return pc + (offset << 2)


def scan_text(text, ts):
    n = len(text) // 4
    adrp_add = []
    prologs = []
    bl_src_target = {}
    str_locs = []  # (instr_addr, rt, rn, off)
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
            bl_src_target[pc] = decode_bl_target(w, pc)
        if is_str_x(w):
            rt = w & 0x1F
            rn = (w >> 5) & 0x1F
            imm12 = (w >> 10) & 0xFFF
            str_locs.append((pc, rt, rn, imm12 * 8))
        i += 1
    return adrp_add, prologs, bl_src_target, str_locs


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


def expand_vtable(slot_to_target, anchor_slot, max_back=64, max_fwd=1024):
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


def find_func_start(prologs_sorted, ia):
    import bisect
    idx = bisect.bisect_right(prologs_sorted, ia) - 1
    if idx >= 0:
        return prologs_sorted[idx]
    return ia & ~0xF


def analyze_at(text, ts, func_start, max_instr=400):
    off = (func_start - ts) // 4
    n = len(text) // 4
    if off < 0 or off >= n:
        return None
    n_bl = 0
    for i in range(off, min(off + max_instr, n)):
        w = struct.unpack_from("<I", text, i * 4)[0]
        if is_bl(w):
            n_bl += 1
        elif w == 0xD65F03C0:
            break
    return {"n_bl": n_bl}


def find_ctors_via_new(text, ts, text_bl_map, adrp_add_map, prologs_sorted, operator_new_addr):
    """
    Ищем функции, которые: (1) вызывают operator_new, (2) пишут vptr в [x0, #off].
    Возвращает список (func_start, vtable_addr).
    """
    result = []
    n = len(text) // 4
    for pc, tgt in text_bl_map.items():
        if tgt != operator_new_addr:
            continue
        f_start = find_func_start(prologs_sorted, pc)
        # смотрим 100 инструкций вперёд
        off = (f_start - ts) // 4
        has_new = True
        # после new: x0 = this, потом mov xN, x0, потом adrp+add vtable, потом str xN2,[xN,#off]
        # ищем любую adrp+add на данные, чей target потом записывается в [xReg]
        for i in range(off, min(off + 120, n)):
            w = struct.unpack_from("<I", text, i * 4)[0]
            ia = ts + i * 4
            if is_bl(w):
                t = decode_bl_target(w, ia)
                # ещё один operator_new или __stack_chk? не важно
            if is_adrp(w):
                rd_adrp = w & 0x1F
                page = decode_adrp_imm(w, ia)
                for j in range(i + 1, min(i + 4, n)):
                    w2 = struct.unpack_from("<I", text, j * 4)[0]
                    if is_add_imm64(w2):
                        rd, rn, imm = decode_add_imm(w2)
                        if rd == rd_adrp and rn == rd_adrp:
                            vt_addr = page + imm
                            # ищем str rd, [xR, #off] в следующих 3 инструкциях
                            for k in range(j + 1, min(j + 4, n)):
                                w3 = struct.unpack_from("<I", text, k * 4)[0]
                                if is_str_x(w3):
                                    rt = w3 & 0x1F
                                    if rt == rd:
                                        result.append((f_start, vt_addr))
                                        break
                            break
            # границы: дошли до ret без стра/адрп? прерываем
            if w == 0xD65F03C0 and i > off + 5:
                break
        # не дублировать
    # дедуп
    seen = set()
    out = []
    for f, vt in result:
        k = (f, vt)
        if k in seen:
            continue
        seen.add(k)
        out.append((f, vt))
    return out


def main():
    global _log_fh
    try:
        _log_fh = open(DETAIL, "w")
    except Exception:
        _log_fh = None

    log("=== find_offsets_r2 v19 ===")

    r2 = r2pipe.open(BIN, flags=["-2"])
    r2.cmd("e scr.color=0")
    r2.cmd("e asm.arch=arm")
    r2.cmd("e asm.bits=64")

    info = cmdj(r2, "ij")
    base = (info or {}).get("baddr", 0x100000000) or 0x100000000
    log("base: 0x%x" % base)

    str_index = build_string_index(r2, base)
    log("[*] strings: %d unique" % len(str_index))

    sections = get_sections(r2)
    text_b, data_secs = pick_sections(sections)
    if not text_b:
        return
    ts, te = text_b
    log("[*] .text: 0x%x - 0x%x" % (ts, te))

    t0 = time.time()
    text = load_range(r2, ts, te - ts)
    log("[*] .text %d bytes %.1fs" % (len(text or b""), time.time() - t0))
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
    log("[*] ptr idx: %d targets, %d slots"
        % (len(ptr_idx), sum(len(v) for v in ptr_idx.values())))

    t0 = time.time()
    adrp_add, prologs, bl_map, str_locs = scan_text(text, ts)
    prologs_sorted = sorted(prologs)
    log("[*] adrp_add=%d prologs=%d bl=%d str=%d %.1fs"
        % (len(adrp_add), len(prologs), len(bl_map), len(str_locs),
           time.time() - t0))

    # оператор new — ищем по строке symbol
    operator_new_addr = None
    for cand in ("_Znwm", "_ZnwmSt11align_val_t", "operator.new",
                 "sym.imp._Znwm", "imp._Znwm"):
        for s, al in str_index.items():
            if cand in s:
                # это строка, xref на неё — не полезно
                pass
    # ищем call на plt-thunk: bl в .plt (первые 0x10000 .text обычно не .plt)
    # но проще: plts в .text содержат adrp+ldr+br; пропускаем
    # берём адрес _Znwm из импортов
    iij = cmdj(r2, "iij")
    if iij:
        for imp in iij:
            name = imp.get("name", "")
            if name in ("_Znwm", "_ZnwmSt11align_val_t", "operator new",
                        "__Znwm", "__ZnwmSt11align_val_t"):
                operator_new_addr = imp.get("plt", 0) or imp.get("vaddr", 0)
                log("[*] operator_new %s @ 0x%x" % (name, operator_new_addr))
                break
    if not operator_new_addr:
        # fallback: r2 symbol
        for cand in ("sym.imp._Znwm", "sym.imp.operator.new",
                     "sym.imp._ZnwmSt11align_val_t"):
            try:
                v = cmd(r2, "is~%s" % cand).strip()
                if v:
                    m = re.search(r"0x([0-9a-f]+)", v)
                    if m:
                        operator_new_addr = int(m.group(1), 16)
                        log("[*] operator_new via is: %s -> 0x%x"
                            % (cand, operator_new_addr))
                        break
            except Exception:
                pass

    # Class::method funcs
    str_addr_to_pc = {}
    for pc, tgt in adrp_add:
        str_addr_to_pc.setdefault(tgt, []).append(pc)

    class_method_funcs = {}
    for s, al in str_index.items():
        idx = s.find("::")
        if idx <= 0:
            continue
        cls = s[:idx]
        if not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", cls):
            continue
        rest = s[idx+2:]
        m = re.match(r"([A-Za-z_][A-Za-z0-9_]*)", rest)
        if not m:
            continue
        key = cls + "::" + m.group(1)
        if key in class_method_funcs:
            continue
        for sa in al:
            pcs = str_addr_to_pc.get(sa, [])
            if pcs:
                class_method_funcs[key] = find_func_start(prologs_sorted, pcs[0])
                break
    log("[*] Class::method funcs: %d" % len(class_method_funcs))

    # vtable по классам: через anchor_funcs (строки класса)
    class_to_vtable = {}
    all_vt_starts = set()
    for cls in CLASSES:
        anchor_funcs = set()
        for key, f in class_method_funcs.items():
            if key.startswith(cls + "::"):
                anchor_funcs.add(f)
        for s, al in str_index.items():
            if s == cls or s.startswith(cls + "::"):
                for sa in al:
                    for pc in str_addr_to_pc.get(sa, []):
                        anchor_funcs.add(find_func_start(prologs_sorted, pc))
        if not anchor_funcs:
            continue
        best = None
        for af in anchor_funcs:
            for slot in ptr_idx.get(af, [])[:5]:
                vt = expand_vtable(slot_to_target, slot)
                if vt and (best is None or len(vt[1]) > len(best[1])):
                    best = vt
        if best:
            class_to_vtable[cls] = best
            all_vt_starts.add(best[0])
    log("[*] class→vtable (via anchors): %d" % len(class_to_vtable))

    # vtable → класс по слоту-якорю (метод, который есть в Class::method)
    vt_to_class = {}
    for cls, (vt_start, slots) in class_to_vtable.items():
        vt_to_class[vt_start] = cls

    # ctor через xref на vtable
    vt_to_ctors = {}
    for pc, tgt in adrp_add:
        if tgt in all_vt_starts:
            f = find_func_start(prologs_sorted, pc)
            vt_to_ctors.setdefault(tgt, set()).add(f)
    log("[*] vtables with ctor xref: %d" % len(vt_to_ctors))

    # ctor через operator_new → запись vptr
    if operator_new_addr:
        log("[*] scanning for ctors via operator_new ...")
        ctors_new = find_ctors_via_new(text, ts, bl_map, None,
                                       prologs_sorted, operator_new_addr)
        log("[*] ctors via new: %d" % len(ctors_new))
        for f, vt in ctors_new:
            # смотрим, знаем ли мы vt (это может быть начало vtable)
            if vt in vt_to_class:
                continue
            # расширим vtable от vt и посмотрим, есть ли anchor Class::method
            vt2 = expand_vtable(slot_to_target, vt)
            if not vt2:
                continue
            # у vtable2 ищем якорь-функцию, которая имеет Class::method
            matched_cls = None
            for sa, tf in vt2[1][:80]:
                # sa — адрес в vtable, tf — цель
                for k, fa in class_method_funcs.items():
                    if fa == tf:
                        matched_cls = k.split("::", 1)[0]
                        break
                if matched_cls:
                    break
            if matched_cls:
                if matched_cls not in class_to_vtable:
                    class_to_vtable[matched_cls] = vt2
                    vt_to_class[vt2[0]] = matched_cls
                    all_vt_starts.add(vt2[0])
                    vt_to_ctors.setdefault(vt2[0], set()).add(f)
    log("[*] after new: class→vtable=%d" % len(class_to_vtable))

    # resolve targets
    results = {}
    unresolved = []
    for t in TARGETS:
        if "." not in t:
            unresolved.append((t, "no_dot"))
            continue
        cls, method = t.split(".", 1)

        if method == "ctor":
            vt = class_to_vtable.get(cls)
            if vt:
                for c in vt_to_ctors.get(vt[0], set()):
                    info = analyze_at(text, ts, c)
                    if info and info["n_bl"] >= 3:
                        results[t] = c - base
                        break
            if t in results:
                continue
            for pattern in (cls + "::" + cls, cls + "::ctor"):
                if pattern in class_method_funcs:
                    results[t] = class_method_funcs[pattern] - base
                    break
            if t in results:
                continue
            unresolved.append((t, "no_ctor"))
            continue

        if method in SINGLETON_NAMES:
            for cand in (cls + "::" + method, cls + "::getInstance",
                         cls + "::instance", cls + "::sharedInstance"):
                if cand in class_method_funcs:
                    results[t] = class_method_funcs[cand] - base
                    break
            if t in results:
                continue
            # через vtable: getInstance часто слот ~1-3
            vt = class_to_vtable.get(cls)
            if vt:
                # нет, getInstance — статик, не в vtable
                pass
            unresolved.append((t, "no_singleton"))
            continue

        # обычный method
        cand = cls + "::" + method
        if cand in class_method_funcs:
            results[t] = class_method_funcs[cand] - base
            continue
        found = None
        for k, f in class_method_funcs.items():
            if k.startswith(cls + "::") and \
               k[len(cls)+2:].lower() == method.lower():
                found = f
                break
        if found:
            results[t] = found - base
            continue
        for k, f in class_method_funcs.items():
            if k.startswith(cls + "::" + method):
                found = f
                break
        if found:
            results[t] = found - base
            continue

        # через vtable: если у класса есть vtable, метод должен быть в слотах
        # но у нас нет имён слотов. Однако мы знаем методы, которые мы уже
        # нашли по строкам — их адреса в vtable. Позиции сохраняются между
        # классами с общим базовым классом. Извлечём «шаблон» из одного
        # класса с известными именами.

        unresolved.append((t, "no_match"))

    r2.quit()

    # запись в SCRE-формате
    try:
        with open(OUT, "w") as fh:
            fh.write("// v19 auto-resolved (SCRE format)\n")
            fh.write("// base=0x%x\n" % base)
            fh.write("// resolved=%d/%d\n\n" % (len(results), len(TARGETS)))
            fh.write("export const offsets = Object.freeze({\n")
            for t in TARGETS:
                js_key = t.replace(".", "_")
                if t in results:
                    fh.write("    %s: 0x%x,\n" % (js_key, results[t]))
                else:
                    fh.write("    // %s: unresolved\n" % js_key)
            fh.write("\n    // --- ctors via vtable ---\n")
            for cls in sorted(class_to_vtable):
                vt_start, slots = class_to_vtable[cls]
                for c in vt_to_ctors.get(vt_start, set()):
                    info = analyze_at(text, ts, c)
                    if info and info["n_bl"] >= 3:
                        fh.write("    %s_ctor: 0x%x,\n" % (cls, c - base))
                        break
            fh.write("\n    // --- vtable addresses ---\n")
            for cls in sorted(class_to_vtable):
                vt_start, slots = class_to_vtable[cls]
                fh.write("    VTABLE_%s: 0x%x,\n"
                         % (cls.upper(), vt_start - base))
            fh.write("});\n")
    except Exception as e:
        log("out: %s" % e)

    try:
        with open(VT, "w") as fh:
            fh.write("// vtables per class\n")
            for cls in sorted(class_to_vtable):
                vt_start, slots = class_to_vtable[cls]
                fh.write("\n%s: 0x%x slots=%d\n"
                         % (cls, vt_start - base, len(slots)))
                for i, (sa, ta) in enumerate(slots[:64]):
                    fh.write("  [%2d] 0x%08x\n" % (i, ta - base))
    except Exception as e:
        log("vt: %s" % e)

    try:
        with open(REPORT, "w") as fh:
            fh.write("# v19 report\n")
            fh.write("# base=0x%x\n" % base)
            fh.write("# resolved=%d/%d\n\n" % (len(results), len(TARGETS)))
            fh.write("## resolved:\n")
            for t in TARGETS:
                if t in results:
                    fh.write("  %-55s 0x%08x\n" % (t, results[t]))
            fh.write("\n## unresolved:\n")
            for t, why in unresolved:
                fh.write("  %-55s (%s)\n" % (t, why))
            fh.write("\n## class→vtable:\n")
            for cls in sorted(class_to_vtable):
                vt_start, slots = class_to_vtable[cls]
                fh.write("%-40s vt=0x%08x slots=%d\n"
                         % (cls, vt_start - base, len(slots)))
    except Exception as e:
        log("report: %s" % e)

    log("[+] resolved %d/%d" % (len(results), len(TARGETS)))
    log("[+] wrote %s, %s, %s" % (OUT, VT, REPORT))
    log("[+] total %.1fs" % (time.time() - START))


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        log("FATAL: %s" % e)
        traceback.print_exc()