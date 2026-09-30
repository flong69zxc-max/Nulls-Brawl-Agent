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

# (key, kind_hint)
# kind_hint: method | ctor | singleton | global | skip
TARGETS = [
    ("String.ctor", "ctor"),
    ("String.equals", "method"),
    ("NativeFont.formatString", "method"),
    ("StringTable.getString", "method"),
    ("StringTable.getCurrentLanguageCode", "method"),
    ("GUI.showPopup", "method"),
    ("GUI.closePopup", "method"),
    ("GUI.getInstance", "singleton"),
    ("GUI.showFloater", "method"),
    ("LoadingScreen.exit", "method"),
    ("LoadingScreen.enter", "method"),
    ("GenericPopup.ctor", "ctor"),
    ("GenericPopup.addButton", "method"),
    ("GenericPopup.addButton2", "method"),
    ("GenericPopup.setTitle", "method"),
    ("GenericPopup.onHudCloseButton", "method"),
    ("ResourceManager.getMovieClip", "method"),
    ("MovieClip.gotoAndStopFrameIndex", "method"),
    ("MovieClip.setText", "method"),
    ("MovieClip.setTextAndScaleIfNecessary", "method"),
    ("MovieClip.getMovieClipByName", "method"),
    ("MovieClip.getChildByName", "method"),
    ("MovieClip.getTextFieldByName", "method"),
    ("MovieClip.playOnce", "method"),
    ("MovieClip.setChildVisible", "method"),
    ("GameButton.ctor", "ctor"),
    ("GameButton.buttonPressed", "method"),
    ("Sprite.ctor", "ctor"),
    ("Sprite.addChild", "method"),
    ("PopupBase.ctor", "ctor"),
    ("PopupBase.addCloseButton", "method"),
    ("GameMain.getAccountIdCtor", "ctor"),
    ("GameMain.getInstanceCtor", "ctor"),
    ("GameMain.reloadGame", "method"),
    ("GameMain.reloadGameAfterContentUpdate", "method"),
    ("GameMain.getStaticVideoAdListener", "method"),
    ("GameMain.getFps", "method"),
    ("GameMain.update", "method"),
    ("GameMain.draw", "method"),
    ("Stage.addChild", "method"),
    ("Stage.instance", "singleton"),
    ("CountryItem.ctor", "ctor"),
    ("DisplayObject.setXY", "method"),
    ("DisplayObject.setPixelSnappedXY", "method"),
    ("TextField.setText", "method"),
    ("TextField.fetchFont", "method"),
    ("DecoratedTextField.setupDecoratedTextField", "method"),
    ("TeamSearchPopup.customButtonTapped", "method"),
    ("GameInputField.ctor", "ctor"),
    ("GameInputField.setScaleTextIfNeeded", "method"),
    ("TextInput.setMaxTextLength", "method"),
    ("InputField.getInputText", "method"),
    ("CustomButton.setButtonListener", "method"),
    ("GameSliderComponent.ctor", "ctor"),
    ("GameSliderComponent.setValueBounds", "method"),
    ("GameSliderComponent.setMaxValueLabel", "method"),
    ("DropGUIContainer.ctor", "ctor"),
    ("DropGUIContainer.addGameButton", "method"),
    ("ResourceListener.addFile", "method"),
    ("HomeMode.enter", "method"),
    ("HomeMode.getPlayerName", "method"),
    ("LogicDailyData.isBrawlPassPremiumUnlocked", "method"),
    ("LogicDataTables.getColorGradientByName", "method"),
    ("Application.copyString", "method"),
    ("Application.openUrl", "method"),
    ("PlayerInfo.refreshPlayerHeader", "method"),
    ("HashTagCodeGenerator.toCode", "method"),
    ("BandMailPopup.ctor", "ctor"),
    ("BattleScreen.activateSkill", "method"),
    ("BattleScreen.getClosestTargetForAutoshoot", "method"),
    ("BattleScreen.update", "method"),
    ("BattleScreen.isAfk", "method"),
    ("BattleScreen.enter", "method"),
    ("BattleScreen.exit", "method"),
    ("BattleScreen.getInstance", "singleton"),
    ("BattleScreen.updateCameraParameters", "method"),
    ("BattleMode.getInstance", "singleton"),
    ("BattleMode.getInstance2", "singleton"),
    ("BattleMode.enter", "method"),
    ("BattleMode.exit", "method"),
    ("BattleMode.update", "method"),
    ("LogicBattleModeClient.getOwnCharacter", "method"),
    ("LogicBattleModeClient.update", "method"),
    ("LogicBattleModeClient.setClientPredictionMoveTo", "method"),
    ("LogicBattleModeClient.getOwnPlayerTeam", "method"),
    ("LogicBattleModeClient.getTileMap", "method"),
    ("LogicGameObjectClient.getX", "method"),
    ("LogicGameObjectClient.getY", "method"),
    ("LogicGameObjectClient.getGlobalID", "method"),
    ("LogicGameObjectClient.getData", "method"),
    ("LogicGameObjectClient.getTileX", "method"),
    ("LogicProjectileData.getSpeed", "method"),
    ("LogicProjectileData.getRadius", "method"),
    ("LogicCharacterClient.getCharacterData", "method"),
    ("LogicCharacterData.getCollisionRadius", "method"),
    ("LogicData.getName", "method"),
    ("LogicConfData.getIntValue", "method"),
    ("LogicLong.getHigherInt", "method"),
    ("LogicLong.getLowerInt", "method"),
    ("LogicClientAvatar.isTutorialState", "method"),
    ("ClientInput.ctor", "ctor"),
    ("ClientInputManager.addInput", "method"),
    ("MessageManager.receiveMessage", "method"),
    ("MessageManager.sendMessage", "method"),
    ("MessageManager.instance", "singleton"),
    ("TeamJoinRequestPopup.ctor", "ctor"),
    ("StartLoadingMessage.ctor", "ctor"),
    ("SimpleWebView.ctor", "ctor"),
    ("SimpleWebView.loadURL", "method"),
    ("TeamMemberItem.setMember", "method"),
    ("HomePage.ctor", "ctor"),
    ("GameScreen.getLogicBattle", "method"),
    ("GameObject.getTileX", "method"),
    ("GameObject.getTileY", "method"),
    ("GameObject.getTileZ", "method"),
    ("GameObject.getLogic", "method"),
    ("LogicTileData.getBaseExportName", "method"),
    ("LogicTileMap.getTile", "method"),
    ("LogicTileMap.getTile2", "method"),
    ("LogicGameObjectManagerClient.getGameObjects", "method"),
    ("RenderSystem.destroyTile", "method"),
    ("Projectile.getAngle", "method"),
    ("Projectile.update", "method"),
    ("GameStateManager.getInstance", "singleton"),
    ("TeamManager.onTeamMessage", "method"),
    ("TeamManager.onTeamLeftMessage", "method"),
    ("TeamManager.getInstance", "singleton"),
    ("PlayerNameColorPopup.ctor", "ctor"),
    ("DownloadedImage.ctor", "ctor"),
    ("DownloadedImage.createFromLocalFile", "method"),
    ("ScrollArea.ctor", "ctor"),
    ("ScrollArea.enablePinching", "method"),
    ("ScrollArea.enableHorizontalDrag", "method"),
    ("ScrollArea.enableVerticalDrag", "method"),
    ("ScrollArea.setAlignment", "method"),
    ("ScrollArea.addContent", "method"),
    ("AboutScreen.ctor", "ctor"),
    ("CombatHUD.ctor", "ctor"),
    ("Character.update", "method"),
    ("Character.updateHealthBar", "method"),
    ("FramerateManager.setSegment", "method"),
    ("FramerateManager.sm_pInstance", "global"),
    ("LogicPlayer.decode", "method"),
    ("TeamMemberEntry.decode", "method"),
    ("BattleLogPlayerEntry.ctor", "ctor"),
    ("FriendEntry.decode", "method"),
    ("PlayerProfile.decode", "method"),
    ("AllianceMemberEntry.decode", "method"),
    ("Messages.ClientHelloMessage", "skip"),
    ("Messages.LoginMessage", "skip"),
    ("Messages.TeamMemberStatusMessage", "skip"),
    ("Messages.PlayAgainMessage_PlayAgainMessage", "skip"),
    ("Messages.TeamChatMessage_encode", "skip"),
    ("Messages.TeamChatMessage", "skip"),
    ("Messages.TeamInviteMessage", "skip"),
    ("Messages.TeamAllianceMemberInviteMessage", "skip"),
    ("Messages.StartSpectateMessage", "skip"),
    ("Messages.PlayerStatusMessage", "skip"),
    ("Messages.LatencyTestMessage", "skip"),
    ("Messages.SendLatencyTestResultsMessage", "skip"),
    ("Other.ModifierOffset", "skip"),
    ("Other.EmojiAnimations", "skip"),
    ("Other.unknownStringOffset", "skip"),
    ("Other.onclickMultiLineInputOkFunc", "skip"),
    ("Other.onclickInputOkFunc", "skip"),
    ("Other.BattleEndScreen_enterAddr", "skip"),
    ("Other.NativeDialog", "skip"),
    ("Other.CustomInputOffset1", "skip"),
    ("Other.CustomInputOffset2", "skip"),
    ("Other.SpectateWithIDOffset1", "skip"),
    ("Other.SpectateWithIDOffset2", "skip"),
]

# Все классы, для которых ищем vtable/ctor
CLASSES = sorted(set([t[0].split(".")[0] for t in TARGETS if "." in t[0]]))

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


def decode_bl_target(w, pc):
    offset = w & 0x3FFFFFF
    if offset & (1 << 25):
        offset -= (1 << 26)
    return pc + (offset << 2)


def scan_text(text, ts):
    n = len(text) // 4
    adrp_add = []
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
        i += 1
    return adrp_add, prologs


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


def expand_vtable(slot_to_target, anchor_slot, max_back=64, max_fwd=512):
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
    for i in range(off, min(off + max_instr, n)):
        w = struct.unpack_from("<I", text, i * 4)[0]
        if is_bl(w):
            n_bl += 1
        elif w == 0xD65F03C0:
            break
    return {"n_bl": n_bl}


def find_func_start(prologs_sorted, ia):
    import bisect
    idx = bisect.bisect_right(prologs_sorted, ia) - 1
    if idx >= 0:
        return prologs_sorted[idx]
    return ia & ~0xF


def main():
    global _log_fh
    try:
        _log_fh = open(DETAIL, "w")
    except Exception:
        _log_fh = None

    log("=== find_offsets_r2 v17 (user targets) ===")

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
        log("[!] no .text")
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
    adrp_add, prologs = scan_text(text, ts)
    prologs_sorted = sorted(prologs)
    log("[*] adrp_add=%d prologs=%d %.1fs"
        % (len(adrp_add), len(prologs), time.time() - t0))

    # построим str_addr → [pc] один раз
    str_addr_to_pc = {}
    for pc, tgt in adrp_add:
        str_addr_to_pc.setdefault(tgt, []).append(pc)

    # индекс Class::method из строк
    class_method_funcs = {}  # "Class::method" -> func_addr
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
        method = m.group(1)
        key = cls + "::" + method
        if key in class_method_funcs:
            continue
        for sa in al:
            pcs = str_addr_to_pc.get(sa, [])
            if pcs:
                f = find_func_start(prologs_sorted, pcs[0])
                class_method_funcs[key] = f
                break
    log("[*] Class::method funcs: %d" % len(class_method_funcs))

    # vtable по классам
    class_to_vtable = {}
    all_vt_starts = set()
    for cls in CLASSES:
        # strings of class
        anchor_funcs = set()
        for key, f in class_method_funcs.items():
            if key.startswith(cls + "::"):
                anchor_funcs.add(f)
        # strings exact match (asserts)
        for s, al in str_index.items():
            if s == cls or s.startswith(cls + "::"):
                for sa in al:
                    for pc in str_addr_to_pc.get(sa, []):
                        anchor_funcs.add(find_func_start(prologs_sorted, pc))
        if not anchor_funcs:
            continue
        best = None
        for af in anchor_funcs:
            for slot in ptr_idx.get(af, [])[:3]:
                vt = expand_vtable(slot_to_target, slot)
                if vt and (best is None or len(vt[1]) > len(best[1])):
                    best = vt
        if best:
            class_to_vtable[cls] = best
            all_vt_starts.add(best[0])
    log("[*] class→vtable: %d" % len(class_to_vtable))

    # xref на vtable → ctor
    vt_to_ctors = {}
    for pc, tgt in adrp_add:
        if tgt in all_vt_starts:
            f = find_func_start(prologs_sorted, pc)
            vt_to_ctors.setdefault(tgt, set()).add(f)
    log("[*] vtables with ctor xref: %d" % len(vt_to_ctors))

    # resolve каждого таргета
    results = {}
    unresolved = []
    for key, kind in TARGETS:
        if kind == "skip":
            unresolved.append((key, "skip"))
            continue
        if "." not in key:
            unresolved.append((key, "no_dot"))
            continue
        cls, method = key.split(".", 1)

        # ctor → через vtable
        if kind == "ctor" or method == "ctor":
            vt = class_to_vtable.get(cls)
            if vt:
                ctors = vt_to_ctors.get(vt[0], set())
                if ctors:
                    best_ctor = None
                    best_score = -1
                    for c in ctors:
                        info = analyze_at(text, ts, c)
                        if not info:
                            continue
                        if info["n_bl"] > best_score:
                            best_score = info["n_bl"]
                            best_ctor = c
                    if best_ctor is not None:
                        results[key] = best_ctor - base
                        continue
            # fallback: строка Class::Class
            for pattern in (cls + "::" + cls, cls + "::ctor"):
                if pattern in class_method_funcs:
                    results[key] = class_method_funcs[pattern] - base
                    break
            if key in results:
                continue
            unresolved.append((key, "no_ctor"))
            continue

        # singleton → строка Class::getInstance / instance / sharedInstance
        if kind == "singleton":
            for cand in (cls + "::getInstance", cls + "::instance",
                         cls + "::sharedInstance", cls + "::getInstanceCtor"):
                if cand in class_method_funcs:
                    results[key] = class_method_funcs[cand] - base
                    break
            if key in results:
                continue
            unresolved.append((key, "no_singleton"))
            continue

        # global (поле-указатель) — ищем через строку Class::method
        if kind == "global":
            for cand in (cls + "::" + method, cls + "::get" + method,
                         cls + "::instance"):
                if cand in class_method_funcs:
                    results[key] = class_method_funcs[cand] - base
                    break
            if key in results:
                continue
            unresolved.append((key, "no_global"))
            continue

        # method → строка Class::method
        if kind == "method":
            # точное совпадение
            cand = cls + "::" + method
            if cand in class_method_funcs:
                results[key] = class_method_funcs[cand] - base
                continue
            # перебор похожих: setTextAndScaleIfNecessary → setTextAndScale...
            found = None
            for k, f in class_method_funcs.items():
                if k.startswith(cls + "::") and \
                   k[len(cls)+2:].lower() == method.lower():
                    found = f
                    break
            if found:
                results[key] = found - base
                continue
            # префиксное
            for k, f in class_method_funcs.items():
                if k.startswith(cls + "::" + method):
                    found = f
                    break
            if found:
                results[key] = found - base
                continue
            unresolved.append((key, "no_string_match"))
            continue

        unresolved.append((key, "unknown_kind"))

    r2.quit()

    # пишем offsets_resolved.js
    try:
        with open(OUT, "w") as fh:
            fh.write("// v17 auto-resolved\n")
            fh.write("// base=0x%x\n" % base)
            fh.write("// resolved=%d/%d\n\n" % (len(results), len(TARGETS)))
            fh.write("export const offsets = Object.freeze({\n")
            for key, _ in TARGETS:
                if key in results:
                    fh.write("    %s: 0x%x,\n" % (key.replace(".", "_"), results[key]))
                else:
                    fh.write("    // %s: unresolved\n" % key.replace(".", "_"))
            fh.write("});\n")
    except Exception as e:
        log("out: %s" % e)

    # vtables.js
    try:
        with open(VT, "w") as fh:
            fh.write("// vtable slots per class (rva)\n")
            fh.write("export const vtables = Object.freeze({\n")
            for cls in sorted(class_to_vtable):
                vt_start, slots = class_to_vtable[cls]
                fh.write("  %s: {\n" % cls)
                fh.write("    addr: 0x%x,\n" % (vt_start - base))
                fh.write("    slots: [\n")
                for i, (sa, ta) in enumerate(slots):
                    fh.write("      0x%x, // [%d]\n" % (ta - base, i))
                fh.write("    ],\n  },\n")
            fh.write("});\n")
    except Exception as e:
        log("vtables: %s" % e)

    # отчёт
    try:
        with open(REPORT, "w") as fh:
            fh.write("# v17 report\n")
            fh.write("# base=0x%x\n" % base)
            fh.write("# resolved=%d/%d\n\n" % (len(results), len(TARGETS)))
            fh.write("## resolved:\n")
            for key, _ in TARGETS:
                if key in results:
                    fh.write("  %-55s 0x%08x\n" % (key, results[key]))
            fh.write("\n## unresolved:\n")
            for key, why in unresolved:
                fh.write("  %-55s (%s)\n" % (key, why))
            fh.write("\n## vtables:\n")
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