#!/usr/bin/env python3
import os, sys, time, struct, re, bisect, traceback
import r2pipe

WS = os.environ.get("GITHUB_WORKSPACE", "/tmp")
BIN = os.environ.get("R2_BIN", "/tmp/brawl_bin")
OUT = os.path.join(WS, "offsets_resolved.js")
LOG = os.path.join(WS, "r2.log")
START = time.time()

TARGETS = [
"String.ctor","String.equals","NativeFont.formatString",
"StringTable.getString","StringTable.getCurrentLanguageCode",
"GUI.showPopup","GUI.closePopup","GUI.getInstance","GUI.showFloater",
"LoadingScreen.exit","LoadingScreen.enter",
"GenericPopup.ctor","GenericPopup.addButton","GenericPopup.addButton2",
"GenericPopup.setTitle","GenericPopup.onHudCloseButton",
"ResourceManager.getMovieClip",
"MovieClip.gotoAndStopFrameIndex","MovieClip.setText",
"MovieClip.setTextAndScaleIfNecessary","MovieClip.getMovieClipByName",
"MovieClip.getChildByName","MovieClip.getTextFieldByName",
"MovieClip.playOnce","MovieClip.setChildVisible",
"GameButton.ctor","GameButton.buttonPressed",
"Sprite.ctor","Sprite.addChild",
"PopupBase.ctor","PopupBase.addCloseButton",
"GameMain.getAccountIdCtor","GameMain.getInstanceCtor",
"GameMain.reloadGame","GameMain.reloadGameAfterContentUpdate",
"GameMain.getStaticVideoAdListener","GameMain.getFps",
"GameMain.update","GameMain.draw",
"Stage.addChild","Stage.instance",
"CountryItem.ctor","DisplayObject.setXY","DisplayObject.setPixelSnappedXY",
"TextField.setText","TextField.fetchFont",
"DecoratedTextField.setupDecoratedTextField",
"TeamSearchPopup.customButtonTapped",
"GameInputField.ctor","GameInputField.setScaleTextIfNeeded",
"TextInput.setMaxTextLength","InputField.getInputText",
"CustomButton.setButtonListener",
"GameSliderComponent.ctor","GameSliderComponent.setValueBounds",
"GameSliderComponent.setMaxValueLabel",
"DropGUIContainer.ctor","DropGUIContainer.addGameButton",
"ResourceListener.addFile",
"HomeMode.enter","HomeMode.getPlayerName",
"LogicDailyData.isBrawlPassPremiumUnlocked",
"LogicDataTables.getColorGradientByName",
"Application.copyString","Application.openUrl",
"PlayerInfo.refreshPlayerHeader","HashTagCodeGenerator.toCode",
"BandMailPopup.ctor",
"BattleScreen.activateSkill","BattleScreen.getClosestTargetForAutoshoot",
"BattleScreen.update","BattleScreen.isAfk",
"BattleScreen.enter","BattleScreen.exit","BattleScreen.getInstance",
"BattleScreen.updateCameraParameters",
"BattleMode.getInstance","BattleMode.getInstance2",
"BattleMode.enter","BattleMode.exit","BattleMode.update",
"LogicBattleModeClient.getOwnCharacter","LogicBattleModeClient.update",
"LogicBattleModeClient.setClientPredictionMoveTo",
"LogicBattleModeClient.getOwnPlayerTeam","LogicBattleModeClient.getTileMap",
"LogicGameObjectClient.getX","LogicGameObjectClient.getY",
"LogicGameObjectClient.getGlobalID","LogicGameObjectClient.getData",
"LogicGameObjectClient.getTileX",
"LogicProjectileData.getSpeed","LogicProjectileData.getRadius",
"LogicCharacterClient.getCharacterData",
"LogicCharacterData.getCollisionRadius","LogicData.getName",
"LogicConfData.getIntValue","LogicLong.getHigherInt","LogicLong.getLowerInt",
"LogicClientAvatar.isTutorialState",
"ClientInput.ctor","ClientInputManager.addInput",
"MessageManager.receiveMessage","MessageManager.sendMessage",
"MessageManager.instance",
"TeamJoinRequestPopup.ctor","StartLoadingMessage.ctor",
"SimpleWebView.ctor","SimpleWebView.loadURL",
"TeamMemberItem.setMember","HomePage.ctor",
"GameScreen.getLogicBattle",
"GameObject.getTileX","GameObject.getTileY","GameObject.getTileZ",
"GameObject.getLogic",
"LogicTileData.getBaseExportName","LogicTileMap.getTile",
"LogicTileMap.getTile2","LogicGameObjectManagerClient.getGameObjects",
"RenderSystem.destroyTile",
"Projectile.getAngle","Projectile.update",
"GameStateManager.getInstance",
"TeamManager.onTeamMessage","TeamManager.onTeamLeftMessage",
"TeamManager.getInstance",
"PlayerNameColorPopup.ctor","DownloadedImage.ctor",
"DownloadedImage.createFromLocalFile",
"ScrollArea.ctor","ScrollArea.enablePinching",
"ScrollArea.enableHorizontalDrag","ScrollArea.enableVerticalDrag",
"ScrollArea.setAlignment","ScrollArea.addContent",
"AboutScreen.ctor","CombatHUD.ctor",
"Character.update","Character.updateHealthBar",
"FramerateManager.setSegment","FramerateManager.sm_pInstance",
"LogicPlayer.decode","TeamMemberEntry.decode",
"BattleLogPlayerEntry.ctor","FriendEntry.decode",
"PlayerProfile.decode","AllianceMemberEntry.decode",
]
CLASSES = set(t.split(".")[0] for t in TARGETS)
SINGLETON_NAMES = ("getInstance","instance","sharedInstance","getInstanceCtor")

_fh = None
def log(m):
    line = "[%7.2f] %s" % (time.time() - START, m)
    try:
        sys.stdout.write(line + "\n"); sys.stdout.flush()
    except Exception: pass
    if _fh:
        try: _fh.write(line + "\n"); _fh.flush()
        except Exception: pass

def cmdj(r2, c):
    try: return r2.cmdj(c)
    except Exception: return None

def cmd(r2, c):
    try: return r2.cmd(c)
    except Exception: return ""

def addr_of(s, base):
    va = s.get("vaddr", 0); pa = s.get("paddr", 0)
    if va and va >= base: return va
    if pa and pa >= base: return pa
    if pa and pa > 0: return pa + base
    return 0

def build_string_index(r2, base):
    idx = {}
    for s in (cmdj(r2, "izj") or []):
        txt = (s.get("string") or s.get("text") or "").strip()
        if not txt: continue
        a = addr_of(s, base)
        if a: idx.setdefault(txt, []).append(a)
    return idx

def get_sections(r2):
    return cmdj(r2, "iSj") or []

def pick_sections(sections):
    text = None; data = []
    for s in sections:
        n = s.get("name", "") or ""
        p = s.get("perm", "") or ""
        va = s.get("vaddr", 0); sz = s.get("size", 0)
        if sz <= 0 or va <= 0: continue
        if ("__text" in n or ".text" in n) and "x" in p:
            text = (va, va + sz)
        elif "x" not in p and ("w" in p or "r" in p):
            data.append((va, sz, n))
    return text, data

def load_range(r2, va, size):
    CH = 0x400000; chunks = []; a = va; end = va + size
    while a < end:
        n = min(CH, end - a)
        hx = cmd(r2, "p8 %d @ 0x%x" % (n, a)).strip()
        if not hx: return None
        try: chunks.append(bytes.fromhex(hx))
        except Exception: return None
        a += n
    return b"".join(chunks)

def is_adrp(w): return (w & 0x9F000000) == 0x90000000
def is_add_imm64(w): return (w & 0xFF800000) == 0x91000000
def is_bl(w): return (w & 0xFC000000) == 0x94000000
def is_str_x(w): return (w & 0xFFC00000) == 0xF9000000
def is_stp_x29_x30_pre(w): return (w & 0xFFC07FFF) == 0xA9807BFD
def is_pacibsp(w): return w == 0xD503237F
def is_paciasp(w): return w == 0xD503233F
def is_bti_c(w): return w == 0xD503245F
def is_bti_j(w): return w == 0xD503249F

def decode_adrp_imm(w, pc):
    immlo = (w >> 29) & 0x3; immhi = (w >> 5) & 0x7FFFF
    imm = (immhi << 2) | immlo
    if imm & (1 << 20): imm -= (1 << 21)
    return (pc & ~0xFFF) + (imm << 12)

def decode_add_imm(w):
    rd = w & 0x1F; rn = (w >> 5) & 0x1F
    imm12 = (w >> 10) & 0xFFF; sh = (w >> 22) & 1
    if sh: imm12 = imm12 << 12
    return rd, rn, imm12

def decode_bl_target(w, pc):
    off = w & 0x3FFFFFF
    if off & (1 << 25): off -= (1 << 26)
    return pc + (off << 2)

def decode_ptr_candidates(raw, base, lo, hi):
    raw &= 0xFFFFFFFFFFFFFFFF
    out = []
    t43 = raw & 0x7FFFFFFFFFF
    high8 = (raw >> 43) & 0xFF
    out.append(t43)
    if high8: out.append((high8 << 56) | t43)
    t36 = raw & 0xFFFFFFFFF
    if t36:
        out.append(t36); out.append(base + t36)
    t32 = raw & 0xFFFFFFFF
    if t32:
        out.append(t32); out.append(base + t32)
    out.append(raw & 0xFFFFFFFFFFFF)
    out.append(base + (raw & 0xFFFFFFFFFFFF))
    res = []; seen = set()
    for c in out:
        if c in seen: continue
        seen.add(c)
        if lo <= c < hi and (c & 3) == 0:
            res.append(c)
    return res

def scan_text(text, ts):
    n = len(text) // 4
    adrp_add = []; prologs = []
    for i in range(n):
        w = struct.unpack_from("<I", text, i * 4)[0]
        pc = ts + i * 4
        if is_stp_x29_x30_pre(w) or is_pacibsp(w) or is_paciasp(w) \
           or is_bti_c(w) or is_bti_j(w):
            prologs.append(pc)
        if is_adrp(w):
            rd_adrp = w & 0x1F
            page = decode_adrp_imm(w, pc)
            for j in range(i + 1, min(i + 8, n)):
                w2 = struct.unpack_from("<I", text, j * 4)[0]
                if is_add_imm64(w2):
                    rd, rn, imm = decode_add_imm(w2)
                    if rn == rd_adrp:
                        adrp_add.append((pc, page + imm)); break
    return adrp_add, prologs

def build_ptr_index(data_blobs, ts, te, base):
    idx = {}
    for va, b in data_blobs:
        for i in range(len(b) // 8):
            raw = struct.unpack_from("<Q", b, i * 8)[0]
            cands = decode_ptr_candidates(raw, base, ts, te)
            if cands:
                slot = va + i * 8
                for c in cands:
                    idx.setdefault(c, []).append(slot)
    return idx

def build_slot_to_target(ptr_idx):
    out = {}
    for tgt, slots in ptr_idx.items():
        for s in slots:
            if s not in out: out[s] = tgt
    return out

def expand_vtable(slot_to_target, anchor_slot, max_back=128, max_fwd=4096):
    vt_start = anchor_slot
    cur = anchor_slot - 8
    for _ in range(max_back):
        if cur in slot_to_target:
            vt_start = cur; cur -= 8
        else: break
    slots = []; cur = vt_start
    for _ in range(max_fwd):
        if cur in slot_to_target:
            slots.append((cur, slot_to_target[cur])); cur += 8
        else: break
    return (vt_start, slots) if len(slots) >= 2 else None

def find_all_vtable_runs(slot_to_tgt, min_slots=4):
    if not slot_to_tgt: return []
    slots = sorted(slot_to_tgt.keys())
    runs = []
    start = slots[0]
    prev = slots[0]
    for s in slots[1:]:
        if s != prev + 8:
            if (prev - start) // 8 + 1 >= min_slots:
                runs.append((start, prev))
            start = s
        prev = s
    if (prev - start) // 8 + 1 >= min_slots:
        runs.append((start, prev))
    return runs

def demangle_itanium(s):
    if not s.startswith("_ZN"): return None
    rest = s[3:]; parts = []
    while rest and rest[0].isdigit():
        i = 0
        while i < len(rest) and rest[i].isdigit(): i += 1
        ln = int(rest[:i]); rest = rest[i:]
        if len(rest) < ln: return None
        parts.append(rest[:ln]); rest = rest[ln:]
    if len(parts) >= 2: return parts[-2], parts[-1]
    if len(parts) == 1: return parts[0], None
    return None

def parse_typeinfo_name(raw):
    if not raw: return None
    if raw.startswith("_ZTI") or raw.startswith("_ZTS"):
        return demangle_itanium("_ZN" + raw[4:]) if raw.startswith("_ZTI") else None
    out = []
    i = 0
    while i < len(raw) and raw[i].isdigit():
        j = i
        while j < len(raw) and raw[j].isdigit(): j += 1
        try: ln = int(raw[i:j])
        except ValueError: break
        if ln <= 0 or j + ln > len(raw): break
        out.append(raw[j:j+ln])
        i = j + ln
    if out:
        return out[-1]
    if re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", raw):
        return raw
    return None

def main():
    global _fh
    try: _fh = open(LOG, "w")
    except Exception: _fh = None

    log("=== find_offsets v19 iOS +typeinfo ===")
    log("targets=%d classes=%d" % (len(TARGETS), len(CLASSES)))

    r2 = r2pipe.open(BIN, flags=["-2"])
    r2.cmd("e scr.color=0"); r2.cmd("e asm.arch=arm"); r2.cmd("e asm.bits=64")
    r2.cmd("aa")
    log("aa done")

    info = cmdj(r2, "ij") or {}
    base = info.get("baddr", 0x100000000) or 0x100000000
    log("base=0x%x" % base)

    str_index = build_string_index(r2, base)
    log("strings total=%d" % len(str_index))

    sections = get_sections(r2)
    text_b, data_secs = pick_sections(sections)
    if not text_b: log("no .text"); return
    ts, te = text_b
    log(".text 0x%x-0x%x size=%d" % (ts, te, te - ts))

    text = load_range(r2, ts, te - ts)
    if not text: log("fail .text"); return
    log(".text loaded=%d" % len(text))

    data_blobs = []
    for va, sz, n in data_secs:
        b = load_range(r2, va, sz)
        if b: data_blobs.append((va, b))
    log("data loaded=%d blobs=%d"
        % (sum(len(b) for _, b in data_blobs), len(data_blobs)))

    ptr_idx = build_ptr_index(data_blobs, ts, te, base)
    slot_to_tgt = build_slot_to_target(ptr_idx)
    log("ptr_idx targets=%d slots=%d" % (len(ptr_idx), len(slot_to_tgt)))

    adrp_add, prologs = scan_text(text, ts)
    prologs_sorted = sorted(prologs)
    log("adrp_add=%d prologs=%d" % (len(adrp_add), len(prologs_sorted)))

    def find_func_start(ia):
        idx = bisect.bisect_right(prologs_sorted, ia) - 1
        if idx < 0: return None
        s = prologs_sorted[idx]
        if ia - s > 0x8000: return None
        return s

    log("--- enumerating ALL vtables via consecutive-slot runs ---")
    runs = find_all_vtable_runs(slot_to_tgt, min_slots=4)
    log("vtable-like runs (>=4 slots): %d" % len(runs))

    ts_lo = ts
    ts_hi = te
    data_lo = min((v for v, _, _ in data_secs), default=base)
    data_hi = max((v + s for v, s, _ in data_secs), default=base)

    def decode_chain_to_va(raw):
        cands = decode_ptr_candidates(raw, base, data_lo, data_hi + 0x100000)
        cands += decode_ptr_candidates(raw, base, ts_lo, ts_hi)
        return cands

    data_blob_map = list(data_blobs)

    def read_qword_from_blobs(va):
        for bva, b in data_blob_map:
            if bva <= va < bva + len(b):
                off = va - bva
                if off + 8 > len(b): return None
                return struct.unpack_from("<Q", b, off)[0]
        return None

    def read_cstr_from_blobs(va, maxlen=128):
        for bva, b in data_blob_map:
            if bva <= va < bva + len(b):
                off = va - bva
                end = min(off + maxlen, len(b))
                chunk = b[off:end]
                z = chunk.find(b"\x00")
                if z < 0: z = len(chunk)
                return chunk[:z].decode("latin-1", errors="replace")
        return None

    def va_from_str_index(s):
        addrs = str_index.get(s, [])
        return addrs[0] if addrs else None

    typeinfo_map = {}
    typeinfo_probe = 0
    for (run_start, run_end) in runs:
        typeinfo_probe += 1
        ti_slot = run_start - 8
        raw = read_qword_from_blobs(ti_slot)
        if raw is None: continue
        cands = decode_chain_to_va(raw)
        if not cands: continue
        ti_va = cands[0]
        name_ptr_raw = read_qword_from_blobs(ti_va + 8)
        if name_ptr_raw is None: continue
        name_cands = decode_chain_to_va(name_ptr_raw)
        if not name_cands: continue
        name_va = name_cands[0]
        raw_str = read_cstr_from_blobs(name_va)
        if not raw_str: continue
        cls = parse_typeinfo_name(raw_str)
        if not cls: continue
        typeinfo_map[run_start] = (cls, ti_va, raw_str)

    log("vtables with typeinfo: %d" % len(typeinfo_map))
    for vt, (cls, ti_va, raw_str) in list(typeinfo_map.items())[:40]:
        log("  vt=0x%x -> class=%s (raw='%s')"
            % (vt - base, cls, raw_str[:48]))

    name_to_vt = {}
    for vt, (cls, _, _) in typeinfo_map.items():
        if cls not in name_to_vt:
            name_to_vt[cls] = vt

    log("--- vtable lookup for our target classes ---")
    class_to_vtable = {}
    for cls in sorted(CLASSES):
        vt = name_to_vt.get(cls)
        if vt is not None:
            slots = []
            cur = vt
            for _ in range(4096):
                t = slot_to_tgt.get(cur)
                if t is None: break
                slots.append((cur, t)); cur += 8
            if len(slots) >= 2:
                class_to_vtable[cls] = (vt, slots)
                log("  %-24s vt=0x%x slots=%d (via typeinfo)"
                    % (cls, vt - base, len(slots)))

    str_addr_to_pc = {}
    for pc, tgt in adrp_add:
        str_addr_to_pc.setdefault(tgt, []).append(pc)

    class_method_funcs = {}
    for s, addrs in str_index.items():
        idx = s.find("::")
        if idx <= 0: continue
        cls = s[:idx]
        if not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", cls): continue
        rest = s[idx + 2:]
        m = re.match(r"([A-Za-z_][A-Za-z0-9_]*)", rest)
        if not m: continue
        method = m.group(1)
        key = cls + "::" + method
        if key in class_method_funcs: continue
        best = None
        for sa in addrs:
            for pc in sorted(str_addr_to_pc.get(sa, []))[:4]:
                f = find_func_start(pc)
                if f is None: continue
                if best is None: best = f
                if (pc - f) < 0x800:
                    best = f; break
            if best is not None and (pc - best) < 0x800: break
        if best is not None:
            class_method_funcs[key] = best
    log("Class::method funcs (from strings)=%d" % len(class_method_funcs))

    for vt, (cls, _, _) in typeinfo_map.items():
        if cls in CLASSES and cls not in class_to_vtable:
            slots = []
            cur = vt
            for _ in range(4096):
                t = slot_to_tgt.get(cur)
                if t is None: break
                slots.append((cur, t)); cur += 8
            if len(slots) >= 2:
                class_to_vtable[cls] = (vt, slots)

    for s, addrs in str_index.items():
        if s not in CLASSES: continue
        for sa in addrs:
            for pc in str_addr_to_pc.get(sa, []):
                f = find_func_start(pc)
                if f is None: continue
                for slot_addr, tgt in ptr_idx.get(f, []):
                    vt = expand_vtable(slot_to_tgt, slot_addr)
                    if vt and vt[0] not in [x[0] for x in class_to_vtable.values()]:
                        cls_name = name_to_vt.get(s)
                        if cls_name == vt[0]:
                            class_to_vtable.setdefault(s, vt)
                            break

    log("class->vtable total=%d" % len(class_to_vtable))

    func_to_names = {}
    for key, f in class_method_funcs.items():
        cls, method = key.split("::", 1)
        func_to_names.setdefault(f, []).append((cls, method))

    for _ in range(4):
        added = 0
        for cls, (vt_start, slots) in class_to_vtable.items():
            for _, func in slots:
                for other_cls, method in func_to_names.get(func, ()):
                    key = cls + "::" + method
                    if key not in class_method_funcs:
                        class_method_funcs[key] = func
                        func_to_names.setdefault(func, []).append((cls, method))
                        added += 1
        if added == 0: break

    log("Class::method funcs total (after propagation)=%d" % len(class_method_funcs))

    method_name_xrefs = {}
    for s, addrs in str_index.items():
        if "::" in s: continue
        if not re.match(r"^[a-zA-Z_][a-zA-Z0-9_]{2,48}$", s): continue
        if s in ("null", "true", "false", "None"): continue
        for sa in addrs:
            for pc in str_addr_to_pc.get(sa, []):
                f = find_func_start(pc)
                if f is not None:
                    method_name_xrefs.setdefault(s, set()).add(f)

    all_vt_starts = set(vt for vt, _ in class_to_vtable.values())
    vt_to_ctors = {}
    for pc, tgt in adrp_add:
        if tgt in all_vt_starts:
            f = find_func_start(pc)
            if f is not None:
                vt_to_ctors.setdefault(tgt, set()).add(f)
    log("vtables with ctor xref=%d" % len(vt_to_ctors))

    results = {}
    unresolved = []

    for t in TARGETS:
        if "." not in t:
            unresolved.append((t, "no_dot")); continue
        cls, method = t.split(".", 1)
        trace = []

        if method == "ctor":
            hit = None
            for k in (cls+"::"+cls, cls+"::ctor", cls+"::__ctor",
                      cls+"::constructor", cls+"::new"):
                if k in class_method_funcs:
                    hit = class_method_funcs[k]; trace.append("str "+k); break
            if hit is not None:
                results[t] = hit - base
                log("  %-40s -> 0x%x (%s)"
                    % (t, results[t], " | ".join(trace)))
                continue
            vt = class_to_vtable.get(cls)
            if vt:
                trace.append("vt=0x%x" % (vt[0]-base))
                for c in vt_to_ctors.get(vt[0], set()):
                    results[t] = c - base
                    trace.append("ctor_cand=0x%x" % (c - base)); break
            if t in results:
                log("  %-40s -> 0x%x (%s)"
                    % (t, results[t], " | ".join(trace)))
                continue
            log("  %-40s FAIL (%s)" % (t, " | ".join(trace) or "no path"))
            unresolved.append((t, "no_ctor")); continue

        if method in SINGLETON_NAMES:
            hit = None
            for cand in (cls+"::"+method, cls+"::getInstance", cls+"::instance",
                         cls+"::sharedInstance", cls+"::getInstanceCtor"):
                if cand in class_method_funcs:
                    hit = class_method_funcs[cand]; trace.append("str "+cand); break
            if hit is not None:
                results[t] = hit - base
                log("  %-40s -> 0x%x (%s)"
                    % (t, results[t], " | ".join(trace)))
                continue
            vt = class_to_vtable.get(cls)
            if vt:
                trace.append("vt=0x%x" % (vt[0]-base))
                vt_funcs = set(f for _, f in vt[1])
                for alt in (method, "getInstance", "instance", "sharedInstance"):
                    cands = method_name_xrefs.get(alt, set()) & vt_funcs
                    if cands:
                        results[t] = next(iter(cands)) - base
                        trace.append("plain '%s' ∩ vt" % alt); break
            if t in results:
                log("  %-40s -> 0x%x (%s)"
                    % (t, results[t], " | ".join(trace)))
                continue
            log("  %-40s FAIL (%s)" % (t, " | ".join(trace) or "no path"))
            unresolved.append((t, "no_singleton")); continue

        hit = class_method_funcs.get(cls + "::" + method)
        if hit is not None:
            results[t] = hit - base
            trace.append("direct string")
            log("  %-40s -> 0x%x (%s)"
                % (t, results[t], " | ".join(trace)))
            continue

        found = None
        for k, f in class_method_funcs.items():
            if k.startswith(cls + "::") and \
               k[len(cls)+2:].lower() == method.lower():
                found = f; trace.append("prefix "+k); break
        if found is None:
            for k, f in class_method_funcs.items():
                if k.startswith(cls + "::" + method):
                    found = f; trace.append("prefix "+k); break
        if found is not None:
            results[t] = found - base
            log("  %-40s -> 0x%x (%s)"
                % (t, results[t], " | ".join(trace)))
            continue

        vt = class_to_vtable.get(cls)
        if vt:
            trace.append("vt=0x%x" % (vt[0]-base))
            vt_funcs = set(f for _, f in vt[1])
            cands = method_name_xrefs.get(method, set()) & vt_funcs
            if cands:
                results[t] = next(iter(cands)) - base
                trace.append("plain '%s' ∩ vt" % method)
                log("  %-40s -> 0x%x (%s)"
                    % (t, results[t], " | ".join(trace)))
                continue
            for k, f in class_method_funcs.items():
                if not k.endswith("::" + method): continue
                other_cls = k.split("::", 1)[0]
                vt2 = class_to_vtable.get(other_cls)
                if not vt2: continue
                idx2 = None
                for i, (_, tf) in enumerate(vt2[1]):
                    if tf == f: idx2 = i; break
                if idx2 is None or idx2 >= len(vt[1]): continue
                results[t] = vt[1][idx2][1] - base
                trace.append("slot %d from %s::%s" % (idx2, other_cls, method))
                break
            if t in results:
                log("  %-40s -> 0x%x (%s)"
                    % (t, results[t], " | ".join(trace)))
                continue

        log("  %-40s FAIL (%s)" % (t, " | ".join(trace) or "no path"))
        unresolved.append((t, "no_match"))

    r2.quit()

    try:
        with open(OUT, "w") as fh:
            fh.write("// v19 auto-resolved (SCRE format) iOS\n")
            fh.write("// base=0x%x\n" % base)
            fh.write("// resolved=%d/%d\n\n" % (len(results), len(TARGETS)))
            fh.write("export const offsets = Object.freeze({\n")
            for t in TARGETS:
                k = t.replace(".", "_")
                if t in results: fh.write("    %s: 0x%x,\n" % (k, results[t]))
                else: fh.write("    // %s: unresolved\n" % k)
            fh.write("\n    // --- ctors via vtable ---\n")
            for cls in sorted(class_to_vtable):
                vt_start, _ = class_to_vtable[cls]
                for c in vt_to_ctors.get(vt_start, set()):
                    fh.write("    %s_ctor: 0x%x,\n" % (cls, c - base)); break
            fh.write("\n    // --- vtable addresses ---\n")
            for cls in sorted(class_to_vtable):
                fh.write("    VTABLE_%s: 0x%x,\n"
                         % (cls.upper(), class_to_vtable[cls][0] - base))
            fh.write("});\n")
    except Exception as e:
        log("out: %s" % e)

    log("")
    log("=== RESOLVED %d/%d ===" % (len(results), len(TARGETS)))
    for t in TARGETS:
        if t in results:
            log("  %-55s 0x%08x" % (t, results[t]))
    log("")
    log("=== class->vtable ===")
    for cls in sorted(class_to_vtable):
        vt_start, slots = class_to_vtable[cls]
        log("%-30s vt=0x%08x slots=%d"
            % (cls, vt_start - base, len(slots)))
    log("")
    log("total %.1fs" % (time.time() - START))

if __name__ == "__main__":
    try: main()
    except Exception as e:
        log("FATAL %s" % e); traceback.print_exc()