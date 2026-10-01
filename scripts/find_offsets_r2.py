#!/usr/bin/env python3
import os, sys, time, struct, re, bisect, traceback
import r2pipe

WS = os.environ.get("GITHUB_WORKSPACE", "/tmp")
BIN = os.environ.get("R2_BIN", "/tmp/brawl_bin")
OUT = os.path.join(WS, "offsets_resolved.js")
LOG = os.path.join(WS, "r2.log")
START = time.time()

TARGETS = [
"MessageManager.receiveMessage",
"MessageManager.sendMessage",
"MessageManager.instance",
"LogicBattleModeClient.update",
"LogicBattleModeClient.getOwnCharacter",
"LogicBattleModeClient.isUltiReadyForClient",
"LogicBattleModeClient.setClientPredictionMoveTo",
"BattleScreen.update",
"BattleScreen.getClosestTargetForAutoshoot",
"BattleScreen.activateSkill",
"BattleScreen.tryToActivateSkill",
"BattleScreen.updateMovement",
"BattleScreen.autoShoot",
"BattleScreen.convertToControlScheme",
"BattleScreen.getLogicBattleModeClient",
"LogicGameObjectClient.getX",
"LogicGameObjectClient.getY",
"LogicGameObjectClient.getGlobalID",
"LogicProjectileData.getSpeed",
"LogicProjectileData.getRadius",
"LogicProjectileData.getIntValueFromColumn",
"Character.update",
"Character.getUltiSkillServer",
"Character.getPrimarySkillServer",
"GameMain.update",
"Stage.addChild",
"Stage.instance",
"GameButton.ctor",
"GenericPopup.ctor",
"GameSliderComponent.ctor",
"NativeFont.formatString",
"MovieClip.setText",
"MovieClip.getChildByName",
"ClientInput.ctor",
"ClientInputManager.addInput",
]
CLASSES = set(t.split(".")[0] for t in TARGETS)
SINGLETON_METHODS = ("instance", "getInstance", "sharedInstance")

_fh = None
def log(m):
    line = "[%7.2f] %s" % (time.time() - START, m)
    try:
        sys.stdout.write(line + "\n"); sys.stdout.flush()
    except Exception:
        pass
    if _fh:
        try:
            _fh.write(line + "\n"); _fh.flush()
        except Exception:
            pass

def cmdj(r2, c):
    try: return r2.cmdj(c)
    except Exception: return None

def cmd(r2, c):
    try: return r2.cmd(c)
    except Exception: return ""

def load_bytes(r2, va, size):
    chunks = []
    a = va; end = va + size; CH = 0x400000
    while a < end:
        n = min(CH, end - a)
        hx = cmd(r2, "p8 %d @ 0x%x" % (n, a)).strip()
        if not hx: return None
        try: chunks.append(bytes.fromhex(hx))
        except Exception: return None
        a += n
    return b"".join(chunks)

def strip_pac(raw):
    return raw & 0x0000FFFFFFFFFFFF

def decode_chained(raw, base):
    """dyld_chained_ptr_arm64e heuristic."""
    auth = (raw >> 63) & 1
    target = raw & 0x7FFFFFFFFFF
    results = []
    if auth:
        # auth-signed; strip PAC by clearing high 24 bits
        results.append(target & 0x0000FFFFFFFFFFFF)
        results.append(target)
    else:
        results.append(target)
    # also try "target - base"
    results.append(base + target)
    return results

def candidates(raw, base, lo, hi):
    out = set()
    for v in (raw, strip_pac(raw)):
        if lo <= v < hi and (v & 3) == 0:
            out.add(v)
    for v in decode_chained(raw, base):
        if lo <= v < hi and (v & 3) == 0:
            out.add(v)
    return out

def is_adrp(w): return (w & 0x9F000000) == 0x90000000
def is_add_imm64(w): return (w & 0xFF800000) == 0x91000000
def is_stp_x29_x30_pre(w): return (w & 0xFFC07FFF) == 0xA9807BFD
def is_pacibsp(w): return w == 0xD503237F
def is_paciasp(w): return w == 0xD503233F
def is_bti_c(w): return w == 0xD503245F
def is_bti_j(w): return w == 0xD503249F
def is_adr(w): return (w & 0x9F000000) == 0x10000000
def is_ret(w): return w == 0xD65F03C0
def is_b(w): return (w & 0xFC000000) == 0x14000000

def decode_adrp_imm(w, pc):
    immlo = (w >> 29) & 3
    immhi = (w >> 5) & 0x7FFFF
    imm = (immhi << 2) | immlo
    if imm & (1 << 20): imm -= (1 << 21)
    return (pc & ~0xFFF) + (imm << 12)

def decode_adr_imm(w, pc):
    immlo = (w >> 29) & 3
    immhi = (w >> 5) & 0x7FFFF
    imm = (immhi << 2) | immlo
    if imm & (1 << 20): imm -= (1 << 21)
    return pc + imm

def decode_add_imm(w):
    rd = w & 0x1F; rn = (w >> 5) & 0x1F
    imm12 = (w >> 10) & 0xFFF; sh = (w >> 22) & 1
    if sh: imm12 <<= 12
    return rd, rn, imm12

def main():
    global _fh
    try: _fh = open(LOG, "w")
    except Exception: _fh = None

    log("=== find_offsets_ios v6 (vtable+rtti) ===")
    r2 = r2pipe.open(BIN, flags=["-2"])
    r2.cmd("e scr.color=0")
    r2.cmd("e asm.arch=arm")
    r2.cmd("e asm.bits=64")
    r2.cmd("e anal.cpp.abi=itanium")

    info = cmdj(r2, "ij") or {}
    base = info.get("baddr", 0x100000000) or 0x100000000
    log("base=0x%x" % base)

    sections = cmdj(r2, "iSj") or []
    text_secs = []
    data_secs = []
    for s in sections:
        n = s.get("name", "") or ""
        p = s.get("perm", "") or ""
        va = s.get("vaddr", 0); sz = s.get("size", 0)
        if sz <= 0 or va <= 0: continue
        if "__text" in n and "x" in p:
            text_secs.append((va, sz, n))
        elif "w" in p or "r" in p:
            data_secs.append((va, sz, n))

    log("text=%d data=%d" % (len(text_secs), len(data_secs)))

    log("loading sections...")
    text_blobs = []
    for va, sz, n in text_secs:
        b = load_bytes(r2, va, sz)
        if b: text_blobs.append((va, b))
    data_blobs = []
    for va, sz, n in data_secs:
        if sz > 4_000_000: continue  # skip huge like __TEXT.__eh_frame
        b = load_bytes(r2, va, sz)
        if b: data_blobs.append((va, b))
    log("text bytes=%d data bytes=%d"
        % (sum(len(b) for _, b in text_blobs),
           sum(len(b) for _, b in data_blobs)))

    # ---- strings ----
    iz = cmdj(r2, "izj") or []
    str_index = {}
    for s in iz:
        txt = (s.get("string") or "").strip()
        if txt and s.get("vaddr"):
            str_index.setdefault(txt, []).append(s["vaddr"])
    log("izj strings=%d" % len(str_index))

    pat_method = re.compile(rb"[A-Za-z_][A-Za-z0-9_]{1,63}::[A-Za-z_~][A-Za-z0-9_]{1,63}")
    for va, blob in text_blobs + data_blobs:
        for m in pat_method.finditer(blob):
            txt = m.group(0).decode("latin-1")
            addr = va + m.start()
            lst = str_index.setdefault(txt, [])
            if addr not in lst: lst.append(addr)
    log("strings total=%d (with :: = %d)"
        % (len(str_index), sum(1 for k in str_index if "::" in k)))

    # ---- adrp+add xref map ----
    log("scanning adrp+add and prologs in __text...")
    t0 = time.time()
    text_va, text_bytes = text_blobs[0]
    n4 = len(text_bytes) // 4
    adrp_add = {}
    adr_only = {}
    prologs = []
    for i in range(n4):
        w = struct.unpack_from("<I", text_bytes, i * 4)[0]
        pc = text_va + i * 4
        if is_adrp(w):
            rd_adrp = w & 0x1F
            page = decode_adrp_imm(w, pc)
            for j in range(i + 1, min(i + 8, n4)):
                w2 = struct.unpack_from("<I", text_bytes, j * 4)[0]
                if is_add_imm64(w2):
                    rd, rn, imm = decode_add_imm(w2)
                    if rn == rd_adrp and (w2 & 0x1F) != 31:
                        tgt = page + imm
                        adrp_add.setdefault(tgt, []).append(pc)
                        break
        if is_adr(w):
            tgt = decode_adr_imm(w, pc)
            adr_only.setdefault(tgt, []).append(pc)
        if is_stp_x29_x30_pre(w) or is_pacibsp(w) or is_paciasp(w) \
           or is_bti_c(w) or is_bti_j(w):
            prologs.append(pc)
    prologs.sort()
    log("adrp+add=%d adr=%d prologs=%d in %.1fs"
        % (len(adrp_add), len(adr_only), len(prologs), time.time() - t0))

    def find_func_start(inner_pc):
        idx = bisect.bisect_right(prologs, inner_pc) - 1
        if idx < 0: return None
        s = prologs[idx]
        if inner_pc - s > 0x40000: return None
        return s

    # ---- build pointer index (chained fixups) ----
    log("building pointer index from data...")
    t0 = time.time()
    data_lo = min(v for v, _ in data_blobs) if data_blobs else 0
    data_hi = max(v + len(b) for v, b in data_blobs) if data_blobs else 0
    text_lo = text_va
    text_hi = text_va + len(text_bytes)

    ptr_slot = {}   # slot_va -> [tgt_vas]
    for va, blob in data_blobs:
        for i in range(len(blob) // 8):
            raw = struct.unpack_from("<Q", blob, i * 8)[0]
            if raw == 0: continue
            slot_va = va + i * 8
            cands = candidates(raw, base, text_lo, text_hi)
            if cands:
                ptr_slot[slot_va] = list(cands)
    log("ptr slots=%d in %.1fs" % (len(ptr_slot), time.time() - t0))

    # ---- vtable detection ----
    log("detecting vtable runs...")
    t0 = time.time()
    slots = sorted(ptr_slot.keys())
    vt_runs = []
    if slots:
        start = slots[0]; prev = slots[0]
        for s in slots[1:]:
            if s != prev + 8:
                if (prev - start) // 8 + 1 >= 4:
                    vt_runs.append((start, prev))
                start = s
            prev = s
        if (prev - start) // 8 + 1 >= 4:
            vt_runs.append((start, prev))
    log("vtable runs=%d in %.1fs" % (len(vt_runs), time.time() - t0))

    # ---- helper: read cstring from blob at va ----
    def read_cstr(va, maxlen=200):
        for bva, b in data_blobs + text_blobs:
            if bva <= va < bva + len(b):
                off = va - bva
                end = min(off + maxlen, len(b))
                chunk = b[off:end]
                z = chunk.find(b"\x00")
                if z < 0: z = len(chunk)
                return chunk[:z].decode("latin-1", errors="replace")
        return None

    def read_qword(va):
        for bva, b in data_blobs + text_blobs:
            if bva <= va < bva + len(b) - 7:
                off = va - bva
                return struct.unpack_from("<Q", b, off)[0]
        return None

    # ---- typeinfo scan ----
    log("scanning typeinfo for vtable runs...")
    t0 = time.time()
    vt_class = {}   # vt_va -> class_name
    for (run_start, run_end) in vt_runs:
        for back in (1, 2, 3):
            ti_slot = run_start - 8 * back
            raw = read_qword(ti_slot)
            if raw is None: continue
            ti_cands = candidates(raw, base, data_lo, data_hi)
            found = False
            for ti_va in ti_cands:
                for name_off in (8, 0, 16):
                    nraw = read_qword(ti_va + name_off)
                    if nraw is None: continue
                    name_cands = candidates(nraw, base, data_lo, data_hi)
                    for nva in name_cands:
                        s = read_cstr(nva, 200)
                        if not s: continue
                        # typeinfo name is often N<len>Name<len>NameE or _ZTS...
                        m = re.search(r"([A-Za-z_][A-Za-z0-9_]{1,63})([0-9]+[A-Z])?$", s)
                        clsname = None
                        if s.startswith("_ZTS") and s.endswith("E"):
                            # _ZTS<len><name>
                            inner = s[4:-1]
                            mm = re.match(r"(\d+)(.*)", inner)
                            if mm:
                                try:
                                    ln = int(mm.group(1))
                                    clsname = mm.group(2)[:ln]
                                except Exception:
                                    pass
                        elif re.match(r"^\d+[A-Za-z_]", s):
                            mm = re.match(r"(\d+)(.*)", s)
                            if mm:
                                try:
                                    ln = int(mm.group(1))
                                    clsname = mm.group(2)[:ln]
                                except Exception:
                                    pass
                        if clsname and re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", clsname):
                            vt_class[run_start] = clsname
                            found = True
                            break
                    if found: break
                if found: break
            if found: break

    log("typeinfo hits=%d in %.1fs" % (len(vt_class), time.time() - t0))
    for vt, cls in list(vt_class.items())[:30]:
        slots_count = sum(1 for s in ptr_slot if vt <= s <= vt + 8*200)
        log("  vt=0x%x cls=%s" % (vt - base, cls))

    # ---- expand vtable and assign method slots ----
    class_vt = {}   # cls -> (vt_va, [(slot_va, [tgt_vas])])
    for vt_va, cls in vt_class.items():
        if cls not in CLASSES: continue
        slots_list = []
        cur = vt_va
        for _ in range(1024):
            if cur not in ptr_slot: break
            slots_list.append((cur, ptr_slot[cur]))
            cur += 8
        if slots_list:
            class_vt[cls] = (vt_va, slots_list)
    log("classes with vtables: %d" % len(class_vt))
    for cls in CLASSES:
        if cls in class_vt:
            log("  %-30s vt=0x%x slots=%d"
                % (cls, class_vt[cls][0] - base, len(class_vt[cls][1])))

    # ---- resolve via strings first ----
    results = {}
    unresolved = []

    for t in TARGETS:
        cls, method = t.split(".", 1)
        needle = cls + "::" + method
        if needle in str_index:
            addrs = str_index[needle]
            found = None
            for sa in addrs:
                for pc in adrp_add.get(sa, []) + adr_only.get(sa, []):
                    fs = find_func_start(pc)
                    if fs is not None:
                        found = fs; break
                if found: break
            if found:
                results[t] = found - base
                log("  %-48s 0x%08x (string)" % (t, found - base))
                continue
        unresolved.append(t)

    log("string-resolved: %d/%d" % (len(results), len(TARGETS)))

    # ---- resolve via vtable for remaining ----
    log("--- vtable-based resolution ---")
    for t in list(unresolved):
        cls, method = t.split(".", 1)
        vt = class_vt.get(cls)
        if not vt: continue

        # for ctor: usually vtable[1] is ctor in Itanium ABI? actually ctor is
        # not in vtable itself; but class's vtable is assigned in ctor, so we
        # can find ctor by looking for xref to vtable address
        if method == "ctor":
            vt_va = vt[0]
            # find xrefs to vt_va in text
            xref_pcs = adrp_add.get(vt_va, [])
            for pc in xref_pcs:
                fs = find_func_start(pc)
                if fs is not None:
                    results[t] = fs - base
                    log("  %-48s 0x%08x (vt_xref)" % (t, fs - base))
                    unresolved.remove(t)
                    break
            continue

        # for singletons: look for method that returns the class
        # this is heuristic; skip for now
    log("after vtable: %d/%d" % (len(results), len(TARGETS)))

    r2.quit()

    log("")
    log("=== FINAL RESULT %d/%d ===" % (len(results), len(TARGETS)))
    for t in TARGETS:
        if t in results:
            log("  %-48s 0x%08x" % (t, results[t]))
    log("")
    log("=== UNRESOLVED ===")
    for t in TARGETS:
        if t not in results:
            log("  %s" % t)

    try:
        with open(OUT, "w") as fh:
            fh.write("// auto-resolved iOS offsets\n")
            fh.write("// base=0x%x\n" % base)
            fh.write("// resolved=%d/%d\n\n" % (len(results), len(TARGETS)))
            fh.write("export const offsets = Object.freeze({\n")
            for t in TARGETS:
                k = t.replace(".", "_")
                if t in results:
                    fh.write("    %s: 0x%x,\n" % (k, results[t]))
                else:
                    fh.write("    // %s: unresolved\n" % k)
            fh.write("});\n")
        log("wrote %s" % OUT)
    except Exception as e:
        log("out write failed: %s" % e)

if __name__ == "__main__":
    try: main()
    except Exception as e:
        log("FATAL %s" % e); traceback.print_exc(); sys.exit(1)