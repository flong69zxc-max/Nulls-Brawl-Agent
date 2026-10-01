#!/usr/bin/env python3
import os, sys, time, struct, re, bisect, traceback, binascii
import r2pipe

try:
    import numpy as np
    HAS_NUMPY = True
except Exception:
    HAS_NUMPY = False

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
    a = va
    end = va + size
    CH = 0x400000
    while a < end:
        n = min(CH, end - a)
        hx = cmd(r2, "p8 %d @ 0x%x" % (n, a)).strip()
        if not hx:
            return None
        try:
            chunks.append(bytes.fromhex(hx))
        except Exception:
            return None
        a += n
    return b"".join(chunks)

def mangled(cls, meth):
    return "_ZN%d%s%d%s" % (len(cls), cls, len(meth), meth)

def build_str_candidates(cls, meth):
    cands = set()
    cands.add(cls + "::" + meth)
    cands.add(cls + "::" + meth + "()")
    cands.add(cls + "::" + meth + "(void)")
    cands.add(mangled(cls, meth))
    return cands

def scan_adrp_add_numpy(text_bytes, text_va):
    if not HAS_NUMPY:
        return None
    words = np.frombuffer(text_bytes, dtype="<u4")
    n = len(words)
    is_adrp = ((words & 0x9F000000) == 0x90000000)
    is_add  = ((words & 0xFF800000) == 0x91000000)

    adrp_idx = np.where(is_adrp)[0]
    if len(adrp_idx) == 0:
        return {}

    immlo = ((words >> np.uint32(29)) & np.uint32(3)).astype(np.int64)
    immhi = ((words >> np.uint32(5)) & np.uint32(0x7FFFF)).astype(np.int64)
    imm21 = (immhi << 2) | immlo
    imm21 = np.where(imm21 & (1 << 20), imm21 - (1 << 21), imm21)

    pcs = text_va + (np.arange(n, dtype=np.int64) * 4)
    pages = (pcs & ~0xFFF) + (imm21 << 12)

    rd_adrp = (words & 0x1F).astype(np.int64)

    rd_add = ((words >> np.uint32(5)) & np.uint32(0x1F)).astype(np.int64)
    rn_add = ((words >> np.uint32(5)) & np.uint32(0x1F)).astype(np.int64)
    imm12 = ((words >> np.uint32(10)) & np.uint32(0xFFF)).astype(np.int64)
    sh    = ((words >> np.uint32(22)) & np.uint32(1)).astype(np.int64)
    imm12 = np.where(sh == 1, imm12 << 12, imm12)

    target_map = {}
    for offset in range(1, 8):
        if np.any(adrp_idx + offset >= n):
            continue
        valid_adrp = adrp_idx[adrp_idx + offset < n]
        add_idx = valid_adrp + offset

        mask_add = is_add[add_idx] & (rd_adrp[valid_adrp] == rn_add[add_idx])
        if not np.any(mask_add):
            continue

        adrp_pcs = pcs[valid_adrp[mask_add]]
        pages_ok = pages[valid_adrp[mask_add]]
        add_imms = imm12[add_idx[mask_add]]
        xref_pcs = adrp_pcs

        targets = pages_ok + add_imms
        for pc, tgt in zip(xref_pcs, targets):
            tgt = int(tgt); pc = int(pc)
            target_map.setdefault(tgt, []).append(pc)

    return target_map

def scan_adrp_add_python(text_bytes, text_va):
    n = len(text_bytes) // 4
    target_map = {}
    for i in range(n):
        w = struct.unpack_from("<I", text_bytes, i * 4)[0]
        if (w & 0x9F000000) != 0x90000000:
            continue
        rd_adrp = w & 0x1F
        immlo = (w >> 29) & 3
        immhi = (w >> 5) & 0x7FFFF
        imm = (immhi << 2) | immlo
        if imm & (1 << 20):
            imm -= (1 << 21)
        pc = text_va + i * 4
        page = (pc & ~0xFFF) + (imm << 12)
        for j in range(i + 1, min(i + 8, n)):
            w2 = struct.unpack_from("<I", text_bytes, j * 4)[0]
            if (w2 & 0xFF800000) != 0x91000000:
                continue
            rd = w2 & 0x1F
            rn = (w2 >> 5) & 0x1F
            if rn != rd_adrp:
                continue
            imm12 = (w2 >> 10) & 0xFFF
            sh = (w2 >> 22) & 1
            if sh:
                imm12 <<= 12
            tgt = page + imm12
            target_map.setdefault(tgt, []).append(pc)
            break
    return target_map

def scan_prologs_numpy(text_bytes, text_va):
    words = np.frombuffer(text_bytes, dtype="<u4")
    pcs = text_va + (np.arange(len(words), dtype=np.int64) * 4)

    m_stp = ((words & 0xFFC07FFF) == 0xA9807BFD)
    m_pacibsp = (words == 0xD503237F)
    m_paciasp = (words == 0xD503233F)
    m_bti_c = (words == 0xD503245F)
    m_bti_j = (words == 0xD503249F)

    mask = m_stp | m_pacibsp | m_paciasp | m_bti_c | m_bti_j
    prologs = pcs[mask]
    return sorted(int(x) for x in prologs)

def scan_prologs_python(text_bytes, text_va):
    prologs = []
    n = len(text_bytes) // 4
    for i in range(n):
        w = struct.unpack_from("<I", text_bytes, i * 4)[0]
        if (w & 0xFFC07FFF) == 0xA9807BFD or \
           w in (0xD503237F, 0xD503233F, 0xD503245F, 0xD503249F):
            prologs.append(text_va + i * 4)
    return prologs

def main():
    global _fh
    try: _fh = open(LOG, "w")
    except Exception: _fh = None

    log("=== find_offsets_ios v4 numpy=%s ===" % HAS_NUMPY)

    r2 = r2pipe.open(BIN, flags=["-2"])
    r2.cmd("e scr.color=0")
    r2.cmd("e asm.arch=arm")
    r2.cmd("e asm.bits=64")

    info = cmdj(r2, "ij") or {}
    base = info.get("baddr", 0x100000000) or 0x100000000
    core = info.get("core", {}) or {}
    log("format=%s base=0x%x" % (core.get("format", "?"), base))

    sections = cmdj(r2, "iSj") or []
    text_va = None
    text_sz = 0
    data_secs = []
    for s in sections:
        n = s.get("name", "") or ""
        p = s.get("perm", "") or ""
        va = s.get("vaddr", 0)
        sz = s.get("size", 0)
        if sz <= 0 or va <= 0:
            continue
        if "__text" in n and "x" in p:
            text_va, text_sz = va, sz
        elif "x" not in p and ("w" in p or "r" in p):
            data_secs.append((va, sz, n))

    if not text_va:
        log("no .text, abort")
        return

    log(".text 0x%x-0x%x size=%d" % (text_va, text_va + text_sz, text_sz))
    log("data sections=%d" % len(data_secs))

    log("loading .text (%.2f MB)..." % (text_sz / 1e6))
    t0 = time.time()
    text = load_bytes(r2, text_va, text_sz)
    log(".text loaded %.1fs bytes=%d" % (time.time() - t0, len(text or b"")))
    if not text:
        log("failed to load .text")
        return

    log("loading data sections...")
    data_blobs = []
    for va, sz, n in data_secs:
        b = load_bytes(r2, va, sz)
        if b:
            data_blobs.append((va, b))
            log("  %-32s 0x%x size=%d" % (n, va, sz))
    log("data total=%d bytes blobs=%d"
        % (sum(len(b) for _, b in data_blobs), len(data_blobs)))

    log("collecting strings via izj...")
    iz = cmdj(r2, "izj") or []
    str_index = {}
    for s in iz:
        txt = (s.get("string") or "").strip()
        if not txt:
            continue
        va = s.get("vaddr", 0)
        if va:
            str_index.setdefault(txt, []).append(va)
    log("izj strings=%d" % len(str_index))

    log("manual regex scan of data blobs...")
    t0 = time.time()
    pat = re.compile(rb"[A-Za-z_][A-Za-z0-9_]{1,63}::[A-Za-z_~][A-Za-z0-9_]{1,63}")
    manual_new = 0
    for va, blob in data_blobs:
        for m in pat.finditer(blob):
            txt = m.group(0).decode("latin-1")
            addr = va + m.start()
            lst = str_index.setdefault(txt, [])
            if addr not in lst:
                lst.append(addr)
                manual_new += 1
    log("manual scan added %d refs in %.1fs" % (manual_new, time.time() - t0))

    total_with_colons = sum(1 for k in str_index if "::" in k)
    log("total unique strings=%d (with :: = %d)"
        % (len(str_index), total_with_colons))

    log("sample found Class::method (first 15):")
    shown = 0
    for k in str_index:
        if "::" in k:
            log("  %s  (%d addr)" % (k, len(str_index[k])))
            shown += 1
            if shown >= 15:
                break

    log("scanning .text for adrp+add...")
    t0 = time.time()
    if HAS_NUMPY:
        adrp_add = scan_adrp_add_numpy(text, text_va)
    else:
        adrp_add = scan_adrp_add_python(text, text_va)
    log("adrp+add targets=%d in %.1fs" % (len(adrp_add), time.time() - t0))

    log("scanning .text for prologs...")
    t0 = time.time()
    if HAS_NUMPY:
        prologs = scan_prologs_numpy(text, text_va)
    else:
        prologs = scan_prologs_python(text, text_va)
    log("prologs=%d in %.1fs" % (len(prologs), time.time() - t0))

    def find_func_start(inner_pc):
        idx = bisect.bisect_right(prologs, inner_pc) - 1
        if idx < 0:
            return None
        s = prologs[idx]
        if inner_pc - s > 0x40000:
            return None
        return s

    log("--- resolving %d targets ---" % len(TARGETS))
    results = {}
    for target in TARGETS:
        cls, method = target.split(".", 1)

        all_candidates = build_str_candidates(cls, method)
        found_addr = None
        found_name = None
        found_addrs = []
        for cand in all_candidates:
            if cand in str_index:
                found_addr = str_index[cand]
                found_name = cand
                found_addrs = found_addr
                break

        if not found_addr:
            log("  %-48s NO_STRING (tried %d cands)"
                % (target, len(all_candidates)))
            continue

        xrefs_all = []
        for sa in found_addrs:
            pcs = adrp_add.get(sa, [])
            xrefs_all.extend(pcs)

        if not xrefs_all:
            log("  %-48s str='%s' addrs=%d xrefs=0"
                % (target, found_name, len(found_addrs)))
            continue

        found = None
        for pc in sorted(set(xrefs_all)):
            fs = find_func_start(pc)
            if fs is not None:
                found = fs
                break

        if found:
            rva = found - base
            results[target] = rva
            log("  %-48s 0x%08x (str='%s' xrefs=%d)"
                % (target, rva, found_name, len(set(xrefs_all))))
        else:
            log("  %-48s str='%s' xrefs=%d no_func"
                % (target, found_name, len(set(xrefs_all))))

    r2.quit()

    log("")
    log("=== RESULT %d/%d ===" % (len(results), len(TARGETS)))
    for t in TARGETS:
        if t in results:
            log("  %-48s 0x%08x" % (t, results[t]))

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
    try:
        main()
    except Exception as e:
        log("FATAL %s" % e)
        traceback.print_exc()
        sys.exit(1)