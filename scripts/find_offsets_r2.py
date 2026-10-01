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

def mangled_candidates(cls, meth):
    out = []
    out.append("_ZN%d%s%d%s" % (len(cls), cls, len(meth), meth))
    return out

def scan_prologs(text_bytes, text_va):
    prologs = []
    n = len(text_bytes) // 4
    for i in range(n):
        w = struct.unpack_from("<I", text_bytes, i * 4)[0]
        # pacibsp / paciasp
        if w == 0xD503237F or w == 0xD503233F:
            prologs.append(text_va + i * 4); continue
        # bti c / bti j
        if w == 0xD503245F or w == 0xD503249F:
            prologs.append(text_va + i * 4); continue
        # stp x29, x30, [sp, #-imm]!  (imm7 = любой)
        if (w & 0xFFC07FFF) == 0xA9807BFD:
            prologs.append(text_va + i * 4); continue
        # stp x29, x30, [sp, #imm]   (post-index, без !)
        if (w & 0xFFC07FFF) == 0xA8807BFD:
            prologs.append(text_va + i * 4); continue
        # sub sp, sp, #imm
        if (w & 0xFF8003FF) == 0xD10003FF:
            prologs.append(text_va + i * 4); continue
    return prologs

def main():
    global _fh
    try: _fh = open(LOG, "w")
    except Exception: _fh = None

    log("=== find_offsets_ios v5 ===")

    r2 = r2pipe.open(BIN, flags=["-2"])
    r2.cmd("e scr.color=0")

    info = cmdj(r2, "ij") or {}
    base = info.get("baddr", 0x100000000) or 0x100000000
    core = info.get("core", {}) or {}
    log("format=%s base=0x%x" % (core.get("format", "?"), base))

    sections = cmdj(r2, "iSj") or []
    text_sections = []
    data_sections = []
    text_va = None
    text_sz = 0

    for s in sections:
        n = s.get("name", "") or ""
        p = s.get("perm", "") or ""
        va = s.get("vaddr", 0)
        sz = s.get("size", 0)
        if sz <= 0 or va <= 0:
            continue
        # секции сегмента __TEXT: __text, __const, __cstring, __ustring, __const, __objc_methname
        if "__text" in n and "x" in p:
            text_va = va; text_sz = sz
            text_sections.append((va, sz, n))
        elif "__const" in n or "__cstring" in n or "__ustring" in n \
             or "__objc_methname" in n or "__objc_classname" in n \
             or "__objc_methtype" in n:
            # обычно лежат в __TEXT сегменте, доступ read-only
            text_sections.append((va, sz, n))
        elif "w" in p or "r" in p:
            data_sections.append((va, sz, n))

    if not text_va:
        log("no __text, abort")
        return

    log("__text 0x%x-0x%x size=%d"
        % (text_va, text_va + text_sz, text_sz))
    log("text-секций=%d data-секций=%d"
        % (len(text_sections), len(data_sections)))

    log("loading text-секций...")
    text_blobs = []
    for va, sz, n in text_sections:
        b = load_bytes(r2, va, sz)
        if b:
            text_blobs.append((va, b))
            log("  TEXT %-32s 0x%x size=%d" % (n, va, sz))
    total_text = sum(len(b) for _, b in text_blobs)
    log("TEXT total=%d bytes blobs=%d" % (total_text, len(text_blobs)))

    log("loading data-секций...")
    data_blobs = []
    for va, sz, n in data_sections:
        b = load_bytes(r2, va, sz)
        if b:
            data_blobs.append((va, b))
            log("  DATA %-32s 0x%x size=%d" % (n, va, sz))
    total_data = sum(len(b) for _, b in data_blobs)
    log("DATA total=%d bytes blobs=%d" % (total_data, len(data_blobs)))

    # ----- собираем строки из всех загруженных блобов + из izj -----
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

    log("manual regex scan across all blobs...")
    t0 = time.time()
    pat_method = re.compile(rb"[A-Za-z_][A-Za-z0-9_]{1,63}::[A-Za-z_~][A-Za-z0-9_]{1,63}")
    pat_mangled = re.compile(rb"_ZN\d+[A-Za-z_][A-Za-z0-9_]+")

    added_method = 0
    added_mangled = 0
    all_blobs = text_blobs + data_blobs
    for va, blob in all_blobs:
        for m in pat_method.finditer(blob):
            txt = m.group(0).decode("latin-1")
            addr = va + m.start()
            lst = str_index.setdefault(txt, [])
            if addr not in lst:
                lst.append(addr)
                added_method += 1
        for m in pat_mangled.finditer(blob):
            txt = m.group(0).decode("latin-1")
            addr = va + m.start()
            lst = str_index.setdefault(txt, [])
            if addr not in lst:
                lst.append(addr)
                added_mangled += 1
    log("regex added method=%d mangled=%d in %.1fs"
        % (added_method, added_mangled, time.time() - t0))

    total_with_colons = sum(1 for k in str_index if "::" in k)
    total_mangled = sum(1 for k in str_index if k.startswith("_ZN"))
    log("total strings=%d (:: = %d, _ZN = %d)"
        % (len(str_index), total_with_colons, total_mangled))

    # выведем все имена с :: в лог (для анализа)
    log("ALL Class::method strings:")
    for k in sorted(str_index.keys()):
        if "::" in k:
            log("  NAME %s (addrs=%d)" % (k, len(str_index[k])))

    # ----- ищем adrp+add -----
    log("scanning __text for adrp+add...")
    t0 = time.time()
    adrp_add_map = {}
    # берём только "чистый" __text (первый блоб)
    text_b = None
    for va, blob in text_blobs:
        if text_b is None:
            text_b = (va, blob)
    if text_b is None:
        log("no text blob"); return
    text_va2, text_bytes = text_b
    n = len(text_bytes) // 4
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
        pc = text_va2 + i * 4
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
            adrp_add_map.setdefault(tgt, []).append(pc)
            break
    log("adrp+add targets=%d in %.1fs"
        % (len(adrp_add_map), time.time() - t0))

    # ----- ищем прологи -----
    log("scanning __text for prologs...")
    t0 = time.time()
    prologs = scan_prologs(text_bytes, text_va2)
    prologs.sort()
    log("prologs=%d in %.1fs" % (len(prologs), time.time() - t0))

    def find_func_start(inner_pc):
        idx = bisect.bisect_right(prologs, inner_pc) - 1
        if idx < 0:
            return None
        s = prologs[idx]
        if inner_pc - s > 0x40000:
            return None
        return s

    # ----- resolve -----
    log("--- resolving %d targets ---" % len(TARGETS))
    results = {}
    for target in TARGETS:
        cls, method = target.split(".", 1)

        all_candidates = [
            cls + "::" + method,
            cls + "::" + method + "()",
            cls + "::" + method + "(void)",
        ]
        all_candidates += mangled_candidates(cls, method)

        found_addr = []
        found_name = None
        for cand in all_candidates:
            if cand in str_index:
                found_addr = str_index[cand]
                found_name = cand
                break

        if not found_addr:
            log("  %-48s NO_STRING" % target)
            continue

        xrefs_all = []
        for sa in found_addr:
            pcs = adrp_add_map.get(sa, [])
            xrefs_all.extend(pcs)

        if not xrefs_all:
            log("  %-48s str='%s' addrs=%d xrefs=0"
                % (target, found_name, len(found_addr)))
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