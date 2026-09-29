# -*- coding: utf-8 -*-
# @runtime Jython

import os
import sys
import time
import traceback

WS = os.environ.get("GITHUB_WORKSPACE", "/tmp")
OUT = os.path.join(WS, "offsets_resolved.js")
REPORT = os.path.join(WS, "offsets_report.txt")
DETAIL = os.path.join(WS, "ctors_detailed.log")
BUDGET = 1500
START = time.time()

CLASSES = [
    "LogicBattleModeClient", "BattleMode", "LogicGameObjectClient",
    "BattleScreen", "Gui", "GUI", "LogicProjectileData", "LogicProjectileClient",
    "LogicProjectileServer", "LogicCharacterData", "LogicCharacterClient",
    "LogicCharacterClientOwn", "LogicSkillData", "LogicSkillClient",
    "LogicTileData", "LogicTile", "LogicTileMap", "LogicDataTables",
    "LogicGameObjectManagerClient", "LogicGameObjectServer",
    "LogicGameModeUtil", "LogicData", "LogicRandom", "LogicJSONObject",
    "LogicCompressedString", "LogicPlayerMap", "LogicPlayerMapUtil",
    "LogicLongToCodeConverterUtil", "LogicSkillData", "LogicAccessory",
    "GameButton", "GameSelectableButton", "CustomButton", "RadioButton",
    "GenericPopup", "PopupBase", "DropGUIContainer", "GameSliderComponent",
    "MapEditorModifierItem", "MapEditorModifierPopup",
    "Sprite", "Stage", "DisplayObject", "MovieClip", "MovieClipHelper",
    "TextField", "DecoratedTextField", "String", "Application", "Name",
    "ClientInput", "ClientInputManager", "ClientInputMessage",
    "Projectile", "GameMain", "DecalManager", "GameObjectManager",
    "RenderSystem", "ResourceManager", "StringTable", "FramerateManager",
    "MessageManager", "AllianceManager", "CombatHUD", "Character",
    "GameScreen", "MapEditorScreen", "GameSettings", "GameStateManager",
    "HomeMode", "HomePage", "HomeScreen", "Screen", "ScrollArea",
    "GlobalID", "AnalyticEvent", "ResourceListener",
    "AreaEffectData", "TeamChatMessage", "TeamSetMemberReadyMessage",
    "StartSpectateMessage", "PiranhaMessage",
    "HashTagCodeGenerator", "CSVRow", "CSVTable",
]

_log_fh = None


def init_log():
    global _log_fh
    try:
        _log_fh = open(DETAIL, "w")
    except Exception as e:
        sys.stderr.write("cannot open %s: %s\n" % (DETAIL, e))
        _log_fh = None


def close_log():
    global _log_fh
    if _log_fh is not None:
        try:
            _log_fh.close()
        except:
            pass
        _log_fh = None


def elapsed():
    return time.time() - START


def log(m):
    line = "[%7.2f] %s" % (elapsed(), m)
    try:
        sys.stdout.write(line + "\n")
        sys.stdout.flush()
    except:
        pass
    if _log_fh is not None:
        try:
            _log_fh.write(line + "\n")
            _log_fh.flush()
        except:
            pass


def img_base():
    try:
        return int(currentProgram.getImageBase().getOffset())
    except:
        return 0x100000000


BASE = img_base()


def rva(a):
    try:
        return int(a.getOffset()) - BASE
    except:
        return -1


def fa(a):
    try:
        return "0x%08x" % rva(a)
    except:
        return "?"


def blk(a):
    try:
        return getMemoryBlock(a)
    except:
        return None


def is_code(a):
    b = blk(a)
    return b is not None and b.isExecute()


def is_data(a):
    b = blk(a)
    if b is None:
        return False
    if b.isExecute():
        return False
    n = b.getName() or ""
    if "LINKEDIT" in n:
        return False
    return b.isRead()


def mem_long(a):
    try:
        v = currentProgram.getMemory().getLong(a)
        if v is None:
            return None
        return v & 0xFFFFFFFFFFFFFFFF
    except:
        return None


def find_refs(a):
    out = []
    try:
        rm = currentProgram.getReferenceManager()
        it = rm.getReferencesTo(a).iterator()
        while it.hasNext():
            try:
                out.append(it.next().getFromAddress())
            except:
                break
    except:
        pass
    return out


def dump_blocks():
    log("memory blocks:")
    try:
        for b in currentProgram.getMemory().getBlocks():
            try:
                log("  %-24s 0x%x-0x%x  r=%s w=%s x=%s init=%s size=0x%x" % (
                    b.getName(),
                    int(b.getStart().getOffset()),
                    int(b.getEnd().getOffset()),
                    b.isRead(), b.isWrite(), b.isExecute(),
                    b.isInitialized(),
                    int(b.getSize())))
            except Exception as e:
                log("  <block error: %s>" % e)
    except Exception as e:
        log("  block dump failed: %s" % e)


def build_string_index():
    t0 = time.time()
    listing = currentProgram.getListing()
    idx = {}
    total = 0
    blocks = []
    try:
        for b in currentProgram.getMemory().getBlocks():
            n = b.getName() or ""
            if ("cstring" in n or "objc" in n.lower() or "ustring" in n):
                blocks.append(b)
    except Exception as e:
        log("string index: block scan failed: %s" % e)
    log("string index: source blocks: %s" % ", ".join([b.getName() for b in blocks]))
    deadline = START + BUDGET - 600
    for b in blocks:
        if time.time() > deadline:
            log("string index: budget guard, stopping at %s" % b.getName())
            break
        b0 = time.time()
        try:
            it = listing.getDefinedData(b.getStart(), True)
        except Exception as e:
            log("string index: iterator failed in %s: %s" % (b.getName(), e))
            continue
        end = b.getEnd()
        cnt = 0
        while it.hasNext():
            if time.time() > deadline:
                break
            try:
                d = it.next()
            except:
                break
            if d is None:
                continue
            try:
                if d.getAddress().compareTo(end) > 0:
                    break
                if not d.hasStringValue():
                    continue
                s = str(d.getValue())
                if not s:
                    continue
                total += 1
                cnt += 1
                idx.setdefault(s, []).append(d.getAddress())
            except:
                continue
        log("string index: block %s -> %d (%.2fs)" % (b.getName(), cnt, time.time() - b0))
    log("string index: total=%d unique=%d (%.2fs)" % (total, len(idx), time.time() - t0))
    return idx


def build_pointer_index():
    t0 = time.time()
    idx = {}
    kept = 0
    skipped = 0
    deadline = START + BUDGET - 400
    try:
        blocks = list(currentProgram.getMemory().getBlocks())
    except Exception as e:
        log("pointer index: getBlocks failed: %s" % e)
        return idx
    for b in blocks:
        if not is_data(b):
            continue
        if time.time() > deadline:
            log("pointer index: budget guard, skipping remaining blocks")
            break
        b0 = time.time()
        start = b.getStart()
        end = b.getEnd()
        sz = 0
        try:
            sz = int(b.getSize())
        except:
            sz = 0
        log("pointer index: block %s size=0x%x" % (b.getName(), sz))
        cur = start
        n = 0
        while True:
            try:
                if cur.compareTo(end) > 0:
                    break
                v = mem_long(cur)
                if v is None:
                    break
                try:
                    va = toAddr(v)
                except:
                    va = None
                if va is not None and is_code(va):
                    idx.setdefault(v, []).append(int(cur.getOffset()))
                    kept += 1
                else:
                    skipped += 1
                cur = cur.add(8)
                n += 1
            except:
                break
            if (n & 0xFFFFF) == 0 and time.time() > deadline:
                log("pointer index: inner budget guard at 0x%x" % int(cur.getOffset()))
                break
        log("pointer index: block %s scanned=%d kept=%d (%.2fs)" % (
            b.getName(), n, kept, time.time() - b0))
    log("pointer index: total kept=%d skipped=%d (%.2fs)" % (
        kept, skipped, time.time() - t0))
    return idx


def ptr_index_lookup(idx, addr):
    if addr is None or not idx:
        return []
    try:
        key = int(addr.getOffset())
    except:
        return []
    lst = idx.get(key, [])
    if not lst:
        return []
    out = []
    for x in lst:
        try:
            out.append(toAddr(x))
        except:
            continue
    return out


BAD_FN = ["log", "Log", "print", "Print", "trace", "Trace",
          "assert", "Assert", "debug", "Debug", "os_log", "_os_log",
          "vsnprintf", "snprintf", "printf", "NSString", "format",
          "abort", "panic", "raise", "throw"]


def is_logger(f):
    if f is None:
        return False
    n = f.getName() or ""
    for b in BAD_FN:
        if b in n:
            return True
    return False


def expand_vtable(anchor):
    start = anchor
    prev = anchor.subtract(8)
    for _ in range(512):
        v = mem_long(prev)
        if v is None or v == 0:
            break
        try:
            va = toAddr(v)
        except:
            break
        if not is_code(va):
            break
        start = prev
        prev = prev.subtract(8)
    slots = []
    cur = start
    for _ in range(1024):
        v = mem_long(cur)
        if v is None or v == 0:
            break
        try:
            va = toAddr(v)
        except:
            break
        if not is_code(va):
            break
        slots.append((cur, va))
        cur = cur.add(8)
    return start, slots


def score_vtable(slots):
    n = len(slots)
    if n < 2 or n > 512:
        return -1
    s = n * 2
    if 4 <= n <= 256:
        s += 20
    try:
        addrs = [int(t.getOffset()) for _, t in slots]
        spread = max(addrs) - min(addrs)
        if spread < 0x800000:
            s += 10
    except:
        pass
    return s


def find_vtables_for_entry(entry, pidx):
    cands = []
    hits = []
    for ra in find_refs(entry):
        if is_data(ra):
            hits.append((ra, "ref"))
    for ra in ptr_index_lookup(pidx, entry):
        if is_data(ra):
            hits.append((ra, "ptr_idx"))
    seen = set()
    for ra, src in hits:
        k = int(ra.getOffset())
        if k in seen:
            continue
        seen.add(k)
        vt_start, slots = expand_vtable(ra)
        sc = score_vtable(slots)
        if sc > 0:
            cands.append((sc, vt_start, slots, src))
    cands.sort(key=lambda x: -x[0])
    return cands


def score_ctor(f, vt_start):
    if f is None:
        return -999
    body = f.getBody()
    if body is None:
        return -999
    n = body.getNumAddresses()
    if n < 16 or n > 4096:
        return -999
    s = 0
    if 32 <= n <= 2000:
        s += 10
    listing = currentProgram.getListing()
    try:
        it = listing.getInstructions(body, True)
    except:
        return s
    bl = 0
    str_z = 0
    cnt = 0
    while it.hasNext() and cnt < 500:
        cnt += 1
        try:
            i = it.next()
        except:
            break
        mn = i.getMnemonicString().lower()
        if mn in ("bl", "blr"):
            bl += 1
        elif mn in ("str", "stp", "stur", "strb", "strh"):
            try:
                txt = i.toString()
            except:
                txt = ""
            if "xzr" in txt or "wzr" in txt:
                str_z += 1
    s += min(bl, 12) * 2
    s += min(str_z, 24)
    if bl == 0:
        s -= 15
    refs_inside = 0
    try:
        rm = currentProgram.getReferenceManager()
        it2 = rm.getReferencesTo(vt_start).iterator()
        while it2.hasNext():
            r = it2.next()
            if body.contains(r.getFromAddress()):
                refs_inside += 1
    except:
        pass
    if refs_inside == 0:
        s -= 10
    else:
        s += refs_inside * 5
    return s


def find_ctors_for_vtable(vt_start, pidx):
    cands = []
    seen = set()
    hits = []
    for ra in find_refs(vt_start):
        if is_code(ra):
            hits.append((ra, "ref"))
    for ra in ptr_index_lookup(pidx, vt_start):
        if is_code(ra):
            hits.append((ra, "ptr_idx"))
    for ra, src in hits:
        f = getFunctionContaining(ra)
        if f is None:
            continue
        k = int(f.getEntryPoint().getOffset())
        if k in seen:
            continue
        seen.add(k)
        sc = score_ctor(f, vt_start)
        cands.append((sc, f, src))
    cands.sort(key=lambda x: -x[0])
    return cands


def scan_class(cls, sidx, pidx):
    t0 = time.time()
    addrs = []
    for s, al in sidx.items():
        try:
            if s == cls or s.startswith(cls + "::") or ("::" + cls) in s:
                addrs.extend(al)
        except:
            continue
    if not addrs:
        log("[%s] no string anchors" % cls)
        return None

    log("[%s] string anchors: %d" % (cls, len(addrs)))

    anchors = []
    seen = set()
    for sa in addrs[:32]:
        for ra in find_refs(sa):
            f = getFunctionContaining(ra)
            if f is None:
                continue
            if is_logger(f):
                continue
            fe = f.getEntryPoint()
            k = int(fe.getOffset())
            if k in seen:
                continue
            seen.add(k)
            anchors.append((fe, sa, f))

    if not anchors:
        log("[%s] no non-logger anchors" % cls)
        return {"class": cls, "method": None, "vtable": None, "ctor": None, "slots": []}

    log("[%s] candidate anchors: %d" % (cls, len(anchors)))
    for fe, sa, f in anchors[:8]:
        log("[%s]   anchor %s  %s  str=%s" % (cls, fa(fe), f.getName(), fa(sa)))

    res = {"class": cls, "method": None, "vtable": None, "ctor": None,
           "slots": [], "vtable_src": None, "ctor_src": None}

    best_vt = None
    for fe, sa, f in anchors:
        cands = find_vtables_for_entry(fe, pidx)
        if not cands:
            continue
        sc, vt_start, slots, src = cands[0]
        log("[%s]   anchor %s -> vtable %s (%d slots, score=%d, via=%s)" % (
            cls, fa(fe), fa(vt_start), len(slots), sc, src))
        if best_vt is None or sc > best_vt[0]:
            best_vt = (sc, vt_start, slots, fe, sa, f, src)

    if best_vt is None:
        fe, sa, f = anchors[0]
        res["method"] = (rva(fe), f.getName(), rva(sa))
        log("[%s] FAILED: no vtable found for any anchor" % cls)
        return res

    _, vt_start, slots, fe, sa, f, vsrc = best_vt
    res["method"] = (rva(fe), f.getName(), rva(sa))
    res["vtable"] = rva(vt_start)
    res["vtable_src"] = vsrc
    res["slots"] = [(rva(a), rva(t)) for a, t in slots[:256]]

    ctors = find_ctors_for_vtable(vt_start, pidx)
    if ctors:
        log("[%s] ctor candidates for vtable %s:" % (cls, fa(vt_start)))
        for sc, c, src in ctors[:5]:
            log("[%s]   ctor %s score=%d via=%s name=%s" % (
                cls, fa(c.getEntryPoint()), sc, src, c.getName()))
        sc, c, src = ctors[0]
        if sc > 0:
            res["ctor"] = (rva(c.getEntryPoint()), c.getName(), sc)
            res["ctor_src"] = src
    else:
        log("[%s] no ctor refs to vtable %s" % (cls, fa(vt_start)))

    log("[%s] done in %.2fs" % (cls, time.time() - t0))
    return res


def write_outputs(results):
    log("writing %s" % REPORT)
    try:
        with open(REPORT, "w") as fh:
            fh.write("# iOS ctor resolution (rtti-less)\n")
            fh.write("# image_base=0x%x\n" % BASE)
            fh.write("# generated at %.2fs\n\n" % elapsed())
            for r in results:
                fh.write("=== %s ===\n" % r["class"])
                if r.get("method"):
                    m = r["method"]
                    fh.write("  method: rva=0x%08x  %s  (str@0x%x)\n" % (m[0], m[1], m[2]))
                if r.get("vtable") is not None:
                    fh.write("  vtable: rva=0x%08x  slots=%d  via=%s\n" % (
                        r["vtable"], len(r.get("slots", [])), r.get("vtable_src")))
                if r.get("ctor"):
                    c = r["ctor"]
                    fh.write("  ctor:   rva=0x%08x  score=%d  via=%s  %s\n" % (
                        c[0], c[2], r.get("ctor_src"), c[1]))
                for i, (sa, ta) in enumerate(r.get("slots", [])):
                    fh.write("    [%3d] 0x%08x -> 0x%08x\n" % (i, sa, ta))
                fh.write("\n")
        log("wrote %s" % REPORT)
    except Exception as e:
        log("write REPORT failed: %s" % e)
        traceback.print_exc()

    log("writing %s" % OUT)
    try:
        n_ok = 0
        n_tot = 0
        with open(OUT, "w") as fh:
            fh.write("export const ctors = Object.freeze({\n")
            for r in results:
                n_tot += 1
                if r.get("ctor"):
                    fh.write("  %s: 0x%x,\n" % (r["class"], r["ctor"][0]))
                    n_ok += 1
                else:
                    fh.write("  // %s: unresolved\n" % r["class"])
            fh.write("});\n")
        log("wrote %s (%d/%d resolved)" % (OUT, n_ok, n_tot))
    except Exception as e:
        log("write OUT failed: %s" % e)
        traceback.print_exc()


def main():
    init_log()
    log("=== find_ctors_ios ===")
    try:
        log("program: %s" % currentProgram.getName())
        log("format: %s" % currentProgram.getExecutableFormat())
        log("language: %s" % currentProgram.getLanguage().getLanguageID().getIdAsString())
    except Exception as e:
        log("env info failed: %s" % e)
    log("image base: 0x%x" % BASE)

    try:
        dump_blocks()
    except Exception as e:
        log("dump_blocks failed: %s" % e)

    try:
        sidx = build_string_index()
    except Exception as e:
        log("build_string_index failed: %s" % e)
        traceback.print_exc()
        return
    if not sidx:
        log("FATAL: no strings indexed, aborting")
        return

    try:
        pidx = build_pointer_index()
    except Exception as e:
        log("build_pointer_index failed: %s" % e)
        traceback.print_exc()
        pidx = {}

    results = []
    for cls in CLASSES:
        if time.time() - START > BUDGET - 120:
            log("[!] global budget exhausted before class %s" % cls)
            break
        try:
            r = scan_class(cls, sidx, pidx)
        except Exception as e:
            log("[%s] EXCEPTION: %s" % (cls, e))
            traceback.print_exc()
            r = None
        if r is None:
            continue
        results.append(r)

    write_outputs(results)
    log("=== done in %.2fs ===" % elapsed())


try:
    main()
except SystemExit:
    raise
except Exception as e:
    log("FATAL: %s" % e)
    traceback.print_exc()
finally:
    close_log()