#!/usr/bin/env python3
import os, sys, time, struct, re, bisect, traceback, binascii
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

def main():
    global _fh
    try: _fh = open(LOG, "w")
    except Exception: _fh = None

    log("=== find_offsets_ios v2 ===")
    r2 = r2pipe.open(BIN, flags=["-2"])
    r2.cmd("e scr.color=0")
    r2.cmd("e asm.arch=arm")
    r2.cmd("e asm.bits=64")
    r2.cmd("e anal.cpp.abi=itanium")
    r2.cmd("e anal.hasnext=true")
    r2.cmd("e anal.depth=24")
    r2.cmd("e anal.jmp.tbl=true")
    r2.cmd("e anal.arm64.v35=true")

    info = cmdj(r2, "ij") or {}
    base = info.get("baddr", 0x100000000) or 0x100000000
    core = info.get("core", {}) or {}
    ftype = (core.get("format") or "?")
    log("format=%s base=0x%x" % (ftype, base))

    binj = cmdj(r2, "iIj") or {}
    if binj:
        enc = binj.get("crypto", binj.get("encrypted", None))
        if enc is not None:
            log("encrypted=%s" % enc)

    sections = cmdj(r2, "iSj") or []
    text_va = None
    text_sz = 0
    for s in sections:
        n = s.get("name", "") or ""
        if "__text" in n and "x" in (s.get("perm") or ""):
            text_va = s.get("vaddr"); text_sz = s.get("size"); break
    if text_va:
        log(".text 0x%x-0x%x size=%d" % (text_va, text_va + text_sz, text_sz))

    log("running aaa (full analysis)...")
    r2.cmd("aaa")
    afl = cmdj(r2, "aflj") or []
    log("functions after aaa=%d" % len(afl))

    if len(afl) < 100:
        log("running aac (analyze all calls)...")
        r2.cmd("aac")
        afl = cmdj(r2, "aflj") or []
        log("functions after aac=%d" % len(afl))

    if len(afl) < 100:
        log("running aar (analyze references)...")
        r2.cmd("aar")
        afl = cmdj(r2, "aflj") or []
        log("functions after aar=%d" % len(afl))

    # Карта адрес -> функция для быстрого поиска
    func_map = {}
    for f in afl:
        off = f.get("offset")
        if off is not None:
            func_map[off] = f
    func_offsets = sorted(func_map.keys())

    def find_func_at(addr):
        if not func_offsets: return None
        idx = bisect.bisect_right(func_offsets, addr) - 1
        if idx < 0: return None
        f = func_map[func_offsets[idx]]
        end = f.get("offset", 0) + f.get("size", 0)
        if addr < end: return f.get("offset")
        return None

    log("--- searching strings via /xj ---")
    results = {}
    for target in TARGETS:
        cls, method = target.split(".", 1)
        needle = cls + "::" + method
        needle_hex = binascii.hexlify(needle.encode("utf-8")).decode("ascii")

        hits = cmdj(r2, "/xj %s" % needle_hex) or []
        if not hits:
            log("  %-48s NO_BYTES" % target)
            continue

        log("  %-48s hits=%d" % (target, len(hits)))

        found_func = None
        for h in hits:
            hit_va = h.get("offset")
            if hit_va is None: continue
            xrefs = cmdj(r2, "axtj @ 0x%x" % hit_va) or []
            for x in xrefs:
                frm = x.get("from")
                if frm is None: continue
                f = find_func_at(frm)
                if f is not None:
                    found_func = f
                    break
            if found_func is not None:
                break

        if found_func is not None:
            rva = found_func - base
            results[target] = rva
            log("  %-48s -> 0x%08x (func 0x%x)" % (target, rva, found_func))
        else:
            log("  %-48s no_xref_func" % target)

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