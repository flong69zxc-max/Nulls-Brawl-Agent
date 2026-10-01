#!/usr/bin/env python3
import os, sys, time, struct, re, bisect, traceback
import r2pipe

WS = os.environ.get("GITHUB_WORKSPACE", "/tmp")
BIN = os.environ.get("R2_BIN", "/tmp/brawl_bin")
LOG = os.path.join(WS, "r2_ios.log")
START = time.time()

TARGETS = [
"MessageManager.receiveMessage",
"MessageManager.sendMessage",
"MessageManager.instance",
"LogicBattleModeClient.update",
"LogicBattleModeClient.getOwnCharacter",
"BattleScreen.update",
"BattleScreen.getClosestTargetForAutoshoot",
"BattleScreen.activateSkill",
"BattleScreen.updateMovement",
"BattleScreen.autoShoot",
"BattleScreen.convertToControlScheme",
"LogicGameObjectClient.getX",
"LogicGameObjectClient.getY",
"LogicGameObjectClient.getGlobalID",
"LogicProjectileData.getSpeed",
"LogicProjectileData.getRadius",
"Character.update",
"GameMain.update",
"Stage.addChild",
"Stage.instance",
"GameButton.ctor",
"GenericPopup.ctor",
"GameSliderComponent.ctor",
"NativeFont.formatString",
"MovieClip.setText",
"MovieClip.getChildByName",
]

_fh = None
def log(m):
    line = "[%7.2f] %s" % (time.time() - START, m)
    print(line)
    if _fh:
        _fh.write(line + "\n"); _fh.flush()

def cmdj(r2, c):
    try: return r2.cmdj(c)
    except Exception: return None

def cmd(r2, c):
    try: return r2.cmd(c)
    except Exception: return ""

def strip_pac(raw):
    """Снимаем PAC-подпись: оставляем только младшие 48 бит."""
    return raw & 0x0000FFFFFFFFFFFF

def decode_chained_ptr(raw, base):
    """Эвристика для dyld_chained_ptr_arm64e: старшие 51 бит — target, младшие 12 — next."""
    # Вариант 1: target = raw >> 12 (для arm64e с 12-битным next)
    t1 = raw >> 12
    # Вариант 2: target = raw & 0x7FFFFFFFFFF (51 бит)
    t2 = raw & 0x7FFFFFFFFFF
    # Вариант 3: target = raw & 0xFFFFFFFFF (36 бит, arm64 без PAC)
    t3 = raw & 0xFFFFFFFFF
    return [t1, t2, t3]

def candidates(raw, base, lo, hi):
    """Возвращает все возможные виртуальные адреса из сырого qword."""
    out = []
    # прямые кандидаты
    for v in (raw, strip_pac(raw)):
        if lo <= v < hi and (v & 3) == 0:
            out.append(v)
    # chained-кандидаты
    for v in decode_chained_ptr(raw, base):
        if lo <= v < hi and (v & 3) == 0:
            out.append(v)
        v2 = v + base
        if lo <= v2 < hi and (v2 & 3) == 0:
            out.append(v2)
    return list(set(out))

def main():
    global _fh
    try: _fh = open(LOG, "w")
    except Exception: _fh = None

    log("=== iOS offset finder ===")
    r2 = r2pipe.open(BIN, flags=["-2"])
    r2.cmd("e scr.color=0")
    r2.cmd("e asm.arch=arm")
    r2.cmd("e asm.bits=64")
    r2.cmd("e anal.cpp.abi=itanium")   # важно для C++ RTTI
    r2.cmd("e bin.relocs.apply=true")  # применяем relocations, если r2 умеет

    log("aa...")
    r2.cmd("aa")
    log("aa done")

    info = cmdj(r2, "ij") or {}
    base = info.get("baddr", 0x100000000)
    log("base=0x%x" % base)

    # Собираем функции из символов и анализа
    funcs = cmdj(r2, "aflj") or []
    log("functions=%d" % len(funcs))

    # Ищем адреса строк "Class::method"
    str_index = {}
    for s in (cmdj(r2, "izj") or []):
        txt = (s.get("string") or "").strip()
        if not txt or "::" not in txt:
            continue
        va = s.get("vaddr", 0)
        if va:
            str_index.setdefault(txt, []).append(va)
    log("strings with :: = %d" % len(str_index))

    # Для каждой строки ищем xref через axt
    results = {}
    for target in TARGETS:
        cls, method = target.split(".", 1)
        needle = cls + "::" + method
        if needle not in str_index:
            log("  %-45s NO STRING" % target)
            continue

        found = None
        for sva in str_index[needle]:
            # axtj @ sva — ищем кросс-ссылки на адрес строки
            xrefs = cmdj(r2, "axtj @ 0x%x" % sva) or []
            for x in xrefs:
                frm = x.get("from", 0)
                if not frm:
                    continue
                # Ищем функцию, содержащую этот xref
                f = cmdj(r2, "afij @ 0x%x" % frm)
                if f and f.get("offset") is not None:
                    found = f["offset"]
                    break
            if found:
                break

        if found:
            rva = found - base
            results[target] = rva
            log("  %-45s 0x%08x" % (target, rva))
        else:
            log("  %-45s not found" % target)

    r2.quit()

    log("")
    log("=== RESULT %d/%d ===" % (len(results), len(TARGETS)))
    for t in TARGETS:
        if t in results:
            log("  %-45s 0x%08x" % (t, results[t]))

if __name__ == "__main__":
    try: main()
    except Exception as e:
        log("FATAL %s" % e)
        traceback.print_exc()