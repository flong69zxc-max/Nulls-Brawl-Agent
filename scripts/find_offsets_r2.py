#!/usr/bin/env python3
import os
import sys
import time
import traceback

import r2pipe

WS = os.environ.get("GITHUB_WORKSPACE", "/tmp")
BIN = os.environ.get("R2_BIN", "/tmp/brawl_bin")
OUT = os.path.join(WS, "offsets_resolved.js")
REPORT = os.path.join(WS, "offsets_report.txt")
DETAIL = os.path.join(WS, "ctors_detailed.log")
BUDGET = 2400
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
    "LogicLongToCodeConverterUtil", "LogicAccessory",
    "GameButton", "GameSelectableButton", "CustomButton", "RadioButton",
    "GenericPopup", "PopupBase", "DropGUIContainer", "GameSliderComponent",
    "MapEditorModifierItem", "MapEditorModifierPopup",
    "Sprite", "Stage", "DisplayObject", "MovieClip", "MovieClipHelper",
    "TextField", "DecoratedTextField", "Application", "Name",
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


def is_logger(name):
    if not name:
        return False
    n = name.lower()
    for b in ("log", "print", "trace", "assert", "debug", "fatal", "panic", "abort"):
        if b in n:
            return True
    return False


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
    strings = cmdj(r2, "izj")
    if not strings:
        log("[!] izj returned nothing")
        return {}
    total = 0
    idx = {}
    for s in strings:
        txt = (s.get("string") or s.get("text") or "").strip()
        if not txt:
            continue
        a = addr_of(s, base)
        if not a:
            continue
        total += 1
        idx.setdefault(txt, []).append(a)
    log("[*] strings: %d unique: %d" % (total, len(idx)))
    return idx


def get_text_bounds(r2):
    sections = cmdj(r2, "iSj")
    if not sections:
        return None
    for s in sections:
        if s.get("name") in ("__text", ".text") and s.get("perm", "").find("x") >= 0:
            return (s.get("vaddr", 0), s.get("vaddr", 0) + s.get("vsize", 0))
    return None


def scan_adrp_add_for_targets(r2, targets, base):
    """Сканирует .text на ADRP+ADD, попадающие в targets.
    Возвращает dict: target_addr -> list of (instr_addr, reg)
    """
    text = get_text_bounds(r2)
    if not text:
        log("[!] no .text section")
        return {}
    t0, t1 = text
    log("[*] .text: 0x%x - 0x%x" % (t0, t1))

    target_set = set(targets)
    result = {}

    # Идём по инструкциям в .text, ищем пары ADRP + ADD
    prev_adrp = None
    count = 0
    addr = t0
    step = 4
    while addr < t1:
        if time.time() - START > BUDGET - 120:
            log("[!] budget exhausted in adrp scan at 0x%x" % addr)
            break
        op = cmdj(r2, "aoj 1 @ 0x%x" % addr)
        if not op:
            addr += step
            continue
        ins = op[0]
        mnem = ins.get("mnemonic", "")
        count += 1
        if mnem == "adrp":
            # adrp xN, page
            dst = ins.get("reg", "")
            if not dst:
                dst = ins.get("dst", "")
            prev_adrp = (addr, dst)
        elif mnem == "add" and prev_adrp is not None:
            dst = ins.get("reg", "")
            if not dst:
                dst = ins.get("dst", "")
            if dst == prev_adrp[1]:
                # попробуем вычислить целевой адрес
                # r2 обычно уже резолвит adrp/add в val
                val = ins.get("val", 0)
                if val:
                    if val in target_set:
                        result.setdefault(val, []).append((prev_adrp[0], dst))
        addr += step

    log("[*] scanned %d instructions, found %d adrp+add pairs matching targets"
        % (count, sum(len(v) for v in result.values())))
    return result


def load_mod_init_func(r2):
    """Читает __mod_init_func / __init_offsets — там адреса конструкторов."""
    out = []
    sections = cmdj(r2, "iSj")
    if not sections:
        return out
    for s in sections:
        name = s.get("name", "")
        if name in ("__mod_init_func", "__init_offsets"):
            va = s.get("vaddr", 0)
            vsize = s.get("vsize", 0)
            log("[*] %s @ 0x%x size 0x%x" % (name, va, vsize))
            if vsize > 0 and va > 0:
                ptrs = cmdj(r2, "pxqj %d @ 0x%x" % (vsize, va))
                if ptrs:
                    for p in ptrs:
                        try:
                            out.append(int(p, 16) if isinstance(p, str) else p)
                        except Exception:
                            pass
    log("[*] __mod_init_func entries: %d" % len(out))
    return out


def scan_class(r2, cls, str_index, adrp_hits, mod_inits, base):
    addrs = []
    for s, al in str_index.items():
        if s == cls or s.startswith(cls + "::") or ("::" + cls) in s \
           or s.startswith(cls + " ") or s.startswith(cls + "\t"):
            addrs.extend(al)
    if not addrs:
        log("[%s] no string anchors" % cls)
        return None

    log("[%s] string anchors: %d" % (cls, len(addrs)))

    # 1) пробуем ADRP+ADD hits
    candidates = []
    for sa in addrs:
        if sa in adrp_hits:
            for (instr_addr, reg) in adrp_hits[sa]:
                candidates.append(("adrp_add", instr_addr, sa))
                log("[%s]   ADRP+ADD hit: str@0x%x -> instr@0x%x reg=%s"
                    % (cls, sa, instr_addr, reg))

    # 2) если нет — пробуем __mod_init_func
    if not candidates and mod_inits:
        # эвристика: если в классе есть строки, а mod_init_func есть —
        # проверим, нет ли функции, которая ссылается на эту строку
        pass

    if not candidates:
        log("[%s] no ADRP+ADD candidates for string anchors" % cls)
        return {"class": cls, "method": None, "vtable": None, "ctor": None}

    # берём первый кандидат
    src, instr_addr, sa = candidates[0]
    fcn = get_function_at(r2, instr_addr)
    if fcn:
        log("[%s] function containing 0x%x: 0x%x %s"
            % (cls, instr_addr, fcn[0], fcn[1]))
        return {"class": cls, "method": (fcn[0] - base, fcn[1]),
                "vtable": None, "ctor": None, "str_addr": sa,
                "src": src}
    else:
        log("[%s] no function at 0x%x" % (cls, instr_addr))
        return {"class": cls, "method": None, "vtable": None, "ctor": None}


def get_function_at(r2, addr):
    f = cmdj(r2, "afij @ 0x%x" % addr)
    if f and isinstance(f, list) and f:
        f0 = f[0]
        return (f0.get("offset", 0), f0.get("name", ""))
    if f and isinstance(f, dict):
        return (f.get("offset", 0), f.get("name", ""))
    return None


def main():
    global _log_fh
    try:
        _log_fh = open(DETAIL, "w")
    except Exception:
        _log_fh = None

    log("=== find_offsets_r2 v4 ===")
    log("bin: %s" % BIN)

    r2 = r2pipe.open(BIN, flags=["-2"])

    log("setting analysis options ...")
    for opt in (
        "e scr.color=0",
        "e anal.timeout=1800",
        "e anal.hasnext=true",
        "e anal.strings=true",
        "e anal.autoname=true",
        "e anal.jmp.after=true",
        "e anal.arm64.preludes=true",
        "e anal.refstr=true",
        "e anal.in=io.maps.x",
    ):
        log("  %s" % opt)
        r2.cmd(opt)

    info = cmdj(r2, "ij")
    if not info:
        log("[!] cannot get bin info")
        return
    base = info.get("baddr", 0x100000000) or 0x100000000
    log("base: 0x%x" % base)

    t0 = time.time()
    log("running aaaa (full analysis) ...")
    out = cmd(r2, "aaaa")
    if out.strip():
        log("aaaa output (first 500 chars): %s" % out[:500])
    log("aaaa done in %.1fs" % (time.time() - t0))

    str_index = build_string_index(r2, base)
    if not str_index:
        log("[!] empty string index")
        return

    # соберём все адреса строк
    all_str_addrs = []
    for al in str_index.values():
        all_str_addrs.extend(al)
    log("[*] total string addresses: %d" % len(all_str_addrs))

    # просканируем .text на ADRP+ADD
    log("scanning .text for ADRP+ADD to strings ...")
    adrp_hits = scan_adrp_add_for_targets(r2, all_str_addrs, base)

    # загрузим __mod_init_func
    mod_inits = load_mod_init_func(r2)

    results = []
    for cls in CLASSES:
        if time.time() - START > BUDGET - 120:
            log("[!] budget exhausted before %s" % cls)
            break
        try:
            r = scan_class(r2, cls, str_index, adrp_hits, mod_inits, base)
        except Exception as e:
            log("[%s] EXCEPTION: %s" % (cls, e))
            traceback.print_exc()
            continue
        if r:
            results.append(r)

    r2.quit()

    try:
        with open(REPORT, "w") as fh:
            fh.write("# r2 ctor resolution (v4, ADRP+ADD scan)\n")
            fh.write("# base=0x%x\n\n" % base)
            for r in results:
                fh.write("=== %s ===\n" % r["class"])
                if r.get("method"):
                    fh.write("  method: rva=0x%08x  %s\n"
                             % (r["method"][0], r["method"][1]))
                if r.get("src"):
                    fh.write("  src:    %s\n" % r["src"])
                fh.write("\n")
    except Exception as e:
        log("write REPORT failed: %s" % e)

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
        log("[*] resolved %d/%d" % (n_ok, n_tot))
    except Exception as e:
        log("write OUT failed: %s" % e)

    log("[+] wrote %s and %s" % (OUT, REPORT))


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        log("FATAL: %s" % e)
        traceback.print_exc()