#!/usr/bin/env python3
import os
import sys
import time
import struct
import traceback

import r2pipe

WS = os.environ.get("GITHUB_WORKSPACE", "/tmp")
BIN = os.environ.get("R2_BIN", "/tmp/brawl_bin")
OUT = os.path.join(WS, "offsets_resolved.js")
REPORT = os.path.join(WS, "offsets_report.txt")
DETAIL = os.path.join(WS, "ctors_detailed.log")
BUDGET = 2700
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
        n = s.get("name", "") or ""
        p = s.get("perm", "") or ""
        if ("__text" in n or ".text" in n) and "x" in p:
            return (s.get("vaddr", 0), s.get("vaddr", 0) + s.get("size", 0))
    return None


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


def is_ldr_literal_64(w):
    # LDR Xt, #imm19 (literal, 64-bit): 0x58000000 base, bits 31:24 = 01011000
    return (w & 0xFF000000) == 0x58000000


def decode_ldr_literal(w, pc):
    rt = w & 0x1F
    imm19 = (w >> 5) & 0x7FFFF
    if imm19 & (1 << 18):
        imm19 -= (1 << 19)
    return (rt, pc + (imm19 << 2))


def scan_adrp_add(r2, ts, te, target_set):
    CHUNK = 0x100000
    overlap = 32
    results = {}
    addr = ts
    carry = b""
    carry_addr = ts
    total_adrp = 0
    total_add = 0
    while addr < te:
        if time.time() - START > BUDGET - 300:
            log("[!] adrp scan budget exhausted")
            break
        size = min(CHUNK, te - addr)
        hx = cmd(r2, "p8 %d @ 0x%x" % (size, addr)).strip()
        if not hx:
            addr += size
            continue
        try:
            data = bytes.fromhex(hx)
        except Exception:
            addr += size
            continue
        data = carry + data
        data_start = carry_addr
        n = len(data) // 4
        for i in range(n):
            off = i * 4
            w = struct.unpack_from("<I", data, off)[0]
            ia = data_start + off
            if is_adrp(w):
                total_adrp += 1
                rd_adrp = w & 0x1F
                page = decode_adrp_imm(w, ia)
                for j in range(i + 1, min(i + 7, n)):
                    w2 = struct.unpack_from("<I", data, j * 4)[0]
                    if is_add_imm64(w2):
                        rd, rn, imm = decode_add_imm(w2)
                        if rd == rd_adrp and rn == rd_adrp:
                            total_add += 1
                            target = page + imm
                            if target in target_set:
                                results.setdefault(target, []).append(ia)
                            break
        carry = data[-overlap:] if len(data) > overlap else data
        carry_addr = addr + size - len(carry)
        addr += size
    log("[*] adrp+add scan: adrp=%d add=%d hits=%d"
        % (total_adrp, total_add, sum(len(v) for v in results.values())))
    return results


def scan_ldr_literal(r2, ts, te, target_set):
    CHUNK = 0x100000
    overlap = 32
    results = {}
    addr = ts
    carry = b""
    carry_addr = ts
    total_ldr = 0
    while addr < te:
        if time.time() - START > BUDGET - 300:
            break
        size = min(CHUNK, te - addr)
        hx = cmd(r2, "p8 %d @ 0x%x" % (size, addr)).strip()
        if not hx:
            addr += size
            continue
        try:
            data = bytes.fromhex(hx)
        except Exception:
            addr += size
            continue
        data = carry + data
        data_start = carry_addr
        n = len(data) // 4
        for i in range(n):
            off = i * 4
            w = struct.unpack_from("<I", data, off)[0]
            ia = data_start + off
            if is_ldr_literal_64(w):
                total_ldr += 1
                rt, target = decode_ldr_literal(w, ia)
                # проверим, не указывает ли literal на указатель на строку
                if target in target_set:
                    results.setdefault(target, []).append(ia)
                    continue
                # проверим, не указывает ли literal на ячейку, где лежит ptr на строку
                try:
                    hx2 = cmd(r2, "pxq 8 @ 0x%x" % target).strip()
                    if hx2:
                        for line in hx2.splitlines():
                            parts = line.split()
                            if len(parts) >= 2:
                                try:
                                    v = int(parts[1], 16)
                                    if v in target_set:
                                        results.setdefault(v, []).append(ia)
                                except Exception:
                                    pass
                except Exception:
                    pass
        carry = data[-overlap:] if len(data) > overlap else data
        carry_addr = addr + size - len(carry)
        addr += size
    log("[*] ldr-literal scan: ldr=%d hits=%d"
        % (total_ldr, sum(len(v) for v in results.values())))
    return results


def load_init_offsets(r2):
    out = []
    sections = cmdj(r2, "iSj")
    if not sections:
        return out
    for s in sections:
        name = s.get("name", "") or ""
        if "__mod_init_func" in name or "__init_offsets" in name:
            va = s.get("vaddr", 0)
            sz = s.get("size", 0)
            if sz > 0 and va > 0:
                raw = cmd(r2, "p8 %d @ 0x%x" % (sz, va)).strip()
                try:
                    b = bytes.fromhex(raw)
                except Exception:
                    continue
                for k in range(0, len(b) - 7, 8):
                    p = struct.unpack_from("<Q", b, k)[0]
                    if p and p > 0x100000000:
                        out.append(p)
    log("[*] __init_offsets entries: %d" % len(out))
    return out


def get_function_at(r2, addr):
    f = cmdj(r2, "afij @ 0x%x" % addr)
    if isinstance(f, list) and f:
        best = None
        for f0 in f:
            off = f0.get("offset", 0)
            sz = f0.get("size", 0)
            if off <= addr < off + sz:
                if best is None or sz > best[2]:
                    best = (off, f0.get("name", ""), sz)
        if best:
            return (best[0], best[1])
        return (f[0].get("offset", 0), f[0].get("name", ""))
    if isinstance(f, dict):
        return (f.get("offset", 0), f.get("name", ""))
    return None


def function_ends_at(r2, addr, max_len=0x4000):
    """Возвращает адрес начала функции, читая инструкции назад до рет/очевидного конца."""
    f = get_function_at(r2, addr)
    if f:
        return f
    return None


def analyze_function(r2, func_addr, base):
    """Дизасм + скор."""
    fj = cmdj(r2, "afij @ 0x%x" % func_addr)
    if not fj:
        return None
    if isinstance(fj, list):
        f0 = None
        for x in fj:
            if x.get("offset", 0) == func_addr:
                f0 = x
                break
        if f0 is None:
            f0 = fj[0]
    else:
        f0 = fj
    size = f0.get("size", 0)
    if size <= 0 or size > 0x8000:
        return None

    ops = cmdj(r2, "pdj %d @ 0x%x" % (min(size // 4 + 4, 400), func_addr))
    if not ops:
        return None

    calls = []
    n_bl = 0
    n_ctor_calls = 0
    n_str_x0 = 0
    n_ret = 0
    for o in ops:
        mn = (o.get("mnemonic") or "").lower()
        if mn in ("bl", "blr"):
            n_bl += 1
            tgt = (o.get("jump") or o.get("ptr") or 0)
            jname = ""
            if tgt:
                try:
                    jname = cmd(r2, "afn @ 0x%x" % tgt).strip()
                except Exception:
                    jname = ""
            calls.append((o.get("offset", 0), tgt, jname))
            if "Znwm" in jname or "operator_new" in jname or "ZNwm" in jname:
                n_ctor_calls += 1
            if "ZdlPv" in jname or "ZdlPvm" in jname:
                n_ctor_calls += 1
        elif mn == "ret":
            n_ret += 1
        elif mn in ("str", "stp") and ("x0" in (o.get("opex", {}).get("operands", "") or "")):
            pass
        # проверка str с x0 как источник (this) — упрощённо
        if mn == "str":
            txt = o.get("opex", {}).get("operands", "")
            if txt and txt.startswith("x0,"):
                n_str_x0 += 1

    # вычислим размер в инструкциях
    ninstr = len(ops)

    # скор
    score = 0
    if n_ctor_calls > 0:
        score += 50 * n_ctor_calls
    if n_bl == 0:
        score -= 30
    if n_ret > 1:
        score -= 10
    if ninstr < 20:
        score -= 20
    if ninstr > 500:
        score -= 15
    # ctor обычно вызывает 2+ функции (базовый ctor, super, init полей)
    score += min(n_bl, 20) * 2
    if n_str_x0 > 0:
        score += n_str_x0 * 3

    return {
        "func": func_addr,
        "size": size,
        "ninstr": ninstr,
        "n_bl": n_bl,
        "n_ctor_calls": n_ctor_calls,
        "n_ret": n_ret,
        "score": score,
        "calls": calls[:30],
    }


def scan_class(r2, cls, str_index, adrp_hits, ldr_hits, init_offsets, base):
    addrs = []
    for s, al in str_index.items():
        if s == cls or s.startswith(cls + "::") or ("::" + cls) in s \
           or s.startswith(cls + " ") or s.startswith(cls + "\t"):
            addrs.extend(al)
    if not addrs:
        log("[%s] no string anchors" % cls)
        return None

    log("[%s] string anchors: %d" % (cls, len(addrs)))

    hits = []
    for sa in addrs:
        for ia in adrp_hits.get(sa, []):
            hits.append(("adrp", ia, sa))
        for ia in ldr_hits.get(sa, []):
            hits.append(("ldr", ia, sa))

    if not hits:
        log("[%s] no ADRP+ADD or LDR hits" % cls)
        return {"class": cls, "method": None, "vtable": None, "ctor": None}

    log("[%s] total hits: %d" % (cls, len(hits)))

    # собираем уникальные функции
    candidates = {}
    for how, ia, sa in hits[:40]:
        f = get_function_at(r2, ia)
        if not f:
            r2.cmd("af @ 0x%x" % ia)
            f = get_function_at(r2, ia)
        if not f:
            continue
        fa = f[0]
        if fa not in candidates:
            candidates[fa] = {"how": how, "hits": [], "name": f[1]}
        candidates[fa]["hits"].append((ia, sa))

    if not candidates:
        log("[%s] no functions for hits" % cls)
        return {"class": cls, "method": None, "vtable": None, "ctor": None}

    log("[%s] candidate functions: %d" % (cls, len(candidates)))
    scored = []
    for fa, meta in candidates.items():
        info = analyze_function(r2, fa, base)
        if not info:
            continue
        # bonus если встречается в init_offsets
        in_init = any(abs(fa - io) < 0x40 or abs(io - fa) < 0x40 for io in init_offsets)
        if in_init:
            info["score"] += 100
            info["in_init"] = True
        # бонус за количество уникальных хит-строк класса
        uniq_strs = set(sa for _, sa in meta["hits"])
        info["score"] += len(uniq_strs) * 4
        info["hits"] = meta["hits"]
        info["how"] = meta["how"]
        info["name"] = meta["name"]
        scored.append(info)

    scored.sort(key=lambda x: -x["score"])

    log("[%s] top-3 by score:" % cls)
    for i, c in enumerate(scored[:3]):
        log("[%s]   [%d] score=%d func=0x%x (%s) size=%d ninstr=%d n_bl=%d n_ctor=%d in_init=%s"
            % (cls, i, c["score"], c["func"], c["name"], c["size"],
               c["ninstr"], c["n_bl"], c["n_ctor_calls"], c.get("in_init", False)))

    best = scored[0]

    return {"class": cls, "method": (best["func"] - base, best["name"]),
            "vtable": None, "ctor": (best["func"] - base, best["name"]),
            "score": best["score"], "src": best["how"],
            "str_addr": best["hits"][0][1] if best["hits"] else 0,
            "hit_addr": best["hits"][0][0] if best["hits"] else 0,
            "n_ctor_calls": best["n_ctor_calls"]}


def main():
    global _log_fh
    try:
        _log_fh = open(DETAIL, "w")
    except Exception:
        _log_fh = None

    log("=== find_offsets_r2 v7 ===")
    log("bin: %s" % BIN)

    r2 = r2pipe.open(BIN, flags=["-2"])
    for opt in (
        "e scr.color=0",
        "e anal.timeout=1800",
        "e anal.hasnext=true",
        "e anal.strings=true",
        "e anal.autoname=true",
        "e anal.arm64.preludes=true",
        "e anal.refstr=true",
        "e asm.arch=arm",
        "e asm.bits=64",
    ):
        r2.cmd(opt)
    try:
        r2.cmd("e anal.arch=arm")
    except Exception:
        pass

    info = cmdj(r2, "ij")
    base = (info or {}).get("baddr", 0x100000000) or 0x100000000
    log("base: 0x%x" % base)

    t0 = time.time()
    r2.cmd("aaa")
    log("aaa %.1fs aflc=%s" % (time.time() - t0, cmd(r2, "aflc").strip()))
    t0 = time.time()
    r2.cmd("aac")
    log("aac %.1fs aflc=%s" % (time.time() - t0, cmd(r2, "aflc").strip()))

    str_index = build_string_index(r2, base)
    if not str_index:
        log("[!] empty string index")
        return

    target_set = set()
    for al in str_index.values():
        for a in al:
            target_set.add(a)
    log("[*] total string addrs: %d" % len(target_set))

    text = get_text_bounds(r2)
    if not text:
        log("[!] .text not found")
        r2.quit()
        return
    ts, te = text
    log("[*] .text: 0x%x - 0x%x (size 0x%x)" % (ts, te, te - ts))

    adrp_hits = scan_adrp_add(r2, ts, te, target_set)
    ldr_hits = scan_ldr_literal(r2, ts, te, target_set)
    init_offsets = load_init_offsets(r2)

    results = []
    for cls in CLASSES:
        if time.time() - START > BUDGET - 120:
            log("[!] budget exhausted before %s" % cls)
            break
        try:
            r = scan_class(r2, cls, str_index, adrp_hits, ldr_hits, init_offsets, base)
        except Exception as e:
            log("[%s] EXCEPTION: %s" % (cls, e))
            traceback.print_exc()
            continue
        if r:
            results.append(r)

    r2.quit()

    try:
        with open(REPORT, "w") as fh:
            fh.write("# r2 ctor resolution (v7)\n")
            fh.write("# base=0x%x\n\n" % base)
            for r in results:
                fh.write("=== %s ===\n" % r["class"])
                if r.get("method"):
                    fh.write("  method: rva=0x%08x  %s\n"
                             % (r["method"][0], r["method"][1]))
                if r.get("score") is not None:
                    fh.write("  score:  %d\n" % r["score"])
                if r.get("n_ctor_calls") is not None:
                    fh.write("  n_ctor_calls: %d\n" % r["n_ctor_calls"])
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
                if r.get("method"):
                    fh.write("  %s: 0x%x,\n" % (r["class"], r["method"][0]))
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