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


def dump_bin_info(r2):
    info = cmdj(r2, "ij")
    if info:
        log("ij: arch=%s bits=%s baddr=0x%x binsz=%s"
            % (info.get("arch", "?"), info.get("bits", "?"),
               info.get("baddr", 0), info.get("size", "?")))
        log("ij: endian=%s os=%s type=%s"
            % (info.get("endian", "?"), info.get("os", "?"), info.get("type", "?")))
    else:
        log("ij: no data")

    log("iSj sections (first 30):")
    secs = cmdj(r2, "iSj")
    if secs:
        for i, s in enumerate(secs[:30]):
            log("  [%2d] name=%-32s vaddr=0x%x size=0x%x perm=%s"
                % (i, s.get("name", ""), s.get("vaddr", 0),
                   s.get("size", 0), s.get("perm", "")))
        if len(secs) > 30:
            log("  ... %d more sections" % (len(secs) - 30))
    else:
        log("iSj: no sections!")

    log("config check:")
    for opt in ("asm.arch", "asm.bits", "anal.arch", "anal.plugin", "asm.features"):
        log("  %s = %s" % (opt, cmd(r2, "e %s" % opt).strip()))


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


# --- ARM64 instruction decode ---
# ADRP: bits 31=1, 30:29=immlo, 28:24=10000, 23:5=immhi, 4:0=Rd
# ADD (imm, 64-bit, no flag): bits 31=1, 30=0, 29=0, 28:23=100010, 22=sh, 21:10=imm12, 9:5=Rn, 4:0=Rd

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
    # 0x91000000 base, sh bit varies: use mask ignoring sh
    return (w & 0xFF800000) == 0x91000000


def decode_add_imm(w):
    rd = w & 0x1F
    rn = (w >> 5) & 0x1F
    imm12 = (w >> 10) & 0xFFF
    sh = (w >> 22) & 1
    if sh:
        imm12 = imm12 << 12
    return (rd, rn, imm12)


def scan_text_for_adrp_add(r2, text_start, text_end, target_set):
    """Byte scan .text for ADRP+ADD pairs matching target_set."""
    CHUNK = 0x100000  # 1 MB
    overlap = 32
    results = {}
    total_pairs = 0
    total_adrp = 0
    total_add = 0
    addr = text_start
    carry = b""
    carry_addr = text_start
    while addr < text_end:
        if time.time() - START > BUDGET - 300:
            log("[!] adrp scan budget exhausted at 0x%x" % addr)
            break
        size = min(CHUNK, text_end - addr)
        hx = cmd(r2, "p8 %d @ 0x%x" % (size, addr))
        hx = hx.strip()
        if not hx:
            log("[!] p8 returned empty at 0x%x" % addr)
            addr += size
            continue
        try:
            data = bytes.fromhex(hx)
        except Exception:
            log("[!] hex parse failed at 0x%x" % addr)
            addr += size
            continue
        data = carry + data
        data_start = carry_addr
        n = len(data) // 4
        i = 0
        while i < n:
            off = i * 4
            w = struct.unpack_from("<I", data, off)[0]
            ia = data_start + off
            if is_adrp(w):
                total_adrp += 1
                rd_adrp = w & 0x1F
                page = decode_adrp_imm(w, ia)
                # look ahead up to 6 instrs for ADD xR, xR, #imm
                found = False
                for j in range(i + 1, min(i + 7, n)):
                    w2 = struct.unpack_from("<I", data, j * 4)[0]
                    if is_add_imm64(w2):
                        rd, rn, imm = decode_add_imm(w2)
                        if rd == rd_adrp and rn == rd_adrp:
                            total_add += 1
                            target = page + imm
                            if target in target_set:
                                results.setdefault(target, []).append(ia)
                                found = True
                            break
            i += 1
        carry = data[-overlap:] if len(data) > overlap else data
        carry_addr = addr + size - len(carry)
        addr += size
        if (addr - text_start) % (8 * CHUNK) == 0:
            log("[*] adrp scan progress: 0x%x / 0x%x (%d pairs)"
                % (addr, text_end, sum(len(v) for v in results.values())))
    log("[*] adrp scan done: adrp=%d add=%d pairs-to-targets=%d"
        % (total_adrp, total_add, sum(len(v) for v in results.values())))
    return results


def load_mod_init_func(r2):
    out = []
    sections = cmdj(r2, "iSj")
    if not sections:
        return out
    for s in sections:
        name = s.get("name", "") or ""
        if "__mod_init_func" in name or "__init_offsets" in name:
            va = s.get("vaddr", 0)
            sz = s.get("size", 0)
            log("[*] %s @ 0x%x size 0x%x" % (name, va, sz))
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
    log("[*] __mod_init_func entries: %d" % len(out))
    return out


def get_function_at(r2, addr):
    f = cmdj(r2, "afij @ 0x%x" % addr)
    if isinstance(f, list) and f:
        f0 = f[0]
        return (f0.get("offset", 0), f0.get("name", ""))
    if isinstance(f, dict):
        return (f.get("offset", 0), f.get("name", ""))
    return None


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

    candidates = []
    for sa in addrs:
        if sa in adrp_hits:
            for ia in adrp_hits[sa]:
                candidates.append(("adrp_add", ia, sa))
                log("[%s]   ADRP+ADD hit: str@0x%x -> adrp@0x%x" % (cls, sa, ia))

    if not candidates:
        log("[%s] no ADRP+ADD candidates" % cls)
        return {"class": cls, "method": None, "vtable": None, "ctor": None}

    src, ia, sa = candidates[0]
    f = get_function_at(r2, ia)
    if f:
        log("[%s] func containing 0x%x: 0x%x %s" % (cls, ia, f[0], f[1]))
        return {"class": cls, "method": (f[0] - base, f[1]),
                "vtable": None, "ctor": None, "src": src, "str_addr": sa}
    log("[%s] no function at 0x%x" % (cls, ia))
    return {"class": cls, "method": None, "vtable": None, "ctor": None}


def main():
    global _log_fh
    try:
        _log_fh = open(DETAIL, "w")
    except Exception:
        _log_fh = None

    log("=== find_offsets_r2 v5 ===")
    log("bin: %s" % BIN)

    r2 = r2pipe.open(BIN, flags=["-2"])

    log("setting options ...")
    for opt in (
        "e scr.color=0",
        "e anal.timeout=1800",
        "e anal.hasnext=true",
        "e anal.strings=true",
        "e anal.autoname=true",
        "e anal.jmp.after=true",
        "e anal.arm64.preludes=true",
        "e anal.refstr=true",
    ):
        r2.cmd(opt)

    # Форсируем архитектуру, если r2 не угадал
    r2.cmd("e asm.arch=arm")
    r2.cmd("e asm.bits=64")
    try:
        r2.cmd("e anal.arch=arm")
    except Exception:
        pass

    dump_bin_info(r2)

    info = cmdj(r2, "ij")
    base = (info or {}).get("baddr", 0x100000000) or 0x100000000
    log("base: 0x%x" % base)

    # === анализ ===
    t0 = time.time()
    log("running aaa ...")
    r2.cmd("aaa")
    log("aaa done in %.1fs, aflc=%s" % (time.time() - t0, cmd(r2, "aflc").strip()))
    t0 = time.time()
    log("running aac ...")
    r2.cmd("aac")
    log("aac done in %.1fs, aflc=%s" % (time.time() - t0, cmd(r2, "aflc").strip()))
    t0 = time.time()
    log("running aar ...")
    r2.cmd("aar")
    log("aar done in %.1fs" % (time.time() - t0))

    str_index = build_string_index(r2, base)
    if not str_index:
        log("[!] empty string index")
        return

    all_str_addrs = []
    for al in str_index.values():
        all_str_addrs.extend(al)
    target_set = set(all_str_addrs)
    log("[*] total string addrs: %d" % len(target_set))

    text = get_text_bounds(r2)
    if not text:
        log("[!] .text not found, cannot scan")
        r2.quit()
        return
    ts, te = text
    log("[*] .text: 0x%x - 0x%x (size 0x%x)" % (ts, te, te - ts))

    log("scanning .text for ADRP+ADD ...")
    adrp_hits = scan_text_for_adrp_add(r2, ts, te, target_set)

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
            fh.write("# r2 ctor resolution (v5, byte-scan ADRP+ADD)\n")
            fh.write("# base=0x%x\n\n" % base)
            for r in results:
                fh.write("=== %s ===\n" % r["class"])
                if r.get("method"):
                    fh.write("  method: rva=0x%08x  %s\n"
                             % (r["method"][0], r["method"][1]))
                if r.get("src"):
                    fh.write("  src:    %s\n" % r["src"])
                if r.get("str_addr"):
                    fh.write("  str:    rva=0x%08x\n" % (r["str_addr"] - base))
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