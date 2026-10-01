#!/usr/bin/env python3
import os, sys, json, time
import r2pipe

WS = os.environ.get("GITHUB_WORKSPACE", "/tmp")
BIN = os.environ.get("R2_BIN", "/tmp/brawl_bin")
JSON_PATH = os.environ.get("OFFSETS_JSON", os.path.join(WS, "offsets.json"))
OUT_JS = os.path.join(WS, "renamed_offsets.js")
LOG = os.path.join(WS, "r2_rename.log")
START = time.time()

IOS = {}
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
    try:
        v = r2.cmdj(c)
        return v if v is not None else None
    except Exception:
        return None


def load_android(path):
    if not os.path.isfile(path):
        log("android json not found: %s" % path)
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        log("json load failed: %s" % e)
        return {}


def nest(flat):
    tree = {}
    if not isinstance(flat, dict):
        return tree
    for key, value in flat.items():
        if not isinstance(value, int):
            continue
        parts = key.split("_")
        if len(parts) < 2:
            tree[key] = value
            continue
        head = parts[0]
        tail = "_".join(parts[1:])
        tree.setdefault(head, {})[tail] = value
    return tree


def detect_platform(r2):
    info = cmdj(r2, "ij") or {}
    if not isinstance(info, dict):
        return "unknown"
    binfo = info.get("bin") or {}
    core = info.get("core") or {}
    if not isinstance(binfo, dict): binfo = {}
    if not isinstance(core, dict): core = {}
    klass = (binfo.get("class") or binfo.get("bclass") or "").lower()
    osname = (core.get("os") or "").lower()
    if "mach" in klass or osname == "darwin":
        return "ios"
    if "elf" in klass or osname == "linux":
        return "android"
    return "unknown"


def as_dict(m):
    return m if isinstance(m, dict) else None


def find_base(r2, platform, name):
    info = cmdj(r2, "ij") or {}
    if not isinstance(info, dict):
        info = {}

    if platform == "ios":
        for key in ("iMj", "iM", "iij"):
            mods = cmdj(r2, key)
            if not isinstance(mods, list):
                continue
            for m in mods:
                d = as_dict(m)
                if not d:
                    continue
                mod_name = d.get("name") or d.get("file") or ""
                if name in mod_name:
                    base = d.get("baddr") or d.get("base") or 0
                    size = d.get("size") or 0
                    return int(base), int(size)
    else:
        mods = cmdj(r2, "iMMj")
        if isinstance(mods, list):
            for m in mods:
                d = as_dict(m)
                if not d:
                    continue
                if name in (d.get("name") or ""):
                    base = d.get("base") or d.get("baddr") or 0
                    size = d.get("size") or 0
                    return int(base), int(size)

    baddr = int(((info.get("bin") or {}) or {}).get("baddr", 0) or 0)
    return baddr, 0


def walk(node):
    for v in node.values():
        if isinstance(v, dict):
            for x in walk(v):
                yield x
        elif isinstance(v, int):
            yield v


def dump(node, base, prefix=""):
    for k in sorted(node.keys()):
        v = node[k]
        if isinstance(v, dict):
            dump(v, base, prefix + k + ".")
        elif isinstance(v, int):
            addr = ("0x%x" % (base + v)) if base else "?"
            log("  %-48s rva=0x%-8x addr=%s" % (prefix + k, v, addr))


def write_out(tree, base, platform):
    count = sum(1 for _ in walk(tree))
    try:
        with open(OUT_JS, "w", encoding="utf-8") as fh:
            fh.write("// auto-resolved offsets\n")
            fh.write("// platform=%s\n" % platform)
            fh.write("// base=0x%x\n" % base)
            fh.write("// resolved=%d\n\n" % count)
            fh.write("export const resolved = Object.freeze({\n")
            def emit(node, prefix=""):
                for k in sorted(node.keys()):
                    v = node[k]
                    if isinstance(v, dict):
                        emit(v, prefix + k + "_")
                    elif isinstance(v, int):
                        fh.write("    %s: 0x%x,\n" % (prefix + k, v))
            emit(tree)
            fh.write("});\n")
        log("wrote %s" % OUT_JS)
    except Exception as e:
        log("out write failed: %s" % e)


def main():
    global _fh
    try:
        _fh = open(LOG, "w")
    except Exception:
        _fh = None

    log("=== offsets ===")

    r2 = r2pipe.open(BIN, flags=["-2"])
    r2.cmd("e scr.color=0")

    platform = detect_platform(r2)
    android_flat = load_android(JSON_PATH)
    android = nest(android_flat)

    if platform == "ios":
        tree = IOS
        modname = "libg.dylib"
        label = "iOS (libg.dylib)"
    elif platform == "android":
        tree = android
        modname = "libg.so"
        label = "Android (libg.so)"
    else:
        tree = {}
        modname = ""
        label = "Unknown"

    log("platform = %s" % platform)
    log("module   = %s" % label)

    base, size = find_base(r2, platform, modname) if modname else (0, 0)
    log("base     = 0x%x size=0x%x" % (base, size))
    log("entries  = %d" % sum(1 for _ in walk(tree)))

    if tree:
        dump(tree, base)

    write_out(tree, base, platform)

    r2.quit()


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        import traceback
        log("FATAL %s" % e)
        traceback.print_exc()
        try:
            with open(OUT_JS, "w", encoding="utf-8") as fh:
                fh.write("// auto-resolved offsets\n")
                fh.write("// failed\n")
                fh.write("export const resolved = Object.freeze({});\n")
        except Exception:
            pass
        sys.exit(0)