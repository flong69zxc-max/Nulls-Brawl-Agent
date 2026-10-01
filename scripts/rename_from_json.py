#!/usr/bin/env python3
import os, sys, json, time
import r2pipe

WS = os.environ.get("GITHUB_WORKSPACE", "/tmp")
BIN = os.environ.get("R2_BIN", "/tmp/brawl_bin")
JSON_PATH = os.environ.get("OFFSETS_JSON", os.path.join(WS, "offsets.json"))
START = time.time()

IOS = {}

def log(m):
    line = "[%7.2f] %s" % (time.time() - START, m)
    try:
        sys.stdout.write(line + "\n"); sys.stdout.flush()
    except Exception:
        pass

def cmdj(r2, c):
    try: return r2.cmdj(c)
    except Exception: return None

def load_android(path):
    if not os.path.isfile(path):
        log("android json not found: %s" % path)
        return {}
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def nest(flat):
    tree = {}
    for key, value in flat.items():
        parts = key.split("_")
        if len(parts) < 2:
            tree[key] = value; continue
        head = parts[0]; tail = "_".join(parts[1:])
        tree.setdefault(head, {})[tail] = value
    return tree

def detect_platform(r2):
    info = cmdj(r2, "ij") or {}
    binfo = info.get("bin", {}) or {}
    core = info.get("core", {}) or {}
    klass = (binfo.get("class") or binfo.get("bclass") or "").lower()
    osname = (core.get("os") or "").lower()
    if "mach" in klass or osname == "darwin":
        return "ios"
    if "elf" in klass or osname == "linux":
        return "android"
    return "unknown"

def find_base(r2, platform, name):
    info = cmdj(r2, "ij") or {}
    if platform == "ios":
        mods = cmdj(r2, "iMj") or []
        for m in mods:
            if name in (m.get("name") or ""):
                return int(m.get("baddr", 0)), int(m.get("size", 0))
    else:
        for m in cmdj(r2, "iMMj") or []:
            if name in (m.get("name") or ""):
                return int(m.get("base", 0)), int(m.get("size", 0))
    baddr = int((info.get("bin", {}) or {}).get("baddr", 0) or 0)
    return baddr, 0

def rva_of(tree, path):
    node = tree
    for p in path.split("."):
        if not isinstance(node, dict): return None
        node = node.get(p)
    return node if isinstance(node, int) else None

def dump(node, base, prefix=""):
    for k in sorted(node.keys()):
        v = node[k]
        if isinstance(v, dict):
            dump(v, base, prefix + k + ".")
        elif isinstance(v, int):
            addr = ("0x%x" % (base + v)) if base else "?"
            log("  %-48s rva=0x%-8x addr=%s" % (prefix + k, v, addr))

def main():
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

    if not tree:
        log("no offsets for this platform")
        r2.quit(); return

    log("entries  = %d" % sum(1 for _ in walk(tree)))
    dump(tree, base)

    r2.quit()

def walk(node):
    for v in node.values():
        if isinstance(v, dict):
            for x in walk(v): yield x
        elif isinstance(v, int):
            yield v

if __name__ == "__main__":
    try: main()
    except Exception as e:
        import traceback
        log("FATAL %s" % e)
        traceback.print_exc()
        sys.exit(1)