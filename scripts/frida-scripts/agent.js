import ObjC from "frida-objc-bridge";

const LOG_NAME = "debug_menu.log";
const UPDATED = "updated";
const TEST_NAME = ".__dm_write_test";
const DOC_DIR = 9;
const USER_MASK = 1;
const MAX_LOG_BYTES = 1048576;

const ANCHOR_STRING = "DisableIngameFriends";

let logPath = null;
let docsPath = null;
let updatedPath = null;
let gameModule = null;
let getBoolAddr = null;

const forceTrue = new Set([
  // "isDeveloperBuild",
  // "isProduction",
]);
const forceFalse = new Set();

function str(v) { try { return v === null || v === undefined ? null : v.toString(); } catch (e) { return null; } }
function fileManager() { return ObjC.classes.NSFileManager.defaultManager(); }

function mkdir(path) {
  try { fileManager().createDirectoryAtPath_withIntermediateDirectories_attributes_error_(path, true, null, null); return true; } catch (e) { return false; }
}
function exists(path) { try { return fileManager().fileExistsAtPath_(path) === true; } catch (e) { return false; } }
function readText(path) { try { const f = new File(path, "r"); const t = f.readText(); f.close(); return t; } catch (e) { return null; } }
function writeText(path, text) { try { const f = new File(path, "w"); f.write(text); f.flush(); f.close(); return true; } catch (e) { return false; } }
function fileSize(path) { try { const f = new File(path, "r"); const b = f.readAllBytes(); f.close(); return b.length; } catch (e) { return -1; } }

function writable(path) {
  if (!path) return false;
  const test = path + "/" + TEST_NAME;
  const payload = "p-" + Date.now();
  if (!writeText(test, payload)) return false;
  const ok = readText(test) === payload;
  try { fileManager().removeItemAtPath_error_(test, null); } catch (e) {}
  return ok;
}

function containerLike(path) {
  if (!path) return false;
  if (path.length < 8 || path.charAt(0) !== "/") return false;
  if (/\/Documents$/.test(path)) return true;
  if (path.indexOf("/Documents/") !== -1) return true;
  if (path.indexOf("/Data/Application/") !== -1) return true;
  return false;
}

function bundlePath() {
  try { return str(ObjC.classes.NSBundle.mainBundle().bundlePath()); } catch (e) { return null; }
}

function filesystemDir() {
  const list = [];
  const seen = {};
  const add = function (p) {
    if (!p) return;
    const x = String(p).replace(/\/+$/, "");
    if (x.length < 2 || x.charAt(0) !== "/" || seen[x]) return;
    seen[x] = true;
    list.push(x);
  };
  try {
    const urls = fileManager().URLsForDirectory_inDomains_(DOC_DIR, USER_MASK);
    if (urls !== null && urls.count() > 0) add(str(urls.firstObject().path()));
  } catch (e) {}
  try {
    const fn = new NativeFunction(Module.getGlobalExportByName("NSHomeDirectory"), "pointer", []);
    add(fn().readUtf8String() + "/Documents");
  } catch (e) {}
  const bundle = bundlePath();
  if (bundle) {
    const parts = bundle.replace(/\/+$/, "").split("/");
    if (parts.length >= 3) {
      const parent = parts.slice(0, -2).join("/");
      const grand = parts.slice(0, -3).join("/");
      const folder = parts[parts.length - 2];
      add(parent + "/" + folder + "/Documents");
      add(grand + "/Data/Application/" + folder + "/Documents");
    }
  }
  add("/tmp");

  let loose = null;
  for (let i = 0; i < list.length; i++) {
    let p = list[i];
    if (!/\/Documents$/.test(p) && exists(p + "/Documents")) p = p + "/Documents";
    if (!exists(p)) continue;
    if (!writable(p)) continue;
    if (loose === null) loose = p;
    if (containerLike(p)) return p;
  }
  return loose;
}

function initPaths() {
  docsPath = filesystemDir();
  updatedPath = docsPath === null ? null : docsPath + "/" + UPDATED;
  if (updatedPath !== null) mkdir(updatedPath);
  const chain = [];
  if (updatedPath !== null) chain.push(updatedPath + "/" + LOG_NAME);
  if (docsPath !== null) chain.push(docsPath + "/" + LOG_NAME);
  chain.push("/tmp/" + LOG_NAME);
  for (let i = 0; i < chain.length; i++) {
    const c = chain[i];
    const cut = c.lastIndexOf("/");
    const dir = cut < 1 ? null : c.substring(0, cut);
    if (dir === null) continue;
    if (!exists(dir)) mkdir(dir);
    if (!writable(dir)) continue;
    if (!writeText(c, "")) continue;
    logPath = c;
    break;
  }
  if (logPath !== null) log("log at " + logPath);
  else try { console.log("console only"); } catch (e) {}
}

function log(line) {
  const text = new Date().toISOString() + " " + line;
  try { console.log(text); } catch (e) {}
  if (logPath === null) return;
  try {
    if (fileSize(logPath) > MAX_LOG_BYTES) {
      try { fileManager().removeItemAtPath_error_(logPath, null); } catch (e) {}
    }
    const f = new File(logPath, "a");
    f.write(text + "\n"); f.flush(); f.close();
  } catch (e) {}
}

initPaths();

log("=== debug_menu start ===");
log("frida=" + Frida.version + " arch=" + Process.arch + " pid=" + Process.id);

function skipModule(m) {
  const p = m.path || "";
  if (p.indexOf("/usr/lib/") === 0) return true;
  if (p.indexOf("/System/") === 0) return true;
  if (p.indexOf("/Developer/") === 0) return true;
  if (m.name === "LiveContainer") return true;
  if (m.name.indexOf("Frida") !== -1) return true;
  if (m.size < 1024 * 1024) return true;
  return false;
}

function findGameModule() {
  const mods = Process.enumerateModules();
  let best = null;
  const bundleId = (() => {
    try { return String(ObjC.classes.NSBundle.mainBundle().bundleIdentifier()).toLowerCase(); } catch (e) { return ""; }
  })();
  const needle = bundleId.replace(/\./g, "");
  for (let i = 0; i < mods.length; i++) {
    const m = mods[i];
    if (skipModule(m)) continue;
    const hay = ((m.name || "") + " " + (m.path || "")).toLowerCase().replace(/\./g, "");
    if (needle && hay.indexOf(needle) !== -1) { gameModule = m; return m; }
  }
  for (let i = 0; i < mods.length; i++) {
    const m = mods[i];
    if (skipModule(m)) continue;
    if (best === null || m.size > best.size) best = m;
  }
  gameModule = best || Process.mainModule;
  return gameModule;
}

function findStringInModule(mod, needle) {
  const ranges = Process.enumerateRanges("r--");
  for (let i = 0; i < ranges.length; i++) {
    const r = ranges[i];
    const inMod = r.base.compare(mod.base) >= 0 && r.base.compare(mod.base.add(mod.size)) < 0;
    if (!inMod) continue;
    try {
      const res = Memory.scanSync(r.base, r.size, needle);
      if (res.length > 0) return res[0].address;
    } catch (e) {}
  }
  return null;
}

function findGetBool() {
  if (gameModule === null) findGameModule();
  log("module: " + gameModule.name + " base=" + gameModule.base + " size=" + gameModule.size);

  const strAddr = findStringInModule(gameModule, ANCHOR_STRING);
  if (strAddr === null) {
    log("anchor string not found: " + ANCHOR_STRING);
    return null;
  }
  log("anchor @ " + strAddr);

  const xrefs = [];
  const ranges = Process.enumerateRanges("r-x");
  for (let i = 0; i < ranges.length; i++) {
    const r = ranges[i];
    const inMod = r.base.compare(gameModule.base) >= 0 && r.base.compare(gameModule.base.add(gameModule.size)) < 0;
    if (!inMod) continue;
    try {
      const insns = Memory.scanSync(r.base, r.size, "?? ?? ?? ??");
      // Настоящий поиск ADRP+ADD xref-ов - дорогая операция, но у Frida есть встроенный API:
    } catch (e) {}
  }

  // Frida не даёт встроенных xref-ов. Используем перебор всех функций модуля и проверку,
  // ссылается ли их код на адрес строки через ADRP+ADD. Это медленно, но надёжно.
  const fm = Process.getModuleByName(gameModule.name);
  // Ищем только по известному RVA из прошлой сессии, если он есть
  return null;
}

function tryKnownRva(rva) {
  if (gameModule === null) findGameModule();
  const addr = gameModule.base.add(rva);
  const r = Process.findRangeByAddress(addr);
  if (r === null || r.protection.indexOf("x") === -1) return null;
  try { Interceptor.attach(addr, { onEnter() {} }).detach(); }
  catch (e) { return null; }
  return addr;
}

function installHook(addr) {
  log("installing hook @ " + addr);
  try {
    Interceptor.attach(addr, {
      onEnter: function (args) {
        this.name = null;
        try {
          const obj = new ObjC.Object(args[0]);
          this.name = obj.toString();
        } catch (e) {
          try { this.name = args[0].readUtf8String(); } catch (e2) {}
        }
        if (this.name !== null && this.name.length > 1 && this.name.length < 120) {
          log("getBool ENTER name=\"" + this.name + "\"");
        }
      },
      onLeave: function (retval) {
        const n = this.name;
        if (n === null) return;
        for (const k of forceTrue) {
          if (n === k || n.indexOf(k) !== -1) {
            log("FORCE-TRUE \"" + n + "\" was=" + retval.toInt32());
            retval.replace(ptr(1));
            return;
          }
        }
        for (const k of forceFalse) {
          if (n === k || n.indexOf(k) !== -1) {
            log("FORCE-FALSE \"" + n + "\" was=" + retval.toInt32());
            retval.replace(ptr(0));
            return;
          }
        }
      }
    });
    getBoolAddr = addr;
    log("hook installed");
  } catch (e) {
    log("hook FAILED: " + e.message);
  }
}

// Из прошлых прогонов известен RVA 0xb24998 для SCIDConfig::getBool.
// Если он актуален — используем его. Если нет — хук не встанет, смотри лог.
const KNOWN_RVA = 0xb24998;

setTimeout(function () {
  const addr = tryKnownRva(KNOWN_RVA);
  if (addr !== null) {
    installHook(addr);
  } else {
    log("known RVA 0x" + KNOWN_RVA.toString(16) + " is not a valid function, need to find by string");
    log("will try to find via anchor string (slow, not implemented in this pass)");
  }
}, 2000);

rpc.exports = {
  addr: function () { return getBoolAddr === null ? null : getBoolAddr.toString(); },
  force_true: function (name) { forceTrue.add(name); return Array.from(forceTrue); },
  force_false: function (name) { forceFalse.add(name); return Array.from(forceFalse); },
  list: function () { return { true: Array.from(forceTrue), false: Array.from(forceFalse) }; },
  logPath: function () { return logPath; }
};

log("=== debug_menu armed ===");