import ObjC from "frida-objc-bridge";

const LOG_NAME = "debug_menu.log";
const UPDATED = "updated";
const TEST_NAME = ".__dm_write_test";
const DOC_DIR = 9;
const USER_MASK = 1;
const MAX_LOG_BYTES = 2097152;

const RVA_GETBOOL = 0xb24820;
const RVA_ISDEV = 0xd93d80;

const FORCE_TRUE_CONTAINS = [
  "isDev",
  "isDeveloperBuild",
  "isDevBuild",
  "enableDebug",
  "enableCheat",
  "disableIngameFriends",
  "debugMenu",
];

let logPath = null;
let docsPath = null;
let updatedPath = null;
let gameModule = null;
let getBoolAddr = null;
let isDevAddr = null;
let getBoolCalls = 0;
let isDevCalls = 0;

function str(v) { try { return v === null || v === undefined ? null : v.toString(); } catch (e) { return null; } }
function fileManager() { return ObjC.classes.NSFileManager.defaultManager(); }

function mkdir(p) { try { fileManager().createDirectoryAtPath_withIntermediateDirectories_attributes_error_(p, true, null, null); return true; } catch (e) { return false; } }
function exists(p) { try { return fileManager().fileExistsAtPath_(p) === true; } catch (e) { return false; } }
function readText(p) { try { const f = new File(p, "r"); const t = f.readText(); f.close(); return t; } catch (e) { return null; } }
function writeText(p, t) { try { const f = new File(p, "w"); f.write(t); f.flush(); f.close(); return true; } catch (e) { return false; } }
function fileSize(p) { try { const f = new File(p, "r"); const b = f.readAllBytes(); f.close(); return b.length; } catch (e) { return -1; } }

function writable(p) {
  if (!p) return false;
  const t = p + "/" + TEST_NAME;
  const payload = "p-" + Date.now();
  if (!writeText(t, payload)) return false;
  const ok = readText(t) === payload;
  try { fileManager().removeItemAtPath_error_(t, null); } catch (e) {}
  return ok;
}

function containerLike(p) {
  if (!p) return false;
  if (p.length < 8 || p.charAt(0) !== "/") return false;
  if (/\/Documents$/.test(p)) return true;
  if (p.indexOf("/Documents/") !== -1) return true;
  if (p.indexOf("/Data/Application/") !== -1) return true;
  return false;
}

function bundlePath() { try { return str(ObjC.classes.NSBundle.mainBundle().bundlePath()); } catch (e) { return null; } }

function filesystemDir() {
  const list = [], seen = {};
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
  if (m.name === "LiveContainerShared") return true;
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

function readArgAsString(arg) {
  if (arg === null || arg === undefined) return null;
  if (arg.isNull()) return null;

  try {
    const obj = new ObjC.Object(arg);
    const cls = obj.$className;
    if (cls === "NSString" || cls === "NSMutableString" || /^NSString/.test(cls) || /^__NSCF/.test(cls) || /NSTaggedPointerString/.test(cls)) {
      const s = obj.toString();
      if (s !== null && s.length > 0) return s;
    }
  } catch (e) {}

  try {
    const s = arg.readUtf8String();
    if (s !== null && s.length > 0 && s.length < 200) return s;
  } catch (e) {}

  try {
    const p = arg.readPointer();
    if (!p.isNull()) {
      const s = p.readUtf8String();
      if (s !== null && s.length > 0 && s.length < 200) return s;
    }
  } catch (e) {}

  try {
    const lenPtr = arg.add(0x4);
    const dataPtr = arg.add(0x8);
    const len = lenPtr.readU32();
    if (len > 0 && len < 200) {
      const p2 = dataPtr.readPointer();
      if (!p2.isNull()) {
        const s = p2.readUtf8String();
        if (s !== null && s.length > 0 && s.length < 200) return s;
      }
    }
  } catch (e) {}

  return null;
}

function shouldForceTrue(name) {
  if (!name) return false;
  const lower = name.toLowerCase();
  for (let i = 0; i < FORCE_TRUE_CONTAINS.length; i++) {
    if (lower.indexOf(FORCE_TRUE_CONTAINS[i].toLowerCase()) !== -1) return true;
  }
  return false;
}

function findGrafterExports() {
  const names = [
    "gum_darwin_grafter_new_from_file",
    "gum_darwin_grafter_add",
    "gum_darwin_grafter_graft"
  ];
  const found = {};
  const mods = Process.enumerateModules();

  for (let i = 0; i < mods.length; i++) {
    const m = mods[i];
    if (!m.path) continue;
    const p = m.path.toLowerCase();
    if (p.indexOf("frida") === -1 && p.indexOf("gadget") === -1 && p.indexOf("gum") === -1) continue;

    for (let j = 0; j < names.length; j++) {
      const n = names[j];
      if (found[n]) continue;
      try {
        const addr = Module.findExportByName(m.name, n);
        if (addr) {
          found[n] = addr;
          log("graft: found " + n + " in " + m.name + " @ " + addr);
        }
      } catch (e) {}
    }
  }

  for (let j = 0; j < names.length; j++) {
    const n = names[j];
    if (found[n]) continue;
    try {
      const addr = Module.getGlobalExportByName(n);
      if (addr) {
        found[n] = addr;
        log("graft: found " + n + " globally @ " + addr);
      }
    } catch (e) {}
  }

  return found;
}

function graftTrampolines(binaryPath) {
  if (!binaryPath) return "no-path";
  if (!exists(binaryPath)) return "no-file";

  const ex = findGrafterExports();
  if (!ex["gum_darwin_grafter_new_from_file"] || !ex["gum_darwin_grafter_add"] || !ex["gum_darwin_grafter_graft"]) {
    log("graft: gum_* not found in any loaded module");
    return "unavailable";
  }

  const fnNew = new NativeFunction(ex["gum_darwin_grafter_new_from_file"], "pointer", ["pointer", "uint"]);
  const fnAdd = new NativeFunction(ex["gum_darwin_grafter_add"], "void", ["pointer", "uint"]);
  const fnGraft = new NativeFunction(ex["gum_darwin_grafter_graft"], "bool", ["pointer", "pointer"]);

  const INGEST_FUNCTION_STARTS = 1;
  const pathPtr = Memory.allocUtf8String(binaryPath);

  const grafter = fnNew(pathPtr, INGEST_FUNCTION_STARTS);
  if (grafter.isNull()) {
    log("graft: new_from_file failed");
    return "error";
  }

  fnAdd(grafter, RVA_GETBOOL);
  fnAdd(grafter, RVA_ISDEV);

  const ok = fnGraft(grafter, ptr(0));

  try {
    const unref = Module.getGlobalExportByName("g_object_unref");
    if (unref) {
      const fnUnref = new NativeFunction(unref, "void", ["pointer"]);
      fnUnref(grafter);
    }
  } catch (e) {}

  log("graft: changed=" + ok);
  return ok ? "applied" : "already";
}

function hookGetBool() {
  const base = gameModule.base;
  const addr = base.add(RVA_GETBOOL);
  log("hooking getBool @ " + addr + " (rva 0x" + RVA_GETBOOL.toString(16) + ")");
  try {
    Interceptor.attach(addr, {
      onEnter: function (args) {
        this.name = readArgAsString(args[0]);
      },
      onLeave: function (retval) {
        const n = this.name;
        if (n === null || n.length === 0) return;
        getBoolCalls++;
        const was = retval.toInt32();
        const force = shouldForceTrue(n);
        if (getBoolCalls <= 500 || force) {
          log("getBool name=\"" + n + "\" was=" + was + (force ? " FORCE->1" : ""));
        }
        if (force && was !== 1) {
          retval.replace(ptr(1));
        }
      }
    });
    getBoolAddr = addr;
    log("getBool hook installed");
  } catch (e) {
    log("getBool hook FAILED: " + e.message);
  }
}

function hookIsDev() {
  const base = gameModule.base;
  const addr = base.add(RVA_ISDEV);
  log("hooking isDev @ " + addr + " (rva 0x" + RVA_ISDEV.toString(16) + ")");
  try {
    Interceptor.attach(addr, {
      onLeave: function (retval) {
        isDevCalls++;
        const was = retval.toInt32();
        if (was !== 1) {
          retval.replace(ptr(1));
          if (isDevCalls <= 20) log("isDev called (#" + isDevCalls + ") was=" + was + " FORCE->1");
        } else {
          if (isDevCalls <= 20) log("isDev called (#" + isDevCalls + ") already=1");
        }
      }
    });
    isDevAddr = addr;
    log("isDev hook installed");
  } catch (e) {
    log("isDev hook FAILED: " + e.message);
  }
}

function run() {
  gameModule = findGameModule();
  log("module: " + gameModule.name + " base=" + gameModule.base + " size=" + gameModule.size);

  const status = graftTrampolines(gameModule.path);
  log("graft status: " + status);

  if (status === "applied") {
    log("=== graft applied, RESTART REQUIRED ===");
    return;
  }

  hookGetBool();
  hookIsDev();

  log("=== debug_menu armed ===");
}

setTimeout(run, 2000);

setTimeout(function () {
  log("timer 10s: getBool calls=" + getBoolCalls + " isDev calls=" + isDevCalls);
}, 12000);

setTimeout(function () {
  log("timer 30s: getBool calls=" + getBoolCalls + " isDev calls=" + isDevCalls);
}, 32000);

rpc.exports = {
  getBool_addr: function () { return getBoolAddr === null ? null : getBoolAddr.toString(); },
  isDev_addr: function () { return isDevAddr === null ? null : isDevAddr.toString(); },
  stats: function () { return { getBool: getBoolCalls, isDev: isDevCalls }; },
  logPath: function () { return logPath; },
  graft: function () {
    if (!gameModule) gameModule = findGameModule();
    return graftTrampolines(gameModule.path);
  }
};