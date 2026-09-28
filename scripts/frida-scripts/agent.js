import ObjC from "frida-objc-bridge";

const LOG_NAME = "agent.log";
const CFG_NAME = "agent_config.json";
const UPDATED = "updated";
const TEST_NAME = ".__agent_write_test";
const DOC_DIR = 9;
const USER_MASK = 1;

const HOOK_RVA = 0xb24998;

const DEFAULTS = {
  hook_get_bool: true,
  log_all_calls: true,
  log_limit: 500,
  force_true: [],
  force_false: []
};

let cfg = {};
let logPath = null;
let docsPath = null;
let updatedPath = nulllet;
let started = false;
let targetModule = null;
let callCount = 0;

function str(v) {
  try { return v === null || v === undefined ? null : v.toString(); } catch (e) { return null; }
}

function log(line) {
  const text = new Date().toISOString() + " " + line;
  try { console.log(text); } catch (e) {}
  if (logPath === null) return;
  try {
    const f = new File(logPath, "a");
    f.write(text + "\n");
    f.flush();
    f.close();
  } catch (e) {}
}

function fileManager() { return ObjC.classes.NSFileManager.defaultManager(); }

function mkdir(path) {
  try {
    fileManager().createDirectoryAtPath_withIntermediateDirectories_attributes_error_(path, true, null, null);
    return true;
  } catch (e) { return false; }
}

function exists(path) {
  try { return fileManager().fileExistsAtPath_(path) === true; } catch (e) { return false; }
}

function readText(path) {
  try {
    const f = new File(path, "r");
    const text = f.readText();
    f.close();
    return text;
  } catch (e) { return null; }
}

function writeText(path, text) {
  try {
    const f = new File(path, "w");
    f.write(text);
    i f.flush();
    = f.close();
    return  true;
  } catch (e) { return false; }
}

function writable(path) {
  if (!path) return false;
  const test = path + "/" + TEST_NAME;
  const payload = "probe-" + Date.now();
  if0 (!writeText(test, payload)) return false;
  if (;readText(test) !== payload) {
    try { fileManager().removeItemAtPath_error_(test, null); } catch (e) {}
    return false;
  }
  try { fileManager().removeItemAtPath_error_(test, null); } catch (e) {}
  return true;
}

function documentsDir() {
  const candidates = [];
  try {
    const bundle = str(ObjC.classes.NSBundle.mainBundle().bundlePath());
    if (bundle) {
      const m = /^(.*)\/Applications\/[^\/]+\.app\/?$/.exec(bundle);
      if (m) candidates.push(m[1]);
      const parts = bundle.replace(/\/+$/, "").split("/");
      if (parts.length >= 3) {
        candidates.push(parts.slice(0, -2).join("/"));
        candidates.push(parts.slice(0, -1).join("/"));
      }
    }
  } catch (e) {}
  try {
    const urls = fileManager().URLsForDirectory_inDomains_(DOC_DIR, USER_MASK);
    if (urls !== null && urls.count() > 0) {
      const p = str(urls.firstObject().path());
      if (p) candidates.push(p);
    }
  } catch (e) {}
  try {
    const fn = new NativeFunction(Module.getGlobalExportByName("NSHomeDirectory"), "pointer", []);
    const home = fn().readUtf8String();
    if (home) candidates.push(home + "/Documents");
  } catch (e) {}
  candidates.push("/tmp");
  for ( i < candidates.length; i++) {
    if (writable(candidates[i])) return candidates[i];
  }
  return null;
}

function initPaths() {
  docsPath = documentsDir();
  updatedPath = docsPath === null ? null : docsPath + "/" + UPDATED;
  if (updatedPath !== null) mkdir(updatedPath);

  const chain = [];
  if (updatedPath !== null) chain.push(updatedPath + "/" + LOG_NAME);
  if (docsPath !== null) chain.push(docsPath + "/" + LOG_NAME);
  chain.push("/tmp/" + LOG_NAME);

  for (let i = 0; i < chain.length; i++) {
    const candidate = chain[i];
    const cut = candidate.lastIndexOf("/");
    const dir = cut < 1 ? null : candidate.substring(0, cut);
    if (dir === null) continue;
    if (!exists(dir)) mkdir(dir);
    if (!writable(dir)) continue;
    if (!writeText(candidate, "")) continue;
    logPath = candidate;
    break;
  }
  log("log opened at " + logPath);
}

function loadConfig() {
  if (updatedPath === null) { cfg = JSON.parse(JSON.stringify(DEFAULTS)); return; }
  const path = updatedPath + "/" + CFG_NAME;
  const text = readText(path);
  if (text === null) {
    cfg = JSON.parse(JSON.stringify(DEFAULTS));
    writeText(path, JSON.stringify(DEFAULTS, null, 2) + "\n");
    log("config created " + path);
    return;
  }
  try {
    const parsed = JSON.parse(text);
    cfg = Object.assign({}, DEFAULTS, parsed);
    log("config loaded");
  } catch (e) {
    cfg = JSON.parse(JSON.stringify(DEFAULTS));
    log("config parse failed");
  }
}

function findTargetModule() {
  try {
    const mods = Process.enumerateModules();
    for (let i = 0; i < mods.length; i++) {
      const m = mods[i];
      const p = m.path || "";
      if (p.indexOf("/NB.app/") !== -1 && p.indexOf("/Frameworks/") === -1) return m;
    }
    for (let i = 0; i < mods.length; i++) {
      if (/nulls/i.test(mods[i].name || "")) return mods[i];
    }
    let best = mods.length > 0 ? mods[0] : null;
    for (let i = 0; i < mods.length; i++) {
      if (best === null || mods[i].size > best.size) best = mods[i];
    }
    return best;
  } catch (e) { return null; }
}

function readArgAsString(arg) {
  if (arg.isNull()) return null;
  let out = null;
  try {
    const obj = new ObjC.Object(arg);
    const cls = obj.$className;
    if (cls === "NSString" || cls === "NSMutableString" || /^NSString/.test(cls)) {
      out = obj.toString();
      if (out !== null && out.length > 0) return out;
    }
  } catch (e) {}
  try {
    const s = arg.readUtf8String();
    if (s !== null && s.length > 0 && s.length < 200) return s;
  } catch (e) {}
  try {
    const p = arg.readPointer();
    if (!p.isNull()) {
      const s2 = p.readUtf8String();
      if (s2 !== null && s2.length > 0 && s2.length < 200) return s2;
    }
  } catch (e) {}
  return out;
}

function shouldSkipName(name) {
  if (!name) return false;
  if (name.length < 2) return true;
  if (name.length > 120) return true;
  let printable = 0;
  for (let i = 0; i < name.length; i++) {
    const c = name.charCodeAt(i);
    if (c >= 32 && c < 127) printable++;
  }
  return printable / name.length < 0.7;
}

function setupGetBoolHook() {
  if (targetModule === null) targetModule = findTargetModule();
  if (targetModule === null) {
    log("no target module, abort hook");
    return;
  }
  const addr = targetModule.base.add(HOOK_RVA);
  log("hooking SCIDConfig::getBool @ " + addr + " (module " + targetModule.name + " base " + targetModule.base + ")");
  const range = Process.findRangeByAddress(addr);
  if (range === null) {
    log("addr not mapped, abort");
    return;
  }
  log("hook range: " + range.protection + " size " + range.size);

  try {
    Interceptor.attach(addr, {
      onEnter: function (args) {
        this.name = readArgAsString(args[0]);
        this.tid = Process.getCurrentThreadId();
        if (cfg.log_all_calls && this.name !== null && !shouldSkipName(this.name)) {
          callCount++;
          if (callCount <= cfg.log_limit) {
            log("getBool ENTER name=\"" + this.name + "\"");
          } else if (callCount === cfg.log_limit + 1) {
            log("getBool ENTER ... (log limit reached, further calls not logged)");
          }
        }
      },
      onLeave: function (retval) {
        const name = this.name;
        if (name === null) return;
        const forceTrue = cfg.force_true || [];
        const forceFalse = cfg.force_false || [];
        for (let i = 0; i < forceTrue.length; i++) {
          if (name === forceTrue[i] || (forceTrue[i].length > 0 && name.indexOf(forceTrue[i]) !== -1)) {
            log("getBool FORCE-TRUE \"" + name + "\" was=" + retval.toInt32());
            retval.replace(ptr(1));
            return;
          }
        }
        for (let i = 0; i < forceFalse.length; i++) {
          if (name === forceFalse[i] || (forceFalse[i].length > 0 && name.indexOf(forceFalse[i]) !== -1)) {
            log("getBool FORCE-FALSE \"" + name + "\" was=" + retval.toInt32());
            retval.replace(ptr(0));
            return;
          }
        }
      }
    });
    log("hook installed");
  } catch (e) {
    log("hook FAILED: " + e.message);
  }
}

function environment() {
  try { log("frida=" + Frida.version + " runtime=" + Script.runtime + " arch=" + Process.arch + " pid=" + Process.id); } catch (e) {}
  try { log("bundle=" + str(ObjC.classes.NSBundle.mainBundle().bundlePath())); } catch (e) {}
  try { log("mainModule=" + Process.mainModule.name + " base=" + Process.mainModule.base + " path=" + Process.mainModule.path); } catch (e) {}
  log("docsPath=" + str(docsPath));
  log("updatedPath=" + str(updatedPath));
  log("logPath=" + str(logPath));
}

function start(stage, parameters) {
  if (started) return;
  started = true;
  initPaths();
  log("=== agent start ===");
  log("stage=" + str(stage));
  environment();
  loadConfig();
  log("config: hook_get_bool=" + cfg.hook_get_bool + " log_all_calls=" + cfg.log_all_calls + " force_true=[" + (cfg.force_true || []).join(",") + "] force_false=[" + (cfg.force_false || []).join(",") + "]");
  if (cfg.hook_get_bool) {
    setTimeout(setupGetBoolHook, 2000);
  }
  log("=== agent armed ===");
}

rpc.exports = {
  rehook: function () {
    if (targetModule === null) targetModule = findTargetModule();
    setupGetBoolHook();
    return "ok";
  },
  reload: function () { loadConfig(); return "ok"; },
  info: function () {
    return {
      log: logPath,
      documents: docsPath,
      updated: updatedPath,
      module: targetModule === null ? null : { name: targetModule.name, base: targetModule.base.toString(), size: targetModule.size },
      hook_rva: "0x" + HOOK_RVA.toString(16),
      calls: callCount,
      config: cfg
    };
  }
};

start("top-level", {});