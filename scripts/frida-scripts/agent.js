import ObjC from "frida-objc-bridge";

const LOG_NAME = "agent.log";
const CFG_NAME = "agent_config.json";
const UPDATED = "updated";
const TEST_NAME = ".__agent_write_test";
const DOC_DIR = 9;
const USER_MASK = 1;

const GETBOOL_RVA = 0xb24998;
const PATCH_BYTES = [0x20, 0x00, 0x80, 0x52, 0xC0, 0x03, 0x5F, 0xD6];

const DEFAULTS = {
  patch_get_bool: true
};

let cfg = {};
let logPath = null;
let docsPath = null;
let updatedPath = null;
let started = false;
let targetModule = null;

function str(v) {
  try {
    return v === null || v === undefined ? null : v.toString();
  } catch (e) {
    return null;
  }
}

function log(line) {
  let text = "";
  try {
    text = new Date().toISOString() + " " + line;
  } catch (e) {
    text = "log " + line;
  }
  try {
    console.log(text);
  } catch (e) {}
  if (logPath === null) {
    return;
  }
  let f = null;
  try {
    f = new File(logPath, "a");
    f.write(text + "\n");
    f.flush();
    f.close();
    f = null;
  } catch (e) {
    if (f !== null) {
      try { f.close(); } catch (e2) {}
    }
  }
}

function fileManager() {
  return ObjC.classes.NSFileManager.defaultManager();
}

function mkdir(path) {
  try {
    fileManager().createDirectoryAtPath_withIntermediateDirectories_attributes_error_(path, true, null, null);
    return true;
  } catch (e) {
    return false;
  }
}

function exists(path) {
  try {
    return fileManager().fileExistsAtPath_(path) === true;
  } catch (e) {
    return false;
  }
}

function readText(path) {
  try {
    const f = new File(path, "r");
    const text = f.readText();
    f.close();
    return text;
  } catch (e) {
    return null;
  }
}

function writeText(path, text) {
  try {
    const f = new File(path, "w");
    f.write(text);
    f.flush();
    f.close();
    return true;
  } catch (e) {
    return false;
  }
}

function writable(path) {
  if (!path) {
    return false;
  }
  const test = path + "/" + TEST_NAME;
  const payload = "probe-" + Date.now();
  if (!writeText(test, payload)) {
    return false;
  }
  if (readText(test) !== payload) {
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
      if (m) {
        candidates.push(m[1]);
      }
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
      if (p) {
        candidates.push(p);
      }
    }
  } catch (e) {}
  try {
    const fn = new NativeFunction(Module.getGlobalExportByName("NSHomeDirectory"), "pointer", []);
    const home = fn().readUtf8String();
    if (home) {
      candidates.push(home + "/Documents");
    }
  } catch (e) {}
  candidates.push("/tmp");
  for (let i = 0; i < candidates.length; i++) {
    if (writable(candidates[i])) {
      return candidates[i];
    }
  }
  return null;
}

function initPaths() {
  docsPath = documentsDir();
  updatedPath = docsPath === null ? null : docsPath + "/" + UPDATED;
  if (updatedPath !== null) {
    mkdir(updatedPath);
  }

  const chain = [];
  if (updatedPath !== null) {
    chain.push(updatedPath + "/" + LOG_NAME);
  }
  if (docsPath !== null) {
    chain.push(docsPath + "/" + LOG_NAME);
  }
  chain.push("/tmp/" + LOG_NAME);

  for (let i = 0; i < chain.length; i++) {
    const candidate = chain[i];
    const cut = candidate.lastIndexOf("/");
    if (cut < 1) {
      continue;
    }
    const dir = candidate.substring(0, cut);
    if (!exists(dir)) {
      mkdir(dir);
    }
    if (!writable(dir)) {
      continue;
    }
    if (!writeText(candidate, "")) {
      continue;
    }
    logPath = candidate;
    break;
  }
  if (logPath === null) {
    try {
      console.log("[agent] no writable directory for log");
    } catch (e) {}
    return;
  }
  log("log opened at " + logPath);
}

function loadConfig() {
  if (updatedPath === null) {
    cfg = JSON.parse(JSON.stringify(DEFAULTS));
    return;
  }
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
      if (p.indexOf("/NB.app/") !== -1 && p.indexOf("/Frameworks/") === -1) {
        log("target module: " + m.name + " " + m.base + " size=" + m.size);
        return m;
      }
    }
    for (let i = 0; i < mods.length; i++) {
      const m = mods[i];
      if (/nulls/i.test(m.name || "")) {
        log("target module (name): " + m.name + " " + m.base);
        return m;
      }
    }
    let best = mods.length > 0 ? mods[0] : null;
    for (let i = 0; i < mods.length; i++) {
      if (best === null || mods[i].size > best.size) {
        best = mods[i];
      }
    }
    if (best !== null) {
      log("target module (fallback): " + best.name + " " + best.base);
    }
    return best;
  } catch (e) {
    log("findTargetModule failed: " + e.message);
    return null;
  }
}

function patchGetBool() {
  if (targetModule === null) {
    targetModule = findTargetModule();
  }
  if (targetModule === null) {
    log("no target module, abort");
    return;
  }
  const addr = targetModule.base.add(GETBOOL_RVA);
  log("patching SCIDConfig::getBool @ " + addr + " (base " + targetModule.base + ")");

  const range = Process.findRangeByAddress(addr);
  if (range === null) {
    log("addr not mapped, abort");
    return;
  }
  log("range: " + range.protection + " size=" + range.size);

  try {
    Memory.patchCode(addr, PATCH_BYTES.length, function (code) {
      for (let i = 0; i < PATCH_BYTES.length; i++) {
        code.add(i).writeU8(PATCH_BYTES[i]);
      }
    });
    log("patch applied: " + PATCH_BYTES.length + " bytes");
  } catch (e) {
    log("patch FAILED: " + e.message);
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
  if (started) {
    return;
  }
  started = true;
  initPaths();
  log("=== agent start ===");
  log("stage=" + str(stage));
  environment();
  loadConfig();
  log("config: patch_get_bool=" + cfg.patch_get_bool);
  if (cfg.patch_get_bool) {
    setTimeout(patchGetBool, 2000);
  }
  log("=== agent armed ===");
}

rpc.exports = {
  patch: function () {
    if (targetModule === null) {
      targetModule = findTargetModule();
    }
    patchGetBool();
    return "ok";
  },
  reload: function () {
    loadConfig();
    return "ok";
  },
  info: function () {
    return {
      log: logPath,
      documents: docsPath,
      updated: updatedPath,
      module: targetModule === null ? null : { name: targetModule.name, base: targetModule.base.toString(), size: targetModule.size },
      hook_rva: "0x" + GETBOOL_RVA.toString(16),
      config: cfg
    };
  }
};

start("top-level", {});