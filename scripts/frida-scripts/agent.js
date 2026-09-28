import ObjC from "frida-objc-bridge";

const LOG_NAME = "agent.log";
const CFG_NAME = "agent_config.json";
const UPDATED = "updated";
const DOC_DIR = 9;
const USER_MASK = 1;
const MAX_LOG_BYTES = 1048576;

const DEFAULTS = {
  patch: false,
  alert: true,
  alert_delay_ms: 5000,
  alert_tries: 40,
  alert_try_ms: 500,
  alert_auto_dismiss_ms: 0,
  reapply_ms: [3000, 8000, 15000],
  targets: [
    { name: "isDev", rva: "0xd93da0", type: "u8", value: 1 }
  ]
};

let cfg = {};
let logPath = null;
let docsPath = null;
let updatedPath = null;
let started = false;

function str(v) {
  try {
    return v === null || v === undefined ? null : v.toString();
  } catch (e) {
    return null;
  }
}

function log(line) {
  const text = new Date().toISOString() + " " + line;
  try {
    console.log(text);
  } catch (e) {}
  if (logPath === null) return;
  try {
    const f = new File(logPath, "a");
    f.write(text + "\n");
    f.flush();
    f.close();
  } catch (e) {}
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

function listDir(path) {
  const out = [];
  try {
    const arr = fileManager().contentsOfDirectoryAtPath_error_(path, null);
    if (arr === null) return out;
    const n = arr.count();
    for (let i = 0; i < n; i++) out.push(str(arr.objectAtIndex_(i)));
  } catch (e) {}
  return out;
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

function fileSize(path) {
  try {
    const f = new File(path, "r");
    const bytes = f.readAllBytes();
    f.close();
    return bytes.length;
  } catch (e) {
    return -1;
  }
}

function filesystemDir() {
  try {
    const urls = fileManager().URLsForDirectory_inDomains_(DOC_DIR, USER_MASK);
    if (urls !== null && urls.count() > 0) {
      const p = str(urls.firstObject().path());
      if (p !== null && p.length > 0) return p;
    }
  } catch (e) {}
  try {
    const fn = new NativeFunction(Module.getGlobalExportByName("NSHomeDirectory"), "pointer", []);
    const home = fn().readUtf8String();
    if (home !== null && home.length > 0) return home + "/Documents";
  } catch (e) {}
  try {
    const bundle = str(ObjC.classes.NSBundle.mainBundle().bundlePath());
    const m = /^(.*)\/[^/]+\.app$/.exec(bundle === null ? "" : bundle);
    if (m !== null) return m[1] + "/Documents";
  } catch (e) {}
  return null;
}

function tempDir() {
  try {
    const fn = new NativeFunction(Module.getGlobalExportByName("NSTemporaryDirectory"), "pointer", []);
    return fn().readUtf8String();
  } catch (e) {
    return null;
  }
}

function uuidIn(path) {
  const m = /[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}/.exec(path === null ? "" : path);
  return m === null ? "-" : m[0];
}

function initPaths() {
  docsPath = filesystemDir();
  updatedPath = docsPath === null ? null : docsPath + "/" + UPDATED;
  const candidates = [];
  if (updatedPath !== null) {
    mkdir(updatedPath);
    candidates.push(updatedPath + "/" + LOG_NAME);
  }
  const tmp = tempDir();
  if (tmp !== null && tmp.length > 0) candidates.push(tmp + "/" + LOG_NAME);
  candidates.push("/tmp/" + LOG_NAME);
  for (let i = 0; i < candidates.length; i++) {
    const p = candidates[i];
    const size = fileSize(p);
    if (size > MAX_LOG_BYTES) writeText(p, "");
    if (writeText(p, "") && (size >= 0 || fileSize(p) >= 0)) {
      logPath = p;
      return;
    }
  }
}

function saveConfig(path) {
  writeText(path, JSON.stringify(DEFAULTS, null, 2) + "\n");
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
    saveConfig(path);
    log("config created " + path);
    return;
  }
  try {
    const parsed = JSON.parse(text);
    cfg = Object.assign({}, DEFAULTS, parsed);
    if (!Array.isArray(cfg.targets) || cfg.targets.length === 0) cfg.targets = DEFAULTS.targets;
    log("config loaded " + path);
  } catch (e) {
    cfg = JSON.parse(JSON.stringify(DEFAULTS));
    log("config parse failed (" + e.message + "), defaults used");
  }
}

function baseOf(target) {
  if (target.module) return Process.getModuleByName(target.module).base;
  return Process.mainModule.base;
}

function addrOf(target) {
  if (target.addr) return ptr(target.addr);
  return baseOf(target).add(parseInt(String(target.rva), 16));
}

function sizeOf(type) {
  if (type === "u64") return 8;
  if (type === "u32") return 4;
  return 1;
}

function readAt(addr, type) {
  if (type === "u64") return addr.readU64().toString(16);
  if (type === "u32") return addr.readU32() >>> 0;
  return addr.readU8();
}

function valueOf(value, type) {
  if (typeof value === "number") return value;
  return parseInt(String(value), 16);
}

function writeAt(p, value, type) {
  if (type === "u64") p.writeU64(value);
  else if (type === "u32") p.writeU32(value);
  else p.writeU8(value);
}

function applyTarget(target) {
  const type = target.type || "u8";
  const name = target.name || "target";
  const size = sizeOf(type);
  let addr;
  try {
    addr = addrOf(target);
  } catch (e) {
    log(name + " address failed: " + e.message);
    return "addr-error";
  }
  const range = Process.findRangeByAddress(addr);
  if (range === null) {
    log(name + " @" + addr + " is not mapped, skipped");
    return "unmapped";
  }
  if (range.protection.indexOf("r") === -1) {
    log(name + " @" + addr + " not readable (" + range.protection + "), skipped");
    return "unreadable";
  }
  let before;
  try {
    before = readAt(addr, type);
  } catch (e) {
    log(name + " @" + addr + " read failed: " + e.message);
    return "read-error";
  }
  const want = valueOf(target.value, type);
  if (target.expect !== undefined && target.expect !== null) {
    const expect = valueOf(target.expect, type);
    if (expect !== before) {
      log(name + " @" + addr + " expect " + str(expect) + " but found " + str(before) + ", skipped (offset changed?)");
      return "expect-mismatch";
    }
  }
  if (before === want) {
    log(name + " @" + addr + " already " + str(before) + " (" + range.protection + ")");
    return "already";
  }
  if (cfg.patch === false || target.patch === false) {
    log(name + " @" + addr + " probe: before=" + str(before) + " want=" + str(want) + " (" + range.protection + ")");
    return "probe";
  }
  try {
    Memory.patchCode(addr, size, function (code) {
      writeAt(code, want, type);
    });
  } catch (e) {
    log(name + " @" + addr + " patchCode failed: " + e.message);
    return "patch-error";
  }
  let after = null;
  try {
    after = readAt(addr, type);
  } catch (e) {}
  if (after === want) {
    log(name + " @" + addr + " " + str(before) + " -> " + str(after) + " (" + range.protection + ")");
    return "ok";
  }
  log(name + " @" + addr + " write did not stick (" + str(before) + " -> " + str(after) + ")");
  return "no-stick";
}

function applyPatches() {
  const targets = cfg.targets || DEFAULTS.targets;
  const result = {};
  for (let i = 0; i < targets.length; i++) {
    const name = targets[i].name || ("target" + i);
    try {
      result[name] = applyTarget(targets[i]);
    } catch (e) {
      result[name] = "error";
      log(name + " apply failed: " + e.message);
    }
  }
  return result;
}

function keyWindowRoot() {
  try {
    const windows = ObjC.classes.UIApplication.sharedApplication().windows();
    for (let i = 0; i < windows.count(); i++) {
      const w = windows.objectAtIndex_(i);
      if (w.isKeyWindow()) return w.rootViewController();
    }
  } catch (e) {}
  return null;
}

function showAlertOnMain(title, message, tries) {
  const root = keyWindowRoot();
  if (root === null) {
    if (tries >= cfg.alert_tries) {
      log("alert skipped: no key window");
      return false;
    }
    setTimeout(function () {
      showAlertOnMain(title, message, tries + 1);
    }, cfg.alert_try_ms);
    return false;
  }
  try {
    const alert = ObjC.classes.UIAlertController.alertControllerWithTitle_message_preferredStyle_(title, message, 1);
    alert.addAction_(ObjC.classes.UIAlertAction.actionWithTitle_style_handler_("OK", 0, null));
    let top = root;
    while (top.presentedViewController() !== null) top = top.presentedViewController();
    top.presentViewController_animated_completion_(alert, true, null);
    log("alert shown: " + title + " / " + message);
    if (cfg.alert_auto_dismiss_ms > 0) {
      setTimeout(function () {
        try {
          alert.dismissViewControllerAnimated_completion_(true, null);
        } catch (e) {}
      }, cfg.alert_auto_dismiss_ms);
    }
    return true;
  } catch (e) {
    log("alert failed: " + e.message);
    return false;
  }
}

function showAlert(title, message) {
  if (cfg.alert === false) return false;
  setTimeout(function () {
    ObjC.schedule(ObjC.mainQueue, function () {
      showAlertOnMain(title, message, 0);
    });
  }, cfg.alert_delay_ms);
  return true;
}

function environment() {
  try {
    log("frida=" + Frida.version + " runtime=" + Script.runtime + " arch=" + Process.arch + " pid=" + Process.id);
  } catch (e) {}
  try {
    const device = ObjC.classes.UIDevice.currentDevice();
    log("device=" + str(device.systemName()) + " " + str(device.systemVersion()) + " " + str(device.model()));
  } catch (e) {}
  try {
    log("bundle=" + str(ObjC.classes.NSBundle.mainBundle().bundlePath()));
  } catch (e) {}
  try {
    log("executable=" + Process.mainModule.path);
    log("base=" + Process.mainModule.base + " code_signing=" + Process.codeSigningPolicy);
  } catch (e) {}
  log("documents=" + str(docsPath) + " uuid=" + uuidIn(docsPath));
  log("updated=" + str(updatedPath));
  log("tmp=" + str(tempDir()));
  log("log=" + str(logPath));
  if (updatedPath !== null) log("updated contents: " + listDir(updatedPath).join(" "));
}

function start(stage, parameters) {
  if (started) return;
  started = true;
  initPaths();
  log("=== agent start ===");
  log("stage=" + str(stage) + " parameters=" + JSON.stringify(parameters === undefined ? {} : parameters));
  environment();
  loadConfig();
  log("config patch=" + cfg.patch + " alert=" + cfg.alert + " targets=" + (cfg.targets || []).length);
  log("patches: " + JSON.stringify(applyPatches()));
  const delays = cfg.reapply_ms || [];
  for (let i = 0; i < delays.length; i++) {
    setTimeout(function () {
      log("reapply " + JSON.stringify(applyPatches()));
    }, delays[i]);
  }
  showAlert("Nulls Brawl", "agent loaded");
  log("=== agent armed ===");
}

rpc.exports = {
  init: function (stage, parameters) {
    start(stage, parameters);
  },
  dispose: function () {
    log("=== agent dispose ===");
    started = false;
  },
  patch: function () {
    return applyPatches();
  },
  probe: function () {
    const targets = cfg.targets || DEFAULTS.targets;
    const out = {};
    for (let i = 0; i < targets.length; i++) {
      const t = targets[i];
      const name = t.name || ("target" + i);
      try {
        const addr = addrOf(t);
        const range = Process.findRangeByAddress(addr);
        out[name] = {
          addr: str(addr),
          mapped: range !== null,
          protection: range === null ? null : range.protection,
          value: range === null ? null : str(readAt(addr, t.type || "u8"))
        };
      } catch (e) {
        out[name] = { error: e.message };
      }
    }
    return out;
  },
  alert: function (title, message) {
    showAlert(str(title), str(message));
    return true;
  },
  info: function () {
    return {
      log: logPath,
      documents: docsPath,
      updated: updatedPath,
      uuid: uuidIn(docsPath),
      patch: cfg.patch,
      alert: cfg.alert,
      targets: cfg.targets
    };
  },
  reload: function () {
    loadConfig();
    return applyPatches();
  }
};

start("top-level", {});
