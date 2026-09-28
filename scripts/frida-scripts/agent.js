import ObjC from "frida-objc-bridge";

const LOG_NAME = "modmenu.log";
const CFG_NAME = "modmenu_config.json";
const UPDATED = "updated";
const TEST_NAME = ".__modmenu_write_test";
const DOC_DIR = 9;
const USER_MASK = 1;
const MAX_LOG_BYTES = 1048576;

const POSITIONS = ["bottom_left", "bottom_right", "top_left", "top_right"];

const DEFAULTS = {
  enabled: true,
  position: "bottom_left",
  text: "MOD MENU",
  color_rgb: [255, 255, 255],
  log_path: "",
  docs_path: "",
  reapply_ms: [3000, 8000, 15000],
  rva: {
    Stage_instance: null,
    ResourceManager_getMovieClip: null,
    GameButton_ctor: null,
    MovieClip_getTextFieldByName: null,
    MovieClip_gotoAndStopFrameIndex: null,
    MovieClip_setChildVisible: null,
    Sprite_ctor: null,
    Sprite_addChild: null,
    DropGUIContainer_ctor: null,
    DisplayObject_setXY: null,
    TextField_setText: null,
    String_ctor: null,
    HomePage_ctor: null,
    GUI_closePopup: null,
    GUI_showFloaterTextAt: null
  }
};

let cfg = {};
let logPath = null;
let docsPath = null;
let updatedPath = null;
let pathReport = [];
let started = false;

let modMenuButton = null;
let homePageHook = null;
let closePopupHook = null;
let bindings = {};

// -------------------------------------------------------------------------
// infra
// -------------------------------------------------------------------------

function str(v) {
  try { return v === null || v === undefined ? null : v.toString(); } catch (e) { return null; }
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
    f.write(text + "\n");
    f.flush();
    f.close();
  } catch (e) {}
}

function fileManager() { return ObjC.classes.NSFileManager.defaultManager(); }

function selector(name) { try { return ObjC.selector(name); } catch (e) { return null; } }

function responds(target, name) {
  const sel = selector(name);
  if (sel === null) return false;
  try { return target.respondsToSelector_(sel) === true; } catch (e) { return false; }
}

function mkdir(path) {
  try {
    fileManager().createDirectoryAtPath_withIntermediateDirectories_attributes_error_(path, true, null, null);
    return true;
  } catch (e) { return false; }
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
    f.flush();
    f.close();
    return true;
  } catch (e) { return false; }
}

function fileSize(path) {
  try {
    const f = new File(path, "r");
    const bytes = f.readAllBytes();
    f.close();
    return bytes.length;
  } catch (e) { return -1; }
}

function writable(path) {
  if (!path) return false;
  const test = path + "/" + TEST_NAME;
  const payload = "probe-" + Date.now();
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
  if (path.indexOf("/Containers/Data/") !== -1) return true;
  return false;
}

function uuidsIn(path) {
  const m = (path === null ? "" : path).match(/[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}/g);
  return m === null ? [] : m;
}

function uuidIn(path) {
  const all = uuidsIn(path);
  return all.length === 0 ? "-" : all[all.length - 1];
}

function bundlePath() {
  try { return str(ObjC.classes.NSBundle.mainBundle().bundlePath()); } catch (e) { return null; }
}

function bundleCandidates() {
  const out = [];
  const bundle = bundlePath();
  if (!bundle) return out;
  const parts = bundle.replace(/\/+$/, "").split("/");
  if (parts.length < 3) return out;
  const appDir = parts.slice(0, -1).join("/");
  const parent = parts.slice(0, -2).join("/");
  const grand = parts.slice(0, -3).join("/");
  const folder = parts[parts.length - 2];
  out.push([parent + "/" + folder + "/Documents", "bundle:parent/folder/Documents"]);
  out.push([grand + "/Data/Application/" + folder + "/Documents", "bundle:Data/Application/folder"]);
  out.push([parent + "/Documents", "bundle:parent/Documents"]);
  out.push([appDir, "bundle:app-dir"]);
  return out;
}

function collectCandidates() {
  const list = [];
  const seen = {};
  const add = function (path, source) {
    if (path === null || path === undefined) return;
    const p = String(path).replace(/\/+$/, "");
    if (p.length < 2 || p.charAt(0) !== "/" || seen[p] === true) return;
    seen[p] = true;
    list.push({ path: p, source: source });
  };
  if (cfg.docs_path) add(cfg.docs_path, "config.docs_path");
  try {
    const urls = fileManager().URLsForDirectory_inDomains_(DOC_DIR, USER_MASK);
    if (urls !== null && urls.count() > 0) add(str(urls.firstObject().path()), "URLsForDirectory");
  } catch (e) {}
  try {
    const fn = new NativeFunction(Module.getGlobalExportByName("NSHomeDirectory"), "pointer", []);
    const home = fn().readUtf8String();
    add(home, "NSHomeDirectory");
    add(home + "/Documents", "NSHomeDirectory/Documents");
  } catch (e) {}
  const derived = bundleCandidates();
  for (let i = 0; i < derived.length; i++) add(derived[i][0], derived[i][1]);
  try {
    const fn = new NativeFunction(Module.getGlobalExportByName("NSTemporaryDirectory"), "pointer", []);
    add(fn().readUtf8String(), "NSTemporaryDirectory");
  } catch (e) {}
  add("/tmp", "fallback");
  return list;
}

function filesystemDir() {
  const candidates = collectCandidates();
  const rows = [];
  let loose = null;
  for (let i = 0; i < candidates.length; i++) {
    const c = candidates[i];
    let docs = c.path;
    if (!/\/Documents$/.test(docs) && exists(docs + "/Documents")) docs = docs + "/Documents";
    const isDir = exists(docs);
    const cc = containerLike(docs);
    const wr = isDir && writable(docs);
    rows.push({ path: docs, source: c.source, dir: isDir, container: cc, writable: wr });
    if (!wr) continue;
    if (loose === null) loose = docs;
    if (cc) { pathReport = rows; return docs; }
  }
  pathReport = rows;
  return loose;
}

function initPaths() {
  docsPath = cfg.docs_path && writable(cfg.docs_path) ? cfg.docs_path : filesystemDir();
  updatedPath = docsPath === null ? null : docsPath + "/" + UPDATED;
  if (updatedPath !== null) mkdir(updatedPath);

  const chain = [];
  if (cfg.log_path) chain.push(cfg.log_path);
  if (updatedPath !== null) chain.push(updatedPath + "/" + LOG_NAME);
  if (docsPath !== null) chain.push(docsPath + "/" + LOG_NAME);
  chain.push("/tmp/" + LOG_NAME);
  try {
    const fn = new NativeFunction(Module.getGlobalExportByName("NSTemporaryDirectory"), "pointer", []);
    const tmp = fn().readUtf8String();
    if (tmp) chain.push(tmp + "/" + LOG_NAME);
  } catch (e) {}

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

  if (logPath === null) {
    log("log opened at console only (no writable directory found)");
    return;
  }
  log("log opened at " + logPath);
}

function saveConfig(path) { writeText(path, JSON.stringify(DEFAULTS, null, 2) + "\n"); }

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
    if (!cfg.rva || typeof cfg.rva !== "object") cfg.rva = DEFAULTS.rva;
    if (POSITIONS.indexOf(cfg.position) === -1) cfg.position = DEFAULTS.position;
    log("config loaded " + path);
  } catch (e) {
    cfg = JSON.parse(JSON.stringify(DEFAULTS));
    log("config parse failed (" + e.message + "), defaults used");
  }
}

// -------------------------------------------------------------------------
// game bindings
// -------------------------------------------------------------------------

function rva(name) {
  const v = cfg.rva ? cfg.rva[name] : null;
  if (v === null || v === undefined || v === "") return null;
  try { return Process.mainModule.base.add(parseInt(String(v), 16)); } catch (e) { return null; }
}

function nf(address, ret, args) {
  if (address === null || address === undefined) return null;
  try { return new NativeFunction(address, ret, args); } catch (e) { return null; }
}

function bind() {
  bindings = {};
  for (const k in cfg.rva) {
    const addr = rva(k);
    bindings[k] = addr;
    log("binding " + k + " = " + str(addr));
  }
}

function strPtr(text) { return Memory.allocUtf8String(text); }

function scPtr(text) {
  const ctor = nf(bindings.String_ctor, "pointer", ["pointer", "pointer"]);
  if (ctor === null) return strPtr(text);
  try {
    const buf = Memory.alloc(64);
    ctor(buf, strPtr(text));
    return buf;
  } catch (e) {
    return strPtr(text);
  }
}

function setXY(ptr, x, y) {
  const fn = nf(bindings.DisplayObject_setXY, "void", ["pointer", "float", "float"]);
  if (fn !== null) {
    try { fn(ptr, x, y); return; } catch (e) {}
  }
  try {
    ptr.add(32).writeFloat(x);
    ptr.add(36).writeFloat(y);
  } catch (e) {}
}

function screenBounds() {
  const instance = bindings.Stage_instance;
  if (instance === null) return { rightX: 800, scale: 0.1 };
  try {
    const stage = instance.readPointer();
    const f88 = stage.add(88).readFloat();
    const f84 = stage.add(84).readFloat();
    let scale = 0.1;
    if (stage.add(7224).readFloat() !== 0) scale = stage.add(7232).readFloat();
    const rightX = stage.add(7376).readInt() - (f84 + f88) / scale;
    return { rightX: rightX, scale: scale };
  } catch (e) {
    return { rightX: 800, scale: 0.1 };
  }
}

function positionXY(position) {
  const bounds = screenBounds();
  switch (position) {
    case "top_left":     return { x: 40,                y: 40  };
    case "top_right":    return { x: bounds.rightX - 40, y: 30  };
    case "bottom_right": return { x: bounds.rightX - 40, y: 540 };
    case "bottom_left":
    default:             return { x: 40,                y: 540 };
  }
}

function floater(message) {
  const fn = nf(bindings.GUI_showFloaterTextAt, "void", ["pointer", "pointer", "float", "int"]);
  if (fn === null) return;
  try { fn(ptr(0), scPtr(message), 0, -1); } catch (e) {}
}

// -------------------------------------------------------------------------
// MOD MENU button
// -------------------------------------------------------------------------

function createButton() {
  if (!cfg.enabled) { log("button disabled in config"); return null; }
  if (modMenuButton !== null) return modMenuButton;

  const clipFn = nf(bindings.ResourceManager_getMovieClip, "pointer", ["pointer", "pointer"]);
  const spriteCtor = nf(bindings.Sprite_ctor, "void", ["pointer", "int"]);
  const gameBtnCtor = nf(bindings.GameButton_ctor, "void", ["pointer"]);
  const dropGuiCtor = bindings.DropGUIContainer_ctor;
  const tfByName = nf(bindings.MovieClip_getTextFieldByName, "pointer", ["pointer", "pointer"]);
  const setText = nf(bindings.TextField_setText, "pointer", ["pointer", "pointer", "bool"]);

  if (clipFn === null || gameBtnCtor === null) {
    log("cannot create button: ResourceManager_getMovieClip or GameButton_ctor missing");
    return null;
  }

  try {
    const ptr = Memory.alloc(544);
    if (spriteCtor !== null) spriteCtor(ptr, 1);

    const clip = clipFn(strPtr("sc/ui.sc"), strPtr("map_editor_exit_button"));
    if (clip === null || clip.isNull()) {
      log("movie clip lookup failed (sc/ui.sc / map_editor_exit_button)");
      return null;
    }

    try {
      if (dropGuiCtor !== null) new NativeFunction(dropGuiCtor, "void", ["pointer", "pointer"])(ptr, clip);
    } catch (e) {
      log("DropGUIContainer ctor failed: " + e.message);
    }

    gameBtnCtor(ptr);

    try {
      const vtableMethod = ptr.readPointer().add(352).readPointer();
      new NativeFunction(vtableMethod, "void", ["pointer", "pointer", "bool"])(ptr, clip, 1);
    } catch (e) {
      log("vtable attach failed: " + e.message);
    }

    try {
      const field = tfByName(clip, strPtr("txt"));
      if (field !== null && !field.isNull() && setText !== null) {
        setText(field, scPtr(cfg.text), 1);
      }
    } catch (e) {
      log("setText failed: " + e.message);
    }

    const pos = positionXY(cfg.position);
    setXY(ptr, pos.x, pos.y);

    modMenuButton = { ptr: ptr, clip: clip, x: pos.x, y: pos.y };
    log("MOD MENU button created at " + pos.x + "," + pos.y + " pos=" + cfg.position);
    return modMenuButton;
  } catch (e) {
    log("createButton error: " + e.message);
    return null;
  }
}

function destroyButton() {
  if (modMenuButton === null) return;
  try { modMenuButton.ptr.add(8).writeU8(0); } catch (e) {}
  try { setXY(modMenuButton.ptr, 9999, 9999); } catch (e) {}
  modMenuButton = null;
  log("MOD MENU button removed");
}

function reposition() {
  if (modMenuButton === null) return false;
  const pos = positionXY(cfg.position);
  setXY(modMenuButton.ptr, pos.x, pos.y);
  modMenuButton.x = pos.x;
  modMenuButton.y = pos.y;
  log("MOD MENU button moved to " + pos.x + "," + pos.y + " pos=" + cfg.position);
  return true;
}

function recreateButton() {
  destroyButton();
  return createButton();
}

// -------------------------------------------------------------------------
// hooks
// -------------------------------------------------------------------------

function attachHooks() {
  if (homePageHook === null && bindings.HomePage_ctor !== null) {
    homePageHook = Interceptor.attach(bindings.HomePage_ctor, {
      onEnter(args) { this.self = args[0]; },
      onLeave() {
        setTimeout(function () {
          recreateButton();
        }, 200);
      }
    });
    log("hooked HomePage.ctor");
  }

  if (closePopupHook === null && bindings.GUI_closePopup !== null) {
    closePopupHook = Interceptor.attach(bindings.GUI_closePopup, {
      onEnter() {
        setTimeout(function () {
          if (modMenuButton === null) createButton();
          else reposition();
        }, 300);
      }
    });
    log("hooked GUI.closePopup");
  }
}

function detachHooks() {
  if (homePageHook !== null) { try { homePageHook.detach(); } catch (e) {} homePageHook = null; }
  if (closePopupHook !== null) { try { closePopupHook.detach(); } catch (e) {} closePopupHook = null; }
}

// -------------------------------------------------------------------------
// lifecycle
// -------------------------------------------------------------------------

function environment() {
  try { log("frida=" + Frida.version + " runtime=" + Script.runtime + " arch=" + Process.arch + " pid=" + Process.id); } catch (e) {}
  try {
    const device = ObjC.classes.UIDevice.currentDevice();
    log("device=" + str(device.systemName()) + " " + str(device.systemVersion()) + " " + str(device.model()));
  } catch (e) {}
  try { log("bundle=" + bundlePath()); } catch (e) {}
  try { log("bundleId=" + str(ObjC.classes.NSBundle.mainBundle().bundleIdentifier())); } catch (e) {}
  try {
    log("executable=" + Process.mainModule.path);
    log("base=" + Process.mainModule.base + " code_signing=" + Process.codeSigningPolicy);
  } catch (e) {}
  log("documents=" + str(docsPath));
  log("uuid=" + uuidIn(docsPath));
  log("updated=" + str(updatedPath));
  log("log=" + str(logPath));
  for (let i = 0; i < pathReport.length; i++) {
    const r = pathReport[i];
    log("candidate " + r.path + " [" + r.source + "] dir=" + r.dir + " container=" + r.container + " writable=" + r.writable);
  }
}

function start(stage, parameters) {
  if (started) return;
  started = true;
  initPaths();
  log("=== modmenu start ===");
  log("stage=" + str(stage) + " parameters=" + JSON.stringify(parameters === undefined ? {} : parameters));
  environment();
  loadConfig();
  log("config enabled=" + cfg.enabled + " position=" + cfg.position + " text=" + cfg.text);
  bind();
  attachHooks();
  const delays = cfg.reapply_ms || [];
  for (let i = 0; i < delays.length; i++) {
    setTimeout(function () {
      log("reapply tick");
      attachHooks();
      if (modMenuButton === null) createButton();
      else reposition();
    }, delays[i]);
  }
  log("=== modmenu armed ===");
}

function dispose() {
  log("=== modmenu dispose ===");
  detachHooks();
  destroyButton();
  started = false;
}

// -------------------------------------------------------------------------
// RPC
// -------------------------------------------------------------------------

rpc.exports = {
  init: function (stage, parameters) { start(stage, parameters); return true; },
  dispose: function () { dispose(); return true; },
  show: function () { return createButton() !== null; },
  hide: function () { destroyButton(); return true; },
  recreate: function () { recreateButton(); return true; },
  setPosition: function (position) {
    if (POSITIONS.indexOf(position) === -1) return false;
    cfg.position = position;
    if (updatedPath !== null) writeText(updatedPath + "/" + CFG_NAME, JSON.stringify(cfg, null, 2) + "\n");
    const ok = reposition();
    floater("Position: " + position);
    return ok;
  },
  setText: function (text) {
    cfg.text = str(text) || "MOD MENU";
    if (updatedPath !== null) writeText(updatedPath + "/" + CFG_NAME, JSON.stringify(cfg, null, 2) + "\n");
    recreateButton();
    return true;
  },
  setColor: function (r, g, b) {
    cfg.color_rgb = [r | 0, g | 0, b | 0];
    if (updatedPath !== null) writeText(updatedPath + "/" + CFG_NAME, JSON.stringify(cfg, null, 2) + "\n");
    log("color set to rgb(" + cfg.color_rgb.join(",") + ")");
    return cfg.color_rgb;
  },
  enable: function (flag) {
    cfg.enabled = flag !== false;
    if (updatedPath !== null) writeText(updatedPath + "/" + CFG_NAME, JSON.stringify(cfg, null, 2) + "\n");
    if (cfg.enabled) createButton();
    else destroyButton();
    return cfg.enabled;
  },
  reload: function () {
    loadConfig();
    bind();
    recreateButton();
    return true;
  },
  info: function () {
    return {
      log: logPath,
      documents: docsPath,
      updated: updatedPath,
      uuid: uuidIn(docsPath),
      uuids: uuidsIn(docsPath),
      bundle: bundlePath(),
      candidates: pathReport,
      enabled: cfg.enabled,
      position: cfg.position,
      text: cfg.text,
      color_rgb: cfg.color_rgb,
      button: modMenuButton === null ? null : {
        x: modMenuButton.x,
        y: modMenuButton.y,
        ptr: str(modMenuButton.ptr),
        clip: str(modMenuButton.clip)
      },
      bindings: (function () {
        const out = {};
        for (const k in bindings) out[k] = str(bindings[k]);
        return out;
      })(),
      rva: cfg.rva
    };
  },
  paths: function () {
    return {
      documents: docsPath,
      updated: updatedPath,
      log: logPath,
      uuid: uuidIn(docsPath),
      uuids: uuidsIn(docsPath),
      bundle: bundlePath(),
      candidates: pathReport
    };
  },
  positions: function () { return POSITIONS.slice(0); }
};

start("top-level", {});