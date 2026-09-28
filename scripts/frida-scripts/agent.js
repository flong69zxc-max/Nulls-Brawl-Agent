import ObjC from "frida-objc-bridge";

const LOG_NAME = "agent.log";
const CFG_NAME = "agent_config.json";
const UPDATED = "updated";
const TEST_NAME = ".__agent_write_test";
const DOC_DIR = 9;
const USER_MASK = 1;
const MAX_LOG_BYTES = 1048576;
const SCAN_CHUNK = 16 * 1024 * 1024;
const SCAN_MARGIN = 0x10000000;

const DEFAULTS = {
  patch: false,
  alert: true,
  alert_delay_ms: 5000,
  alert_tries: 40,
  alert_try_ms: 500,
  alert_auto_dismiss_ms: 0,
  reapply_ms: [3000, 8000, 15000],
  log_path: "",
  docs_path: "",
  scan_strings: true,
  scan_dev_flags: true,
  scan_delay_ms: 10000,
  scan_min_length: 4,
  scan_result_file: "scan_result.json",
  targets: [
    { name: "isDev", rva: "0xd93da0", type: "u8", value: 1 }
  ]
};

const STRING_ANCHORS = {
  "LogicVersion_isDeveloperBuild": ["isDeveloperBuild"],
  "LogicVersion_isProduction": ["isProduction"],
  "SCIDConfig_isDevBuild": ["isDevBuild"],
  "LogicBattleModeClient_update": ["LogicBattleModeClient"],
  "BattleScreen_activateSkill": ["activateSkill"],
  "Gui_showFloaterTextAtDefaultPos": ["showFloaterText"],
  "StringCtor": ["String not found:"],
  "SCIDConfig__getBool": ["DisableIngameFriends"],
  "LogicCharacterData_getCollisionRadius": ["CollisionRadius"],
  "LogicProjectileData_getRadius": ["ProjectileRadius"],
  "ClientInputManager_addInput": ["addInput"],
  "ResourceManager__isResourceLoaded": ["isResourceLoaded"],
  "MessageManager__receiveMessage": ["receiveMessage"],
  "MessageManager__sendMessage": ["sendMessage"],
  "LogicBattleModeClient_getOwnCharacter": ["getOwnCharacter"],
  "LogicGameObjectClient_getX": ["getX"],
  "LogicGameObjectClient_getY": ["getY"],
  "LogicGameObjectClient_getZ": ["getZ"],
  "Sprite_Sprite": ["Sprite"],
  "TextField_setText": ["setText"],
  "ScrollArea__scrollTo": ["scrollTo"],
  "DisplayObject__setXY": ["setXY"],
  "MovieClip__getTextFieldByName": ["getTextFieldByName"],
  "Sprite__addChild": ["addChild"],
  "Sprite__removeChild": ["removeChild"],
  "LogicSkillData__getMsBetweenAttacks": ["MsBetweenAttacks"],
  "LogicSkillData__getActiveTime": ["ActiveTime"],
  "LogicSkillData__getCastingRange": ["CastingRange"],
  "LogicSkillData__getRechargeTime": ["RechargeTime"],
  "LogicSkillData__getMaxCharge": ["MaxCharge"],
  "LogicProjectileData_getSpeed": ["ProjectileSpeed"],
  "LogicProjectileData_getRendering": ["ProjectileRendering"],
  "LogicProjectileData__isBeam": ["isBeam"],
  "LogicProjectileData__getNumEarlyTicks": ["NumEarlyTicks"],
  "LogicTileData__blocksMovement": ["BlocksMovement"],
  "LogicTileData__blocksProjectiles": ["BlocksProjectiles"],
  "LogicBattleModeClient__getTileMap": ["getTileMap"],
  "LogicBattleModeClient__getOwnPlayerIndex": ["getOwnPlayerIndex"],
  "LogicBattleModeClient__setRandomSeed": ["setRandomSeed"],
  "LogicBattleModeClient__setPlayerAvatar": ["setPlayerAvatar"],
  "LogicCharacterClient__getWeaponSkill": ["getWeaponSkill"],
  "LogicCharacterClient__getSkillAt": ["getSkillAt"],
  "LogicCharacterClient__getCarryableData": ["getCarryableData"],
  "LogicCharacterClient__getLinkedCarryable": ["getLinkedCarryable"],
  "LogicCharacterClient__isImmuneOrUntargetable": ["isImmuneOrUntargetable"],
  "LogicGameObjectManagerClient__getGameObjects": ["getGameObjects"],
  "LogicGameObjectManagerClient__findGameObject": ["findGameObject"],
  "LogicProjectileServer__shootProjectile": ["shootProjectile"],
  "LogicProjectileServer__runEarlyTicks": ["runEarlyTicks"],
  "GlobalID__getInstanceID": ["getInstanceID"],
  "LogicPlayerMap__save": ["save"],
  "LogicPlayerMapUtil__tileDataToTileCode": ["tileDataToTileCode"],
  "LogicRandom__setIteratedRandomSeed": ["setIteratedRandomSeed"],
  "LogicLongToCodeConverterUtil__convert": ["convert"],
  "LogicLongToCodeConverterUtil__toCode": ["toCode"],
  "ResourceListener__addFile": ["addFile"],
  "String__format": ["format"],
  "FramerateManager__setSegment": ["setSegment"],
  "FramerateManager__setLimit": ["setLimit"],
  "Application__copyString": ["copyString"],
  "BattleScreen__calculateProjectilePath": ["calculateProjectilePath"],
  "BattleScreen__joystickToWorld": ["joystickToWorld"],
  "BattleScreen__shouldShowAccessoryButton": ["shouldShowAccessoryButton"],
  "BattleScreen__updateCameraParameters": ["updateCameraParameters"],
  "BattleScreen__stopWithStick": ["stopWithStick"],
  "BattleScreen__handleTouchReleased": ["handleTouchReleased"],
  "BattleScreen__updateMovement": ["updateMovement"],
  "BattleScreen__updateAutoshoot": ["updateAutoshoot"],
  "BattleScreen__tryToActivateSkill": ["tryToActivateSkill"],
  "BattleScreen_getClosestTargetForAutoshoot": ["getClosestTargetForAutoshoot"],
  "CombatHUD__toggleEditing": ["toggleEditing"],
  "CombatHUD__setShootStickState": ["setShootStickState"],
  "CombatHUD__setMoveStickState": ["setMoveStickState"],
  "CombatHUD__sendPinCommand": ["sendPinCommand"],
  "CombatHUD__sendSprayCommand": ["sendSprayCommand"],
  "Character__updateHealthBar": ["updateHealthBar"],
  "GUI__getDefaultFloaterPos": ["getDefaultFloaterPos"],
  "GUI__showFloaterTextAt": ["showFloaterTextAt"],
  "GUI__showPopup": ["showPopup"],
  "GameSliderComponent__setValueBounds": ["setValueBounds"],
  "MapEditorModifierPopup__addModifierItem": ["addModifierItem"],
  "ScrollArea__updateBounds": ["updateBounds"],
  "ScrollArea__addContent": ["addContent"],
  "ScrollArea__removeAllContent": ["removeAllContent"],
  "CSVRow__getIntegerValueAt": ["getIntegerValueAt"],
  "CSVRow__getName": ["getName"],
  "CSVRow__getValueAt": ["getValueAt"],
  "CSVRow__getBooleanValueAt": ["getBooleanValueAt"],
  "CSVTable__getColumnIndexByName": ["getColumnIndexByName"],
  "LogicJSONObject__put": ["put"],
  "GameStateManager__getInstance": ["getInstance"],
  "GameStateManager__isState": ["isState"],
  "HomeMode__getInstance": ["getInstance"],
  "StringTable__getMovieClip": ["getMovieClip"],
  "MovieClipHelper__setTextAndScaleIfNecessary": ["setTextAndScaleIfNecessary"],
  "LogicTile__setData": ["setData"],
  "LogicTileMap__isPlayerLineOfSightClear": ["isPlayerLineOfSightClear"],
  "LogicDataTables__getOpenTileData": ["getOpenTileData"],
  "LogicDataTables__getBaseTileData": ["getBaseTileData"],
  "LogicDataTables__getSiegeBoltTileData": ["getSiegeBoltTileData"],
  "LogicCharacterData_getSpeed": ["CharacterSpeed"],
  "BattleMode_getInstance": ["getInstance"],
  "BattleMode__enter": ["enter"],
  "BattleMode__addResourcesToLoad": ["addResourcesToLoad"],
  "ClientInputMessage_sendMovement": ["sendMovement"],
  "HashTagCodeGenerator__toId": ["toId"],
  "HashTagCodeGenerator__isValid": ["isValid"],
  "Name_setupDecorated": ["setupDecorated"],
  "Name_applyDecoration": ["applyDecoration"],
  "AllianceManager__startSpectate": ["startSpectate"],
  "CustomButton_onButtonPressed": ["onButtonPressed"],
  "nativeCopyToClipboard": ["copyToClipboard"],
  "LogicGameModeUtil__isTileOnPoisonArea": ["isTileOnPoisonArea"],
  "LogicData_getName": ["getName"],
  "LogicDataTable_findByName": ["findByName"],
  "AreaEffectData__getRadius": ["getRadius"],
  "AreaEffectData__getActiveTimeMs": ["getActiveTimeMs"],
  "MovieClip__getChildClipByName": ["getChildClipByName"],
  "MovieClip__setChildVisible": ["setChildVisible"],
  "MovieClip__gotoAndStopFrameIndex": ["gotoAndStopFrameIndex"],
  "Screen__getDpiClass": ["getDpiClass"],
  "Screen__getHeight": ["getHeight"],
  "Screen__getWidth": ["getWidth"]
};

const DEVELOPER_FLAGS = {
  "LogicVersion_isDeveloperBuild": ["isDeveloperBuild"],
  "LogicVersion_isDev": ["isDev"],
  "LogicVersion_isProd": ["isProd"],
  "SCIDConfig_isDevBuild": ["isDevBuild"],
  "LogicVersion_isProduction": ["isProduction"]
};

let cfg = {};
let logPath = null;
let docsPath = null;
let updatedPath = null;
let pathReport = [];
let lcReport = [];
let started = false;
let targetModule = null;
let regionCache = {};

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

function sep(label) { log("---- " + label + " ----"); }

function fileManager() { return ObjC.classes.NSFileManager.defaultManager(); }

function selector(name) {
  try { return ObjC.selector(name); } catch (e) { return null; }
}

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

function writable(path) {
  if (!path) return false;
  const test = path + "/" + TEST_NAME;
  const payload = "probe-" + Date.now();
  if (!writeText(test, payload)) return false;
  if (readText(test) !== payload) {
    try { fileManager().removeItemAtPath_error_(test, null); } catch (e) {}
    return false;
  }
  try { fileManager().removeItemAtPath_error_(test, null); } catch (e) {}
  return true;
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

function numOf(pointer) {
  const text = pointer.toString();
  return parseInt(text.substring(0, 2) === "0x" ? text.substring(2) : text, 16);
}

function hexOf(pointer) { return "0x" + numOf(pointer).toString(16); }

function lcDump() {
  const out = [];
  const seen = {};
  const push = function (key, value) {
    if (seen[key] === true) return;
    seen[key] = true;
    out.push(key + "=" + str(value));
  };
  let ud = null;
  try { ud = ObjC.classes.NSUserDefaults; } catch (e) { ud = null; }
  if (ud === null || ud === undefined) {
    lcReport = ["lc api not found"];
    return out;
  }
  const classMethods = ["isLiveProcess", "lcGuestAppId", "lcAppGroupPath", "isSharedApp"];
  for (let i = 0; i < classMethods.length; i++) {
    const name = classMethods[i];
    if (!responds(ud, name)) continue;
    try { push("lc." + name, ud[name]()); } catch (e) {}
  }
  const dicts = ["guestContainerInfo", "guestAppInfo"];
  for (let d = 0; d < dicts.length; d++) {
    const name = dicts[d];
    if (!responds(ud, name)) continue;
    let info = null;
    try { info = ud[name](); } catch (e) { continue; }
    if (info === null) continue;
    try {
      const keys = info.allKeys();
      const n = keys.count();
      for (let i = 0; i < n; i++) {
        const key = keys.objectAtIndex_(i);
        let value = null;
        try { value = info.objectForKey_(key); } catch (e) {}
        push("lc." + name + "." + str(key), value);
      }
    } catch (e) {}
  }
  lcReport = out.slice(0);
  return out;
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
  out.push([grand + "/Data/Application/" + folder, "bundle:Data/Application/folder-root"]);
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
  const lc = lcDump();
  for (let i = 0; i < lc.length; i++) {
    const eq = lc[i].indexOf("=");
    const key = lc[i].substring(0, eq);
    const value = lc[i].substring(eq + 1);
    if (!value || value.charAt(0) !== "/") continue;
    add(value, "lc:" + key);
    add(value + "/Documents", "lc:" + key + "/Documents");
  }
  try {
    const urls = fileManager().URLsForDirectory_inDomains_(DOC_DIR, USER_MASK);
    if (urls !== null && urls.count() > 0) add(str(urls.firstObject().path()), "URLsForDirectory");
  } catch (e) {}
  try {
    const fn = new NativeFunction(Module.getGlobalExportByName("NSSearchPathForDirectoriesInDomains"), "pointer", ["uint", "uint", "bool"]);
    const arr = new ObjC.Object(fn(DOC_DIR, USER_MASK, true));
    if (arr.count() > 0) add(str(arr.objectAtIndex_(0)), "NSSearchPathForDirectoriesInDomains");
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
    try { console.log("[agent] no writable directory for log"); } catch (e) {}
    return;
  }
  log("log opened at " + logPath);
}

function saveConfig(path) { writeText(path, JSON.stringify(DEFAULTS, null, 2) + "\n"); }

function loadConfig() {
  if (updatedPath === null) {
    cfg = JSON.parse(JSON.stringify(DEFAULTS));
    log("no updated path, using defaults");
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

function findTargetModule() {
  try {
    const mods = Process.enumerateModules();
    log("modules total: " + mods.length);
    for (let i = 0; i < mods.length; i++) {
      const m = mods[i];
      const p = m.path || "";
      if (p.indexOf("/NB.app/") !== -1 && p.indexOf("/Frameworks/") === -1) {
        log("target module matched NB.app: " + m.name + " " + m.base + " size=" + m.size + " path=" + p);
        return m;
      }
    }
    for (let i = 0; i < mods.length; i++) {
      const m = mods[i];
      if (/nulls/i.test(m.name || "")) {
        log("target module matched name nulls: " + m.name + " " + m.base);
        return m;
      }
    }
    let best = mods.length > 0 ? mods[0] : null;
    for (let i = 0; i < mods.length; i++) {
      if (best === null || mods[i].size > best.size) best = mods[i];
    }
    if (best !== null) log("target module fallback largest: " + best.name + " " + best.base + " size=" + best.size);
    return best;
  } catch (e) {
    log("findTargetModule failed: " + e.message);
    return null;
  }
}

function baseOf(target) {
  if (target.module) return Process.getModuleByName(target.module).base;
  if (targetModule !== null) return targetModule.base;
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

function tryProtect(addr, size) {
  try {
    Memory.protect(addr, size, "rwx");
    return true;
  } catch (e) {}
  try {
    Memory.protect(addr, size, "rw-");
    return true;
  } catch (e) {}
  return false;
}

function applyTarget(target) {
  const type = target.type || "u8";
  const name = target.name || "target";
  const size = sizeOf(type);
  let addr;
  try { addr = addrOf(target); } catch (e) {
    log("target " + name + ": address failed: " + e.message);
    return "addr-error";
  }
  const range = Process.findRangeByAddress(addr);
  if (range === null) {
    log("target " + name + " @" + addr + ": not mapped, skipped");
    return "unmapped";
  }
  if (range.protection.indexOf("r") === -1) {
    log("target " + name + " @" + addr + ": not readable (" + range.protection + "), skipped");
    return "unreadable";
  }
  let before;
  try { before = readAt(addr, type); } catch (e) {
    log("target " + name + " @" + addr + ": read failed: " + e.message);
    return "read-error";
  }
  const want = valueOf(target.value, type);
  if (target.expect !== undefined && target.expect !== null) {
    const expect = valueOf(target.expect, type);
    if (expect !== before) {
      log("target " + name + " @" + addr + ": expect " + str(expect) + " but found " + str(before) + ", skipped");
      return "expect-mismatch";
    }
  }
  if (before === want) {
    log("target " + name + " @" + addr + ": already " + str(before) + " (" + range.protection + ")");
    return "already";
  }
  if (cfg.patch === false || target.patch === false) {
    log("target " + name + " @" + addr + ": probe: before=" + str(before) + " want=" + str(want) + " (" + range.protection + ")");
    return "probe";
  }
  let patched = false;
  try {
    Memory.patchCode(addr, size, function (code) { writeAt(code, want, type); });
    patched = true;
  } catch (e) {
    log("target " + name + " @" + addr + ": patchCode failed: " + e.message + ", trying Memory.protect");
  }
  if (!patched) {
    if (!tryProtect(addr, size)) {
      log("target " + name + " @" + addr + ": Memory.protect failed");
      return "protect-error";
    }
    try { writeAt(addr, want, type); patched = true; }
    catch (e) {
      log("target " + name + " @" + addr + ": write failed: " + e.message);
      return "write-error";
    }
  }
  let after = null;
  try { after = readAt(addr, type); } catch (e) {}
  if (after === want) {
    log("target " + name + " @" + addr + ": " + str(before) + " -> " + str(after) + " (" + range.protection + ")");
    return "ok";
  }
  log("target " + name + " @" + addr + ": write did not stick (" + str(before) + " -> " + str(after) + ")");
  return "no-stick";
}

function applyPatches() {
  const targets = cfg.targets || DEFAULTS.targets;
  const result = {};
  for (let i = 0; i < targets.length; i++) {
    const name = targets[i].name || ("target" + i);
    try { result[name] = applyTarget(targets[i]); } catch (e) {
      result[name] = "error";
      log("target " + name + ": apply failed: " + e.message);
    }
  }
  return result;
}

function hexPattern(text) {
  if (text === null || text === undefined) return null;
  const s = String(text);
  if (s.length < cfg.scan_min_length) return null;
  const parts = [];
  for (let i = 0; i < s.length; i++) {
    const code = s.charCodeAt(i);
    if (code > 127) return null;
    parts.push(("0" + code.toString(16)).slice(-2));
  }
  return parts.join(" ");
}

function targetRange() {
  if (targetModule === null) targetModule = findTargetModule();
  if (targetModule === null) return null;
  const base = numOf(targetModule.base);
  return [base, base + targetModule.size + SCAN_MARGIN];
}

function regionList(protections) {
  const key = protections.slice().sort().join(",");
  if (regionCache[key] !== undefined) return regionCache[key];
  const tr = targetRange();
  if (tr === null) {
    regionCache[key] = [];
    return regionCache[key];
  }
  const lo = tr[0];
  const hi = tr[1];
  log("region filter: lo=0x" + lo.toString(16) + " hi=0x" + hi.toString(16));
  const out = [];
  const seen = {};
  for (let i = 0; i < protections.length; i++) {
    let ranges = [];
    try { ranges = Process.enumerateRanges(protections[i]); } catch (e) { continue; }
    for (let r = 0; r < ranges.length; r++) {
      const range = ranges[r];
      const rb = numOf(range.base);
      const re = rb + range.size;
      if (re < lo || rb > hi) continue;
      const dedupe = range.base.toString() + ":" + range.size;
      if (seen[dedupe] === true) continue;
      seen[dedupe] = true;
      out.push(range);
    }
  }
  log("regions after filter [" + protections.join("|") + "]: " + out.length);
  regionCache[key] = out;
  return out;
}

function scanRegion(range, pattern) {
  const results = [];
  const base = range.base;
  const size = range.size;
  let offset = 0;
  while (offset < size) {
    const take = Math.min(SCAN_CHUNK, size - offset);
    try {
      const matches = Memory.scanSync(base.add(offset), take, pattern);
      for (let i = 0; i < matches.length; i++) results.push(matches[i].address);
    } catch (e) {
      log("scan chunk fail at " + hexOf(base.add(offset)) + " size=" + take + ": " + e.message);
    }
    offset += take;
  }
  return results;
}

function pageOf(value) { return value - (value % 4096); }

function tagAnchor(target, tag) {
  if (target.anchors.indexOf(tag) === -1) target.anchors.push(tag);
}

function collectStringHits(map, regions) {
  const hits = [];
  const byAddress = {};
  let anchorsScanned = 0;
  for (const name in map) {
    const anchors = map[name];
    for (let a = 0; a < anchors.length; a++) {
      const pattern = hexPattern(anchors[a]);
      if (pattern === null) continue;
      anchorsScanned++;
      let before = hits.length;
      for (let r = 0; r < regions.length; r++) {
        const matches = scanRegion(regions[r], pattern);
        for (let m = 0; m < matches.length; m++) {
          const address = numOf(matches[m]);
          const key = String(address);
          if (byAddress[key] === undefined) {
            byAddress[key] = { address: address, anchors: [], xrefs: [] };
            hits.push(byAddress[key]);
          }
          tagAnchor(byAddress[key], name + ":" + anchors[a]);
        }
      }
      if (hits.length > before) {
        log("anchor " + name + ":" + anchors[a] + " -> " + (hits.length - before) + " new hit(s)");
      }
    }
  }
  log("anchors scanned " + anchorsScanned + ", unique addresses=" + hits.length);
  return hits;
}

function symbolOf(address) {
  try {
    const sym = DebugSymbol.fromAddress(ptr(String(address)));
    const name = sym === null || sym === undefined ? null : sym.name;
    return name === null || name === undefined ? null : String(name);
  } catch (e) { return null; }
}

function findXrefs(targets, regions) {
  if (targets.length === 0) return;
  const wanted = {};
  for (let i = 0; i < targets.length; i++) wanted[String(targets[i].address)] = targets[i];
  log("xref search over " + regions.length + " exec region(s) for " + targets.length + " addresses");
  let execBytes = 0;
  for (let r = 0; r < regions.length; r++) execBytes += regions[r].size;
  log("exec bytes total: " + execBytes);
  for (let r = 0; r < regions.length; r++) {
    const range = regions[r];
    const base = numOf(range.base);
    const size = range.size;
    let offset = 0;
    while (offset < size) {
      const take = Math.min(SCAN_CHUNK, size - offset);
      let buffer = null;
      try { buffer = range.base.add(offset).readByteArray(take); } catch (e) {
        offset += take;
        continue;
      }
      if (buffer === null) { offset += take; continue; }
      const view = new DataView(buffer);
      const count = Math.floor(take / 4);
      const registers = {};
      for (let i = 0; i < count; i++) {
        const insn = view.getUint32(i * 4, true);
        const address = base + offset + i * 4;
        const family = (insn & 0x9f000000) >>> 0;
        if (family === 0x90000000 || family === 0x10000000) {
          let imm = (((insn >>> 5) & 0x7ffff) << 2) | ((insn >>> 29) & 3);
          if (imm & 0x100000) imm -= 0x200000;
          if (family === 0x90000000) {
            registers[insn & 0x1f] = pageOf(address) + imm * 4096;
          } else {
            const direct = wanted[String(address + imm)];
            if (direct !== undefined) direct.xrefs.push({ function: address, symbol: symbolOf(address) });
          }
          continue;
        }
        if (((insn & 0xff800000) >>> 0) === 0x91000000) {
          const from = registers[(insn >>> 5) & 0x1f];
          if (from === undefined) continue;
          const shift = (insn >>> 22) & 3;
          const imm12 = (insn >>> 10) & 0xfff;
          const value = from + (shift === 1 ? imm12 * 4096 : imm12);
          const hit = wanted[String(value)];
          if (hit !== undefined) hit.xrefs.push({ function: address, symbol: symbolOf(address) });
        }
      }
      offset += take;
    }
  }
}

function scanMap(map, label, resultFile) {
  sep("scan " + label + " start");
  if (targetModule === null) targetModule = findTargetModule();
  if (targetModule === null) {
    log("no target module, abort");
    return null;
  }
  log("target module: " + targetModule.name);
  log("target base: " + targetModule.base);
  log("target size: 0x" + targetModule.size.toString(16));
  log("target path: " + targetModule.path);
  const base = numOf(targetModule.base);
  const readRegions = regionList(["r--", "r-x"]);
  const execRegions = regionList(["r-x"]);
  log("read regions: " + readRegions.length);
  log("exec regions: " + execRegions.length);
  const hits = collectStringHits(map, readRegions);
  for (let i = 0; i < hits.length; i++) hits[i].rva = hits[i].address - base;
  log("hits with rva computed: " + hits.length);
  findXrefs(hits, execRegions);
  const report = {
    generatedAt: new Date().toISOString(),
    label: label,
    module: {
      name: targetModule.name,
      base: targetModule.base.toString(),
      size: targetModule.size,
      path: targetModule.path
    },
    hits: [],
    summary: { hits: hits.length, withXrefs: 0, totalXrefs: 0 }
  };
  for (let i = 0; i < hits.length; i++) {
    const hit = hits[i];
    if (hit.xrefs.length > 0) report.summary.withXrefs++;
    report.summary.totalXrefs += hit.xrefs.length;
    const entry = {
      anchor: hit.anchors.join(","),
      address: "0x" + hit.address.toString(16),
      rva: "0x" + hit.rva.toString(16),
      xrefs: []
    };
    for (let x = 0; x < hit.xrefs.length; x++) {
      const xref = hit.xrefs[x];
      entry.xrefs.push({
        function: "0x" + xref.function.toString(16),
        functionRva: "0x" + (xref.function - base).toString(16),
        symbol: xref.symbol
      });
    }
    report.hits.push(entry);
    if (entry.xrefs.length > 0) {
      log("HIT " + entry.anchor + " strRva=" + entry.rva + " xrefs=" + entry.xrefs.length);
      for (let x = 0; x < entry.xrefs.length && x < 5; x++) {
        log("    xref funcRva=" + entry.xrefs[x].functionRva + (entry.xrefs[x].symbol ? " symbol=" + entry.xrefs[x].symbol : ""));
      }
    } else {
      log("HIT " + entry.anchor + " strRva=" + entry.rva + " xrefs=0");
    }
  }
  if (updatedPath !== null) {
    const target = updatedPath + "/" + (resultFile || cfg.scan_result_file);
    if (writeText(target, JSON.stringify(report, null, 2) + "\n")) log("scan result written to " + target);
    else log("scan result write failed: " + target);
  }
  sep("scan " + label + " done: hits=" + report.summary.hits + " withXrefs=" + report.summary.withXrefs + " totalXrefs=" + report.summary.totalXrefs);
  return report;
}

function scanStrings() { return scanMap(STRING_ANCHORS, "strings", cfg.scan_result_file); }
function scanDevFlags() { return scanMap(DEVELOPER_FLAGS, "dev flags", "scan_result_devflags.json"); }

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
    if (tries >= cfg.alert_tries) { log("alert skipped: no key window"); return false; }
    setTimeout(function () { showAlertOnMain(title, message, tries + 1); }, cfg.alert_try_ms);
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
      setTimeout(function () { try { alert.dismissViewControllerAnimated_completion_(true, null); } catch (e) {} }, cfg.alert_auto_dismiss_ms);
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
    ObjC.schedule(ObjC.mainQueue, function () { showAlertOnMain(title, message, 0); });
  }, cfg.alert_delay_ms);
  return true;
}

function environment() {
  sep("environment");
  try { log("frida=" + Frida.version + " runtime=" + Script.runtime + " arch=" + Process.arch + " pid=" + Process.id); } catch (e) {}
  try {
    const device = ObjC.classes.UIDevice.currentDevice();
    log("device=" + str(device.systemName()) + " " + str(device.systemVersion()) + " " + str(device.model()));
  } catch (e) {}
  try { log("bundle=" + bundlePath()); } catch (e) {}
  try { log("bundleId=" + str(ObjC.classes.NSBundle.mainBundle().bundleIdentifier())); } catch (e) {}
  try {
    log("mainModule.path=" + Process.mainModule.path);
    log("mainModule.base=" + Process.mainModule.base + " code_signing=" + Process.codeSigningPolicy);
  } catch (e) {}
  const lc = lcDump();
  log("livecontainer: " + (lc.length === 0 ? "not detected" : "detected"));
  for (let i = 0; i < lc.length; i++) log("  lc " + lc[i]);
  log("docsPath=" + str(docsPath));
  log("updatedPath=" + str(updatedPath));
  log("logPath=" + str(logPath));
  log("uuid=" + uuidIn(docsPath) + " all=" + uuidsIn(docsPath).join(","));
  sep("path candidates");
  for (let i = 0; i < pathReport.length; i++) {
    const r = pathReport[i];
    log("  " + r.path);
    log("    source=" + r.source + " dir=" + r.dir + " container=" + r.container + " writable=" + r.writable);
  }
  if (updatedPath !== null) log("updated contents: [" + listDir(updatedPath).join(" ") + "]");
}

function start(stage, parameters) {
  if (started) return;
  started = true;
  initPaths();
  sep("agent start");
  log("stage=" + str(stage));
  log("parameters=" + JSON.stringify(parameters === undefined ? {} : parameters));
  environment();
  loadConfig();
  targetModule = findTargetModule();
  sep("config");
  log("patch=" + cfg.patch);
  log("alert=" + cfg.alert);
  log("scan_strings=" + cfg.scan_strings);
  log("scan_dev_flags=" + cfg.scan_dev_flags);
  log("scan_delay_ms=" + cfg.scan_delay_ms);
  log("targets count=" + (cfg.targets || []).length);
  for (let i = 0; i < (cfg.targets || []).length; i++) {
    const t = cfg.targets[i];
    log("  target[" + i + "] " + (t.name || "?") + " rva=" + t.rva + " type=" + (t.type || "u8") + " value=" + t.value);
  }
  sep("initial patches");
  log("result: " + JSON.stringify(applyPatches()));
  const delays = cfg.reapply_ms || [];
  for (let i = 0; i < delays.length; i++) {
    (function (delay) {
      setTimeout(function () { log("reapply at +" + delay + "ms: " + JSON.stringify(applyPatches())); }, delay);
    })(delays[i]);
  }
  if (cfg.scan_strings || cfg.scan_dev_flags) {
    setTimeout(function () {
      if (cfg.scan_strings) scanStrings();
      if (cfg.scan_dev_flags) scanDevFlags();
      log("=== all scans complete ===");
    }, cfg.scan_delay_ms);
  }
  showAlert("Nulls Brawl", "agent loaded");
  sep("agent armed");
}

rpc.exports = {
  init: function (stage, parameters) { start(stage, parameters); },
  dispose: function () { log("=== agent dispose ==="); started = false; },
  patch: function () { return applyPatches(); },
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
      } catch (e) { out[name] = { error: e.message }; }
    }
    return out;
  },
  alert: function (title, message) { showAlert(str(title), str(message)); return true; },
  info: function () {
    return {
      log: logPath,
      documents: docsPath,
      updated: updatedPath,
      uuid: uuidIn(docsPath),
      uuids: uuidsIn(docsPath),
      bundle: bundlePath(),
      livecontainer: lcReport,
      candidates: pathReport,
      patch: cfg.patch,
      alert: cfg.alert,
      targets: cfg.targets,
      targetModule: targetModule === null ? null : { name: targetModule.name, base: targetModule.base.toString(), size: targetModule.size, path: targetModule.path }
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
      livecontainer: lcReport,
      candidates: pathReport
    };
  },
  reload: function () { loadConfig(); return applyPatches(); },
  scanStrings: function () { return scanStrings(); },
  scanDevFlags: function () { return scanDevFlags(); }
};

start("top-level", {});