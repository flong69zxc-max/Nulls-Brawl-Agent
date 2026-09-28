import ObjC from "frida-objc-bridge";

const LOG_NAME = "offsets_finder.log";
const RESULT_NAME = "offsets.json";
const FLAT_NAME = "offsets_flat.json";
const UPDATED = "updated";
const TEST_NAME = ".__finder_write_test";
const DOC_DIR = 9;
const USER_MASK = 1;
const MAX_LOG_BYTES = 1048576;
const CHUNK_SIZE = 1024 * 1024;
const MAX_XREF_HITS = 16;

const ANCHORS = {
  Stage_instance:                     ["Stage"],
  ResourceManager_getMovieClip:       ["getMovieClip"],
  GameButton_ctor:                    ["onButtonPressed"],
  MovieClip_getTextFieldByName:       ["getTextFieldByName"],
  MovieClip_gotoAndStopFrameIndex:    ["gotoAndStopFrameIndex"],
  MovieClip_setChildVisible:          ["setChildVisible"],
  Sprite_ctor:                        ["Sprite"],
  Sprite_addChild:                    ["addChild"],
  DropGUIContainer_ctor:              ["DropGUIContainer"],
  DisplayObject_setXY:                ["setXY"],
  TextField_setText:                  ["setText"],
  String_ctor:                        ["String not found:"],
  HomePage_ctor:                      ["HomePage"],
  GUI_closePopup:                     ["closePopup"],
  GUI_showFloaterTextAt:              ["showFloaterTextAt"]
};

let logPath = null;
let docsPath = null;
let updatedPath = null;
let gameModule = null;
let started = false;

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
  try { const f = new File(path, "r"); const t = f.readText(); f.close(); return t; } catch (e) { return null; }
}

function writeText(path, text) {
  try { const f = new File(path, "w"); f.write(text); f.flush(); f.close(); return true; } catch (e) { return false; }
}

function fileSize(path) {
  try { const f = new File(path, "r"); const b = f.readAllBytes(); f.close(); return b.length; } catch (e) { return -1; }
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
  let loose = null;
  for (let i = 0; i < candidates.length; i++) {
    const c = candidates[i];
    let docs = c.path;
    if (!/\/Documents$/.test(docs) && exists(docs + "/Documents")) docs = docs + "/Documents";
    if (!exists(docs)) continue;
    if (!writable(docs)) continue;
    if (loose === null) loose = docs;
    if (containerLike(docs)) return docs;
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

// -------------------------------------------------------------------------
// game module
// -------------------------------------------------------------------------

function skipModule(m) {
  const path = m.path || "";
  if (path.indexOf("/usr/lib/") === 0) return true;
  if (path.indexOf("/System/") === 0) return true;
  if (path.indexOf("/Developer/") === 0) return true;
  if (m.name === "LiveContainer") return true;
  if (m.name.indexOf("Frida") !== -1) return true;
  if (m.size < 1024 * 1024) return true;
  return false;
}

function findGameModule() {
  const modules = Process.enumerateModules();
  let best = null;
  const bundleId = (() => {
    try { return String(ObjC.classes.NSBundle.mainBundle().bundleIdentifier()).toLowerCase(); } catch (e) { return ""; }
  })();
  const needle = bundleId.replace(/\./g, "");

  for (let i = 0; i < modules.length; i++) {
    const m = modules[i];
    if (skipModule(m)) continue;
    const hay = ((m.name || "") + " " + (m.path || "")).toLowerCase().replace(/\./g, "");
    if (needle && hay.indexOf(needle) !== -1) {
      gameModule = m;
      log("game module matched by bundleId: " + m.name + " base=" + m.base + " size=" + m.size);
      return m;
    }
  }
  for (let i = 0; i < modules.length; i++) {
    const m = modules[i];
    if (skipModule(m)) continue;
    if (best === null || m.size > best.size) best = m;
  }
  if (best === null) best = Process.mainModule;
  gameModule = best;
  log("game module fallback (largest): " + best.name + " base=" + best.base + " size=" + best.size);
  return best;
}

function gameBase() {
  if (gameModule === null) findGameModule();
  return gameModule.base;
}

function gameRegions() {
  // только регионы, пересекающиеся с [base, base+size) game-модуля
  const mod = gameModule || findGameModule();
  const low = mod.base;
  const high = mod.base.add(mod.size);
  const lowNum = parseInt(low.toString(), 16);
  const highNum = parseInt(high.toString(), 16);

  const out = [];
  const seen = {};
  const modes = ["r--", "rw-", "r-x"];
  for (let i = 0; i < modes.length; i++) {
    let list = [];
    try { list = Process.enumerateRanges(modes[i]); } catch (e) { continue; }
    for (let r = 0; r < list.length; r++) {
      const range = list[r];
      const key = range.base.toString();
      if (seen[key] === true) continue;
      seen[key] = true;

      const startNum = parseInt(range.base.toString(), 16);
      const endNum = startNum + range.size;
      if (endNum <= lowNum || startNum >= highNum) continue;
      out.push(range);
    }
  }
  log("game regions for scan: " + out.length + " (of " + mod.size + " bytes module)");
  return out;
}

// -------------------------------------------------------------------------
// string scan
// -------------------------------------------------------------------------

function hexPattern(text) {
  if (!text) return null;
  const parts = [];
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i);
    if (c > 127) return null;
    parts.push(("0" + c.toString(16)).slice(-2));
  }
  return parts.join(" ");
}

function findStrings(needles, ranges) {
  const hits = [];
  const byAddr = {};

  for (let n = 0; n < needles.length; n++) {
    const pattern = hexPattern(needles[n]);
    if (pattern === null) {
      log("  anchor skipped (non-ascii): " + needles[n]);
      continue;
    }
    for (let r = 0; r < ranges.length; r++) {
      let matches = [];
      try {
        matches = Memory.scanSync(ranges[r].base, ranges[r].size, pattern);
      } catch (e) {
        continue;
      }
      for (let m = 0; m < matches.length; m++) {
        const a = matches[m].address;
        const key = a.toString();
        if (byAddr[key] === undefined) {
          byAddr[key] = { address: a, needles: [] };
          hits.push(byAddr[key]);
        }
        if (byAddr[key].needles.indexOf(needles[n]) === -1) byAddr[key].needles.push(needles[n]);
      }
    }
  }
  return hits;
}

// -------------------------------------------------------------------------
// xref scan (ADRP + ADD imm) — только по game-регионам с r-x
// -------------------------------------------------------------------------

function pageOf(addr) {
  return addr.and(ptr("0xFFFFFFFFFFFFF000"));
}

function findXrefs(targets, execRanges) {
  const map = {};
  for (let i = 0; i < targets.length; i++) {
    map[targets[i].address.toString()] = targets[i];
    targets[i].xrefs = [];
  }

  for (let r = 0; r < execRanges.length; r++) {
    const range = execRanges[r];
    let off = 0;
    while (off < range.size) {
      const take = Math.min(CHUNK_SIZE, range.size - off);
      let buf = null;
      try { buf = range.base.add(off).readByteArray(take); } catch (e) { break; }
      if (buf === null) break;
      const view = new DataView(buf);
      const count = Math.floor(take / 4);
      const regs = {};

      for (let i = 0; i < count; i++) {
        const insn = view.getUint32(i * 4, true);
        const insnAddr = range.base.add(off + i * 4);
        const family = (insn & 0x9f000000) >>> 0;

        if (family === 0x90000000) {
          let imm = (((insn >>> 5) & 0x7ffff) << 2) | ((insn >>> 29) & 3);
          if (imm & 0x100000) imm -= 0x200000;
          regs[insn & 0x1f] = pageOf(insnAddr).add(imm * 4096);
          continue;
        }
        if (family === 0x10000000) {
          let imm = (((insn >>> 5) & 0x7ffff) << 2) | ((insn >>> 29) & 3);
          if (imm & 0x100000) imm -= 0x200000;
          const tgt = insnAddr.add(imm);
          const hit = map[tgt.toString()];
          if (hit && hit.xrefs.length < MAX_XREF_HITS) hit.xrefs.push(insnAddr);
          continue;
        }
        if (((insn & 0xff800000) >>> 0) === 0x91000000) {
          const from = regs[(insn >>> 5) & 0x1f];
          if (from === undefined) continue;
          const shift = (insn >>> 22) & 3;
          const imm12 = (insn >>> 10) & 0xfff;
          const val = shift === 1 ? from.add(imm12 * 4096) : from.add(imm12);
          const hit = map[val.toString()];
          if (hit && hit.xrefs.length < MAX_XREF_HITS) hit.xrefs.push(insnAddr);
        }
      }
      off += take;
    }
  }
}

// -------------------------------------------------------------------------
// backend scan (экспорты/символы) — только в game-модуле
// -------------------------------------------------------------------------

function backendScan() {
  const names = Object.keys(ANCHORS);
  const result = {};
  const mod = gameModule || findGameModule();

  let exports = [];
  try { exports = Module.enumerateExports(mod.name); } catch (e) { exports = []; }
  log("exports in game module: " + exports.length);

  for (let e = 0; e < exports.length; e++) {
    const exp = exports[e];
    const n = exp.name || "";
    for (let k = 0; k < names.length; k++) {
      const key = names[k];
      const needles = ANCHORS[key];
      for (let j = 0; j < needles.length; j++) {
        if (n.indexOf(needles[j]) === -1) continue;
        if (result[key] === undefined) result[key] = [];
        const rva = exp.address.sub(mod.base);
        result[key].push({
          source: "export",
          name: n,
          rva: "0x" + rva.toString(16),
          abs: exp.address.toString()
        });
        break;
      }
    }
  }

  let syms = [];
  try { syms = Module.enumerateSymbols(mod.name); } catch (e) { syms = []; }
  log("symbols in game module: " + syms.length);

  for (let s = 0; s < syms.length; s++) {
    const sym = syms[s];
    const n = sym.name || "";
    for (let k = 0; k < names.length; k++) {
      const;
 key = names[k];
      const needles}

 = ANCHORS[key];
      for (functionlet j = 0; j < needles.length; j++) run {
        if() (n.indexOf(need {
les[j]) === -1 ) continue;
        if (result[key] === undefined) result[key] = [];
        const rva = sym.address.sub(mod.base);
        result[key].push({
          source: "symbol",
          name: n,
          rva: "0x" + rva.toString(16),
          abs: sym.address.toString()
        });
        break;
      }
    }
  }
  return result;
}

// -------------------------------------------------------------------------
// main
// -------------------------------------------------------------------------

function saveOffsets(result) {
  if (updatedPath === null) return null;
  const path = updatedPath + "/" + RESULT_NAME;
  if (writeText(path, JSON.stringify(result, null, 2) + "\n")) log("offsets written: " + path);

  const flat = {};
  const keys = Object.keys(result);
  for (let i = 0; i < keys.length; i++) {
    const key = keys[i];
    const e = result[key];
    if (e.candidates && e.candidates.length > 0) flat[key] = e.candidates[0].rva;
    else if (e.functions && e.functions.length > 0) flat[key] = e.functions[0].rva;
  }
  const flatPath = updatedPath + "/" + FLAT_NAME;
  if (writeText(flatPath, JSON.stringify(flat, null, 2) + "\n")) log("flat offsets written: " + flatPath);
  return flat log("=== offsets finder start ===");
  initPaths();

  try {
    const device = ObjC.classes.UIDevice.currentDevice();
    log("device=" + str(device.systemName()) + " " + str(device.systemVersion()) + " " + str(device.model()));
  } catch (e) {}
  log("frida=" + Frida.version + " runtime=" + Script.runtime + " arch=" + Process.arch);
  log("bundle=" + bundlePath());
  log("docs=" + str(docsPath));
  log("updated=" + str(updatedPath));

  const mod = findGameModule();
  log("game module: " + mod.name + " base=" + mod.base + " size=" + mod.size);

  log("--- backend scan (exports/symbols) ---");
  let backendHits = {};
  try { backendHits = backendScan(); } catch (e) { log("backend scan error: " + e.message); }
  const backendKeys = Object.keys(backendHits);
  for (let i = 0; i < backendKeys.length; i++) {
    const k = backendKeys[i];
    log("backend " + k + ": " + backendHits[k].length + " hits");
    for (let j = 0; j < Math.min(3, backendHits[k].length); j++) {
      const h = backendHits[k][j];
      log("  " + h.source + " " + h.name + " rva=" + h.rva);
    }
  }

  log("--- string scan (needles + xref) ---");
  const ranges = gameRegions();
  if (ranges.length === 0) {
    log("no game regions found, abort string scan");
  } else {
    const names = Object.keys(ANCHORS);
    const stringsByKey = {};
    const allStrings = [];

    for (let i = 0; i < names.length; i++) {
      const key = names[i];
      log("scan " + key);
      let hits = [];
      try { hits = findStrings(ANCHORS[key], ranges); } catch (e) { log("  error: " + e.message); }
      log("  hits: " + hits.length);
      stringsByKey[key] = hits;
      for (let j = 0; j < hits.length; j++) allStrings.push(hits[j]);
    }
    log("total string hits: " + allStrings.length);

    if (allStrings.length > 0) {
      log("scanning xrefs...");
      const execRanges = ranges.filter(function (r) { return r.protection.indexOf("x") !== -1; });
      log("exec ranges: " + execRanges.length);
      try { findXrefs(allStrings, execRanges); } catch (e) { log("xref error: " + e.message); }
      log("xref done");
    }

    // собираем результат
    const result = {};
    for (let i = 0; i < names.length; i++) {
      const key = names[i];
      const strings = stringsByKey[key] || [];
      const funcs = [];
      const seenRva = {};
      const base = gameBase();
      for (let j = 0; j < strings.length; j++) {
        const xrefs = strings[j].xrefs || [];
        for (let x = 0; x < xrefs.length; x++) {
          const rva = xrefs[x].sub(base);
          const rvaStr = "0x" + rva.toString(16);
          if (seenRva[rvaStr] === true) continue;
          seenRva[rvaStr] = true;
          funcs.push({
            needle: strings[j].needles[0],
            string: strings[j].address.toString(),
            xref: xrefs[x].toString(),
            rva: rvaStr
          });
        }
      }
      result[key] = {
        candidates: backendHits[key] || [],
        functions: funcs,
        strings: strings.map(function (s) {
          return { address: s.address.toString(), needles: s.needles };
        })
      };
    }

    log("--- summary ---");
    for (let i = 0; i < names.length; i++) {
      const key = names[i];
      const e = result[key];
      log(key + ": candidates=" + e.candidates.length + " xrefs=" + e.functions.length + " strings=" + e.strings.length);
      if (e.candidates.length > 0) log("  best(candidate) rva=" + e.candidates[0].rva + " (" + e.candidates[0].name + ")");
      if (e.functions.length > 0) log("  best(xref)     rva=" + e.functions[0].rva + " needle=" + e.functions[0].needle);
    }

    saveOffsets(result);
  }

  log("=== offsets finder done ===");
}

// -------------------------------------------------------------------------
// RPC
// -------------------------------------------------------------------------

rpc.exports = {
  init: function () { if (started) return true; started = true; setTimeout(run, 0); return true; },
  run: function () { run(); return true; },
  paths: function () {
    return { docs: docsPath, updated: updatedPath, log: logPath, bundle: bundlePath() };
  },
  module: function () {
    if (gameModule === null) findGameModule();
    return {
      name: gameModule.name,
      base: gameModule.base.toString(),
      size: gameModule.size,
      path: gameModule.path
    };
  },
  modules: function () {
    const out = [];
    const modules = Process.enumerateModules();
    for (let i = 0; i < modules.length; i++) {
      const m = modules[i];
      if ((m.path || "").indexOf("/usr/lib/") === 0) continue;
      if ((m.path || "").indexOf("/System/") === 0) continue;
      out.push({ name: m.name, base: m.base.toString(), size: m.size, path: m.path });
    }
    return out;
  },
  findExport: function (name) {
    const hits = [];
    const modules = Process.enumerateModules();
    for (let i = 0; i < modules.length; i++) {
      const m = modules[i];
      if (skipModule(m)) continue;
      let addr = null;
      try { addr = Module.findExportByName(m.name, name); } catch (e) {}
      if (addr === null) continue;
      hits.push({ module: m.name, abs: addr.toString(), rva: "0x" + addr.sub(m.base).toString(16) });
    }
    return hits;
  },
  symbols: function (pattern) {
    const out = [];
    const modules = Process.enumerateModules();
    for (let i = 0; i < modules.length; i++) {
      const m = modules[i];
      if (skipModule(m)) continue;
      if (m.size < 2 * 1024 * 1024) continue;
      let syms = [];
      try { syms = Module.enumerateSymbols(m.name); } catch (e) { continue; }
      for (let s = 0; s < syms.length; s++) {
        const sym = syms[s];
        if (pattern && (sym.name || "").indexOf(pattern) === -1) continue;
        out.push({
          module: m.name,
          name: sym.name,
          type: sym.type,
          abs: sym.address.toString(),
          rva: "0x" + sym.address.sub(m.base).toString(16)
        });
        if (out.length > 400) return out;
      }
    }
    return out;
  }
};

setTimeout(run, 0);