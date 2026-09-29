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

const forceTrue = new Set([]);
const forceFalse = new Set([]);

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

function findAllOccurrences(needle, limit) {
  const out = [];
  const ranges = Process.enumerateRanges("r--");
  for (let i = 0; i < ranges.length; i++) {
    const r = ranges[i];
    const inMod = r.base.compare(gameModule.base) >= 0 && r.base.compare(gameModule.base.add(gameModule.size)) < 0;
    if (!inMod) continue;
    try {
      const res = Memory.scanSync(r.base, r.size, needle);
      for (let j = 0; j < res.length && out.length < limit; j++) out.push(res[j].address);
    } catch (e) {}
  }
  return out;
}

// Найти все ADRP+ADD пары, чей конечный адрес равен target
function findXrefs(target, maxHits) {
  const hits = [];
  const modStart = gameModule.base;
  const modEnd = modStart.add(gameModule.size);
  const targetNum = target.toUInt32 ? parseInt(target.toString(), 16) : target;

  const ranges = Process.enumerateRanges("r-x");
  for (let i = 0; i < ranges.length; i++) {
    const r = ranges[i];
    if (r.base.compare(modStart) < 0) continue;
    if (r.base.compare(modEnd) >= 0) continue;

    const size = Math.min(r.size, modEnd.sub(r.base).toInt32());
    let offset = 0;
    const CHUNK = 1024 * 1024;
    while (offset < size && hits.length < maxHits) {
      const take = Math.min(CHUNK, size - offset);
      let buf = null;
      try { buf = r.base.add(offset).readByteArray(take); } catch (e) { offset += take; continue; }
      if (buf === null) { offset += take; continue; }
      const dv = new DataView(buf);
      const count = Math.floor(take / 4);
      const regs = {};
      const baseAddr = r.base.add(offset);
      for (let k = 0; k < count; k++) {
        const insn = dv.getUint32(k * 4, true);
        const addr = baseAddr.add(k * 4);

        const family = (insn & 0x9F000000) >>> 0;
        if (family === 0x90000000) {
          // ADRP
          const rd = insn & 0x1F;
          let imm = (((insn >>> 5) & 0x7FFFF) << 2) | ((insn >>> 29) & 3);
          if (imm & 0x100000) imm -= 0x200000;
          const pcPage = parseInt(addr.toString(), 16) & ~0xFFF;
          const page = pcPage + (imm * 4096);
          regs[rd] = page;
          continue;
        }

        if (((insn & 0xFF800000) >>> 0) === 0x91000000) {
          // ADD (immediate) 64-bit
          const rn = (insn >>> 5) & 0x1F;
          const rd = insn & 0x1F;
          const shift = (insn >>> 22) & 3;
          const imm12 = (insn >>> 10) & 0xFFF;
          if (shift === 0 || shift === 1) {
            const base = regs[rn];
            if (base !== undefined) {
              const value = base + (shift === 1 ? imm12 * 4096 : imm12);
              if (value === targetNum) {
                hits.push({ addr: addr, via: "add", value: value });
              }
            }
          }
          regs[rd] = undefined;
          continue;
        }

        // Сброс regs не делаем целиком, это эвристика — оставляем значения между парами,
        // что даёт ложные, но редкие срабатывания. Достаточно для нашей задачи.
      }
      offset += take;
    }
  }
  return hits;
}

function findFunctionStart(addr) {
  // Идём назад до пролога. Пролог ARM64:
  //   STP x29, x30, [sp, #-N]! = 0xA9B?7BFD (маска 0xFFC07FFF == 0xA9807BFD)
  //   PACIASP = 0xD503233F
  //   SUB sp, sp, #imm = 0xD10?03FF (маска 0xFF8003FF == 0xD10003FF)
  //   STP x19..., [sp, #-N]! = 0xA9B?7BFD с разными регистрами
  const MAX_BACK = 4096;
  let cur = addr;
  for (let i = 0; i < MAX_BACK / 4; i++) {
    let insn = null;
    try { insn = cur.readU32(); } catch (e) { break; }
    if ((insn & 0xFFC07FFF) === 0xA9807BFD) return cur;
    if (insn === 0xD503233F) return cur;
    if ((insn & 0xFF8003FF) === 0xD10003FF) return cur;
    if ((insn & 0xFFE07FFF) === 0xA9807BFD) return cur;
    cur = cur.sub(4);
  }
  return addr;
}

function installHook(addr) {
  log("installing hook @ " + addr + " (rva 0x" + addr.sub(gameModule.base).toString(16) + ")");
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

function run() {
  if (gameModule === null) findGameModule();
  log("module: " + gameModule.name + " base=" + gameModule.base + " size=" + gameModule.size);

  log("scanning for string " + ANCHOR_STRING);
  const strAddrs = findAllOccurrences(ANCHOR_STRING, 8);
  log("found " + strAddrs.length + " string occurrence(s)");
  if (strAddrs.length === 0) {
    log("anchor string not found, aborting");
    return;
  }

  let picked = null;
  for (let i = 0; i < strAddrs.length; i++) {
    log("string candidate " + i + ": " + strAddrs[i]);
    picked = strAddrs[i];
    break;
  }

  log("searching xrefs for " + picked + " (this may take 10-30s)");
  const xrefs = findXrefs(picked, 64);
  log("xrefs found: " + xrefs.length);

  if (xrefs.length === 0) {
    log("no direct ADRP+ADD xrefs. Probably chained fixups / literal pool. Aborting.");
    return;
  }

  const seen = {};
  const funcStarts = [];
  for (let i = 0; i < xrefs.length; i++) {
    const hit = xrefs[i];
    const start = findFunctionStart(hit.addr);
    const key = start.toString();
    if (seen[key]) continue;
    seen[key] = true;
    funcStarts.push({ start: start, hit: hit.addr });
    log("xref#" + i + " hit=" + hit.addr + " (rva 0x" + hit.addr.sub(gameModule.base).toString(16) + ") -> func@ " + start + " (rva 0x" + start.sub(gameModule.base).toString(16) + ")");
  }

  if (funcStarts.length === 0) {
    log("no function starts resolved, aborting");
    return;
  }

  installHook(funcStarts[0].start);
}

setTimeout(run, 2000);

rpc.exports = {
  addr: function () { return getBoolAddr === null ? null : getBoolAddr.toString(); },
  force_true: function (name) { forceTrue.add(name); return Array.from(forceTrue); },
  force_false: function (name) { forceFalse.add(name); return Array.from(forceFalse); },
  list: function () { return { t: Array.from(forceTrue), f: Array.from(forceFalse) }; },
  logPath: function () { return logPath; }
};

log("=== debug_menu armed ===");