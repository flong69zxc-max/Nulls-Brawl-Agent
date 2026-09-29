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
let targetModule = null;
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
  if (m.name === "LiveContainerShared") return true;
  if (m.name.indexOf("Frida") !== -1) return true;
  if (m.name === "Nulls Brawl") return true;
  if (m.size < 512 * 1024) return true;
  return false;
}

function findScidModule() {
  const mods = Process.enumerateModules();
  // Приоритет: Scid
  for (let i = 0; i < mods.length; i++) {
    const m = mods[i];
    if (m.name === "Scid" || (m.path && m.path.indexOf("/Scid.framework/") !== -1)) {
      log("scid module: " + m.name + " base=" + m.base + " size=" + m.size);
      return m;
    }
  }
  // Fallback: любой сторонний модуль > 512 KB кроме основных
  for (let i = 0; i < mods.length; i++) {
    const m = mods[i];
    if (skipModule(m)) continue;
    const hay = ((m.name || "") + " " + (m.path || "")).toLowerCase();
    if (hay.indexOf("nb.app") !== -1 || hay.indexOf("nulls") !== -1) {
      if (m.name === "Nulls Brawl") continue;
    }
    log("fallback module: " + m.name + " base=" + m.base + " size=" + m.size);
    return m;
  }
  return null;
}

function findAllOccurrencesInModule(mod, needle, limit) {
  const out = [];
  const ranges = Process.enumerateRanges("r--");
  for (let i = 0; i < ranges.length; i++) {
    const r = ranges[i];
    if (r.base.compare(mod.base) < 0) continue;
    if (r.base.compare(mod.base.add(mod.size)) >= 0) continue;
    try {
      const res = Memory.scanSync(r.base, r.size, needle);
      for (let j = 0; j < res.length && out.length < limit; j++) out.push(res[j].address);
    } catch (e) {}
  }
  return out;
}

// Поиск xref-ов: сканирует r-x секции модуля, ищет ADRP+ADD и ADRP+LDR,
// которые приводят к адресу target
function findXrefs(mod, target, maxHits) {
  const hits = [];
  const modStart = mod.base;
  const modEnd = mod.base.add(mod.size);
  const targetNum = parseInt(target.toString(), 16);

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

        // ADRP
        const family = (insn & 0x9F000000) >>> 0;
        if (family === 0x90000000) {
          const rd = insn & 0x1F;
          let imm = (((insn >>> 5) & 0x7FFFF) << 2) | ((insn >>> 29) & 3);
          if (imm & 0x100000) imm -= 0x200000;
          const pcPage = parseInt(addr.toString(), 16) & ~0xFFF;
          regs[rd] = pcPage + imm * 4096;
          continue;
        }

        // ADD (immediate) 64-bit
        if (((insn & 0xFF800000) >>> 0) === 0x91000000) {
          const rn = (insn >>> 5) & 0x1F;
          const shift = (insn >>> 22) & 3;
          const imm12 = (insn >>> 10) & 0xFFF;
          if (shift === 0 || shift === 1) {
            const base = regs[rn];
            if (base !== undefined) {
              const value = base + (shift === 1 ? imm12 * 4096 : imm12);
              if (value === targetNum) {
                hits.push({ addr: addr, via: "add" });
              }
            }
          }
          continue;
        }

        // LDR (immediate) 64-bit unsigned offset, from literal pool
        // 0xF9400000 mask 0xFFC00000
        if (((insn & 0xFFC00000) >>> 0) === 0xF9400000) {
          const rn = (insn >>> 5) & 0x1F;
          const imm12 = ((insn >>> 10) & 0xFFF) * 8;
          const base = regs[rn];
          if (base !== undefined) {
            const poolAddr = base + imm12;
            let poolValue = null;
            try {
              const pv = ptr(poolAddr).readPointer();
              if (!pv.isNull()) poolValue = parseInt(pv.toString(), 16);
            } catch (e) {}
            if (poolValue !== null && poolValue === targetNum) {
              hits.push({ addr: addr, via: "ldr" });
            }
          }
          continue;
        }
      }
      offset += take;
    }
  }
  return hits;
}

function findFunctionStart(addr) {
  const MAX_BACK = 8192;
  let cur = addr;
  for (let i = 0; i < MAX_BACK / 4; i++) {
    let insn = null;
    try { insn = cur.readU32(); } catch (e) { break; }
    if ((insn & 0xFFC07FFF) === 0xA9807BFD) return cur;  // STP x29,x30,[sp,#-N]!
    if (insn === 0xD503233F) return cur;                  // PACIASP
    if ((insn & 0xFF8003FF) === 0xD10003FF) return cur;   // SUB sp,sp,#imm
    if ((insn & 0xFFE07FFF) === 0xA9807BFD) return cur;
    if (insn === 0x910003FD) return cur;                  // MOV x29,sp
    cur = cur.sub(4);
  }
  return addr;
}

function installHook(addr) {
  log("installing hook @ " + addr + " (rva 0x" + addr.sub(targetModule.base).toString(16) + ")");
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
  targetModule = findScidModule();
  if (targetModule === null) {
    log("Scid module not found, aborting");
    return;
  }

  log("scanning " + targetModule.name + " for string " + ANCHOR_STRING);
  const strAddrs = findAllOccurrencesInModule(targetModule, ANCHOR_STRING, 8);
  log("found " + strAddrs.length + " string occurrence(s)");

  if (strAddrs.length === 0) {
    // Расширенный поиск: все модули процесса
    log("not found in " + targetModule.name + ", scanning all modules...");
    const allMods = Process.enumerateModules();
    for (let i = 0; i < allMods.length; i++) {
      const m = allMods[i];
      if (skipModule(m)) continue;
      if (m.name === targetModule.name) continue;
      const hits = findAllOccurrencesInModule(m, ANCHOR_STRING, 4);
      if (hits.length > 0) {
        log("found in " + m.name + ": " + hits.length + " occurrence(s)");
        targetModule = m;
        for (let j = 0; j < hits.length; j++) log("  string@" + hits[j]);
        break;
      }
    }
    if (strAddrs.length === 0) {
      const recheck = findAllOccurrencesInModule(targetModule, ANCHOR_STRING, 8);
      if (recheck.length === 0) {
        log("anchor string NOT FOUND anywhere, aborting");
        return;
      }
      strAddrs.length = 0;
      for (let j = 0; j < recheck.length; j++) strAddrs.push(recheck[j]);
    }
  }

  const picked = strAddrs[0];
  log("picked string@" + picked);

  log("searching xrefs (ADRP+ADD and ADRP+LDR)");
  const xrefs = findXrefs(targetModule, picked, 64);
  log("xrefs found: " + xrefs.length);

  if (xrefs.length === 0) {
    log("no xrefs found, aborting");
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
    funcStarts.push({ start: start, hit: hit.addr, via: hit.via });
    log("xref#" + i + " hit=" + hit.addr + " via=" + hit.via + " rva=0x" + hit.addr.sub(targetModule.base).toString(16) + " -> func@ " + start + " rva=0x" + start.sub(targetModule.base).toString(16));
  }

  if (funcStarts.length === 0) {
    log("no function starts, aborting");
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