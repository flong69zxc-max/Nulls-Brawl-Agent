'use strict';

import ObjC from 'frida-objc-bridge';

const FILE_BASE = 0x100000000;
const TEXT_LO   = 0x100004000;
const TEXT_HI   = 0x100D8AF60;
const DATA_LO   = 0x100F74000;
const DATA_HI   = 0x101170000;

const KNOWN = {
    'NativeFont::formatString':                      0x00b3fde8,
    'MessageManager::receiveMessage':                0x0075cce0,
    'LogicDataTables::initDataTable':                0x009a8f3c,
    'LogicProjectileData::getIntValueFromColumn':    0x009cb098,
    'Stage::setViewport':                            0x00ba17b8,
    'GameButton::ctor':                              0x005425b0,
    'HomePage::ctor':                                0x0086eb80,
    'Character::ctor':                               0x009e3100,
    'MessageManager::ctor':                          0x0075bb1c,
    'MovieClip::ctor':                               0x00b5f028,
    'NativeFont::ctor':                              0x00b3ec50,
    'Stage::ctor':                                   0x00b9ee6c,
};

const VTABLES = {
    'GameButton':          0x00f9b0f8,
    'HomePage':            0x00fe4008,
    'Character':           0x00ff45c0,
    'LogicDataTables':     0x00ff2478,
    'LogicProjectileData': 0x00ff3aa0,
    'MessageManager':      0x00fd57e8,
    'MovieClip':           0x01006150,
    'NativeFont':          0x01005858,
    'Stage':               0x010091b0,
};

const LOG_LIMIT        = 10;
const MAX_SLOT_DUMPS   = 128;
const RUNTIME_HOOK_ALL = true;
const LOG_FILE_NAME    = 'FRIDA_TRACE.txt';

let gBase       = null;
let gSlide      = null;
let gLogPath    = null;
let gLogBuf     = [];
let gStarted    = false;
let gLastFlush  = 0;
let gCallCounts = {};
let gHooks      = {};

function OXTs() {
    const d = new Date();
    const pad = (n, w) => String(n).padStart(w, '0');
    return d.getFullYear() + '-' + pad(d.getMonth() + 1, 2) + '-' + pad(d.getDate(), 2) +
        ' ' + pad(d.getHours(), 2) + ':' + pad(d.getMinutes(), 2) + ':' +
        pad(d.getSeconds(), 2) + '.' + pad(d.getMilliseconds(), 3);
}

function objcReady() {
    try {
        return typeof ObjC !== 'undefined' && ObjC && ObjC.classes && ObjC.classes.NSFileManager;
    } catch (e) {
        return false;
    }
}

function nsString(str) {
    return ObjC.classes.NSString.stringWithString_(str);
}

function resolveDocumentsPath() {
    try {
        const fn = new NativeFunction(
            Module.findExportByName(null, 'NSSearchPathForDirectoriesInDomains'),
            'pointer', ['uint', 'uint', 'bool']
        );
        const arr = new ObjC.Object(fn(9, 1, 1));
        if (arr.count() > 0) {
            return arr.objectAtIndex_(0).toString();
        }
    } catch (e) {}

    try {
        const bundlePath = ObjC.classes.NSBundle.mainBundle().bundlePath().toString();
        if (bundlePath) return bundlePath + '/Documents';
    } catch (e) {}

    try {
        const fn = new NativeFunction(
            Module.findExportByName(null, 'NSHomeDirectory'),
            'pointer', []
        );
        const home = new ObjC.Object(fn()).toString();
        if (home) return home + '/Documents';
    } catch (e) {}

    return null;
}

function openLog() {
    if (!objcReady()) return false;
    const docs = resolveDocumentsPath();
    if (!docs) return false;

    gLogPath = docs + '/' + LOG_FILE_NAME;

    try {
        const fileManager = ObjC.classes.NSFileManager.defaultManager();
        const dirPath = nsString(docs);
        if (!fileManager.fileExistsAtPath_(dirPath)) {
            fileManager.createDirectoryAtPath_withIntermediateDirectories_attributes_error_(
                dirPath, true, null, null
            );
        }
        nsString('').writeToFile_atomically_encoding_error_(
            nsString(gLogPath), true, 4 /* NSUTF8StringEncoding */, null
        );
        return true;
    } catch (e) {
        console.log('[!] cannot init log: ' + e);
        return false;
    }
}

function LOG(line) {
    const msg = '[' + OXTs() + '] ' + line;
    console.log(msg);

    if (!gLogPath) return;

    gLogBuf.push(msg);
    const now = Date.now();
    const doFlush = gLogBuf.length >= 16 || (now - gLastFlush) > 1000;
    if (doFlush) OXFlush();
}

function OXFlush() {
    if (!gLogPath || gLogBuf.length === 0) return;
    const chunk = gLogBuf.join('\n') + '\n';
    gLogBuf = [];

    try {
        const fileManager = ObjC.classes.NSFileManager.defaultManager();
        const path = nsString(gLogPath);
        if (!fileManager.fileExistsAtPath_(path)) {
            nsString(chunk).writeToFile_atomically_encoding_error_(
                path, true, 4, null
            );
        } else {
            const handle = ObjC.classes.NSFileHandle.fileHandleForWritingAtPath_(path);
            if (!handle) {
                nsString(chunk).writeToFile_atomically_encoding_error_(
                    path, true, 4, null
                );
            } else {
                handle.seekToEndOfFile();
                const data = nsString(chunk).dataUsingEncoding_(4);
                handle.writeData_(data);
                handle.closeFile();
            }
        }
        gLastFlush = Date.now();
    } catch (e) {
        console.log('[!] flush err: ' + e);
    }
}

function readPtr(addr) {
    try { return addr.readPointer(); } catch (e) { return ptr('0'); }
}

function fileOffset(runtimePtr) {
    if (!runtimePtr || runtimePtr.isNull()) return 0;
    return parseInt(runtimePtr.toString(), 16) - gSlide - FILE_BASE;
}

function moduleByBasename(basename) {
    const mods = Process.enumerateModules();
    for (let i = 0; i < mods.length; i++) {
        const m = mods[i];
        const name = m.name;
        if (name === basename || name.endsWith('/' + basename)) return m;
    }
    return null;
}

function findMainBinary() {
    const candidates = ['Nulls Brawl', 'NullsBrawl', 'brawl', 'Brawl'];
    for (let i = 0; i < candidates.length; i++) {
        const m = moduleByBasename(candidates[i]);
        if (m) return m;
    }

    const mods = Process.enumerateModules();
    let best = null;
    for (let i = 0; i < mods.length; i++) {
        const m = mods[i];
        const p = m.path || '';
        if (p.indexOf('.app/') !== -1 &&
            p.indexOf('.framework') === -1 &&
            p.indexOf('.dylib') === -1 &&
            p.indexOf('.bundle') === -1) {
            if (!best || m.size > best.size) best = m;
        }
    }
    return best;
}

function installHook(name, fileOff, onEnterFn) {
    if (!gBase) return false;
    const target = gBase.add(fileOff);
    try {
        Interceptor.attach(target, {
            onEnter: function (args) {
                if (onEnterFn) onEnterFn(args, this);
            }
        });
        gHooks[name] = { target: target, offset: fileOff };
        LOG('HOOK OK  ' + name + '  file=0x' + fileOff.toString(16) + '  rt=' + target);
        return true;
    } catch (e) {
        LOG('HOOK FAIL ' + name + '  file=0x' + fileOff.toString(16) + '  err=' + e);
        return false;
    }
}

function shouldLog(name) {
    if (!gCallCounts[name]) gCallCounts[name] = 0;
    gCallCounts[name]++;
    return gCallCounts[name] <= LOG_LIMIT;
}

function installAllKnownHooks() {
    LOG('=== INSTALLING KNOWN HOOKS ===');

    installHook('GameButton::ctor', KNOWN['GameButton::ctor'], (args) => {
        if (!shouldLog('GameButton::ctor')) return;
        const self = args[0];
        const vt = readPtr(self);
        LOG('BRK GameButton::ctor #' + gCallCounts['GameButton::ctor'] +
            ' self=' + self + ' vt=' + vt + ' file=0x' + fileOffset(vt).toString(16));
    });

    installHook('HomePage::ctor', KNOWN['HomePage::ctor'], (args) => {
        if (!shouldLog('HomePage::ctor')) return;
        const self = args[0];
        const vt = readPtr(self);
        LOG('BRK HomePage::ctor #' + gCallCounts['HomePage::ctor'] +
            ' self=' + self + ' vt=' + vt + ' file=0x' + fileOffset(vt).toString(16));
    });

    installHook('Character::ctor', KNOWN['Character::ctor'], (args) => {
        if (!shouldLog('Character::ctor')) return;
        const self = args[0];
        const vt = readPtr(self);
        LOG('BRK Character::ctor #' + gCallCounts['Character::ctor'] +
            ' self=' + self + ' vt=' + vt + ' file=0x' + fileOffset(vt).toString(16));
    });

    installHook('MessageManager::receiveMessage', KNOWN['MessageManager::receiveMessage'], (args) => {
        if (!shouldLog('MessageManager::receiveMessage')) return;
        LOG('BRK MessageManager::receiveMessage #' + gCallCounts['MessageManager::receiveMessage'] +
            ' self=' + args[0] + ' msg=' + args[1]);
    });

    installHook('NativeFont::formatString', KNOWN['NativeFont::formatString'], (args) => {
        if (!shouldLog('NativeFont::formatString')) return;
        LOG('BRK NativeFont::formatString #' + gCallCounts['NativeFont::formatString'] +
            ' self=' + args[0] + ' str=' + args[1]);
    });

    installHook('LogicDataTables::initDataTable', KNOWN['LogicDataTables::initDataTable'], (args) => {
        if (!shouldLog('LogicDataTables::initDataTable')) return;
        LOG('BRK LogicDataTables::initDataTable #' + gCallCounts['LogicDataTables::initDataTable'] +
            ' self=' + args[0] + ' a=' + args[1]);
    });

    installHook('Stage::setViewport', KNOWN['Stage::setViewport'], (args) => {
        if (!shouldLog('Stage::setViewport')) return;
        LOG('BRK Stage::setViewport #' + gCallCounts['Stage::setViewport'] + ' self=' + args[0]);
    });

    installHook('MessageManager::ctor', KNOWN['MessageManager::ctor'], (args) => {
        if (!shouldLog('MessageManager::ctor')) return;
        const self = args[0];
        const vt = readPtr(self);
        LOG('BRK MessageManager::ctor #' + gCallCounts['MessageManager::ctor'] +
            ' self=' + self + ' vt=' + vt + ' file=0x' + fileOffset(vt).toString(16));
    });

    installHook('MovieClip::ctor', KNOWN['MovieClip::ctor'], (args) => {
        if (!shouldLog('MovieClip::ctor')) return;
        const self = args[0];
        const vt = readPtr(self);
        LOG('BRK MovieClip::ctor #' + gCallCounts['MovieClip::ctor'] +
            ' self=' + self + ' vt=' + vt + ' file=0x' + fileOffset(vt).toString(16));
    });

    installHook('NativeFont::ctor', KNOWN['NativeFont::ctor'], (args) => {
        if (!shouldLog('NativeFont::ctor')) return;
        const self = args[0];
        const vt = readPtr(self);
        LOG('BRK NativeFont::ctor #' + gCallCounts['NativeFont::ctor'] +
            ' self=' + self + ' vt=' + vt + ' file=0x' + fileOffset(vt).toString(16));
    });

    installHook('Stage::ctor', KNOWN['Stage::ctor'], (args) => {
        if (!shouldLog('Stage::ctor')) return;
        const self = args[0];
        const vt = readPtr(self);
        LOG('BRK Stage::ctor #' + gCallCounts['Stage::ctor'] +
            ' self=' + self + ' vt=' + vt + ' file=0x' + fileOffset(vt).toString(16));
    });
}

function dumpVtable(clsName, vtFileOffset) {
    const vt = gBase.add(vtFileOffset);
    LOG('=== VT ' + clsName + ' file=0x' + vtFileOffset.toString(16) + ' rt=' + vt + ' ===');

    for (let i = 0; i < MAX_SLOT_DUMPS; i++) {
        let raw;
        try { raw = vt.add(i * 8).readPointer(); } catch (e) { break; }
        if (!raw || raw.isNull()) break;

        const fnFile = fileOffset(raw);
        if (fnFile < TEXT_LO || fnFile >= TEXT_HI) break;

        LOG('  [' + String(i).padStart(3, ' ') + '] file=0x' +
            fnFile.toString(16) + '  rt=' + raw);
    }
}

function dumpAllVtables() {
    LOG('=== DUMPING ALL KNOWN VTABLES ===');
    const keys = Object.keys(VTABLES);
    for (let i = 0; i < keys.length; i++) {
        dumpVtable(keys[i], VTABLES[keys[i]]);
    }
}

function scanDataForVtableRuns() {
    LOG('=== SCANNING DATA FOR VTABLE RUNS ===');
    const CHUNK = 0x10000;
    let runLen = 0;
    let runStart = 0;
    let prevSlot = 0;
    let totalRuns = 0;

    try {
        for (let off = 0; off < (DATA_HI - DATA_LO); off += CHUNK) {
            const chunkSize = Math.min(CHUNK, DATA_HI - DATA_LO - off);
            const fileAddr = DATA_LO + off;
            const rtAddr = gBase.add(fileAddr);
            const n = Math.floor(chunkSize / 8);

            for (let i = 0; i < n; i++) {
                const slotFile = fileAddr + i * 8;
                let raw = null;
                try { raw = rtAddr.add(i * 8).readPointer(); } catch (e) {}

                if (!raw || raw.isNull()) {
                    if (runLen >= 4) {
                        totalRuns++;
                        LOG('VT 0x' + runStart.toString(16) + ' slots=' + runLen);
                    }
                    runLen = 0;
                    continue;
                }
                const fnFile = fileOffset(raw);
                const valid = (fnFile >= TEXT_LO && fnFile < TEXT_HI);
                if (valid) {
                    if (runLen === 0) { runStart = slotFile; runLen = 1; }
                    else if (slotFile === prevSlot + 8) { runLen++; }
                    else {
                        if (runLen >= 4) {
                            totalRuns++;
                            LOG('VT 0x' + runStart.toString(16) + ' slots=' + runLen);
                        }
                        runStart = slotFile; runLen = 1;
                    }
                    prevSlot = slotFile;
                } else {
                    if (runLen >= 4) {
                        totalRuns++;
                        LOG('VT 0x' + runStart.toString(16) + ' slots=' + runLen);
                    }
                    runLen = 0;
                }
            }
        }
        if (runLen >= 4) {
            totalRuns++;
            LOG('VT 0x' + runStart.toString(16) + ' slots=' + runLen);
        }
    } catch (e) {
        LOG('scan err: ' + e);
    }
    LOG('total vtable-like runs: ' + totalRuns);
}

function scanAdrpAddMap() {
    LOG('=== SCANNING .text FOR adrp+add ===');
    const map = {};
    const CHUNK = 0x100000;

    for (let off = 0; off < (TEXT_HI - TEXT_LO); off += CHUNK) {
        const chunkSize = Math.min(CHUNK, TEXT_HI - TEXT_LO - off);
        const fileAddr = TEXT_LO + off;
        const rtAddr = gBase.add(fileAddr);

        let buf;
        try { buf = rtAddr.readByteArray(chunkSize); } catch (e) { break; }
        if (!buf) break;

        const dv = new DataView(buf);
        const words = Math.floor(chunkSize / 4);
        let prevPc = 0, prevRd = 0, prevPage = 0;

        for (let i = 0; i < words; i++) {
            const pcFile = fileAddr + i * 4;
            const w = dv.getUint32(i * 4, true);

            if ((w & 0x9F000000) === 0x90000000) {
                prevPc = pcFile;
                prevRd = w & 0x1F;
                const immlo = (w >>> 29) & 3;
                const immhi = (w >>> 5) & 0x7FFFF;
                let imm = (immhi << 2) | immlo;
                if (imm & (1 << 20)) imm -= (1 << 21);
                prevPage = (pcFile & ~0xFFF) + (imm << 12);
                continue;
            }

            if (prevPc && (w & 0xFF800000) === 0x91000000) {
                const rd = w & 0x1F;
                const rn = (w >>> 5) & 0x1F;
                let imm12 = (w >>> 10) & 0xFFF;
                const sh = (w >>> 22) & 1;
                if (sh) imm12 <<= 12;
                if (rd === prevRd && rn === prevRd) {
                    const target = prevPage + imm12;
                    if (target >= FILE_BASE && target < DATA_HI + 0x100000) {
                        if (!map[target]) map[target] = [];
                        if (map[target].length < 16) map[target].push(prevPc);
                    }
                }
            }
            prevPc = 0;
        }
    }

    LOG('adrp+add map entries: ' + Object.keys(map).length);
    return map;
}

function findCtorsViaAdrpMap(adrpMap) {
    LOG('=== FINDING CTORS VIA adrp+add ===');
    const keys = Object.keys(VTABLES);
    for (let i = 0; i < keys.length; i++) {
        const cls = keys[i];
        const vtFile = VTABLES[cls];
        const refs = adrpMap[vtFile];
        if (!refs || refs.length === 0) {
            LOG('  ' + cls + ': no xrefs to vtable');
            continue;
        }
        LOG('  ' + cls + ': ' + refs.length + ' xref(s) to vtable 0x' + vtFile.toString(16));
        for (let j = 0; j < refs.length; j++) {
            LOG('    ctor candidate @ file=0x' + refs[j].toString(16) +
                '  rt=' + gBase.add(refs[j]));
        }
    }
}

function main() {
    if (gStarted) { LOG('already started'); return; }
    gStarted = true;

    const logReady = openLog();
    LOG('=== FRIDA TRACE v1 ===');
    LOG('objcReady = ' + objcReady());
    LOG('logPath   = ' + (gLogPath || '(null)'));
    LOG('logReady  = ' + logReady);

    const mainBin = findMainBinary();
    if (!mainBin) {
        LOG('FATAL: cannot locate main binary');
        OXFlush();
        return;
    }

    gBase = mainBin.base;
    gSlide = parseInt(gBase.toString(), 16) - FILE_BASE;

    LOG('main  = ' + mainBin.name);
    LOG('path  = ' + mainBin.path);
    LOG('base  = ' + gBase);
    LOG('slide = 0x' + gSlide.toString(16));
    LOG('');

    if (RUNTIME_HOOK_ALL) {
        installAllKnownHooks();
        LOG('');
    }

    dumpAllVtables();
    LOG('');

    const adrpMap = scanAdrpAddMap();
    LOG('');

    findCtorsViaAdrpMap(adrpMap);
    LOG('');

    scanDataForVtableRuns();
    LOG('');

    LOG('=== TRACE READY ===');
    OXFlush();

    setInterval(OXFlush, 3000);
}

function waitAndStart() {
    let tries = 0;
    function attempt() {
        tries++;
        if (objcReady()) {
            main();
            return;
        }
        if (tries > 60) {
            console.log('[!] ObjC never became ready, giving up');
            return;
        }
        setTimeout(attempt, 500);
    }
    attempt();
}

if (typeof rpc !== 'undefined' && rpc) {
    rpc.exports = {
        start: function () { waitAndStart(); },
        dump: function () { dumpAllVtables(); OXFlush(); },
    };
}

setTimeout(waitAndStart, 2000);