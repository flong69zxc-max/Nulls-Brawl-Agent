'use strict';

var LOG_PATH = '/tmp/agent.log';
var TARGET_RVA = 0xb24998;

function log(msg) {
    var line = new Date().toISOString() + ' ' + msg;
    try { console.log(line); } catch (e) {}
    try {
        var f = new File(LOG_PATH, 'a');
        f.write(line + '\n');
        f.flush();
        f.close();
    } catch (e) {}
}

log('=== agent start ===');

function findTargetModule() {
    var mods = Process.enumerateModules();
    for (var i = 0; i < mods.length; i++) {
        var p = mods[i].path || '';
        if (p.indexOf('/NB.app/') !== -1 && p.indexOf('/Frameworks/') === -1) {
            return mods[i];
        }
    }
    for (var j = 0; j < mods.length; j++) {
        if (/nulls/i.test(mods[j].name || '')) {
            return mods[j];
        }
    }
    return null;
}

var target = findTargetModule();
if (target === null) {
    log('target module not found, abort');
} else {
    var addr = target.base.add(TARGET_RVA);
    log('target module: ' + target.name + ' base: ' + target.base + ' addr: ' + addr);

    var range = Process.findRangeByAddress(addr);
    if (range === null) {
        log('addr not mapped, abort');
    } else {
        log('range: ' + range.protection);
        try {
            var patch = [0x20, 0x00, 0x80, 0x52, 0xC0, 0x03, 0x5F, 0xD6];
            Memory.patchCode(addr, patch.length, function (code) {
                for (var i = 0; i < patch.length; i++) {
                    code.add(i).writeU8(patch[i]);
                }
            });
            log('patch applied successfully');
        } catch (e) {
            log('patch failed: ' + e.message);
        }
    }
}

log('=== agent armed ===');