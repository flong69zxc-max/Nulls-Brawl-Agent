'use strict';

var BUNDLE = null;
try {
    BUNDLE = ObjC.classes.NSBundle.mainBundle().bundlePath().toString();
} catch (e) {}

var LOG = '/tmp/frida_agent.log';

function log(msg) {
    var line = new Date().toISOString() + ' ' + msg;
    try { console.log(line); } catch (e) {}
    try {
        var f = new File(LOG, 'a');
        f.write(line + '\n');
        f.flush();
        f.close();
    } catch (e) {}
}

log('=== agent start ===');
log('bundle=' + BUNDLE);

function tryLoadOriginal() {
    var candidates = [
        BUNDLE + '/updated/original_69_252.js',
        BUNDLE + '/updated/script_69_252.js.bak',
        BUNDLE + '/updated/nulls_bytecode.js'
    ];
    for (var i = 0; i < candidates.length; i++) {
        var p = candidates[i];
        if (!p) continue;
        try {
            var exists = false;
            try { var t = new File(p, 'r'); t.close(); exists = true; } catch (e) {}
            if (!exists) continue;
            log('found original: ' + p);

            if (typeof Script !== 'undefined' && typeof Script.load === 'function') {
                try {
                    Script.load(p);
                    log('original loaded via Script.load');
                    return true;
                } catch (e) {
                    log('Script.load failed: ' + e.message);
                }
            }

            var f = new File(p, 'rb');
            var bytes = f.readAllBytes();
            f.close();
            log('original size=' + bytes.length + ' bytes');

            try {
                var str = '';
                for (var k = 0; k < bytes.length; k++) {
                    str += String.fromCharCode(bytes[k] & 0xff);
                }
                var fn = new Function(str);
                fn();
                log('original evaluated as JS');
                return true;
            } catch (e) {
                log('eval failed (expected if bytecode): ' + e.message);
            }
        } catch (e) {
            log('candidate error: ' + e.message);
        }
    }
    log('original NOT loaded');
    return false;
}

var PATCHES = [
    { name: 'isDev', rva: 0xd93da0, value: 1 }
];

function applyPatches() {
    var mod;
    try {
        mod = Process.enumerateModules()[0];
    } catch (e) {
        log('enumModules fail: ' + e.message);
        return;
    }
    var base = mod.base;
    log('module=' + mod.name + ' base=' + base);

    for (var i = 0; i < PATCHES.length; i++) {
        var p = PATCHES[i];
        try {
            var addr = base.add(p.rva);
            Memory.protect(addr, 4, 'rw-');
            Memory.writeS8(addr, p.value);
            log('patched ' + p.name + ' @ ' + addr + ' = ' + Memory.readS8(addr));
        } catch (e) {
            log('patch ' + p.name + ' FAIL: ' + e.message);
        }
    }
}

function showAlert(title, message) {
    try {
        var UIAlertController = ObjC.classes.UIAlertController;
        var UIAlertAction = ObjC.classes.UIAlertAction;
        var UIApplication = ObjC.classes.UIApplication;

        var alert = UIAlertController.alertControllerWithTitle_message_preferredStyle_(
            title, message, 1
        );
        var ok = UIAlertAction.actionWithTitle_style_handler_('OK', 0, NULL);
        alert.addAction_(ok);

        var windows = UIApplication.sharedApplication().windows();
        var root = null;
        for (var i = 0; i < windows.count(); i++) {
            var w = windows.objectAtIndex_(i);
            if (w.isKeyWindow()) {
                root = w.rootViewController();
                break;
            }
        }
        if (!root) {
            log('alert skipped: no key window');
            return false;
        }
        while (root.presentedViewController()) {
            root = root.presentedViewController();
        }
        root.presentViewController_animated_completion_(alert, 1, NULL);
        log('alert shown: ' + title + ' / ' + message);
        return true;
    } catch (e) {
        log('alert FAIL: ' + e.message);
        return false;
    }
}

rpc.exports = {
    patch: function () { applyPatches(); return 'ok'; },
    alert: function (t, m) { return showAlert(t, m); }
};

tryLoadOriginal();

setTimeout(applyPatches, 3000);
setTimeout(applyPatches, 8000);
setTimeout(applyPatches, 15000);

setTimeout(function () {
    showAlert('Frida', 'успешно');
}, 5000);

log('=== agent armed ===');