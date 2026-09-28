'use strict';

function log(msg) {
    try { console.log(msg); } catch (e) {}
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
        if (!root) throw new Error('no key window');

        while (root.presentedViewController()) {
            root = root.presentedViewController();
        }
        root.presentViewController_animated_completion_(alert, 1, NULL);

        log('[+] alert shown: ' + title + ' / ' + message);
        return true;
    } catch (e) {
        log('[!] alert FAIL: ' + e.message);
        return false;
    }
}

function tick() {
    log('=== tick ===');
    var ok = showAlert('Frida', 'успешно');
    if (!ok) {
        try {
            var f = new File('/tmp/frida_ok.txt', 'w');
            f.write('успешно ' + new Date().toISOString());
            f.flush();
            f.close();
        } catch (e) {}
    }
}

setTimeout(tick, 4000);