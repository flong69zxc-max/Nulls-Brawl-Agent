import ObjC from "frida-objc-bridge";

function log(msg) {
  var line = new Date().toISOString() + " " + msg;
  try { console.log(line); } catch (e) {}
  try {
    var home = ObjC.classes.NSHomeDirectory().toString();
    var path = home + "/Documents/frida_interceptor.log";
    var f = new File(path, "a");
    f.write(line + "\n");
    f.flush();
    f.close();
  } catch (e) {}
  try {
    var f2 = new File("/tmp/frida_interceptor.log", "a");
    f2.write(line + "\n");
    f2.flush();
    f2.close();
  } catch (e) {}
}

log("=== interceptor test start ===");
log("frida=" + Frida.version);
log("runtime=" + Script.runtime);
log("arch=" + Process.arch);
log("pid=" + Process.id);

function getExport(name) {
  try {
    if (Module.getGlobalExportByName) return Module.getGlobalExportByName(name);
  } catch (e) {}
  try {
    if (Module.findGlobalExportByName) return Module.findGlobalExportByName(name);
  } catch (e) {}
  try {
    var libc = Process.getModuleByName("libSystem.B.dylib");
    return libc.getExportByName(name);
  } catch (e) {}
  return null;
}

function attachExport(name, onEnter) {
  var addr = getExport(name);
  if (addr === null) {
    log("attach " + name + " FAILED: export not found");
    return false;
  }
  try {
    Interceptor.attach(addr, { onEnter: onEnter });
    log("attached " + name + " @ " + addr);
    return true;
  } catch (e) {
    log("attach " + name + " FAILED: " + e.message);
    return false;
  }
}

var openCount = 0;
attachExport("open", function (args) {
  openCount++;
  if (openCount <= 20) {
    try {
      var p = args[0].readUtf8String();
      if (p !== null && p.length > 0) log("[open] " + p);
    } catch (e) {}
  }
});

var fopenCount = 0;
attachExport("fopen", function (args) {
  fopenCount++;
  if (fopenCount <= 10) {
    try {
      var p = args[0].readUtf8String();
      if (p !== null && p.length > 0) log("[fopen] " + p);
    } catch (e) {}
  }
});

try {
  var UIApplication = ObjC.classes.UIApplication;
  var method = UIApplication["- openURL:options:completionHandler:"];
  if (method) {
    Interceptor.attach(method.implementation, {
      onEnter: function (args) {
        try {
          var url = new ObjC.Object(args[2]).toString();
          log("[UIApplication openURL] " + url);
        } catch (e) {
          log("[UIApplication openURL] (parse fail)");
        }
      }
    });
    log("attached UIApplication openURL");
  } else {
    log("UIApplication openURL method not found");
  }
} catch (e) {
  log("objc attach failed: " + e.message);
}

try {
  var NSString = ObjC.classes.NSString;
  var m = NSString["+ stringWithUTF8String:"];
  if (m) {
    Interceptor.attach(m.implementation, {
      onEnter: function (args) {
        try {
          var s = args[2].readUtf8String();
          if (s !== null && s.length > 3 && s.length < 60) log("[NSString] " + s);
        } catch (e) {}
      }
    });
    log("attached NSString stringWithUTF8String:");
  }
} catch (e) {
  log("NSString attach failed: " + e.message);
}

setTimeout(function () {
  log("timer 5s - hooks alive, openCount=" + openCount + " fopenCount=" + fopenCount);
}, 5000);

setTimeout(function () {
  log("timer 15s - hooks alive, openCount=" + openCount + " fopenCount=" + fopenCount);
}, 15000);

setTimeout(function () {
  try {
    ObjC.schedule(ObjC.mainQueue, function () {
      try {
        var alert = ObjC.classes.UIAlertController.alertControllerWithTitle_message_preferredStyle_(
          "Frida", "Interceptor works! v" + Frida.version, 1
        );
        alert.addAction_(ObjC.classes.UIAlertAction.actionWithTitle_style_handler_("OK", 0, null));
        var windows = ObjC.classes.UIApplication.sharedApplication().windows();
        var root = null;
        for (var i = 0; i < windows.count(); i++) {
          var w = windows.objectAtIndex_(i);
          if (w.isKeyWindow()) { root = w.rootViewController(); break; }
        }
        if (root !== null) {
          while (root.presentedViewController() !== null) root = root.presentedViewController();
          root.presentViewController_animated_completion_(alert, true, null);
          log("alert shown");
        } else {
          log("alert skipped: no key window");
        }
      } catch (e) {
        log("alert FAIL: " + e.message);
      }
    });
  } catch (e) {
    log("ObjC.schedule FAIL: " + e.message);
  }
}, 8000);

rpc.exports = {
  ping: function () { return "pong"; },
  openCount: function () { return openCount; },
  fopenCount: function () { return fopenCount; }
};

log("=== interceptor test armed ===");