import ObjC from "frida-objc-bridge";

const LOG_NAME = "agent.log";
const UPDATED = "updated";
const TEST_NAME = ".__agent_write_test";
const DOC_DIR = 9;
const USER_MASK = 1;

let logPath = null;
let docsPath = null;
let updatedPath = null;
let started = false;

function str(v) {
  try {
    return v === null || v === undefined ? null : v.toString();
  } catch (e) {
    return null;
  }
}

function log(line) {
  let text = "";
  try {
    text = new Date().toISOString() + " " + line;
  } catch (e) {
    text = "log " + line;
  }
  try {
    console.log(text);
  } catch (e) {}
  if (logPath === null) {
    return;
  }
  let f = null;
  try {
    f = new File(logPath, "a");
    f.write(text + "\n");
    f.flush();
    f.close();
    f = null;
  } catch (e) {
    if (f !== null) {
      try {
        f.close();
      } catch (e2) {}
    }
  }
}

function fileManager() {
  return ObjC.classes.NSFileManager.defaultManager();
}

function mkdir(path) {
  try {
    fileManager().createDirectoryAtPath_withIntermediateDirectories_attributes_error_(path, true, null, null);
    return true;
  } catch (e) {
    return false;
  }
}

function exists(path) {
  try {
    return fileManager().fileExistsAtPath_(path) === true;
  } catch (e) {
    return false;
  }
}

function readText(path) {
  try {
    const f = new File(path, "r");
    const text = f.readText();
    f.close();
    return text;
  } catch (e) {
    return null;
  }
}

function writeText(path, text) {
  try {
    const f = new File(path, "w");
    f.write(text);
    f.flush();
    f.close();
    return true;
  } catch (e) {
    return false;
  }
}

function writable(path) {
  if (!path) {
    return false;
  }
  const test = path + "/" + TEST_NAME;
  const payload = "probe-" + Date.now();
  if (!writeText(test, payload)) {
    return false;
  }
  if (readText(test) !== payload) {
    try {
      fileManager().removeItemAtPath_error_(test, null);
    } catch (e) {}
    return false;
  }
  try {
    fileManager().removeItemAtPath_error_(test, null);
  } catch (e) {}
  return true;
}

function documentsDir() {
  const candidates = [];
  try {
    const bundle = str(ObjC.classes.NSBundle.mainBundle().bundlePath());
    if (bundle) {
      const m = /^(.*)\/Applications\/[^\/]+\.app\/?$/.exec(bundle);
      if (m) {
        candidates.push(m[1]);
      }
      const parts = bundle.replace(/\/+$/, "").split("/");
      if (parts.length >= 3) {
        candidates.push(parts.slice(0, -2).join("/"));
        candidates.push(parts.slice(0, -1).join("/"));
      }
    }
  } catch (e) {}
  try {
    const urls = fileManager().URLsForDirectory_inDomains_(DOC_DIR, USER_MASK);
    if (urls !== null && urls.count() > 0) {
      const p = str(urls.firstObject().path());
      if (p) {
        candidates.push(p);
      }
    }
  } catch (e) {}
  try {
    const fn = new NativeFunction(Module.getGlobalExportByName("NSHomeDirectory"), "pointer", []);
    const home = fn().readUtf8String();
    if (home) {
      candidates.push(home + "/Documents");
    }
  } catch (e) {}
  candidates.push("/tmp");
  for (let i = 0; i < candidates.length; i++) {
    if (writable(candidates[i])) {
      return candidates[i];
    }
  }
  return null;
}

function initPaths() {
  docsPath = documentsDir();
  updatedPath = docsPath === null ? null : docsPath + "/" + UPDATED;
  if (updatedPath !== null) {
    mkdir(updatedPath);
  }

  const chain = [];
  if (updatedPath !== null) {
    chain.push(updatedPath + "/" + LOG_NAME);
  }
  if (docsPath !== null) {
    chain.push(docsPath + "/" + LOG_NAME);
  }
  chain.push("/tmp/" + LOG_NAME);

  for (let i = 0; i < chain.length; i++) {
    const candidate = chain[i];
    const cut = candidate.lastIndexOf("/");
    if (cut < 1) {
      continue;
    }
    const dir = candidate.substring(0, cut);
    if (!exists(dir)) {
      mkdir(dir);
    }
    if (!writable(dir)) {
      continue;
    }
    if (!writeText(candidate, "")) {
      continue;
    }
    logPath = candidate;
    break;
  }
  if (logPath === null) {
    try {
      console.log("[agent] no writable directory for log");
    } catch (e) {}
    return;
  }
  log("log opened at " + logPath);
}

function environment() {
  try {
    log("frida=" + Frida.version + " runtime=" + Script.runtime + " arch=" + Process.arch + " pid=" + Process.id);
  } catch (e) {}
  try {
    log("bundle=" + str(ObjC.classes.NSBundle.mainBundle().bundlePath()));
  } catch (e) {}
  try {
    log("mainModule=" + Process.mainModule.name + " base=" + Process.mainModule.base + " path=" + Process.mainModule.path);
  } catch (e) {}
  log("docsPath=" + str(docsPath));
  log("updatedPath=" + str(updatedPath));
  log("logPath=" + str(logPath));
}

function showAlert(title, message) {
  try {
    const UIAlertController = ObjC.classes.UIAlertController;
    const UIAlertAction = ObjC.classes.UIAlertAction;
    const UIApplication = ObjC.classes.UIApplication;

    const alert = UIAlertController.alertControllerWithTitle_message_preferredStyle_(title, message, 1);
    const ok = UIAlertAction.actionWithTitle_style_handler_("OK", 0, null);
    alert.addAction_(ok);

    const windows = UIApplication.sharedApplication().windows();
    let root = null;
    for (let i = 0; i < windows.count(); i++) {
      const w = windows.objectAtIndex_(i);
      if (w.isKeyWindow()) {
        root = w.rootViewController();
        break;
      }
    }
    if (root === null) {
      log("alert skipped: no key window");
      return false;
    }
    while (root.presentedViewController() !== null) {
      root = root.presentedViewController();
    }
    root.presentViewController_animated_completion_(alert, true, null);
    log("alert shown: " + title + " / " + message);
    return true;
  } catch (e) {
    log("alert failed: " + e.message);
    return false;
  }
}

function start(stage, parameters) {
  if (started) {
    return;
  }
  started = true;
  initPaths();
  log("=== agent start ===");
  log("stage=" + str(stage));
  environment();
  log("frida-agent loaded, user @eurogoth");
  setTimeout(function () {
    showAlert("Frida", "frida-agent loaded, user @eurogoth");
  }, 4000);
  log("=== agent armed ===");
}

rpc.exports = {
  info: function () {
    return {
      log: logPath,
      documents: docsPath,
      updated: updatedPath
    };
  }
};

start("top-level", {});