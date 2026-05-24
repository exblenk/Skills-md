// SaboraTV v5 Extra Hooks Bisection — Find which ADDITIONAL hooks crash JSC
// Base: Known-safe config (A-G1+H minimal from bisect-v5.js)
// Tests: X1-X4 = hooks in v5 that bisection never had
//
// Usage: frida -U -f com.plebits.saboratv -l saboratv-bisect-v5-extras.js --no-pause
//
// Round 1: X1+X2=ON, X3+X4=OFF. Crash → problem in X1/X2. No crash → X3/X4.
// Round 2: Narrow to single group. Round 3: Individual hook.

(function () {
    'use strict';

    // ============ EXTRA HOOKS TOGGLE ============
    // X1: Additional C-level hooks (stat64/lstat64/readlink/readlinkat/_NSGetExecutablePath/mkdir/SecKey)
    var ENABLE_X1 = true;
    // X2: System ObjC hooks (NSJSONSerialization/NSMutableURLRequest/NSNotificationCenter/NSProcessInfo)
    var ENABLE_X2 = true;
    // X3: App-specific ObjC (GoogleAds/OneSignal/FlutterMethodChannel/canOpenURL/jailbreak ApiResolver/AppDelegate screen)
    var ENABLE_X3 = true;
    // X4: Extended ObjC+ApiResolver (H6 extra/H7 exports/H8 ApiResolver+exports/S3 extended/S12 extended/RevenueCat/Sentry/Firebase)
    var ENABLE_X4 = true;
    // ============================================

    var TAG = '[BISECT-X]';

    console.log(TAG + ' ==========================================');
    console.log(TAG + ' BASE: A-G1+H (known safe from prior bisection)');
    console.log(TAG + ' EXTRAS: X1=' + ENABLE_X1 + ' X2=' + ENABLE_X2 + ' X3=' + ENABLE_X3 + ' X4=' + ENABLE_X4);
    console.log(TAG + ' X1=C-level(stat64/readlink/mkdir/SecKey)');
    console.log(TAG + ' X2=SystemObjC(JSON/URLReq/NotifCenter/ProcInfo)');
    console.log(TAG + ' X3=AppObjC(GAds/OneSignal/Flutter/canOpen/JBdetect)');
    console.log(TAG + ' X4=Extended(H6+/H7+/H8+/S3+/S12+/RevCat/Sentry)');
    console.log(TAG + ' ==========================================');

    Process.setExceptionHandler(function (details) {
        try {
            var pc = details.context.pc;
            var mod = Process.findModuleByAddress(pc);
            var modName = mod ? mod.name + '+0x' + pc.sub(mod.base).toString(16) : pc;
            console.log(TAG + ' [CRASH] ' + details.type + ' at ' + modName);
        } catch (e) {}
        return false;
    });

    function randomUUID() {
        return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function (c) {
            var r = Math.random() * 16 | 0;
            return (c === 'x' ? r : (r & 0x3 | 0x8)).toString(16);
        });
    }
    var SPOOF_DEVICE_ID = randomUUID();
    var SPOOF_USER_UUID = randomUUID();
    console.log(TAG + ' device_id: ' + SPOOF_DEVICE_ID);
    console.log(TAG + ' user_uuid: ' + SPOOF_USER_UUID);

    function findExport(modName, symName) {
        if (typeof Module.findExportByName === 'function') {
            return Module.findExportByName(modName, symName);
        }
        try { return Module.getExportByName(symName); } catch (e) {}
        return null;
    }

    // =======================================================
    // BASE: Everything from the WORKING bisection (known safe)
    // =======================================================

    // --- A: sysctl + task_info ---
    var sysctlPtr = findExport(null, "sysctl");
    if (sysctlPtr) {
        Interceptor.attach(sysctlPtr, {
            onEnter: function (args) {
                try { this.size = args[1].toInt32(); this.oldp = args[2]; } catch (e) { this.size = 0; }
            },
            onLeave: function (retval) {
                if (this.size === 4 && this.oldp && !this.oldp.isNull()) {
                    try { var f = this.oldp.add(32).readU32(); if ((f & 0x800) !== 0) this.oldp.add(32).writeU32(f & ~0x800); } catch (e) {}
                }
            }
        });
    }
    var taskInfoPtr = findExport(null, "task_info");
    if (taskInfoPtr) {
        Interceptor.attach(taskInfoPtr, {
            onEnter: function (args) { this.flavor = args[1].toInt32(); this.info = args[2]; },
            onLeave: function (retval) {
                if (this.flavor === 17 && !this.info.isNull()) {
                    try { this.info.writeByteArray([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]); } catch (e) {}
                }
            }
        });
    }
    console.log(TAG + ' [BASE-A] sysctl+task_info');

    // --- B: file access (stat/lstat/fopen/open/openat/realpath) ---
    var jbPaths = [
        "/Applications/Cydia.app", "/Applications/Sileo.app", "/Applications/Zebra.app",
        "/Library/MobileSubstrate/MobileSubstrate.dylib", "/Library/MobileSubstrate",
        "/private/var/lib/apt", "/private/var/lib/cydia", "/private/var/stash",
        "/var/lib/apt", "/var/lib/cydia", "/var/jb", "/var/binpack",
        "/bin/bash", "/bin/sh", "/usr/sbin/sshd", "/usr/bin/sshd",
        "/usr/sbin/frida-server", "/usr/lib/libcycript.dylib",
        "/usr/lib/TweakInject", "/etc/apt", "/private/preboot"
    ];
    var jbKeywords = ["Cydia", "Sileo", "substrate", "jailbreak", "frida", "MobileSubstrate",
        "TweakInject", "libhooker", "substitute", "checkra1n", "unc0ver", "Dopamine", "palera1n"];

    function isJBPath(path) {
        if (!path) return false;
        for (var i = 0; i < jbPaths.length; i++) { if (path.indexOf(jbPaths[i]) !== -1) return true; }
        for (var j = 0; j < jbKeywords.length; j++) { if (path.indexOf(jbKeywords[j]) !== -1) return true; }
        return false;
    }

    ["access", "stat", "lstat"].forEach(function (fn) {
        var p = findExport(null, fn);
        if (p) {
            Interceptor.attach(p, {
                onEnter: function (args) { try { this.path = args[0].readUtf8String(); } catch (e) { this.path = ""; } },
                onLeave: function (retval) { if (isJBPath(this.path)) retval.replace(-1); }
            });
        }
    });
    var fopenPtr = findExport(null, "fopen");
    if (fopenPtr) {
        Interceptor.attach(fopenPtr, {
            onEnter: function (args) { try { this.path = args[0].readUtf8String(); } catch (e) { this.path = ""; } },
            onLeave: function (retval) { if (isJBPath(this.path)) retval.replace(ptr(0x0)); }
        });
    }
    var openPtr = findExport(null, "open");
    if (openPtr) {
        Interceptor.attach(openPtr, {
            onEnter: function (args) { try { this.path = args[0].readUtf8String(); if (isJBPath(this.path)) this.blocked = true; } catch (e) {} },
            onLeave: function (retval) { if (this.blocked) retval.replace(-1); }
        });
    }
    var openatPtr = findExport(null, "openat");
    if (openatPtr) {
        Interceptor.attach(openatPtr, {
            onEnter: function (args) { try { if (isJBPath(args[1].readUtf8String())) this.blocked = true; } catch (e) {} },
            onLeave: function (retval) { if (this.blocked) retval.replace(-1); }
        });
    }
    var realpathPtr = findExport(null, "realpath$DARWIN_EXTSN");
    if (!realpathPtr) realpathPtr = findExport(null, "realpath");
    if (realpathPtr) {
        Interceptor.attach(realpathPtr, {
            onEnter: function (args) { try { this.path = args[0].readUtf8String(); } catch (e) { this.path = ""; } },
            onLeave: function (retval) { if (isJBPath(this.path)) retval.replace(ptr(0x0)); }
        });
    }
    console.log(TAG + ' [BASE-B] file access');

    // --- C: dyld ---
    var suspiciousDylibs = ["frida", "FridaGadget", "substrate", "SubstrateLoader", "SubstrateInserter",
        "CydiaSubstrate", "libhooker", "substitute", "TweakInject", "Shadow", "0Shadow",
        "FlyJB", "Liberty", "A-Bypass", "Hestia", "KernBypass", "vnodebypass"];
    function isSuspiciousDylib(name) {
        if (!name) return false;
        for (var i = 0; i < suspiciousDylibs.length; i++) { if (name.indexOf(suspiciousDylibs[i]) !== -1) return true; }
        if (name.indexOf("/var/jb/") !== -1 || name.indexOf("/Library/MobileSubstrate/") !== -1 ||
            name.indexOf("/usr/lib/TweakInject/") !== -1 || name.indexOf("/private/preboot/") !== -1) return true;
        return false;
    }
    var dyldGetImageName = findExport(null, "_dyld_get_image_name");
    if (dyldGetImageName) {
        var fakeNamePtr = Memory.allocUtf8String("/usr/lib/libSystem.B.dylib");
        Interceptor.attach(dyldGetImageName, {
            onLeave: function (retval) {
                if (!retval.isNull()) {
                    try { var name = retval.readUtf8String(); if (isSuspiciousDylib(name)) retval.replace(fakeNamePtr); } catch (e) {}
                }
            }
        });
    }
    var dyldImageCount = findExport(null, "_dyld_image_count");
    if (dyldImageCount) {
        var getName = new NativeFunction(findExport(null, "_dyld_get_image_name"), 'pointer', ['int']);
        Interceptor.attach(dyldImageCount, {
            onLeave: function (retval) {
                var real = retval.toInt32(); var hc = 0;
                for (var i = 0; i < real; i++) { try { var n = getName(i).readUtf8String(); if (isSuspiciousDylib(n)) hc++; } catch (e) {} }
                if (hc > 0) retval.replace(real - hc);
            }
        });
    }
    console.log(TAG + ' [BASE-C] dyld');

    // --- D: getenv ---
    var blockedEnvVars = ["DYLD_INSERT_LIBRARIES", "DYLD_FRAMEWORK_PATH", "DYLD_LIBRARY_PATH",
        "DYLD_PRINT_STATISTICS", "DYLD_PRINT_LIBRARIES", "DYLD_ROOT_PATH"];
    var getenvPtr = findExport(null, "getenv");
    if (getenvPtr) {
        Interceptor.attach(getenvPtr, {
            onEnter: function (args) { try { this.name = args[0].readUtf8String(); } catch (e) { this.name = ""; } },
            onLeave: function (retval) {
                for (var i = 0; i < blockedEnvVars.length; i++) {
                    if (this.name === blockedEnvVars[i]) { retval.replace(ptr(0x0)); return; }
                }
            }
        });
    }
    console.log(TAG + ' [BASE-D] getenv');

    // --- E: SSL ---
    try {
        var flutterMod = Process.findModuleByName("Flutter");
        if (flutterMod) {
            flutterMod.enumerateExports().forEach(function (exp) {
                if (exp.name.indexOf("ssl_verify_peer_cert") !== -1 && exp.type === 'function') {
                    Interceptor.attach(exp.address, { onLeave: function (retval) { retval.replace(0x0); } });
                }
            });
        }
    } catch (e) {}
    try {
        var secTrustEvalErr = findExport("Security", "SecTrustEvaluateWithError");
        if (secTrustEvalErr) {
            Interceptor.attach(secTrustEvalErr, {
                onEnter: function (args) { this.errPtr = args[1]; },
                onLeave: function (retval) {
                    retval.replace(0x1);
                    if (this.errPtr && !this.errPtr.isNull()) { try { this.errPtr.writePointer(ptr(0x0)); } catch (e) {} }
                }
            });
        }
    } catch (e) {}
    console.log(TAG + ' [BASE-E] SSL');

    // --- F: connect + dladdr + dlsym + dlopen ---
    var connectPtr = findExport(null, "connect");
    if (connectPtr) {
        Interceptor.attach(connectPtr, {
            onEnter: function (args) {
                try {
                    var family = args[1].readU16();
                    if (family === 2) {
                        var port = (args[1].add(2).readU8() << 8) | args[1].add(3).readU8();
                        if (port === 27042 || port === 27043) this.block = true;
                    }
                } catch (e) {}
            },
            onLeave: function (retval) { if (this.block) retval.replace(-1); }
        });
    }
    var dladdrPtr = findExport(null, "dladdr");
    if (dladdrPtr) {
        Interceptor.attach(dladdrPtr, {
            onEnter: function (args) { this.info = args[1]; },
            onLeave: function (retval) {
                if (retval.toInt32() !== 0 && !this.info.isNull()) {
                    try { var fname = this.info.add(Process.pointerSize).readPointer().readUtf8String(); if (fname && isSuspiciousDylib(fname)) retval.replace(0); } catch (e) {}
                }
            }
        });
    }
    var dlsymPtr = findExport(null, "dlsym");
    if (dlsymPtr) {
        Interceptor.attach(dlsymPtr, {
            onEnter: function (args) {
                try {
                    if (!args[1].isNull()) {
                        var sym = args[1].readUtf8String();
                        if (sym && (sym.indexOf("frida") !== -1 || sym.indexOf("gum_") !== -1 ||
                            sym.indexOf("substrate") !== -1 || sym.indexOf("MSHookFunction") !== -1)) this.block = true;
                    }
                } catch (e) {}
            },
            onLeave: function (retval) { if (this.block) retval.replace(ptr(0x0)); }
        });
    }
    var dlopenPtr = findExport(null, "dlopen");
    if (dlopenPtr) {
        Interceptor.attach(dlopenPtr, {
            onEnter: function (args) {
                if (!args[0].isNull()) {
                    try {
                        var path = args[0].readUtf8String();
                        if (path && isSuspiciousDylib(path)) { this.fakePath = Memory.allocUtf8String("/dev/null"); args[0] = this.fakePath; }
                    } catch (e) {}
                }
            }
        });
    }
    console.log(TAG + ' [BASE-F] connect+dl*');

    // --- G1: fork + ptrace + exit/abort ---
    var forkPtr = findExport(null, "fork");
    if (forkPtr) { Interceptor.attach(forkPtr, { onLeave: function (retval) { retval.replace(-1); } }); }
    var ptracePtr = findExport(null, "ptrace");
    if (ptracePtr) {
        Interceptor.attach(ptracePtr, {
            onEnter: function (args) { if (args[0].toInt32() === 31) { this.deny = true; args[0] = ptr(0); } },
            onLeave: function (retval) { if (this.deny) retval.replace(0); }
        });
    }
    ["exit", "_exit", "_Exit", "abort"].forEach(function (fn) {
        try {
            var p = findExport(null, fn);
            if (p) { Interceptor.attach(p, { onEnter: function () { console.log(TAG + ' [EXIT] ' + fn + '() blocked'); Thread.sleep(86400); } }); }
        } catch (e) {}
    });
    try {
        var abp = findExport(null, "__abort_with_payload");
        if (abp) { Interceptor.attach(abp, { onEnter: function () { console.log(TAG + ' [EXIT] __abort_with_payload blocked'); Thread.sleep(86400); } }); }
    } catch (e) {}
    // sigaction SIG_IGN for SIGTERM/SIGTRAP/SIGABRT
    try {
        var sigactionFn = new NativeFunction(findExport(null, "sigaction"), 'int', ['int', 'pointer', 'pointer']);
        var saIgnore = Memory.alloc(128);
        saIgnore.writePointer(ptr(0x1));
        sigactionFn(15, saIgnore, ptr(0));
        sigactionFn(5, saIgnore, ptr(0));
        var sigabrtHandler = new NativeCallback(function () {
            console.log(TAG + ' [SIGNAL] SIGABRT caught');
        }, 'void', ['int']);
        var saAbort = Memory.alloc(128);
        saAbort.writePointer(sigabrtHandler);
        sigactionFn(6, saAbort, ptr(0));
    } catch (e) {}
    console.log(TAG + ' [BASE-G1] fork+ptrace+exit+sigaction');

    // --- H (minimal): ISS basic + Talsec basic + Ban clear ---
    try {
        var IOSSecuritySuite = ObjC.classes.IOSSecuritySuite;
        if (IOSSecuritySuite) {
            ["amIJailbroken", "amIJailbrokenWithFailMessage", "amIJailbrokenWithFailedChecks",
             "amIRunInEmulator", "amIDebugged", "amIReverseEngineered", "amIProxied",
             "amITampered:", "amIRuntimeHooked:", "denyDebugger", "denySymbolHook:"].forEach(function (m) {
                try {
                    var sel = '+ ' + m;
                    if (IOSSecuritySuite[sel]) {
                        Interceptor.attach(IOSSecuritySuite[sel].implementation, {
                            onLeave: function (retval) { retval.replace(0x0); }
                        });
                    }
                } catch (e) {}
            });
        }
    } catch (e) {}
    try {
        ["SecurityThreatCenter", "TalsecRuntime", "FreeraspFlutterPlugin"].forEach(function (cls) {
            try {
                var klass = ObjC.classes[cls];
                if (klass) {
                    klass.$ownMethods.forEach(function (method) {
                        try { Interceptor.attach(klass[method].implementation, { onLeave: function (retval) {} }); } catch (e) {}
                    });
                }
            } catch (e) {}
        });
    } catch (e) {}
    setTimeout(function () {
        try {
            var NSFileManager = ObjC.classes.NSFileManager;
            if (NSFileManager) {
                ["- fileExistsAtPath:", "- fileExistsAtPath:isDirectory:"].forEach(function (sel) {
                    try {
                        if (NSFileManager[sel]) {
                            Interceptor.attach(NSFileManager[sel].implementation, {
                                onEnter: function (args) { try { this.path = ObjC.Object(args[2]).toString(); } catch (e) { this.path = ""; } },
                                onLeave: function (retval) { if (isJBPath(this.path)) retval.replace(0x0); }
                            });
                        }
                    } catch (e) {}
                });
            }
        } catch (e) {}
        console.log(TAG + ' [BASE-H] NSFileManager basic');
    }, 50);
    // Ban clear
    setTimeout(function () {
        try {
            var SecItemDelete = new NativeFunction(findExport("Security", "SecItemDelete"), 'int', ['pointer']);
            ["ban", "device_id", "user_uuid", "session_token"].forEach(function (key) {
                try {
                    var query = ObjC.classes.NSMutableDictionary.alloc().init();
                    query.setObject_forKey_(ObjC.classes.NSString.stringWithString_("flutter_secure_storage_service"), ObjC.classes.NSString.stringWithString_("svce"));
                    query.setObject_forKey_(ObjC.classes.NSString.stringWithString_(key), ObjC.classes.NSString.stringWithString_("acct"));
                    query.setObject_forKey_(ObjC.classes.NSString.stringWithString_("genp"), ObjC.classes.NSString.stringWithString_("class"));
                    var r = SecItemDelete(query);
                    console.log(TAG + ' [BAN] SecItemDelete(' + key + ') = ' + r);
                } catch (e) {}
            });
        } catch (e) {}
    }, 0);
    // S9: flutter_jailbreak_detection_plus (basic — was in ObjC-only test)
    try {
        var ApiProvider = ObjC.classes["flutter_jailbreak_detection_plus.SwiftFlutterJailbreakDetectionPlusPlugin"];
        if (!ApiProvider) ApiProvider = ObjC.classes["SwiftFlutterJailbreakDetectionPlusPlugin"];
        if (ApiProvider) {
            ApiProvider.$ownMethods.forEach(function (method) {
                try { Interceptor.attach(ApiProvider[method].implementation, { onLeave: function (retval) {} }); } catch (e) {}
            });
            console.log(TAG + ' [BASE-H] flutter_jailbreak_detection_plus');
        }
    } catch (e) {}
    // S14: RevenueCat basic (was in ObjC-only test)
    try {
        ["RCBackend", "RCPurchases", "RCDeviceCache"].forEach(function (cls) {
            try {
                var klass = ObjC.classes[cls];
                if (klass) {
                    klass.$ownMethods.forEach(function (method) {
                        if (method.indexOf("jailbreak") !== -1 || method.indexOf("sandbox") !== -1 ||
                            method.indexOf("tamper") !== -1 || method.indexOf("integrity") !== -1) {
                            try { Interceptor.attach(klass[method].implementation, { onLeave: function (retval) {} }); } catch (e) {}
                        }
                    });
                }
            } catch (e) {}
        });
    } catch (e) {}
    // UIApplication terminateWithSuccess (was in ObjC-only test)
    setTimeout(function () {
        try {
            var UIApp = ObjC.classes.UIApplication;
            if (UIApp && UIApp["- terminateWithSuccess"]) {
                Interceptor.attach(UIApp["- terminateWithSuccess"].implementation, {
                    onEnter: function () { console.log(TAG + ' [EXIT] terminateWithSuccess blocked'); Thread.sleep(86400); }
                });
            }
        } catch (e) {}
    }, 100);
    // UIScreen isCaptured (was in ObjC-only test)
    setTimeout(function () {
        try {
            var UIScreen = ObjC.classes.UIScreen;
            if (UIScreen && UIScreen["- isCaptured"]) {
                Interceptor.attach(UIScreen["- isCaptured"].implementation, {
                    onLeave: function (retval) { retval.replace(0x0); }
                });
            }
        } catch (e) {}
    }, 100);
    // S8 basic: AppDelegate screen hooks (was in ObjC-only test)
    setTimeout(function () {
        try {
            var AppDelegate = ObjC.classes.AppDelegate;
            if (AppDelegate) {
                var sr = AppDelegate["- screenRecordingStatusChanged"];
                if (sr) Interceptor.attach(sr.implementation, { onEnter: function () { return; } });
                var ss = AppDelegate["- screenshotHasTaken"];
                if (ss) Interceptor.attach(ss.implementation, { onEnter: function () { return; } });
                console.log(TAG + ' [BASE-H] AppDelegate screen hooks');
            }
        } catch (e) {}
    }, 100);
    console.log(TAG + ' [BASE-H] ISS+Talsec+BanClear+JBDetect+RevCat+Screen');

    // =======================================================
    // X1: Additional C-level hooks NOT in bisection
    // stat64, lstat64, readlink, readlinkat, _NSGetExecutablePath, mkdir, SecKey
    // =======================================================
    if (ENABLE_X1) {
        // stat64/lstat64 — different entry points from stat/lstat on newer iOS
        ["stat64", "lstat64"].forEach(function (fn) {
            var p = findExport(null, fn);
            if (p) {
                Interceptor.attach(p, {
                    onEnter: function (args) { try { this.path = args[0].readUtf8String(); } catch (e) { this.path = ""; } },
                    onLeave: function (retval) { if (isJBPath(this.path)) retval.replace(-1); }
                });
                console.log(TAG + ' [X1] ' + fn + ' hooked');
            }
        });

        // readlink/readlinkat
        ["readlink", "readlinkat"].forEach(function (fn) {
            var p = findExport(null, fn);
            if (p) {
                Interceptor.attach(p, {
                    onEnter: function (args) {
                        try {
                            var pathIdx = fn === "readlinkat" ? 1 : 0;
                            this.path = args[pathIdx].readUtf8String();
                            this.bufPtr = args[fn === "readlinkat" ? 2 : 1];
                        } catch (e) { this.path = ""; this.bufPtr = null; }
                    },
                    onLeave: function (retval) {
                        if (isJBPath(this.path)) { retval.replace(-1); return; }
                        if (retval.toInt32() > 0 && this.bufPtr && !this.bufPtr.isNull()) {
                            try { var resolved = this.bufPtr.readUtf8String(retval.toInt32()); if (isJBPath(resolved)) retval.replace(-1); } catch (e) {}
                        }
                    }
                });
                console.log(TAG + ' [X1] ' + fn + ' hooked');
            }
        });

        // _NSGetExecutablePath
        var nsGetExecPath = findExport(null, "_NSGetExecutablePath");
        if (nsGetExecPath) {
            Interceptor.attach(nsGetExecPath, {
                onEnter: function (args) { this.buf = args[0]; },
                onLeave: function (retval) {
                    if (retval.toInt32() === 0 && this.buf && !this.buf.isNull()) {
                        try { var path = this.buf.readUtf8String(); if (isJBPath(path)) retval.replace(-1); } catch (e) {}
                    }
                }
            });
            console.log(TAG + ' [X1] _NSGetExecutablePath hooked');
        }

        // mkdir (sandbox write test)
        var mkdirPtr = findExport(null, "mkdir");
        if (mkdirPtr) {
            Interceptor.attach(mkdirPtr, {
                onEnter: function (args) {
                    try { var path = args[0].readUtf8String(); if (path === "/" || path === "/private" || path === "/private/test_jailbreak") this.block = true; } catch (e) {}
                },
                onLeave: function (retval) { if (this.block) retval.replace(-1); }
            });
            console.log(TAG + ' [X1] mkdir hooked');
        }

        // SecKeyVerifySignature / SecKeyRawVerify
        try {
            var secKeyVerify = findExport("Security", "SecKeyVerifySignature");
            if (secKeyVerify) { Interceptor.attach(secKeyVerify, { onLeave: function (retval) { retval.replace(0x1); } }); console.log(TAG + ' [X1] SecKeyVerifySignature hooked'); }
            var secKeyRawVerify = findExport("Security", "SecKeyRawVerify");
            if (secKeyRawVerify) { Interceptor.attach(secKeyRawVerify, { onLeave: function (retval) { retval.replace(0); } }); console.log(TAG + ' [X1] SecKeyRawVerify hooked'); }
        } catch (e) {}

        // SecTrustGetTrustResult (extra SSL from v5 not in bisection)
        try {
            var secTrustGetResult = findExport("Security", "SecTrustGetTrustResult");
            if (secTrustGetResult) {
                Interceptor.attach(secTrustGetResult, {
                    onEnter: function (args) { this.resultPtr = args[1]; },
                    onLeave: function (retval) {
                        retval.replace(0);
                        if (this.resultPtr && !this.resultPtr.isNull()) { try { this.resultPtr.writeU32(1); } catch (e) {} }
                    }
                });
                console.log(TAG + ' [X1] SecTrustGetTrustResult hooked');
            }
        } catch (e) {}

        console.log(TAG + ' [X1] Additional C-level hooks -- loaded');
    }

    // =======================================================
    // X2: System ObjC hooks (hot methods JSC might call)
    // NSJSONSerialization, NSMutableURLRequest, NSNotificationCenter, NSProcessInfo
    // =======================================================
    if (ENABLE_X2) {
        // S6: NSJSONSerialization (API response ban interception)
        try {
            var NSJSONSerialization = ObjC.classes.NSJSONSerialization;
            if (NSJSONSerialization) {
                var jsonParse = NSJSONSerialization["+ JSONObjectWithData:options:error:"];
                if (jsonParse) {
                    Interceptor.attach(jsonParse.implementation, {
                        onLeave: function (retval) {
                            if (retval.isNull()) return;
                            try {
                                var obj = ObjC.Object(retval);
                                if (!obj.isKindOfClass_(ObjC.classes.NSDictionary)) return;
                                var banKeys = ["ban", "is_banned", "banned", "blocked", "is_blocked",
                                               "suspended", "is_suspended", "restricted", "is_restricted",
                                               "device_banned", "device_blocked", "device_restricted"];
                                var mutable = null;
                                for (var i = 0; i < banKeys.length; i++) {
                                    var val = obj.objectForKey_(ObjC.classes.NSString.stringWithString_(banKeys[i]));
                                    if (val && !val.isNull()) {
                                        var valStr = val.toString();
                                        if (valStr === "1" || valStr === "true" || valStr === "yes") {
                                            if (!mutable) mutable = obj.mutableCopy();
                                            mutable.setObject_forKey_(ObjC.classes.NSNumber.numberWithBool_(false),
                                                ObjC.classes.NSString.stringWithString_(banKeys[i]));
                                        }
                                    }
                                }
                                if (mutable) retval.replace(mutable);
                            } catch (e) {}
                        }
                    });
                    console.log(TAG + ' [X2] NSJSONSerialization hooked');
                }
            }
        } catch (e) {}

        // S7: NSMutableURLRequest (Sentry/Firebase URL blocking)
        try {
            var blockedHosts = ["sentry.io", "crashlytics", "firebase-settings", "app-measurement"];
            var NSMutableURLRequest2 = ObjC.classes.NSMutableURLRequest;
            if (NSMutableURLRequest2) {
                ["- initWithURL:", "- initWithURL:cachePolicy:timeoutInterval:"].forEach(function (sel) {
                    var m = NSMutableURLRequest2[sel];
                    if (m) {
                        Interceptor.attach(m.implementation, {
                            onEnter: function (args) {
                                try {
                                    var url = ObjC.Object(args[2]).absoluteString().toString();
                                    for (var i = 0; i < blockedHosts.length; i++) {
                                        if (url.indexOf(blockedHosts[i]) !== -1) {
                                            args[2] = ObjC.classes.NSURL.URLWithString_(ObjC.classes.NSString.stringWithString_("https://localhost/blocked"));
                                            break;
                                        }
                                    }
                                } catch (e) {}
                            }
                        });
                    }
                });
                console.log(TAG + ' [X2] NSMutableURLRequest hooked');
            }
        } catch (e) {}

        // S8 extended: NSNotificationCenter observer filtering
        setTimeout(function () {
            try {
                var NSNotificationCenter = ObjC.classes.NSNotificationCenter;
                if (NSNotificationCenter) {
                    Interceptor.attach(NSNotificationCenter["- addObserver:selector:name:object:"].implementation, {
                        onEnter: function (args) {
                            try {
                                var name = ObjC.Object(args[4]).toString();
                                if (name.indexOf("UserDidTakeScreenshot") !== -1 || name.indexOf("CapturedDidChange") !== -1) {
                                    args[4] = ObjC.classes.NSString.stringWithString_("__blocked_" + name);
                                }
                            } catch (e) {}
                        }
                    });
                    console.log(TAG + ' [X2] NSNotificationCenter hooked');
                }
            } catch (e) {}
        }, 100);

        // H9 extended: NSProcessInfo.environment
        try {
            var NSProcessInfo = ObjC.classes.NSProcessInfo;
            if (NSProcessInfo) {
                var envMethod = NSProcessInfo["- environment"];
                if (envMethod) {
                    Interceptor.attach(envMethod.implementation, {
                        onLeave: function (retval) {
                            if (retval.isNull()) return;
                            try {
                                var dict = ObjC.Object(retval);
                                var mutable = dict.mutableCopy();
                                var changed = false;
                                blockedEnvVars.forEach(function (key) {
                                    var nsKey = ObjC.classes.NSString.stringWithString_(key);
                                    var val = mutable.objectForKey_(nsKey);
                                    if (val && !val.isNull() && val.toString() !== "nil") {
                                        mutable.removeObjectForKey_(nsKey);
                                        changed = true;
                                    }
                                });
                                if (changed) retval.replace(mutable);
                            } catch (e) {}
                        }
                    });
                    console.log(TAG + ' [X2] NSProcessInfo.environment hooked');
                }
            }
        } catch (e) {}

        console.log(TAG + ' [X2] System ObjC hooks -- loaded');
    }

    // =======================================================
    // X3: App-specific ObjC hooks
    // Google Ads, OneSignal, FlutterMethodChannel, canOpenURL, jailbreak ApiResolver
    // =======================================================
    if (ENABLE_X3) {
        // S2: Google Ads JB detection
        try {
            ["GADDevice", "GADApplication", "GADApplicationStateEvents",
             "GADCrashReporter", "GADDebugGestureMonitor"].forEach(function (cls) {
                try {
                    var klass = ObjC.classes[cls];
                    if (klass) {
                        klass.$ownMethods.forEach(function (method) {
                            var lower = method.toLowerCase();
                            if (lower.indexOf("jailb") !== -1 || lower.indexOf("_jb") !== -1 ||
                                lower.indexOf("isrooted") !== -1 || lower.indexOf("deviceintegrity") !== -1) {
                                Interceptor.attach(klass[method].implementation, {
                                    onLeave: function (retval) { retval.replace(0x0); }
                                });
                            }
                        });
                    }
                } catch (e) {}
            });
            console.log(TAG + ' [X3] Google Ads JB bypass');
        } catch (e) {}

        // S4: OneSignal
        try {
            var OneSignal = ObjC.classes.OneSignal;
            if (OneSignal) {
                OneSignal.$ownMethods.forEach(function (method) {
                    var lower = method.toLowerCase();
                    if (lower.indexOf("setexternaluserid") !== -1 || lower.indexOf("sendtag") !== -1 ||
                        lower.indexOf("setsubscription") !== -1 || lower.indexOf("setemail") !== -1 ||
                        lower.indexOf("setsmsnumber") !== -1) {
                        try {
                            Interceptor.attach(OneSignal[method].implementation, {
                                onEnter: function (args) { args[2] = ObjC.classes.NSNull._null(); }
                            });
                        } catch (e) {}
                    }
                });
            }
            var resolver_os = new ApiResolver('objc');
            resolver_os.enumerateMatches('-[* setPlayerId*]', {
                onMatch: function (m) {
                    if (m.name.toLowerCase().indexOf('onesignal') !== -1) {
                        Interceptor.attach(m.address, {
                            onEnter: function (args) { args[2] = ObjC.classes.NSNull._null(); }
                        });
                    }
                },
                onComplete: function () {}
            });
            resolver_os.enumerateMatches('-[* oneSignalDidRegisterForRemoteNotifications:deviceToken:]', {
                onMatch: function (m) {
                    Interceptor.attach(m.address, {
                        onEnter: function (args) { args[3] = ObjC.classes.NSData.data(); }
                    });
                },
                onComplete: function () {}
            });
            resolver_os.enumerateMatches('-[* sendTags*]', {
                onMatch: function (m) {
                    if (m.name.toLowerCase().indexOf('onesignal') !== -1) {
                        Interceptor.attach(m.address, {
                            onEnter: function (args) { try { args[2] = ObjC.classes.NSDictionary.dictionary(); } catch (e) {} }
                        });
                    }
                },
                onComplete: function () {}
            });
            console.log(TAG + ' [X3] OneSignal');
        } catch (e) {}

        // S5: FlutterMethodChannel
        try {
            var FlutterMethodChannel = ObjC.classes.FlutterMethodChannel;
            if (FlutterMethodChannel) {
                var invokeMethod = FlutterMethodChannel["- invokeMethod:arguments:"];
                if (invokeMethod) {
                    Interceptor.attach(invokeMethod.implementation, {
                        onEnter: function (args) {
                            try {
                                var method = ObjC.Object(args[2]).toString();
                                if (method.indexOf("jailbreak") !== -1 || method.indexOf("isJailbroken") !== -1 ||
                                    method.indexOf("checkSecurity") !== -1 || method.indexOf("threatDetected") !== -1) {
                                    console.log(TAG + ' [CHANNEL] Intercepted: ' + method);
                                }
                            } catch (e) {}
                        }
                    });
                    console.log(TAG + ' [X3] FlutterMethodChannel');
                }
            }
        } catch (e) {}

        // S10: canOpenURL
        try {
            var jbSchemes = ["cydia://", "sileo://", "zbra://", "filza://", "undecimus://",
                             "activator://", "atlas://", "dopamine://", "palera1n://"];
            var UIApp3 = ObjC.classes.UIApplication;
            if (UIApp3) {
                var canOpenURL = UIApp3["- canOpenURL:"];
                if (canOpenURL) {
                    Interceptor.attach(canOpenURL.implementation, {
                        onEnter: function (args) { try { this.url = ObjC.Object(args[2]).toString(); } catch (e) { this.url = ""; } },
                        onLeave: function (retval) {
                            for (var i = 0; i < jbSchemes.length; i++) { if (this.url.indexOf(jbSchemes[i]) !== -1) { retval.replace(0x0); return; } }
                        }
                    });
                    console.log(TAG + ' [X3] canOpenURL');
                }
            }
        } catch (e) {}

        // S9 extended: jailbreak detection via ApiResolver (broader than base)
        try {
            var resolver2 = new ApiResolver('objc');
            ['-[* jailbreakDetection*]', '+[* isJailbroken*]', '-[* isJailbroken*]',
             '-[* checkJailbreak*]', '+[* checkJailbreak*]',
             '-[* isDeviceRooted*]', '+[* isDeviceRooted*]'].forEach(function (p) {
                try {
                    resolver2.enumerateMatches(p, {
                        onMatch: function (m) { Interceptor.attach(m.address, { onLeave: function (retval) { retval.replace(0x0); } }); },
                        onComplete: function () {}
                    });
                } catch (e) {}
            });
            console.log(TAG + ' [X3] jailbreak ApiResolver');
        } catch (e) {}

        console.log(TAG + ' [X3] App-specific ObjC hooks -- loaded');
    }

    // =======================================================
    // X4: Extended ObjC/ApiResolver hooks
    // H6 extra, H7 exports, H8 ApiResolver+exports, S3 extended,
    // S7 Sentry/Firebase ObjC, S12 extended, S14 RevenueCat extended
    // =======================================================
    if (ENABLE_X4) {
        // H6 extended: contentsOfDirectory, attributesOfItem
        setTimeout(function () {
            try {
                var NSFileManager = ObjC.classes.NSFileManager;
                if (NSFileManager) {
                    var contentsOfDir = NSFileManager["- contentsOfDirectoryAtPath:error:"];
                    if (contentsOfDir) {
                        Interceptor.attach(contentsOfDir.implementation, {
                            onEnter: function (args) { try { this.path = ObjC.Object(args[2]).toString(); } catch (e) { this.path = ""; } },
                            onLeave: function (retval) { if (isJBPath(this.path)) retval.replace(ObjC.classes.NSArray.array()); }
                        });
                    }
                    var attrsOfItem = NSFileManager["- attributesOfItemAtPath:error:"];
                    if (attrsOfItem) {
                        Interceptor.attach(attrsOfItem.implementation, {
                            onEnter: function (args) { try { this.path = ObjC.Object(args[2]).toString(); } catch (e) { this.path = ""; } },
                            onLeave: function (retval) { if (isJBPath(this.path)) retval.replace(ptr(0x0)); }
                        });
                    }
                    console.log(TAG + ' [X4] NSFileManager extended');
                }
            } catch (e) {}
        }, 50);

        // H7 extended: ISS module exports
        try {
            var issModule = Process.findModuleByName("IOSSecuritySuite");
            if (issModule) {
                issModule.enumerateExports().forEach(function (exp) {
                    var n = exp.name.toLowerCase();
                    if ((n.indexOf("amijailbroken") !== -1 || n.indexOf("amidebugged") !== -1 ||
                         n.indexOf("amiruninemulator") !== -1 || n.indexOf("amireverseengineered") !== -1 ||
                         n.indexOf("amiruntimehooked") !== -1 || n.indexOf("denydebugger") !== -1 ||
                         n.indexOf("amitampered") !== -1 || n.indexOf("amiproxied") !== -1) && exp.type === 'function') {
                        Interceptor.attach(exp.address, { onLeave: function (retval) { retval.replace(0x0); } });
                    }
                });
                console.log(TAG + ' [X4] ISS module exports');
            }
        } catch (e) {}

        // H7 extended: ISS $ownMethods (broader matching than base)
        try {
            var IOSSecuritySuite2 = ObjC.classes.IOSSecuritySuite;
            if (IOSSecuritySuite2) {
                IOSSecuritySuite2.$ownMethods.forEach(function (method) {
                    var lower = method.toLowerCase();
                    if (lower.indexOf("ami") !== -1 || lower.indexOf("jailbr") !== -1 ||
                        lower.indexOf("debug") !== -1 || lower.indexOf("reverse") !== -1 ||
                        lower.indexOf("hook") !== -1 || lower.indexOf("emulator") !== -1 ||
                        lower.indexOf("tamper") !== -1 || lower.indexOf("integrity") !== -1 ||
                        lower.indexOf("deny") !== -1 || lower.indexOf("proxy") !== -1 ||
                        lower.indexOf("simulator") !== -1) {
                        try { Interceptor.attach(IOSSecuritySuite2[method].implementation, { onLeave: function (retval) { retval.replace(0x0); } }); } catch (e) {}
                    }
                });
                console.log(TAG + ' [X4] ISS ownMethods extended');
            }
        } catch (e) {}

        // H8 extended: Talsec ApiResolver + module exports
        try {
            var resolver_t = new ApiResolver('objc');
            ['-[* threatDetected*]', '-[* onJailbreak*]', '-[* onDebugger*]',
             '-[* onHook*]', '-[* onTamper*]', '-[* onReverseEngineering*]',
             '-[* onDeviceBinding*]', '-[* onUnofficialStore*]', '+[* isThreatDetected*]',
             '-[* onMalware*]', '-[* securityThreat*]', '-[* onSecurityThreat*]'
            ].forEach(function (pattern) {
                try {
                    resolver_t.enumerateMatches(pattern, {
                        onMatch: function (match) {
                            var mn = match.name.toLowerCase();
                            if (mn.indexOf('talsec') !== -1 || mn.indexOf('freerasp') !== -1 ||
                                mn.indexOf('threat') !== -1 || mn.indexOf('security') !== -1) {
                                Interceptor.attach(match.address, { onLeave: function (retval) { retval.replace(0x0); } });
                            }
                        },
                        onComplete: function () {}
                    });
                } catch (e) {}
            });
            console.log(TAG + ' [X4] Talsec ApiResolver');
        } catch (e) {}

        try {
            Process.enumerateModules().forEach(function (mod) {
                if (mod.name.toLowerCase().indexOf('talsec') !== -1 || mod.name.toLowerCase().indexOf('freerasp') !== -1) {
                    mod.enumerateExports().forEach(function (exp) {
                        var n = exp.name.toLowerCase();
                        if ((n.indexOf("threat") !== -1 || n.indexOf("jailbreak") !== -1 ||
                             n.indexOf("hook") !== -1 || n.indexOf("tamper") !== -1 ||
                             n.indexOf("debug") !== -1 || n.indexOf("integrity") !== -1) && exp.type === 'function') {
                            Interceptor.attach(exp.address, { onLeave: function (retval) { retval.replace(0x0); } });
                        }
                    });
                    console.log(TAG + ' [X4] Talsec module exports');
                }
            });
        } catch (e) {}

        // S3 extended: SecItemCopyMatching + ApiResolver SecureStorage
        try {
            var keychainSpoofMap = { "ban": "0", "device_id": SPOOF_DEVICE_ID, "user_uuid": SPOOF_USER_UUID, "subscription_status": "active" };
            var resolver3 = new ApiResolver('objc');
            ['-[* read*]', '-[* write*]', '-[* delete*]', '-[* readAll*]'].forEach(function (pattern) {
                try {
                    resolver3.enumerateMatches(pattern, {
                        onMatch: function (m) {
                            if (m.name.indexOf('SecureStorage') === -1 && m.name.indexOf('FlutterSecure') === -1) return;
                            Interceptor.attach(m.address, {
                                onEnter: function (args) {
                                    try { if (args[2]) this.key = ObjC.Object(args[2]).toString(); } catch (e) { this.key = ""; }
                                },
                                onLeave: function (retval) {
                                    if (!this.key) return;
                                    var spoofVal = keychainSpoofMap[this.key];
                                    if (spoofVal !== undefined && m.name.indexOf("read") !== -1) {
                                        try { retval.replace(ObjC.classes.NSString.stringWithString_(spoofVal)); } catch (e) {}
                                    }
                                }
                            });
                        },
                        onComplete: function () {}
                    });
                } catch (e) {}
            });
            console.log(TAG + ' [X4] SecureStorage ApiResolver');
        } catch (e) {}

        try {
            var SecItemCopyMatchingPtr = findExport("Security", "SecItemCopyMatching");
            if (SecItemCopyMatchingPtr) {
                Interceptor.attach(SecItemCopyMatchingPtr, {
                    onEnter: function (args) { this.query = args[0]; this.result = args[1]; },
                    onLeave: function (retval) {
                        if (retval.toInt32() !== 0) return;
                        try {
                            var queryObj = ObjC.Object(this.query);
                            var svce = queryObj.objectForKey_(ObjC.classes.NSString.stringWithString_("svce"));
                            if (!svce || svce.isNull() || svce.toString().indexOf("flutter_secure") === -1) return;
                            var acct = queryObj.objectForKey_(ObjC.classes.NSString.stringWithString_("acct"));
                            if (!acct || acct.isNull()) return;
                            if (acct.toString() === "ban") {
                                retval.replace(-25300);
                                console.log(TAG + ' [KEYCHAIN] Blocked ban read');
                            }
                        } catch (e) {}
                    }
                });
                console.log(TAG + ' [X4] SecItemCopyMatching');
            }
        } catch (e) {}

        // S7: Sentry + Firebase ObjC hooks
        try {
            var SentrySDK = ObjC.classes.SentrySDK;
            if (SentrySDK) {
                ["+ startWithOptions:", "+ captureEvent:", "+ captureError:",
                 "+ captureMessage:", "+ captureException:", "+ captureEnvelope:"].forEach(function (sel) {
                    try {
                        var m = SentrySDK[sel];
                        if (m) { Interceptor.attach(m.implementation, { onLeave: function (retval) { if (!retval.isNull()) retval.replace(ptr(0x0)); } }); }
                    } catch (e) {}
                });
                console.log(TAG + ' [X4] SentrySDK');
            }
        } catch (e) {}

        try {
            ["FIRCrashlytics", "FIRAnalytics", "FIRCLSReportManager"].forEach(function (cls) {
                var klass = ObjC.classes[cls];
                if (klass) {
                    klass.$ownMethods.forEach(function (method) {
                        var lower = method.toLowerCase();
                        if (lower.indexOf("record") !== -1 || lower.indexOf("crash") !== -1 ||
                            lower.indexOf("log") !== -1 || lower.indexOf("report") !== -1 ||
                            lower.indexOf("send") !== -1) {
                            try { Interceptor.attach(klass[method].implementation, { onLeave: function (retval) {} }); } catch (e) {}
                        }
                    });
                }
            });
            console.log(TAG + ' [X4] Firebase/Crashlytics');
        } catch (e) {}

        // S12 extended: ApiResolver terminate + __pthread_kill deferred
        try {
            var resolver_term = new ApiResolver('objc');
            ['-[* terminateWithReason*]', '-[* terminateApplication*]',
             '-[UIApplication _terminateWithStatus:]'].forEach(function (p) {
                try {
                    resolver_term.enumerateMatches(p, {
                        onMatch: function (m) {
                            Interceptor.attach(m.address, {
                                onEnter: function (args) { args[1] = ObjC.selector("description"); }
                            });
                        },
                        onComplete: function () {}
                    });
                } catch (e) {}
            });
            console.log(TAG + ' [X4] terminate ApiResolver');
        } catch (e) {}

        setTimeout(function () {
            var pthreadKillPtr = findExport(null, "__pthread_kill");
            if (pthreadKillPtr) {
                Interceptor.attach(pthreadKillPtr, {
                    onEnter: function (args) {
                        var sig = args[1].toInt32();
                        if (sig === 5 || sig === 6 || sig === 9 || sig === 15) {
                            console.log(TAG + ' [KILL] blocked __pthread_kill(sig=' + sig + ')');
                            args[1] = ptr(0);
                        }
                    }
                });
                console.log(TAG + ' [X4] __pthread_kill deferred');
            }
        }, 2000);

        // S14 extended: RevenueCat (broader matching)
        try {
            ["RCPurchases", "RCBackend", "RCHTTPClient", "RCDeviceCache", "RCSubscriberAttributesManager"].forEach(function (cls) {
                var klass = ObjC.classes[cls];
                if (klass) {
                    klass.$ownMethods.forEach(function (method) {
                        var lower = method.toLowerCase();
                        if (lower.indexOf("fraud") !== -1 || lower.indexOf("integrity") !== -1 ||
                            lower.indexOf("sandbox") !== -1 || lower.indexOf("verification") !== -1 ||
                            lower.indexOf("diagnostic") !== -1 || lower.indexOf("telemetry") !== -1) {
                            try { Interceptor.attach(klass[method].implementation, { onLeave: function (retval) {} }); } catch (e) {}
                        }
                    });
                }
            });
            console.log(TAG + ' [X4] RevenueCat extended');
        } catch (e) {}

        // abort_with_payload
        try {
            var abp2 = findExport(null, "abort_with_payload");
            if (abp2) { Interceptor.attach(abp2, { onEnter: function () { Thread.sleep(86400); } }); console.log(TAG + ' [X4] abort_with_payload'); }
        } catch (e) {}

        console.log(TAG + ' [X4] Extended ObjC/ApiResolver hooks -- loaded');
    }

    console.log(TAG + ' ==========================================');
    console.log(TAG + ' Bisection ready. Test X1+X2 first.');
    console.log(TAG + ' Crash → narrow X1 vs X2');
    console.log(TAG + ' No crash → enable X3+X4');
    console.log(TAG + ' ==========================================');
})();
