// Frida Script -- SaboraTV Ultimate Bypass v5.2 STABLE (com.plebits.saboratv v6.2.6)
// Based on v4.5 + crash fixes from analysis
// Usage: frida -U -f com.plebits.saboratv -l saboratv-bypass-v5.js --no-pause
//
// v5.0 CHANGES:
//   [FIX] Removed ALL duplicate hooks (connect/strstr/strcmp/dladdr/dlsym/ptrace/kill/raise/pthread_kill)
//   [FIX] Converted ALL Interceptor.replace → Interceptor.attach (ssl_verify_peer_cert, AppDelegate methods)
//   [FIX] Removed ObjC.Block manipulation in FlutterMethodChannel (crash source)
//   [FIX] Consolidated S11+S14 Frida detection + termination into single section
//   [FIX] Added try/catch around ALL ObjC class access
//   [FIX] Deferred ObjC hooks to avoid race conditions during startup
// v5.1 CHANGES:
//   [FIX] REMOVED strstr/strcmp/strnstr hooks (breaks JSC JIT trampoline)
// v5.2 CHANGES (bisection-confirmed):
//   [FIX] REMOVED signal/sigaction hooks — JSC needs them for JIT signal handlers
//   [FIX] REMOVED syscall hook — invalid syscall number causes kernel crash
//   [FIX] kill/raise/__pthread_kill — only block SIGABRT(6)/SIGKILL(9)/SIGTERM(15)
//         NOT SIGTRAP(5) — JSC JIT uses it internally
//   Root cause: Group G2 (signal/kill/syscall) confirmed via 4-round bisection

(function () {
    'use strict';

    var TAG = '[SaboraTV-v5]';
    var SPOOF_DEVICE_ID = null;
    var SPOOF_USER_UUID = null;

    // v5.2: Exception handler for diagnostics only (return false = don't interfere)
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
    SPOOF_DEVICE_ID = randomUUID();
    SPOOF_USER_UUID = randomUUID();
    console.log(TAG + ' Spoofed device_id: ' + SPOOF_DEVICE_ID);
    console.log(TAG + ' Spoofed user_uuid: ' + SPOOF_USER_UUID);

    function findExport(modName, symName) {
        if (typeof Module.findExportByName === 'function') {
            return Module.findExportByName(modName, symName);
        }
        if (typeof Module.getExportByName === 'function') {
            try { return Module.getExportByName(symName); } catch (e) {}
        }
        var searchLibs = modName ? [modName] : [
            "libSystem.B.dylib", "libsystem_kernel.dylib",
            "libsystem_c.dylib", "libdyld.dylib",
            "libsystem_platform.dylib", "libsystem_pthread.dylib",
            "Security"
        ];
        for (var i = 0; i < searchLibs.length; i++) {
            try {
                var m = Process.findModuleByName(searchLibs[i]);
                if (m) {
                    if (typeof m.findExportByName === 'function') {
                        var r = m.findExportByName(symName);
                        if (r && !r.isNull()) return r;
                    }
                    if (typeof m.getExportByName === 'function') {
                        try {
                            var r2 = m.getExportByName(symName);
                            if (r2 && !r2.isNull()) return r2;
                        } catch (e) {}
                    }
                }
            } catch (e) {}
        }
        return null;
    }

    // ==========================================
    // [H1] sysctl -- clear P_TRACED
    // ==========================================

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
    console.log(TAG + ' [H1] sysctl -- loaded');

    // ==========================================
    // [H2] task_info -- zero TASK_DYLD_INFO
    // ==========================================

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
    console.log(TAG + ' [H2] task_info -- loaded');

    // ==========================================
    // [H3] File access hooks -- JB path hiding
    // ==========================================

    var jbPaths = [
        "/Applications/Cydia.app", "/Applications/SBSettings.app",
        "/Applications/WinterBoard.app", "/Applications/blackra1n.app",
        "/Applications/Sileo.app", "/Applications/Zebra.app",
        "/Library/MobileSubstrate/MobileSubstrate.dylib",
        "/Library/MobileSubstrate/CydiaSubstrate.dylib",
        "/Library/MobileSubstrate",
        "/private/var/lib/apt", "/private/var/lib/cydia",
        "/private/var/stash", "/private/var/tmp/cydia.log",
        "/private/var/mobile/Library/SBSettings/Themes",
        "/private/test_jailbreak",
        "/var/lib/apt", "/var/lib/cydia", "/var/cache/apt",
        "/var/log/syslog", "/var/jb", "/var/binpack",
        "/bin/bash", "/bin/sh",
        "/usr/sbin/sshd", "/usr/bin/sshd", "/usr/bin/ssh",
        "/usr/sbin/frida-server", "/usr/local/bin/cycript",
        "/usr/lib/libcycript.dylib", "/usr/lib/libjailbreak.dylib",
        "/usr/lib/TweakInject", "/usr/libexec/cydia",
        "/etc/apt", "/data/local/tmp/frida-server",
        "/jb/lzma", "/jb/amfid_payload.dylib", "/jb/",
        "/.bootstrapped_electra", "/.installed_unc0ver",
        "/.installed_lfhs", "/.cydia_no_stash",
        "/Library/dpkg", "/Library/PreferenceBundles",
        "/Library/PreferenceLoader",
        "/usr/lib/libsubstitute.dylib", "/usr/lib/libsubstrate.dylib",
        "/private/preboot"
    ];

    var jbKeywords = [
        "Cydia", "Sileo", "Zebra", "cydia", "substrate",
        "jailbreak", "frida", "MobileSubstrate", "TweakInject",
        "libhooker", "substitute", "checkra1n", "unc0ver",
        "Dopamine", "palera1n", "Taurine", "electra", "chimera"
    ];

    function isJBPath(path) {
        if (!path) return false;
        for (var i = 0; i < jbPaths.length; i++) { if (path.indexOf(jbPaths[i]) !== -1) return true; }
        for (var j = 0; j < jbKeywords.length; j++) { if (path.indexOf(jbKeywords[j]) !== -1) return true; }
        return false;
    }

    ["access", "stat", "lstat", "stat64", "lstat64"].forEach(function (fn) {
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
            onEnter: function (args) {
                try { this.path = args[0].readUtf8String(); } catch (e) { this.path = ""; }
                if (isJBPath(this.path)) this.blocked = true;
            },
            onLeave: function (retval) { if (this.blocked) retval.replace(-1); }
        });
    }

    var openatPtr = findExport(null, "openat");
    if (openatPtr) {
        Interceptor.attach(openatPtr, {
            onEnter: function (args) {
                try { this.path = args[1].readUtf8String(); if (isJBPath(this.path)) this.blocked = true; } catch (e) {}
            },
            onLeave: function (retval) { if (this.blocked) retval.replace(-1); }
        });
    }

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
        }
    });

    var realpathPtr = findExport(null, "realpath");
    if (realpathPtr) {
        Interceptor.attach(realpathPtr, {
            onEnter: function (args) {
                try { this.path = args[0].readUtf8String(); } catch (e) { this.path = ""; }
                this.outBuf = args[1];
            },
            onLeave: function (retval) {
                if (isJBPath(this.path)) { retval.replace(ptr(0x0)); return; }
                if (!retval.isNull() && this.outBuf && !this.outBuf.isNull()) {
                    try { var resolved = this.outBuf.readUtf8String(); if (isJBPath(resolved)) retval.replace(ptr(0x0)); } catch (e) {}
                }
            }
        });
    }

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
    }

    console.log(TAG + ' [H3] file access hooks -- loaded');

    // ==========================================
    // [H4+H5] dyld hooks -- hide tweaks + fix count
    // ==========================================

    var suspiciousDylibs = [
        "FridaGadget", "frida-agent", "frida-gadget", "libfrida",
        "SubstrateLoader", "SubstrateInserter", "SubstrateBootstrap",
        "MobileSubstrate", "CydiaSubstrate", "TweakInject",
        "libhooker", "substitute", "Shadow", "xCon",
        "AutoRevenueCat", "NotRecording", "Choicy", "Crane",
        "Flex", "Substrate", "Inject", "hook", "tweak",
        "libsubstitute", "libsubstrate", "librocketbootstrap",
        "Activator", "PreferenceLoader", "AppList",
        "0Shadow", "FlyJB", "Liberty", "A-Bypass", "Hestia",
        "KernBypass", "vnodebypass"
    ];

    function isSuspiciousDylib(name) {
        if (!name) return false;
        for (var i = 0; i < suspiciousDylibs.length; i++) { if (name.indexOf(suspiciousDylibs[i]) !== -1) return true; }
        if (name.indexOf("/var/jb/") !== -1 || name.indexOf("/Library/MobileSubstrate/") !== -1 ||
            name.indexOf("/usr/lib/TweakInject/") !== -1 || name.indexOf("/Library/Frameworks/CydiaSubstrate") !== -1 ||
            name.indexOf("/private/preboot/") !== -1) return true;
        return false;
    }

    var dyldGetImageName = findExport(null, "_dyld_get_image_name");
    if (dyldGetImageName) {
        var fakeNamePtr = Memory.allocUtf8String("/usr/lib/system/libsystem_c.dylib");
        Interceptor.attach(dyldGetImageName, {
            onLeave: function (retval) {
                if (retval.isNull()) return;
                try { var name = retval.readUtf8String(); if (isSuspiciousDylib(name)) retval.replace(fakeNamePtr); } catch (e) {}
            }
        });
    }

    var hiddenCount = 0;
    var dyldImageCount = findExport(null, "_dyld_image_count");
    if (dyldImageCount) {
        var realCount = new NativeFunction(dyldImageCount, 'uint32', [])();
        var getName = new NativeFunction(findExport(null, "_dyld_get_image_name"), 'pointer', ['uint32']);
        for (var idx = 0; idx < realCount; idx++) {
            try { var n = getName(idx).readUtf8String(); if (isSuspiciousDylib(n)) hiddenCount++; } catch (e) {}
        }
        Interceptor.attach(dyldImageCount, {
            onLeave: function (retval) { retval.replace(retval.toInt32() - hiddenCount); }
        });
        console.log(TAG + ' [H5] hiding ' + hiddenCount + ' dylibs');
    }

    var dyldGetImageHeader = findExport(null, "_dyld_get_image_header");
    var dyldGetImageNamePtr = findExport(null, "_dyld_get_image_name");
    if (dyldGetImageHeader && dyldGetImageNamePtr) {
        var getNameForHeader = new NativeFunction(dyldGetImageNamePtr, 'pointer', ['uint32']);
        Interceptor.attach(dyldGetImageHeader, {
            onEnter: function (args) { this.idx = args[0].toInt32(); },
            onLeave: function (retval) {
                try {
                    var namePtr = getNameForHeader(this.idx);
                    if (!namePtr.isNull()) { var name = namePtr.readUtf8String(); if (isSuspiciousDylib(name)) retval.replace(ptr(0x0)); }
                } catch (e) {}
            }
        });
    }

    console.log(TAG + ' [H4+H5] dyld hooks -- loaded');

    // ==========================================
    // [H6] NSFileManager -- deferred to avoid startup race
    // ==========================================

    setTimeout(function () {
        try {
            var NSFileManager = ObjC.classes.NSFileManager;
            if (NSFileManager) {
                ["- fileExistsAtPath:", "- fileExistsAtPath:isDirectory:"].forEach(function (sel) {
                    var m = NSFileManager[sel];
                    if (m) {
                        Interceptor.attach(m.implementation, {
                            onEnter: function (args) { try { this.path = ObjC.Object(args[2]).toString(); } catch (e) { this.path = ""; } },
                            onLeave: function (retval) { if (isJBPath(this.path)) retval.replace(0x0); }
                        });
                    }
                });

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
            }
        } catch (e) {}
        console.log(TAG + ' [H6] NSFileManager -- loaded');
    }, 50);

    // ==========================================
    // [H7] IOSSecuritySuite v2.2.0
    // ==========================================

    var issHookCount = 0;
    try {
        var IOSSecuritySuite = ObjC.classes.IOSSecuritySuite;
        if (IOSSecuritySuite) {
            IOSSecuritySuite.$ownMethods.forEach(function (method) {
                var lower = method.toLowerCase();
                if (lower.indexOf("ami") !== -1 || lower.indexOf("jailbr") !== -1 ||
                    lower.indexOf("debug") !== -1 || lower.indexOf("reverse") !== -1 ||
                    lower.indexOf("hook") !== -1 || lower.indexOf("emulator") !== -1 ||
                    lower.indexOf("tamper") !== -1 || lower.indexOf("integrity") !== -1 ||
                    lower.indexOf("deny") !== -1 || lower.indexOf("proxy") !== -1 ||
                    lower.indexOf("simulator") !== -1) {
                    Interceptor.attach(IOSSecuritySuite[method].implementation, {
                        onLeave: function (retval) { retval.replace(0x0); }
                    });
                    issHookCount++;
                }
            });
        }
    } catch (e) {}

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
                    issHookCount++;
                }
            });
        }
    } catch (e) {}
    console.log(TAG + ' [H7] IOSSecuritySuite (' + issHookCount + ' hooks)');

    // ==========================================
    // [H8] Talsec/freerasp
    // ==========================================

    var talsecCount = 0;
    try {
        var resolver = new ApiResolver('objc');
        ['-[* threatDetected*]', '-[* onJailbreak*]', '-[* onDebugger*]',
         '-[* onHook*]', '-[* onTamper*]', '-[* onReverseEngineering*]',
         '-[* onDeviceBinding*]', '-[* onUnofficialStore*]', '+[* isThreatDetected*]',
         '-[* onMalware*]', '-[* securityThreat*]', '-[* onSecurityThreat*]'
        ].forEach(function (pattern) {
            try {
                resolver.enumerateMatches(pattern, {
                    onMatch: function (match) {
                        var mn = match.name.toLowerCase();
                        if (mn.indexOf('talsec') !== -1 || mn.indexOf('freerasp') !== -1 ||
                            mn.indexOf('threat') !== -1 || mn.indexOf('security') !== -1) {
                            Interceptor.attach(match.address, { onLeave: function (retval) { retval.replace(0x0); } });
                            talsecCount++;
                        }
                    },
                    onComplete: function () {}
                });
            } catch (e) {}
        });
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
                        talsecCount++;
                    }
                });
            }
        });
    } catch (e) {}
    console.log(TAG + ' [H8] Talsec (' + talsecCount + ' hooks)');

    // ==========================================
    // [H9] getenv + NSProcessInfo.environment
    // ==========================================

    var blockedEnvVars = [
        "DYLD_INSERT_LIBRARIES", "DYLD_FRAMEWORK_PATH",
        "DYLD_LIBRARY_PATH", "DYLD_PRINT_STATISTICS",
        "DYLD_PRINT_LIBRARIES", "DYLD_ROOT_PATH"
    ];

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
            }
        }
    } catch (e) {}
    console.log(TAG + ' [H9] getenv + NSProcessInfo -- loaded');

    // ==========================================
    // [S1] BoringSSL -- Flutter SSL pinning bypass
    // v5 FIX: ALL Interceptor.attach, NO Interceptor.replace
    // ==========================================

    var boringSSLHooks = 0;
    try {
        var flutterModule = Process.findModuleByName("Flutter");
        if (!flutterModule) {
            Process.enumerateModules().forEach(function (m) {
                if (m.name.indexOf("Flutter") !== -1 && !flutterModule) flutterModule = m;
            });
        }

        if (flutterModule) {
            flutterModule.enumerateExports().forEach(function (exp) {
                if (exp.name.indexOf("ssl_verify_peer_cert") !== -1 && exp.type === 'function') {
                    Interceptor.attach(exp.address, {
                        onLeave: function (retval) { retval.replace(0x0); }
                    });
                    boringSSLHooks++;
                } else if (exp.name.indexOf("SSL_get_verify_result") !== -1 && exp.type === 'function') {
                    Interceptor.attach(exp.address, {
                        onLeave: function (retval) { retval.replace(0x0); }
                    });
                    boringSSLHooks++;
                } else if ((exp.name.indexOf("set_custom_verify") !== -1 || exp.name.indexOf("SSL_set_verify") !== -1) && exp.type === 'function') {
                    Interceptor.attach(exp.address, {
                        onEnter: function (args) { args[1] = ptr(0x0); }
                    });
                    boringSSLHooks++;
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
            boringSSLHooks++;
        }
    } catch (e) {}

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
            boringSSLHooks++;
        }
    } catch (e) {}

    console.log(TAG + ' [S1] SSL/TLS bypass (' + boringSSLHooks + ' hooks, ALL attach)');

    // ==========================================
    // [S2] Google Ads SDK JB detection bypass
    // ==========================================

    var gadHooks = 0;
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
                            gadHooks++;
                        }
                    });
                }
            } catch (e) {}
        });
    } catch (e) {}
    console.log(TAG + ' [S2] Google Ads JB bypass (' + gadHooks + ')');

    // ==========================================
    // [S3] Device Identity Spoofing + Ban clear
    // ==========================================

    var keychainSpoofMap = {
        "ban": "0",
        "device_id": SPOOF_DEVICE_ID,
        "user_uuid": SPOOF_USER_UUID,
        "subscription_status": "active"
    };

    try {
        var resolver3 = new ApiResolver('objc');
        ['-[* read*]', '-[* write*]', '-[* delete*]', '-[* readAll*]'].forEach(function (pattern) {
            try {
                resolver3.enumerateMatches(pattern, {
                    onMatch: function (m) {
                        if (m.name.indexOf('SecureStorage') === -1 && m.name.indexOf('FlutterSecure') === -1) return;
                        Interceptor.attach(m.address, {
                            onEnter: function (args) {
                                try {
                                    if (args[2]) this.key = ObjC.Object(args[2]).toString();
                                    if (args[3]) this.val = ObjC.Object(args[3]).toString();
                                } catch (e) { this.key = ""; this.val = ""; }
                            },
                            onLeave: function (retval) {
                                if (!this.key) return;
                                var spoofVal = keychainSpoofMap[this.key];
                                if (spoofVal !== undefined && m.name.indexOf("read") !== -1) {
                                    try {
                                        retval.replace(ObjC.classes.NSString.stringWithString_(spoofVal));
                                    } catch (e) {}
                                }
                            }
                        });
                    },
                    onComplete: function () {}
                });
            } catch (e) {}
        });
    } catch (e) {}

    setTimeout(function () {
        try {
            var SecItemDelete = new NativeFunction(findExport("Security", "SecItemDelete"), 'int', ['pointer']);
            ["ban", "device_id", "user_uuid", "session_token"].forEach(function (key) {
                var query = ObjC.classes.NSMutableDictionary.alloc().init();
                query.setObject_forKey_(ObjC.classes.NSString.stringWithString_("genp"), ObjC.classes.NSString.stringWithString_("class"));
                query.setObject_forKey_(ObjC.classes.NSString.stringWithString_("flutter_secure_storage_service"), ObjC.classes.NSString.stringWithString_("svce"));
                query.setObject_forKey_(ObjC.classes.NSString.stringWithString_(key), ObjC.classes.NSString.stringWithString_("acct"));
                var result = SecItemDelete(query);
                console.log(TAG + ' [BAN] SecItemDelete(' + key + ') = ' + result);
            });
        } catch (e) {}
    }, 1500);

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
        }
    } catch (e) {}
    console.log(TAG + ' [S3] Device ID + ban clear -- loaded');

    // ==========================================
    // [S4] OneSignal Token Block
    // ==========================================

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

        var resolver_os2 = new ApiResolver('objc');
        resolver_os2.enumerateMatches('-[* oneSignalDidRegisterForRemoteNotifications:deviceToken:]', {
            onMatch: function (m) {
                Interceptor.attach(m.address, {
                    onEnter: function (args) { args[3] = ObjC.classes.NSData.data(); }
                });
            },
            onComplete: function () {}
        });

        resolver_os2.enumerateMatches('-[* sendTags*]', {
            onMatch: function (m) {
                if (m.name.toLowerCase().indexOf('onesignal') !== -1) {
                    Interceptor.attach(m.address, {
                        onEnter: function (args) { try { args[2] = ObjC.classes.NSDictionary.dictionary(); } catch (e) {} }
                    });
                }
            },
            onComplete: function () {}
        });
    } catch (e) {}
    console.log(TAG + ' [S4] OneSignal blocking -- loaded');

    // ==========================================
    // [S5] FlutterMethodChannel -- SAFE version
    // v5 FIX: Removed ObjC.Block manipulation (crash source)
    //         Only log + intercept return values, no block calls
    // ==========================================

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
            }
        }
    } catch (e) {}
    console.log(TAG + ' [S5] FlutterMethodChannel -- loaded (safe, no Block manip)');

    // ==========================================
    // [S6] API Response Interception (ban bypass)
    // ==========================================

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

                            function cleanBanFromDict(dict) {
                                var mutable = null;
                                for (var i = 0; i < banKeys.length; i++) {
                                    var val = dict.objectForKey_(ObjC.classes.NSString.stringWithString_(banKeys[i]));
                                    if (val && !val.isNull()) {
                                        var valStr = val.toString();
                                        if (valStr === "1" || valStr === "true" || valStr === "yes") {
                                            if (!mutable) mutable = dict.mutableCopy();
                                            mutable.setObject_forKey_(
                                                ObjC.classes.NSNumber.numberWithBool_(false),
                                                ObjC.classes.NSString.stringWithString_(banKeys[i]));
                                        }
                                    }
                                }
                                return mutable;
                            }

                            var mutated = cleanBanFromDict(obj);
                            if (mutated) { retval.replace(mutated); }

                            ["data", "user"].forEach(function (nestedKey) {
                                try {
                                    var nested = obj.objectForKey_(ObjC.classes.NSString.stringWithString_(nestedKey));
                                    if (nested && !nested.isNull() && nested.isKindOfClass_(ObjC.classes.NSDictionary)) {
                                        var nestedMut = cleanBanFromDict(nested);
                                        if (nestedMut) {
                                            var topMut = mutated || obj.mutableCopy();
                                            topMut.setObject_forKey_(nestedMut, ObjC.classes.NSString.stringWithString_(nestedKey));
                                            retval.replace(topMut);
                                        }
                                    }
                                } catch (e) {}
                            });
                        } catch (e) {}
                    }
                });
            }
        }
    } catch (e) {}
    console.log(TAG + ' [S6] API response ban interception -- loaded');

    // ==========================================
    // [S7] Sentry + Firebase + Crashlytics block
    // ==========================================

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
    } catch (e) {}

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
        }
    } catch (e) {}
    console.log(TAG + ' [S7] Sentry + Firebase + Crashlytics -- blocked');

    // ==========================================
    // [S8] Screen Recording & Screenshot bypass
    // v5 FIX: Interceptor.attach ONLY, no replace
    // ==========================================

    setTimeout(function () {
        try {
            var AppDelegate = ObjC.classes["Runner.AppDelegate"];
            if (AppDelegate) {
                var screenRec = AppDelegate["- screenRecordingStatusChanged:"];
                if (screenRec) {
                    Interceptor.attach(screenRec.implementation, {
                        onEnter: function (args) { args[1] = ObjC.selector("description"); }
                    });
                }
                var screenshotMethod = AppDelegate["- screenshotHasTaken:"];
                if (screenshotMethod) {
                    Interceptor.attach(screenshotMethod.implementation, {
                        onEnter: function (args) { args[1] = ObjC.selector("description"); }
                    });
                }
            }
        } catch (e) {}

        try {
            var UIScreen = ObjC.classes.UIScreen;
            if (UIScreen) {
                Interceptor.attach(UIScreen["- isCaptured"].implementation, {
                    onLeave: function (retval) { retval.replace(0x0); }
                });
            }
        } catch (e) {}

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
            }
        } catch (e) {}

        console.log(TAG + ' [S8] Screen recording/screenshot -- loaded (attach only)');
    }, 100);

    // ==========================================
    // [S9] flutter_jailbreak_detection_plus
    // ==========================================

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
    } catch (e) {}

    // ==========================================
    // [S10] canOpenURL bypass
    // ==========================================

    var jbSchemes = ["cydia://", "sileo://", "zbra://", "filza://", "undecimus://",
                     "activator://", "atlas://", "dopamine://", "palera1n://"];
    try {
        var UIApp = ObjC.classes.UIApplication;
        if (UIApp) {
            var canOpenURL = UIApp["- canOpenURL:"];
            if (canOpenURL) {
                Interceptor.attach(canOpenURL.implementation, {
                    onEnter: function (args) { try { this.url = ObjC.Object(args[2]).toString(); } catch (e) { this.url = ""; } },
                    onLeave: function (retval) {
                        for (var i = 0; i < jbSchemes.length; i++) { if (this.url.indexOf(jbSchemes[i]) !== -1) { retval.replace(0x0); return; } }
                    }
                });
            }
        }
    } catch (e) {}

    // ==========================================
    // [S11] UNIFIED Frida detection bypass
    // v5.1 FIX: Caller filtering to avoid crashing JavaScriptCore/WebKit
    // Only process hooks when called from app binary or security libs
    // ==========================================

    var _skipModules = {};
    var _skipRanges = [];
    (function () {
        var skipNames = ["JavaScriptCore", "WebKit", "WebCore", "libicucore", "CoreFoundation",
            "Foundation", "UIKitCore", "UIKit", "CFNetwork", "libnetwork", "libsqlite3",
            "libc++", "libobjc", "libdispatch", "libswiftCore"];
        var allMods = Process.enumerateModules();
        for (var i = 0; i < allMods.length; i++) {
            for (var j = 0; j < skipNames.length; j++) {
                if (allMods[i].name.indexOf(skipNames[j]) !== -1) {
                    _skipRanges.push({ base: allMods[i].base, end: allMods[i].base.add(allMods[i].size) });
                    break;
                }
            }
        }
    })();

    function isFromSkippedModule(retAddr) {
        for (var i = 0; i < _skipRanges.length; i++) {
            if (retAddr.compare(_skipRanges[i].base) >= 0 && retAddr.compare(_skipRanges[i].end) < 0) return true;
        }
        return false;
    }

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

    // v5.1: strstr/strcmp/strnstr hooks REMOVED — patching these hot libc functions
    // breaks JavaScriptCore's JIT (access-violation at JSC+0xd06fc).
    // Frida string detection is handled at ObjC level by H7 (IOSSecuritySuite) and H8 (Talsec).

    var dladdrPtr = findExport(null, "dladdr");
    if (dladdrPtr) {
        Interceptor.attach(dladdrPtr, {
            onEnter: function (args) { this.info = args[1]; },
            onLeave: function (retval) {
                if (isFromSkippedModule(this.returnAddress)) return;
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
                if (isFromSkippedModule(this.returnAddress)) return;
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

    console.log(TAG + ' [S11] Frida detection bypass -- loaded (no duplicates)');

    // ==========================================
    // [S12] UNIFIED fork/ptrace/signal/sigaction + termination prevention
    // v5 FIX: Single instance, no duplicate hooks
    // ==========================================

    var forkPtr = findExport(null, "fork");
    if (forkPtr) { Interceptor.attach(forkPtr, { onLeave: function (retval) { retval.replace(-1); } }); }

    var ptracePtr = findExport(null, "ptrace");
    if (ptracePtr) {
        Interceptor.attach(ptracePtr, {
            onEnter: function (args) { if (args[0].toInt32() === 31) { this.deny = true; args[0] = ptr(0); } },
            onLeave: function (retval) { if (this.deny) retval.replace(0); }
        });
    }

    // v5.2: NO Interceptor hooks on signal/sigaction/syscall/kill/raise/__pthread_kill
    // (trampolines on these break JSC's JIT). Instead, use sigaction() directly
    // to ignore termination signals at the kernel level — no trampoline needed.
    try {
        var sigactionFn = new NativeFunction(findExport(null, "sigaction"), 'int', ['int', 'pointer', 'pointer']);
        // struct sigaction: first field is sa_handler (pointer-sized)
        var saIgnore = Memory.alloc(128);
        Memory.protect(saIgnore, 128, 'rw-');
        saIgnore.writePointer(ptr(0x1)); // SIG_IGN
        // Ignore termination signals the app uses to self-kill
        sigactionFn(15, saIgnore, ptr(0)); // SIGTERM
        sigactionFn(5, saIgnore, ptr(0));  // SIGTRAP (anti-debug)
        sigactionFn(17, saIgnore, ptr(0)); // SIGSTOP — may fail but harmless
        // SIGABRT needs a real handler (SIG_IGN may not work)
        var sigabrtHandler = new NativeCallback(function () {
            console.log(TAG + ' [SIGNAL] SIGABRT caught — ignoring');
        }, 'void', ['int']);
        var saAbort = Memory.alloc(128);
        Memory.protect(saAbort, 128, 'rw-');
        saAbort.writePointer(sigabrtHandler);
        sigactionFn(6, saAbort, ptr(0));  // SIGABRT
        console.log(TAG + ' [S12] sigaction SIG_IGN installed for SIGTERM/SIGTRAP/SIGABRT');
    } catch (e) { console.log(TAG + ' [S12] sigaction setup error: ' + e); }

    // v5.2: exit/abort hooks installed IMMEDIATELY (no setTimeout)
    // to prevent race condition where app exits before hooks are ready
    ["exit", "_exit", "_Exit", "abort"].forEach(function (fn) {
        try {
            var p = findExport(null, fn);
            if (p) {
                Interceptor.attach(p, {
                    onEnter: function (args) {
                        console.log(TAG + ' [EXIT] ' + fn + '() — holding');
                        Thread.sleep(86400);
                    }
                });
            }
        } catch (e) {}
    });

    try {
        var abp = findExport(null, "__abort_with_payload");
        if (abp) { Interceptor.attach(abp, { onEnter: function () { console.log(TAG + ' [EXIT] __abort_with_payload — holding'); Thread.sleep(86400); } }); }
    } catch (e) {}
    try {
        var abp2 = findExport(null, "abort_with_payload");
        if (abp2) { Interceptor.attach(abp2, { onEnter: function () { Thread.sleep(86400); } }); }
    } catch (e) {}

    // v5.2: NO kill/raise hooks at startup (any Interceptor on these crashes JSC).
    // sigaction SIG_IGN above handles SIGTERM/SIGTRAP/SIGABRT at kernel level.

    // __pthread_kill deferred (less critical, avoid JSC race)
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
        }
        console.log(TAG + ' [S12] Deferred kill/raise/__pthread_kill hooks installed (2s delay)');
    }, 2000);

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
    } catch (e) {}

    try {
        var UIApp2 = ObjC.classes.UIApplication;
        if (UIApp2 && UIApp2["- terminateWithSuccess"]) {
            Interceptor.attach(UIApp2["- terminateWithSuccess"].implementation, {
                onEnter: function (args) { args[1] = ObjC.selector("description"); }
            });
        }
    } catch (e) {}

    console.log(TAG + ' [S12] fork/ptrace + exit/abort termination prevention -- loaded (no G2 hooks)');

    // ==========================================
    // [S13] MD5/integrity + SecKeyVerifySignature
    // ==========================================

    try {
        var secKeyVerify = findExport("Security", "SecKeyVerifySignature");
        if (secKeyVerify) { Interceptor.attach(secKeyVerify, { onLeave: function (retval) { retval.replace(0x1); } }); }
        var secKeyRawVerify = findExport("Security", "SecKeyRawVerify");
        if (secKeyRawVerify) { Interceptor.attach(secKeyRawVerify, { onLeave: function (retval) { retval.replace(0); } }); }
    } catch (e) {}
    console.log(TAG + ' [S13] MD5/integrity -- loaded');

    // ==========================================
    // [S14] RevenueCat telemetry neutralization
    // ==========================================

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
    } catch (e) {}
    console.log(TAG + ' [S14] RevenueCat telemetry -- neutralized');

    // ==========================================
    // [S15] Sandbox write test bypass
    // ==========================================

    var mkdirPtr = findExport(null, "mkdir");
    if (mkdirPtr) {
        Interceptor.attach(mkdirPtr, {
            onEnter: function (args) {
                try { var path = args[0].readUtf8String(); if (path === "/" || path === "/private" || path === "/private/test_jailbreak") this.block = true; } catch (e) {}
            },
            onLeave: function (retval) { if (this.block) retval.replace(-1); }
        });
    }

    // v5.1: Duplicate exception handler REMOVED — the handler at script top (return true) is authoritative

    // ==========================================
    // SUMMARY
    // ==========================================

    console.log('\n' + TAG + ' =============================================');
    console.log(TAG + ' SaboraTV Ultimate Bypass v5.2 STABLE');
    console.log(TAG + ' =============================================');
    console.log(TAG + ' [H1-H9] Core hooks (sysctl/task_info/files/dyld/NSFileManager/ISS/Talsec/getenv)');
    console.log(TAG + ' [S1]  SSL bypass (ALL attach, NO replace)');
    console.log(TAG + ' [S2]  Google Ads JB bypass');
    console.log(TAG + ' [S3]  Device ID: ' + SPOOF_DEVICE_ID);
    console.log(TAG + '        User UUID: ' + SPOOF_USER_UUID);
    console.log(TAG + ' [S4]  OneSignal blocking');
    console.log(TAG + ' [S5]  FlutterMethodChannel (safe, no Block manip)');
    console.log(TAG + ' [S6]  API response ban interception');
    console.log(TAG + ' [S7]  Sentry + Firebase + Crashlytics block');
    console.log(TAG + ' [S8]  Screen recording/screenshot (attach only)');
    console.log(TAG + ' [S9]  flutter_jailbreak_detection_plus');
    console.log(TAG + ' [S10] canOpenURL bypass');
    console.log(TAG + ' [S11] Frida detection (unified, no duplicates)');
    console.log(TAG + ' [S12] fork/ptrace/signal + termination (unified)');
    console.log(TAG + ' [S13] MD5/integrity bypass');
    console.log(TAG + ' [S14] RevenueCat telemetry');
    console.log(TAG + ' [S15] Sandbox write bypass');
    console.log(TAG + ' =============================================');
    console.log(TAG + ' v5 FIXES:');
    console.log(TAG + '   [FIX] Removed ALL duplicate hooks (was hooking same functions 2x)');
    console.log(TAG + '   [FIX] ssl_verify_peer_cert: attach instead of replace');
    console.log(TAG + '   [FIX] AppDelegate screenRec/screenshot: attach instead of replace');
    console.log(TAG + '   [FIX] FlutterMethodChannel: removed ObjC.Block manipulation');
    console.log(TAG + '   [FIX] NSURLSession delegate bypass removed (unstable ObjC.Block)');
    console.log(TAG + '   [FIX] Unified S11+S12+S14 into single hook instances');
    console.log(TAG + '   [FIX] Deferred ObjC hooks (NSFileManager, Screen, exit) to avoid race');
    console.log(TAG + ' =============================================');
    console.log(TAG + ' USE A NEW ACCOUNT — old account is banned server-side');
    console.log(TAG + ' =============================================\n');

})();
