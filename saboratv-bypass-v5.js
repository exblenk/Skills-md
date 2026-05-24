// SaboraTV Ultimate Bypass v5.3 STABLE (com.plebits.saboratv v6.2.6)
// Built from bisection-confirmed safe hooks (BASE+X1+X2+X3 all passed)
// X4 crash source identified: ISS/Talsec exports + broader $ownMethods crash libswiftCore
// Safe X4 hooks (SecItemCopyMatching, SecureStorage, Sentry/Firebase ObjC) included
//
// Usage: frida -U -f com.plebits.saboratv -l saboratv-bypass-v5.js --no-pause

(function () {
    'use strict';

    var TAG = '[SaboraTV-v5.3]';

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
    console.log(TAG + ' Spoofed device_id: ' + SPOOF_DEVICE_ID);
    console.log(TAG + ' Spoofed user_uuid: ' + SPOOF_USER_UUID);

    function findExport(modName, symName) {
        if (typeof Module.findExportByName === 'function') {
            return Module.findExportByName(modName, symName);
        }
        try { return Module.getExportByName(symName); } catch (e) {}
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

    var realpathPtr = findExport(null, "realpath$DARWIN_EXTSN");
    if (!realpathPtr) realpathPtr = findExport(null, "realpath");
    if (realpathPtr) {
        Interceptor.attach(realpathPtr, {
            onEnter: function (args) { try { this.path = args[0].readUtf8String(); } catch (e) { this.path = ""; } },
            onLeave: function (retval) { if (isJBPath(this.path)) retval.replace(ptr(0x0)); }
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

    console.log(TAG + ' [H4+H5] dyld hooks -- loaded');

    // ==========================================
    // [H6] NSFileManager -- deferred
    // ==========================================
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
        console.log(TAG + ' [H6] NSFileManager -- loaded');
    }, 50);

    // ==========================================
    // [H7] IOSSecuritySuite — ObjC class methods + $ownMethods
    // v5.3: NO module exports (crash libSwiftCore) — ObjC-level only
    // ==========================================
    var issCount = 0;
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
                    try {
                        Interceptor.attach(IOSSecuritySuite[method].implementation, {
                            onLeave: function (retval) { retval.replace(0x0); }
                        });
                        issCount++;
                    } catch (e) {}
                }
            });
        }
    } catch (e) {}
    try {
        var resolver_iss = new ApiResolver('objc');
        ['+[* amIJailbroken*]', '+[* amIDebugged*]', '+[* amIReverseEngineered*]',
         '+[* amIRunInEmulator*]', '+[* amIRuntimeHooked*]', '+[* amITampered*]',
         '+[* amIProxied*]', '+[* denyDebugger*]', '+[* denySymbolHook*]'].forEach(function (p) {
            try {
                resolver_iss.enumerateMatches(p, {
                    onMatch: function (m) {
                        if (m.name.indexOf('SecuritySuite') !== -1 || m.name.indexOf('Security') !== -1) {
                            try { Interceptor.attach(m.address, { onLeave: function (retval) { retval.replace(0x0); } }); issCount++; } catch (e) {}
                        }
                    },
                    onComplete: function () {}
                });
            } catch (e) {}
        });
    } catch (e) {}
    console.log(TAG + ' [H7] IOSSecuritySuite (' + issCount + ' hooks, ObjC only)');

    // ==========================================
    // [H8] Talsec/freerasp — class methods + ApiResolver (ObjC-level)
    // v5.3: NO module exports (crash libSwiftCore) — ObjC-level only
    // ==========================================
    var talsecCount = 0;
    try {
        ["SecurityThreatCenter", "TalsecRuntime", "FreeraspFlutterPlugin"].forEach(function (cls) {
            try {
                var klass = ObjC.classes[cls];
                if (klass) {
                    klass.$ownMethods.forEach(function (method) {
                        try { Interceptor.attach(klass[method].implementation, { onLeave: function (retval) {} }); talsecCount++; } catch (e) {}
                    });
                }
            } catch (e) {}
        });
    } catch (e) {}
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
                            try { Interceptor.attach(match.address, { onLeave: function (retval) { retval.replace(0x0); } }); talsecCount++; } catch (e) {}
                        }
                    },
                    onComplete: function () {}
                });
            } catch (e) {}
        });
    } catch (e) {}
    console.log(TAG + ' [H8] Talsec (' + talsecCount + ' hooks, ObjC+ApiResolver)');

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
    // ==========================================
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
                    Interceptor.attach(exp.address, { onLeave: function (retval) { retval.replace(0x0); } });
                } else if (exp.name.indexOf("SSL_get_verify_result") !== -1 && exp.type === 'function') {
                    Interceptor.attach(exp.address, { onLeave: function (retval) { retval.replace(0x0); } });
                } else if ((exp.name.indexOf("set_custom_verify") !== -1 || exp.name.indexOf("SSL_set_verify") !== -1) && exp.type === 'function') {
                    Interceptor.attach(exp.address, { onEnter: function (args) { args[1] = ptr(0x0); } });
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
        }
    } catch (e) {}
    console.log(TAG + ' [S1] SSL/TLS bypass -- loaded');

    // ==========================================
    // [S2] Google Ads SDK JB detection bypass
    // ==========================================
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
                            Interceptor.attach(klass[method].implementation, { onLeave: function (retval) { retval.replace(0x0); } });
                        }
                    });
                }
            } catch (e) {}
        });
    } catch (e) {}
    console.log(TAG + ' [S2] Google Ads JB bypass -- loaded');

    // ==========================================
    // [S3] Device Identity Spoofing + Ban clear + Keychain interception
    // ==========================================
    var keychainSpoofMap = {
        "ban": "0",
        "device_id": SPOOF_DEVICE_ID,
        "user_uuid": SPOOF_USER_UUID,
        "subscription_status": "active"
    };

    // SecItemCopyMatching — block ban reads
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

    // SecureStorage ApiResolver — spoof reads
    try {
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
    } catch (e) {}

    // Ban clear — delete ban keys from keychain
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

    console.log(TAG + ' [S3] Device ID + ban clear + keychain interception -- loaded');

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
                    Interceptor.attach(m.address, { onEnter: function (args) { args[2] = ObjC.classes.NSNull._null(); } });
                }
            },
            onComplete: function () {}
        });
        resolver_os.enumerateMatches('-[* oneSignalDidRegisterForRemoteNotifications:deviceToken:]', {
            onMatch: function (m) {
                Interceptor.attach(m.address, { onEnter: function (args) { args[3] = ObjC.classes.NSData.data(); } });
            },
            onComplete: function () {}
        });
        resolver_os.enumerateMatches('-[* sendTags*]', {
            onMatch: function (m) {
                if (m.name.toLowerCase().indexOf('onesignal') !== -1) {
                    Interceptor.attach(m.address, { onEnter: function (args) { try { args[2] = ObjC.classes.NSDictionary.dictionary(); } catch (e) {} } });
                }
            },
            onComplete: function () {}
        });
    } catch (e) {}
    console.log(TAG + ' [S4] OneSignal blocking -- loaded');

    // ==========================================
    // [S5] FlutterMethodChannel -- SAFE version
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
    console.log(TAG + ' [S5] FlutterMethodChannel -- loaded');

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
                            ["data", "user"].forEach(function (nestedKey) {
                                try {
                                    var nested = obj.objectForKey_(ObjC.classes.NSString.stringWithString_(nestedKey));
                                    if (nested && !nested.isNull() && nested.isKindOfClass_(ObjC.classes.NSDictionary)) {
                                        var nestedMut = null;
                                        for (var i = 0; i < banKeys.length; i++) {
                                            var val2 = nested.objectForKey_(ObjC.classes.NSString.stringWithString_(banKeys[i]));
                                            if (val2 && !val2.isNull()) {
                                                var valStr2 = val2.toString();
                                                if (valStr2 === "1" || valStr2 === "true" || valStr2 === "yes") {
                                                    if (!nestedMut) nestedMut = nested.mutableCopy();
                                                    nestedMut.setObject_forKey_(ObjC.classes.NSNumber.numberWithBool_(false),
                                                        ObjC.classes.NSString.stringWithString_(banKeys[i]));
                                                }
                                            }
                                        }
                                        if (nestedMut) {
                                            var topMut = mutable || obj.mutableCopy();
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
    // ==========================================
    setTimeout(function () {
        try {
            var AppDelegate = ObjC.classes.AppDelegate;
            if (AppDelegate) {
                var sr = AppDelegate["- screenRecordingStatusChanged"];
                if (sr) Interceptor.attach(sr.implementation, { onEnter: function () { return; } });
                var ss = AppDelegate["- screenshotHasTaken"];
                if (ss) Interceptor.attach(ss.implementation, { onEnter: function () { return; } });
            }
        } catch (e) {}
        try {
            var UIScreen = ObjC.classes.UIScreen;
            if (UIScreen && UIScreen["- isCaptured"]) {
                Interceptor.attach(UIScreen["- isCaptured"].implementation, { onLeave: function (retval) { retval.replace(0x0); } });
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
        console.log(TAG + ' [S8] Screen recording/screenshot -- loaded');
    }, 100);

    // ==========================================
    // [S9] flutter_jailbreak_detection_plus
    // ==========================================
    try {
        var ApiProvider = ObjC.classes["flutter_jailbreak_detection_plus.SwiftFlutterJailbreakDetectionPlusPlugin"];
        if (!ApiProvider) ApiProvider = ObjC.classes["SwiftFlutterJailbreakDetectionPlusPlugin"];
        if (ApiProvider) {
            ApiProvider.$ownMethods.forEach(function (method) {
                try { Interceptor.attach(ApiProvider[method].implementation, { onLeave: function (retval) {} }); } catch (e) {}
            });
        }
    } catch (e) {}
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
    console.log(TAG + ' [S9] flutter_jailbreak_detection_plus -- loaded');

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
    console.log(TAG + ' [S10] canOpenURL bypass -- loaded');

    // ==========================================
    // [S11] Frida detection bypass
    // ==========================================
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
    console.log(TAG + ' [S11] Frida detection bypass -- loaded');

    // ==========================================
    // [S12] fork/ptrace + termination prevention
    // v5.3: NO signal/sigaction/kill/raise/__pthread_kill hooks (crash JSC/libSwiftCore)
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

    // sigaction SIG_IGN (kernel-level, no trampoline)
    try {
        var sigactionFn = new NativeFunction(findExport(null, "sigaction"), 'int', ['int', 'pointer', 'pointer']);
        var saIgnore = Memory.alloc(128);
        saIgnore.writePointer(ptr(0x1));
        sigactionFn(15, saIgnore, ptr(0)); // SIGTERM
        sigactionFn(5, saIgnore, ptr(0));  // SIGTRAP
        var sigabrtHandler = new NativeCallback(function () {
            console.log(TAG + ' [SIGNAL] SIGABRT caught');
        }, 'void', ['int']);
        var saAbort = Memory.alloc(128);
        saAbort.writePointer(sigabrtHandler);
        sigactionFn(6, saAbort, ptr(0));   // SIGABRT
    } catch (e) {}

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

    // ObjC termination prevention
    setTimeout(function () {
        try {
            var UIApp2 = ObjC.classes.UIApplication;
            if (UIApp2 && UIApp2["- terminateWithSuccess"]) {
                Interceptor.attach(UIApp2["- terminateWithSuccess"].implementation, {
                    onEnter: function () { console.log(TAG + ' [EXIT] terminateWithSuccess blocked'); Thread.sleep(86400); }
                });
            }
        } catch (e) {}
    }, 100);

    console.log(TAG + ' [S12] fork/ptrace + termination prevention -- loaded');

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
    // [S14] RevenueCat telemetry (basic only)
    // ==========================================
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
    console.log(TAG + ' [S14] RevenueCat -- loaded');

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
    console.log(TAG + ' [S15] Sandbox write bypass -- loaded');

    // ==========================================
    // SUMMARY
    // ==========================================
    console.log('\n' + TAG + ' =============================================');
    console.log(TAG + ' SaboraTV Ultimate Bypass v5.3 STABLE');
    console.log(TAG + ' Built from bisection-confirmed safe hooks');
    console.log(TAG + ' =============================================');
    console.log(TAG + ' Device ID: ' + SPOOF_DEVICE_ID);
    console.log(TAG + ' User UUID: ' + SPOOF_USER_UUID);
    console.log(TAG + ' =============================================');
    console.log(TAG + ' v5.3 FIXES (from v5.2):');
    console.log(TAG + '   REMOVED: ISS module exports (crash libSwiftCore)');
    console.log(TAG + '   REMOVED: Talsec module exports (crash libSwiftCore)');
    console.log(TAG + '   ADDED: ISS $ownMethods + ApiResolver (ObjC safe)');
    console.log(TAG + '   ADDED: Talsec ApiResolver (ObjC safe)');
    console.log(TAG + '   REMOVED: __pthread_kill hook (crash JSC)');
    console.log(TAG + '   ADDED: SecItemCopyMatching ban block');
    console.log(TAG + '   ADDED: SecureStorage ApiResolver spoof');
    console.log(TAG + '   ADDED: Sentry/Firebase ObjC + URL blocking');
    console.log(TAG + ' =============================================');
    console.log(TAG + ' USE A NEW ACCOUNT — old account banned server-side');
    console.log(TAG + ' =============================================\n');
})();
