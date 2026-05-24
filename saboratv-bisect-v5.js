// SaboraTV v5 Bisection Script — Find which hook group crashes JavaScriptCore
// Usage: frida -U -f com.plebits.saboratv -l saboratv-bisect-v5.js --no-pause
//
// Toggle groups ON/OFF below. Start with all OFF, enable half at a time.
// Round 1: Enable A-D, keep E-H off. If crash → problem in A-D. If no crash → E-H.
// Round 2: Narrow to 2 groups. Round 3: Single group. Round 4: Individual hook.

(function () {
    'use strict';

    // ============ TOGGLE GROUPS ============
    // ROUND 4: All safe groups ON + G split into G1(safe) vs G2(risky)
    var ENABLE_A = true;   // SAFE
    var ENABLE_B = true;   // SAFE
    var ENABLE_C = true;   // SAFE
    var ENABLE_D = true;   // SAFE
    var ENABLE_E = true;   // SAFE
    var ENABLE_F = true;   // SAFE
    var ENABLE_G = true;   // ON — but G is now split internally (see G1/G2 below)
    var ENABLE_H = true;   // SAFE (ObjC-level)
    // G sub-split:
    var ENABLE_G1 = true;  // fork + ptrace + exit/abort (anti-termination)
    var ENABLE_G2 = false; // signal + sigaction + kill + raise + __pthread_kill + syscall
    // ========================================
    // ========================================

    var TAG = '[BISECT-v5]';

    console.log(TAG + ' ==========================================');
    console.log(TAG + ' Groups: A=' + ENABLE_A + ' B=' + ENABLE_B + ' C=' + ENABLE_C + ' D=' + ENABLE_D);
    console.log(TAG + '         E=' + ENABLE_E + ' F=' + ENABLE_F + ' G=' + ENABLE_G + ' H=' + ENABLE_H);
    if (ENABLE_G) console.log(TAG + '         G1=' + ENABLE_G1 + ' (fork/ptrace/exit) G2=' + ENABLE_G2 + ' (signal/kill/syscall)');
    console.log(TAG + ' ==========================================');

    Process.setExceptionHandler(function (details) {
        if (details.type === 'access-violation') {
            try {
                var pc = details.context.pc;
                var mod = Process.findModuleByAddress(pc);
                var modName = mod ? mod.name + '+0x' + pc.sub(mod.base).toString(16) : pc;
                console.log(TAG + ' [CRASH] ' + details.type + ' at ' + modName);
            } catch (e) {}
            return false;
        }
        return false;
    });

    function findExport(modName, symName) {
        if (typeof Module.findExportByName === 'function') {
            return Module.findExportByName(modName, symName);
        }
        try { return Module.getExportByName(symName); } catch (e) {}
        return null;
    }

    // ============ GROUP A: sysctl + task_info ============
    if (ENABLE_A) {
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
        console.log(TAG + ' [A] sysctl + task_info -- loaded');
    }

    // ============ GROUP B: file access hooks ============
    if (ENABLE_B) {
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

        function isJbPath(path) {
            if (!path) return false;
            for (var i = 0; i < jbPaths.length; i++) { if (path.indexOf(jbPaths[i]) !== -1) return true; }
            return false;
        }

        ["access", "stat", "lstat"].forEach(function (fn) {
            var p = findExport(null, fn);
            if (p) {
                Interceptor.attach(p, {
                    onEnter: function (args) { try { if (isJbPath(args[0].readUtf8String())) this.hide = true; } catch (e) {} },
                    onLeave: function (retval) { if (this.hide) retval.replace(-1); }
                });
            }
        });

        var fopenPtr = findExport(null, "fopen");
        if (fopenPtr) {
            Interceptor.attach(fopenPtr, {
                onEnter: function (args) { try { if (isJbPath(args[0].readUtf8String())) this.hide = true; } catch (e) {} },
                onLeave: function (retval) { if (this.hide) retval.replace(ptr(0x0)); }
            });
        }

        var openPtr = findExport(null, "open");
        if (openPtr) {
            Interceptor.attach(openPtr, {
                onEnter: function (args) { try { if (isJbPath(args[0].readUtf8String())) this.hide = true; } catch (e) {} },
                onLeave: function (retval) { if (this.hide) retval.replace(-1); }
            });
        }

        var openatPtr = findExport(null, "openat");
        if (openatPtr) {
            Interceptor.attach(openatPtr, {
                onEnter: function (args) { try { if (isJbPath(args[1].readUtf8String())) this.hide = true; } catch (e) {} },
                onLeave: function (retval) { if (this.hide) retval.replace(-1); }
            });
        }

        var realpathPtr = findExport(null, "realpath$DARWIN_EXTSN");
        if (!realpathPtr) realpathPtr = findExport(null, "realpath");
        if (realpathPtr) {
            Interceptor.attach(realpathPtr, {
                onEnter: function (args) { try { if (isJbPath(args[0].readUtf8String())) this.hide = true; } catch (e) {} },
                onLeave: function (retval) { if (this.hide) retval.replace(ptr(0x0)); }
            });
        }
        console.log(TAG + ' [B] file access hooks -- loaded');
    }

    // ============ GROUP C: dyld image hooks ============
    if (ENABLE_C) {
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
                    var real = retval.toInt32(); var hiddenCount = 0;
                    for (var i = 0; i < real; i++) { try { var n = getName(i).readUtf8String(); if (isSuspiciousDylib(n)) hiddenCount++; } catch (e) {} }
                    if (hiddenCount > 0) retval.replace(real - hiddenCount);
                }
            });
        }

        var dyldGetImageHeader = findExport(null, "_dyld_get_image_header");
        if (dyldGetImageHeader) {
            Interceptor.attach(dyldGetImageHeader, {
                onLeave: function (retval) {
                    if (!retval.isNull()) {
                        try {
                            var namePtr = new NativeFunction(findExport(null, "_dyld_get_image_name"), 'pointer', ['int']);
                        } catch (e) {}
                    }
                }
            });
        }
        console.log(TAG + ' [C] dyld hooks -- loaded');
    }

    // ============ GROUP D: getenv ============
    if (ENABLE_D) {
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
        console.log(TAG + ' [D] getenv -- loaded');
    }

    // ============ GROUP E: SSL/TLS ============
    if (ENABLE_E) {
        var sslNames = ["ssl_verify_peer_cert", "ssl_verify_server_cert_chain"];
        sslNames.forEach(function (name) {
            try {
                var addr = findExport("libboringssl.dylib", name);
                if (addr) { Interceptor.attach(addr, { onLeave: function (retval) { retval.replace(0x0); } }); }
            } catch (e) {}
        });

        try {
            var secTrustEvalErr = findExport("Security", "SecTrustEvaluateWithError");
            if (secTrustEvalErr) {
                Interceptor.attach(secTrustEvalErr, {
                    onLeave: function (retval) { retval.replace(0x1); if (!this.errPtr.isNull()) this.errPtr.writePointer(ptr(0x0)); }
                });
            }
        } catch (e) {}
        console.log(TAG + ' [E] SSL/TLS -- loaded');
    }

    // ============ GROUP F: connect + dladdr + dlsym + dlopen ============
    if (ENABLE_F) {
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
                onLeave: function (retval) {
                    if (retval.toInt32() !== 0) {
                        try {
                            var info = this.context; // not perfect but safe
                        } catch (e) {}
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
                            if (path && (path.indexOf("frida") !== -1 || path.indexOf("substrate") !== -1 ||
                                path.indexOf("TweakInject") !== -1)) {
                                this.fakePath = Memory.allocUtf8String("/dev/null");
                                args[0] = this.fakePath;
                            }
                        } catch (e) {}
                    }
                }
            });
        }
        console.log(TAG + ' [F] connect+dladdr+dlsym+dlopen -- loaded');
    }

    // ============ GROUP G: split into G1 (safe) and G2 (risky) ============
    if (ENABLE_G) {

        // G1: fork + ptrace + exit/abort (anti-termination basics)
        if (ENABLE_G1) {
            var forkPtr = findExport(null, "fork");
            if (forkPtr) { Interceptor.attach(forkPtr, { onLeave: function (retval) { retval.replace(-1); } }); }

            var ptracePtr = findExport(null, "ptrace");
            if (ptracePtr) {
                Interceptor.attach(ptracePtr, {
                    onEnter: function (args) { if (args[0].toInt32() === 31) { this.deny = true; args[0] = ptr(0); } },
                    onLeave: function (retval) { if (this.deny) retval.replace(0); }
                });
            }

            setTimeout(function () {
                ["exit", "_exit", "_Exit", "abort"].forEach(function (fn) {
                    try {
                        var p = findExport(null, fn);
                        if (p) { Interceptor.attach(p, { onEnter: function () { console.log(TAG + ' [EXIT] ' + fn + '() blocked'); Thread.sleep(86400); } }); }
                    } catch (e) {}
                });
            }, 100);

            console.log(TAG + ' [G1] fork+ptrace+exit -- loaded');
        }

        // G2: signal + sigaction + kill + raise + __pthread_kill + syscall
        if (ENABLE_G2) {
            try {
                var signalPtr = findExport(null, "signal");
                if (signalPtr) {
                    Interceptor.attach(signalPtr, {
                        onEnter: function (args) { var sig = args[0].toInt32(); if (sig === 5 || sig === 17) args[1] = ptr(0x1); }
                    });
                }
                var sigactionPtr = findExport(null, "sigaction");
                if (sigactionPtr) {
                    Interceptor.attach(sigactionPtr, {
                        onEnter: function (args) { if (args[0].toInt32() === 5) this.blocked = true; },
                        onLeave: function (retval) { if (this.blocked) retval.replace(0); }
                    });
                }
            } catch (e) {}

            var getpidPtr = findExport(null, "getpid");
            var myPid = 0;
            if (getpidPtr) { try { myPid = new NativeFunction(getpidPtr, 'int', [])(); } catch (e) {} }

            var killPtr = findExport(null, "kill");
            if (killPtr) {
                Interceptor.attach(killPtr, {
                    onEnter: function (args) {
                        var pid = args[0].toInt32();
                        if (pid === myPid || pid === 0 || pid === -1) { args[0] = ptr(-99); args[1] = ptr(0); }
                    }
                });
            }

            var raisePtr = findExport(null, "raise");
            if (raisePtr) {
                Interceptor.attach(raisePtr, {
                    onEnter: function (args) { var sig = args[0].toInt32(); if (sig === 5 || sig === 6 || sig === 9 || sig === 15) args[0] = ptr(0); }
                });
            }

            var pthreadKillPtr = findExport(null, "__pthread_kill");
            if (pthreadKillPtr) {
                Interceptor.attach(pthreadKillPtr, {
                    onEnter: function (args) { var sig = args[1].toInt32(); if (sig === 5 || sig === 6 || sig === 9 || sig === 15) args[1] = ptr(0); }
                });
            }

            try {
                var syscallPtr = findExport(null, "syscall");
                if (syscallPtr) {
                    Interceptor.attach(syscallPtr, {
                        onEnter: function (args) { var num = args[0].toInt32(); if (num === 1 || num === 37) args[0] = ptr(999999); }
                    });
                }
            } catch (e) {}

            console.log(TAG + ' [G2] signal+kill+raise+syscall -- loaded');
        }

        console.log(TAG + ' [G] fork/ptrace/signal/kill/syscall -- loaded');
    }

    // ============ GROUP H: ObjC-level hooks (ISS, Talsec, Keychain, etc.) ============
    if (ENABLE_H) {
        // H6: NSFileManager
        setTimeout(function () {
            try {
                var NSFileManager = ObjC.classes.NSFileManager;
                if (NSFileManager) {
                    var fm = NSFileManager["- fileExistsAtPath:"];
                    if (fm) { Interceptor.attach(fm.implementation, { onLeave: function (retval) { /* minimal */ } }); }
                }
            } catch (e) {}
            console.log(TAG + ' [H] NSFileManager -- loaded');
        }, 50);

        // H7: IOSSecuritySuite
        try {
            var IOSSecuritySuite = ObjC.classes.IOSSecuritySuite;
            if (IOSSecuritySuite) {
                var issMethods = ["amIJailbroken", "amIJailbrokenWithFailMessage", "amIJailbrokenWithFailedChecks",
                    "amIRunInEmulator", "amIDebugged", "amIReverseEngineered", "amIProxied",
                    "amITampered:", "amIRuntimeHooked:", "denyDebugger", "denySymbolHook:",
                    "amIJailbrokenWithFailedChecksWithFailedJailbreakChecks"];
                issMethods.forEach(function (method) {
                    try {
                        var sel = '+ ' + method;
                        if (IOSSecuritySuite[sel]) {
                            Interceptor.attach(IOSSecuritySuite[sel].implementation, {
                                onLeave: function (retval) { retval.replace(0x0); }
                            });
                        }
                    } catch (e) {}
                });
            }
        } catch (e) {}

        // H8: Talsec
        try {
            var talsecClasses = ["SecurityThreatCenter", "TalsecRuntime", "FreeraspFlutterPlugin"];
            talsecClasses.forEach(function (cls) {
                try {
                    var klass = ObjC.classes[cls];
                    if (klass) {
                        var methods = klass.$ownMethods;
                        methods.forEach(function (method) {
                            try { Interceptor.attach(klass[method].implementation, { onLeave: function (retval) {} }); } catch (e) {}
                        });
                    }
                } catch (e) {}
            });
        } catch (e) {}

        // S3: Ban clear
        setTimeout(function () {
            try {
                var SecItemDelete = new NativeFunction(findExport("Security", "SecItemDelete"), 'int', ['pointer']);
                ["ban", "device_id", "user_uuid", "session_token"].forEach(function (key) {
                    try {
                        var query = ObjC.classes.NSMutableDictionary.alloc().init();
                        query.setObject_forKey_("flutter_secure_storage_service", "svce");
                        query.setObject_forKey_(key, "acct");
                        query.setObject_forKey_(ObjC.classes.NSString.stringWithString_("genp"), "class");
                        var r = SecItemDelete(query);
                        console.log(TAG + ' [BAN] SecItemDelete(' + key + ') = ' + r);
                    } catch (e) {}
                });
            } catch (e) {}
        }, 0);

        console.log(TAG + ' [H] ObjC hooks (ISS+Talsec+BanClear) -- loaded');
    }

    console.log(TAG + ' ==========================================');
    console.log(TAG + ' Bisection ready. If crash → narrow enabled groups.');
    console.log(TAG + ' If no crash → enable more groups.');
    console.log(TAG + ' ==========================================');
})();
