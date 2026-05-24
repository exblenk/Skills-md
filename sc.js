// Frida Script for com.saidul.aivideo (AI_Video_Maker)
// Advanced Security Testing & Analysis Script v2

'use strict';

const C = {
    R: '\x1b[0m', r: '\x1b[31m', g: '\x1b[32m', y: '\x1b[33m',
    b: '\x1b[34m', m: '\x1b[35m', c: '\x1b[36m', w: '\x1b[37m',
    bg: '\x1b[42m', br: '\x1b[41m',
};

function log(tag, msg, color) {
    console.log(`${color || C.g}[${tag}]${C.R} ${msg}`);
}

function banner(text) {
    console.log(`\n${C.bg}${C.w} ★ ${text} ${C.R}\n`);
}

// ==========================================
// 1. SSL PINNING BYPASS (COMPREHENSIVE)
// ==========================================
banner('SSL PINNING BYPASS');

// 1a. BoringSSL - Primary iOS TLS engine
['SSL_set_custom_verify', 'SSL_CTX_set_custom_verify'].forEach(function (name) {
    try {
        var addr = Module.findExportByName('libboringssl.dylib', name);
        if (addr) {
            Interceptor.attach(addr, {
                onEnter: function (args) {
                    args[1] = ptr(0x0);
                    args[2] = ptr(0x0);
                }
            });
            log('SSL', name + ' → bypassed', C.g);
        }
    } catch (e) {}
});

// 1b. SSL_get_psk_identity - return null to skip PSK
try {
    var sslVerifyResult = Module.findExportByName('libboringssl.dylib', 'SSL_get_verify_result');
    if (sslVerifyResult) {
        Interceptor.attach(sslVerifyResult, {
            onLeave: function (retval) {
                retval.replace(ptr(0x0)); // X509_V_OK
            }
        });
        log('SSL', 'SSL_get_verify_result → always OK', C.g);
    }
} catch (e) {}

// 1c. SecTrust* family - complete bypass
var secTrustFuncs = {
    'SecTrustEvaluate': function (trust, result) {
        if (!result.isNull()) result.writeU32(4); // kSecTrustResultProceed
        return 0; // errSecSuccess
    },
    'SecTrustEvaluateWithError': function (trust, error) {
        if (!error.isNull()) error.writePointer(ptr(0));
        return 1;
    },
    'SecTrustGetTrustResult': function (trust, result) {
        if (!result.isNull()) result.writeU32(4);
        return 0;
    },
    'SecTrustEvaluateAsync': null,
    'SecTrustEvaluateAsyncWithError': null,
};

Object.keys(secTrustFuncs).forEach(function (name) {
    try {
        var addr = Module.findExportByName('Security', name);
        if (!addr) return;
        if (secTrustFuncs[name]) {
            var types = name.indexOf('WithError') !== -1
                ? ['bool', ['pointer', 'pointer']]
                : name === 'SecTrustGetTrustResult'
                    ? ['int', ['pointer', 'pointer']]
                    : name === 'SecTrustEvaluate'
                        ? ['int', ['pointer', 'pointer']]
                        : ['int', ['pointer', 'pointer']];
            Interceptor.replace(addr, new NativeCallback(secTrustFuncs[name], types[0], types[1]));
        } else {
            Interceptor.attach(addr, {
                onEnter: function (args) {
                    // let it pass
                }
            });
        }
        log('SSL', name + ' → bypassed', C.g);
    } catch (e) {}
});

// 1d. NSURLSession challenge handler
try {
    if (ObjC.classes.NSURLSession) {
        // Override all URLSession delegate auth challenges
        var resolveChallenge = function (args) {
            try {
                var challenge = new ObjC.Object(args[3]);
                var ps = challenge.protectionSpace();
                var authMethod = ps.authenticationMethod().toString();
                if (authMethod === 'NSURLAuthenticationMethodServerTrust') {
                    var trust = ps.serverTrust();
                    var cred = ObjC.classes.NSURLCredential.credentialForTrust_(trust);
                    var handler = new ObjC.Block(args[4]);
                    handler(0, cred); // UseCredential
                    log('SSL', 'Challenge bypassed: ' + ps.host().toString(), C.c);
                }
            } catch (e) {}
        };

        // Hook URLSession:didReceiveChallenge:completionHandler:
        var sessionDelegateClass = ObjC.classes.NSURLSession;
        if (ObjC.classes.__NSCFURLSessionConnection) {
            try {
                Interceptor.attach(
                    ObjC.classes.__NSCFURLSessionConnection['- _handleAuthChallenge:completionHandler:'].implementation, {
                        onEnter: function (args) {
                            try {
                                var challenge = new ObjC.Object(args[2]);
                                var ps = challenge.protectionSpace();
                                if (ps.authenticationMethod().toString() === 'NSURLAuthenticationMethodServerTrust') {
                                    var trust = ps.serverTrust();
                                    var cred = ObjC.classes.NSURLCredential.credentialForTrust_(trust);
                                    var handler = new ObjC.Block(args[3]);
                                    handler(0, cred);
                                }
                            } catch (e) {}
                        }
                    }
                );
                log('SSL', '__NSCFURLSessionConnection auth challenge → bypassed', C.g);
            } catch (e) {}
        }
    }
} catch (e) {}

// 1e. AFNetworking
try {
    if (ObjC.classes.AFSecurityPolicy) {
        Interceptor.attach(ObjC.classes.AFSecurityPolicy['- setSSLPinningMode:'].implementation, {
            onEnter: function (args) { args[2] = ptr(0x0); }
        });
        Interceptor.attach(ObjC.classes.AFSecurityPolicy['- setAllowInvalidCertificates:'].implementation, {
            onEnter: function (args) { args[2] = ptr(0x1); }
        });
        try {
            Interceptor.attach(ObjC.classes.AFSecurityPolicy['- evaluateServerTrust:forDomain:'].implementation, {
                onLeave: function (retval) { retval.replace(ptr(0x1)); }
            });
        } catch (e) {}
        log('SSL', 'AFNetworking → bypassed', C.g);
    }
} catch (e) {}

// 1f. TrustKit
try {
    if (ObjC.classes.TSKPinningValidator) {
        Interceptor.attach(ObjC.classes.TSKPinningValidator['- evaluateTrust:forHostname:'].implementation, {
            onLeave: function (retval) { retval.replace(ptr(0x0)); }
        });
        log('SSL', 'TrustKit → bypassed', C.g);
    }
} catch (e) {}

// 1g. Alamofire ServerTrustManager
try {
    var alamofireClasses = ['ServerTrustManager', 'Alamofire.ServerTrustManager'];
    alamofireClasses.forEach(function (cls) {
        if (ObjC.classes[cls]) {
            var methods = ObjC.classes[cls].$ownMethods;
            methods.forEach(function (m) {
                if (m.indexOf('serverTrustEvaluator') !== -1 || m.indexOf('evaluate') !== -1) {
                    try {
                        Interceptor.attach(ObjC.classes[cls][m].implementation, {
                            onLeave: function (retval) { retval.replace(ptr(0x1)); }
                        });
                    } catch (e) {}
                }
            });
            log('SSL', 'Alamofire ' + cls + ' → bypassed', C.g);
        }
    });
} catch (e) {}

log('SSL', '✓ All SSL bypass techniques loaded', C.g);


// ==========================================
// 2. JAILBREAK DETECTION BYPASS (FULL)
// ==========================================
banner('JAILBREAK DETECTION BYPASS');

var jbPaths = [
    '/Applications/Cydia.app', '/Applications/Sileo.app', '/Applications/Zebra.app',
    '/Applications/Filza.app', '/Applications/Activator.app', '/Applications/blackra1n.app',
    '/Applications/FakeCarrier.app', '/Applications/Icy.app', '/Applications/IntelliScreen.app',
    '/Applications/MxTube.app', '/Applications/RockApp.app', '/Applications/SBSettings.app',
    '/Applications/WinterBoard.app', '/Applications/Dopamine.app',
    '/usr/sbin/sshd', '/usr/bin/ssh', '/usr/libexec/sftp-server', '/usr/libexec/ssh-keysign',
    '/bin/bash', '/bin/sh', '/usr/bin/sshd',
    '/etc/apt', '/etc/apt/sources.list.d',
    '/private/var/lib/apt', '/private/var/lib/cydia', '/private/var/stash',
    '/private/var/tmp/cydia.log', '/private/var/mobile/Library/SBSettings/Themes',
    '/var/cache/apt', '/var/lib/apt', '/var/lib/cydia', '/var/log/syslog',
    '/usr/lib/substrate', '/usr/lib/TweakInject', '/usr/lib/libhooker.dylib',
    '/usr/lib/libsubstitute.dylib', '/usr/lib/libsubstrate.dylib',
    '/Library/MobileSubstrate', '/Library/MobileSubstrate/MobileSubstrate.dylib',
    '/Library/MobileSubstrate/DynamicLibraries',
    '/System/Library/LaunchDaemons/com.saurik.Cydia.Startup.plist',
    '/System/Library/LaunchDaemons/com.ikey.bbot.plist',
    '/usr/libexec/cydia',
    '/.bootstrapped_electra', '/.cydia_no_stash', '/.installed_unc0ver',
    '/usr/lib/libjailbreak.dylib',
    '/jb/lzma', '/jb/jailbreakd.plist', '/jb/amfid_payload.dylib', '/jb/libjailbreak.dylib',
    '/Library/LaunchDaemons/com.openssh.sshd.plist',
    '/var/checkra1n.dmg', '/var/binpack',
    '/Library/PreferenceBundles/LibertyPref.bundle',
    '/Library/PreferenceBundles/ShadowPreferences.bundle',
    '/Library/PreferenceBundles/ABypassPrefs.bundle',
    '/Library/PreferenceBundles/FlyJBPrefs.bundle',
    '/usr/lib/libcycript.dylib', '/usr/lib/frida', '/usr/local/bin/cycript',
    '/private/var/containers/Bundle/tweaksupport',
    '/var/mobile/Library/Preferences/com.saurik.Cydia.plist',
    '/private/etc/dpkg/origins/debian',
    '/Library/dpkg/info',
    '/var/mobile/Library/Caches/com.saurik.Cydia',
];

var jbSchemes = ['cydia', 'sileo', 'zbra', 'filza', 'undecimus', 'activator',
    'postbox', 'icleaner', 'santander'];

// 2a. NSFileManager - all file check methods
var fmMethods = [
    '- fileExistsAtPath:',
    '- fileExistsAtPath:isDirectory:',
    '- isReadableFileAtPath:',
    '- isWritableFileAtPath:',
    '- isExecutableFileAtPath:',
    '- isDeletableFileAtPath:',
    '- attributesOfItemAtPath:error:',
    '- contentsAtPath:',
];

fmMethods.forEach(function (method) {
    try {
        Interceptor.attach(ObjC.classes.NSFileManager[method].implementation, {
            onEnter: function (args) {
                try {
                    this.path = new ObjC.Object(args[2]).toString();
                    this.block = jbPaths.some(function (p) { return this.path.indexOf(p) !== -1; }.bind(this));
                } catch (e) { this.block = false; }
            },
            onLeave: function (retval) {
                if (this.block) {
                    retval.replace(ptr(0x0));
                }
            }
        });
    } catch (e) {}
});
log('JB', 'NSFileManager (' + fmMethods.length + ' methods) → bypassed', C.g);

// 2b. C-level file access functions
['access', 'stat', 'stat64', 'lstat', 'lstat64', 'fopen', 'opendir', 'readlink',
 'realpath', 'realpath$DARWIN_EXTSN'].forEach(function (fname) {
    try {
        var func = Module.findExportByName(null, fname);
        if (!func) return;
        Interceptor.attach(func, {
            onEnter: function (args) {
                try {
                    this.path = args[0].readUtf8String();
                    this.block = this.path && jbPaths.some(function (p) {
                        return this.path.indexOf(p) !== -1;
                    }.bind(this));
                } catch (e) { this.block = false; }
            },
            onLeave: function (retval) {
                if (this.block) {
                    retval.replace(fname === 'fopen' || fname === 'opendir' || fname.indexOf('realpath') !== -1
                        ? ptr(0x0) : ptr(-1));
                }
            }
        });
    } catch (e) {}
});
log('JB', 'C-level file functions → bypassed', C.g);

// 2c. NSString pathExists / stringByResolvingSymlinks
try {
    Interceptor.attach(ObjC.classes.NSString['- stringByResolvingSymlinksInPath'].implementation, {
        onLeave: function (retval) {
            try {
                var resolved = new ObjC.Object(retval).toString();
                if (jbPaths.some(function (p) { return resolved.indexOf(p) !== -1; })) {
                    retval.replace(ObjC.classes.NSString.stringWithString_('/nonexistent'));
                }
            } catch (e) {}
        }
    });
} catch (e) {}

// 2d. canOpenURL
try {
    Interceptor.attach(ObjC.classes.UIApplication['- canOpenURL:'].implementation, {
        onEnter: function (args) {
            try { this.url = new ObjC.Object(args[2]).toString(); } catch (e) { this.url = ''; }
        },
        onLeave: function (retval) {
            if (this.url && jbSchemes.some(function (s) { return this.url.indexOf(s) !== -1; }.bind(this))) {
                retval.replace(ptr(0x0));
                log('JB', 'Blocked canOpenURL: ' + this.url, C.y);
            }
        }
    });
} catch (e) {}

// 2e. fork / popen / system
['fork', 'popen', 'system'].forEach(function (fname) {
    try {
        var func = Module.findExportByName(null, fname);
        if (func) {
            Interceptor.attach(func, {
                onLeave: function (retval) {
                    retval.replace(ptr(-1));
                }
            });
        }
    } catch (e) {}
});
log('JB', 'fork/popen/system → blocked', C.g);

// 2f. sandbox_check - writing to /private
try {
    var sandboxCheck = Module.findExportByName(null, 'sandbox_check');
    if (sandboxCheck) {
        Interceptor.attach(sandboxCheck, {
            onLeave: function (retval) {
                retval.replace(ptr(0x0)); // allowed
            }
        });
        log('JB', 'sandbox_check → bypassed', C.g);
    }
} catch (e) {}

// 2g. dyld image enumeration - hide injected libs
try {
    var _dyld_get_image_name = Module.findExportByName(null, '_dyld_get_image_name');
    if (_dyld_get_image_name) {
        var badLibs = ['substrate', 'substitute', 'TweakInject', 'ellekit', 'CydiaSubstrate',
            'FridaGadget', 'frida', 'libcycript', 'libhooker', 'Shadow', 'ABypass',
            'Liberty', 'FlyJB', 'Cephei', 'rocketbootstrap', 'AppSync'];
        Interceptor.attach(_dyld_get_image_name, {
            onLeave: function (retval) {
                if (retval.isNull()) return;
                try {
                    var name = retval.readUtf8String();
                    if (name && badLibs.some(function (b) { return name.toLowerCase().indexOf(b.toLowerCase()) !== -1; })) {
                        retval.replace(Memory.allocUtf8String('/usr/lib/libSystem.B.dylib'));
                    }
                } catch (e) {}
            }
        });
        log('JB', '_dyld_get_image_name → filtered', C.g);
    }
} catch (e) {}

// 2h. sysctl P_TRACED + anti-debug
try {
    var sysctl = Module.findExportByName(null, 'sysctl');
    if (sysctl) {
        Interceptor.attach(sysctl, {
            onEnter: function (args) {
                var mib = args[0];
                var mib0 = mib.readS32();
                var mib1 = mib.add(4).readS32();
                var mib2 = mib.add(8).readS32();
                if (mib0 === 1 && mib1 === 14 && mib2 === 1) {
                    this.isDebugCheck = true;
                    this.outBuf = args[2];
                }
            },
            onLeave: function (retval) {
                if (this.isDebugCheck && this.outBuf && !this.outBuf.isNull()) {
                    try {
                        var flags = this.outBuf.add(32).readU32();
                        flags &= ~0x800;
                        this.outBuf.add(32).writeU32(flags);
                    } catch (e) {}
                }
            }
        });
        log('JB', 'sysctl P_TRACED → cleared', C.g);
    }
} catch (e) {}

// 2i. ptrace anti-debug
try {
    var ptrace = Module.findExportByName(null, 'ptrace');
    if (ptrace) {
        Interceptor.attach(ptrace, {
            onEnter: function (args) {
                if (args[0].toInt32() === 31) { // PT_DENY_ATTACH
                    args[0] = ptr(0);
                    log('JB', 'ptrace PT_DENY_ATTACH → blocked', C.y);
                }
            }
        });
    }
} catch (e) {}

// 2j. getenv
try {
    var getenv = Module.findExportByName(null, 'getenv');
    if (getenv) {
        var blockedEnvs = ['DYLD_INSERT_LIBRARIES', 'DYLD_LIBRARY_PATH',
            'DYLD_FRAMEWORK_PATH', '_MSSafeMode', 'SUBSTRATE_HOME'];
        Interceptor.attach(getenv, {
            onEnter: function (args) {
                try { this.key = args[0].readUtf8String(); } catch (e) { this.key = null; }
            },
            onLeave: function (retval) {
                if (this.key && blockedEnvs.indexOf(this.key) !== -1) {
                    retval.replace(ptr(0x0));
                }
            }
        });
        log('JB', 'getenv DYLD_* → hidden', C.g);
    }
} catch (e) {}

// 2k. NSProcessInfo environment
try {
    Interceptor.attach(ObjC.classes.NSProcessInfo['- environment'].implementation, {
        onLeave: function (retval) {
            try {
                var env = new ObjC.Object(retval);
                var mutableEnv = env.mutableCopy();
                ['DYLD_INSERT_LIBRARIES', 'DYLD_LIBRARY_PATH', '_MSSafeMode'].forEach(function (key) {
                    mutableEnv.removeObjectForKey_(key);
                });
                retval.replace(mutableEnv);
            } catch (e) {}
        }
    });
    log('JB', 'NSProcessInfo environment → cleaned', C.g);
} catch (e) {}

log('JB', '✓ All Jailbreak bypass techniques loaded', C.g);


// ==========================================
// 3. FRIDA DETECTION BYPASS (ADVANCED)
// ==========================================
banner('FRIDA DETECTION BYPASS');

// 3a. Port scan blocking (27042, 27043)
try {
    var connectFunc = Module.findExportByName(null, 'connect');
    if (connectFunc) {
        Interceptor.attach(connectFunc, {
            onEnter: function (args) {
                var sa = args[1];
                var family = sa.readU16();
                if (family === 2) {
                    var port = (sa.add(2).readU8() << 8) | sa.add(3).readU8();
                    if (port === 27042 || port === 27043) {
                        this.blockIt = true;
                    }
                }
            },
            onLeave: function (retval) {
                if (this.blockIt) {
                    retval.replace(ptr(-1));
                }
            }
        });
        log('FRIDA', 'Port 27042/27043 → blocked', C.g);
    }
} catch (e) {}

// 3b. String searches
try {
    var fridaStrings = ['frida', 'FRIDA', 'gum-js-loop', 'gmain', 'linjector',
        'frida-agent', 'frida-server', 'frida-gadget', '/data/local/tmp'];
    var strstr = Module.findExportByName(null, 'strstr');
    if (strstr) {
        Interceptor.attach(strstr, {
            onEnter: function (args) {
                try { this.needle = args[1].readUtf8String(); } catch (e) { this.needle = null; }
            },
            onLeave: function (retval) {
                if (this.needle && fridaStrings.some(function (s) {
                    return this.needle.indexOf(s) !== -1;
                }.bind(this))) {
                    retval.replace(ptr(0x0));
                }
            }
        });
        log('FRIDA', 'strstr Frida strings → hidden', C.g);
    }
} catch (e) {}

// 3c. strcmp for Frida thread names
try {
    var strcmp = Module.findExportByName(null, 'strcmp');
    if (strcmp) {
        Interceptor.attach(strcmp, {
            onEnter: function (args) {
                try {
                    var s1 = args[0].readUtf8String();
                    var s2 = args[1].readUtf8String();
                    if ((s1 && s1.indexOf('frida') !== -1) || (s2 && s2.indexOf('frida') !== -1) ||
                        (s1 && s1.indexOf('gmain') !== -1) || (s2 && s2.indexOf('gmain') !== -1)) {
                        this.fake = true;
                    }
                } catch (e) {}
            },
            onLeave: function (retval) {
                if (this.fake) retval.replace(ptr(-1)); // not equal
            }
        });
        log('FRIDA', 'strcmp Frida thread check → hidden', C.g);
    }
} catch (e) {}

// 3d. /proc/self/maps (task_info on iOS)
try {
    var task_info = Module.findExportByName(null, 'task_info');
    if (task_info) {
        Interceptor.attach(task_info, {
            onLeave: function (retval) {
                // don't tamper, just log
            }
        });
    }
} catch (e) {}

// 3e. dlopen/dlsym checks for Frida
try {
    var dlopen = Module.findExportByName(null, 'dlopen');
    if (dlopen) {
        Interceptor.attach(dlopen, {
            onEnter: function (args) {
                try {
                    var path = args[0].readUtf8String();
                    if (path && (path.indexOf('frida') !== -1 || path.indexOf('FridaGadget') !== -1)) {
                        args[0] = Memory.allocUtf8String('/nonexistent');
                        log('FRIDA', 'Blocked dlopen: ' + path, C.y);
                    }
                } catch (e) {}
            }
        });
        log('FRIDA', 'dlopen Frida lib → blocked', C.g);
    }
} catch (e) {}

// 3f. Named pipe / socket detection
try {
    var openFunc = Module.findExportByName(null, 'open');
    if (openFunc) {
        Interceptor.attach(openFunc, {
            onEnter: function (args) {
                try {
                    var path = args[0].readUtf8String();
                    if (path && path.indexOf('linjector') !== -1) {
                        args[0] = Memory.allocUtf8String('/dev/null');
                    }
                } catch (e) {}
            }
        });
    }
} catch (e) {}

log('FRIDA', '✓ All Frida detection bypass loaded', C.g);


// ==========================================
// 4. SCREENSHOT / SCREEN RECORDING BYPASS
// ==========================================
banner('SCREENSHOT/RECORDING BYPASS');

// 4a. UIScreen isCaptured
try {
    Interceptor.attach(ObjC.classes.UIScreen['- isCaptured'].implementation, {
        onLeave: function (retval) {
            retval.replace(ptr(0x0)); // NO
        }
    });
    log('SCREEN', 'UIScreen isCaptured → false', C.g);
} catch (e) {}

// 4b. Screenshot notification
try {
    var notifCenter = ObjC.classes.NSNotificationCenter;
    Interceptor.attach(notifCenter['- addObserver:selector:name:object:'].implementation, {
        onEnter: function (args) {
            try {
                var name = new ObjC.Object(args[4]).toString();
                if (name.indexOf('Screenshot') !== -1 || name.indexOf('CapturedDidChange') !== -1) {
                    args[4] = ObjC.classes.NSString.stringWithString_('__blocked__');
                    log('SCREEN', 'Blocked screenshot notification: ' + name, C.y);
                }
            } catch (e) {}
        }
    });
    log('SCREEN', 'Screenshot notifications → blocked', C.g);
} catch (e) {}

log('SCREEN', '✓ Screen capture bypass loaded', C.g);


// ==========================================
// 5. NETWORK / API MONITORING (ENHANCED)
// ==========================================
banner('NETWORK MONITORING');

// 5a. NSURLSession - all request methods
try {
    var sessionMethods = [
        '- dataTaskWithRequest:completionHandler:',
        '- dataTaskWithRequest:',
        '- dataTaskWithURL:completionHandler:',
        '- uploadTaskWithRequest:fromData:completionHandler:',
        '- downloadTaskWithRequest:completionHandler:',
    ];
    sessionMethods.forEach(function (method) {
        try {
            Interceptor.attach(ObjC.classes.NSURLSession[method].implementation, {
                onEnter: function (args) {
                    try {
                        var obj = new ObjC.Object(args[2]);
                        var url;
                        if (obj.$className === 'NSURL' || obj.$className === '__NSCFConstantString' || obj.$className === '__NSCFString') {
                            url = obj.toString();
                        } else {
                            url = obj.URL().absoluteString().toString();
                            var httpMethod = obj.HTTPMethod().toString();
                            log('NET', '→ ' + httpMethod + ' ' + url, C.b);

                            // Print auth headers
                            var headers = obj.allHTTPHeaderFields();
                            if (headers) {
                                var keys = headers.allKeys();
                                for (var i = 0; i < keys.count(); i++) {
                                    var key = keys.objectAtIndex_(i).toString();
                                    var kl = key.toLowerCase();
                                    if (kl.indexOf('auth') !== -1 || kl.indexOf('token') !== -1 ||
                                        kl.indexOf('api') !== -1 || kl.indexOf('key') !== -1 ||
                                        kl.indexOf('bearer') !== -1 || kl.indexOf('cookie') !== -1) {
                                        var val = headers.objectForKey_(keys.objectAtIndex_(i)).toString();
                                        log('NET', '  ⤷ ' + key + ': ' + val.substring(0, 120), C.m);
                                    }
                                }
                            }

                            // Print body
                            var body = obj.HTTPBody();
                            if (body && !body.isNull()) {
                                try {
                                    var bodyStr = ObjC.classes.NSString.alloc().initWithData_encoding_(body, 4).toString();
                                    if (bodyStr.length > 0) {
                                        log('NET', '  ⤷ Body: ' + bodyStr.substring(0, 300), C.c);
                                    }
                                } catch (e) {}
                            }
                            return;
                        }
                        log('NET', '→ GET ' + url, C.b);
                    } catch (e) {}
                }
            });
        } catch (e) {}
    });
    log('NET', 'NSURLSession hooks loaded', C.g);
} catch (e) {}

// 5b. Response monitoring
try {
    Interceptor.attach(ObjC.classes.NSHTTPURLResponse['- initWithURL:statusCode:HTTPVersion:headerFields:'].implementation, {
        onEnter: function (args) {
            try {
                var url = new ObjC.Object(args[2]).toString();
                var statusCode = args[3].toInt32();
                if (statusCode >= 400) {
                    log('NET', '← ERROR ' + statusCode + ' ' + url, C.r);
                } else {
                    log('NET', '← ' + statusCode + ' ' + url, C.g);
                }
            } catch (e) {}
        }
    });
    log('NET', 'Response monitoring loaded', C.g);
} catch (e) {}

log('NET', '✓ Network monitoring loaded', C.g);


// ==========================================
// 6. STOREKIT / IAP MONITORING
// ==========================================
banner('STOREKIT MONITORING');

// 6a. SKPaymentQueue
try {
    Interceptor.attach(ObjC.classes.SKPaymentQueue['- addPayment:'].implementation, {
        onEnter: function (args) {
            try {
                var payment = new ObjC.Object(args[2]);
                var productId = payment.productIdentifier().toString();
                var qty = payment.quantity();
                log('IAP', '💰 Purchase: ' + productId + ' (qty: ' + qty + ')', C.m);
            } catch (e) {}
        }
    });
} catch (e) {}

// 6b. SKPaymentTransaction states
try {
    Interceptor.attach(ObjC.classes.SKPaymentTransaction['- transactionState'].implementation, {
        onLeave: function (retval) {
            var states = ['Purchasing', 'Purchased ✓', 'Failed ✗', 'Restored', 'Deferred'];
            var state = retval.toInt32();
            if (state >= 0 && state < states.length) {
                try {
                    var tx = new ObjC.Object(this.context.x0 || this.context.r0);
                    var pid = tx.payment().productIdentifier().toString();
                    log('IAP', '  → ' + pid + ': ' + states[state], C.m);
                } catch (e) {
                    log('IAP', '  → State: ' + states[state], C.m);
                }
            }
        }
    });
} catch (e) {}

// 6c. SKProduct price monitoring
try {
    Interceptor.attach(ObjC.classes.SKProduct['- price'].implementation, {
        onLeave: function (retval) {
            try {
                var product = new ObjC.Object(this.context.x0 || this.context.r0);
                var pid = product.productIdentifier().toString();
                var price = new ObjC.Object(retval).toString();
                log('IAP', '  📦 Product: ' + pid + ' = ' + price, C.c);
            } catch (e) {}
        }
    });
} catch (e) {}

// 6d. AI_Video_Maker StoreKit classes - hook ALL methods
try {
    ['AI_Video_Maker.StoreKitManager', 'AI_Video_Maker.StoreKit2Manager'].forEach(function (cls) {
        if (ObjC.classes[cls]) {
            var methods = ObjC.classes[cls].$ownMethods;
            methods.forEach(function (m) {
                try {
                    Interceptor.attach(ObjC.classes[cls][m].implementation, {
                        onEnter: function (args) {
                            log('IAP', '🔧 ' + cls.split('.')[1] + ' ' + m, C.m);
                        },
                        onLeave: function (retval) {
                            if (!retval.isNull()) {
                                try {
                                    var obj = new ObjC.Object(retval);
                                    log('IAP', '  ↩ return: ' + obj.toString().substring(0, 150), C.c);
                                } catch (e) {}
                            }
                        }
                    });
                } catch (e) {}
            });
            log('IAP', cls + ' → ' + methods.length + ' methods hooked', C.g);
        }
    });
} catch (e) {}

// 6e. Receipt validation
try {
    Interceptor.attach(ObjC.classes.NSBundle['- appStoreReceiptURL'].implementation, {
        onLeave: function (retval) {
            try {
                log('IAP', '📄 Receipt URL accessed: ' + new ObjC.Object(retval).toString(), C.y);
            } catch (e) {}
        }
    });
} catch (e) {}

log('IAP', '✓ StoreKit monitoring loaded', C.g);


// ==========================================
// 7. USERDEFAULTS MONITORING
// ==========================================
banner('USERDEFAULTS MONITORING');

try {
    var interestingKeys = ['premium', 'pro', 'subscription', 'purchased', 'paid', 'trial',
        'expire', 'entitle', 'unlock', 'vip', 'coins', 'credits', 'token',
        'limit', 'count', 'ads', 'ad_free', 'remove_ads'];

    // setObject:forKey:
    Interceptor.attach(ObjC.classes.NSUserDefaults['- setObject:forKey:'].implementation, {
        onEnter: function (args) {
            try {
                var key = new ObjC.Object(args[3]).toString();
                var val = new ObjC.Object(args[2]).toString();
                var kl = key.toLowerCase();
                if (interestingKeys.some(function (ik) { return kl.indexOf(ik) !== -1; })) {
                    log('UD', '✏️  SET ' + key + ' = ' + val.substring(0, 100), C.y);
                }
            } catch (e) {}
        }
    });

    // setBool:forKey:
    Interceptor.attach(ObjC.classes.NSUserDefaults['- setBool:forKey:'].implementation, {
        onEnter: function (args) {
            try {
                var key = new ObjC.Object(args[3]).toString();
                var val = args[2].toInt32() ? 'YES' : 'NO';
                var kl = key.toLowerCase();
                if (interestingKeys.some(function (ik) { return kl.indexOf(ik) !== -1; })) {
                    log('UD', '✏️  SET (bool) ' + key + ' = ' + val, C.y);
                }
            } catch (e) {}
        }
    });

    // setInteger:forKey:
    Interceptor.attach(ObjC.classes.NSUserDefaults['- setInteger:forKey:'].implementation, {
        onEnter: function (args) {
            try {
                var key = new ObjC.Object(args[3]).toString();
                var val = args[2].toInt32();
                var kl = key.toLowerCase();
                if (interestingKeys.some(function (ik) { return kl.indexOf(ik) !== -1; })) {
                    log('UD', '✏️  SET (int) ' + key + ' = ' + val, C.y);
                }
            } catch (e) {}
        }
    });

    // objectForKey: reads
    Interceptor.attach(ObjC.classes.NSUserDefaults['- objectForKey:'].implementation, {
        onEnter: function (args) {
            try {
                this.key = new ObjC.Object(args[2]).toString();
                this.track = interestingKeys.some(function (ik) {
                    return this.key.toLowerCase().indexOf(ik) !== -1;
                }.bind(this));
            } catch (e) { this.track = false; }
        },
        onLeave: function (retval) {
            if (this.track && !retval.isNull()) {
                try {
                    log('UD', '📖 GET ' + this.key + ' = ' + new ObjC.Object(retval).toString().substring(0, 100), C.c);
                } catch (e) {}
            }
        }
    });

    // boolForKey: reads
    Interceptor.attach(ObjC.classes.NSUserDefaults['- boolForKey:'].implementation, {
        onEnter: function (args) {
            try {
                this.key = new ObjC.Object(args[2]).toString();
                this.track = interestingKeys.some(function (ik) {
                    return this.key.toLowerCase().indexOf(ik) !== -1;
                }.bind(this));
            } catch (e) { this.track = false; }
        },
        onLeave: function (retval) {
            if (this.track) {
                log('UD', '📖 GET (bool) ' + this.key + ' = ' + (retval.toInt32() ? 'YES' : 'NO'), C.c);
            }
        }
    });

    log('UD', '✓ UserDefaults monitoring loaded', C.g);
} catch (e) {}


// ==========================================
// 8. KEYCHAIN MONITORING
// ==========================================
banner('KEYCHAIN MONITORING');

try {
    var SecItemCopyMatching = Module.findExportByName('Security', 'SecItemCopyMatching');
    var SecItemAdd = Module.findExportByName('Security', 'SecItemAdd');
    var SecItemUpdate = Module.findExportByName('Security', 'SecItemUpdate');
    var SecItemDelete = Module.findExportByName('Security', 'SecItemDelete');

    if (SecItemCopyMatching) {
        Interceptor.attach(SecItemCopyMatching, {
            onEnter: function (args) {
                try {
                    var query = new ObjC.Object(args[0]);
                    log('KC', '🔑 SecItemCopyMatching: ' + query.toString().substring(0, 200), C.c);
                } catch (e) {}
            }
        });
    }

    if (SecItemAdd) {
        Interceptor.attach(SecItemAdd, {
            onEnter: function (args) {
                try {
                    var attrs = new ObjC.Object(args[0]);
                    log('KC', '➕ SecItemAdd: ' + attrs.toString().substring(0, 200), C.y);
                } catch (e) {}
            }
        });
    }

    if (SecItemUpdate) {
        Interceptor.attach(SecItemUpdate, {
            onEnter: function (args) {
                try {
                    var query = new ObjC.Object(args[0]);
                    log('KC', '✏️  SecItemUpdate: ' + query.toString().substring(0, 200), C.y);
                } catch (e) {}
            }
        });
    }

    if (SecItemDelete) {
        Interceptor.attach(SecItemDelete, {
            onEnter: function (args) {
                try {
                    var query = new ObjC.Object(args[0]);
                    log('KC', '🗑  SecItemDelete: ' + query.toString().substring(0, 200), C.r);
                } catch (e) {}
            }
        });
    }

    log('KC', '✓ Keychain monitoring loaded', C.g);
} catch (e) {}


// ==========================================
// 9. FIREBASE / ANALYTICS
// ==========================================
banner('FIREBASE MONITORING');

try {
    if (ObjC.classes.FIRFirestore) {
        ['- collectionWithPath:', '- documentWithPath:'].forEach(function (m) {
            try {
                Interceptor.attach(ObjC.classes.FIRFirestore[m].implementation, {
                    onEnter: function (args) {
                        try {
                            log('FB', 'Firestore ' + m.split(':')[0].replace('- ', '') + ': ' + new ObjC.Object(args[2]).toString(), C.c);
                        } catch (e) {}
                    }
                });
            } catch (e) {}
        });
    }
} catch (e) {}

try {
    if (ObjC.classes.FIRAnalytics) {
        Interceptor.attach(ObjC.classes.FIRAnalytics['+ logEventWithName:parameters:'].implementation, {
            onEnter: function (args) {
                try {
                    var name = new ObjC.Object(args[2]).toString();
                    var params = new ObjC.Object(args[3]);
                    log('FB', '📊 Event: ' + name + ' ' + (params.isNull ? '' : params.toString().substring(0, 150)), C.c);
                } catch (e) {}
            }
        });
    }
} catch (e) {}

log('FB', '✓ Firebase monitoring loaded', C.g);


// ==========================================
// 10. GOOGLE ADS (ADMOB)
// ==========================================
banner('ADMOB MONITORING');

var adClasses = {
    'GADInterstitialAd': '+ loadWithAdUnitID:request:completionHandler:',
    'GADBannerView': '- loadRequest:',
    'GADRewardedAd': '+ loadWithAdUnitID:request:completionHandler:',
    'GADRewardedInterstitialAd': '+ loadWithAdUnitID:request:completionHandler:',
    'GADAppOpenAd': '+ loadWithAdUnitID:request:completionHandler:',
};

Object.keys(adClasses).forEach(function (cls) {
    try {
        if (ObjC.classes[cls]) {
            Interceptor.attach(ObjC.classes[cls][adClasses[cls]].implementation, {
                onEnter: function (args) {
                    try {
                        var adType = cls.replace('GAD', '').replace('Ad', '');
                        if (args[2] && !new ObjC.Object(args[2]).isNull) {
                            var adUnitId = new ObjC.Object(args[2]).toString();
                            log('ADS', '📢 ' + adType + ' load: ' + adUnitId, C.y);
                        } else {
                            log('ADS', '📢 ' + adType + ' load', C.y);
                        }
                    } catch (e) {}
                }
            });
            log('ADS', cls + ' → monitored', C.g);
        }
    } catch (e) {}
});

// Ad presentation
try {
    if (ObjC.classes.GADFullScreenPresentingAd) {
        var presentMethods = ObjC.classes.GADFullScreenPresentingAd.$ownMethods;
        presentMethods.forEach(function (m) {
            if (m.indexOf('present') !== -1) {
                try {
                    Interceptor.attach(ObjC.classes.GADFullScreenPresentingAd[m].implementation, {
                        onEnter: function () {
                            log('ADS', '🖥  Ad presenting: ' + m, C.y);
                        }
                    });
                } catch (e) {}
            }
        });
    }
} catch (e) {}

log('ADS', '✓ AdMob monitoring loaded', C.g);


// ==========================================
// HEARTBEAT & SUMMARY
// ==========================================
var startTime = Date.now();
setInterval(function () {
    var elapsed = Math.floor((Date.now() - startTime) / 1000);
    var mins = Math.floor(elapsed / 60);
    var secs = elapsed % 60;
    log('♥', mins + 'm ' + secs + 's — alive', C.g);
}, 30000);

console.log('\n' + C.bg + C.w + ' ══════════════════════════════════════════════════ ' + C.R);
console.log(C.bg + C.w + '  AI_Video_Maker Hook Script v2 — FULLY LOADED     ' + C.R);
console.log(C.bg + C.w + '  Modules: SSL | JB | FRIDA | SCREEN | NET | IAP   ' + C.R);
console.log(C.bg + C.w + '           UD | KEYCHAIN | FIREBASE | ADS          ' + C.R);
console.log(C.bg + C.w + ' ══════════════════════════════════════════════════ ' + C.R + '\n');
