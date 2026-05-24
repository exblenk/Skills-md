// Frida Script for com.saidul.aivideo (AI_Video_Maker)
// Advanced Security Testing & Analysis Script v4 — DEEP-RECON BUILD
// MONITORING ONLY — no subscription/premium tampering

'use strict';

const C = {
    R: '\x1b[0m', r: '\x1b[31m', g: '\x1b[32m', y: '\x1b[33m',
    b: '\x1b[34m', m: '\x1b[35m', c: '\x1b[36m', w: '\x1b[37m',
    bg: '\x1b[42m', br: '\x1b[41m', by: '\x1b[43m', bb: '\x1b[44m', bm: '\x1b[45m',
    bold: '\x1b[1m', dim: '\x1b[2m',
};

function log(tag, msg, color) {
    console.log(`${color || C.g}[${tag}]${C.R} ${msg}`);
}

function banner(text) {
    console.log(`\n${C.bg}${C.w}${C.bold} ★ ${text} ${C.R}\n`);
}

// global stats counter
var STATS = { net: 0, json: 0, ud: 0, kc: 0, fb: 0, crypto: 0, notif: 0, iap: 0 };


// ==========================================
// 1. SSL PINNING BYPASS (COMPREHENSIVE)
// ==========================================
banner('SSL PINNING BYPASS');

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

try {
    var sslVerifyResult = Module.findExportByName('libboringssl.dylib', 'SSL_get_verify_result');
    if (sslVerifyResult) {
        Interceptor.attach(sslVerifyResult, {
            onLeave: function (retval) { retval.replace(ptr(0x0)); }
        });
        log('SSL', 'SSL_get_verify_result → OK', C.g);
    }
} catch (e) {}

var secTrustReplacements = {
    'SecTrustEvaluate': ['int', ['pointer', 'pointer'], function (trust, result) {
        if (!result.isNull()) result.writeU32(4);
        return 0;
    }],
    'SecTrustEvaluateWithError': ['bool', ['pointer', 'pointer'], function (trust, error) {
        if (!error.isNull()) error.writePointer(ptr(0));
        return 1;
    }],
    'SecTrustGetTrustResult': ['int', ['pointer', 'pointer'], function (trust, result) {
        if (!result.isNull()) result.writeU32(4);
        return 0;
    }],
};

Object.keys(secTrustReplacements).forEach(function (name) {
    try {
        var addr = Module.findExportByName('Security', name);
        if (!addr) return;
        var spec = secTrustReplacements[name];
        Interceptor.replace(addr, new NativeCallback(spec[2], spec[0], spec[1]));
        log('SSL', name + ' → bypassed', C.g);
    } catch (e) {}
});

['SecTrustEvaluateAsync', 'SecTrustEvaluateAsyncWithError'].forEach(function (name) {
    try {
        var addr = Module.findExportByName('Security', name);
        if (addr) Interceptor.attach(addr, { onEnter: function () {} });
    } catch (e) {}
});

try {
    if (ObjC.classes.__NSCFURLSessionConnection) {
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
        log('SSL', 'NSURLSession auth challenge → bypassed', C.g);
    }
} catch (e) {}

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

try {
    if (ObjC.classes.TSKPinningValidator) {
        Interceptor.attach(ObjC.classes.TSKPinningValidator['- evaluateTrust:forHostname:'].implementation, {
            onLeave: function (retval) { retval.replace(ptr(0x0)); }
        });
        log('SSL', 'TrustKit → bypassed', C.g);
    }
} catch (e) {}

try {
    ['ServerTrustManager', 'Alamofire.ServerTrustManager'].forEach(function (cls) {
        if (ObjC.classes[cls]) {
            ObjC.classes[cls].$ownMethods.forEach(function (m) {
                if (m.indexOf('evaluate') !== -1) {
                    try {
                        Interceptor.attach(ObjC.classes[cls][m].implementation, {
                            onLeave: function (retval) { retval.replace(ptr(0x1)); }
                        });
                    } catch (e) {}
                }
            });
            log('SSL', cls + ' → bypassed', C.g);
        }
    });
} catch (e) {}

log('SSL', '✓ All SSL bypass loaded', C.g);


// ==========================================
// 2. JAILBREAK DETECTION BYPASS
// ==========================================
banner('JAILBREAK DETECTION BYPASS');

var jbPaths = [
    '/Applications/Cydia.app', '/Applications/Sileo.app', '/Applications/Zebra.app',
    '/Applications/Filza.app', '/Applications/Activator.app', '/Applications/blackra1n.app',
    '/Applications/FakeCarrier.app', '/Applications/Icy.app', '/Applications/IntelliScreen.app',
    '/Applications/SBSettings.app', '/Applications/WinterBoard.app', '/Applications/Dopamine.app',
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
    '/private/etc/dpkg/origins/debian', '/Library/dpkg/info',
    '/var/mobile/Library/Caches/com.saurik.Cydia',
];

var jbSchemes = ['cydia', 'sileo', 'zbra', 'filza', 'undecimus', 'activator', 'icleaner', 'santander'];

['- fileExistsAtPath:', '- fileExistsAtPath:isDirectory:', '- isReadableFileAtPath:',
 '- isWritableFileAtPath:', '- isExecutableFileAtPath:', '- isDeletableFileAtPath:',
 '- attributesOfItemAtPath:error:', '- contentsAtPath:'].forEach(function (method) {
    try {
        Interceptor.attach(ObjC.classes.NSFileManager[method].implementation, {
            onEnter: function (args) {
                try {
                    this.path = new ObjC.Object(args[2]).toString();
                    this.block = jbPaths.some(function (p) { return this.path.indexOf(p) !== -1; }.bind(this));
                } catch (e) { this.block = false; }
            },
            onLeave: function (retval) {
                if (this.block) retval.replace(ptr(0x0));
            }
        });
    } catch (e) {}
});
log('JB', 'NSFileManager → bypassed', C.g);

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
log('JB', 'C-level file checks → bypassed', C.g);

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

['fork', 'popen', 'system'].forEach(function (fname) {
    try {
        var func = Module.findExportByName(null, fname);
        if (func) Interceptor.attach(func, { onLeave: function (retval) { retval.replace(ptr(-1)); } });
    } catch (e) {}
});

try {
    var sandboxCheck = Module.findExportByName(null, 'sandbox_check');
    if (sandboxCheck) {
        Interceptor.attach(sandboxCheck, {
            onLeave: function (retval) { retval.replace(ptr(0x0)); }
        });
    }
} catch (e) {}

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
    }
} catch (e) {}

try {
    var sysctl = Module.findExportByName(null, 'sysctl');
    if (sysctl) {
        Interceptor.attach(sysctl, {
            onEnter: function (args) {
                var mib = args[0];
                if (mib.readS32() === 1 && mib.add(4).readS32() === 14 && mib.add(8).readS32() === 1) {
                    this.isDebugCheck = true;
                    this.outBuf = args[2];
                }
            },
            onLeave: function (retval) {
                if (this.isDebugCheck && this.outBuf && !this.outBuf.isNull()) {
                    try {
                        var flags = this.outBuf.add(32).readU32();
                        this.outBuf.add(32).writeU32(flags & ~0x800);
                    } catch (e) {}
                }
            }
        });
    }
} catch (e) {}

try {
    var ptrace = Module.findExportByName(null, 'ptrace');
    if (ptrace) {
        Interceptor.attach(ptrace, {
            onEnter: function (args) {
                if (args[0].toInt32() === 31) args[0] = ptr(0);
            }
        });
    }
} catch (e) {}

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
                if (this.key && blockedEnvs.indexOf(this.key) !== -1) retval.replace(ptr(0x0));
            }
        });
    }
} catch (e) {}

try {
    Interceptor.attach(ObjC.classes.NSProcessInfo['- environment'].implementation, {
        onLeave: function (retval) {
            try {
                var env = new ObjC.Object(retval).mutableCopy();
                ['DYLD_INSERT_LIBRARIES', 'DYLD_LIBRARY_PATH', '_MSSafeMode'].forEach(function (k) {
                    env.removeObjectForKey_(k);
                });
                retval.replace(env);
            } catch (e) {}
        }
    });
} catch (e) {}

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

log('JB', '✓ All Jailbreak bypass loaded', C.g);


// ==========================================
// 3. FRIDA DETECTION BYPASS
// ==========================================
banner('FRIDA DETECTION BYPASS');

try {
    var connectFunc = Module.findExportByName(null, 'connect');
    if (connectFunc) {
        Interceptor.attach(connectFunc, {
            onEnter: function (args) {
                var sa = args[1];
                if (sa.readU16() === 2) {
                    var port = (sa.add(2).readU8() << 8) | sa.add(3).readU8();
                    if (port === 27042 || port === 27043) this.blockIt = true;
                }
            },
            onLeave: function (retval) {
                if (this.blockIt) retval.replace(ptr(-1));
            }
        });
    }
} catch (e) {}

try {
    var fridaStrings = ['frida', 'FRIDA', 'gum-js-loop', 'gmain', 'linjector',
        'frida-agent', 'frida-server', 'frida-gadget'];
    var strstr = Module.findExportByName(null, 'strstr');
    if (strstr) {
        Interceptor.attach(strstr, {
            onEnter: function (args) {
                try { this.needle = args[1].readUtf8String(); } catch (e) { this.needle = null; }
            },
            onLeave: function (retval) {
                if (this.needle && fridaStrings.some(function (s) {
                    return this.needle.indexOf(s) !== -1;
                }.bind(this))) retval.replace(ptr(0x0));
            }
        });
    }
} catch (e) {}

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
                if (this.fake) retval.replace(ptr(-1));
            }
        });
    }
} catch (e) {}

try {
    var dlopen = Module.findExportByName(null, 'dlopen');
    if (dlopen) {
        Interceptor.attach(dlopen, {
            onEnter: function (args) {
                try {
                    var path = args[0].readUtf8String();
                    if (path && (path.indexOf('frida') !== -1 || path.indexOf('FridaGadget') !== -1)) {
                        args[0] = Memory.allocUtf8String('/nonexistent');
                    }
                } catch (e) {}
            }
        });
    }
} catch (e) {}

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
banner('SCREENSHOT BYPASS');

try {
    Interceptor.attach(ObjC.classes.UIScreen['- isCaptured'].implementation, {
        onLeave: function (retval) { retval.replace(ptr(0x0)); }
    });
    log('SCREEN', 'isCaptured → false', C.g);
} catch (e) {}

try {
    Interceptor.attach(ObjC.classes.NSNotificationCenter['- addObserver:selector:name:object:'].implementation, {
        onEnter: function (args) {
            try {
                var name = new ObjC.Object(args[4]).toString();
                if (name.indexOf('Screenshot') !== -1 || name.indexOf('CapturedDidChange') !== -1) {
                    args[4] = ObjC.classes.NSString.stringWithString_('__blocked__');
                    log('SCREEN', 'Blocked notification: ' + name, C.y);
                }
            } catch (e) {}
        }
    });
} catch (e) {}

log('SCREEN', '✓ Screen bypass loaded', C.g);


// ==========================================
// 5. NETWORK / API DEEP MONITORING
// ==========================================
banner('NETWORK MONITORING (ENHANCED)');

var targetDomains = [
    'api.kie.ai',
    'api.pikapikapika.io',
    'api.useapi.net',
    'api.ai-auto.io',
    'media.pixverse.ai',
    'us-central1-ai-video-65e40.cloudfunctions.net',
    'checkvideostatus-jpktk6ub7a-uc.a.run.app',
    'tztdq0ux1l.execute-api.us-east-1.amazonaws.com',
    'firestore.googleapis.com',
    'securetoken.googleapis.com',
    'identitytoolkit.googleapis.com',
    'vision.googleapis.com',
];

function isTargetURL(url) {
    if (!url) return false;
    return targetDomains.some(function (d) { return url.indexOf(d) !== -1; });
}

function isLimitRelated(text) {
    if (!text) return false;
    var t = text.toLowerCase();
    return t.indexOf('limit') !== -1 || t.indexOf('quota') !== -1 ||
           t.indexOf('exceeded') !== -1 || t.indexOf('remaining') !== -1 ||
           t.indexOf('left') !== -1 || t.indexOf('premium') !== -1 ||
           t.indexOf('subscribe') !== -1 || t.indexOf('grok') !== -1 ||
           t.indexOf('gemini') !== -1 || t.indexOf('seedance') !== -1 ||
           t.indexOf('daily') !== -1 || t.indexOf('trial') !== -1 ||
           t.indexOf('plan') !== -1 || t.indexOf('credits') !== -1 ||
           t.indexOf('free') !== -1 || t.indexOf('pro') !== -1;
}

// Track tasks → URLs for response correlation
var taskURLMap = {};

try {
    ['- dataTaskWithRequest:completionHandler:',
     '- dataTaskWithRequest:',
     '- dataTaskWithURL:completionHandler:',
     '- uploadTaskWithRequest:fromData:completionHandler:',
     '- downloadTaskWithRequest:completionHandler:',
    ].forEach(function (method) {
        try {
            Interceptor.attach(ObjC.classes.NSURLSession[method].implementation, {
                onEnter: function (args) {
                    try {
                        var obj = new ObjC.Object(args[2]);
                        var url, httpMethod;

                        if (obj.$className.indexOf('URL') !== -1 && obj.$className.indexOf('Request') === -1) {
                            url = obj.toString();
                            httpMethod = 'GET';
                        } else {
                            url = obj.URL().absoluteString().toString();
                            httpMethod = obj.HTTPMethod().toString();
                        }

                        this.url = url;
                        STATS.net++;
                        var isTarget = isTargetURL(url);
                        var color = isTarget ? C.m : C.b;
                        var prefix = isTarget ? '★ ' : '';

                        log('NET', prefix + '→ ' + httpMethod + ' ' + url, color);

                        if (obj.allHTTPHeaderFields) {
                            try {
                                var headers = obj.allHTTPHeaderFields();
                                if (headers) {
                                    var keys = headers.allKeys();
                                    for (var i = 0; i < keys.count(); i++) {
                                        var key = keys.objectAtIndex_(i).toString();
                                        var val = headers.objectForKey_(keys.objectAtIndex_(i)).toString();
                                        var kl = key.toLowerCase();
                                        if (isTarget || kl.indexOf('auth') !== -1 || kl.indexOf('token') !== -1 ||
                                            kl.indexOf('api') !== -1 || kl.indexOf('bearer') !== -1 ||
                                            kl.indexOf('cookie') !== -1 || kl.indexOf('key') !== -1) {
                                            log('NET', '  ⤷ ' + key + ': ' + val.substring(0, 200), C.c);
                                        }
                                    }
                                }
                            } catch (e) {}
                        }

                        if (obj.HTTPBody) {
                            try {
                                var body = obj.HTTPBody();
                                if (body && !body.isNull()) {
                                    var bodyStr = ObjC.classes.NSString.alloc().initWithData_encoding_(body, 4).toString();
                                    if (bodyStr.length > 0) {
                                        log('NET', '  ⤷ Body: ' + bodyStr.substring(0, 800), C.c);
                                    }
                                }
                            } catch (e) {}
                        }
                    } catch (e) {}
                },
                onLeave: function (retval) {
                    if (!retval.isNull() && this.url) {
                        try {
                            taskURLMap[retval.toString()] = this.url;
                        } catch (e) {}
                    }
                }
            });
        } catch (e) {}
    });
    log('NET', 'Request monitoring loaded', C.g);
} catch (e) {}

try {
    Interceptor.attach(ObjC.classes.NSHTTPURLResponse['- initWithURL:statusCode:HTTPVersion:headerFields:'].implementation, {
        onEnter: function (args) {
            try {
                var url = new ObjC.Object(args[2]).toString();
                var statusCode = args[3].toInt32();
                var isTarget = isTargetURL(url);

                if (statusCode >= 400) {
                    log('NET', '← ERROR ' + statusCode + ' ' + url, C.r);
                } else if (isTarget) {
                    log('NET', '★ ← ' + statusCode + ' ' + url, C.m);
                }

                if (isTarget) {
                    try {
                        var respHeaders = new ObjC.Object(args[5]);
                        if (respHeaders && !respHeaders.isNull()) {
                            log('NET', '  ⤷ Response headers: ' + respHeaders.toString().substring(0, 400), C.c);
                        }
                    } catch (e) {}
                }
            } catch (e) {}
        }
    });
    log('NET', 'Response monitoring loaded', C.g);
} catch (e) {}

try {
    Interceptor.attach(ObjC.classes.NSJSONSerialization['+ JSONObjectWithData:options:error:'].implementation, {
        onEnter: function (args) {
            try {
                var data = new ObjC.Object(args[2]);
                var str = ObjC.classes.NSString.alloc().initWithData_encoding_(data, 4);
                if (str) {
                    var s = str.toString();
                    STATS.json++;
                    if (isLimitRelated(s)) {
                        log('JSON', '⚡ LIMIT/QUOTA response detected:', C.br);
                        log('JSON', '  ' + s.substring(0, 1000), C.r);
                    }

                    if (s.indexOf('kie.ai') !== -1 || s.indexOf('createTask') !== -1 ||
                        s.indexOf('recordInfo') !== -1 || s.indexOf('taskId') !== -1) {
                        log('JSON', '★ [KIE.AI] Response:', C.m);
                        log('JSON', '  ' + s.substring(0, 1000), C.m);
                    }

                    if (s.indexOf('grok') !== -1 || s.indexOf('Grok') !== -1) {
                        log('JSON', '★ [GROK] Response:', C.y);
                        log('JSON', '  ' + s.substring(0, 1000), C.y);
                    }
                    if (s.indexOf('gemini') !== -1 || s.indexOf('Gemini') !== -1) {
                        log('JSON', '★ [GEMINI] Response:', C.y);
                        log('JSON', '  ' + s.substring(0, 1000), C.y);
                    }
                    if (s.indexOf('seedance') !== -1 || s.indexOf('Seedance') !== -1) {
                        log('JSON', '★ [SEEDANCE] Response:', C.y);
                        log('JSON', '  ' + s.substring(0, 1000), C.y);
                    }

                    if (s.indexOf('pika') !== -1 || s.indexOf('Pika') !== -1) {
                        log('JSON', '★ [PIKA] Response:', C.c);
                        log('JSON', '  ' + s.substring(0, 1000), C.c);
                    }

                    if (s.indexOf('pixverse') !== -1 || s.indexOf('PixVerse') !== -1) {
                        log('JSON', '★ [PIXVERSE] Response:', C.c);
                        log('JSON', '  ' + s.substring(0, 1000), C.c);
                    }

                    if (s.indexOf('subscription') !== -1 || s.indexOf('purchase') !== -1 ||
                        s.indexOf('entitlement') !== -1 || s.indexOf('receipt') !== -1) {
                        log('JSON', '💰 [PURCHASE] Response:', C.y);
                        log('JSON', '  ' + s.substring(0, 1000), C.y);
                    }
                }
            } catch (e) {}
        }
    });
    log('NET', 'JSON response interceptor loaded', C.g);
} catch (e) {}

log('NET', '✓ Enhanced network monitoring loaded', C.g);


// ==========================================
// 6. STOREKIT MONITORING (READ-ONLY)
// ==========================================
banner('STOREKIT MONITORING (READ-ONLY)');

try {
    Interceptor.attach(ObjC.classes.SKPaymentQueue['- addPayment:'].implementation, {
        onEnter: function (args) {
            try {
                var payment = new ObjC.Object(args[2]);
                var productId = payment.productIdentifier().toString();
                STATS.iap++;
                log('IAP', '💰 Purchase: ' + productId, C.m);
            } catch (e) {}
        }
    });
} catch (e) {}

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

try {
    Interceptor.attach(ObjC.classes.SKProduct['- price'].implementation, {
        onLeave: function (retval) {
            try {
                var product = new ObjC.Object(this.context.x0 || this.context.r0);
                var pid = product.productIdentifier().toString();
                var price = new ObjC.Object(retval).toString();
                log('IAP', '  📦 ' + pid + ' = $' + price, C.c);
            } catch (e) {}
        }
    });
} catch (e) {}

try {
    Interceptor.attach(ObjC.classes.NSBundle['- appStoreReceiptURL'].implementation, {
        onLeave: function (retval) {
            try { log('IAP', '📄 Receipt URL: ' + new ObjC.Object(retval).toString(), C.y); } catch (e) {}
        }
    });
} catch (e) {}

log('IAP', '✓ StoreKit monitoring loaded', C.g);


// ==========================================
// 7. USERDEFAULTS MONITORING (FOCUSED + FILTERED)
// ==========================================
banner('USERDEFAULTS MONITORING (FILTERED)');

var udKeys = ['premium', 'pro', 'subscription', 'purchased', 'paid', 'trial',
    'expire', 'entitle', 'unlock', 'vip', 'coins', 'credits', 'token',
    'limit', 'count', 'ads', 'ad_free', 'remove_ads', 'grok', 'gemini',
    'seedance', 'pika', 'pixverse', 'kie', 'daily', 'free', 'quota',
    'remaining', 'video', 'generation', 'plan', 'user_id', 'firebase'];

// noise filter — exclude these prefixes/keywords
var udNoise = ['WebKit', 'NSUbiquitous', 'AKLastIDMS', 'PKLogging', 'PKKeychainVersion',
    'NSWindow', 'com.apple', 'AppleKeyboard', '__internal__', 'kCFPreferences'];

function isUDInteresting(key) {
    if (!key) return false;
    var kl = key.toLowerCase();
    if (udNoise.some(function (n) { return key.indexOf(n) !== -1; })) return false;
    return udKeys.some(function (ik) { return kl.indexOf(ik) !== -1; });
}

try {
    [['- setObject:forKey:', function (args) {
        var key = new ObjC.Object(args[3]).toString();
        var val = new ObjC.Object(args[2]).toString();
        return [key, val];
    }],
    ['- setBool:forKey:', function (args) {
        var key = new ObjC.Object(args[3]).toString();
        var val = args[2].toInt32() ? 'YES' : 'NO';
        return [key, val];
    }],
    ['- setInteger:forKey:', function (args) {
        var key = new ObjC.Object(args[3]).toString();
        var val = args[2].toInt32().toString();
        return [key, val];
    }],
    ['- setDouble:forKey:', function (args) {
        var key = new ObjC.Object(args[3]).toString();
        return [key, '(double)'];
    }],
    ['- setFloat:forKey:', function (args) {
        var key = new ObjC.Object(args[3]).toString();
        return [key, '(float)'];
    }]].forEach(function (pair) {
        try {
            Interceptor.attach(ObjC.classes.NSUserDefaults[pair[0]].implementation, {
                onEnter: function (args) {
                    try {
                        var result = pair[1](args);
                        if (isUDInteresting(result[0])) {
                            STATS.ud++;
                            log('UD', '✏️  SET ' + result[0] + ' = ' + result[1].substring(0, 200), C.y);
                        }
                    } catch (e) {}
                }
            });
        } catch (e) {}
    });

    [['- objectForKey:', true],
     ['- boolForKey:', false],
     ['- integerForKey:', false],
     ['- stringForKey:', true],
     ['- doubleForKey:', false]].forEach(function (pair) {
        try {
            Interceptor.attach(ObjC.classes.NSUserDefaults[pair[0]].implementation, {
                onEnter: function (args) {
                    try {
                        this.key = new ObjC.Object(args[2]).toString();
                        this.track = isUDInteresting(this.key);
                    } catch (e) { this.track = false; }
                },
                onLeave: function (retval) {
                    if (this.track) {
                        try {
                            var val = pair[1] && !retval.isNull()
                                ? new ObjC.Object(retval).toString().substring(0, 200)
                                : retval.toInt32().toString();
                            log('UD', '📖 GET ' + this.key + ' = ' + val, C.c);
                        } catch (e) {}
                    }
                }
            });
        } catch (e) {}
    });

    log('UD', '✓ UserDefaults monitoring loaded (with noise filter)', C.g);
} catch (e) {}


// ==========================================
// 8. KEYCHAIN MONITORING
// ==========================================
banner('KEYCHAIN MONITORING');

try {
    var kcFuncs = {
        'SecItemCopyMatching': ['🔑 READ', C.c],
        'SecItemAdd': ['➕ ADD', C.y],
        'SecItemUpdate': ['✏️  UPDATE', C.y],
        'SecItemDelete': ['🗑  DELETE', C.r],
    };

    Object.keys(kcFuncs).forEach(function (name) {
        try {
            var addr = Module.findExportByName('Security', name);
            if (addr) {
                Interceptor.attach(addr, {
                    onEnter: function (args) {
                        try {
                            var query = new ObjC.Object(args[0]).toString();
                            STATS.kc++;
                            log('KC', kcFuncs[name][0] + ' ' + name + ': ' + query.substring(0, 300), kcFuncs[name][1]);
                        } catch (e) {}
                    }
                });
            }
        } catch (e) {}
    });

    log('KC', '✓ Keychain monitoring loaded', C.g);
} catch (e) {}


// ==========================================
// 9. FIREBASE FIRESTORE DEEP MONITORING (WITH SNAPSHOT EXTRACTION)
// ==========================================
banner('FIREBASE DEEP MONITORING (v4)');

try {
    if (ObjC.classes.FIRFirestore) {
        ['- collectionWithPath:', '- documentWithPath:'].forEach(function (m) {
            try {
                Interceptor.attach(ObjC.classes.FIRFirestore[m].implementation, {
                    onEnter: function (args) {
                        try {
                            var path = new ObjC.Object(args[2]).toString();
                            STATS.fb++;
                            log('FB', '📂 Firestore ' + m.split(':')[0].replace('- ', '') + ': ' + path, C.c);
                        } catch (e) {}
                    }
                });
            } catch (e) {}
        });
    }
} catch (e) {}

// v4: Extract document data from FIRDocumentSnapshot
try {
    if (ObjC.classes.FIRDocumentSnapshot) {
        Interceptor.attach(ObjC.classes.FIRDocumentSnapshot['- data'].implementation, {
            onLeave: function (retval) {
                try {
                    if (!retval.isNull()) {
                        var data = new ObjC.Object(retval);
                        var snap = new ObjC.Object(this.context.x0 || this.context.r0);
                        var docID = '?';
                        try { docID = snap.documentID().toString(); } catch (e) {}
                        log('FB', '📄 [SNAPSHOT] ' + docID + ': ' + data.toString().substring(0, 600), C.m);
                    }
                } catch (e) {}
            }
        });
        log('FB', 'FIRDocumentSnapshot.data → captured', C.g);
    }
} catch (e) {}

// v4: Extract from FIRQuerySnapshot
try {
    if (ObjC.classes.FIRQuerySnapshot) {
        Interceptor.attach(ObjC.classes.FIRQuerySnapshot['- documents'].implementation, {
            onLeave: function (retval) {
                try {
                    if (!retval.isNull()) {
                        var docs = new ObjC.Object(retval);
                        log('FB', '📚 [QUERY-SNAP] ' + docs.count() + ' documents', C.m);
                    }
                } catch (e) {}
            }
        });
        log('FB', 'FIRQuerySnapshot.documents → captured', C.g);
    }
} catch (e) {}

try {
    if (ObjC.classes.FIRDocumentReference) {
        ['- getDocumentWithCompletion:', '- getDocumentWithSource:completion:'].forEach(function (m) {
            try {
                Interceptor.attach(ObjC.classes.FIRDocumentReference[m].implementation, {
                    onEnter: function (args) {
                        try {
                            var ref = new ObjC.Object(args[0]);
                            log('FB', '📄 getDocument: ' + ref.path().toString(), C.c);
                        } catch (e) {}
                    }
                });
            } catch (e) {}
        });
    }
} catch (e) {}

try {
    if (ObjC.classes.FIRQuery) {
        ['- getDocumentsWithCompletion:', '- getDocumentsWithSource:completion:'].forEach(function (m) {
            try {
                Interceptor.attach(ObjC.classes.FIRQuery[m].implementation, {
                    onEnter: function (args) {
                        try {
                            log('FB', '📚 Query getDocuments', C.c);
                        } catch (e) {}
                    }
                });
            } catch (e) {}
        });
    }
} catch (e) {}

try {
    if (ObjC.classes.FIRDocumentReference) {
        ['- setData:completion:', '- setData:merge:completion:', '- updateData:completion:'].forEach(function (m) {
            try {
                Interceptor.attach(ObjC.classes.FIRDocumentReference[m].implementation, {
                    onEnter: function (args) {
                        try {
                            var ref = new ObjC.Object(args[0]);
                            var data = new ObjC.Object(args[2]);
                            log('FB', '✏️  WRITE ' + ref.path().toString() + ': ' + data.toString().substring(0, 500), C.y);
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
                    var p = params && !params.isNull() ? ' ' + params.toString().substring(0, 300) : '';
                    log('FB', '📊 Event: ' + name + p, C.c);
                } catch (e) {}
            }
        });
    }
} catch (e) {}

try {
    if (ObjC.classes.FIRAuth) {
        ['- signInWithCredential:completion:', '- signInWithEmail:password:completion:',
         '- signInAnonymouslyWithCompletion:', '- signOut:'].forEach(function (m) {
            try {
                Interceptor.attach(ObjC.classes.FIRAuth[m].implementation, {
                    onEnter: function () {
                        log('FB', '🔐 Auth: ' + m, C.y);
                    }
                });
            } catch (e) {}
        });
    }
} catch (e) {}

log('FB', '✓ Firebase deep monitoring loaded', C.g);


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
                            log('ADS', '📢 ' + adType + ': ' + new ObjC.Object(args[2]).toString(), C.y);
                        } else {
                            log('ADS', '📢 ' + adType + ' load', C.y);
                        }
                    } catch (e) {}
                }
            });
        }
    } catch (e) {}
});

log('ADS', '✓ AdMob monitoring loaded', C.g);


// ==========================================
// 11. v4: AUTO-DISCOVERY OF AI_Video_Maker.* CLASSES
// Hook EVERY method of every app class — full tracer
// ==========================================
banner('v4 ★ AUTO-TRACER (App Classes)');

var APP_PREFIX = 'AI_Video_Maker';
var APP_KEYWORDS = ['Premium', 'Subscription', 'Purchase', 'StoreKit', 'Limit', 'Quota',
    'Generation', 'Video', 'Image', 'Kie', 'Pika', 'PixVerse', 'Grok', 'Gemini',
    'Seedance', 'User', 'Account', 'Token', 'Receipt', 'Entitle'];

function isInterestingClass(name) {
    if (!name) return false;
    if (name.indexOf(APP_PREFIX) === 0) return true;
    return APP_KEYWORDS.some(function (k) { return name.indexOf(k) !== -1; });
}

var tracedMethods = 0;
var tracedClasses = 0;
var skipPatterns = ['init', 'dealloc', 'release', 'retain', 'autorelease', 'class',
    'isEqual', 'hash', 'description', 'copy', 'mutableCopy', 'self',
    'forwardInvocation', 'methodSignatureForSelector', 'respondsToSelector'];

function shouldSkipMethod(m) {
    var lower = m.toLowerCase();
    return skipPatterns.some(function (p) { return lower.indexOf(p) !== -1; });
}

try {
    var allClasses = Object.keys(ObjC.classes);
    log('AUTO', 'Scanning ' + allClasses.length + ' classes...', C.dim);

    allClasses.forEach(function (clsName) {
        if (!isInterestingClass(clsName)) return;
        // skip system classes
        if (clsName.indexOf('NSCF') === 0 || clsName.indexOf('__') === 0) return;

        try {
            var cls = ObjC.classes[clsName];
            var methods = cls.$ownMethods;
            if (!methods || methods.length === 0) return;

            var hookedHere = 0;
            methods.forEach(function (m) {
                if (shouldSkipMethod(m)) return;
                try {
                    Interceptor.attach(cls[m].implementation, {
                        onEnter: function (args) {
                            var argCount = m.split(':').length - 1;
                            var argStr = '';
                            if (argCount > 0 && argCount <= 3) {
                                var parts = [];
                                for (var i = 0; i < argCount; i++) {
                                    try {
                                        var arg = args[2 + i];
                                        if (arg && !arg.isNull()) {
                                            var obj = new ObjC.Object(arg);
                                            var s = obj.toString();
                                            if (s.length > 100) s = s.substring(0, 100) + '...';
                                            parts.push(s);
                                        } else {
                                            parts.push('nil');
                                        }
                                    } catch (e) { parts.push('?'); }
                                }
                                argStr = ' (' + parts.join(' | ') + ')';
                            }
                            log('TRACE', clsName + ' ' + m + argStr, C.c);
                        },
                        onLeave: function (retval) {
                            try {
                                if (!retval.isNull()) {
                                    var lower = m.toLowerCase();
                                    if (lower.indexOf('premium') !== -1 || lower.indexOf('subscription') !== -1 ||
                                        lower.indexOf('purchase') !== -1 || lower.indexOf('entitle') !== -1 ||
                                        lower.indexOf('limit') !== -1 || lower.indexOf('quota') !== -1 ||
                                        lower.indexOf('count') !== -1 || lower.indexOf('remaining') !== -1) {
                                        var v;
                                        try { v = new ObjC.Object(retval).toString().substring(0, 200); }
                                        catch (e) { v = retval.toString(); }
                                        log('TRACE', '  ↩ ' + m + ' → ' + v, C.m);
                                    }
                                }
                            } catch (e) {}
                        }
                    });
                    hookedHere++;
                    tracedMethods++;
                } catch (e) {}
            });

            if (hookedHere > 0) {
                tracedClasses++;
                log('AUTO', '✓ ' + clsName + ' → ' + hookedHere + ' methods', C.g);
            }
        } catch (e) {}
    });

    log('AUTO', '✓ Auto-tracer loaded: ' + tracedClasses + ' classes, ' + tracedMethods + ' methods', C.bold + C.g);
} catch (e) {
    log('AUTO', 'Error: ' + e.message, C.r);
}


// ==========================================
// 12. v4: FULL HTTP RESPONSE BODY CAPTURE
// Hook NSURLSession delegate to capture all bytes
// ==========================================
banner('v4 ★ FULL RESPONSE BODY CAPTURE');

// Hook didReceiveData (delegate method) — catches ALL response bodies
try {
    var responseBuffers = {};

    // Hook the data delegate callback
    Interceptor.attach(ObjC.classes.NSData['+ dataWithBytes:length:'].implementation, {
        onLeave: function (retval) {
            // skip — too noisy
        }
    });

    // Hook URLSession delegate: did receive data
    var sessionDelegateSel = '- URLSession:dataTask:didReceiveData:';
    var classesWithDelegate = [];
    var allClassNames = Object.keys(ObjC.classes);
    allClassNames.forEach(function (cn) {
        try {
            var cls = ObjC.classes[cn];
            if (cls && cls[sessionDelegateSel]) {
                classesWithDelegate.push(cn);
            }
        } catch (e) {}
    });

    classesWithDelegate.forEach(function (cn) {
        try {
            Interceptor.attach(ObjC.classes[cn][sessionDelegateSel].implementation, {
                onEnter: function (args) {
                    try {
                        var task = new ObjC.Object(args[3]);
                        var data = new ObjC.Object(args[4]);
                        var taskPtr = args[3].toString();
                        var url = taskURLMap[taskPtr];

                        if (url && isTargetURL(url)) {
                            if (!responseBuffers[taskPtr]) responseBuffers[taskPtr] = '';
                            try {
                                var chunk = ObjC.classes.NSString.alloc().initWithData_encoding_(data, 4);
                                if (chunk) responseBuffers[taskPtr] += chunk.toString();
                            } catch (e) {}
                        }
                    } catch (e) {}
                }
            });
        } catch (e) {}
    });

    // Hook completion
    var completionSel = '- URLSession:task:didCompleteWithError:';
    allClassNames.forEach(function (cn) {
        try {
            var cls = ObjC.classes[cn];
            if (cls && cls[completionSel]) {
                Interceptor.attach(cls[completionSel].implementation, {
                    onEnter: function (args) {
                        try {
                            var taskPtr = args[3].toString();
                            var url = taskURLMap[taskPtr];
                            var body = responseBuffers[taskPtr];

                            if (url && body) {
                                log('BODY', '★ ← FULL RESPONSE BODY ' + url, C.bm + C.w);
                                log('BODY', '  ' + body.substring(0, 1500), C.m);
                                delete responseBuffers[taskPtr];
                                delete taskURLMap[taskPtr];
                            }
                        } catch (e) {}
                    }
                });
            }
        } catch (e) {}
    });

    log('BODY', '✓ Full response body capture loaded (' + classesWithDelegate.length + ' delegates)', C.g);
} catch (e) {
    log('BODY', 'Error: ' + e.message, C.r);
}


// ==========================================
// 13. v4: CRYPTO MONITORING (CommonCrypto + CryptoKit)
// See what's being encrypted/decrypted
// ==========================================
banner('v4 ★ CRYPTO MONITORING');

try {
    // CCCrypt — symmetric crypto
    var ccCrypt = Module.findExportByName(null, 'CCCrypt');
    if (ccCrypt) {
        Interceptor.attach(ccCrypt, {
            onEnter: function (args) {
                try {
                    STATS.crypto++;
                    var op = args[0].toInt32();
                    var alg = args[1].toInt32();
                    var ops = ['ENCRYPT', 'DECRYPT'];
                    var algs = ['AES128', 'DES', '3DES', 'CAST', 'RC4', 'RC2', 'BLOWFISH', 'AES256'];
                    var keyLen = args[5].toInt32();
                    var dataLen = args[8].toInt32();

                    var opName = ops[op] || 'OP' + op;
                    var algName = algs[alg] || 'ALG' + alg;

                    log('CRYPTO', '🔐 CCCrypt ' + opName + ' ' + algName +
                        ' keyLen=' + keyLen + ' dataLen=' + dataLen, C.bm + C.w);

                    // Read input data (small enough to show)
                    if (dataLen > 0 && dataLen < 256) {
                        try {
                            var input = args[7];
                            if (!input.isNull()) {
                                var bytes = input.readByteArray(Math.min(dataLen, 64));
                                var hex = Array.prototype.map.call(new Uint8Array(bytes), function (b) {
                                    return ('0' + b.toString(16)).slice(-2);
                                }).join('');
                                log('CRYPTO', '  ↳ Input: ' + hex.substring(0, 128), C.c);
                            }
                        } catch (e) {}
                    }

                    // Show key (small only)
                    if (keyLen > 0 && keyLen <= 32) {
                        try {
                            var keyPtr = args[4];
                            if (!keyPtr.isNull()) {
                                var keyBytes = keyPtr.readByteArray(keyLen);
                                var keyHex = Array.prototype.map.call(new Uint8Array(keyBytes), function (b) {
                                    return ('0' + b.toString(16)).slice(-2);
                                }).join('');
                                log('CRYPTO', '  🔑 Key: ' + keyHex, C.y);
                            }
                        } catch (e) {}
                    }
                } catch (e) {}
            }
        });
        log('CRYPTO', 'CCCrypt → hooked', C.g);
    }
} catch (e) {}

try {
    // CCHmac — HMAC operations
    var ccHmac = Module.findExportByName(null, 'CCHmac');
    if (ccHmac) {
        Interceptor.attach(ccHmac, {
            onEnter: function (args) {
                try {
                    var alg = args[0].toInt32();
                    var algs = ['SHA1', 'MD5', 'SHA256', 'SHA384', 'SHA512', 'SHA224'];
                    var dataLen = args[3].toInt32();
                    log('CRYPTO', '🔏 HMAC-' + (algs[alg] || alg) + ' dataLen=' + dataLen, C.c);
                } catch (e) {}
            }
        });
        log('CRYPTO', 'CCHmac → hooked', C.g);
    }
} catch (e) {}

try {
    // CC_SHA256 + CC_MD5
    ['CC_SHA256', 'CC_MD5', 'CC_SHA1'].forEach(function (fname) {
        var fn = Module.findExportByName(null, fname);
        if (fn) {
            Interceptor.attach(fn, {
                onEnter: function (args) {
                    try {
                        var len = args[1].toInt32();
                        if (len > 0 && len < 512) {
                            this.input = args[0].readUtf8String(Math.min(len, 200));
                            this.fname = fname;
                        }
                    } catch (e) {}
                },
                onLeave: function () {
                    if (this.input && this.input.length > 4) {
                        var s = this.input.replace(/[^\x20-\x7e]/g, '.');
                        log('CRYPTO', '#  ' + this.fname + ': ' + s.substring(0, 150), C.c);
                    }
                }
            });
        }
    });
} catch (e) {}

log('CRYPTO', '✓ Crypto monitoring loaded', C.g);


// ==========================================
// 14. v4: STACK TRACES on critical methods
// Know who is calling premium/limit checks
// ==========================================
banner('v4 ★ STACK TRACES');

var stackTargets = ['premium', 'subscription', 'entitle', 'isPremium', 'hasActive',
    'canGenerate', 'remainingCredits', 'checkLimit'];

try {
    var allClassNames2 = Object.keys(ObjC.classes);
    var stackHooks = 0;

    allClassNames2.forEach(function (cn) {
        if (cn.indexOf(APP_PREFIX) !== 0) return;
        try {
            var cls = ObjC.classes[cn];
            var methods = cls.$ownMethods;
            methods.forEach(function (m) {
                var lower = m.toLowerCase();
                if (stackTargets.some(function (t) { return lower.indexOf(t) !== -1; })) {
                    try {
                        Interceptor.attach(cls[m].implementation, {
                            onEnter: function () {
                                try {
                                    var bt = Thread.backtrace(this.context, Backtracer.ACCURATE)
                                        .slice(0, 5)
                                        .map(DebugSymbol.fromAddress);
                                    log('STACK', '🎯 ' + cn + ' ' + m, C.bm + C.w);
                                    bt.forEach(function (s, i) {
                                        log('STACK', '  ' + i + ': ' + s.toString(), C.c);
                                    });
                                } catch (e) {}
                            }
                        });
                        stackHooks++;
                    } catch (e) {}
                }
            });
        } catch (e) {}
    });
    log('STACK', '✓ Stack traces enabled on ' + stackHooks + ' methods', C.g);
} catch (e) {}


// ==========================================
// 15. v4: WEBSOCKET MONITORING
// ==========================================
banner('v4 ★ WEBSOCKET MONITORING');

try {
    if (ObjC.classes.NSURLSessionWebSocketTask) {
        ['- sendMessage:completionHandler:', '- receiveMessageWithCompletionHandler:',
         '- sendPingWithPongReceiveHandler:'].forEach(function (m) {
            try {
                Interceptor.attach(ObjC.classes.NSURLSessionWebSocketTask[m].implementation, {
                    onEnter: function (args) {
                        try {
                            var task = new ObjC.Object(args[0]);
                            var url = '?';
                            try { url = task.currentRequest().URL().absoluteString().toString(); } catch (e) {}
                            if (m.indexOf('send') !== -1) {
                                var msg = new ObjC.Object(args[2]);
                                var content = '';
                                try {
                                    if (msg.string && !msg.string().isNull()) content = msg.string().toString();
                                    else if (msg.data && !msg.data().isNull()) {
                                        content = ObjC.classes.NSString.alloc().initWithData_encoding_(msg.data(), 4).toString();
                                    }
                                } catch (e) {}
                                log('WS', '↑ ' + url + ' → ' + content.substring(0, 400), C.m);
                            } else {
                                log('WS', '↓ ' + m.split(':')[0].replace('- ', '') + ' ' + url, C.c);
                            }
                        } catch (e) {}
                    }
                });
            } catch (e) {}
        });
        log('WS', '✓ WebSocket monitoring loaded', C.g);
    } else {
        log('WS', 'NSURLSessionWebSocketTask not loaded yet (deferred)', C.y);
    }
} catch (e) {}


// ==========================================
// 16. v4: NOTIFICATION CENTER MONITORING
// Catch internal app state-change notifications
// ==========================================
banner('v4 ★ NOTIFICATION TRACKING');

var notifKeywords = ['premium', 'subscription', 'purchase', 'restore', 'entitle',
    'limit', 'quota', 'login', 'logout', 'auth', 'user', 'credit', 'generation'];

try {
    Interceptor.attach(ObjC.classes.NSNotificationCenter['- postNotificationName:object:userInfo:'].implementation, {
        onEnter: function (args) {
            try {
                var name = new ObjC.Object(args[2]).toString();
                var nl = name.toLowerCase();
                if (notifKeywords.some(function (k) { return nl.indexOf(k) !== -1; })) {
                    STATS.notif++;
                    var info = '';
                    try {
                        var userInfo = new ObjC.Object(args[4]);
                        if (userInfo && !userInfo.isNull()) info = ' info=' + userInfo.toString().substring(0, 300);
                    } catch (e) {}
                    log('NOTIF', '📡 ' + name + info, C.bm + C.w);
                }
            } catch (e) {}
        }
    });

    Interceptor.attach(ObjC.classes.NSNotificationCenter['- postNotificationName:object:'].implementation, {
        onEnter: function (args) {
            try {
                var name = new ObjC.Object(args[2]).toString();
                var nl = name.toLowerCase();
                if (notifKeywords.some(function (k) { return nl.indexOf(k) !== -1; })) {
                    log('NOTIF', '📡 ' + name, C.bm + C.w);
                }
            } catch (e) {}
        }
    });

    log('NOTIF', '✓ Notification tracking loaded', C.g);
} catch (e) {}


// ==========================================
// 17. v4: STRING SCANNER — find API keys in app binary
// ==========================================
banner('v4 ★ STRING SCANNER');

setTimeout(function () {
    try {
        var mainModule = Process.enumerateModules()[0];
        log('STR', 'Scanning module: ' + mainModule.name + ' (' + mainModule.size + ' bytes)', C.dim);

        var patterns = [
            { name: 'OpenAI key', regex: /sk-[a-zA-Z0-9]{20,}/g },
            { name: 'AWS access', regex: /AKIA[0-9A-Z]{16}/g },
            { name: 'Google API', regex: /AIza[0-9A-Za-z\-_]{35}/g },
            { name: 'Bearer token', regex: /eyJ[a-zA-Z0-9_=\-]{20,}\.[a-zA-Z0-9_=\-]{20,}/g },
            { name: 'Kie.AI key', regex: /kie[_-]?api[_-]?key/gi },
            { name: 'Firebase URL', regex: /https?:\/\/[a-z0-9-]+\.firebaseio\.com/g },
            { name: 'Stripe', regex: /sk_(test|live)_[0-9a-zA-Z]{24,}/g },
        ];

        var found = {};
        var scanned = 0;

        Process.enumerateRanges('r--').slice(0, 80).forEach(function (range) {
            if (range.size > 10000000) return;
            try {
                var bytes = range.base.readByteArray(Math.min(range.size, 200000));
                var str = '';
                var arr = new Uint8Array(bytes);
                for (var i = 0; i < arr.length; i++) {
                    str += String.fromCharCode(arr[i] & 0xFF);
                }
                scanned++;

                patterns.forEach(function (p) {
                    var matches = str.match(p.regex);
                    if (matches) {
                        matches.forEach(function (m) {
                            if (!found[m]) {
                                found[m] = p.name;
                                log('STR', '🔍 [' + p.name + '] ' + m.substring(0, 80), C.bm + C.w);
                            }
                        });
                    }
                });
            } catch (e) {}
        });

        log('STR', '✓ Scan complete — ' + scanned + ' ranges, ' + Object.keys(found).length + ' secrets', C.g);
    } catch (e) {
        log('STR', 'Error: ' + e.message, C.r);
    }
}, 3000);


// ==========================================
// HEARTBEAT + STATS
// ==========================================
var startTime = Date.now();
setInterval(function () {
    var elapsed = Math.floor((Date.now() - startTime) / 1000);
    var mins = Math.floor(elapsed / 60);
    var secs = elapsed % 60;
    log('♥', mins + 'm ' + secs + 's | NET=' + STATS.net + ' JSON=' + STATS.json +
        ' UD=' + STATS.ud + ' KC=' + STATS.kc + ' FB=' + STATS.fb +
        ' CRYPTO=' + STATS.crypto + ' NOTIF=' + STATS.notif + ' IAP=' + STATS.iap, C.g);
}, 30000);

console.log('\n' + C.bg + C.w + C.bold + ' ══════════════════════════════════════════════════════ ' + C.R);
console.log(C.bg + C.w + C.bold + '  AI_Video_Maker Hook Script v4 — DEEP-RECON BUILD    ' + C.R);
console.log(C.bg + C.w + C.bold + '  17 modules | monitoring-only | no IAP tampering    ' + C.R);
console.log(C.bg + C.w + C.bold + '  v4 NEW:                                              ' + C.R);
console.log(C.bg + C.w + C.bold + '   11. Auto-tracer (every AI_Video_Maker method)     ' + C.R);
console.log(C.bg + C.w + C.bold + '   12. Full HTTP response body capture                 ' + C.R);
console.log(C.bg + C.w + C.bold + '   13. Crypto (CCCrypt/CCHmac/SHA/MD5)                ' + C.R);
console.log(C.bg + C.w + C.bold + '   14. Stack traces on premium/limit checks           ' + C.R);
console.log(C.bg + C.w + C.bold + '   15. WebSocket monitoring                            ' + C.R);
console.log(C.bg + C.w + C.bold + '   16. Notification center tracking                    ' + C.R);
console.log(C.bg + C.w + C.bold + '   17. String scanner (API keys in binary)            ' + C.R);
console.log(C.bg + C.w + C.bold + ' ══════════════════════════════════════════════════════ ' + C.R + '\n');
