// Frida Script for com.saidul.aivideo (AI_Video_Maker)
// Advanced Security Testing & Analysis Script v3
// Updated based on diff-report analysis (new version)

'use strict';

const C = {
    R: '\x1b[0m', r: '\x1b[31m', g: '\x1b[32m', y: '\x1b[33m',
    b: '\x1b[34m', m: '\x1b[35m', c: '\x1b[36m', w: '\x1b[37m',
    bg: '\x1b[42m', br: '\x1b[41m', by: '\x1b[43m',
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

// 1a. BoringSSL
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

// 1b. SecTrust* family
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

// 1c. NSURLSession challenge
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

// 1d. AFNetworking
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

// 1e. TrustKit
try {
    if (ObjC.classes.TSKPinningValidator) {
        Interceptor.attach(ObjC.classes.TSKPinningValidator['- evaluateTrust:forHostname:'].implementation, {
            onLeave: function (retval) { retval.replace(ptr(0x0)); }
        });
        log('SSL', 'TrustKit → bypassed', C.g);
    }
} catch (e) {}

// 1f. Alamofire
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

// 2a. NSFileManager
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

// 2b. C-level file functions
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

// 2c. canOpenURL
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

// 2d. fork / popen / system
['fork', 'popen', 'system'].forEach(function (fname) {
    try {
        var func = Module.findExportByName(null, fname);
        if (func) Interceptor.attach(func, { onLeave: function (retval) { retval.replace(ptr(-1)); } });
    } catch (e) {}
});

// 2e. sandbox_check
try {
    var sandboxCheck = Module.findExportByName(null, 'sandbox_check');
    if (sandboxCheck) {
        Interceptor.attach(sandboxCheck, {
            onLeave: function (retval) { retval.replace(ptr(0x0)); }
        });
    }
} catch (e) {}

// 2f. dyld — hide injected libs
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

// 2g. sysctl P_TRACED
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

// 2h. ptrace PT_DENY_ATTACH
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

// 2i. getenv + NSProcessInfo
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

// 2j. NSString resolving symlinks
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

// 3a. Port blocking
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

// 3b. String searches
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

// 3c. strcmp
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

// 3d. dlopen
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

// 3e. Named pipe
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

// === TARGETED DOMAINS ===
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

// 5a. NSURLSession — all request types
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

                        var isTarget = isTargetURL(url);
                        var color = isTarget ? C.m : C.b;
                        var prefix = isTarget ? '★ ' : '';

                        log('NET', prefix + '→ ' + httpMethod + ' ' + url, color);

                        // Headers (always for target, auth-only for others)
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
                                            log('NET', '  ⤷ ' + key + ': ' + val.substring(0, 150), C.c);
                                        }
                                    }
                                }
                            } catch (e) {}
                        }

                        // Body
                        if (obj.HTTPBody) {
                            try {
                                var body = obj.HTTPBody();
                                if (body && !body.isNull()) {
                                    var bodyStr = ObjC.classes.NSString.alloc().initWithData_encoding_(body, 4).toString();
                                    if (bodyStr.length > 0) {
                                        log('NET', '  ⤷ Body: ' + bodyStr.substring(0, 500), C.c);

                                        // Kie AI specific
                                        if (url.indexOf('kie.ai') !== -1) {
                                            log('NET', '  ⤷ [KIE.AI] Full request body:', C.m);
                                            log('NET', '    ' + bodyStr, C.m);
                                        }
                                    }
                                }
                            } catch (e) {}
                        }
                    } catch (e) {}
                }
            });
        } catch (e) {}
    });
    log('NET', 'Request monitoring loaded', C.g);
} catch (e) {}

// 5b. Response monitoring with body capture
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

                // Log response headers for target domains
                if (isTarget) {
                    try {
                        var respHeaders = new ObjC.Object(args[5]);
                        if (respHeaders && !respHeaders.isNull()) {
                            log('NET', '  ⤷ Response headers: ' + respHeaders.toString().substring(0, 300), C.c);
                        }
                    } catch (e) {}
                }
            } catch (e) {}
        }
    });
    log('NET', 'Response monitoring loaded', C.g);
} catch (e) {}

// 5c. NSJSONSerialization — capture ALL JSON parsing (catches API responses)
try {
    Interceptor.attach(ObjC.classes.NSJSONSerialization['+ JSONObjectWithData:options:error:'].implementation, {
        onEnter: function (args) {
            try {
                var data = new ObjC.Object(args[2]);
                var str = ObjC.classes.NSString.alloc().initWithData_encoding_(data, 4);
                if (str) {
                    var s = str.toString();
                    if (isLimitRelated(s)) {
                        log('JSON', '⚡ LIMIT/QUOTA response detected:', C.br);
                        log('JSON', '  ' + s.substring(0, 800), C.r);
                    }

                    // Kie AI responses
                    if (s.indexOf('kie.ai') !== -1 || s.indexOf('createTask') !== -1 ||
                        s.indexOf('recordInfo') !== -1 || s.indexOf('taskId') !== -1) {
                        log('JSON', '★ [KIE.AI] Response:', C.m);
                        log('JSON', '  ' + s.substring(0, 800), C.m);
                    }

                    // Grok / Gemini / Seedance responses
                    if (s.indexOf('grok') !== -1 || s.indexOf('Grok') !== -1) {
                        log('JSON', '★ [GROK] Response:', C.y);
                        log('JSON', '  ' + s.substring(0, 800), C.y);
                    }
                    if (s.indexOf('gemini') !== -1 || s.indexOf('Gemini') !== -1) {
                        log('JSON', '★ [GEMINI] Response:', C.y);
                        log('JSON', '  ' + s.substring(0, 800), C.y);
                    }
                    if (s.indexOf('seedance') !== -1 || s.indexOf('Seedance') !== -1) {
                        log('JSON', '★ [SEEDANCE] Response:', C.y);
                        log('JSON', '  ' + s.substring(0, 800), C.y);
                    }

                    // Pika responses
                    if (s.indexOf('pika') !== -1 || s.indexOf('Pika') !== -1) {
                        log('JSON', '★ [PIKA] Response:', C.c);
                        log('JSON', '  ' + s.substring(0, 800), C.c);
                    }

                    // PixVerse responses
                    if (s.indexOf('pixverse') !== -1 || s.indexOf('PixVerse') !== -1) {
                        log('JSON', '★ [PIXVERSE] Response:', C.c);
                        log('JSON', '  ' + s.substring(0, 800), C.c);
                    }

                    // Subscription/purchase related
                    if (s.indexOf('subscription') !== -1 || s.indexOf('purchase') !== -1 ||
                        s.indexOf('entitlement') !== -1 || s.indexOf('receipt') !== -1) {
                        log('JSON', '💰 [PURCHASE] Response:', C.y);
                        log('JSON', '  ' + s.substring(0, 800), C.y);
                    }
                }
            } catch (e) {}
        }
    });
    log('NET', 'JSON response interceptor loaded (catches limits/quotas)', C.g);
} catch (e) {}

log('NET', '✓ Enhanced network monitoring loaded', C.g);


// ==========================================
// 6. STOREKIT MONITORING (ADAPTED FOR NEW VERSION)
// ==========================================
banner('STOREKIT MONITORING (v3 — adapted)');

// Note: StoreKit2 symbols (Product.purchase, Transaction.finish, AppStore.sync)
// were REMOVED in the new version. Focus on StoreKit1 + server-side.

// 6a. SKPaymentQueue (StoreKit1 — still present)
try {
    Interceptor.attach(ObjC.classes.SKPaymentQueue['- addPayment:'].implementation, {
        onEnter: function (args) {
            try {
                var payment = new ObjC.Object(args[2]);
                var productId = payment.productIdentifier().toString();
                log('IAP', '💰 Purchase: ' + productId, C.m);
            } catch (e) {}
        }
    });
} catch (e) {}

// 6b. SKPaymentTransaction
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

// 6c. SKProduct price
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

// 6d. Receipt URL access
try {
    Interceptor.attach(ObjC.classes.NSBundle['- appStoreReceiptURL'].implementation, {
        onLeave: function (retval) {
            try { log('IAP', '📄 Receipt URL: ' + new ObjC.Object(retval).toString(), C.y); } catch (e) {}
        }
    });
} catch (e) {}

// 6e. AI_Video_Maker StoreKit classes
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
                                    log('IAP', '  ↩ ' + new ObjC.Object(retval).toString().substring(0, 200), C.c);
                                } catch (e) {}
                            }
                        }
                    });
                } catch (e) {}
            });
            log('IAP', cls + ' → ' + methods.length + ' methods hooked', C.g);
        } else {
            log('IAP', cls + ' NOT FOUND (may be removed in new version)', C.y);
        }
    });
} catch (e) {}

log('IAP', '✓ StoreKit monitoring loaded', C.g);


// ==========================================
// 7. USERDEFAULTS MONITORING (FOCUSED)
// ==========================================
banner('USERDEFAULTS MONITORING');

var udKeys = ['premium', 'pro', 'subscription', 'purchased', 'paid', 'trial',
    'expire', 'entitle', 'unlock', 'vip', 'coins', 'credits', 'token',
    'limit', 'count', 'ads', 'ad_free', 'remove_ads', 'grok', 'gemini',
    'seedance', 'pika', 'pixverse', 'kie', 'daily', 'free', 'quota',
    'remaining', 'video', 'generation', 'plan'];

function isUDInteresting(key) {
    if (!key) return false;
    var kl = key.toLowerCase();
    return udKeys.some(function (ik) { return kl.indexOf(ik) !== -1; });
}

try {
    // Writes
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
                            log('UD', '✏️  SET ' + result[0] + ' = ' + result[1].substring(0, 150), C.y);
                        }
                    } catch (e) {}
                }
            });
        } catch (e) {}
    });

    // Reads
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
                                ? new ObjC.Object(retval).toString().substring(0, 150)
                                : retval.toInt32().toString();
                            log('UD', '📖 GET ' + this.key + ' = ' + val, C.c);
                        } catch (e) {}
                    }
                }
            });
        } catch (e) {}
    });

    log('UD', '✓ UserDefaults monitoring loaded', C.g);
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
                            log('KC', kcFuncs[name][0] + ' ' + name + ': ' + query.substring(0, 250), kcFuncs[name][1]);
                        } catch (e) {}
                    }
                });
            }
        } catch (e) {}
    });

    log('KC', '✓ Keychain monitoring loaded', C.g);
} catch (e) {}


// ==========================================
// 9. FIREBASE FIRESTORE DEEP MONITORING
// ==========================================
banner('FIREBASE DEEP MONITORING');

// 9a. Firestore collections/documents
try {
    if (ObjC.classes.FIRFirestore) {
        ['- collectionWithPath:', '- documentWithPath:'].forEach(function (m) {
            try {
                Interceptor.attach(ObjC.classes.FIRFirestore[m].implementation, {
                    onEnter: function (args) {
                        try {
                            var path = new ObjC.Object(args[2]).toString();
                            log('FB', 'Firestore ' + m.split(':')[0].replace('- ', '') + ': ' + path, C.c);
                        } catch (e) {}
                    }
                });
            } catch (e) {}
        });
    }
} catch (e) {}

// 9b. FIRDocumentReference getDocument
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

// 9c. FIRQuery getDocuments
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

// 9d. FIRDocumentReference setData / updateData
try {
    if (ObjC.classes.FIRDocumentReference) {
        ['- setData:completion:', '- setData:merge:completion:', '- updateData:completion:'].forEach(function (m) {
            try {
                Interceptor.attach(ObjC.classes.FIRDocumentReference[m].implementation, {
                    onEnter: function (args) {
                        try {
                            var ref = new ObjC.Object(args[0]);
                            var data = new ObjC.Object(args[2]);
                            log('FB', '✏️  WRITE ' + ref.path().toString() + ': ' + data.toString().substring(0, 300), C.y);
                        } catch (e) {}
                    }
                });
            } catch (e) {}
        });
    }
} catch (e) {}

// 9e. Firebase Analytics
try {
    if (ObjC.classes.FIRAnalytics) {
        Interceptor.attach(ObjC.classes.FIRAnalytics['+ logEventWithName:parameters:'].implementation, {
            onEnter: function (args) {
                try {
                    var name = new ObjC.Object(args[2]).toString();
                    var params = new ObjC.Object(args[3]);
                    var p = params && !params.isNull() ? ' ' + params.toString().substring(0, 200) : '';
                    log('FB', '📊 Event: ' + name + p, C.c);
                } catch (e) {}
            }
        });
    }
} catch (e) {}

// 9f. Firebase Auth state
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
// HEARTBEAT
// ==========================================
var startTime = Date.now();
setInterval(function () {
    var elapsed = Math.floor((Date.now() - startTime) / 1000);
    var mins = Math.floor(elapsed / 60);
    var secs = elapsed % 60;
    log('♥', mins + 'm ' + secs + 's — alive', C.g);
}, 30000);

console.log('\n' + C.bg + C.w + ' ══════════════════════════════════════════════════════ ' + C.R);
console.log(C.bg + C.w + '  AI_Video_Maker Hook Script v3 — DIFF-AWARE BUILD    ' + C.R);
console.log(C.bg + C.w + '  Modules: SSL | JB | FRIDA | SCREEN | NET | IAP      ' + C.R);
console.log(C.bg + C.w + '           UD | KEYCHAIN | FIREBASE | ADS             ' + C.R);
console.log(C.bg + C.w + '  Target APIs: Kie.AI | Grok | Gemini | Seedance      ' + C.R);
console.log(C.bg + C.w + '              Pika | PixVerse | Firebase               ' + C.R);
console.log(C.bg + C.w + ' ══════════════════════════════════════════════════════ ' + C.R + '\n');
