// Frida Script for com.saidul.aivideo (AI_Video_Maker)
// Security Testing & Analysis Script

'use strict';

const Colors = {
    reset: '\x1b[0m',
    red: '\x1b[31m',
    green: '\x1b[32m',
    yellow: '\x1b[33m',
    blue: '\x1b[34m',
    magenta: '\x1b[35m',
    cyan: '\x1b[36m',
};

function log(tag, msg, color) {
    console.log(`${color || Colors.green}[${tag}]${Colors.reset} ${msg}`);
}

// ==========================================
// 1. SSL PINNING BYPASS
// ==========================================
(function sslPinningBypass() {
    log('SSL', 'Setting up SSL Pinning bypass...', Colors.cyan);

    // NSURLSession delegate bypass
    try {
        var NSURLSessionConfiguration = ObjC.classes.NSURLSessionConfiguration;
        Interceptor.attach(NSURLSessionConfiguration['+ defaultSessionConfiguration'].implementation, {
            onLeave: function (retval) {
                var config = new ObjC.Object(retval);
                config.setTLSMinimumSupportedProtocol_(0x0301); // TLSv1.0
            }
        });
    } catch (e) {}

    // URLSession:didReceiveChallenge:completionHandler:
    try {
        var resolver = new ObjC.Block({
            retType: 'void',
            argTypes: ['int', 'pointer'],
            implementation: function (disposition, credential) {}
        });

        var URLSession_didReceiveChallenge = ObjC.classes.NSURLSession['- session:didReceiveChallenge:completionHandler:'];

        if (ObjC.classes.__NSCFURLSessionConnection) {
            Interceptor.attach(
                ObjC.classes.__NSCFURLSessionConnection['- _]handleAuthChallenge:completionHandler:'].implementation, {
                    onEnter: function (args) {
                        var dominated = new ObjC.Object(args[3]);
                        var NSURLCredential = ObjC.classes.NSURLCredential;
                        var challenge = new ObjC.Object(args[2]);
                        var trust = challenge.protectionSpace().serverTrust();
                        var cred = NSURLCredential.credentialForTrust_(trust);
                        var handler = new ObjC.Block(args[3]);
                        handler.implementation = function (disposition, credential) {
                            handler(0, cred);
                        };
                    }
                }
            );
        }
    } catch (e) {}

    // BoringSSL bypass
    try {
        var boringssl_context_set_verify_mode = Module.findExportByName('libboringssl.dylib', 'SSL_set_custom_verify');
        if (boringssl_context_set_verify_mode) {
            Interceptor.attach(boringssl_context_set_verify_mode, {
                onEnter: function (args) {
                    args[1] = ptr(0x0); // SSL_VERIFY_NONE
                }
            });
        }
    } catch (e) {}

    // SSL_CTX_set_custom_verify
    try {
        var ssl_ctx_set = Module.findExportByName('libboringssl.dylib', 'SSL_CTX_set_custom_verify');
        if (ssl_ctx_set) {
            Interceptor.attach(ssl_ctx_set, {
                onEnter: function (args) {
                    args[1] = ptr(0x0);
                }
            });
        }
    } catch (e) {}

    // SecTrustEvaluate
    try {
        var SecTrustEvaluate = Module.findExportByName('Security', 'SecTrustEvaluate');
        if (SecTrustEvaluate) {
            Interceptor.attach(SecTrustEvaluate, {
                onLeave: function (retval) {
                    retval.replace(ptr(0)); // errSecSuccess
                }
            });
        }
    } catch (e) {}

    // SecTrustEvaluateWithError
    try {
        var SecTrustEvaluateWithError = Module.findExportByName('Security', 'SecTrustEvaluateWithError');
        if (SecTrustEvaluateWithError) {
            Interceptor.replace(SecTrustEvaluateWithError, new NativeCallback(function (trust, error) {
                return 1; // true = trusted
            }, 'bool', ['pointer', 'pointer']));
        }
    } catch (e) {}

    // SecTrustEvaluateAsync
    try {
        var SecTrustEvaluateAsync = Module.findExportByName('Security', 'SecTrustEvaluateAsync');
        if (SecTrustEvaluateAsync) {
            Interceptor.attach(SecTrustEvaluateAsync, {
                onEnter: function (args) {
                    // Will allow all
                }
            });
        }
    } catch (e) {}

    // AFNetworking / Alamofire pinning
    try {
        if (ObjC.classes.AFSecurityPolicy) {
            Interceptor.attach(ObjC.classes.AFSecurityPolicy['- setSSLPinningMode:'].implementation, {
                onEnter: function (args) {
                    args[2] = ptr(0x0); // AFSSLPinningModeNone
                }
            });
            Interceptor.attach(ObjC.classes.AFSecurityPolicy['- setAllowInvalidCertificates:'].implementation, {
                onEnter: function (args) {
                    args[2] = ptr(0x1); // YES
                }
            });
        }
    } catch (e) {}

    // TrustKit bypass
    try {
        if (ObjC.classes.TSKPinningValidator) {
            Interceptor.attach(ObjC.classes.TSKPinningValidator['- evaluateTrust:forHostname:'].implementation, {
                onLeave: function (retval) {
                    retval.replace(ptr(0x0)); // TSKTrustDecisionShouldAllowConnection
                }
            });
        }
    } catch (e) {}

    log('SSL', 'SSL Pinning bypass loaded ✓', Colors.green);
})();


// ==========================================
// 2. JAILBREAK DETECTION BYPASS
// ==========================================
(function jailbreakBypass() {
    log('JB', 'Setting up Jailbreak Detection bypass...', Colors.cyan);

    // File existence checks
    var jailbreakPaths = [
        '/Applications/Cydia.app',
        '/Applications/Sileo.app',
        '/Applications/Zebra.app',
        '/usr/sbin/sshd',
        '/usr/bin/ssh',
        '/usr/libexec/sftp-server',
        '/bin/bash',
        '/bin/sh',
        '/etc/apt',
        '/etc/apt/sources.list.d',
        '/private/var/lib/apt',
        '/private/var/lib/cydia',
        '/private/var/stash',
        '/private/var/tmp/cydia.log',
        '/var/cache/apt',
        '/var/lib/apt',
        '/var/lib/cydia',
        '/var/log/syslog',
        '/usr/lib/substrate',
        '/usr/lib/TweakInject',
        '/Library/MobileSubstrate',
        '/var/mobile/Library/SBSettings/Themes',
        '/private/var/mobile/Library/SBSettings/Themes',
        '/System/Library/LaunchDaemons/com.saurik.Cydia.Startup.plist',
        '/usr/libexec/cydia',
        '/.bootstrapped_electra',
        '/usr/lib/libjailbreak.dylib',
        '/jb/lzma',
        '/.cydia_no_stash',
        '/.installed_unc0ver',
        '/jb/jailbreakd.plist',
        '/jb/amfid_payload.dylib',
        '/jb/libjailbreak.dylib',
        '/usr/libexec/ssh-keysign',
        '/Library/LaunchDaemons/com.openssh.sshd.plist',
        '/var/checkra1n.dmg',
        '/var/binpack',
    ];

    // NSFileManager fileExistsAtPath:
    try {
        Interceptor.attach(ObjC.classes.NSFileManager['- fileExistsAtPath:'].implementation, {
            onEnter: function (args) {
                this.path = new ObjC.Object(args[2]).toString();
                this.shouldBlock = jailbreakPaths.some(function (p) {
                    return this.path.indexOf(p) !== -1;
                }.bind(this));
            },
            onLeave: function (retval) {
                if (this.shouldBlock) {
                    retval.replace(ptr(0x0)); // NO
                    log('JB', 'Blocked fileExists: ' + this.path, Colors.yellow);
                }
            }
        });
    } catch (e) {}

    // C-level file access
    var accessFunc = Module.findExportByName(null, 'access');
    if (accessFunc) {
        Interceptor.attach(accessFunc, {
            onEnter: function (args) {
                this.path = args[0].readUtf8String();
                this.shouldBlock = jailbreakPaths.some(function (p) {
                    return this.path && this.path.indexOf(p) !== -1;
                }.bind(this));
            },
            onLeave: function (retval) {
                if (this.shouldBlock) {
                    retval.replace(ptr(-1)); // not found
                }
            }
        });
    }

    // stat / lstat
    ['stat', 'lstat'].forEach(function (fname) {
        var func = Module.findExportByName(null, fname);
        if (func) {
            Interceptor.attach(func, {
                onEnter: function (args) {
                    this.path = args[0].readUtf8String();
                    this.shouldBlock = jailbreakPaths.some(function (p) {
                        return this.path && this.path.indexOf(p) !== -1;
                    }.bind(this));
                },
                onLeave: function (retval) {
                    if (this.shouldBlock) {
                        retval.replace(ptr(-1));
                    }
                }
            });
        }
    });

    // fopen
    var fopenFunc = Module.findExportByName(null, 'fopen');
    if (fopenFunc) {
        Interceptor.attach(fopenFunc, {
            onEnter: function (args) {
                this.path = args[0].readUtf8String();
                this.shouldBlock = jailbreakPaths.some(function (p) {
                    return this.path && this.path.indexOf(p) !== -1;
                }.bind(this));
            },
            onLeave: function (retval) {
                if (this.shouldBlock) {
                    retval.replace(ptr(0x0)); // NULL
                }
            }
        });
    }

    // canOpenURL (cydia://, sileo://)
    try {
        Interceptor.attach(ObjC.classes.UIApplication['- canOpenURL:'].implementation, {
            onEnter: function (args) {
                this.url = new ObjC.Object(args[2]).toString();
            },
            onLeave: function (retval) {
                if (this.url && (
                    this.url.indexOf('cydia') !== -1 ||
                    this.url.indexOf('sileo') !== -1 ||
                    this.url.indexOf('zbra') !== -1 ||
                    this.url.indexOf('filza') !== -1 ||
                    this.url.indexOf('undecimus') !== -1
                )) {
                    retval.replace(ptr(0x0)); // NO
                    log('JB', 'Blocked canOpenURL: ' + this.url, Colors.yellow);
                }
            }
        });
    } catch (e) {}

    // fork() detection
    var forkFunc = Module.findExportByName(null, 'fork');
    if (forkFunc) {
        Interceptor.attach(forkFunc, {
            onLeave: function (retval) {
                retval.replace(ptr(-1)); // fork failed = not jailbroken
            }
        });
    }

    // dyld checks (for substrate/tweak injection)
    var _dyld_image_count = Module.findExportByName(null, '_dyld_image_count');
    var _dyld_get_image_name = Module.findExportByName(null, '_dyld_get_image_name');

    if (_dyld_get_image_name) {
        Interceptor.attach(_dyld_get_image_name, {
            onLeave: function (retval) {
                if (retval.isNull()) return;
                try {
                    var name = retval.readUtf8String();
                    if (name && (
                        name.indexOf('substrate') !== -1 ||
                        name.indexOf('substitute') !== -1 ||
                        name.indexOf('TweakInject') !== -1 ||
                        name.indexOf('ellekit') !== -1 ||
                        name.indexOf('CydiaSubstrate') !== -1 ||
                        name.indexOf('FridaGadget') !== -1 ||
                        name.indexOf('frida') !== -1 ||
                        name.indexOf('libcycript') !== -1
                    )) {
                        retval.replace(Memory.allocUtf8String('/usr/lib/libSystem.B.dylib'));
                    }
                } catch (e) {}
            }
        });
    }

    // sysctl (P_TRACED check - anti-debug)
    var sysctl = Module.findExportByName(null, 'sysctl');
    if (sysctl) {
        Interceptor.attach(sysctl, {
            onEnter: function (args) {
                var mib = args[0];
                var mib0 = mib.readS32();
                var mib1 = mib.add(4).readS32();
                var mib2 = mib.add(8).readS32();
                var mib3 = mib.add(12).readS32();
                // CTL_KERN, KERN_PROC, KERN_PROC_PID
                if (mib0 === 1 && mib1 === 14 && mib2 === 1) {
                    this.isDebugCheck = true;
                    this.outBuf = args[2];
                }
            },
            onLeave: function (retval) {
                if (this.isDebugCheck && this.outBuf && !this.outBuf.isNull()) {
                    try {
                        // Clear P_TRACED flag (offset 32 in kinfo_proc -> kp_proc.p_flag)
                        var flags = this.outBuf.add(32).readU32();
                        flags &= ~0x800; // P_TRACED = 0x800
                        this.outBuf.add(32).writeU32(flags);
                    } catch (e) {}
                }
            }
        });
    }

    // getenv DYLD_INSERT_LIBRARIES
    var getenv = Module.findExportByName(null, 'getenv');
    if (getenv) {
        Interceptor.attach(getenv, {
            onEnter: function (args) {
                this.key = args[0].readUtf8String();
            },
            onLeave: function (retval) {
                if (this.key === 'DYLD_INSERT_LIBRARIES') {
                    retval.replace(ptr(0x0));
                }
            }
        });
    }

    log('JB', 'Jailbreak Detection bypass loaded ✓', Colors.green);
})();


// ==========================================
// 3. FRIDA DETECTION BYPASS
// ==========================================
(function fridaDetectionBypass() {
    log('FRIDA', 'Setting up Frida Detection bypass...', Colors.cyan);

    // Block connections to Frida default port
    var connectFunc = Module.findExportByName(null, 'connect');
    if (connectFunc) {
        Interceptor.attach(connectFunc, {
            onEnter: function (args) {
                var sockAddr = args[1];
                var family = sockAddr.readU16();
                if (family === 2) { // AF_INET
                    var port = (sockAddr.add(2).readU8() << 8) | sockAddr.add(3).readU8();
                    if (port === 27042) {
                        this.blockConnect = true;
                    }
                }
            },
            onLeave: function (retval) {
                if (this.blockConnect) {
                    retval.replace(ptr(-1));
                    log('FRIDA', 'Blocked connect to port 27042', Colors.yellow);
                }
            }
        });
    }

    // String-based Frida detection
    var strstr = Module.findExportByName(null, 'strstr');
    if (strstr) {
        Interceptor.attach(strstr, {
            onEnter: function (args) {
                try {
                    this.needle = args[1].readUtf8String();
                } catch (e) { this.needle = null; }
            },
            onLeave: function (retval) {
                if (this.needle && (
                    this.needle === 'frida' ||
                    this.needle === 'FRIDA' ||
                    this.needle === 'gum-js-loop' ||
                    this.needle === 'gmain' ||
                    this.needle === 'linjector'
                )) {
                    retval.replace(ptr(0x0));
                }
            }
        });
    }

    log('FRIDA', 'Frida Detection bypass loaded ✓', Colors.green);
})();


// ==========================================
// 4. NETWORK / API MONITORING
// ==========================================
(function networkMonitoring() {
    log('NET', 'Setting up Network monitoring...', Colors.cyan);

    // NSURLRequest monitoring
    try {
        Interceptor.attach(ObjC.classes.NSMutableURLRequest['- setHTTPBody:'].implementation, {
            onEnter: function (args) {
                var req = new ObjC.Object(args[0]);
                var body = new ObjC.Object(args[2]);
                try {
                    var url = req.URL().absoluteString().toString();
                    var bodyStr = ObjC.classes.NSString.alloc().initWithData_encoding_(body, 4).toString();
                    log('NET', '→ POST ' + url, Colors.blue);
                    log('NET', '  Body: ' + bodyStr.substring(0, 500), Colors.blue);
                } catch (e) {}
            }
        });
    } catch (e) {}

    // NSURLSession dataTaskWithRequest
    try {
        var methods = [
            '- dataTaskWithRequest:completionHandler:',
            '- dataTaskWithRequest:',
        ];
        methods.forEach(function (method) {
            try {
                Interceptor.attach(ObjC.classes.NSURLSession[method].implementation, {
                    onEnter: function (args) {
                        var request = new ObjC.Object(args[2]);
                        try {
                            var url = request.URL().absoluteString().toString();
                            var method = request.HTTPMethod().toString();
                            log('NET', '→ ' + method + ' ' + url, Colors.blue);

                            var headers = request.allHTTPHeaderFields();
                            if (headers) {
                                var keys = headers.allKeys();
                                for (var i = 0; i < keys.count(); i++) {
                                    var key = keys.objectAtIndex_(i).toString();
                                    var val = headers.objectForKey_(keys.objectAtIndex_(i)).toString();
                                    if (key.toLowerCase().indexOf('auth') !== -1 ||
                                        key.toLowerCase().indexOf('token') !== -1 ||
                                        key.toLowerCase().indexOf('api') !== -1) {
                                        log('NET', '  Header: ' + key + ': ' + val.substring(0, 80), Colors.magenta);
                                    }
                                }
                            }
                        } catch (e) {}
                    }
                });
            } catch (e) {}
        });
    } catch (e) {}

    log('NET', 'Network monitoring loaded ✓', Colors.green);
})();


// ==========================================
// 5. STOREKIT MONITORING
// ==========================================
(function storeKitMonitoring() {
    log('IAP', 'Setting up StoreKit monitoring...', Colors.cyan);

    // SKPaymentQueue
    try {
        Interceptor.attach(ObjC.classes.SKPaymentQueue['- addPayment:'].implementation, {
            onEnter: function (args) {
                var payment = new ObjC.Object(args[2]);
                var productId = payment.productIdentifier().toString();
                log('IAP', 'Purchase requested: ' + productId, Colors.magenta);
            }
        });
    } catch (e) {}

    // SKPaymentTransaction observer
    try {
        Interceptor.attach(ObjC.classes.SKPaymentTransaction['- transactionState'].implementation, {
            onLeave: function (retval) {
                var states = ['Purchasing', 'Purchased', 'Failed', 'Restored', 'Deferred'];
                var state = retval.toInt32();
                if (state >= 0 && state < states.length) {
                    var tx = new ObjC.Object(this.context.x0 || this.context.r0);
                    try {
                        var productId = tx.payment().productIdentifier().toString();
                        log('IAP', 'Transaction: ' + productId + ' → ' + states[state], Colors.magenta);
                    } catch (e) {
                        log('IAP', 'Transaction state: ' + states[state], Colors.magenta);
                    }
                }
            }
        });
    } catch (e) {}

    // AI_Video_Maker.StoreKitManager
    try {
        var storeKitClasses = ['AI_Video_Maker.StoreKitManager', 'AI_Video_Maker.StoreKit2Manager'];
        storeKitClasses.forEach(function (className) {
            if (ObjC.classes[className]) {
                var methods = ObjC.classes[className].$ownMethods;
                methods.forEach(function (method) {
                    try {
                        Interceptor.attach(ObjC.classes[className][method].implementation, {
                            onEnter: function () {
                                log('IAP', className + ' ' + method, Colors.magenta);
                            }
                        });
                    } catch (e) {}
                });
                log('IAP', 'Hooked ' + methods.length + ' methods on ' + className, Colors.green);
            }
        });
    } catch (e) {}

    log('IAP', 'StoreKit monitoring loaded ✓', Colors.green);
})();


// ==========================================
// 6. FIREBASE / ANALYTICS MONITORING
// ==========================================
(function firebaseMonitoring() {
    log('FB', 'Setting up Firebase monitoring...', Colors.cyan);

    // Firestore reads
    try {
        if (ObjC.classes.FIRFirestore) {
            var firestoreMethods = ObjC.classes.FIRFirestore.$ownMethods;
            firestoreMethods.forEach(function (method) {
                if (method.indexOf('collection') !== -1 || method.indexOf('document') !== -1) {
                    try {
                        Interceptor.attach(ObjC.classes.FIRFirestore[method].implementation, {
                            onEnter: function (args) {
                                try {
                                    var path = new ObjC.Object(args[2]).toString();
                                    log('FB', 'Firestore: ' + method + ' → ' + path, Colors.cyan);
                                } catch (e) {}
                            }
                        });
                    } catch (e) {}
                }
            });
        }
    } catch (e) {}

    // Firebase Analytics
    try {
        if (ObjC.classes.FIRAnalytics) {
            Interceptor.attach(ObjC.classes.FIRAnalytics['+ logEventWithName:parameters:'].implementation, {
                onEnter: function (args) {
                    var name = new ObjC.Object(args[2]).toString();
                    log('FB', 'Analytics event: ' + name, Colors.cyan);
                }
            });
        }
    } catch (e) {}

    log('FB', 'Firebase monitoring loaded ✓', Colors.green);
})();


// ==========================================
// 7. GOOGLE ADS (ADMOB) MONITORING
// ==========================================
(function admobMonitoring() {
    log('ADS', 'Setting up AdMob monitoring...', Colors.cyan);

    // GADInterstitialAd
    try {
        if (ObjC.classes.GADInterstitialAd) {
            Interceptor.attach(ObjC.classes.GADInterstitialAd['+ loadWithAdUnitID:request:completionHandler:'].implementation, {
                onEnter: function (args) {
                    var adUnitId = new ObjC.Object(args[2]).toString();
                    log('ADS', 'Interstitial load: ' + adUnitId, Colors.yellow);
                }
            });
        }
    } catch (e) {}

    // GADBannerView
    try {
        if (ObjC.classes.GADBannerView) {
            Interceptor.attach(ObjC.classes.GADBannerView['- loadRequest:'].implementation, {
                onEnter: function () {
                    log('ADS', 'Banner ad load requested', Colors.yellow);
                }
            });
        }
    } catch (e) {}

    // GADRewardedAd
    try {
        if (ObjC.classes.GADRewardedAd) {
            Interceptor.attach(ObjC.classes.GADRewardedAd['+ loadWithAdUnitID:request:completionHandler:'].implementation, {
                onEnter: function (args) {
                    var adUnitId = new ObjC.Object(args[2]).toString();
                    log('ADS', 'Rewarded ad load: ' + adUnitId, Colors.yellow);
                }
            });
        }
    } catch (e) {}

    log('ADS', 'AdMob monitoring loaded ✓', Colors.green);
})();


// ==========================================
// HEARTBEAT
// ==========================================
var startTime = Date.now();
setInterval(function () {
    var elapsed = Math.floor((Date.now() - startTime) / 1000);
    log('HEARTBEAT', 't=' + elapsed + 's — script alive', Colors.green);
}, 30000);

log('READY', '═══════════════════════════════════════════', Colors.green);
log('READY', ' AI_Video_Maker hook script loaded!', Colors.green);
log('READY', ' Modules: SSL | JB | Frida | NET | IAP | FB | ADS', Colors.green);
log('READY', '═══════════════════════════════════════════', Colors.green);
