// SaboraTV Test: ObjC-only hooks (ZERO C-level hooks)
// If this doesn't crash JSC → problem is in C-level hooks
// Usage: frida -U -f com.plebits.saboratv -l saboratv-test-objc-only.js --no-pause

(function () {
    'use strict';
    var TAG = '[TEST-ObjC]';

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

    // H7: IOSSecuritySuite
    try {
        var IOSSecuritySuite = ObjC.classes.IOSSecuritySuite;
        if (IOSSecuritySuite) {
            var methods = ["amIJailbroken", "amIJailbrokenWithFailMessage", "amIJailbrokenWithFailedChecks",
                "amIRunInEmulator", "amIDebugged", "amIReverseEngineered", "amIProxied",
                "amITampered:", "amIRuntimeHooked:", "denyDebugger", "denySymbolHook:",
                "amIJailbrokenWithFailedChecksWithFailedJailbreakChecks"];
            var issCount = 0;
            methods.forEach(function (m) {
                try {
                    var sel = '+ ' + m;
                    if (IOSSecuritySuite[sel]) {
                        Interceptor.attach(IOSSecuritySuite[sel].implementation, {
                            onLeave: function (retval) { retval.replace(0x0); }
                        });
                        issCount++;
                    }
                } catch (e) {}
            });
            console.log(TAG + ' [H7] IOSSecuritySuite (' + issCount + ' hooks)');
        }
    } catch (e) {}

    // H8: Talsec
    try {
        var talsecCount = 0;
        ["SecurityThreatCenter", "TalsecRuntime", "FreeraspFlutterPlugin"].forEach(function (cls) {
            try {
                var klass = ObjC.classes[cls];
                if (klass) {
                    klass.$ownMethods.forEach(function (method) {
                        try {
                            Interceptor.attach(klass[method].implementation, { onLeave: function (retval) {} });
                            talsecCount++;
                        } catch (e) {}
                    });
                }
            } catch (e) {}
        });
        console.log(TAG + ' [H8] Talsec (' + talsecCount + ' hooks)');
    } catch (e) {}

    // H6: NSFileManager (deferred)
    setTimeout(function () {
        try {
            var NSFileManager = ObjC.classes.NSFileManager;
            if (NSFileManager) {
                ["- fileExistsAtPath:", "- fileExistsAtPath:isDirectory:"].forEach(function (sel) {
                    try {
                        if (NSFileManager[sel]) {
                            Interceptor.attach(NSFileManager[sel].implementation, {
                                onEnter: function (args) {
                                    try {
                                        var path = ObjC.Object(args[2]).toString();
                                        if (path.indexOf("Cydia") !== -1 || path.indexOf("substrate") !== -1 ||
                                            path.indexOf("jailbreak") !== -1 || path.indexOf("frida") !== -1 ||
                                            path.indexOf("/var/jb") !== -1 || path.indexOf("TweakInject") !== -1 ||
                                            path.indexOf("Sileo") !== -1 || path.indexOf("preboot") !== -1) this.hide = true;
                                    } catch (e) {}
                                },
                                onLeave: function (retval) { if (this.hide) retval.replace(0x0); }
                            });
                        }
                    } catch (e) {}
                });
                console.log(TAG + ' [H6] NSFileManager -- loaded');
            }
        } catch (e) {}
    }, 50);

    // S3: Ban clear + Device ID spoof via Keychain
    setTimeout(function () {
        try {
            var SecItemDeletePtr = Module.findExportByName("Security", "SecItemDelete");
            var SecItemDelete = new NativeFunction(SecItemDeletePtr, 'int', ['pointer']);
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
        } catch (e) { console.log(TAG + ' [BAN] error: ' + e); }
    }, 0);

    // S8: Screen recording/screenshot (deferred)
    setTimeout(function () {
        try {
            var AppDelegate = ObjC.classes.AppDelegate;
            if (AppDelegate) {
                var screenRec = AppDelegate["- screenRecordingStatusChanged"];
                if (screenRec) Interceptor.attach(screenRec.implementation, { onEnter: function () { return; } });
                var screenshot = AppDelegate["- screenshotHasTaken"];
                if (screenshot) Interceptor.attach(screenshot.implementation, { onEnter: function () { return; } });
                console.log(TAG + ' [S8] Screen recording/screenshot -- loaded');
            }
        } catch (e) {}

        try {
            var UIScreen = ObjC.classes.UIScreen;
            if (UIScreen && UIScreen["- isCaptured"]) {
                Interceptor.attach(UIScreen["- isCaptured"].implementation, {
                    onLeave: function (retval) { retval.replace(0x0); }
                });
            }
        } catch (e) {}
    }, 100);

    // S9: flutter_jailbreak_detection_plus
    try {
        var ApiProvider = ObjC.classes["flutter_jailbreak_detection_plus.SwiftFlutterJailbreakDetectionPlusPlugin"];
        if (!ApiProvider) ApiProvider = ObjC.classes["SwiftFlutterJailbreakDetectionPlusPlugin"];
        if (ApiProvider) {
            ApiProvider.$ownMethods.forEach(function (method) {
                try { Interceptor.attach(ApiProvider[method].implementation, { onLeave: function (retval) {} }); } catch (e) {}
            });
            console.log(TAG + ' [S9] flutter_jailbreak_detection_plus -- loaded');
        }
    } catch (e) {}

    // S14: RevenueCat
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
        console.log(TAG + ' [S14] RevenueCat -- neutralized');
    } catch (e) {}

    // Anti-termination (ObjC only)
    setTimeout(function () {
        try {
            var UIApp = ObjC.classes.UIApplication;
            if (UIApp && UIApp["- terminateWithSuccess"]) {
                Interceptor.attach(UIApp["- terminateWithSuccess"].implementation, {
                    onEnter: function () { console.log(TAG + ' [EXIT] terminateWithSuccess — blocked'); Thread.sleep(86400); }
                });
            }
        } catch (e) {}
    }, 100);

    console.log(TAG + ' ==========================================');
    console.log(TAG + ' ObjC-ONLY test (zero C-level hooks)');
    console.log(TAG + ' If no JSC crash → C hooks are the problem');
    console.log(TAG + ' ==========================================');
})();
