// SaboraTV API Monitor — Extract endpoints, tokens, and auth data
// Usage: frida -U -f com.plebits.saboratv -l saboratv-api-monitor.js --no-pause
// Run ALONGSIDE the bypass: frida -U com.plebits.saboratv -l saboratv-api-monitor.js

(function () {
    'use strict';
    var TAG = '[API-MON]';
    var seen = {};

    console.log(TAG + ' =============================================');
    console.log(TAG + ' SaboraTV API Monitor');
    console.log(TAG + ' Capturing: endpoints, tokens, headers, keys');
    console.log(TAG + ' =============================================');

    // ==========================================
    // 1. NSURLRequest — capture ALL requests with full headers
    // ==========================================
    setTimeout(function () {
        try {
            var NSURLSession = ObjC.classes.NSURLSession;
            if (!NSURLSession) return;

            var methods = [
                "- dataTaskWithRequest:completionHandler:",
                "- dataTaskWithRequest:",
                "- uploadTaskWithRequest:fromData:completionHandler:",
                "- uploadTaskWithRequest:fromData:",
                "- downloadTaskWithRequest:completionHandler:",
                "- downloadTaskWithRequest:"
            ];

            methods.forEach(function (sel) {
                try {
                    var m = NSURLSession[sel];
                    if (!m) return;
                    Interceptor.attach(m.implementation, {
                        onEnter: function (args) {
                            try {
                                var req = ObjC.Object(args[2]);
                                var url = "";
                                try {
                                    url = req.URL().absoluteString().toString();
                                } catch (e) {
                                    try { url = req.absoluteString().toString(); } catch (e2) { return; }
                                }

                                var method = "GET";
                                try { method = req.HTTPMethod().toString(); } catch (e) {}

                                var key = method + ' ' + url;
                                if (seen[key]) return;
                                seen[key] = true;

                                console.log('\n' + TAG + ' ─────────────────────────────────────');
                                console.log(TAG + ' ' + method + ' ' + url);

                                // Extract ALL headers
                                try {
                                    var headers = req.allHTTPHeaderFields();
                                    if (headers && !headers.isNull()) {
                                        var keys = headers.allKeys();
                                        var count = keys.count();
                                        for (var i = 0; i < count; i++) {
                                            var hKey = keys.objectAtIndex_(i).toString();
                                            var hVal = headers.objectForKey_(keys.objectAtIndex_(i)).toString();
                                            var lk = hKey.toLowerCase();
                                            var isSecret = (lk.indexOf('auth') !== -1 || lk.indexOf('token') !== -1 ||
                                                lk.indexOf('key') !== -1 || lk.indexOf('secret') !== -1 ||
                                                lk.indexOf('bearer') !== -1 || lk.indexOf('api') !== -1 ||
                                                lk.indexOf('x-') !== -1 || lk.indexOf('cookie') !== -1 ||
                                                lk.indexOf('session') !== -1);
                                            if (isSecret) {
                                                console.log(TAG + '   ★ ' + hKey + ': ' + hVal);
                                            } else {
                                                console.log(TAG + '     ' + hKey + ': ' + hVal);
                                            }
                                        }
                                    }
                                } catch (e) {}

                                // Extract body for POST/PUT/PATCH
                                if (method === "POST" || method === "PUT" || method === "PATCH") {
                                    try {
                                        var body = req.HTTPBody();
                                        if (body && !body.isNull()) {
                                            var bodyStr = ObjC.classes.NSString.alloc().initWithData_encoding_(body, 4).toString();
                                            if (bodyStr.length > 2000) bodyStr = bodyStr.substring(0, 2000) + '... [truncated]';
                                            console.log(TAG + '   BODY: ' + bodyStr);
                                        }
                                    } catch (e) {}
                                }
                            } catch (e) {}
                        }
                    });
                } catch (e) {}
            });
        } catch (e) {}
        console.log(TAG + ' [1] NSURLSession request monitoring active');
    }, 100);

    // ==========================================
    // 2. NSHTTPURLResponse — capture response headers (tokens in responses)
    // ==========================================
    setTimeout(function () {
        try {
            var NSHTTPURLResponse = ObjC.classes.NSHTTPURLResponse;
            if (NSHTTPURLResponse) {
                var initMethod = NSHTTPURLResponse["- initWithURL:statusCode:HTTPVersion:headerFields:"];
                if (initMethod) {
                    Interceptor.attach(initMethod.implementation, {
                        onEnter: function (args) {
                            try {
                                var url = ObjC.Object(args[2]).absoluteString().toString();
                                var statusCode = args[3].toInt32();
                                var headers = ObjC.Object(args[5]);

                                if (statusCode >= 400 || url.indexOf('auth') !== -1 || url.indexOf('token') !== -1 ||
                                    url.indexOf('login') !== -1 || url.indexOf('register') !== -1 ||
                                    url.indexOf('api') !== -1 || url.indexOf('user') !== -1) {
                                    console.log('\n' + TAG + ' ← RESPONSE ' + statusCode + ' ' + url);
                                    if (headers && !headers.isNull()) {
                                        var keys = headers.allKeys();
                                        var count = keys.count();
                                        for (var i = 0; i < count; i++) {
                                            var hKey = keys.objectAtIndex_(i).toString();
                                            var lk = hKey.toLowerCase();
                                            if (lk.indexOf('token') !== -1 || lk.indexOf('auth') !== -1 ||
                                                lk.indexOf('set-cookie') !== -1 || lk.indexOf('session') !== -1 ||
                                                lk.indexOf('key') !== -1 || lk.indexOf('x-') !== -1) {
                                                var hVal = headers.objectForKey_(keys.objectAtIndex_(i)).toString();
                                                console.log(TAG + '   ★ ' + hKey + ': ' + hVal);
                                            }
                                        }
                                    }
                                }
                            } catch (e) {}
                        }
                    });
                }
            }
        } catch (e) {}
        console.log(TAG + ' [2] Response header monitoring active');
    }, 200);

    // ==========================================
    // 3. JSON Response body — extract tokens/keys from response data
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

                            var tokenKeys = ["token", "access_token", "accessToken", "refresh_token",
                                "refreshToken", "auth_token", "authToken", "jwt", "bearer",
                                "api_key", "apiKey", "api_secret", "apiSecret",
                                "developer_token", "developerToken", "dev_token", "devToken",
                                "secret_key", "secretKey", "client_id", "clientId",
                                "client_secret", "clientSecret", "session_token", "sessionToken",
                                "id_token", "idToken", "firebase_token", "fcm_token",
                                "onesignal_token", "push_token", "device_token",
                                "subscription_key", "x-api-key", "base_url", "baseUrl",
                                "endpoint", "server_url", "serverUrl", "ws_url", "wsUrl",
                                "socket_url", "socketUrl"];

                            var found = false;
                            for (var i = 0; i < tokenKeys.length; i++) {
                                try {
                                    var val = obj.objectForKey_(ObjC.classes.NSString.stringWithString_(tokenKeys[i]));
                                    if (val && !val.isNull() && val.toString() !== "nil") {
                                        if (!found) {
                                            console.log('\n' + TAG + ' ★★★ TOKEN/KEY IN JSON RESPONSE ★★★');
                                            found = true;
                                        }
                                        console.log(TAG + '   ' + tokenKeys[i] + ' = ' + val.toString());
                                    }
                                } catch (e) {}
                            }

                            // Check nested "data" object
                            try {
                                var data = obj.objectForKey_(ObjC.classes.NSString.stringWithString_("data"));
                                if (data && !data.isNull() && data.isKindOfClass_(ObjC.classes.NSDictionary)) {
                                    for (var j = 0; j < tokenKeys.length; j++) {
                                        try {
                                            var val2 = data.objectForKey_(ObjC.classes.NSString.stringWithString_(tokenKeys[j]));
                                            if (val2 && !val2.isNull() && val2.toString() !== "nil") {
                                                if (!found) {
                                                    console.log('\n' + TAG + ' ★★★ TOKEN/KEY IN data.{} ★★★');
                                                    found = true;
                                                }
                                                console.log(TAG + '   data.' + tokenKeys[j] + ' = ' + val2.toString());
                                            }
                                        } catch (e) {}
                                    }
                                }
                            } catch (e) {}
                        } catch (e) {}
                    }
                });
            }
        }
    } catch (e) {}
    console.log(TAG + ' [3] JSON response token extraction active');

    // ==========================================
    // 4. Keychain reads — capture stored tokens/keys
    // ==========================================
    try {
        var SecItemCopyMatchingPtr = Module.findExportByName("Security", "SecItemCopyMatching");
        if (SecItemCopyMatchingPtr) {
            Interceptor.attach(SecItemCopyMatchingPtr, {
                onEnter: function (args) {
                    this.query = args[0];
                    this.result = args[1];
                },
                onLeave: function (retval) {
                    if (retval.toInt32() !== 0) return;
                    try {
                        var query = ObjC.Object(this.query);
                        var svce = query.objectForKey_(ObjC.classes.NSString.stringWithString_("svce"));
                        var acct = query.objectForKey_(ObjC.classes.NSString.stringWithString_("acct"));
                        if (!acct || acct.isNull()) return;
                        var aStr = acct.toString();
                        var sStr = svce ? svce.toString() : "";

                        // Read the actual value
                        var resultPtr = this.result;
                        if (resultPtr && !resultPtr.isNull()) {
                            try {
                                var resultObj = ObjC.Object(resultPtr.readPointer());
                                var val = "";
                                if (resultObj.isKindOfClass_(ObjC.classes.NSData)) {
                                    try { val = ObjC.classes.NSString.alloc().initWithData_encoding_(resultObj, 4).toString(); } catch (e) { val = resultObj.toString(); }
                                } else {
                                    val = resultObj.toString();
                                }
                                if (val.length > 0 && val !== "nil") {
                                    console.log(TAG + ' [KC] svce=' + sStr + ' acct=' + aStr + ' → ' + val.substring(0, 500));
                                }
                            } catch (e) {}
                        }
                    } catch (e) {}
                }
            });
        }
    } catch (e) {}
    console.log(TAG + ' [4] Keychain read monitoring active');

    // ==========================================
    // 5. NSUserDefaults — capture stored config/tokens
    // ==========================================
    setTimeout(function () {
        try {
            var NSUserDefaults = ObjC.classes.NSUserDefaults;
            if (NSUserDefaults) {
                var objectForKey = NSUserDefaults["- objectForKey:"];
                if (objectForKey) {
                    var loggedKeys = {};
                    Interceptor.attach(objectForKey.implementation, {
                        onEnter: function (args) {
                            try { this.key = ObjC.Object(args[2]).toString(); } catch (e) { this.key = ""; }
                        },
                        onLeave: function (retval) {
                            if (!this.key || retval.isNull()) return;
                            var lk = this.key.toLowerCase();
                            if (lk.indexOf('token') !== -1 || lk.indexOf('key') !== -1 ||
                                lk.indexOf('secret') !== -1 || lk.indexOf('api') !== -1 ||
                                lk.indexOf('auth') !== -1 || lk.indexOf('endpoint') !== -1 ||
                                lk.indexOf('url') !== -1 || lk.indexOf('base') !== -1 ||
                                lk.indexOf('server') !== -1 || lk.indexOf('host') !== -1 ||
                                lk.indexOf('session') !== -1 || lk.indexOf('config') !== -1) {
                                var mapKey = this.key;
                                if (loggedKeys[mapKey]) return;
                                loggedKeys[mapKey] = true;
                                try {
                                    var val = ObjC.Object(retval).toString();
                                    if (val.length > 0 && val !== "nil" && val !== "(null)") {
                                        console.log(TAG + ' [UD] ' + this.key + ' = ' + val.substring(0, 500));
                                    }
                                } catch (e) {}
                            }
                        }
                    });
                }
            }
        } catch (e) {}
        console.log(TAG + ' [5] NSUserDefaults monitoring active');
    }, 50);

    // ==========================================
    // 6. Flutter MethodChannel — capture channel names and calls
    // ==========================================
    setTimeout(function () {
        try {
            var FlutterMethodChannel = ObjC.classes.FlutterMethodChannel;
            if (FlutterMethodChannel) {
                var invokeMethod = FlutterMethodChannel["- invokeMethod:arguments:"];
                if (invokeMethod) {
                    Interceptor.attach(invokeMethod.implementation, {
                        onEnter: function (args) {
                            try {
                                var method = ObjC.Object(args[2]).toString();
                                var arguments_ = "";
                                try { arguments_ = ObjC.Object(args[3]).toString(); } catch (e) {}
                                if (arguments_.length > 500) arguments_ = arguments_.substring(0, 500) + '...';
                                console.log(TAG + ' [FLUTTER] invokeMethod: ' + method + (arguments_ ? ' args=' + arguments_ : ''));
                            } catch (e) {}
                        }
                    });
                }

                var setHandler = FlutterMethodChannel["- setMethodCallHandler:"];
                if (setHandler) {
                    Interceptor.attach(setHandler.implementation, {
                        onEnter: function (args) {
                            try {
                                var channel = ObjC.Object(args[0]);
                                var name = channel.name ? channel.name().toString() : "unknown";
                                console.log(TAG + ' [FLUTTER] Channel registered: ' + name);
                            } catch (e) {}
                        }
                    });
                }
            }
        } catch (e) {}

        // Also FlutterEventChannel
        try {
            var FlutterEventChannel = ObjC.classes.FlutterEventChannel;
            if (FlutterEventChannel) {
                var setStreamHandler = FlutterEventChannel["- setStreamHandler:"];
                if (setStreamHandler) {
                    Interceptor.attach(setStreamHandler.implementation, {
                        onEnter: function (args) {
                            try {
                                var channel = ObjC.Object(args[0]);
                                var name = channel.name ? channel.name().toString() : "unknown";
                                console.log(TAG + ' [FLUTTER] EventChannel registered: ' + name);
                            } catch (e) {}
                        }
                    });
                }
            }
        } catch (e) {}
        console.log(TAG + ' [6] Flutter channel monitoring active');
    }, 300);

    // ==========================================
    // 7. Info.plist — dump interesting keys
    // ==========================================
    setTimeout(function () {
        try {
            var bundle = ObjC.classes.NSBundle.mainBundle();
            var info = bundle.infoDictionary();
            var interestingKeys = [
                "CFBundleIdentifier", "CFBundleVersion", "CFBundleShortVersionString",
                "API_BASE_URL", "BASE_URL", "SERVER_URL", "BACKEND_URL",
                "API_KEY", "DEVELOPER_TOKEN", "APP_SECRET",
                "ONESIGNAL_APP_ID", "FIREBASE_API_KEY", "SENTRY_DSN",
                "REVENUE_CAT_API_KEY", "RevenueCatAPIKey",
                "com.onesignal.app_id", "com.google.firebase.api_key"
            ];

            console.log('\n' + TAG + ' ─── Info.plist ───');
            interestingKeys.forEach(function (k) {
                try {
                    var val = info.objectForKey_(ObjC.classes.NSString.stringWithString_(k));
                    if (val && !val.isNull() && val.toString() !== "nil") {
                        console.log(TAG + '   ' + k + ' = ' + val.toString());
                    }
                } catch (e) {}
            });

            // Also scan ALL keys for anything with api/token/key/secret/url in the name
            try {
                var allKeys = info.allKeys();
                var count = allKeys.count();
                for (var i = 0; i < count; i++) {
                    var key = allKeys.objectAtIndex_(i).toString();
                    var lk = key.toLowerCase();
                    if ((lk.indexOf('api') !== -1 || lk.indexOf('token') !== -1 ||
                         lk.indexOf('key') !== -1 || lk.indexOf('secret') !== -1 ||
                         lk.indexOf('url') !== -1 || lk.indexOf('server') !== -1 ||
                         lk.indexOf('endpoint') !== -1 || lk.indexOf('dsn') !== -1 ||
                         lk.indexOf('firebase') !== -1 || lk.indexOf('sentry') !== -1 ||
                         lk.indexOf('onesignal') !== -1 || lk.indexOf('revenue') !== -1) &&
                        interestingKeys.indexOf(key) === -1) {
                        var val = info.objectForKey_(allKeys.objectAtIndex_(i));
                        if (val && !val.isNull()) {
                            console.log(TAG + '   ' + key + ' = ' + val.toString().substring(0, 300));
                        }
                    }
                }
            } catch (e) {}
        } catch (e) {}
    }, 500);

    // ==========================================
    // 8. Firebase/Google config — GoogleService-Info.plist
    // ==========================================
    setTimeout(function () {
        try {
            var fm = ObjC.classes.NSFileManager.defaultManager();
            var bundle = ObjC.classes.NSBundle.mainBundle();
            var googlePlist = bundle.pathForResource_ofType_("GoogleService-Info", "plist");
            if (googlePlist && !googlePlist.isNull()) {
                var dict = ObjC.classes.NSDictionary.dictionaryWithContentsOfFile_(googlePlist);
                if (dict && !dict.isNull()) {
                    console.log('\n' + TAG + ' ─── GoogleService-Info.plist ───');
                    var keys = dict.allKeys();
                    var count = keys.count();
                    for (var i = 0; i < count; i++) {
                        var key = keys.objectAtIndex_(i).toString();
                        var val = dict.objectForKey_(keys.objectAtIndex_(i)).toString();
                        console.log(TAG + '   ' + key + ' = ' + val);
                    }
                }
            }
        } catch (e) {}
    }, 600);

    console.log('\n' + TAG + ' =============================================');
    console.log(TAG + ' All monitors active — use the app normally');
    console.log(TAG + ' Endpoints and tokens will appear as traffic flows');
    console.log(TAG + ' =============================================\n');
})();
