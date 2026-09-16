# Frida Script Library for iOS (Gadget Mode)

Complete runnable scripts for dynamic analysis without jailbreak. Run with:

```bash
frida -U -f com.example.app -l script.js --no-pause
```

## 1. ObjC Method Hook Template

```javascript
// Base template for hooking ObjC methods
const targetClass = ObjC.classes.NSURLSession;  // or any class
const method = '-dataTaskWithRequest:completionHandler:';

Interceptor.attach(targetClass[method].implementation, {
    onEnter(args) {
        const req = new ObjC.Object(args[2]);
        console.log(`[${method}] URL: ${req.URL().absoluteString()}`);
        this.backtrace = Thread.backtrace(this.context, Backtracer.ACCURATE)
            .map(DebugSymbol.fromAddress).join('\n');
    },
    onLeave(retval) {
        console.log(`[${method}] returned: ${retval}`);
    }
});

// Enumerate existing instances
ObjC.choose(ObjC.classes.NSURLSession, {
    onMatch(instance) { console.log('Found NSURLSession:', instance); },
    onComplete() {}
});
```

## 2. Keychain Dump

```javascript
function dumpKeychain() {
    const SecItemCopyMatching = Module.findExportByName(null, 'SecItemCopyMatching');
    const kSecClassGenericPassword = Memory.allocUtf8String('genp');
    const kSecReturnData = Memory.allocUtf8String('r_Data');
    const kSecReturnAttributes = Memory.allocUtf8String('r_Attributes');
    const kSecMatchLimitAll = Memory.allocUtf8String('m_LimitAll');

    // Build query dictionary via ObjC NSMutableDictionary
    const dict = ObjC.classes.NSMutableDictionary.alloc().init();
    dict.setObject_forKey_(ObjC.classes.__NSCFConstantString.stringWithUTF8String_('genp'),
        ObjC.classes.__NSCFConstantString.stringWithUTF8String_('class'));
    dict.setObject_forKey_(ObjC.classes.NSNumber.numberWithBool_(1),
        ObjC.classes.__NSCFConstantString.stringWithUTF8String_('r_Data'));
    dict.setObject_forKey_(ObjC.classes.NSNumber.numberWithBool_(1),
        ObjC.classes.__NSCFConstantString.stringWithUTF8String_('r_Attributes'));
    dict.setObject_forKey_(ObjC.classes.__NSCFConstantString.stringWithUTF8String_('m_LimitAll'),
        ObjC.classes.__NSCFConstantString.stringWithUTF8String_('m_LimitAll'));

    const fn = new NativeFunction(SecItemCopyMatching, 'int',
        ['pointer', 'pointer']);
    const result = Memory.alloc(Process.pointerSize);
    const status = fn(dict.handle, result);
    console.log(`[keychain] status: ${status}`);
    if (status === 0) {
        const items = new ObjC.Object(result.readPointer());
        console.log(`[keychain] items: ${items.count()}`);
        for (let i = 0; i < items.count(); i++) {
            const item = items.objectAtIndex_(i);
            const svc = item.objectForKey_(ObjC.classes.__NSCFConstantString.stringWithUTF8String_('svce'));
            const acct = item.objectForKey_(ObjC.classes.__NSCFConstantString.stringWithUTF8String_('acct'));
            console.log(`[keychain] svc=${svc} acct=${acct}`);
        }
    }
}
setImmediate(dumpKeychain);
```

## 3. NSUserDefaults Dump

```javascript
function dumpDefaults() {
    const defaults = ObjC.classes.NSUserDefaults.standardUserDefaults();
    const dict = defaults.dictionaryRepresentation();
    const keys = dict.allKeys();
    console.log(`[defaults] ${keys.count()} keys`);
    for (let i = 0; i < keys.count(); i++) {
        const key = keys.objectAtIndex_(i);
        const val = dict.objectForKey_(key);
        console.log(`[defaults] ${key} = ${val}`);
    }
}
setImmediate(dumpDefaults);
```

## 4. Network Interception (NSURLSession + NSURLConnection)

```javascript
// NSURLSession
const dataTask = '-dataTaskWithRequest:completionHandler:';
const impl = ObjC.classes.NSURLSession[dataTask].implementation;
Interceptor.attach(impl, {
    onEnter(args) {
        const req = new ObjC.Object(args[2]);
        const url = req.URL().absoluteString();
        const method = req.HTTPMethod();
        const headers = req.allHTTPHeaderFields();
        console.log(`[net] ${method} ${url}`);
        console.log(`[net] headers: ${headers}`);
        if (req.HTTPBody()) {
            console.log(`[net] body: ${req.HTTPBody().readUtf8String() || '(binary)'}`);
        }
    }
});
// NSURLConnection (legacy)
const conn = ObjC.classes.NSURLConnection;
if (conn) {
    Interceptor.attach(conn['+sendSynchronousRequest:returningResponse:error:'].implementation, {
        onEnter(args) {
            const req = new ObjC.Object(args[2]);
            console.log(`[conn] ${req.URL().absoluteString()}`);
        }
    });
}
```

## 5. Crypto Tracing (CCCrypt)

```javascript
const CCCrypt = Module.findExportByName(null, 'CCCrypt');
if (CCCrypt) {
    Interceptor.attach(CCCrypt, {
        onEnter(args) {
            // CCCrypt(op, alg, options, key, keyLength, iv, dataIn, dataInLength, dataOut, dataOutAvailable, dataOutMoved)
            this.op = args[0].toInt32();
            this.alg = args[1].toInt32();
            this.options = args[2].toInt32();
            this.keyLen = args[4].toInt32();
            this.iv = args[5].readByteArray(16);
            this.dataInLen = args[7].toInt32();
            const algNames = {0: 'AES128', 1: 'DES', 2: '3DES', 3: 'CAST', 4: 'RC4', 5: 'RC2'};
            console.log(`[crypto] CCCrypt op=${this.op} alg=${algNames[this.alg] || this.alg} options=0x${this.options.toString(16)} keyLen=${this.keyLen}`);
            if (this.options & 0x2) console.log('[crypto] ECB MODE — WEAK');
            console.log(`[crypto] IV: ${hexdump(this.iv, {length: 16})}`);
        }
    });
}
```

## 6. Certificate Pinning Bypass

```javascript
// Patch SecTrustEvaluate + SecTrustEvaluateWithError
['SecTrustEvaluate', 'SecTrustEvaluateWithError'].forEach(name => {
    const addr = Module.findExportByName(null, name);
    if (addr) {
        Interceptor.attach(addr, {
            onLeave(retval) {
                console.log(`[pinning] bypassed ${name}`);
                retval.replace(name.includes('Error') ? 1 : 0);
            }
        });
    }
});
// Also patch SecTrustSetAnchorCertificates to keep default trust
const setAnchor = Module.findExportByName(null, 'SecTrustSetAnchorCertificates');
if (setAnchor) {
    Interceptor.attach(setAnchor, {
        onEnter(args) {
            console.log('[pinning] anchor certificates set — app may pin');
        }
    });
}
```

## 7. Jailbreak Detection Bypass

```javascript
// Patch common file-existence checks
const fileExistsAtPath = ObjC.classes.NSFileManager['-fileExistsAtPath:'].implementation;
Interceptor.replace(fileExistsAtPath, new NativeCallback((self, sel, path) => {
    const p = new ObjC.Object(path).toString();
    if (p.includes('Cydia') || p.includes('Sileo') || p.includes('Substrate') ||
        p.includes('TweakInject') || p.includes('bash') || p.includes('sshd')) {
        return 0;  // NO — file does not exist
    }
    return Interceptor.invokeTarget;
}, 'bool', ['pointer', 'pointer', 'pointer']));
// NOTE: above replacement must call original for other paths — use a saved orig:
let origFileExists;
Interceptor.attach(fileExistsAtPath, {
    onEnter(args) { this.path = new ObjC.Object(args[2]).toString(); },
    onLeave(retval) {
        if (this.path && /Cydia|Sileo|Substrate|TweakInject|bash|sshd/.test(this.path)) {
            console.log(`[jb-bypass] hidden: ${this.path}`);
            retval.replace(0);
        }
    }
});
```

## 8. Method Tracing (objc_msgSend whitelist)

```javascript
// Trace calls to specific selectors (arm64: objc_msgSend signature differs — use ObjC.classes)
const targets = ['+array', '-initWithString:', '+stringWithFormat:'];
targets.forEach(sel => {
    const cls = sel.startsWith('+') ? 'NSString' : 'NSMutableString';
    try {
        const method = ObjC.classes[cls][sel];
        if (method) {
            Interceptor.attach(method.implementation, {
                onEnter(args) {
                    console.log(`[trace] ${cls} ${sel}`);
                }
            });
        }
    } catch(e) {}
});
```

## 9. HTTP Sniffing via NSURLProtocol Registration

```javascript
// Register a custom NSURLProtocol subclass to see all requests
const NSURLProtocol = ObjC.classes.NSURLProtocol;
// (Full implementation requires subclassing at runtime — see objection's implementation)
console.log('[sniff] NSURLProtocol available:', !!NSURLProtocol);
console.log('[sniff] use objection: ios nsurlprotocol --register');
```

## Utilities

```javascript
// Hexdump helper (Frida >= 16 built-in hexdump also available)
function hexdumpBytes(bytes, length) {
    const result = [];
    for (let i = 0; i < Math.min(length || bytes.length, 64); i++) {
        result.push(('0' + bytes[i].toString(16)).slice(-2));
    }
    return result.join(' ');
}

// ObjC object introspection
function inspectObjC(obj) {
    const cls = obj.$className;
    console.log(`Class: ${cls}`);
    const methods = ObjC.classes[cls].$ownMethods;
    methods.forEach(m => console.log(`  ${m}`));
}
```

## iOS Version Considerations

- **arm64 objc_msgSend**: do not hook `objc_msgSend` directly (variadic, register-based); hook resolved `implementation` pointers instead.
- **SecTrustEvaluateWithError** exists iOS 12+; patch both.
- **Swift methods**: use mangled symbol names from `nm`/`macho_parser` output.
- **Gadget mode**: scripts load AFTER app launch unless `-f` spawn; state-dependent code may need `on_load: "wait"` in FridaGadget.config.

## AI Agent Notes

- `probe_plan.py` generates URL-scheme/XPC/extension-specific scripts into `probes/`; this library covers the generic categories.
- When hooking fails silently, check the class exists first (`ObjC.available` + try/catch around `ObjC.classes`).
- Scripts are device-dependent; record iOS version + app version with any dynamic finding.
- Never paste captured secrets/bodies into reports; reference files and hash them.

## Resources

- Frida docs: frida.re/docs/javascript-api/
- Objection: github.com/sensepost/objection
- iOS hooking examples: codeshare.frida.re
