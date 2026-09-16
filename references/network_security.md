# iOS Network Security Reference

ATS, certificate pinning, traffic analysis without jailbreak, and the toolkit's verification path.

## App Transport Security (ATS)

`NSAppTransportSecurity` dict in Info.plist. Default: HTTPS required, TLS 1.2+.

### Key Table (with security severity)

| Key | Effect | Severity if present |
|-----|--------|---------------------|
| `NSAllowsArbitraryLoads` | Disables ATS for ALL connections | CRITICAL |
| `NSAllowsArbitraryLoadsForMedia` | HTTP for AVFoundation media | MEDIUM |
| `NSAllowsArbitraryLoadsInWebContent` | HTTP inside WKWebView | MEDIUM |
| `NSAllowsLocalNetworking` | Plaintext to local hosts | LOW (local only) |
| `NSExceptionDomains.<domain>.NSExceptionAllowsInsecureHTTPLoads` | HTTP to specific domain | HIGH |
| `NSExceptionDomains.<domain>.NSIncludesSubdomains` | Broadens exception | +1 severity step |
| `NSExceptionDomains.<domain>.NSRequiresCertificateTransparency` | Enforces CT | positive control |
| `NSExceptionDomains.<domain>.NSExceptionMinimumTLSVersion` | Lowers TLS floor | MEDIUM-HIGH |

`NSThirdPartyException*` variants apply to third-party domains the app loads — same severity.

## Certificate Pinning

### Techniques
1. **NSURLSession delegate** — `didReceiveChallenge` compares `SecTrustCopyPublicKey`/cert DER against embedded pins.
2. **AFNetworking/Alamofire** — `sslPinningMode`/`PinnedCertificates`.
3. **SecTrustEvaluate** — direct trust evaluation with pinned anchors (`SecTrustSetAnchorCertificates`).

### Weakness Patterns
- Pins stored as plain strings (extractable → replace).
- Pinning only in debug builds.
- `NSAllowsArbitraryLoadsInWebContent` + custom scheme handler bypasses pinning.
- Pins checked after `SecTrustEvaluate` (evaluate accepts any valid chain — no pin enforcement).

## Traffic Analysis Without Jailbreak

### mitmproxy flow
1. Install mitmproxy CA profile on device (Settings → General → About → Certificate Trust Settings → Enable).
2. Wi-Fi proxy → workstation IP:8080.
3. Limitations: pinned apps abort handshake until bypassed.

### SSL Kill Switch (Frida)

```javascript
// Force SecTrustEvaluate to always succeed
const SecTrustEvaluate = Module.findExportByName(null, 'SecTrustEvaluate');
if (SecTrustEvaluate) {
    Interceptor.attach(SecTrustEvaluate, {
        onLeave(retval) { retval.replace(0); }  // kSecTrustResultProceed
    });
}
// Also patch SecTrustEvaluateWithError for iOS 12+
const WithError = Module.findExportByName(null, 'SecTrustEvaluateWithError');
if (WithError) {
    Interceptor.attach(WithError, {
        onLeave(retval) { retval.replace(1); }
    });
}
```

### Objection
```bash
objection -g com.example.app run ios sslpinning disable
```

## Detection Signatures (static)

| String | Meaning |
|--------|---------|
| `SecTrustEvaluate` | Trust evaluation (pinning candidate) |
| `NSAllowsArbitraryLoads` | ATS disabled |
| `NSExceptionAllowsInsecureHTTPLoads` | HTTP exception |
| `sslPinningMode` | AFNetworking pinning |
| `.der` / `.cer` bundled files | Embedded pin candidates |

## AI Agent Notes

- `crypto_scan.py` detects ATS weakening in `__cstring` (category `ats`) and in Info.plist via `ipa_structure.py` (`ats_config` field).
- Info.plist ATS findings: CRITICAL for `NSAllowsArbitraryLoads=true`, HIGH per-domain HTTP exceptions.
- Pinning presence ≠ pinning correctness: verify the pin is actually compared (grep for `SecTrustCopyPublicKey`/`SecTrustGetCertificateAtIndex`).
- Dynamic pinning bypass results (Frida scripts) are device-dependent; report as "bypass demonstrated" only with a captured response.

## Resources

- Apple: NSAppTransportSecurity reference
- OWASP MASVS-NETWORK (MSTG-NETWORK-001..006)
- mitmproxy docs (mitmproxy.org)
