# MASVS Mapping Reference for iOS Security Wizard

## Overview

The **iOS Security Wizard** provides a set of static and dynamic analysis utilities that align with the **OWASP Mobile Application Security Verification Standard (MASVS) v2** and the accompanying **Mobile Security Testing Guide (MSTG)**. This reference maps each MASVS requirement to the specific wizard command(s), expected output, and verification criteria. The mapping is split by MASVS “Control” categories.

---

## MASVS‑STORAGE (Secure Data at Rest)

| MASVS ID | Requirement (excerpt) | Wizard Tool | Command | Expected Output / Success Indicator |
|----------|-----------------------|------------|--------|--------------------------------------|
| **MASVS‑STORAGE‑1** | Sensitive data must be stored encrypted. | `storagecheck` | `storagecheck encrypt ./tmp/Payload/MyApp.app` | JSON list of files flagged as **unencrypted**; each entry includes `path`, `size`, and `type` (Keychain, NSUserDefaults, file). Successful if list is empty.
| **MASVS‑STORAGE‑2** | Use iOS Keychain for secrets; avoid plain‑text files. | `keychaininfo` | `keychaininfo dump ./tmp/Payload/MyApp.app` | JSON array of keychain items with `kSecAttrService`, `kSecAttrAccount`, and `kSecAttrAccessible`. Presence of any `kSecAttrAccessibleWhenUnlocked` without `kSecAttrAccessibleAfterFirstUnlock` is reported as **warning**.
| **MASVS‑STORAGE‑3** | Filesystem storage must use appropriate file‑protection attributes. | `fileattr` | `fileattr verify ./tmp/Payload/MyApp.app` | Table summarising `NSFileProtectionComplete` vs `None`. All relevant files (e.g., `*.sqlite`, `*.plist`) must have `NSFileProtectionComplete`.
| **MASVS‑STORAGE‑4** | Data must be wiped on uninstall. | `uninstallcheck` | `uninstallcheck simulate ./tmp/Payload/MyApp.app` | Report indicates whether any data resides in the `Documents/` directory that is not covered by `NSFileProtectionComplete`. Success when **no** such files exist.
| **MASVS‑STORAGE‑5** | Prevent data leakage via backup. | `backupcheck` | `backupcheck analyze ./tmp/Payload/MyApp.app` | JSON showing `NSURLIsExcludedFromBackupKey` status for each file. All user‑generated files must have the key set to `true`.

---

## MASVS‑CRYPTO (Cryptography)

| MASVS ID | Requirement | Wizard Tool | Command | Expected Output |
|----------|-------------|------------|--------|-----------------|
| **MASVS‑CRYPTO‑1** | Use approved cryptographic algorithms (AES‑GCM, RSA‑OAEP). | `cryptocheck` | `cryptocheck algorithms ./tmp/Payload/MyApp.app` | List of cryptographic API calls; each entry includes `module` (CommonCrypto, Security), `algorithm`, and `mode`. All entries must be in the **Allowed** set.
| **MASVS‑CRYPTO‑2** | Private keys must be stored in Secure Enclave or Keychain. | `keystoreinfo` | `keystoreinfo audit ./tmp/Payload/MyApp.app` | JSON of private key locations. Any key found in the bundle resources (e.g., `.p12` file) is flagged.
| **MASVS‑CRYPTO‑3** | Use a cryptographically secure RNG. | `rngcheck` | `rngcheck analyze ./tmp/Payload/MyApp.app` | Detects usage of `arc4random`, `drand48`, or `SecRandomCopyBytes`. Only `SecRandomCopyBytes` is acceptable; others raise **warning**.
| **MASVS‑CRYPTO‑4** | Verify proper handling of certificate pinning. | `pinningcheck` | `pinningcheck inspect ./tmp/Payload/MyApp.app` | JSON listing of `NSURLSession` / `AFHTTPSessionManager` configurations. Should include `TLSPinnedCertificates` or `publicKeyPins`. Missing pinning yields **fail**.
| **MASVS‑CRYPTO‑5** | Ensure hashes use SHA‑256 or stronger. | `hashcheck` | `hashcheck algorithms ./tmp/Payload/MyApp.app` | Reports any usage of MD5, SHA‑1, or insecure HMAC. All references must be SHA‑256+, otherwise **fail**.

---

## MASVS‑NETWORK (Secure Communication)

| MASVS ID | Requirement | Wizard Tool | Command | Expected Output |
|----------|-------------|------------|--------|-----------------|
| **MASVS‑NETWORK‑1** | Enforce App Transport Security (ATS). | `netcheck` | `netcheck ats ./tmp/Payload/MyApp.app/Info.plist` | JSON with `NSAppTransportSecurity` flags. All `NSAllowsArbitraryLoads` must be **false**; any domain exceptions must be listed under `NSExceptionDomains` with explicit TLS version/pinning.
| **MASVS‑NETWORK‑2** | No clear‑text HTTP traffic. | `netcheck` | `netcheck cleartext ./tmp/Payload/MyApp.app` | Scans the binary for hard‑coded `http://` URLs. Empty list = pass; any entry = fail.
| **MASVS‑NETWORK‑3** | TLS version ≥ 1.2, cipher suite validation. | `tlscheck` | `tlscheck evaluate ./tmp/Payload/MyApp.app` | JSON of TLS configurations extracted from `NSURLSessionConfiguration` and custom SSLContext usage. Any TLS‑1.0/1.1 entries cause **fail**.
| **MASVS‑NETWORK‑4** | Validate certificate pinning implementation. | `pinningcheck` | `pinningcheck verify ./tmp/Payload/MyApp.app` | Shows whether pinning is **static** (bundled certs) or **dynamic** (public‑key pinning). Must be present; otherwise **fail**.
| **MASVS‑NETWORK‑5** | Ensure proper handling of redirects and HSTS. | `netcheck` | `netcheck redirects ./tmp/Payload/MyApp.app` | Detects usage of `allowInvalidSSLCertificate`, `setAllowsAnyHTTPSCertificate`. Any allowance is flagged as **warning**.

---

## MASVS‑PLATFORM (Platform Interaction)

| MASVS ID | Requirement | Wizard Tool | Command | Expected Output |
|----------|-------------|------------|--------|-----------------|
| **MASVS‑PLATFORM‑1** | Secure usage of IPC mechanisms (XPC, URL schemes). | `ipccheck` | `ipccheck audit ./tmp/Payload/MyApp.app` | JSON‑array of XPC services and registered URL schemes. Each XPC service must have `com.apple.security.application-groups` entitlements matching the host app; mismatches are **fail**.
| **MASVS‑PLATFORM‑2** | Validate that custom URL schemes are protected against hijacking. | `urlschemecheck` | `urlschemecheck scan ./tmp/Payload/MyApp.app/Info.plist` | List of schemes; any scheme that lacks a corresponding entitlement or validation in code is flagged.
| **MASVS‑PLATFORM‑3** | Verify that WebViews have content‑security‑policy (CSP) or disable JavaScript if not needed. | `webviewcheck` | `webviewcheck analyze ./tmp/Payload/MyApp.app` | Reports each `WKWebView`/`UIWebView` initialization. Must contain `configuration.preferences.javaScriptEnabled = NO` or a CSP header injection. Absence = **warning**.
| **MASVS‑PLATFORM‑4** | Restrict use of `UIApplicationOpenSettingsURLString` to approved targets. | `urlschemecheck` | `urlschemecheck open-settings ./tmp/Payload/MyApp.app/Info.plist` | Emits any `openURL:` calls targeting settings without user consent. Flagged as **warning**.
| **MASVS‑PLATFORM‑5** | Ensure proper sandboxing of extensions and plugins. | `extcheck` | `extcheck sandbox ./tmp/Payload/MyApp.app/PlugIns` | Checks each `.appex` bundle for `com.apple.security.application-groups` and `com.apple.security.network.client` restrictions. Missing or overly permissive entitlements cause **fail**.

---

## MASVS‑CODE (Code Integrity & Anti‑Reverse Engineering)

| MASVS ID | Requirement | Wizard Tool | Command | Expected Output |
|----------|-------------|------------|--------|-----------------|
| **MASVS‑CODE‑1** | Binary must be signed with a valid Apple certificate. | `signcheck` | `signcheck verify ./tmp/Payload/MyApp.app` | Prints `valid: true` and the leaf certificate fingerprint. Any invalid signature = **fail**.
| **MASVS‑CODE‑2** | Enable Hardened Runtime (if applicable). | `entcheck` | `entcheck hardened ./tmp/Payload/MyApp.app` | Checks for `com.apple.security.cs.runtime` entitlement. Missing = **warning**.
| **MASVS‑CODE‑3** | Detect presence of debug symbols or stripped binaries. | `symbolcheck` | `symbolcheck status ./tmp/Payload/MyApp.app` | Outputs `stripped: true/false`. Unstripped binaries should be **false** (i.e., stripped). If symbols are present, flag as **warning**.
| **MASVS‑CODE‑4** | Detect jailbreak detection evasion. | `antirootcheck` | `antirootcheck scan ./tmp/Payload/MyApp.app` | Lists known jailbreak detection APIs (`statfs`, `system`, `fork`). If none are present, raise **warning** – positive detection is a security feature.
| **MASVS‑CODE‑5** | Verify that `get-task-allow` entitlement is **false** for release builds. | `entcheck` | `entcheck get-task-allow ./tmp/Payload/MyApp.app` | Reports boolean; must be `false`. Anything else = **fail**.
| **MASVS‑CODE‑6** | Ensure `CFBundleExecutable` name matches the binary in the bundle. | `bundlecheck` | `bundlecheck executable ./tmp/Payload/MyApp.app` | Returns `match: true`. Mismatch = **fail**.
| **MASVS‑CODE‑7** | Detect usage of unsafe APIs (`execve`, `system`, `dlopen` with arbitrary paths). | `unsafeapi` | `unsafeapi detect ./tmp/Payload/MyApp.app` | JSON list of unsafe calls with file/line numbers (if debug symbols available). Any entry = **warning**.

---

## MASVS‑RESILIENCE (Resilience Against Attacks)

| MASVS ID | Requirement | Wizard Tool | Command | Expected Output |
|----------|-------------|------------|--------|-----------------|
| **MASVS‑RESILIENCE‑1** | Enforce `NSAppTransportSecurity` exceptions only for trusted domains. | `netcheck` | `netcheck ats-exceptions ./tmp/Payload/MyApp.app/Info.plist` | Lists domain exceptions; each must have a matching pinned certificate. Empty list = **pass**; any missing pin = **fail**.
| **MASVS‑RESILIENCE‑2** | Implement runtime integrity checks (e.g., `SecCodeCopySelf`). | `integritycheck` | `integritycheck detect ./tmp/Payload/MyApp.app` | Reports presence of integrity verification calls. Absence = **warning** (optional check).
| **MASVS‑RESILIENCE‑3** | Use `NSProcessInfo.isOperatingSystemAtLeastVersion` to guard against older OS vulnerabilities. | `compatcheck` | `compatcheck os-version ./tmp/Payload/MyApp.app` | Returns boolean for each supported OS version. Must be **true** for iOS 13+. False entries flagged.

---

## MASVS‑PRIVACY (Privacy Controls)

| MASVS ID | Requirement | Wizard Tool | Command | Expected Output |
|----------|-------------|------------|--------|-----------------|
| **MASVS‑PRIVACY‑1** | Prompt user before accessing location, contacts, camera, microphone. | `privacycheck` | `privacycheck prompts ./tmp/Payload/MyApp.app` | JSON of `Info.plist` usage description keys (`NSLocationWhenInUseUsageDescription`, etc.) and code scans for `requestWhenInUseAuthorization`. All required prompts must be present; missing prompts = **fail**.
| **MASVS‑PRIVACY‑2** | Disclose data collection in the privacy policy URL. | `policycheck` | `policycheck url ./tmp/Payload/MyApp.app/Info.plist` | Checks `NSPrivacyPolicyURL`. Must be a reachable HTTPS URL; empty or HTTP = **fail**.
| **MASVS‑PRIVACY‑3** | Minimise data collection – only collect data required for functionality. | `datamincheck` | `datamincheck audit ./tmp/Payload/MyApp.app` | Generates a high‑level report comparing accessed APIs vs. declared features (derived from `CFBundleDisplayName`). Any API not aligned with a declared feature is flagged as **warning**.

---\n
## L1 vs L2 Coverage

| Level | Description | Toolkit Coverage |
|-------|-------------|-------------------|
| **L1 – Static Verification** | Source‑code‑independent, binary‑only checks (signing, entitlements, resource analysis). | All tools prefixed with `signcheck`, `entcheck`, `storagecheck`, `cryptocheck`, `netcheck`, `ipccheck`, `unsafeapi` operate purely on the extracted IPA.
| **L2 – Dynamic / Gadget Mode** | Runtime instrumentation using a jail‑broken device or an iOS simulator to observe live behaviour (TLS pinning, keychain access, network traffic). | `dynscan` (exposes runtime hooks), `gadgetmode` (loads the app on a device and runs the same commands via Frida scripts). The mapping table marks L2‑only tools with a **✱**.

---

## How to Use the Mapping Table

1. Identify the MASVS requirement you wish to verify.
2. Locate the corresponding row in the table → `Wizard Tool` and `Command`.
3. Run the command against the extracted bundle (default path `./tmp/...`).
4. Append `--json` for machine‑readable results; pipe into `jq` or the wizard’s result‑verifier.
5. Compare the output against the **Expected Output** column. Any deviation should be treated as a non‑compliant finding.

---

## Resources

- OWASP **MASVS v2** (PDF) – https://github.com/OWASP/owasp-masvs
- OWASP **MSTG** – https://github.com/OWASP/owasp-mstg
- Apple **App Security Guide** – https://developer.apple.com/documentation/security
- iOS Security Wizard source repository – `tools/` directory for each command implementation.

---

## AI Agent Notes

- **Table parsing**: Each row is pipe‑delimited; cells may contain inline backticks for commands. Preserve whitespace inside backticks.
- **JSON flag**: All commands support `--json`. Agents should request JSON when feeding results into further analysis pipelines.
- **Path handling**: The default extraction path is `./tmp`. If a user provides a custom path, replace the prefix accordingly.
- **L1/L2 indicator**: Rows marked with a **✱** (asterisk) denote tools that require a device/simulator (dynamic). Agents must ensure a connected device before invocation.
- **Versioning**: This file is version‑controlled; future MASVS revisions should be added as new rows preserving the column order.
