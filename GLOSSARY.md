# GLOSSARY — iOS Security Terms

## Binary Format

| Term | Definition |
|------|-----------|
| **Mach-O** | The executable format on iOS/macOS. Consists of a header, load commands, segments, and sections. |
| **Fat/Universal binary** | A container holding multiple Mach-O binaries for different architectures. Identified by magic `0xcafebabe`. |
| **Load command (LC_*)** | Instructions to the loader: LC_SEGMENT_64, LC_SYMTAB, LC_CODE_SIGNATURE, etc. |
| **Segment** | A named memory region (__TEXT, __DATA, __LINKEDIT) with permissions. |
| **Section** | A named sub-region of a segment (__text, __objc_classlist, __cstring). |
| **PIE (MH_PIE)** | Position-Independent Executable — ASLR-compatible. Flag 0x200000. |
| **Chained fixups** | Modern relocation format (LC_DYLD_CHAINED_FIXUPS). Pointers stored as delta-encoded chains; used for PAC and dyld rebasing. |
| **LC_DYLD_EXPORTS_TRIE** | Load command pointing to the exports trie — a compact prefix tree of exported symbols. |

## Code Signing

| Term | Definition |
|------|-----------|
| **CodeDirectory** | Structure containing per-page hashes of the binary, plus entitlements and requirements. |
| **Entitlements** | Capabilities granted to an app (keychain groups, sandbox extensions). Enforced by code signature. |
| **embedded.mobileprovision** | CMS-signed provisioning profile inside the app bundle: team ID, expiration, device list, entitlements. |
| **Hardened Runtime** | macOS/iOS feature requiring explicit opt-out flags for JIT, unsigned memory, library validation. |
| **Designated Requirement (DR)** | The code requirement the signature must satisfy (identifier, anchor). |
| **Team ID** | 10-char identifier of the Apple Developer team that signed the binary. |

## Runtime Protection

| Term | Definition |
|------|-----------|
| **ASLR** | Address Space Layout Randomization — randomizes image, heap, stack bases. |
| **PAC** | Pointer Authentication — ARMv8.3 feature signing pointers with a keyed MAC. Keys: IA, IB, DA, DB, GA. |
| **Sandbox** | Seatbelt profile restricting filesystem, network, IPC per app. |
| **AMFI** | Apple Mobile File Integrity — kernel enforcement of code signing. |
| **SIP** | System Integrity Protection — protects system files from modification even by root. |
| **MobileGestalt** | System service exposing device properties (model, build, serial, security domain). |

## IPC & Services

| Term | Definition |
|------|-----------|
| **XPC** | Inter-process communication mechanism. Connections carry serialized objects over Mach ports. |
| **Mach service** | A named endpoint registered with launchd that XPC clients connect to. |
| **launchd** | PID 1; manages daemons, agents, and Mach service registration. |
| **LaunchDaemon** | System-wide background service (runs as root). |
| **LaunchAgent** | Per-user background service. |
| **URL scheme** | Custom `app://` protocol registered in CFBundleURLTypes — an entry point from other apps. |
| **App extension** | Bundled sub-app (.appex) exposing a service point (share, keyboard, widget). |
| **App group** | Shared container enabling data exchange between an app and its extensions. |
| **Audit token** | Identity (pid/uid/gid/audit session) of the XPC client — must be validated server-side. |

## Instrumentation

| Term | Definition |
|------|-----------|
| **Frida** | Dynamic instrumentation framework. Injects a JS engine into the target process. |
| **Frida gadget** | A dylib injected into the app bundle — the no-jailbreak path. Loaded via LC_LOAD_DYLIB insertion + re-signing. |
| **Objection** | Frida-based exploration toolkit (keychain dump, URL scheme fuzzing, filesystem browsing). |
| **dyld interposing** | Overriding dyld API calls by inserting a library earlier in the load order. |
| **Method swizzling** | Replacing an ObjC method implementation at runtime. |

## Static Analysis

| Term | Definition |
|------|-----------|
| **IPA** | iOS App Store package — a zip containing Payload/App.app. |
| **.app bundle** | Directory containing the main binary, Info.plist, resources, frameworks. |
| **Info.plist** | Bundle metadata: identifier, URL types, extensions, background modes, ATS config. |
| **ATS (NSAppTransportSecurity)** | Requires HTTPS; per-domain exceptions weaken it. |
| **Keychain** | Encrypted credential store; accessibility classes control when data is readable. |
| **ObjC classlist** | __objc_classlist section — pointer array to class structures; enables class dumping. |
| **Symbol table (LC_SYMTAB)** | Exported/imported symbols; stripped binaries lose local symbols. |

## Assessment

| Term | Definition |
|------|-----------|
| **Baseline** | Known-good snapshot (mobilegestalt + sysctls) for later drift comparison. |
| **Drift** | Deviation between current device state and baseline — indicator of compromise or tampering. |
| **SARIF** | Static Analysis Results Interchange Format — machine-readable findings standard for CI. |
| **MASVS** | OWASP Mobile Application Security Verification Standard. |
| **MSTG** | OWASP Mobile Security Testing Guide. |
| **Risk-weighted delta** | Diff where each change type carries a severity (new entitlement = CRITICAL, resource change = LOW). |
