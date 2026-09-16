# IPA Structure Reference

## Overview

An iOS application delivered to devices is packaged as an **IPA** file – essentially a ZIP archive containing the app bundle and supporting metadata. Understanding the internal layout is prerequisite for static analysis, code‑signing verification, and dynamic instrumentation performed by the **iOS Security Wizard** toolkit.

---

## ZIP Archive Layout

```
MyApp.ipa
├─ Payload/
│   └─ MyApp.app/                ← Primary bundle (Mach‑O executable + resources)
├─ iTunesMetadata.plist          ← App Store metadata (optional for ad‑hoc builds)
├─ iTunesArtwork                 ← 512×512 PNG (legacy)
├─ WatchKitSupport/              ← Stubs for watchOS extensions (optional)
└─ SwiftSupport/                 ← Swift runtime libraries for older OS versions
```

- **Payload/** – always present; contains exactly one `.app` directory.
- **iTunesMetadata.plist** – contains `bundleIdentifier`, `trackId`, and licensing info when the binary originates from the App Store.
- **WatchKitSupport/** – only when the IPA includes a watchOS companion app.
- **SwiftSupport/** – provides `libswift*.dylib` for devices lacking the required Swift runtime (pre‑iOS 13).

---

## Inside the `.app` Bundle

```
MyApp.app/
├─ Info.plist                     ← Primary bundle metadata
├─ <CFBundleExecutable>           ← Mach‑O executable (binary)
├─ _CodeSignature/                ← Code signing data
│   ├─ CodeResources
│   ├─ CodeDirectory
│   └─ Requirements
├─ Frameworks/                   ← Embedded frameworks (.framework)
├─ PlugIns/                       ← App extensions (.appex)
├─ Watch/                         ← watchOS app bundle (WatchKit)
├─ Assets.car                     ← Asset catalog compiled binary
├─ Base.lproj/                    ← Default localization (storyboard / nib)
├─ en.lproj/                     ← English localization folder
├─ *.storyboardc                 ← Compiled storyboards
├─ *.xcassets                     ← Asset catalog directories (source)
├─ *.png, *.jpg, *.json, …        ← Raw resources
└─ entitlements.plist *(optional)← Embedded entitlements (sometimes in _CodeSignature)
```

### Key Directories
| Directory | Purpose |
|-----------|---------|
| `_CodeSignature/` | Holds the code‑signature blob (CMS). Includes `CodeResources`, `CodeDirectory`, and `Requirements`. |
| `Frameworks/` | Embedded dynamic libraries (e.g., `MyFramework.framework`). |
| `PlugIns/` | App extensions (`.appex`). Each extension is itself a bundle with its own `Info.plist` and signature. |
| `Watch/` | WatchOS companion app (`WatchApp.app`). |
| `*.lproj/` | Localization resources. Storyboards, XIBs, and `.strings` files. |
| `Assets.car` | Compiled asset catalog (images, colors, launch screens). |

---

## Code Signing Files

| File | Description |
|------|-------------|
| `_CodeSignature/CodeResources` | Legacy hash table of all bundled resources (pre‑iOS 13). |
| `_CodeSignature/CodeDirectory` | Contains hashes of each page, bundle identifier, and entitlements hash. |
| `_CodeSignature/Requirements` | Logical code requirements (e.g., `identifier = com.example.app`). |
| `embedded.mobileprovision` *(optional in the bundle root)* | Provisioning profile that binds the app to a developer/team ID and lists entitlements. |

The **iOS Security Wizard** includes `signcheck` – a wrapper around `codesign` and `security` that extracts, validates, and displays each component.

---

## Info.plist Key Reference

| Key | Type | Description |
|-----|------|------------|
| `CFBundleIdentifier` | String | Unique reverse‑DNS bundle ID (e.g., `com.example.myapp`). |
| `CFBundleExecutable` | String | Name of the Mach‑O executable (usually matches the bundle name). |
| `CFBundleVersion` | String | Build number (integer‑compatible). |
| `CFBundleShortVersionString` | String | Human‑readable version (e.g., `1.2.3`). |
| `CFBundleURLTypes` | Array of dicts | URL scheme definitions – each dict may contain `CFBundleURLName` and `CFBundleURLSchemes`. |
| `UIBackgroundModes` | Array | Declares permitted background tasks (`audio`, `fetch`, `remote-notification`, etc.). |
| `UIApplicationSceneManifest` | Dictionary | Scene configuration for multi‑window support (iOS 13+). |
| `LSApplicationQueriesSchemes` | Array | Whitelist of URL schemes the app may query via `canOpenURL:`. |
| `UIRequiredDeviceCapabilities` | Array | Declares mandatory hardware features (e.g., `armv7`, `gps`). |
| `NSLocationWhenInUseUsageDescription` | String | User‑visible rationale for location permission. |
| `NSCameraUsageDescription` | String | Rationale for camera access. |
| `NSPhotoLibraryAddUsageDescription` | String | Rationale for saving to the photo library. |
| `NSAppTransportSecurity` | Dictionary | ATS exceptions – keys like `NSAllowsArbitraryLoads`. |
| `UIFileSharingEnabled` | Boolean | Enables iTunes file sharing. |
| `UISupportedInterfaceOrientations` | Array | Supported orientations (e.g., `UIInterfaceOrientationPortrait`). |
| `UIUserInterfaceStyle` | String | Preferred UI style (`Light`, `Dark`, `Automatic`). |

*Only the keys above are listed; the full plist can contain any of the documented keys in Apple’s **Info.plist Key Reference**.*

---

## Extension Bundles (`.appex`)

App extensions are packaged as miniature `.app` bundles inside `PlugIns/`. They follow the same structure: an `Info.plist`, an executable, optional resources, and their own `_CodeSignature/`. Common extension types include:

| Extension Type | Directory Name | Primary Usage |
|---------------|----------------|---------------|
| Today Extension | `MyAppWidget.appex` | Home‑screen widget. |
| Share Extension | `MyAppShareExtension.appex` | Share sheet integration. |
| Action Extension | `MyAppActionExtension.appex` | Custom actions from other apps. |
| Siri Shortcut | `MyAppIntents.appex` | Siri intents & shortcuts. |
| Network Extension | `MyAppNetworkExtension.appex` | VPN, content filtering. |
| Notification Content | `MyAppNotificationContent.appex` | Custom notification UI. |

Each extension may declare **XPC services** (`.xpc`) and can have its own entitlements (e.g., `com.apple.developer.networking.networkextension`).

---

## XPC Service Bundles (`.xpc`)

XPC services are lightweight helper processes used for inter‑process communication. They reside within the extension bundle or directly in the app bundle under `MyApp.app/`. Structure:

```
MyApp.app/
└─ MyHelper.xpc/
   ├─ Info.plist
   ├─ MyHelper (Mach‑O executable)
   └─ _CodeSignature/
```

The **iOS Security Wizard** provides `xpcdump` to list exported interfaces from the `Info.plist` and to validate the signature.

---

## Asset Catalogs (`*.xcassets` → `Assets.car`)

Developers author resources in `*.xcassets` directories. At build time Xcode compiles them into a single binary `Assets.car`. The wizard offers `carread` to enumerate image names, scales, and universal vs. device‑specific variations.

---

## Localization (`*.lproj`)

Each localization folder contains `.strings`, `.storyboard`, `.xib`, and other resources. The naming convention `xx.lproj` where `xx` is an ISO‑639‑1 language code, optionally followed by a region (`xx-YY`). The wizard’s `locscan` parses all localization files and reports missing keys across languages.

---

## Entitlements Location

Entitlements are packaged in two places:
1. **Embedded in the code signature** – the `Entitlements.plist` is part of the `CodeDirectory` hash and can be extracted with `codesign -d --entitlements :- MyApp.app`.
2. **Explicit `Entitlements.plist` file** – sometimes present at the bundle root for convenience; the wizard normalises both sources.

Typical entitlement keys include:
- `com.apple.security.application-groups`
- `com.apple.developer.networking.vpn.api`
- `com.apple.developer.healthkit`
- `com.apple.developer.siri`
- `com.apple.security.cs.allow-jit`
- `com.apple.security.get-task-allow`

---

## Extraction & Inspection Workflow (Toolkit Commands)

| Step | Command | Description |
|------|---------|-------------|
| **1. Unzip IPA** | `unzip -qq MyApp.ipa -d ./tmp` | Extracts the archive preserving permissions. |
| **2. List bundle contents** | `tree ./tmp/Payload` | Quick visual of directory hierarchy. |
| **3. Show Info.plist** | `plutil -convert xml1 -o - ./tmp/Payload/MyApp.app/Info.plist` | Human‑readable XML output. |
| **4. Verify code signature** | `signcheck verify ./tmp/Payload/MyApp.app` | Wrapper around `codesign -v --deep`. |
| **5. Dump embedded entitlements** | `signcheck entitlements ./tmp/Payload/MyApp.app` | Extracts and pretty‑prints entitlements. |
| **6. List embedded frameworks** | `ls ./tmp/Payload/MyApp.app/Frameworks` | Shows third‑party frameworks. |
| **7. Examine XPC services** | `xpcdump list ./tmp/Payload/MyApp.app` | Lists XPC bundles and exported interfaces. |
| **8. Parse asset catalog** | `carread ./tmp/Payload/MyApp.app/Assets.car` | Prints image identifiers and scales. |
| **9. Scan for ATS violations** | `mascanner ats ./tmp/Payload/MyApp.app/Info.plist` | Checks `NSAppTransportSecurity` keys. |
| **10. Enumerate URL schemes** | `mascanner urlschemes ./tmp/Payload/MyApp.app/Info.plist` | Extracts `CFBundleURLTypes`. |

All commands output JSON when `--json` flag is supplied, enabling downstream automation.

---

## Resources

- Apple Developer Documentation – *App Distribution Guide* (IPA format).
- `codesign` man page – details of code‑signature components.
- **iOS Security Wizard** – `signcheck`, `xpcdump`, `carread`, `mascanner` source code (in `tools/` directory).
- “The iOS App Security Checklist” – PDF by OWASP Mobile.

---

## AI Agent Notes

- **Parsing**: Tables use the pipe (`|`) delimiter; empty cells are allowed. The `Info.plist` section is a reliable anchor for key‑value extraction.
- **Execution**: All toolkit commands accept a `--json` flag; agents should prefer JSON for deterministic downstream processing.
- **Path handling**: When referencing extracted files, always prefix with `./tmp/` (the default extraction path) unless the user overrides.
- **Versioning**: The reference file is version‑controlled; future updates will add new Info.plist keys and Apple‑added entitlements.
