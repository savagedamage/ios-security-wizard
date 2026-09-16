# Entitlement Keys Reference

## App Sandbox / Hardened Runtime

### com.apple.security.cs.*
| Key | Type | Description | Weakens Security |
|-----|------|-------------|------------------|
| com.apple.security.cs.runtime | bool | Enable hardened runtime | No |
| com.apple.security.cs.allow-jit | bool | Allow JIT compilation | Yes |
| com.apple.security.cs.allow-unsigned-executable-memory | bool | Allow unsigned executable memory | Yes |
| com.apple.security.cs.allow-dyld-environment-variables | bool | Allow DYLD_* env vars | Yes |
| com.apple.security.cs.disable-library-validation | bool | Disable library validation | Yes |
| com.apple.security.cs.disable-executable-page-protection | bool | Disable executable page protection | Yes |
| com.apple.security.cs.debugger | bool | Allow debugger attachment | Yes |
| com.apple.security.get-task-allow | bool | Allow task port access | Yes |

### File Access
| Key | Type | Description |
|-----|------|-------------|
| com.apple.security.files.user-selected.read-only | bool | Read-only access to user-selected files |
| com.apple.security.files.user-selected.read-write | bool | Read-write access to user-selected files |
| com.apple.security.files.downloads.read-only | bool | Read-only access to Downloads |
| com.apple.security.files.downloads.read-write | bool | Read-write access to Downloads |
| com.apple.security.files.removable-volumes | bool | Access removable volumes |

### Network
| Key | Type | Description |
|-----|------|-------------|
| com.apple.security.network.server | bool | Allow incoming network connections |
| com.apple.security.network.client | bool | Allow outgoing network connections |

### App Groups / Containers
| Key | Type | Description |
|-----|------|-------------|
| com.apple.security.application-groups | array | App Groups (shared containers) |
| com.apple.developer.ubiquity-container-identifiers | array | iCloud containers |
| com.apple.developer.ubiquity-kvstore-identifier | string | iCloud key-value store |

### Keychain
| Key | Type | Description |
|-----|------|-------------|
| keychain-access-groups | array | Shared keychain access groups |

## Developer Entitlements (com.apple.developer.*)

### Network Extensions
| Key | Type | Description |
|-----|------|-------------|
| com.apple.developer.networking.networkextension | array | Network Extension entitlements |
| com.apple.developer.networking.vpn.api | array | VPN API entitlements |
| com.apple.developer.networking.multicast | bool | Multicast networking |
| com.apple.developer.networking.HotspotHelper | bool | Hotspot Helper |

### Bluetooth
| Key | Type | Description |
|-----|------|-------------|
| com.apple.developer.bluetooth-peripheral | array | Bluetooth peripheral |
| com.apple.developer.bluetooth-central | array | Bluetooth central |

### NFC
| Key | Type | Description |
|-----|------|-------------|
| com.apple.developer.nfc.readersession | array | NFC reader session |

### Hardware
| Key | Type | Description |
|-----|------|-------------|
| com.apple.developer.usb | array | USB device access |
| com.apple.developer.camera | array | Camera access |
| com.apple.developer.microphone | array | Microphone access |

### Health / HomeKit / Wallet
| Key | Type | Description |
|-----|------|-------------|
| com.apple.developer.healthkit | bool | HealthKit |
| com.apple.developer.homekit | bool | HomeKit |
| com.apple.developer.payment-pass-provisioning | bool | Apple Pay |

### Siri / Maps / CarPlay
| Key | Type | Description |
|-----|------|-------------|
| com.apple.developer.siri | bool | SiriKit |
| com.apple.developer.maps | array | Maps |
| com.apple.developer.carplay | array | CarPlay |

### App Clips / Associated Domains
| Key | Type | Description |
|-----|------|-------------|
| com.apple.developer.associated-domains | array | Associated Domains (universal links) |
| com.apple.developer.app-clips | array | App Clips |

### Push / Background
| Key | Type | Description |
|-----|------|-------------|
| aps-environment | string | Push environment (development/production) |
| com.apple.developer.background-modes | array | Background modes |

## Provisioning Profile Fields

| Field | Description |
|-------|-------------|
| UUID | Profile UUID |
| Name | Profile name |
| TeamIdentifier | Team ID(s) |
| TeamName | Team name |
| ApplicationIdentifierPrefix | App ID prefix |
| Entitlements | Entitlements dict |
| ExpirationDate | Expiration |
| CreationDate | Creation |
| Platform | Platform (iOS, macOS, etc.) |
| ProvisionedDevices | Device UDIDs (dev profiles) |
| DeveloperCertificates | Certificates (DER) |
| IsXcodeManaged | Xcode managed |
| ProvisionedDevices | List of device UDIDs |

## Wildcard Detection Patterns

### Keychain Access Groups
- `*` - Full keychain access
- `TEAMID.*` - All team keychains
- `com.company.*` - All company keychains

### App Groups
- `group.*` - All app groups
- `group.com.company.*` - All company groups

### Associated Domains
- `applinks:*` - All universal links
- `webcredentials:*` - All web credentials

## Security Recommendations

1. **Never use wildcards** in keychain-access-groups or app-groups
2. **Enable hardened runtime** (com.apple.security.cs.runtime = true)
3. **Disable library validation only when necessary** with specific alternatives
4. **Remove get-task-allow** for release builds
5. **Minimize network entitlements** - client only unless server needed
6. **Use specific associated domains** - no wildcards
7. **Audit provisioning profiles** for expired/revoked certificates
8. **Check team identifier matches** your Apple Developer account