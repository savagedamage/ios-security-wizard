# Known XPC Services Reference

## System XPC Services (macOS/iOS)

### Security / Authentication
| Service | Mach Service | Description | Privileged |
|---------|--------------|-------------|------------|
| com.apple.securityd | com.apple.securityd | Security daemon | Yes |
| com.apple.SecurityServer | com.apple.SecurityServer | Legacy security server | Yes |
| com.apple.authorizationhost | com.apple.authorizationhost | Authorization host | Yes |
| com.apple.authd | com.apple.authd | Authentication daemon | Yes |
| com.apple.tccd | com.apple.tccd | Transparency, Consent, Control | Yes |
| com.apple.secinitd | com.apple.secinitd | Secure init daemon | Yes |

### Launch Services
| Service | Mach Service | Description | Privileged |
|---------|--------------|-------------|------------|
| com.apple.launchd | com.apple.launchd | Launch daemon (PID 1) | Yes |
| com.apple.launchd.peruser.* | com.apple.launchd.peruser.* | Per-user launchd | User |
| com.apple.launchd.user.* | com.apple.launchd.user.* | User launchd | User |

### Core System
| Service | Mach Service | Description | Privileged |
|---------|--------------|-------------|------------|
| com.apple.xpc.proxy | com.apple.xpc.proxy | XPC proxy | Yes |
| com.apple.xpc.activity | com.apple.xpc.activity | Activity daemon | Yes |
| com.apple.powerd | com.apple.powerd | Power management | Yes |
| com.apple.syslogd | com.apple.syslogd | System logging | Yes |
| com.apple.notifyd | com.apple.notifyd | Notification daemon | Yes |
| com.apple.distributednoted | com.apple.distributednoted | Distributed notifications | Yes |

### Network
| Service | Mach Service | Description | Privileged |
|---------|--------------|-------------|------------|
| com.apple.networkd | com.apple.networkd | Network daemon | Yes |
| com.apple.mDNSResponder | com.apple.mDNSResponder | mDNS/Bonjour | Yes |
| com.apple.netauth.sys.auth | com.apple.netauth.sys.auth | Network auth | Yes |
| com.apple.networkextension | com.apple.networkextension | Network extensions | Yes |

### File System / Storage
| Service | Mach Service | Description | Privileged |
|---------|--------------|-------------|------------|
| com.apple.fseventsd | com.apple.fseventsd | File system events | Yes |
| com.apple.hidd | com.apple.hidd | Human interface device | Yes |
| com.apple.iokit.iokit | com.apple.iokit.iokit | IOKit | Yes |
| com.apple.diskarbitrationd | com.apple.diskarbitrationd | Disk arbitration | Yes |

### User Services (per-user)
| Service | Mach Service | Description | Privileged |
|---------|--------------|-------------|------------|
| com.apple.cfprefsd | com.apple.cfprefsd | Preferences daemon | User |
| com.apple.nsurlstoraged | com.apple.nsurlstoraged | URL storage | User |
| com.apple.cloudd | com.apple.cloudd | Cloud daemon | User |
| com.apple.identityservicesd | com.apple.identityservicesd | Identity services | User |
| com.apple.imagent | com.apple.imagent | iMessage agent | User |
| com.apple.ctkd | com.apple.ctkd | CallKit daemon | User |

## App XPC Services (Common Patterns)

### Naming Convention
- `<bundle-id>.xpc` - Generic app XPC service
- `<bundle-id>.helper` - Privileged helper
- `<bundle-id>.service` - Background service

### Common App XPC Services
| App | Service | Purpose |
|-----|---------|---------|
| Safari | com.apple.Safari.SafeBrowsing | Safe browsing |
| Safari | com.apple.Safari.Translation | Translation |
| Mail | com.apple.mail.PluginManager | Plugin manager |
| Xcode | com.apple.dt.Xcode.Helper | Build helper |
| Terminal | com.apple.Terminal.Helper | Terminal helper |

## XPC Service Types

### Launchd Mach Services
Defined in launchd plist under `MachServices`:
```xml
<key>MachServices</key>
<dict>
    <key>com.example.service</key>
    <dict>
        <key>IsAgent</key><false/>
    </dict>
</dict>
```

### App Bundle XPCServices
Defined in Info.plist:
```xml
<key>XPCServices</key>
<dict>
    <key>com.example.service</key>
    <dict>
        <key>Executable</key><string>XPCService</string>
        <key>MachServiceName</key><string>com.example.service</string>
        <key>BundleIdentifier</key><string>com.example.service</string>
    </dict>
</dict>
```

### Embedded XPC Services (.xpc bundles)
Located in `Contents/XPCServices/` with their own Info.plist

## Security Analysis Checklist

### For Each XPC Service:
1. **Privilege Level**: Runs as root? (LaunchDaemons = yes)
2. **Sandboxed**: Is it sandboxed? (App sandbox / System sandbox)
3. **Entitlements**: What entitlements does the binary have?
4. **Input Validation**: Does it validate XPC messages?
5. **Audit Token**: Does it check client audit token?
6. **Reply Validation**: Does it validate replies?
7. **Connection Limits**: Any rate limiting?
8. **Exposed Methods**: What routines does it export?

### Common Vulnerabilities:
- **Message Fuzzing**: Unvalidated dictionary/array inputs
- **Type Confusion**: Expecting string, getting data
- **Size Limits**: No bounds on data/blob sizes
- **Privilege Escalation**: Root service accepting untrusted input
- **Sandbox Escape**: Helper with dangerous entitlements
- **Connection Hijacking**: Predictable Mach port names

## Frida Hooking Points

### Client Side
```javascript
// Hook xpc_connection_create_mach_service
const create = Module.findExportByName(null, 'xpc_connection_create_mach_service');
// Hook xpc_connection_send_message
const send = Module.findExportByName(null, 'xpc_connection_send_message');
// Hook xpc_connection_send_message_with_reply
const send_reply = Module.findExportByName(null, 'xpc_connection_send_message_with_reply');
```

### Server Side
```javascript
// Hook xpc_connection_set_event_handler
const set_handler = Module.findExportByName(null, 'xpc_connection_set_event_handler');
// Hook xpc_dictionary_get_* functions
const get_string = Module.findExportByName(null, 'xpc_dictionary_get_string');
// Hook xpc_array_get_* functions
```

## Enumeration Commands

```bash
# List all launchd services
launchctl list | grep -i xpc

# List system XPC services
ls /System/Library/XPCServices/

# Check app XPC services
ls /Applications/App.app/Contents/XPCServices/

# View launchd plist
cat /Library/LaunchDaemons/com.example.plist

# Check running XPC connections (requires root)
sudo lsmp -p <pid> | grep xpc
```

## Audit Token Validation

Proper XPC service should validate client:
```c
// In event handler
audit_token_t token;
xpc_connection_get_audit_token(connection, &token);

// Check uid/gid/pid
if (token.au_uid != 0 && token.au_uid != getuid()) {
    // Reject untrusted client
}
```

## Resources
- Apple XPC Documentation
- "MacOS and iOS Internals" by Jonathan Levin
- "The Mac Hacker's Handbook"
- Frida iOS XPC examples