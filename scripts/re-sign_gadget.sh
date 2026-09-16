#!/bin/bash
# re-sign_gadget.sh — IPA re-signing with Frida gadget
# Requires: Apple Developer Program membership, codesign, objection, frida-tools

set -euo pipefail

IPA_PATH="${1:-}"
OUTPUT_IPA="${2:-}"
CODESIGN_IDENTITY="${3:-}"
PROVISIONING_PROFILE="${4:-}"
BUNDLE_ID="${5:-}"

if [[ -z "$IPA_PATH" || -z "$OUTPUT_IPA" ]]; then
    echo "Usage: $0 <input.ipa> <output.ipa> [codesign_identity] [provisioning_profile] [bundle_id]"
    echo ""
    echo "Environment variables:"
    echo "  CODESIGN_IDENTITY     - Apple Developer codesign identity (e.g., 'Apple Development: name (TEAMID)')"
    echo "  PROVISIONING_PROFILE  - Path to .mobileprovision file"
    echo "  BUNDLE_ID             - Bundle identifier (auto-detected if not provided)"
    exit 1
fi

# Use environment variables if not provided as args
CODESIGN_IDENTITY="${CODESIGN_IDENTITY:-${CODESIGN_IDENTITY}}"
PROVISIONING_PROFILE="${PROVISIONING_PROFILE:-${PROVISIONING_PROFILE}}"
BUNDLE_ID="${BUNDLE_ID:-${BUNDLE_ID}}"

if [[ -z "$CODESIGN_IDENTITY" ]]; then
    echo "Error: CODESIGN_IDENTITY not set"
    exit 1
fi

WORKDIR=$(mktemp -d)
trap "rm -rf $WORKDIR" EXIT

echo "[*] Extracting IPA..."
unzip -q "$IPA_PATH" -d "$WORKDIR"

APP_PATH=$(find "$WORKDIR/Payload" -name "*.app" -maxdepth 1 | head -1)
if [[ -z "$APP_PATH" ]]; then
    echo "Error: No .app found in IPA"
    exit 1
fi

echo "[*] Found app: $APP_PATH"

# Detect bundle ID if not provided
if [[ -z "$BUNDLE_ID" ]]; then
    BUNDLE_ID=$(defaults read "$APP_PATH/Info.plist" CFBundleIdentifier 2>/dev/null || \
                plutil -extract CFBundleIdentifier xml1 -o - "$APP_PATH/Info.plist" 2>/dev/null | \
                sed -n 's/.*<string>\(.*\)<\/string>.*/\1/p')
    echo "[*] Detected bundle ID: $BUNDLE_ID"
fi

# Download FridaGadget.dylib for iOS arm64
GADGET_DIR="$WORKDIR/gadget"
mkdir -p "$GADGET_DIR"

echo "[*] Downloading Frida gadget..."
FRIDA_VERSION=$(curl -s https://api.github.com/repos/frida/frida/releases/latest | grep '"tag_name"' | sed 's/.*"v\([^"]*\)".*/\1/')
GADGET_URL="https://github.com/frida/frida/releases/download/${FRIDA_VERSION}/frida-gadget-${FRIDA_VERSION}-ios-universal.dylib.xz"
curl -L "$GADGET_URL" -o "$GADGET_DIR/frida-gadget.dylib.xz"
xz -d "$GADGET_DIR/frida-gadget.dylib.xz"
GADGET_DYLIB="$GADGET_DIR/frida-gadget.dylib"

# Copy gadget to Frameworks
FRAMEWORKS_DIR="$APP_PATH/Frameworks"
mkdir -p "$FRAMEWORKS_DIR"
cp "$GADGET_DYLIB" "$FRAMEWORKS_DIR/FridaGadget.dylib"

# Find main binary
MAIN_BINARY=$(find "$APP_PATH" -type f -perm +111 ! -name "*.dylib" ! -name "*.so" ! -path "*/Frameworks/*" | head -1)
if [[ -z "$MAIN_BINARY" ]]; then
    echo "Error: Could not find main binary"
    exit 1
fi

echo "[*] Main binary: $MAIN_BINARY"

# Use insert_dylib to inject load command
if ! command -v insert_dylib &> /dev/null; then
    echo "Error: insert_dylib not found. Install: brew install insert_dylib"
    exit 1
fi

echo "[*] Injecting FridaGadget.dylib..."
insert_dylib --inplace "@executable_path/Frameworks/FridaGadget.dylib" "$MAIN_BINARY"

# Create FridaGadget.config
cat > "$APP_PATH/FridaGadget.config" <<EOF
{
  "interaction": {
    "type": "listen",
    "address": "0.0.0.0",
    "port": 27042,
    "on_load": "resume"
  },
  "tls": {
    "enabled": false
  },
  "logging": {
    "level": "info",
    "file": "/tmp/frida-gadget.log"
  }
}
EOF

# Copy provisioning profile if provided
if [[ -n "$PROVISIONING_PROFILE" && -f "$PROVISIONING_PROFILE" ]]; then
    echo "[*] Copying provisioning profile..."
    cp "$PROVISIONING_PROFILE" "$APP_PATH/embedded.mobileprovision"
fi

# Re-sign everything
echo "[*] Re-signing app..."
codesign -f -s "$CODESIGN_IDENTITY" \
    --deep \
    --timestamp \
    --options runtime \
    --entitlements "$WORKDIR/entitlements.plist" 2>/dev/null || \
codesign -f -s "$CODESIGN_IDENTITY" \
    --deep \
    --timestamp \
    --options runtime \
    "$APP_PATH"

# Verify signature
echo "[*] Verifying signature..."
codesign -v --strict "$APP_PATH"

# Repackage IPA
echo "[*] Repackaging IPA..."
cd "$WORKDIR"
zip -qr "$OUTPUT_IPA" Payload

echo "[*] Done: $OUTPUT_IPA"
echo "[*] Install on device via: ios-deploy --bundle $OUTPUT_IPA or AltStore/Sideloadly"