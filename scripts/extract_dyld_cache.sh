#!/bin/bash
# extract_dyld_cache.sh — macOS dyld shared cache extraction
# Extracts individual dylibs from dyld_shared_cache for analysis

set -euo pipefail

CACHE_PATH="${1:-}"
OUTPUT_DIR="${2:-./extracted_dylibs}"

if [[ -z "$CACHE_PATH" ]]; then
    # Auto-detect common locations
    for p in /System/Library/dyld/dyld_shared_cache_*; do
        if [[ -f "$p" ]]; then
            CACHE_PATH="$p"
            break
        fi
    done
fi

if [[ -z "$CACHE_PATH" || ! -f "$CACHE_PATH" ]]; then
    echo "Usage: $0 <dyld_shared_cache_path> [output_dir]"
    echo ""
    echo "Common locations:"
    ls -la /System/Library/dyld/dyld_shared_cache_* 2>/dev/null || echo "  (none found)"
    exit 1
fi

echo "[*] Using cache: $CACHE_PATH"
echo "[*] Output dir: $OUTPUT_DIR"

mkdir -p "$OUTPUT_DIR"

# Use dsc_extractor.bundle (part of Xcode) or dyld_shared_cache_util
if command -v dyld_shared_cache_util &> /dev/null; then
    echo "[*] Using dyld_shared_cache_util..."
    dyld_shared_cache_util -extract "$CACHE_PATH" "$OUTPUT_DIR"
elif [[ -d "/Applications/Xcode.app/Contents/Developer/usr/lib/dsc_extractor.bundle" ]]; then
    echo "[*] Using dsc_extractor.bundle..."
    DSC_EXTRACTOR="/Applications/Xcode.app/Contents/Developer/usr/lib/dsc_extractor.bundle/Contents/MacOS/dsc_extractor"
    "$DSC_EXTRACTOR" "$CACHE_PATH" "$OUTPUT_DIR"
else
    echo "[*] Using Python extractor (from ios-security-wizard)..."
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    python3 -c "
import sys, os
sys.path.insert(0, os.path.join('$SCRIPT_DIR', '..', 'static'))
from dyld_cache import list_cache_images, extract_dylib_from_cache
images = list_cache_images('$CACHE_PATH')
print(f'Found {len(images)} images')
for img in images:
    print(f'  Extracting: {img}')
    extract_dylib_from_cache('$CACHE_PATH', img, '$OUTPUT_DIR')
"
fi

echo "[*] Done. Extracted dylibs in: $OUTPUT_DIR"
ls -la "$OUTPUT_DIR" | head -20