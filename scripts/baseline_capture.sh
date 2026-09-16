#!/bin/bash
# baseline_capture.sh — Device baseline capture (mobilegestalt + sysctls)
# Run on target device (macOS or iOS via SSH)

set -euo pipefail

OUTPUT="${1:-baseline-$(date +%Y%m%d-%H%M%S).json}"

echo "[*] Capturing device baseline..."
echo "[*] Output: $OUTPUT"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
python3 -c "
import sys, os
sys.path.insert(0, os.path.join('$SCRIPT_DIR', '..', 'pentest'))
from device_baseline import capture_baseline, save_baseline
baseline = capture_baseline()
save_baseline(baseline, '$OUTPUT')
"