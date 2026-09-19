#!/bin/bash
# sync_skill.sh — push the repo corpus into the local Hermes skill install.
#
# The repo is the source of truth. The Hermes skill install lives at
# ~/.hermes/skills/security/ios-security-wizard/ and is what `skill_view` reads.
# Run this after any corpus change so both stay identical.
#
# Usage:
#   ./scripts/sync_skill.sh            # sync to the default skill path
#   SKILL_DIR=/path ./scripts/sync_skill.sh

set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SKILL_DIR="${SKILL_DIR:-$HOME/.hermes/skills/security/ios-security-wizard}"

if [[ ! -d "$SKILL_DIR" ]]; then
    echo "[!] Skill dir does not exist: $SKILL_DIR"
    echo "    Create it first or set SKILL_DIR to the right path."
    exit 1
fi

echo "[*] Repo:  $REPO_DIR"
echo "[*] Skill: $SKILL_DIR"

# Corpus files/dirs shared by both. Repo-only files (ROADMAP.md, .gitignore,
# scripts/sync_skill.sh) are intentionally NOT copied.
ITEMS=(
    SKILL.md README.md CHANGELOG.md INDEX.md GLOSSARY.md AGENT-GUIDE.md LICENSE
    ios-wizard static dynamic pentest scripts references templates test
    test_fixtures.py
)

for item in "${ITEMS[@]}"; do
    src="$REPO_DIR/$item"
    [[ -e "$src" ]] || continue
    if [[ -d "$src" ]]; then
        rm -rf "${SKILL_DIR:?}/$item"
        cp -a "$src" "$SKILL_DIR/$item"
    else
        cp -a "$src" "$SKILL_DIR/$item"
    fi
    echo "    synced $item"
done

# Keep the skill install free of repo-only tooling that would confuse skill_view.
rm -f "$SKILL_DIR/scripts/check_links.py" "$SKILL_DIR/scripts/sync_skill.sh" 2>/dev/null || true
find "$SKILL_DIR" -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true

# Verify the sync by running the suite from the skill install.
echo "[*] Verifying skill install..."
cd "$SKILL_DIR"
./ios-wizard test 2>&1 | tail -3

echo "[*] Done."
