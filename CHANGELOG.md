# Changelog

All notable changes to the iOS Security Wizard corpus.

## [1.1.1] - 2026-09-16

### Added
- `scripts/check_links.py` — corpus URL health checker (dead/bot-blocked/timeout classification, JSON output, non-zero exit on dead links)
- `ROADMAP.md` — measured baseline + tiered plan (trust → use → depth → reach) with acceptance criteria per item

### Changed
- Shell scripts (`extract_dyld_cache.sh`, `baseline_capture.sh`) are now location-independent — they resolve their own directory instead of a hardcoded home path
- README rewritten for public release: corpus-at-a-glance tables, coverage checklist, honest gaps, contributing section, sibling repo link

### Verified
- Link check 2026-09-16: 4 unique external URLs, 4 OK, 0 dead
- Full suite: 15 passed, 0 failed

## [1.1.0] - 2026-09-16

### Added
- **Corpus documentation layer**: INDEX.md (corpus map), README.md (human quick start), AGENT-GUIDE.md (AI operating manual), GLOSSARY.md (terminology), CHANGELOG.md
- **New static tools**: `static/ipa_structure.py` (bundle anatomy analyzer), `static/crypto_scan.py` (crypto API and keychain weakness scanner)
- **New dynamic tool**: `dynamic/jailbreak_check.py` (compromise assessment without root)
- **New pentest tool**: `pentest/report_gen.py` (unified evidence-schema report generator)
- **Unified CLI**: `ios-wizard` — single entry point for all tools, with `triage`, `static`, `dynamic`, `pentest`, `test` subcommands
- **Knowledge base expansion**: 8 new reference docs (ipa_structure, crypto_analysis, network_security, data_storage, jailbreak_detection, anti_tampering, frida_scripts, masvs_mapping)
- **Templates**: pentest_report.md, entitlements_plist.xml
- **Test infrastructure**: `test/macho_fixture.py` (minimal valid Mach-O builder), expanded component tests
- LICENSE file

### Changed
- `static/objc_swift.py`: completed previously-stubbed class/protocol/category parsing
- `static/macho_parser.py`: fixed cpu_arch 64-bit detection (ARM64 was misreported as "arm")
- SKILL.md: workflows corrected to match actual tool filenames; added Verification section
- All scripts now executable with proper shebangs

## [1.0.0] - 2026-09-16

### Added
- Initial skill definition (SKILL.md)
- Static analysis layer: macho_parser, dyld_cache, entitlements, objc_swift, hardened_runtime
- Dynamic analysis layer (gadget-mode): gadget_frida, dyld_interpose, xpc_enum, launchd_inspect
- Pentest suite: ipa_diff (SARIF delta), probe_plan (attack surface), device_baseline (drift)
- Shell scripts: re-sign_gadget, extract_dyld_cache, baseline_capture
- Core reference docs: macho_format, entitlements_ref, xpc_services, pac_bypass
- Component test suite (9 tests)
