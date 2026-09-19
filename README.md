# iOS Security Wizard

A synthesized iOS security research corpus: one integrated skill document plus 12 deep companion references covering the full iOS application security assessment pipeline — Mach-O static analysis, IPA/bundle anatomy, entitlement and provisioning auditing, crypto weakness scanning, gadget-mode dynamic instrumentation (no jailbreak), XPC/URL-scheme attack surface mapping, launchd persistence inspection, jailbreak/compromise assessment, device baseline drift detection, anti-tampering research, and pointer authentication (PAC) techniques. It also ships 18 stdlib-only Python tools (7 static, 5 dynamic, 4 pentest, 1 fixture builder, 1 test suite), 3 shell scripts, and a unified `ios-wizard` CLI.

**Grand total: ~10,500 lines / ~950 KB across 20 documents** (SKILL.md + AGENT-GUIDE + INDEX + GLOSSARY + 12 companions + README + CHANGELOG + report template), plus 19 stdlib-only Python scripts. Current release: **v1.1.1 (2026-09-16)** — see `CHANGELOG.md`. Last updated: 2026-09-16.

Last link check: 2026-09-16 — 4 unique external URLs: **4 OK, 0 dead**. Re-run with `python3 scripts/check_links.py`.

---

## What this is

This repository is the working corpus behind the `ios-security-wizard` Hermes skill — the direct sibling of `android-security-wizard`. The two corpora share one philosophy: no-root dynamic analysis, stdlib-only parsers, evidence-grounded findings. Where Android uses ADB/Shizuku for privileged access, iOS has no equivalent — so every dynamic capability here runs in **Frida gadget mode** (re-signed IPA), and the static layer does the heavy lifting.

- **The skill** (`SKILL.md`) — the synthesized, operational reference with the decision tree, workflows, and quick-reference tables. Start here.
- **`AGENT-GUIDE.md`** — the operating manual for AI agents: task routing, iron rules, evidence schema, output interpretation, failure handling.
- **The companion files** (`references/`) — deep, topic-isolated knowledge base that the skill references for format details, weakness taxonomies, and script libraries.

## The 3 capability pillars

| Pillar | Focus |
|--------|-------|
| 1. Static analysis | stdlib-only Mach-O parser, IPA/bundle anatomy, dyld cache extraction, entitlements/provisioning audit, ObjC 64-bit runtime metadata recovery, hardened runtime audit, crypto weakness scanning |
| 2. Dynamic analysis (gadget-mode, no jailbreak) | Frida gadget injection via IPA re-signing, dyld interposition tracing, XPC service enumeration, launchd persistence inspection, multi-indicator jailbreak/compromise assessment |
| 3. Pentest workflows | risk-weighted IPA delta (SARIF), XPC/URL-scheme probe generation, device baseline drift detection, unified evidence-schema reporting |

## Corpus at a glance

| File | Lines | Content |
|------|------:|---------|
| `SKILL.md` | 267 | The skill: layers, workflows, corpus index, verification, quick reference |
| `AGENT-GUIDE.md` | 138 | AI operating manual: decision tree, iron rules, evidence schema, tool output interpretation |
| `references/macho_format.md` | 138 | Mach-O binary format: headers, load commands, sections, code signature, PAC |
| `references/ipa_structure.md` | 194 | IPA/app bundle anatomy, Info.plist keys, extensions, XPC bundles |
| `references/entitlements_ref.md` | 139 | Entitlement keys, wildcard detection, hardened runtime flags |
| `references/crypto_analysis.md` | 77 | Crypto APIs, weakness taxonomy, keychain accessibility, Secure Enclave |
| `references/network_security.md` | 89 | ATS, certificate pinning, traffic analysis without jailbreak |
| `references/data_storage.md` | 95 | Keychain, NSUserDefaults, file protection, SQLite, biometrics |
| `references/xpc_services.md` | 182 | XPC architecture, enumeration, known services, audit checklist |
| `references/jailbreak_detection.md` | 92 | Detection techniques, bypass methods, false-positive guidance |
| `references/anti_tampering.md` | 78 | Anti-debugging, hook detection, integrity checks |
| `references/frida_scripts.md` | 267 | Runnable Frida script library (keychain dump, crypto trace, pinning bypass) |
| `references/pac_bypass.md` | 216 | Pointer Authentication: keys, instructions, bypass techniques, gadgets |
| `references/masvs_mapping.md` | 124 | OWASP MASVS/MSTG requirement → toolkit tool mapping |
| `INDEX.md` | 115 | Corpus map and reading paths |
| `GLOSSARY.md` | 83 | 60+ terms across the whole subject |
| `templates/pentest_report.md` | 90 | Evidence-schema report structure |

**Tooling** (7,928 Python lines):

| Tool | Lines | Purpose |
|------|------:|---------|
| `static/macho_parser.py` | 823 | stdlib Mach-O parser — headers, segments, sections, symbols, security checks |
| `static/ipa_structure.py` | 312 | IPA/bundle anatomy analyzer |
| `static/entitlements.py` | 333 | Provisioning profile + entitlement audit |
| `static/objc_swift.py` | 608 | ObjC 2.0 64-bit runtime metadata (classes, methods, ivars, protocols, categories) |
| `static/dyld_cache.py` | 351 | dyld shared cache parser |
| `static/hardened_runtime.py` | 187 | Hardened runtime flag audit |
| `static/crypto_scan.py` | 316 | Crypto API + weakness scanner with severity weighting |
| `dynamic/gadget_frida.py` | 364 | Frida gadget injection helpers |
| `dynamic/dyld_interpose.py` | 409 | dyld interposition tracing generators (Frida JS + C) |
| `dynamic/xpc_enum.py` | 462 | XPC service enumeration + security audit |
| `dynamic/launchd_inspect.py` | 452 | launchd persistence inspection |
| `dynamic/jailbreak_check.py` | 363 | Multi-indicator jailbreak/compromise assessment |
| `pentest/ipa_diff.py` | 602 | Risk-weighted IPA delta with SARIF output |
| `pentest/probe_plan.py` | 718 | XPC/URL-scheme/extension probe generation |
| `pentest/device_baseline.py` | 565 | MobileGestalt/sysctl baseline + drift detection |
| `pentest/report_gen.py` | 378 | Unified evidence-schema report generator |
| `test/macho_fixture.py` | 246 | Minimal valid arm64 Mach-O builder (no Xcode needed) |
| `test_fixtures.py` | 439 | 15-test component suite exercising every tool |
| `scripts/check_links.py` | 110 | Corpus URL health checker (verifiable link-check claim) |

## Coverage areas

1. ✅ Mach-O parsing, validated against generated arm64 fixtures (header, segments, sections, symbols, UUID, PIE/canary)
2. ✅ Entitlements & provisioning profile auditing with wildcard/over-privilege detection
3. ✅ Crypto weakness scanning (ECB, MD5, hardcoded keys, weak keychain classes) with severity weighting
4. ✅ ObjC 2.0 64-bit metadata recovery (class_t/class_ro_t/method_t/ivar_t/protocol_t/category_t)
5. ✅ XPC/URL-scheme/extension attack surface enumeration + probe generation
6. ✅ launchd persistence inspection with suspicious-pattern detection
7. ✅ Risk-weighted IPA delta (SARIF + markdown + JSON)
8. ✅ Device baseline capture + drift detection (mobilegestalt/sysctl/boot-args/PAC/AMFI/SIP)
9. ✅ Multi-indicator jailbreak/compromise assessment with false-positive guidance
10. ✅ Unified evidence-schema reporting across all tools
11. ⬜ Live-device gadget-mode validation — needs macOS, Apple Developer cert, physical device
12. ⬜ dyld cache parser verification against a real iOS cache — needs macOS or a cache sample
13. ⬜ Swift metadata parsing (type refs, conformance records) — unit-tested but not fixture-verified
14. ✅ PAC research — consolidated methodology, documented for defense only

## Quick start

```bash
# One-command static triage of an IPA
./ios-wizard triage App.ipa -o report/

# Single tools
./ios-wizard static macho AppBinary
./ios-wizard static crypto AppBinary
./ios-wizard dynamic xpc App.app
./ios-wizard pentest diff v1.ipa v2.ipa -o delta/

# Run the test suite (builds real arm64 fixtures, exercises every tool)
./ios-wizard test
```

Requirements: Python 3.11+ (stdlib only) for everything static; macOS + Apple Developer Program + Frida 16+ for gadget-mode work; `codesign`/`otool`/`nm` for binary verification.

## Status & honest gaps

- The Mach-O parser and crypto scanner are verified against **generated** arm64 fixtures — not yet against real App Store binaries. Fixture generation is byte-accurate to the format spec, but real-world binaries carry more load-command variety.
- No live-device runs are documented yet: gadget re-signing requires a macOS host with a paid Apple Developer certificate and a physical device. The workflow is fully scripted but unexercised end-to-end.
- The dyld cache parser handles the header/mapping/image model but has not been run against a real iOS dyld cache (requires macOS).
- `ipa_diff`'s entitlement comparison relies on `codesign` (macOS); on Linux-only hosts that section reports unavailable rather than guessing.
- PAC material is research documentation for defensive understanding — not exploit code, and never weaponized.
- No CI workflow yet; the local suite is the release gate. See `ROADMAP.md` Tier 1.
- The ObjC parser targets the standard 64-bit runtime layout; binaries built with unusual runtime forks may need layout adjustment.

## Repository layout

This repo is the source of truth. The Hermes skill install (`~/.hermes/skills/security/ios-security-wizard/`) is a synced copy used by `skill_view`; keep them identical with `./scripts/sync_skill.sh` after any corpus change. Repo-only files (this README's public edition, `ROADMAP.md`, `.gitignore`, `scripts/check_links.py`, `scripts/sync_skill.sh`) are intentionally not part of the skill install.

## Contributing

This corpus is open and actively maintained — contributions of verified technique docs, new detection signatures, or fixture improvements are welcome. Open an issue first to align scope, then PR against `master` with the test suite green (`./ios-wizard test`). Findings must be evidence-grounded; see the evidence schema in `AGENT-GUIDE.md`.

## Related repositories

- **`savagedamage/android-security-wizard`** — the direct sibling: same philosophy (stdlib-only parsers, evidence-grounded findings, no-root dynamic analysis) applied to Android via ADB/Shizuku. The two corpora share the pentest workflow shape (delta gating, probe plans, drift baselines) and are designed to be used together for mobile security assessments.

## License

MIT — see `LICENSE`. Usage notice: this toolkit is for security assessment of systems you own or have explicit written authorization to test.

---

*Corpus: 20 documents (SKILL.md, AGENT-GUIDE, INDEX, GLOSSARY, README, CHANGELOG, 12 references, 1 template), ~10,500 lines / ~950 KB, plus 18 stdlib-only Python tools, 3 shell scripts, and the `ios-wizard` CLI. Last updated 2026-09-16.*
