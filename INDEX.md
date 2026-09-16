# iOS Security Wizard — Corpus Index

**Version:** 1.1.0 · **Author:** savagedamage · **License:** MIT

This corpus covers iOS application security: static analysis, gadget-mode dynamic instrumentation (no jailbreak), attack surface mapping, delta analysis, and device integrity. It is written to serve two audiences equally: **humans** reading for understanding and **AI agents** executing workflows.

## Reading Paths

### For Humans
1. Start at [README.md](README.md) — what this is, quick start, examples
2. Browse [references/](references/) topically as needed
3. Use the `ios-wizard` CLI with `--help` on any command

### For AI Agents
1. Start at [AGENT-GUIDE.md](AGENT-GUIDE.md) — decision tree, tool selection, output handling
2. Follow numbered workflows in [SKILL.md](SKILL.md)
3. Consult [references/](references/) for format details when parsing fails

## Layer Map

```
┌─────────────────────────────────────────────────────────────┐
│                     ios-wizard (CLI)                        │
│        unified entry point — dispatches all tools           │
├───────────────┬─────────────────────┬───────────────────────┤
│   STATIC      │      DYNAMIC        │      PENTEST          │
│  (offline)    │   (gadget-mode)     │   (workflows)         │
├───────────────┼─────────────────────┼───────────────────────┤
│ macho_parser  │ gadget_frida        │ ipa_diff              │
│ ipa_structure │ dyld_interpose      │ probe_plan            │
│ entitlements  │ xpc_enum            │ device_baseline       │
│ objc_swift    │ launchd_inspect     │ report_gen            │
│ dyld_cache    │ jailbreak_check     │                       │
│ hardened_rt   │                     │                       │
│ crypto_scan   │                     │                       │
└───────────────┴─────────────────────┴───────────────────────┘
```

## File Inventory

### Core Documents
| File | Audience | Purpose |
|------|----------|---------|
| [SKILL.md](SKILL.md) | Both | Hermes skill definition, workflow entry points |
| [README.md](README.md) | Human | Overview, quick start, examples |
| [AGENT-GUIDE.md](AGENT-GUIDE.md) | AI | Operating manual: decision tree, tool selection |
| [INDEX.md](INDEX.md) | Both | This file — corpus map |
| [GLOSSARY.md](GLOSSARY.md) | Both | Terminology definitions |
| [CHANGELOG.md](CHANGELOG.md) | Both | Version history |

### Tooling
| Directory | Files | Purpose |
|-----------|-------|---------|
| `static/` | 7 tools | Offline analysis of Mach-O, IPA, entitlements, crypto |
| `dynamic/` | 5 tools | Runtime analysis via Frida gadget (no jailbreak) |
| `pentest/` | 4 tools | End-to-end workflows: delta, probes, baseline, reports |
| `scripts/` | 3 shell | IPA re-signing, dyld cache extraction, baseline capture |
| `test/` | 1 builder | Minimal valid Mach-O fixture builder |
| `test_fixtures.py` | 1 suite | 15 component tests, real-fixture end-to-end |

### Knowledge Base (`references/`)
| File | Topic |
|------|-------|
| [macho_format.md](references/macho_format.md) | Mach-O binary format |
| [ipa_structure.md](references/ipa_structure.md) | IPA/app bundle anatomy |
| [entitlements_ref.md](references/entitlements_ref.md) | Entitlement keys and security impact |
| [crypto_analysis.md](references/crypto_analysis.md) | Crypto API detection and weakness patterns |
| [network_security.md](references/network_security.md) | ATS, certificate pinning, network analysis |
| [data_storage.md](references/data_storage.md) | Keychain, NSUserDefaults, file security |
| [xpc_services.md](references/xpc_services.md) | XPC architecture, enumeration, attack surface |
| [jailbreak_detection.md](references/jailbreak_detection.md) | Jailbreak detection and bypass methods |
| [anti_tampering.md](references/anti_tampering.md) | Anti-tampering and anti-debugging |
| [frida_scripts.md](references/frida_scripts.md) | Frida script library for iOS |
| [pac_bypass.md](references/pac_bypass.md) | Pointer Authentication techniques |
| [masvs_mapping.md](references/masvs_mapping.md) | OWASP MASVS/MSTG mapping |

### Templates (`templates/`)
| File | Purpose |
|------|---------|
| [pentest_report.md](templates/pentest_report.md) | Standard pentest report structure |
| [entitlements_plist.xml](templates/entitlements_plist.xml) | Example entitlement configuration |

## Numbered Workflows (from SKILL.md)

1. **Static Triage** — IPA → extracted bundle → per-binary analysis → findings
2. **Gadget-Mode Dynamic Setup** — IPA re-sign with Frida gadget → install → instrument
3. **IPA Delta Analysis** — baseline vs target → risk-weighted diff → SARIF + markdown
4. **Attack Surface Probe Generation** — enumerate XPC/URL schemes/extensions → probe scripts
5. **Device Baseline & Drift** — capture mobilegestalt/sysctls → detect anomalies
6. **Full Assessment** (see AGENT-GUIDE.md) — combines 1–5 into a complete engagement

## Quick Start (Human)

```bash
# One-command static triage
./ios-wizard triage App.ipa -o report/

# Single tool
./ios-wizard static macho AppBinary
./ios-wizard static crypto AppBinary
./ios-wizard dynamic xpc App.app
./ios-wizard pentest diff v1.ipa v2.ipa
./ios-wizard pentest baseline --capture

# Run tests
./ios-wizard test
```

## Quick Start (AI Agent)

Load `AGENT-GUIDE.md` first. The decision tree routes every task to the right tool. Key rules:
- Never guess Mach-O offsets — use `static/macho_parser.py` output as ground truth
- All dynamic work assumes **no jailbreak** — gadget mode is the only path
- Always capture a baseline before any drift comparison
- Report every finding with evidence (offset, hash, section name)
