# AGENT-GUIDE — Operating Manual for AI Agents

This document is the operating manual for AI agents (Hermes, Claude Code, Codex, etc.) executing iOS security work with this toolkit. It is prescriptive: follow the decision tree, use the exact commands, and record findings with the evidence schema.

## Decision Tree

```
TASK: "analyze/assess/test <target>"
│
├─ target is an .ipa file (or two .ipa files)?
│   ├─ TWO ipas → pentest/ipa_diff.py  (Workflow 3)
│   └─ ONE ipa  → ./ios-wizard triage <ipa> -o report/  (Workflow 1)
│
├─ target is an .app bundle (extracted or macOS app)?
│   ├─ question is about entitlements → static/entitlements.py
│   ├─ question is about XPC/URL schemes/extensions → pentest/probe_plan.py
│   ├─ question is about crypto → static/crypto_scan.py
│   ├─ question is about persistence → dynamic/launchd_inspect.py
│   └─ general static assessment → ./ios-wizard triage
│
├─ target is a single Mach-O binary?
│   ├─ "what's in it" → static/macho_parser.py (print_summary)
│   ├─ "is it hardened" → static/hardened_runtime.py
│   ├─ "what crypto" → static/crypto_scan.py
│   └─ "what ObjC classes" → static/objc_swift.py
│
├─ target is a live iOS device (owned/authorized)?
│   ├─ need instrumentation → Workflow 2 (gadget re-sign)
│   ├─ need XPC mapping on device → dynamic/xpc_enum.py
│   ├─ need integrity check → pentest/device_baseline.py --check
│   └─ need compromise assessment → dynamic/jailbreak_check.py
│
└─ target is a dyld shared cache?
    ├─ list images → static/dyld_cache.py --list
    ├─ inspect header → static/dyld_cache.py --info
    └─ extract dylib → static/dyld_cache.py <cache> <image> <out>
```

## Iron Rules

1. **Never guess offsets.** Every offset, address, and size must come from parsed structures (`macho_parser.py`) or documented format references. If a parse fails, consult `references/macho_format.md` before patching code.

2. **No jailbreak assumptions.** This toolkit's dynamic path is gadget mode (re-signed IPA). Do not suggest or use jailbreak-only tooling (Cydia, checkra1n). If a task genuinely requires root, state that as a blocker with the specific capability needed.

3. **Evidence-before-finding.** Every finding must carry evidence: file path, section name, address/offset, hash, or tool output line. Use the evidence schema below. Never report a finding you cannot point to.

4. **Baseline before drift.** Any integrity/drift comparison requires a prior capture. If the user asks "has this device changed?" and no baseline exists, capture one, note that it establishes the baseline (not a finding), and explain that drift detection starts from now.

5. **PII and device identifiers are sensitive.** UDIDs, serials, IMEI, phone numbers found in baselines or captures must not be echoed into chat output. Reference them as `<UDID-redacted>` and keep them only in the user's local files.

6. **Report severity honestly.** Severity follows the risk-weighting tables in each tool's docstring. Do not inflate LOW→HIGH to make a report look valuable.

## Evidence Schema

Every finding in a report must include:

```json
{
  "id": "F-<category>-<number>",
  "title": "one-line summary",
  "severity": "CRITICAL|HIGH|MEDIUM|LOW",
  "target": "file path or service name",
  "evidence": {
    "type": "offset|hash|section|symbol|entitlement|sysctl|tool-output",
    "value": "0x... or hash or key name",
    "tool": "which script produced it",
    "command": "exact invocation"
  },
  "impact": "what an attacker gains",
  "remediation": "what to change"
}
```

## Output Handling

- **SARIF** goes to CI pipelines (`delta.sarif`). Never hand-edit SARIF; regenerate from findings.
- **Markdown** goes to humans. Keep it readable: tables, severity badges, one finding per section.
- **JSON findings** go to other agents (`findings.json`). Match the evidence schema above.
- **Frida scripts** are written to `probes/` by `probe_plan.py`. Run them with `frida -U -f <bundle> -l <script>`. Do not paste script contents into reports; reference the file.

## Interpreting Tool Output

### macho_parser.py print_summary
- `Architecture: arm64` + `PAC/Chained Fixups: True` = modern hardened binary.
- `Stack Canary: False` on an executable = immediate HIGH finding.
- `LC_MAIN` present = modern entry point; `LC_UNIXTHREAD` = legacy.
- Symbols section truncates at 30 — run `nm -g` for full list if needed.

### entitlements.py
- "Wildcard keychain access group" = CRITICAL (any app on team can read).
- "Hardened runtime relaxed: allow-jit" = MEDIUM by itself; HIGH if the app loads remote code.
- "Missing hardened runtime flag" on a release build = HIGH.

### crypto_scan.py
- `kSecAttrAccessibleAlways` / `AlwaysThisDeviceOnly` = HIGH (keychain readable even when locked/after restore).
- ECB mode = CRITICAL. CBC without IV = HIGH. Hardcoded key = HIGH.
- MD5/SHA1 for security decisions = MEDIUM.

### ipa_diff.py
- "Binary modified" (hash mismatch) = expected on version bumps; escalate only when paired with entitlement/symbol findings.
- "New entitlement added" = CRITICAL when it grants new capability; the severity is computed per-key.
- Symbol changes in `__TEXT,__objc_classlist` region = worth deeper `objc_swift.py` pass.

### jailbreak_check.py
- Positive on a device that should be clean = investigate before anything else.
- False positives are common on dev-signed builds (`get-task-allow` looks like jailbreak evidence). Corroborate with ≥2 independent indicators before reporting.

## Workflow Reference

All five numbered workflows live in SKILL.md. Full-assessment workflow:

```
1. ./ios-wizard triage target.ipa -o report/        (static, offline)
2. baseline: ./ios-wizard pentest baseline --capture (if device available)
3. probes: ./ios-wizard pentest probes App.app -o probes/
4. gadget setup + run probes (needs macOS + cert)
5. ./ios-wizard pentest report report/findings.json -o final.md
```

Steps 1, 3, 5 run anywhere. Steps 2, 4 need the device.

## Failure Handling

| Symptom | Action |
|---------|--------|
| Mach-O parse raises `Unknown magic` | Not a Mach-O. Check with `file <path>`. ELF/PE are out of scope. |
| `EOFError` mid-parse | Truncated binary or wrong arch parse. Re-check endianness; verify with `otool -l` if available. |
| entitlements.py can't decode mobileprovision | Not CMS-signed or malformed. Fall back to `codesign -d --entitlements -` on the binary itself. |
| dyld_cache parse offsets don't match | Cache format varies by OS version — read `references/macho_format.md` section on dyld caches; target the specific version. |
| Frida attach fails | Gadget not injected or wrong bundle ID. Verify with `./scripts/re-sign_gadget.sh` output and `frida -U -l` listing. |
| device_baseline empty sysctls | Running on Linux without iOS device — expected. Baselines must be captured on-device. |

## Constraints to Respect

- **Python stdlib only** for all `static/` tools — do not add pip dependencies there.
- **All dynamic tooling is gadget-mode** — scripts must not assume root or jailbreak.
- **Media-off-limits rule applies**: never enumerate or view media files on target devices.
- **Authorization**: the user's authorization statement governs scope. If scope is unclear, stop and ask.
