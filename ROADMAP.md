# Roadmap — ios-security-wizard

Planning document for the corpus, its tooling, and its distribution.
Baseline measured 2026-09-16 (v1.1.0).

**Rule for every item below: the result must be checkable from the repository.**
A change counts only if a test passes, a parser reads a real fixture correctly, or a
script reproduces the stated number. Prose that cannot be checked does not belong here.

## Measured baseline

| Metric | Value |
|--------|-------|
| Research documents | 20 markdown (SKILL.md, AGENT-GUIDE, INDEX, GLOSSARY, README, CHANGELOG, 12 references, pentest report template) |
| Documentation size | ~2,528 lines |
| Tooling | 18 Python scripts (7 static, 5 dynamic, 4 pentest, 1 fixture builder, 1 test suite) + 3 shell scripts + unified CLI |
| Tooling size | ~7,928 Python lines |
| Component tests | 15 (all passing) |
| Real-binary verification | Mach-O parser + crypto scanner verified against generated arm64 fixtures |
| CI | none |
| LICENSE | MIT at repository root |
| Live-device coverage | none yet (gadget re-sign and device checks need macOS + Apple Developer cert + physical device) |
| dyld cache coverage | structure only — parser not yet verified against a real iOS dyld cache |

## Tiers

### Tier 1 — trust (verification)

- [ ] CI workflow (GitHub Actions) running the 15-test suite on push. Acceptance: green badge on README.
- [ ] `ios-wizard test` exit code wired as the release gate. Acceptance: `gh run watch <id> --exit-status` passes.
- [ ] dyld cache parser verified against a real iOS/macOS dyld shared cache (needs macOS host or a cache sample). Acceptance: parser lists ≥100 images with correct paths.
- [ ] ipa_diff verified against two real IPA builds of the same app. Acceptance: delta report contains expected binary hash changes and zero false CRITICALs.

### Tier 2 — use (real workflows)

- [ ] Gadget-mode end-to-end run: re-sign a real IPA, install, attach Frida, capture one hook. Acceptance: documented run with a real bundle ID (redacted where needed).
- [ ] jailbreak_check live run against a stock device. Acceptance: verdict `CLEAN` on a clean device, evidence captured.
- [ ] device_baseline capture + drift check on a real device. Acceptance: baseline JSON with non-empty mobilegestalt + sysctls; drift check reports zero drift.

### Tier 3 — depth (coverage expansion)

- [ ] ObjC parser verified against a real arm64 app binary (not fixture). Acceptance: class list matches `class-dump` output for ≥10 classes.
- [ ] Swift metadata parsing implemented for type refs and conformance records. Acceptance: unit test on a Swift-compiled fixture.
- [ ] XPC fuzzing probe generator extended to send structured payloads (dictionaries, arrays, data blobs). Acceptance: generated script runs without errors on a test XPC service.

### Tier 4 — reach (distribution)

- [ ] Corpus published on the Hermes Skills Hub. Acceptance: installable via hub, tests pass after install.
- [ ] Sibling integration doc with android-security-wizard (combined mobile assessment workflow). Acceptance: doc with concrete handoff artifacts between the two skills.

## v2.0 definition of done

All Tier 1 items complete, at least two Tier 2 runs documented, CI green on the release tag, and the README's "at a glance" table regenerated from measured values (never hand-edited).
