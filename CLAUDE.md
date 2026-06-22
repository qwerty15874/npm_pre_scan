# CLAUDE.md
> Last updated: 2026-06-22

---

## Progress

```
Pipeline: package name → Layer 0 → Layer 1 → Layer 2 → Layer 3 → risk score

Layer 0  [████████████████████] DONE   Metadata check        (no execution, Rust)
Layer 1  [████████████████████] DONE   Static analysis       (no execution, Rust)
Layer 2  [░░░░░░░░░░░░░░░░░░░░] TODO   Dynamic — simple run  (Docker)
Layer 3  [░░░░░░░░░░░░░░░░░░░░] TODO   Dynamic — condition mutation (Docker)
Scoring  [░░░░░░░░░░░░░░░░░░░░] TODO   Aggregate risk score
```

---

## Research Positioning (IMPORTANT — avoid scope confusion)

### This tool is an independent research artifact
- **Decoupled from the KIISC measurement paper** (HCR/DAF/TTD/EWDT, 4-registry comparison).
  - The measurement study is small in scale and unsuitable as a justification base → dependency dropped.
  - The tool stands without citing the KIISC paper.
- **The tool's justification comes from a gap in international SOTA tools:**
  - Existing dynamic detection tools (MalOSS, OSCAR, DONAPI) cover install/import/run-time,
    but lack **active triggering (clock manipulation, environment spoofing, API fuzzing)**
    for condition-gated attacks (time-bomb, environment-triggered, trigger-on-use).
  - This tool fills that gap.

### Core contributions (emphasize BOTH)
1. **Unified single tool (Layer 0~3)** — covers all in-scope npm attack vectors, from metadata to condition mutation.
2. **Layer 3 active condition mutation** — detects time-bomb / env-triggered / trigger-on-use, which existing tools do not.

### One-line contribution statement
> "A unified single npm tool spanning metadata to dynamic analysis that detects condition-gated
> attacks (time-bomb, environment-triggered, trigger-on-use) — which existing dynamic detection
> tools fail to trigger — via active condition mutation (clock manipulation, environment spoofing,
> API fuzzing)."

---

## ★ Design Goal: Complete Attack-Vector Coverage (within defined scope)

**The tool MUST cover every attack vector within its defined scope. This is a hard requirement, not a best-effort target.**

### Scope definition (must be stated explicitly in the paper)
Coverage is defined over **attack vectors detectable by an npm package consumer at install time**,
based on Ladisa et al. taxonomy (IEEE S&P 2023, 107 vectors).
- IN SCOPE: vectors reachable after a package lands on the npm registry, detectable from the
  downstream-consumer perspective (naming confusion, malicious package content, condition-gated payloads).
- OUT OF SCOPE: VCS compromise, CI/CD injection, build-system tampering — not detectable by a
  package scanner. Declaring this boundary is itself part of the contribution.

### Coverage rule
- Every IN-SCOPE vector (A1–E1 below) MUST map to at least one Layer.
- No in-scope vector may be silently skipped. If a vector cannot be reliably detected,
  it must be explicitly documented as a known limitation (not omitted).
- The early-exit optimization (Layer 0 BLOCK skips Layer 1) is a performance choice and
  does NOT reduce coverage: the final verdict still represents the full in-scope vector set.

### Coverage matrix (target: 100% of in-scope vectors)

| ID | Attack vector | Trigger | Layer | Dummy package | Status |
|----|---------------|---------|-------|---------------|--------|
| A1 | Typosquatting | metadata | Layer 0 | dummy_typosquat | ✅ DONE |
| A2 | Dependency Confusion | metadata | Layer 0 | dummy_dep_confusion | ✅ DONE |
| A3 | Account Hijacking (maintainer change) | metadata | Layer 0 | dummy_hijack | ✅ DONE |
| A4 | Combosquatting | metadata | Layer 0 | `lodash-utils-fix` (name test) | ✅ DONE |
| B1 | Install-time script (pre/postinstall) | install | Layer 1+2 | dummy_install_time | TODO |
| B2 | Obfuscation (eval+base64, hex) | install/import | Layer 1 | dummy_obfuscated | ✅ DONE |
| B3 | Malicious version update (legit pkg subversion) | install/import | Layer 1 (version diff) | dummy_malicious_update | ✅ DONE |
| C1 | Import-time execution (top-level index.js) | import | Layer 2 | dummy_import_time | TODO |
| C2 | Slow exfiltration (DNS tunneling) | import/run | Layer 2 | dummy_slow_exfil | TODO |
| C3 | Hidden binary (.node C extension) | import/run | Layer 2 | dummy_binary | TODO |
| D1 | Time Bomb (date/time-gated) | condition | Layer 3 | dummy_timebomb | TODO |
| D2 | Environment-triggered (CI evasion) | condition | Layer 3 | dummy_env_triggered | TODO |
| D3 | Trigger-on-use (API-call-gated) | run-time | Layer 3 | dummy_api_triggered | TODO |
| E1 | Self-propagating worm (Shai-Hulud) | install/import/run | Layer 1 (worm signature) + Layer 2/3 | dummy_shai_hulud | Layer 1 ✅ DONE / dynamic TODO |

> A4 and B3 promoted from candidates to DONE (implemented and verified via integration tests).
> E1 Layer 1 static detection done (worm_signature.rs); Layer 2/3 dynamic verification deferred.
> Coverage is considered complete only when every non-candidate in-scope vector is VERIFIED.

---

## Change Log

### v1: Initial design
- Python pipeline + Docker, Layer 0~3 early-exit structure.

### v2: Implementation underway
- Language switched Python → Rust (Layer 0, 1 done).
- Layer 0 = BLOCK skips Layer 1 (performance optimization).

### v3: Advisor feedback (cover all attack patterns + single tool)
- Added Ladisa-based vector classification, expanded dummy packages.

### v4: Research repositioning (2026-06-08)
- **Dropped KIISC measurement-paper dependency** → tool redefined as independent research.
- Justification moved from "limitations of my measurement paper" to "gap in international SOTA tools."
- Comparison targets: OSCAR (ASE 2024), MalOSS (NDSS 2021), DONAPI (USENIX 2024).
- Ladisa 107 vectors → explicitly scoped to npm-consumer-detectable vectors.
- Both core contributions emphasized: (1) unified single tool, (2) Layer 3 condition mutation.

### v8: E1 Shai-Hulud worm defense added (2026-06-22)
- **E1 Self-propagating worm** detection added: `src/layer1/worm_signature.rs` — three-category heuristic (self_propagation, credential_harvest, exfil_persistence) + SHA-256 IOC hashing vs `data/worm_iocs.txt` → BLOCK; aggregate `worm` BLOCK when ≥2 categories.
- **Worm regex subset** added to `version_diff.rs` diff_findings for B3-style worm-via-update detection (worm carrier injected via legit-package update → BLOCK).
- **Layer 2 Docker stub** scaffolded: `docker/Dockerfile`, `docker/run_layer2.sh`, `src/layer2/mod.rs` (graceful Error+note when Docker absent), `--layer2 <DIR>` flag in `main.rs`.
- **On-disk dummy fixture** `dummy_packages/dummy_shai_hulud/{clean,infected}/` created; infected includes `bundle.js` (IOC-hash matched) and `.github/workflows/shai-hulud-workflow.yml` persistence IOC.
- **Integration tests** `tests/layer1_worm.rs` (4 tests: E1 static BLOCK, self_propagation present, clean control, worm-via-update diff BLOCK). All 67 tests pass.
- `sha2 = "0.10"` added to `[dependencies]` in Cargo.toml.
- `pub mod layer2` + `run_layer2_local` re-exported from `lib.rs`.

### v7: Layer 0/1 coverage complete (2026-06-18)
- **A4 Combosquatting** detection added: `src/combosquat.rs` — popular-token + suspicious-affix heuristic → SUSPECT. Wired into `run_layer0` as Check 3 (name-based, no registry call).
- **B3 Malicious version update** verification seam added: `diff_findings()` extracted from `version_diff.rs`; `run_version_diff_local(prev, latest)` added to `layer1/mod.rs` for network-free testing.
- **On-disk dummy fixtures** created: `dummy_packages/dummy_obfuscated/` (B2) and `dummy_packages/dummy_malicious_update/{prev,latest}/` (B3).
- **Integration tests** created: `tests/layer0_dummy.rs` (8 tests: A1, A2, A4, controls) and `tests/layer1_dummy.rs` (4 tests: B2, B3). All 57 tests pass.
- `reqwest` switched from OpenSSL to `rustls-tls` backend (build portability).
- A4 and B3 promoted from candidates to DONE in coverage matrix.

### v6: Layer 0 follow-up complete (2026-06-10)
- dummy_dep_confusion (A2): `aws-sdk-client-s3` → BLOCK via namespace conflict with `@aws-sdk/client-s3`. E2E verified.
- dummy_hijack (A3): SUSPECT via maintainer change. Integration test in `tests/layer0_dummy.rs` (7 tests). Note: CLI E2E requires a real package with a recent maintainer change; logic verified by test fixture.
- `[dev-dependencies]` added (`chrono`, `serde_json`) for integration tests.

### v5: Coverage made a hard requirement (2026-06-08)
- Added "Complete Attack-Vector Coverage (within defined scope)" as an explicit, mandatory design goal.
- Coverage rule: every in-scope vector maps to a Layer; undetectable ones documented as limitations, not omitted.

---

## Implementation Status

### Layer 0 — DONE
```
src/
  checker.rs      run_layer0(name) → CheckResult {verdict, findings}
  registry.rs     npm registry + downloads API (reqwest blocking)
  typosquat.rs    levenshtein() + check_typosquat() vs top_packages.txt (~1137 pkgs)
  age_check.rs    age < 7 days + download spike ratio (5× threshold)
  maintainer.rs   first-version vs latest-version maintainer set comparison
  signatures.rs   registry ECDSA-P256 signature verification (npm audit signatures)
  namespace.rs    unscoped name vs top_scoped_packages.txt (94 scoped pkgs)
  combosquat.rs   popular-token + suspicious-affix heuristic (A4)
  models.rs       Verdict enum, Finding type, CheckResult struct
  main.rs         CLI: npm-pre-scan [--json] [--no-color] <pkg> [<pkg>...]

data/top_packages.txt        — embedded at compile time
data/top_scoped_packages.txt — embedded at compile time

Binary:
  npm-pre-scan [--json] [--no-color] <pkg> [<pkg>...]
  npm-pre-scan --local <dir>    (Layer 1 only on local dir)
  npm-pre-scan --layer2 <dir>   (Layer 2 dynamic analysis — requires Docker)
  exit 0=PASS  1=SUSPECT  2=BLOCK  3=ERROR

Severity rules:
  typosquat distance=1 (name ≥5 chars)               → BLOCK
  typosquat distance=1 (name <5 chars)               → SUSPECT
  typosquat distance=2                               → SUSPECT
  namespace conflict                                 → BLOCK
  combosquat (popular token + suspicious affix)      → SUSPECT
  age<7d + spike                                     → SUSPECT
  maintainer change                                  → SUSPECT
  signature missing                                  → SUSPECT
  signature invalid / no valid key                   → BLOCK
  (any BLOCK present)                                → verdict BLOCK
  (any SUSPECT, no BLOCK)                            → verdict SUSPECT
```

### Layer 1 — DONE
```
src/layer1/
  mod.rs            run_layer1(name, info), run_layer1_local(name, dir), run_version_diff_local(prev, latest)
  tarball.rs        get_tarball_url(), download_and_extract()
  checks.rs         5 static checks
  version_diff.rs   check_version_diff(info), diff_findings(prev_files, latest_files, …)
  worm_signature.rs check_worm_signature(dir) — E1 three-category heuristic + SHA-256 IOC hashing

data/worm_iocs.txt — known-IOC SHA-256 list, embedded at compile time

Checks:
  install_script      scripts.pre/install/postinstall      → SUSPECT
  obfuscation         eval(Buffer.from())                  → BLOCK
                      eval(), hex, long base64             → SUSPECT
  suspicious_strings  /etc/passwd, /etc/shadow, ~/.ssh     → BLOCK
                      process.env, os.homedir()            → SUSPECT
  network_imports     require(axios/node-fetch/https/…)    → SUSPECT
  dynamic_require     require(variable)                    → SUSPECT
  version_diff        newly-introduced eval(Buffer.from)/sensitive → BLOCK
                      newly-introduced eval/network/process.env    → SUSPECT
                      newly-introduced worm indicators             → BLOCK
  worm_signature      self_propagation (npm publish/_authToken)    → BLOCK
                      credential_harvest (TruffleHog/IMDS/creds)  → BLOCK
                      exfil_persistence (webhook.site/GH-API/wf)  → BLOCK
                      ioc_hash (SHA-256 match vs worm_iocs.txt)    → BLOCK
                      worm aggregate (≥2 categories)               → BLOCK

Scoring: BLOCK=50, SUSPECT=15, INFO=2 weighted sum, capped at 100
Pipeline: Layer 0 BLOCK → Layer 1 skipped
Local test: npm-pre-scan --local <dir>
```

### Layer 2 — STUB (Docker scaffolding done, full dynamic verification TODO)
```
Environment: Docker container (network-isolated)
Execution:
  Step 1. npm install → observe install-time behavior
  Step 2. node -e "require('pkg')" → observe import-time behavior
Monitoring: strace (file syscalls), tcpdump (network), DNS logs, child_process detection
Covers: B1 (dynamic), C1, C2, C3, E1 (worm egress)

Files:
  docker/Dockerfile        — node:lts-alpine + strace + tcpdump
  docker/run_layer2.sh     — monitoring script, writes /out/layer2.json
  src/layer2/mod.rs        — run_layer2_local(name, dir) → CheckResult
                             (graceful Error + note when Docker absent)
  CLI: npm-pre-scan --layer2 <dir>   exit 0/1/2/3
```

### Layer 3 — TODO (★ core contribution)
```
Environment: Layer 2 container + mutation layer (run ALL scenarios)
Scenario 1 — clock manipulation: libfaketime +30d/+90d/+180d, re-run
Scenario 2 — environment spoofing: HOME=/home/developer, USER=dev, strip CI env vars, change hostname
Scenario 3 — API fuzzing: auto-invoke all public exports with dummy args (string/number/object/null/undefined)
Output: per-scenario behavior diff (new events vs Layer 2 baseline)
Covers: D1, D2, D3
→ Active condition mutation not performed by existing tools (incl. OSCAR). The differentiator.
```

### Risk-score aggregation — TODO
```json
{
  "package": "name",
  "risk_score": 0.87,
  "detections": {
    "layer_0": ["A1: typosquatting (edit_dist=1 from 'express')"],
    "layer_1": ["B2: obfuscation (eval+base64 at index.js:12)"],
    "layer_2": [],
    "layer_3": ["D1: timebomb (network activity after +90d)"]
  }
}
```

---

## Dummy Packages — verification status

| Package | Target layer | Prior layers | Status |
|---------|-------------|--------------|--------|
| dummy_typosquat (`expres`) | Layer 0 (A1) | — | ✅ VERIFIED: BLOCK |
| dummy_dep_confusion (`aws-sdk-client-s3`) | Layer 0 (A2) | — | ✅ VERIFIED: BLOCK (namespace conflict with @aws-sdk/client-s3) |
| dummy_hijack | Layer 0 (A3) | — | ✅ VERIFIED: SUSPECT (integration test; maintainer.rs + tests/layer0_dummy.rs) |
| `lodash-utils-fix` (name test) | Layer 0 (A4) | — | ✅ VERIFIED: SUSPECT (combosquat; tests/layer0_dummy.rs) |
| dummy_obfuscated | Layer 1 (B2) | L0 PASS | ✅ VERIFIED: BLOCK (on-disk fixture; tests/layer1_dummy.rs) |
| dummy_malicious_update | Layer 1 (B3) | L0-1 PASS | ✅ VERIFIED: BLOCK diff (on-disk fixture; tests/layer1_dummy.rs) |
| dummy_shai_hulud (infected) | Layer 1 (E1) | L0 PASS | ✅ VERIFIED: BLOCK (worm_signature; tests/layer1_worm.rs) |
| dummy_shai_hulud (clean) | Layer 1 (E1) | L0 PASS | ✅ VERIFIED: PASS control |
| dummy_install_time | Layer 2 | L0-1 PASS | TODO |
| dummy_import_time | Layer 2 | L0-1 PASS | TODO |
| dummy_slow_exfil | Layer 2 | L0-1 PASS | TODO |
| dummy_binary | Layer 2 | L0-1 PASS | TODO |
| dummy_timebomb | Layer 3 | L0-2 PASS | TODO |
| dummy_env_triggered | Layer 3 | L0-2 PASS | TODO |
| dummy_api_triggered | Layer 3 | L0-2 PASS | TODO |

---

## Evaluation — TBD
- Dummy-package verification stays (confirms each Layer works as intended).
- Whether to add a real malicious-package benchmark (e.g., OSSF malicious-packages) is undecided.
- Note: OSCAR reports F1 0.95 (npm) on a real benchmark — an independent tool may need performance metrics.
- **Decision deferred.**

---

## Task Checklist

### Layer 0 follow-up
- [x] Build & verify dummy_dep_confusion (A2)
- [x] Build & verify dummy_hijack (A3)
- [x] Implement A4 combosquatting detection (src/combosquat.rs)
- [x] Implement B3 offline verification seam (diff_findings, run_version_diff_local)
- [x] Create on-disk dummy fixtures (dummy_obfuscated, dummy_malicious_update)
- [x] Create integration tests (tests/layer0_dummy.rs, tests/layer1_dummy.rs)

### Layer 2
- [ ] Docker base image (node:lts-alpine + strace + tcpdump)
- [ ] Network isolation setup
- [ ] Auto npm install + strace integration
- [ ] Auto node -e "require()" + monitoring
- [ ] Log parser (syscall → structured events)
- [ ] Verify: dummy_install_time, dummy_import_time, dummy_slow_exfil, dummy_binary

### Layer 3 (core contribution)
- [ ] libfaketime container integration
- [ ] Environment-spoofing script
- [ ] API fuzzer (auto-detect exports + dummy-arg invocation)
- [ ] Behavior diff vs Layer 2 baseline
- [ ] Verify: dummy_timebomb, dummy_env_triggered, dummy_api_triggered

### Integration
- [ ] Layer 0~3 outputs → weighted risk score
- [ ] JSON report output
- [ ] Confirm full coverage: every non-candidate in-scope vector VERIFIED
- [ ] Finalize evaluation method (TBD)

---

## Tech Stack
- Language: Rust (Layer 0, 1), Docker + shell (Layer 2, 3)
- Container: Docker
- Monitoring: strace, tcpdump, DNS logging
- Clock manipulation: libfaketime
- Static analysis: custom Rust (regex + string patterns)
- Typosquatting: Levenshtein (custom Rust)

## Constraints
- npm-only (justification: most dangerous ecosystem due to install-time execution; independent of measurement paper)
- Docker required — host protection
- Dummy packages: local test only (never npm publish)
- Layer 0 → 1 → 2 → 3 sequential, single entry point npm-pre-scan
- Scope: only vectors an npm consumer can detect at install time (VCS/build compromise excluded)

## Environment
- NixOS LINUX Location:/home/hpschkkim/문서/Dev/npm_pre_scan

## References (independent justification base)
- Ladisa et al., "SoK: Taxonomy of Attacks on OSS Supply Chains", IEEE S&P 2023 — classification base
- Zheng et al., "OSCAR", ASE 2024 — comparison target, basis for Layer 3 gap
- Duan et al., "MalOSS", NDSS 2021 — comparison target (simplistic testing limitation)
- Huang et al., "DONAPI", USENIX Security 2024 — comparison target
- OSSF malicious-packages GitHub repo — candidate evaluation dataset
- (KIISC measurement paper decoupled — no citation required)

---

## Coding Guidelines
1. Think Before Coding: state assumptions, ask if uncertain, surface tradeoffs.
2. Simplicity First: only what's asked, no speculative features, rewrite if overcomplicated.
3. Surgical Changes: touch only what's needed, don't improve adjacent code, match existing style.
4. Goal-Driven: define success criteria first; multi-step → plan then verify.

---
> This file is auto-maintained by the code-sync skill. Do not edit manually unless necessary.
