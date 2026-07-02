# CLAUDE.md
> Last updated: 2026-07-02 (v12)

---

## Progress

```
Pipeline: package name → Layer 0 → Layer 1 → Layer 2 → Layer 3 → risk score

Layer 0  [████████████████████] DONE   Metadata check        (no execution, Rust)
Layer 1  [████████████████████] DONE   Static analysis       (no execution, Rust)
Layer 2  [████████████████████] DONE   Dynamic — static + live Docker verified
Layer 3  [████████████████████] DONE   Dynamic — condition mutation, live Docker verified
Scoring  [████████████████████] DONE   Aggregate risk score (noisy-OR, --full pipeline)
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
| B1 | Install-time script (pre/postinstall) | install | Layer 1+2 | dummy_install_time | ✅ DONE (Layer 2 live-verified: BLOCK) |
| B2 | Obfuscation (eval+base64, hex) | install/import | Layer 1 | dummy_obfuscated | ✅ DONE |
| B3 | Malicious version update (legit pkg subversion) | install/import | Layer 1 (version diff) | dummy_malicious_update | ✅ DONE |
| C1 | Import-time execution (top-level index.js) | import | Layer 2 | dummy_import_time | ✅ DONE (Layer 2 live-verified: BLOCK) |
| C2 | Slow exfiltration (DNS tunneling) | import/run | Layer 2 | dummy_slow_exfil | ✅ DONE (Layer 2 live-verified: BLOCK) |
| C3 | Hidden binary (.node C extension) | import/run | Layer 2 | dummy_binary | ✅ DONE (Layer 2 live-verified: BLOCK) |
| D1 | Time Bomb (date/time-gated) | condition | Layer 3 | dummy_timebomb | ✅ DONE (L3 live-verified: clock scenario triggers DNS) |
| D2 | Environment-triggered (CI evasion) | condition | Layer 3 | dummy_env_triggered | ✅ DONE (L3 live-verified: env scenario triggers DNS) |
| D3 | Trigger-on-use (API-call-gated) | run-time | Layer 3 | dummy_api_triggered | ✅ DONE (L3 live-verified: fuzz scenario triggers DNS) |
| E1 | Self-propagating worm (Shai-Hulud) | install/import/run | Layer 1 (worm signature) + Layer 2/3 | dummy_shai_hulud | ✅ DONE (L1 static + L2 live worm-egress BLOCK); L3 TODO |

> A4 and B3 promoted from candidates to DONE (implemented and verified via integration tests).
> E1 Layer 1 static detection done (worm_signature.rs); Layer 2 dynamic worm-egress live-verified (BLOCK); Layer 3 deferred.
> D1/D2/D3 promoted to DONE (Layer 3 condition mutation, live Docker verified 2026-07-01).
> **All in-scope detection vectors (A1–E1) are now DONE and verified.** Remaining work is risk-score aggregation, not coverage.

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

### v12: Risk-score aggregation complete — unified single tool (2026-07-02)
- **Final build task done**: `src/report.rs` aggregates the four layers' `CheckResult`s into one
  `RiskReport { package, risk_score, verdict, detections }` — delivering **core contribution #1
  ("a unified single tool")** end-to-end. Pure function; **no layer detection logic changed**
  (reuses `models::score_findings`). `pub use report::{RiskReport, aggregate, run_full_local}`.
- **`--full <DIR>` orchestrator**: chains L1_local + L2 + L3 → one `RiskReport` (Docker). Name scans
  now also emit a `RiskReport` (L0+L1, `layer_2`/`layer_3` empty) as the standard `--json` output;
  `--local`/`--layer2`/`--layer3` single-layer modes still emit a raw `CheckResult`.
- **Score = weighted noisy-OR** `1 − ∏(1 − wᵢ·scoreᵢ/100)`, weights `[1.0,1.0,0.5,1.0]` (Layer 2
  down-weighted for its over-approximation), Error layers excluded, 2-dp. Example confirmed:
  L0=15/L1=50/L2=100/L3=15 → **0.82**.
- **Layer 2 verdict cap (found in live verification, user-approved)**: `run_full_local` on the benign
  control `dummy_benign_l3` initially returned BLOCK because npm's own install reads `.npmrc`//etc/passwd
  → L2 `sensitive_file_read` (L1/L3 clean). Fix: in `aggregate`, Layer 2 is **capped at SUSPECT** in the
  verdict — it can raise suspicion but never alone force BLOCK (BLOCK must come from L0/L1/L3). All L2
  findings still surface in `detections` + `risk_score`. This is the verdict-level analog of the score
  down-weight and keeps credential-read detections visible without letting toolchain noise dominate.
- **Live-verified (2026-07-02, WSL2 + Docker 29.1.3)**: `cargo test --test full_pipeline -- --ignored`
  = 2 passed — dummy_timebomb → SUSPECT, risk_score 0.57, `layer_3` timebomb detection; dummy_benign_l3
  → SUSPECT (L1+L3 clean, L2 baseline noise only). Offline suite = **127 passed** (was 114; +11 report
  units/integration + the 2 full_pipeline are `#[ignore]`d). Docker-gated total = 11.
- **Known limitation reaffirmed**: unified precision for *unconditional-at-install* attacks is bounded by
  Layer 2's lack of baseline subtraction; Layer 3's baseline-diff only cleans *condition-gated* behavior.
  A benign package still surfaces as SUSPECT (npm baseline reads). Full L2 baseline subtraction = future work.
- **Minor cosmetic (noted, not fixed)**: Layer 3 findings keep the reused Layer 2 `vector` (e.g. `C1`)
  while `check` is the L3 name (`timebomb`); the `layer_3` placement + check name convey the scenario.

### v11: Layer 3 condition mutation complete — core contribution (2026-07-01)
- **Layer 3 implemented and live-verified** — the headline differentiator (active condition mutation
  that OSCAR/MalOSS/DONAPI do not perform). Reuses Layer 2's "dumb container + smart Rust" split:
  `docker/run_layer3.sh` runs the package's import step under a clean **baseline** plus three mutated
  scenarios, each with its own per-scenario dnsmasq log (restarted between scenarios), then Rust
  **diffs** each mutated profile against the baseline and classifies only the mutation-induced events.
  - **Scenario clock (D1)**: `libfaketime` (LD_PRELOAD) + absolute `FAKETIME="@2026-09-29 00:00:00"`.
    Empirically confirmed libfaketime **works on `node:lts-alpine`/musl** (survives `strace -f` and the
    `sh→node` postinstall chain) — the earlier "unreliable on musl" caveat does NOT hold for this image.
  - **Scenario env (D2)**: `env -u CI -u GITHUB_ACTIONS -u CONTINUOUS_INTEGRATION HOME=/home/developer USER=dev`.
  - **Scenario fuzz (D3)**: `docker/fuzz_exports.js` enumerates public exports (module fn + object keys
    + one level of nesting) and invokes each with a dummy-arg matrix (guarded, async-flushed).
- **Reuse, not reimplement**: `src/layer3/diff.rs` (pure `diff_profiles`, path-normalizing set-difference)
  + `src/layer3/classify.rs` (thin wrapper re-tagging `crate::layer2::classify::classify` findings with
  `layer:3` + `scenario`). `src/layer3/mod.rs` mirrors `layer2/mod.rs` (Docker graceful-degradation,
  `--entrypoint /run_layer3.sh` on the shared image). `--layer3 <DIR>` CLI flag added.
- **Baseline-diff cancels Layer 2's precision noise**: npm/node `.npmrc` + `/etc/passwd` reads appear in
  both baseline and mutated, so they subtract out — the intended fix for the v10 over-approximation.
- **D3 baseline correctness fix (found in review)**: D3 must diff the mutated fuzz run against the
  **plain-`require` baseline**, not a second identical fuzz run (two identical harness runs always diff to
  empty → detects nothing). `classify` only trips on real connect/dns/child/sensitive syscalls, so merely
  *calling* benign exports produces nothing to cancel.
- **`env`-symmetry precision fix (found in live verification)**: the `baseline`/`fuzz` scenarios ran
  `node` directly while `clock`/`env` ran `env … node`, so `/usr/bin/env` showed up as a spurious "child
  process spawned" (C1) in every mutated diff — mis-attributing dummy_timebomb to D2 AND flagging even
  BENIGN packages as SUSPECT. Fixed by prefixing ALL four scenarios with a bare `env` so the `env` exec +
  its libc opens appear in baseline too and cancel. Added `dummy_benign_l3` (pure `add(a,b)`, no side
  effects) + a live control test asserting `Verdict::Pass` — the proof that baseline-diff precision holds.
- **Live-verified (WSL2/Ubuntu 26.04 + Docker 29.1.3)**: `cargo test --test layer3_dynamic -- --ignored` =
  4 passed. Each malicious dummy fires via ONLY its intended scenario (dummy_timebomb→D1 clock,
  dummy_env_triggered→D2 env, dummy_api_triggered→D3 fuzz, dormant otherwise); dummy_benign_l3→PASS (no
  false positives). Layer 2's 5 live tests still pass (shared-image change is additive). Offline suite =
  114 passed (was 97; +12 diff/classify units + 5 layer3_diff fixture tests). Docker-gated total now 9
  (5 Layer 2 + 4 Layer 3).
- **Known limitations (documented, not omitted)**:
  - **Network-time timebombs are out of scope**: payloads gated on NTP / HTTP `Date` header see nothing
    under `--network=none` + sinkhole (both time source and callback blocked). Layer 3 covers *local-clock*
    checks — the common case.
  - **API fuzzer is best-effort**: exports needing specific arg shapes / constructor protocols may not
    trigger; such cases are swallowed (logged, not crashed), not guaranteed-covered.

### v10: Layer 2 live Docker verification complete (2026-07-01)
- **All 5 Layer 2 dynamic tests pass in real containers** (WSL2/Ubuntu 26.04, Docker 29.1.3):
  B1/C1/C2/C3 → BLOCK, E1 → BLOCK, each via its intended vector (install_script_exec,
  import_side_effect, dns_tunneling, native_addon, worm_egress). `cargo test -- --ignored` = 5 passed;
  offline suite = 97 passed. Total 102 tests.
- **Container fixes required for live runs** (`docker/run_layer2.sh`, `src/layer2/mod.rs`):
  - `--cap-add=SYS_PTRACE` on `docker run` — `strace -f` needs it inside the container.
  - **CRLF bug**: `run_layer2.sh` had been checked out with CRLF (`* text=auto` on Windows/WSL), so the
    shebang was `#!/bin/sh\r` → `exec: no such file or directory`. Converted to LF; added
    `*.sh text eol=lf` to `.gitattributes` to prevent recurrence.
  - Copy package to a writable `/work` inside the container (host mount stays `:ro`) — npm install was
    failing `EROFS` on read-only `/pkg`, so the postinstall never ran.
  - `npm install … --offline` + `npm_config_registry=http://127.0.0.1` — stop npm's own
    registry.npmjs.org DNS from polluting the sinkhole log (was a universal false worm-egress).
  - `chmod -R a+r /out` at end — dnsmasq writes dns.log 0640 (syslog user); the host Rust parser
    otherwise gets EACCES and silently sees an empty DNS log (broke C1/C2/E1).
- **Parser fix** (`src/layer2/profile.rs`): handle the plain `open` syscall, not just `openat`.
  musl/alpine node emits `open(...)`, so the openat-only filter captured no file opens and C3
  (native_addon) + sensitive-file reads never fired. Broadened strace to
  `execve,open,openat,openat2,connect`; added `parse_open` + 2 unit tests.
- **Dummy packages recreated** on disk (gitignored `/dummy_packages`, absent on this fresh clone).
  `dummy_shai_hulud/infected` gained an `index.js` doing an import-time DNS lookup to `api.github.com`
  (payload-free, sinkholed) to drive the dynamic E1 path; its `bundle.js` SHA-256 IOC in
  `data/worm_iocs.txt` was refreshed to match the recreated file.
- **Environment**: moved off NixOS → Windows 11 / WSL2 / Ubuntu 26.04. (Repo had been copied in as
  root:root; a `chown` to the user was required before any build could write `target/`.)
- **Known limitation (precision)**: install-phase npm baseline reads (.npmrc, /etc/passwd) register as
  sensitive_file_read, so Layer 2 over-approximates toward BLOCK for anything that runs `npm install`.
  Layer 3's baseline behavior-diff is the intended fix.

### v9: Layer 2 dynamic analysis logic complete (2026-06-22)
- **Layer 2 detection logic implemented** in pure Rust (no Docker required for testing):
  - `src/layer2/profile.rs` — `Layer2Profile` struct + `parse_strace` / `parse_dns` pure parsers (execve, openat, connect sockaddr, dnsmasq qnames).
  - `src/layer2/classify.rs` — `classify(&Layer2Profile) -> Vec<Finding>` covering E1 worm egress (BLOCK), B1 install child process (SUSPECT/BLOCK), sensitive file reads (BLOCK), C1 import-phase side effects (SUSPECT/BLOCK), C2 DNS tunneling (SUSPECT/BLOCK), C3 native addon (SUSPECT).
  - `src/layer2/mod.rs` — replaced inline event-mapping with parse_* → classify pipeline; kept existing docker-build/run/tempdir plumbing and error_result graceful-degradation.
- **Docker entrypoint reworked** (`docker/run_layer2.sh`): dnsmasq sinkhole (--log-queries, address=/#/127.0.0.1, no upstream) + strace for install and import phases; leaves raw logs in /out for Rust parser. `docker/Dockerfile`: added `dnsmasq` to apk add.
- **Four dummy packages** (payload-free, local-only): `dummy_install_time` (B1), `dummy_import_time` (C1), `dummy_slow_exfil` (C2), `dummy_binary` (C3).
- **Fixture logs** hand-crafted in `tests/fixtures/layer2/` (install_time_strace, import_time_strace, slow_exfil_dns, binary_strace, worm_egress_dns, worm_egress_strace, benign control).
- **Integration tests** `tests/layer2_classify.rs` (8 offline tests, all pass without Docker) + `tests/layer2_dynamic.rs` (5 Docker-gated tests, all #[ignore]d).
- **Known limitation:** Layer 2 classification logic verified by fixtures; live container verification of the dummies (B1/C1/C2/C3) is pending a Docker-capable environment.
- All 91 tests pass (71 unit + 8 layer0_dummy + 4 layer1_dummy + 4 layer1_worm + 8 layer2_classify + 5 ignored).

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
  npm-pre-scan --layer3 <dir>   (Layer 3 condition mutation — requires Docker)
  npm-pre-scan --full <dir>     (full pipeline L1+L2+L3 → aggregate risk report; requires Docker)
  exit 0=PASS  1=SUSPECT  2=BLOCK  3=ERROR
  (name scans also emit the aggregate RiskReport: L0+L1, layer_2/layer_3 empty)

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

### Layer 2 — DONE (static + live Docker verified)
```
Architecture: dumb container (raw logs only) + smart Rust (parse + classify)
  docker/run_layer2.sh   → dnsmasq sinkhole + strace install + strace import → raw logs in /out
  src/layer2/profile.rs  → parse_strace(&str) + parse_dns(&str) → Layer2Profile  [pure, tested]
  src/layer2/classify.rs → classify(&Layer2Profile) → Vec<Finding>               [pure, tested]
  src/layer2/mod.rs      → run_layer2_local(): docker run → read logs → parse → classify

Network model: --network=none + in-container dnsmasq sinkhole (address=/#/127.0.0.1, no upstream).
Every DNS lookup is logged with its qname; connect() destinations captured by strace.

Detection rules (classify):
  E1 worm egress       DNS/connect to registry.npmjs.org, api.github.com, webhook.site, 169.254.169.254 → BLOCK
  B1 install script    child process (unexpected) during install phase; +network/sensitive → BLOCK     → SUSPECT/BLOCK
  sensitive file read  /etc/passwd, /etc/shadow, ~/.ssh, .npmrc, .aws/credentials, .git-credentials   → BLOCK
  C1 import side effect network/process/file-write activity during import phase                        → SUSPECT/BLOCK
  C2 DNS tunneling     many distinct qnames, or long base32/hex-looking labels                         → SUSPECT/BLOCK
  C3 native addon      *.node file opened/loaded at import                                             → SUSPECT

Files:
  docker/Dockerfile           — node:lts-alpine + strace + tcpdump + dnsmasq
  docker/run_layer2.sh        — raw-log capture (install + import strace, dnsmasq dns.log)
  src/layer2/profile.rs       — parse_strace, parse_dns → Layer2Profile (serde-serializable for Layer 3)
  src/layer2/classify.rs      — classify(&Layer2Profile) → Vec<Finding>
  src/layer2/mod.rs           — run_layer2_local(name, dir) → CheckResult
                                (graceful Error + note when Docker absent)
  tests/fixtures/layer2/      — recorded fixture logs per scenario
  tests/layer2_classify.rs    — 8 offline tests (all pass without Docker)
  tests/layer2_dynamic.rs     — 5 Docker-gated tests (#[ignore]d)
  CLI: npm-pre-scan --layer2 <dir>   exit 0/1/2/3

Live-verified (2026-07-01, WSL2/Ubuntu 26.04 + Docker 29.1.3): all 5 Docker-gated tests in
tests/layer2_dynamic.rs pass in real containers — B1/C1/C2/C3 → BLOCK, E1 → BLOCK — each via its
intended vector (B1 install_script_exec, C1 import_side_effect, C2 dns_tunneling, C3 native_addon,
E1 worm_egress api.github.com).  Run: `cargo test -- --ignored`.

Known limitation (precision): the install phase also captures npm's own baseline reads (.npmrc, and
os.homedir()'s /etc/passwd access) as sensitive_file_read, so verdicts over-approximate toward BLOCK
for any package that runs `npm install`. Layer 2 does no baseline subtraction — removing this
toolchain noise is exactly what Layer 3's behavior-diff-vs-baseline is designed to do.
```

### Layer 3 — DONE (★ core contribution, static + live Docker verified)
```
Architecture: reuse Layer 2's "dumb container + smart Rust" split, add a mutation layer.
  docker/run_layer3.sh   → per scenario: (re)start dnsmasq sinkhole → dns_<scenario>.log,
                           run import under strace → strace_<scenario>.log, SIGTERM dnsmasq.
                           Scenarios: baseline, clock, env, fuzz. npm install done once, unmutated.
  docker/fuzz_exports.js → enumerate exports (module fn + object keys + 1 level nesting) and
                           invoke each with a dummy-arg matrix (guarded, async-flushed).
  src/layer3/diff.rs     → diff_profiles(baseline, mutated) → Layer2Profile of mutated-only events
                           (set difference; normalizes /tmp, /proc/<pid>, .npm cache). [pure, tested]
  src/layer3/classify.rs → classify_scenario(scenario, diff): reuse layer2::classify::classify,
                           re-tag each Finding with layer:3 + scenario + Layer-3 check name. [tested]
  src/layer3/mod.rs      → run_layer3_local(): docker run (--entrypoint /run_layer3.sh, shared image)
                           → read per-scenario logs → parse (layer2::profile) → diff vs baseline
                           → classify. Graceful Verdict::Error when Docker absent.

Scenarios / mutation → vector:
  clock (D1)  LD_PRELOAD=/usr/lib/faketime/libfaketime.so.1 FAKETIME="@2026-09-29 00:00:00"  (time bomb)
  env   (D2)  env -u CI -u GITHUB_ACTIONS -u CONTINUOUS_INTEGRATION HOME=/home/developer USER=dev
  fuzz  (D3)  node /fuzz_exports.js — invoke public API surface (trigger-on-use)

Baseline pairing: D1/D2 diff vs the plain-`require` baseline; D3 diffs the fuzz run vs the SAME
plain-`require` baseline (payload dormant at require, fires when exports are invoked). Severity comes
from the reused Layer 2 classifier (egress host / sensitive read → BLOCK; other network/child/side
effect → SUSPECT). Baseline-diff cancels npm/node toolchain noise (the v10 precision fix).

Files:
  docker/Dockerfile           — + libfaketime; COPY run_layer3.sh + fuzz_exports.js (Layer 2 entrypoint intact)
  docker/run_layer3.sh        — per-scenario raw-log capture (LF-committed; CRLF shebang footgun)
  docker/fuzz_exports.js      — D3 export-invocation harness
  src/layer3/{mod,diff,classify}.rs
  tests/fixtures/layer3/       — per-scenario baseline + mutated fixture logs
  tests/layer3_diff.rs         — 5 offline tests (parse → diff → classify; noise-cancellation)
  tests/layer3_dynamic.rs      — 4 Docker-gated tests (#[ignore]d): 3 malicious dummies + benign control
  CLI: npm-pre-scan --layer3 <dir>   exit 0/1/2/3

Live-verified (2026-07-01, WSL2/Ubuntu 26.04 + Docker 29.1.3): `cargo test --test layer3_dynamic --
--ignored` = 4 passed. dummy_timebomb→D1 (clock), dummy_env_triggered→D2 (env), dummy_api_triggered→D3
(fuzz) — each fires via ONLY its intended scenario, dormant otherwise; dummy_benign_l3→PASS (control,
no false positives). All four scenarios exec via `env → node` so the wrapper cancels in the diff.

Known limitations: network-time timebombs (NTP / HTTP Date header) out of scope under --network=none;
API fuzzer is best-effort (exports needing specific arg shapes/constructors may not trigger).
```

### Risk-score aggregation — DONE (offline + live Docker verified)
```
src/report.rs — pure aggregation over existing layer CheckResults (no layer logic changed):
  RiskReport { package, risk_score: f64, verdict, detections: {layer_0..layer_3: [String]} }
  aggregate(pkg, [Option<&CheckResult>; 4]) -> RiskReport
  run_full_local(name, dir) -> RiskReport   (L1_local + L2 + L3, aggregated; layer_0 empty for local)

Score: weighted NOISY-OR  risk_score = 1 − ∏(1 − wᵢ·scoreᵢ/100)  over layers that ran & verdict≠Error.
  Weights [L0,L1,L2,L3] = [1.0, 1.0, 0.5, 1.0]. Layer 2 down-weighted 0.5 (over-approximation).
  Rounded to 2 dp; an Error layer (e.g. Docker absent) contributes nothing to risk.
Verdict: worst-of layers (BLOCK>SUSPECT>ERROR>PASS), BUT Layer 2 is CAPPED at SUSPECT — L2's
  documented npm-baseline noise (.npmrc//etc/passwd reads) can raise suspicion but never alone force
  BLOCK; BLOCK must come from L0/L1/L3. All L2 findings still appear in detections + risk_score.
detections: each Finding → "{vector}: {check} ({message})" (or "{check}: {message}" if no vector).

CLI: npm-pre-scan --full <dir>  (L1+L2+L3, Docker); name scans emit RiskReport from L0+L1.
Tests: tests/report_aggregate.rs (offline) + report.rs units (incl. 0.82 example, L2-cap);
       tests/full_pipeline.rs (2 Docker-gated: dummy_timebomb→SUSPECT+layer_3, dummy_benign_l3→SUSPECT/L1+L3 clean).
```

Example output (`--full dummy_timebomb`, live):
```json
{ "package": "dummy_timebomb", "risk_score": 0.57, "verdict": "SUSPECT",
  "detections": {
    "layer_0": [], "layer_1": [],
    "layer_2": ["B1: sensitive_file_read (Sensitive file opened: /work/.npmrc)", "..."],
    "layer_3": ["C1: timebomb (Import-phase side effect detected: network activity)"] } }
```
Target schema (name scan with all layers populated):
```json
{ "package": "name", "risk_score": 0.87, "verdict": "BLOCK",
  "detections": { "layer_0": ["A1: typosquat (…)"], "layer_1": ["B2: obfuscation (…)"],
                  "layer_2": [], "layer_3": ["D1: timebomb (…)"] } }
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
| dummy_shai_hulud (infected) | Layer 1+2 (E1) | L0 PASS | ✅ VERIFIED: BLOCK (L1 worm_signature; L2 live worm_egress — api.github.com) |
| dummy_shai_hulud (clean) | Layer 1 (E1) | L0 PASS | ✅ VERIFIED: PASS control |
| dummy_install_time | Layer 2 (B1) | L0-1 PASS | ✅ VERIFIED: BLOCK (live Docker; install_script_exec — /usr/bin/id) |
| dummy_import_time | Layer 2 (C1) | L0-1 PASS | ✅ VERIFIED: BLOCK (live Docker; import_side_effect — DNS example.com) |
| dummy_slow_exfil | Layer 2 (C2) | L0-1 PASS | ✅ VERIFIED: BLOCK (live Docker; dns_tunneling — encoded labels) |
| dummy_binary | Layer 2 (C3) | L0-1 PASS | ✅ VERIFIED: BLOCK (live Docker; native_addon — /work/build/addon.node) |
| dummy_timebomb | Layer 3 (D1) | L0-2 PASS | ✅ VERIFIED: SUSPECT (live Docker; clock scenario triggers DNS to evil.example.com) |
| dummy_env_triggered | Layer 3 (D2) | L0-2 PASS | ✅ VERIFIED: SUSPECT (live Docker; env scenario — USER=dev/no-CI — triggers DNS) |
| dummy_api_triggered | Layer 3 (D3) | L0-2 PASS | ✅ VERIFIED: SUSPECT (live Docker; fuzz scenario invokes run(), dormant at require) |
| dummy_benign_l3 (control) | Layer 3 | L0-2 PASS | ✅ VERIFIED: PASS (live Docker; pure add(), no findings — precision/false-positive control) |

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
- [x] Docker base image (node:lts-alpine + strace + tcpdump + dnsmasq)
- [x] Network isolation setup (--network=none + dnsmasq sinkhole)
- [x] Auto npm install + strace integration (strace_install.log)
- [x] Auto node -e "require()" + monitoring (strace_import.log, dns.log)
- [x] Log parser (profile.rs: parse_strace, parse_dns → Layer2Profile)
- [x] Classification logic (classify.rs: B1/C1/C2/C3/E1 detection rules)
- [x] Offline fixture tests (tests/layer2_classify.rs — 8 tests pass)
- [x] Dummy packages created: dummy_install_time, dummy_import_time, dummy_slow_exfil, dummy_binary
- [x] Live Docker verification: all 5 dummies verified in real containers (WSL2/Ubuntu 26.04 + Docker 29.1.3), 2026-07-01

### Layer 3 (core contribution) — DONE
- [x] libfaketime container integration (verified working on node:lts-alpine/musl)
- [x] Environment-spoofing script (env scenario: strip CI vars, USER=dev, HOME=/home/developer)
- [x] API fuzzer (docker/fuzz_exports.js: auto-detect exports + dummy-arg invocation)
- [x] Behavior diff vs baseline (src/layer3/diff.rs: normalized set-difference)
- [x] Verify: dummy_timebomb (D1), dummy_env_triggered (D2), dummy_api_triggered (D3) — live Docker, 2026-07-01

### Integration
- [x] Layer 0~3 outputs → weighted risk score (src/report.rs: noisy-OR, L2 down-weighted; --full pipeline)
- [x] JSON report output (RiskReport serde struct; --json on all modes)
- [x] Confirm full coverage: every non-candidate in-scope vector VERIFIED (A1–E1 + D1/D2/D3 done)
- [ ] Finalize evaluation method (TBD — dummy verification stays; OSSF real-benchmark undecided)

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
- Windows 11 → WSL2 → Ubuntu 26.04. Location: /home/hkkhpsc/dev/npm_pre_scan (moved off NixOS 2026-07-01)

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
