# Changelog archive — npm-pre-scan v1–v13

Moved verbatim out of `CLAUDE.md` (which is loaded into context every session) so that file
carries only the current entries, v14–v17. Nothing here has been summarised or reworded; the
ordering is the one the entries had in `CLAUDE.md`, where v1–v4 sat between v14 and v13.

The operational content of v9–v12 that still matters — the CRLF shebang footgun, the
`parse_connect` sockaddr form, the `chmod -R a+r /out` requirement — also lives in the per-layer
sections of `CLAUDE.md`, which is where an agent will look for it.

---

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

### v13: Post-v12 hardening revision — flow, precision, coverage, visibility (2026-07-02)
Driven by a 3-agent audit; prioritized flow → visibility → detection coverage → deferred compromises.
Planning Fable, coding Sonnet (per-phase, reviewed between), docs Fable. Offline **164 passed**; live
Docker **12/12** (5 layer2_dynamic + 4 layer3_dynamic + 2 full_pipeline + 1 full_registry).
- **Phase 1 — execution flow**: `run_full_registry(name)` + `--full` now accepts **name OR dir** — the
  registry name path resolves → downloads ONCE → runs all four layers (the true "unified single tool").
  `tarball::download_and_extract` made pub; `run_layer1_extracted` factored (no double download).
  Silent-failure fixes: missing/unreadable Layer 2/3 logs → `Verdict::Error` (was `unwrap_or_default`);
  signature key-fetch failure → INFO note (was silent None). Shared `src/docker.rs`
  (`docker_available` + SYS_PTRACE preflight). Exit-code mapping consolidated via `exit_code_for`.
- **Phase 2 — Layer 2 baseline subtraction (the deep v10 compromise)**: `run_layer2.sh` now traces
  baseline + real per phase (install `--ignore-scripts` vs scripts; import `node -e 0` vs require),
  same `/work` reset pristine between installs so CWD-relative reads cancel; `mod.rs` diffs
  real-vs-baseline via `diff_profiles_phase` then classifies + dedups. npm's `.npmrc`//etc/passwd noise
  cancels → **benign packages are a true PASS**. Consequently `report.rs` **removed the L2 SUSPECT cap
  and restored L2 weight to 1.0** (canonical example re-based 0.82 → 1.00). `diff.rs` gained
  `diff_profiles_phase` (back-compat) + normalization of `.npm/_logs`/lockfile names.
  ⚠ Live verification caught a path-asymmetry bug (baseline in `/work_base` vs real in `/work` left
  `/work/.npmrc` uncancelled → benign BLOCK); fixed by using the same `/work` for both.
- **Phase 3 — detection coverage**: `vector` tag on every L0/L1 finding (A1–E1 / META); network-import
  set broadened (ws, socket.io, http(s)-proxy-agent, undici) + new `shell_exfil` (child_process
  curl/wget/nc); `prepare` lifecycle hook; obfuscation FP reduction (data: URI exclusion, hex 4→8
  consecutive) with FP-control tests; typosquat homoglyph folding (Cyrillic/Greek confusables → ASCII,
  no new dep); worm-IOC + data-file provenance headers; L2 finding dedup; L3 `vector` set to D1/D2/D3.
- **Phase 4 — visibility**: `--verbose`/`-v` (per-layer progress + per-scenario diff `evidence` surfaced
  on findings and in the report); `RiskReport.layer_status` [ran|skipped|not_run|error]; removed the
  unused tcpdump/`capture.pcap` capture from both docker scripts.
- **Phase 5 — docs**: README rewritten to current reality (was stale: L3/scoring/D1–D3 "TODO");
  this v13 entry; heuristic thresholds documented. Evaluation harness remains deferred (TBD).
- **Known follow-ups (not bugs)**: 3 minor clippy style nits (manual char-cmp, match→?, if-let→unwrap_or_default);
  working-tree CRLF on some .rs/.txt (git `* text=auto` normalizes on commit; .sh verified LF).

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
