# npm-pre-scan

A unified npm supply-chain scanner covering metadata to dynamic condition mutation —
implemented in Rust (Layers 0–1) and Docker + shell (Layers 2–3), producing a single
aggregate risk score.

The tool fills a gap in existing SOTA dynamic detection tools (MalOSS, OSCAR, DONAPI):
they cover install/import/run-time observation but lack **active condition triggering**
for time-bomb, environment-triggered, and trigger-on-use payloads. Layer 3 addresses
this via clock manipulation, environment spoofing, and API fuzzing.

Scope: npm-only; vectors detectable by a downstream package consumer at install time.
Out of scope: VCS/CI/build-system compromise (not detectable by a package scanner).


-------------------------------------------------------------------------------
 PIPELINE STATUS
-------------------------------------------------------------------------------

    Layer 0  Metadata check          [DONE]   static, no execution (Rust)
    Layer 1  Static analysis         [DONE]   static, no execution (Rust)
    Layer 2  Dynamic — baseline diff [DONE]   live Docker verified (strace + dnsmasq)
    Layer 3  Dynamic — condition mut [DONE]   live Docker verified (libfaketime, env spoof, API fuzz)
    Scoring  Aggregate risk score    [DONE]   cross-layer weighted noisy-OR

All in-scope attack vectors (A1–E1, incl. D1–D3) are implemented and live-verified.


-------------------------------------------------------------------------------
 ATTACK-VECTOR COVERAGE  (Ladisa et al. IEEE S&P 2023 taxonomy)
-------------------------------------------------------------------------------

 ID  Attack vector                    Layer    Status
 --  -------------------------------- ------   ------
 A1  Typosquatting                    0        DONE — BLOCK (edit_dist ≤1; homoglyph-folded)
 A2  Dependency Confusion             0        DONE — BLOCK (unscoped vs scoped namespace)
 A3  Account Hijacking                0        DONE — SUSPECT (maintainer change detection)
 A4  Combosquatting                   0        DONE — SUSPECT (popular-token + suspicious affix)
 B1  Install-time script              1+2      DONE — Layer 1 SUSPECT + Layer 2 live BLOCK
 B2  Obfuscation (eval+base64, hex)   1        DONE — BLOCK (eval+Buffer.from)
 B3  Malicious version update         1        DONE — BLOCK (newly-introduced eval/sensitive diff)
 C1  Import-time execution            2        DONE — live BLOCK (import-phase side effects)
 C2  Slow exfiltration (DNS tunnel)   2        DONE — live BLOCK (encoded subdomain labels)
 C3  Hidden binary (.node addon)      2        DONE — live SUSPECT (native addon open)
 D1  Time Bomb (date/time-gated)      3        DONE — live SUSPECT (clock scenario triggers egress)
 D2  Environment-triggered            3        DONE — live SUSPECT (env scenario triggers egress)
 D3  Trigger-on-use (API-gated)       3        DONE — live SUSPECT (fuzz scenario triggers egress)
 E1  Self-propagating worm            1+2      DONE — Layer 1 BLOCK (heuristic + IOC); Layer 2 live BLOCK
 B4  Destructive / persistence        2+3      DONE — live BLOCK (wiper: mass-deletion; persistence:
                                               sensitive-file write — .npmrc/.bashrc/authorized_keys/
                                               cron/git-hooks/node_modules/.bin), baseline-diffed

Every finding carries a "vector" tag (A1…E1, or "META" for heuristic metadata signals) so
JSON consumers can map detections to the taxonomy.


-------------------------------------------------------------------------------
 LAYER 0 — METADATA CHECKS  [DONE]
-------------------------------------------------------------------------------
Runs on registry metadata only; nothing is downloaded or executed.

  typosquat       Levenshtein distance against ~1137 popular packages
                  (data/top_packages.txt, embedded at compile time). The name is
                  lowercased and homoglyph-folded (Cyrillic/Greek confusables →
                  ASCII) before comparison, so "lodаsh" (Cyrillic а) is caught.
                    distance=1, name>=5 chars  → BLOCK
                    distance=1, name<5 chars   → SUSPECT  (short-name guard)
                    distance=2                 → SUSPECT
                  Envelope: ASCII + confusable-folded, distance ≤2.

  namespace       Unscoped name collides with a popular scoped package
                  (e.g. "aws-sdk-client-s3" vs "@aws-sdk/client-s3").   → BLOCK

  combosquat      Name contains a popular token AND a suspicious affix
                  (e.g. "lodash-utils-fix").                            → SUSPECT

  age_downloads   Package age <7 days + weekly downloads ≥5× monthly average
                  (minimum 1000/wk).                                    → SUSPECT  (vector META)

  maintainer      New maintainer(s) in the latest version relative to the first
                  version, when the latest version shipped <30 days ago. → SUSPECT
                  (30-day window trades slow-hijack recall for lower FPs.)

  signatures      Verifies the npm registry's ECDSA-P256 signature on the latest
                  version (equivalent to `npm audit signatures`).       (vector META)
                    signature missing          → SUSPECT
                    signature invalid / no key → BLOCK
                    keys unavailable (network) → INFO note (never false-BLOCKs)


-------------------------------------------------------------------------------
 LAYER 1 — STATIC ANALYSIS  [DONE]
-------------------------------------------------------------------------------
Downloads and unpacks the package tarball (or reads a local directory);
recursively scans all .js / .cjs / .mjs / .ts / .tsx / .jsx files. No execution.

  install_script     preinstall / install / postinstall / prepare present  → SUSPECT
                     (test/prepack/prepublishOnly are out of scope — not run
                      at consumer install time.)

  obfuscation        eval(Buffer.from(...,'base64'))                        → BLOCK
                     atob(...) whose file also has eval() or a Function("…")
                       string-constructor (decoded-and-executed)           → BLOCK
                     bare eval(), long hex (8+ consecutive \xNN), long base64 → SUSPECT
                     atob() alone, Function("…") constructor                → SUSPECT
                     (base64 inside a data: URI and short ANSI escape runs
                      are excluded to reduce false positives; a bare `atob`
                      identifier / comment mention and Function.prototype are
                      not flagged.)

  computed_load      computed dynamic import() — import(<var>) or import(x+y) → SUSPECT
                     systematic split-string obfuscation ('ht'+'tp', ≥3 in a file) → SUSPECT

  suspicious_strings /etc/passwd, /etc/shadow, ~/.ssh                       → BLOCK
                     process.env, os.homedir()                             → SUSPECT

  network_imports    require/import of axios, node-fetch, cross-fetch, got,
                     superagent, request, ws, socket.io, http(s)-proxy-agent,
                     undici                                                → SUSPECT
  shell_exfil        child_process exec/spawn of curl / wget / nc / ncat /
                     python / perl / ruby, a /dev/tcp/ socket, or `base64 -d` → SUSPECT

  capability_notes   worker_threads import, *.wasm reference                → INFO
                     (low-weight capability surface — common in benign code)

  dynamic_require    require(<variable>) — non-literal argument             → SUSPECT

  version_diff       Diffs previous vs latest published tarball; new lines only:
                       eval(Buffer.from) / sensitive path                  → BLOCK
                       eval / network import / process.env                 → SUSPECT
                       worm propagation indicators                         → BLOCK (vector B3)

  worm_signature     Three-category heuristic + SHA-256 IOC lookup
                     (data/worm_iocs.txt, embedded at compile time):
                       self_propagation   npm publish + _authToken        → BLOCK
                       credential_harvest TruffleHog / IMDS / creds        → BLOCK
                       exfil_persistence  webhook.site / GH-API            → BLOCK
                       ioc_hash           SHA-256 matches known IOC        → BLOCK
                       worm aggregate     ≥2 categories present            → BLOCK (vector E1)

Per-layer scoring:  BLOCK=50, SUSPECT=15, INFO=2; weighted sum capped at 100.


-------------------------------------------------------------------------------
 LAYER 2 — DYNAMIC ANALYSIS (BASELINE SUBTRACTION)  [DONE — live Docker verified]
-------------------------------------------------------------------------------
Architecture: dumb container (raw logs) + smart Rust (parse + diff + classify).
Network model: --network=none + in-container dnsmasq sinkhole, restarted per run
(every DNS query name logged; no actual egress leaves the host).

To cancel npm/node's OWN toolchain reads (.npmrc, /etc/passwd) at the source,
each phase is traced TWICE — an unmutated baseline and the real run — and the
Rust side diffs real-vs-baseline (reusing Layer 3's diff engine) before
classifying. Only *package-attributable* behavior survives the diff, so a benign
package is a genuine PASS (no more over-approximation to BLOCK on npm's own reads).

Container produces (4 runs, each with its own dnsmasq log):
  strace_install_base.log / _real.log   — npm install --ignore-scripts vs scripts-enabled
  strace_import_base.log  / _real.log   — node -e "0" vs node -e require(pkg)
  dns_install_base/real.log, dns_import_base/real.log

Both install runs use the SAME working dir (reset to pristine between them) so
CWD-relative reads (.npmrc, package.json, node_modules/…) are byte-identical and
cancel in the diff.

The strace syscall set is broadened beyond reads/exec/connect to make file
WRITES, DELETES, RENAMES and CHMODs visible (wipers, persistence-file drops,
node_modules pollution): execve, open, openat, openat2, connect, unlink,
unlinkat, rename, renameat, renameat2, chmod, fchmodat (bare `write` is
deliberately omitted — log volume). Layer2Profile gains file_writes /
file_deletes accordingly.

Detection rules (applied to the diff, src/layer2/classify.rs):

  E1 worm egress        DNS/connect to registry.npmjs.org, api.github.com,
                        webhook.site, 169.254.169.254               → BLOCK
  C1 ip_literal_egress  connect() to a public IPv4 literal — closes the
                        DNS-sinkhole bypass where malware hardcodes a C2 IP → SUSPECT
  B1 install script     unexpected child process during install phase;
                        +network/sensitive/write/wipe                → SUSPECT/BLOCK
  sensitive file read   /etc/passwd, ~/.ssh, .npmrc, .aws/creds     → BLOCK
  B4 sensitive_file_write  write/modify of .npmrc / .bashrc / authorized_keys /
                        crontab / .git/hooks / node_modules/.bin     → BLOCK
  B4 mass_deletion      ≥20 package-attributable unlinks (wiper)     → BLOCK
  C1 import side effect network/process/file write/delete during import phase → SUSPECT/BLOCK
  C2 DNS tunneling      many distinct qnames or encoded labels      → SUSPECT/BLOCK
  C3 native addon       *.node file opened/loaded at import         → SUSPECT

All write/delete rules are baseline-diffed, and writes/deletes to ephemeral or
system scratch (/tmp, /dev incl. /dev/shm, /proc, /sys, /run, /var/tmp,
/var/cache, /etc/localtime, */faketime*) are excluded — this is what keeps the
Layer 3 clock scenario honest (libfaketime, LD_PRELOAD'd only in the mutated
run, writes/unlinks its own /dev/shm/faketime_* files that would otherwise
survive the diff and false-positive every benign package).

Findings from both phases are de-duplicated. Implementation note: musl/alpine node
emits the plain `open` syscall (not `openat`); the strace filter and parser handle
both, or C3 + sensitive-read detection would be blind on alpine.

Known limitation: a payload that ONLY reads .npmrc (credential theft) at install
cancels against npm's own .npmrc read — Layer 1 static (suspicious_strings) still
flags .npmrc references in the source.


-------------------------------------------------------------------------------
 LAYER 3 — CONDITION MUTATION  [DONE — core research contribution, live-verified]
-------------------------------------------------------------------------------
Extends the Layer 2 container with active mutation to trigger condition-gated
payloads existing tools (MalOSS, OSCAR, DONAPI) do not reach. Runs a clean
baseline plus three mutated scenarios, then diffs each mutated profile against the
baseline and classifies only the mutation-induced (new) events.

  baseline        clean env, real clock, plain require() — the reference profile.

  clock (D1)      libfaketime (LD_PRELOAD) with an absolute future FAKETIME
                  (~+90d). Confirmed working with musl-linked node on
                  node:lts-alpine, including through the sh→node postinstall chain.
                  Detects: time-bomb payloads.

  env (D2)        strip CI signals (CI, GITHUB_ACTIONS, CONTINUOUS_INTEGRATION),
                  set HOME=/home/developer, USER=dev, NODE_ENV=production,
                  TERM=xterm-256color (the last two widen the developer-machine
                  spoof to catch NODE_ENV- and TTY-gated payloads too).
                  Detects: environment-triggered (CI-evasion) payloads.

  fuzz (D3)       docker/fuzz_exports.js auto-enumerates public exports (module
                  fn + object keys + one level of nesting) and invokes each with a
                  dummy-arg matrix, guarded and async-flushed.
                  Detects: trigger-on-use (API-call-gated) payloads.

Each mutated scenario's new-events diff is classified and tagged with its scenario
vector (D1/D2/D3). Out of scope: network-time bombs (NTP / HTTP Date header) — the
time source and callback are both blocked under --network=none.


-------------------------------------------------------------------------------
 RISK-SCORE AGGREGATION  [DONE]
-------------------------------------------------------------------------------
src/report.rs combines the per-layer CheckResults into one RiskReport (a pure
function; no layer logic changed):

  risk_score   weighted noisy-OR:  1 − Π(1 − wᵢ·scoreᵢ/100)  over layers that ran
               (Error layers contribute nothing). Weights [L0,L1,L2,L3]=[1,1,1,1];
               Layer 2 is a first-class trusted layer now that baseline subtraction
               makes it precise. Rounded to 2 decimals.
  verdict      worst-of the layers that ran (BLOCK > SUSPECT > ERROR > PASS).
  detections   per-layer list of "vector: check (message)" summaries.
  layer_status per-layer: "ran" | "skipped" (L1 when L0 BLOCK short-circuits) |
               "not_run" (absent / Docker unavailable) | "error".
  evidence     per-layer list of the exact new events (dns/connect/file/proc) that
               Layer 2/3's diff-based findings fired on (shown under --verbose).

Example (`--full <name>` JSON):
    {
      "package": "name", "risk_score": 0.82, "verdict": "BLOCK",
      "detections": { "layer_0": ["A1: typosquat (…)"], "layer_1": ["B2: obfuscation (…)"],
                      "layer_2": [], "layer_3": ["D1: timebomb (…)"] },
      "layer_status": ["ran","ran","ran","ran"],
      "evidence": { "layer_0": [], "layer_1": [], "layer_2": [], "layer_3": ["dns:evil.example.com"] }
    }


-------------------------------------------------------------------------------
 BUILD & USAGE
-------------------------------------------------------------------------------
Build:
    cargo build              # debug:   target/debug/npm-pre-scan
    cargo build --release    # release: target/release/npm-pre-scan

Usage:
    npm-pre-scan [--json] [--no-color] [-v|--verbose] <pkg> [<pkg> ...]
    npm-pre-scan --local  <dir>          # Layer 1 static scan of a local directory
    npm-pre-scan --layer2 <dir>          # Layer 2 dynamic analysis (requires Docker)
    npm-pre-scan --layer3 <dir>          # Layer 3 condition mutation (requires Docker)
    npm-pre-scan --full   <name|dir>     # full pipeline + aggregate risk report

Modes:
    <pkg> …            registry scan: Layer 0, then Layer 1 (skips L1 if L0 BLOCKs);
                       emits an aggregate RiskReport (layer_2/layer_3 = not_run).
    --full <name>      the unified single-tool path: resolves the name, downloads
                       the tarball once, and runs ALL four layers → RiskReport.
    --full <dir>       full pipeline (L1+L2+L3) on a local directory (Layer 0 = not_run,
                       no registry identity).
    --local/--layer2/--layer3 <dir>   run a single layer on a local directory.

Flags:
    --json        emit raw JSON instead of the human-readable report
    --no-color    disable ANSI color output
    -v, --verbose per-layer progress + per-scenario diff evidence

Exit codes (worst verdict across all packages / layers):
    0 = PASS    1 = SUSPECT    2 = BLOCK    3 = ERROR

Examples:
    npm-pre-scan lodash                       # registry scan: Layer 0 then 1
    npm-pre-scan --no-color expresss          # typosquat of "express" → BLOCK
    npm-pre-scan --full ./my-package          # local full pipeline (L1+L2+L3)
    npm-pre-scan --full some-package           # registry full pipeline (all 4 layers)
    npm-pre-scan -v --full ./my-package        # + per-scenario diff evidence
    npm-pre-scan --json react vue             # JSON array of RiskReports

Docker prerequisite (Layers 2/3, --full):
    The container image is built automatically on first use.
    Requires: docker CLI accessible, --cap-add=SYS_PTRACE capability available
    (checked up front; a confirmed denial fails fast rather than silently
     producing empty logs).
    WSL2 note (Arch): `sudo systemctl start docker` (Arch WSL ships systemd as
    PID 1). On distros without systemd, use `sudo service docker start`.


-------------------------------------------------------------------------------
 DATA FILES
-------------------------------------------------------------------------------
    data/top_packages.txt          ~1137 popular package names (typosquat ref)
    data/top_scoped_packages.txt   94 popular scoped packages (namespace ref)
    data/worm_iocs.txt             SHA-256 IOC hashes for known worm artifacts

All three are embedded into the binary at compile time via include_str! and carry a
provenance header (source + date). One entry per line; blank lines and '#' comments
are ignored. Add entries and rebuild to extend coverage.

Runtime-extensible lists (no recompile): point these env vars at a file (same
one-per-line format) to ADD to the embedded defaults (additive, never replacing):
    NPM_PRE_SCAN_IOCS           extra worm IOC SHA-256 hashes (data/worm_iocs.txt)
    NPM_PRE_SCAN_EGRESS_HOSTS   extra worm-egress hostnames (Layer 2/3 classifier)
See src/runtime_lists.rs (merge_runtime_lines — additive-over-embedded, never panics).


-------------------------------------------------------------------------------
 TESTING
-------------------------------------------------------------------------------
    cargo test                                     # offline suite (no network, no Docker)
    cargo test --no-fail-fast -- --ignored         # live Docker tests (requires Docker)

Test counts (current):
    217 offline tests — unit (Levenshtein, namespace, scoring, aggregation, Layer 1
        static checks incl. atob/Function-ctor/computed-load/capability-notes, Layer 2/3
        diff+classify incl. file-write/mass-deletion/ip-literal, homoglyph fold, FP-controls, …),
        Layer 0/1 dummy integration, Layer 2 fixture classify, Layer 3 diff.
    15  live Docker tests (#[ignore]d, require Docker):
        8 layer2_dynamic (B1/C1/C2/C3/E1 + B4 wiper + B4 persistence + C1 ip-egress),
        4 layer3_dynamic (D1/D2/D3 + benign control),
        2 full_pipeline (timebomb + benign), 1 full_registry (registry-name smoke).

Dummy packages (gitignored; payload-free; never published):

    dummy_typosquat         Layer 0 (A1)  VERIFIED  BLOCK
    dummy_dep_confusion     Layer 0 (A2)  VERIFIED  BLOCK
    dummy_hijack            Layer 0 (A3)  VERIFIED  SUSPECT
    lodash-utils-fix (name) Layer 0 (A4)  VERIFIED  SUSPECT (combosquat)
    dummy_obfuscated        Layer 1 (B2)  VERIFIED  BLOCK
    dummy_malicious_update  Layer 1 (B3)  VERIFIED  BLOCK (version diff)
    dummy_shai_hulud/clean  Layer 1 (E1)  VERIFIED  PASS   (control)
    dummy_shai_hulud/infect Layer 1+2(E1) VERIFIED  BLOCK  (static + live worm-egress)
    dummy_install_time      Layer 2 (B1)  VERIFIED  BLOCK  (live Docker, via diff)
    dummy_import_time       Layer 2 (C1)  VERIFIED  BLOCK  (live Docker, via diff)
    dummy_slow_exfil        Layer 2 (C2)  VERIFIED  BLOCK  (live Docker, via diff)
    dummy_binary            Layer 2 (C3)  VERIFIED  SUSPECT (live Docker, via diff)
    dummy_wiper             Layer 2 (B4)  VERIFIED  BLOCK  (live Docker; mass deletion)
    dummy_persistence       Layer 2 (B4)  VERIFIED  BLOCK  (live Docker; sensitive-file write)
    dummy_ip_egress         Layer 2 (C1)  VERIFIED  SUSPECT (live Docker; public-IP-literal connect)
    dummy_timebomb          Layer 3 (D1)  VERIFIED  SUSPECT (live Docker; clock scenario)
    dummy_env_triggered     Layer 3 (D2)  VERIFIED  SUSPECT (live Docker; env scenario)
    dummy_api_triggered     Layer 3 (D3)  VERIFIED  SUSPECT (live Docker; fuzz scenario)
    dummy_benign_l3         Layer 2+3     VERIFIED  PASS   (precision control — no false positives)


-------------------------------------------------------------------------------
 PROJECT LAYOUT
-------------------------------------------------------------------------------
    src/
      main.rs              CLI, report formatting, --verbose, exit codes
      lib.rs               module declarations + public re-exports
      docker.rs            shared docker_available() + SYS_PTRACE preflight probe
      checker.rs           run_layer0() — orchestrates Layer 0 checks
      registry.rs          npm registry + downloads API; signing keys
      typosquat.rs         levenshtein() + homoglyph fold + check_typosquat()
      age_check.rs         package age + download-spike detection
      maintainer.rs        first-vs-latest maintainer-set comparison
      signatures.rs        ECDSA-P256 registry signature verification
      namespace.rs         unscoped-vs-scoped namespace-conflict detection
      combosquat.rs        popular-token + suspicious-affix heuristic (A4)
      runtime_lists.rs     additive runtime extension of embedded IOC/egress lists (env-file loader)
      models.rs            Verdict enum, Finding, CheckResult, scoring
      report.rs            RiskReport, aggregate(), run_full_local/registry(), LayerStatus
      layer1/
        mod.rs             run_layer1() / _local() / _extracted() / run_version_diff_local()
        tarball.rs         tarball URL resolution + download/extract (pub)
        checks.rs          static source checks (install/obfuscation/strings/network/shell/
                           computed-load/capability-notes/require)
        version_diff.rs    previous-vs-latest tarball line diff
        worm_signature.rs  three-category worm heuristic + SHA-256 IOC lookup (E1)
      layer2/
        mod.rs             run_layer2_local() — baseline-subtraction Docker orchestration
        profile.rs         parse_strace() + parse_dns() → Layer2Profile (pure)
        classify.rs        classify(&Layer2Profile) → Vec<Finding> (pure)
      layer3/
        mod.rs             run_layer3_local() — mutation-scenario Docker orchestration
        diff.rs            diff_profiles[_phase]() + evidence_lines() (pure)
        classify.rs        classify_scenario() — reuses layer2::classify, tags D1/D2/D3
    docker/
      Dockerfile           node:lts-alpine + strace + dnsmasq + libfaketime
      run_layer2.sh        Layer 2 entrypoint (baseline + real, per-run dns)
      run_layer3.sh        Layer 3 entrypoint (baseline + clock/env/fuzz scenarios)
      fuzz_exports.js      D3 API-fuzz harness
    data/                  embedded reference lists (see DATA FILES above)
    tests/
      layer0_dummy.rs      integration: A1/A2/A4 on-disk dummies (+ A3 fixture)
      layer1_dummy.rs      integration: B2/B3 on-disk dummies
      layer1_worm.rs       integration: E1 static detection
      layer2_classify.rs   offline: classify() fixture tests (no Docker)
      layer2_dynamic.rs    live:    Docker-gated Layer 2 tests (#[ignore])
      layer3_diff.rs       offline: diff + classify_scenario tests
      layer3_dynamic.rs    live:    Docker-gated Layer 3 tests (#[ignore])
      report_aggregate.rs  offline: aggregation / risk-score / layer_status tests
      full_pipeline.rs     live:    --full local pipeline (#[ignore])
      full_registry.rs     live:    --full registry-name smoke (#[ignore])
      fixtures/            hand-crafted strace/dns log fixtures (layer2 + layer3)
    dummy_packages/        per-vector test packages (gitignored; never published)


-------------------------------------------------------------------------------
 REFERENCES
-------------------------------------------------------------------------------
    Ladisa et al., "SoK: Taxonomy of Attacks on OSS Supply Chains",
      IEEE S&P 2023 — classification base (107 vectors; npm-consumer scope defined here)
    Zheng et al., "OSCAR", ASE 2024 — comparison target; basis for Layer 3 gap
    Duan et al., "MalOSS", NDSS 2021 — comparison target
    Huang et al., "DONAPI", USENIX Security 2024 — comparison target
    OSSF malicious-packages (GitHub) — candidate evaluation dataset (evaluation TBD)
    npm registry signatures: docs.npmjs.com/about-registry-signatures
