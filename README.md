# npm-pre-scan

A unified npm supply-chain scanner covering metadata to dynamic condition mutation —
implemented in Rust (Layers 0–1) and Docker + shell (Layers 2–3).

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
    Layer 2  Dynamic — simple run    [DONE]   live Docker verified (strace + dnsmasq)
    Layer 3  Dynamic — condition mut [TODO]   core contribution (libfaketime, env spoof, API fuzz)
    Scoring  Aggregate risk score    [TODO]   cross-layer weighted aggregation


-------------------------------------------------------------------------------
 ATTACK-VECTOR COVERAGE  (Ladisa et al. IEEE S&P 2023 taxonomy)
-------------------------------------------------------------------------------

 ID  Attack vector                    Layer    Status
 --  -------------------------------- ------   ------
 A1  Typosquatting                    0        DONE — BLOCK (edit_dist=1 from popular pkg)
 A2  Dependency Confusion             0        DONE — BLOCK (unscoped vs scoped namespace)
 A3  Account Hijacking                0        DONE — SUSPECT (maintainer change detection)
 A4  Combosquatting                   0        DONE — SUSPECT (popular-token + suspicious affix)
 B1  Install-time script              1+2      DONE — Layer 1 SUSPECT + Layer 2 live BLOCK
 B2  Obfuscation (eval+base64, hex)   1        DONE — BLOCK (eval+Buffer.from)
 B3  Malicious version update         1        DONE — BLOCK (newly-introduced eval/sensitive diff)
 C1  Import-time execution            2        DONE — live BLOCK (import-phase side effects)
 C2  Slow exfiltration (DNS tunnel)   2        DONE — live BLOCK (encoded subdomain labels)
 C3  Hidden binary (.node addon)      2        DONE — live SUSPECT (native addon open)
 D1  Time Bomb (date/time-gated)      3        TODO
 D2  Environment-triggered            3        TODO
 D3  Trigger-on-use (API-gated)       3        TODO
 E1  Self-propagating worm            1+2      DONE — Layer 1 BLOCK (worm heuristic + IOC hash);
                                               Layer 2 live BLOCK (worm-egress DNS)

Coverage is considered complete when every in-scope vector is live-verified.
D1–D3 are blocked on Layer 3 implementation.


-------------------------------------------------------------------------------
 LAYER 0 — METADATA CHECKS  [DONE]
-------------------------------------------------------------------------------
Runs on registry metadata only; nothing is downloaded or executed.

  typosquat       Levenshtein distance against ~1137 popular packages
                  (data/top_packages.txt, embedded at compile time).
                    distance=1, name>=5 chars  → BLOCK
                    distance=1, name<5 chars   → SUSPECT  (short-name guard)
                    distance=2                 → SUSPECT

  namespace       Unscoped name collides with a popular scoped package
                  (e.g. "aws-sdk-client-s3" vs "@aws-sdk/client-s3").
                                                → BLOCK

  combosquat      Name contains a popular token AND a suspicious affix
                  (e.g. "lodash-utils-fix").     → SUSPECT

  age_downloads   Package age <7 days + weekly downloads ≥5× monthly average
                  (minimum 1000/wk).             → SUSPECT

  maintainer      New maintainer(s) in the latest version relative to the
                  first version, when the latest version shipped <30 days ago.
                                                → SUSPECT

  signatures      Verifies the npm registry's ECDSA-P256 signature on the
                  latest version (equivalent to `npm audit signatures`).
                    signature missing           → SUSPECT
                    signature invalid / no key  → BLOCK


-------------------------------------------------------------------------------
 LAYER 1 — STATIC ANALYSIS  [DONE]
-------------------------------------------------------------------------------
Downloads and unpacks the package tarball (or reads a local directory);
scans all .js / .cjs / .mjs / .ts / .tsx / .jsx files. No execution.

  install_script     preinstall / install / postinstall present    → SUSPECT

  obfuscation        eval(Buffer.from(...,'base64'))                → BLOCK
                     bare eval(), long hex, long base64            → SUSPECT

  suspicious_strings /etc/passwd, /etc/shadow, ~/.ssh              → BLOCK
                     process.env, os.homedir()                     → SUSPECT

  network_imports    require/import of axios, node-fetch, https,
                     got, superagent, request                      → SUSPECT

  dynamic_require    require(<variable>) — non-literal argument     → SUSPECT

  version_diff       Diffs previous vs latest published tarball;
                     newly-introduced lines only:
                       eval(Buffer.from) / sensitive path          → BLOCK
                       eval / network import / process.env         → SUSPECT
                       worm propagation indicators                 → BLOCK

  worm_signature     Three-category heuristic + SHA-256 IOC lookup
                     (data/worm_iocs.txt, embedded at compile time):
                       self_propagation   npm publish + _authToken → BLOCK
                       credential_harvest TruffleHog / IMDS / creds→ BLOCK
                       exfil_persistence  webhook.site / GH-API    → BLOCK
                       ioc_hash           SHA-256 matches known IOC → BLOCK
                       worm aggregate     ≥2 categories present    → BLOCK

Scoring per layer:  BLOCK=50, SUSPECT=15, INFO=2; weighted sum capped at 100.


-------------------------------------------------------------------------------
 LAYER 2 — DYNAMIC ANALYSIS  [DONE — live Docker verified]
-------------------------------------------------------------------------------
Architecture: dumb container (raw logs) + smart Rust (parse + classify).
Network model: --network=none + in-container dnsmasq sinkhole (every DNS query
name logged; no actual egress leaves the host).

Container produces:
  /out/strace_install.log  — strace of npm install phase
  /out/strace_import.log   — strace of node require() phase
  /out/dns.log             — dnsmasq query log (all DNS query names)

Detection rules (src/layer2/classify.rs):

  E1 worm egress        DNS/connect to registry.npmjs.org, api.github.com,
                        webhook.site, 169.254.169.254               → BLOCK
  B1 install script     child process spawned during install phase;
                        +network/sensitive path access               → SUSPECT/BLOCK
  sensitive file read   /etc/passwd, ~/.ssh, .npmrc, .aws/creds     → BLOCK
  C1 import side effect network/process/file-write during import phase
                                                                    → SUSPECT/BLOCK
  C2 DNS tunneling      many distinct qnames or encoded labels
                        (long base32/hex-looking subdomains)        → SUSPECT/BLOCK
  C3 native addon       *.node file opened/loaded at import         → SUSPECT

Implementation note: musl/alpine node emits the plain `open` syscall (not
`openat`). The strace filter includes both (`open,openat,openat2`) and the Rust
parser handles both forms — omitting either would blind C3 and sensitive-read
detection on alpine containers.


-------------------------------------------------------------------------------
 LAYER 3 — CONDITION MUTATION  [TODO — core research contribution]
-------------------------------------------------------------------------------
Extends the Layer 2 container with active mutation to trigger condition-gated
payloads that existing tools (MalOSS, OSCAR, DONAPI) do not reach.

  Scenario 1 — Clock manipulation
    libfaketime offsets: +30d / +90d / +180d; re-runs install + import.
    Detects: D1 time-bomb payloads.

  Scenario 2 — Environment spoofing
    HOME=/home/developer, USER=dev, strip CI env vars (CI, GITHUB_ACTIONS, …),
    change hostname; re-runs install + import.
    Detects: D2 environment-triggered payloads (CI evasion).

  Scenario 3 — API fuzzing
    Auto-detect all public exports; invoke each with dummy args
    (string / number / object / null / undefined).
    Detects: D3 trigger-on-use (API-call-gated) payloads.

Output: per-scenario behavior diff vs Layer 2 baseline (new events only).


-------------------------------------------------------------------------------
 BUILD & USAGE
-------------------------------------------------------------------------------
Build:
    cargo build              # debug:   target/debug/npm-pre-scan
    cargo build --release    # release: target/release/npm-pre-scan

Usage:
    npm-pre-scan [--json] [--no-color] <pkg> [<pkg> ...]
    npm-pre-scan --local <dir>     # Layer 1 static scan of a local directory
    npm-pre-scan --layer2 <dir>    # Layer 2 dynamic analysis (requires Docker)

Flags:
    --json        emit raw JSON instead of the human-readable report
    --no-color    disable ANSI color output
    --local DIR   Layer 1 only on a local directory (no tarball download)
    --layer2 DIR  Layer 2 dynamic analysis on a local directory

Exit codes (worst verdict across all packages / layers):
    0 = PASS    1 = SUSPECT    2 = BLOCK    3 = ERROR

Examples:
    npm-pre-scan lodash                       # registry scan: Layer 0 then 1
    npm-pre-scan --no-color expresss          # typosquat of "express" → BLOCK
    npm-pre-scan --local ./my-package         # offline static scan
    npm-pre-scan --layer2 ./my-package        # dynamic sandbox scan
    npm-pre-scan --json react vue             # JSON array output

Docker prerequisite (Layer 2):
    The container image is built automatically on first `--layer2` run.
    Requires: docker CLI accessible, --cap-add=SYS_PTRACE capability available.
    WSL2 note: `sudo service docker start` (no systemd by default).


-------------------------------------------------------------------------------
 DATA FILES
-------------------------------------------------------------------------------
    data/top_packages.txt          ~1137 popular package names (typosquat ref)
    data/top_scoped_packages.txt   94 popular scoped packages (namespace ref)
    data/worm_iocs.txt             SHA-256 IOC hashes for known worm artifacts

All three are embedded into the binary at compile time via include_str!.
One entry per line; blank lines and '#' comments are ignored. Add entries and
rebuild to extend coverage.


-------------------------------------------------------------------------------
 TESTING
-------------------------------------------------------------------------------
    cargo test                  # offline suite (no network, no Docker)
    cargo test -- --ignored     # live Layer 2 Docker tests (requires Docker)

Test counts (current):
    97 offline tests:
      - unit tests (Levenshtein, namespace, scoring, Layer 1 static checks, …)
      - integration tests against on-disk dummy packages (Layer 0/1)
      - Layer 2 fixture-based classify tests (offline, no Docker)
    5  live Docker tests (#[ignore]d, require Docker):
      - B1 install_time, C1 import_time, C2 slow_exfil, C3 binary, E1 worm_egress

Dummy packages (gitignored; payload-free; never published):

    dummy_typosquat         Layer 0 (A1)  VERIFIED  BLOCK
    dummy_dep_confusion     Layer 0 (A2)  VERIFIED  BLOCK
    dummy_hijack            Layer 0 (A3)  VERIFIED  SUSPECT
    lodash-utils-fix (name) Layer 0 (A4)  VERIFIED  SUSPECT (combosquat)
    dummy_obfuscated        Layer 1 (B2)  VERIFIED  BLOCK
    dummy_malicious_update  Layer 1 (B3)  VERIFIED  BLOCK (version diff)
    dummy_shai_hulud/clean  Layer 1 (E1)  VERIFIED  PASS   (control)
    dummy_shai_hulud/infect Layer 1+2(E1) VERIFIED  BLOCK  (static + live worm-egress)
    dummy_install_time      Layer 2 (B1)  VERIFIED  BLOCK  (live Docker)
    dummy_import_time       Layer 2 (C1)  VERIFIED  BLOCK  (live Docker)
    dummy_slow_exfil        Layer 2 (C2)  VERIFIED  BLOCK  (live Docker)
    dummy_binary            Layer 2 (C3)  VERIFIED  SUSPECT (live Docker)
    dummy_timebomb          Layer 3 (D1)  TODO
    dummy_env_triggered     Layer 3 (D2)  TODO
    dummy_api_triggered     Layer 3 (D3)  TODO


-------------------------------------------------------------------------------
 PROJECT LAYOUT
-------------------------------------------------------------------------------
    src/
      main.rs              CLI, report formatting, exit codes
      lib.rs               module declarations + public re-exports
      checker.rs           run_layer0() — orchestrates Layer 0 checks
      registry.rs          npm registry + downloads API; signing keys
      typosquat.rs         levenshtein() + check_typosquat()
      age_check.rs         package age + download-spike detection
      maintainer.rs        first-vs-latest maintainer-set comparison
      signatures.rs        ECDSA-P256 registry signature verification
      namespace.rs         unscoped-vs-scoped namespace-conflict detection
      combosquat.rs        popular-token + suspicious-affix heuristic (A4)
      models.rs            Verdict enum, Finding, CheckResult, scoring
      layer1/
        mod.rs             run_layer1() / run_layer1_local() / run_version_diff_local()
        tarball.rs         tarball URL resolution + download/extract
        checks.rs          five static source checks
        version_diff.rs    previous-vs-latest tarball line diff
        worm_signature.rs  three-category worm heuristic + SHA-256 IOC lookup (E1)
      layer2/
        mod.rs             run_layer2_local() — Docker orchestration
        profile.rs         parse_strace() + parse_dns() → Layer2Profile (pure)
        classify.rs        classify(&Layer2Profile) → Vec<Finding> (pure)
    docker/
      Dockerfile           node:lts-alpine + strace + dnsmasq
      run_layer2.sh        container entrypoint (raw log capture)
    data/                  embedded reference lists (see DATA FILES above)
    tests/
      layer0_dummy.rs      integration: A1/A2/A3/A4 on-disk dummies
      layer1_dummy.rs      integration: B2/B3 on-disk dummies
      layer1_worm.rs       integration: E1 static detection
      layer2_classify.rs   offline: classify() fixture tests (no Docker)
      layer2_dynamic.rs    live:    Docker-gated Layer 2 tests (#[ignore])
      fixtures/layer2/     hand-crafted strace/dns log fixtures per scenario
    dummy_packages/        per-vector test packages (gitignored; never published)


-------------------------------------------------------------------------------
 REFERENCES
-------------------------------------------------------------------------------
    Ladisa et al., "SoK: Taxonomy of Attacks on OSS Supply Chains",
      IEEE S&P 2023 — classification base (107 vectors; npm-consumer scope defined here)
    Zheng et al., "OSCAR", ASE 2024 — comparison target; basis for Layer 3 gap
    Duan et al., "MalOSS", NDSS 2021 — comparison target
    Huang et al., "DONAPI", USENIX Security 2024 — comparison target
    OSSF malicious-packages (GitHub) — candidate evaluation dataset
    npm registry signatures: docs.npmjs.com/about-registry-signatures
