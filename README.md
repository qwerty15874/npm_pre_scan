# npm_pre_scan
npm prescan for detecting malicious npm packages 

A Rust prototype that screens npm packages for supply-chain attack indicators
BEFORE they are installed or executed. It is the static, no-execution front end
(Layer 0 + Layer 1) of a larger layered detection pipeline.


-------------------------------------------------------------------------------
 1. GOAL & SCOPE
-------------------------------------------------------------------------------
Build a behaviour-based supply-chain attack detection pipeline for the npm
registry, complementing static-analysis-centric measurement methodologies from
prior research. The full design is a 4-layer pipeline that escalates from cheap
metadata checks to expensive sandboxed execution:

    input package name
        |
        v
    Layer 0  Metadata check        (no execution)        [DONE]
        |
        v
    Layer 1  Static analysis       (no execution)        [DONE]
        |
        v
    Layer 2  Dynamic - simple run  (Docker sandbox)       [TODO]
        |
        v
    Layer 3  Dynamic - condition mutation (Docker)        [TODO]
        |
        v
    aggregate risk score

Lower-cost layers run first; a package that earns a BLOCK at Layer 0 short-
circuits and is never handed to Layer 1. Scope is npm-only for the prototype
(PyPI / Maven / NuGet are future work).


-------------------------------------------------------------------------------
 2. LAYER 0 — METADATA CHECKS  (implemented)
-------------------------------------------------------------------------------
Runs purely on registry metadata; no package code is downloaded or executed.

  typosquat       Levenshtein distance of the (de-scoped) name against a list
                  of ~1137 popular packages (data/top_packages.txt).
  age_downloads   Package age < 7 days combined with a download spike
                  (weekly >= 5x the monthly-derived expectation, min 1000/wk).
  maintainer      New maintainer(s) in the latest version vs the first version,
                  flagged only if the latest version shipped within 30 days.
  signatures      Verifies the npm registry's ECDSA-P256 signature on the
                  latest version (equivalent to `npm audit signatures`):
                  fetches registry keys from
                  https://registry.npmjs.org/-/npm/v1/keys and verifies
                  sig over payload  "<name>@<version>:<integrity>".
  namespace       An unscoped name that collides with a popular scoped package
                  (e.g. "aws-sdk-client-s3" shadowing "@aws-sdk/client-s3").

  Severity rules:
    typosquat distance=1 (name >= 5 chars)  -> BLOCK
    typosquat distance=1 (name <  5 chars)  -> SUSPECT   (short-name guard)
    typosquat distance=2                    -> SUSPECT
    namespace conflict                      -> BLOCK
    age < 7d + download spike               -> SUSPECT
    maintainer change                       -> SUSPECT
    registry signature missing              -> SUSPECT
    registry signature invalid / no key     -> BLOCK

  Network-error and best-effort note: registry/signature fetch failures never
  produce a false BLOCK; the affected check is skipped.


-------------------------------------------------------------------------------
 3. LAYER 1 — STATIC ANALYSIS  (implemented)
-------------------------------------------------------------------------------
Downloads and unpacks the package tarball (or reads a local directory) and scans
source files (.js .cjs .mjs .ts .tsx .jsx). No code is executed.

  install_script     package.json preinstall / install / postinstall present
                                                                  -> SUSPECT
  obfuscation        eval(Buffer.from(...))                       -> BLOCK
                     bare eval(), long hex sequences, long base64 -> SUSPECT
  suspicious_strings /etc/passwd, /etc/shadow, ~/.ssh             -> BLOCK
                     process.env, os.homedir()                    -> SUSPECT
  network_imports    CommonJS require() and ESM import of
                     axios/node-fetch/cross-fetch/http(s)/got/
                     superagent/request                           -> SUSPECT
  dynamic_require    require(<non-literal>)  e.g. require(name),
                     require(a+b)  (literal require('x') ignored)  -> SUSPECT
  version_diff       Diffs the previous vs latest published tarball and flags
                     NEWLY introduced code (registry mode only; needs >= 2
                     versions; best-effort):
                       new eval(Buffer.from) / sensitive path      -> BLOCK
                       new eval / network import / process.env      -> SUSPECT


-------------------------------------------------------------------------------
 4. SCORING
-------------------------------------------------------------------------------
Each finding contributes a weight; the per-layer score is the sum, capped at 100.

    BLOCK   = 50
    SUSPECT = 15
    INFO    =  2
    score   = min(100, sum of weights)

Verdict aggregation per layer:
    any BLOCK present          -> BLOCK
    any SUSPECT (and no BLOCK)  -> SUSPECT
    otherwise                   -> PASS
    (ERROR is used for fetch/parse failures that prevent analysis)


-------------------------------------------------------------------------------
 5. BUILD & USAGE
-------------------------------------------------------------------------------
Build:
    cargo build              # debug binary at target/debug/npm-pre-scan
    cargo build --release    # optimized binary at target/release/npm-pre-scan

Usage:
    npm-pre-scan [--json] [--no-color] <pkg> [<pkg> ...]
    npm-pre-scan --local <dir>          # Layer 1 only on a local directory
                                        # (no tarball download; version_diff skipped)

Flags:
    --json       emit raw JSON instead of the human-readable report
    --no-color   disable ANSI color
    --local DIR  scan a local package directory with Layer 1 only

Exit codes (worst verdict across all packages / layers):
    0 = PASS    1 = SUSPECT    2 = BLOCK    3 = ERROR

Examples:
    npm-pre-scan lodash                 # registry scan: Layer 0 then Layer 1
    npm-pre-scan --no-color expresss    # typosquat of "express" -> BLOCK
    npm-pre-scan --local ./my-package   # offline static scan of a local dir
    npm-pre-scan --json react vue       # JSON array of {layer0, layer1} results


-------------------------------------------------------------------------------
 6. DATA FILES
-------------------------------------------------------------------------------
    data/top_packages.txt          ~1137 popular package names (typosquat ref)
    data/top_scoped_packages.txt   94 popular scoped packages (namespace ref)

Both are embedded into the binary at compile time via include_str!. One name per
line; blank lines and lines starting with '#' are ignored. Add entries to extend
coverage and rebuild.


-------------------------------------------------------------------------------
 7. TESTING
-------------------------------------------------------------------------------
    cargo test

Unit tests cover the pure detection logic: Levenshtein and typosquat severity
(including the short-name guard), namespace conflict, scoring/verdict, maintainer
change windows, all Layer 1 file checks (via temp-dir fixtures), version-diff
line accounting, and signature helper logic.

Network-backed paths (registry/download fetch, live tarball download, live
version-diff, and the end-to-end run_layer0/run_layer1 orchestration) are NOT
unit-tested; they are exercised manually against real packages.


-------------------------------------------------------------------------------
 8. PROJECT LAYOUT
-------------------------------------------------------------------------------
    src/
      main.rs            CLI entry point, report formatting, exit codes
      lib.rs             module declarations + public re-exports
      checker.rs         run_layer0(): orchestrates the Layer 0 checks
      registry.rs        npm registry + downloads API; registry signing keys
      typosquat.rs       levenshtein() + check_typosquat()
      age_check.rs       package age + download-spike detection
      maintainer.rs      first-vs-latest maintainer-set comparison
      signatures.rs      ECDSA-P256 registry signature verification
      namespace.rs       unscoped-vs-scoped namespace-conflict detection
      models.rs          Verdict enum, Finding type, CheckResult, scoring
      layer1/
        mod.rs           run_layer1() / run_layer1_local() orchestration
        tarball.rs       tarball URL resolution + download/extract
        checks.rs        the 5 static source checks
        version_diff.rs  previous-vs-latest tarball line diff
    data/                embedded reference lists (see section 6)
    dummy_packages/      hand-crafted test packages per attack type


-------------------------------------------------------------------------------
 9. BLUEPRINT CONFORMANCE  (implementation vs CLAUDE.md design)
-------------------------------------------------------------------------------
    Layer 0  Metadata check            DONE   all four blueprint checks
                                               implemented; registry signature
                                               verification added.
    Layer 1  Static analysis           DONE   all blueprint static checks plus
                                               version-diff and numeric scoring.
    Layer 2  Dynamic - simple run      TODO   Docker sandbox (strace + tcpdump +
                                               DNS logging); npm install and
                                               require() observation.
    Layer 3  Dynamic - condition mut.  TODO   libfaketime clock skew, env
                                               disguise, API fuzzing.
    Scoring  aggregate risk score      PARTIAL per-layer score implemented;
                                               cross-layer aggregate score TODO.

  Dummy-package verification status:
    dummy_typosquat   (Layer 0)  VERIFIED  BLOCK (distance=1 from "express")
    dummy_obfuscated  (Layer 1)  VERIFIED  BLOCK (eval+Buffer.from, install
                                           scripts, process.env, net imports)
    dummy_install_time (Layer 2)  not built
    dummy_import_time  (Layer 2)  not built
    dummy_timebomb     (Layer 3)  not built
    dummy_env_triggered(Layer 3)  not built
    dummy_api_triggered(Layer 3)  not built


-------------------------------------------------------------------------------
 10. REFERENCES
-------------------------------------------------------------------------------
    - OpenSSF malicious-packages (GitHub) — malicious sample data
    - MalOSS (Duan et al., NDSS 2021) — prior art
    - OSSF Package Analysis — strace-based dynamic analysis prior art
    - npm registry signatures: docs.npmjs.com/about-registry-signatures
