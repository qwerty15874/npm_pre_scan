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
    Eval     Batch harness + corpus  [DONE]   --eval; 6 arms measured (v17)
    Precision Verdict calibration    [PART]   v19: BLOCK 0/27; any-finding FPR
                                              70.4% -> 48.1%. Ceiling is coverage.

All in-scope attack vectors (A1–E1, incl. D1–D3) are implemented and live-verified.

✅ v18 fixed the worst of what v17 measured. No legitimate package is BLOCK'd any more:
  arm F went from 12 of 27 hard-BLOCK'd to ZERO, with no BLOCK-severity finding of any
  check on the benign corpus. The real Sept-2025 crypto clipper (ansi-styles@6.2.2),
  which used to pass all four layers, is now caught.

✅ v19 nearly halved what was left, at no recall cost. 14 of 27 legitimate packages are
  now completely clean (was 8); any-finding FPR 70.4% -> 48.1%. Four rules that measured
  as non-discriminating — two of them INVERTED, firing more on legitimate packages than
  on malware — became capabilities: informational alone, accusing only when >=3 co-occur.

⚠ Do not cite an FPR without reading EVALUATION. 13 of 27 legitimate packages still
  collect at least one SUSPECT. They genuinely have the capability (axios imports http,
  node-sass runs a postinstall) — telling "has" from "abuses" needs dynamic evidence,
  and the dynamic layers reach only 11 of 27. That is a coverage limit, not calibration.


-------------------------------------------------------------------------------
 ATTACK-VECTOR COVERAGE  (Ladisa et al. IEEE S&P 2023 taxonomy)
-------------------------------------------------------------------------------

 Coverage is complete. The measured column is what the real-corpus arms observed,
 updated for the v18 fix pass (v17 figures shown as "was" where they changed).

   fires  cross-arm total (dominated by the malicious corpora — arms A/D/E), v17 run.
   FP     distinct legitimate packages out of the 27 in eval/corpus/parent_benign.tsv,
          as measured by arm F. Arm F is the only arm that ran all four layers over the
          benign corpus, so it is the single source for false positives. Do NOT sum FPs
          across arms: parent_benign.tsv was scanned in arms A, B and F, so summing
          double- and triple-counts the same packages.

 NO VECTOR NOW PRODUCES A BLOCK-LEVEL FALSE POSITIVE. Every FP below is SUSPECT-level.

 ID  Attack vector                    Layer    Implemented                          fires (all arms) / FP (arm F, v19)
 --  -------------------------------- ------   -----------------------------------  --------------------------
 A1  Typosquatting                    0        BLOCK (edit_dist ≤1; suffix squat;   OK 0 FP (was 1, sqlite).
                                               homoglyph-fold)                         Arm B name recall 25.7%
                                                                                      -> 85.7% (suffix squats
                                                                                      + absent parents, v18)
 A2  Dependency Confusion             0        BLOCK (unscoped vs scoped namespace) OK 0 FP (was 1, babel-cli);
                                                                                      no real TP observed
 A3  Account Hijacking                0        CAPABILITY (maintainer change)       OK 0 FP (was 3). v19: zero
                                                                                      true positives across every
                                                                                      arm ever run -> capability
 A4  Combosquatting                   0        SUSPECT (token + suspicious affix)   OK 410 fires / 0 FP
 B1  Install-time script              1+2      L1: exec-shape cmd BLOCK /           OK 359 fires / ! 1 FP
                                               pre+postinstall SUSPECT /               (node-sass). v19 hook+body
                                               install+prepare CAPABILITY.             split; arm D BLOCK-level
                                               L2 live BLOCK                           recall 21.6% -> 35.1%
 B2  Obfuscation (eval+base64, hex,   1        BLOCK (eval+Buffer.from; >=25        ! 392 fires / 9 of 27 legit
     hex-identifier density)                   distinct _0x identifiers).              packages (was 18). v18 closed
                                               long-base64 -> CAPABILITY (v19)         the obfuscator.io gap:
                                                                                      ansi-styles@6.2.2 now BLOCKs
                                                                                      (was a clean PASS)
 B3  Malicious version update         1        BLOCK (newly-introduced eval/diff)   X 2 fires / 1 FP (bcrypt) —
                                                                                      no true positive; too few
                                                                                      observations to calibrate
 C1  Import-time execution            2        live BLOCK (import side effects)     OK 25 fires / 0 FP
 C2  Slow exfiltration (DNS tunnel)   2        live BLOCK (encoded labels)          OK 10 fires / 0 FP
 C3  Hidden binary (.node addon)      2        live SUSPECT (native addon open)     - dummy only, no real sample
 D1  Time Bomb (date/time-gated)      3        live SUSPECT (clock scenario,        - dummy only, no real sample.
                                               PINNED baseline+clock since v18)        Differential is now
                                                                                      date-invariant
 D2  Environment-triggered            3        live SUSPECT (env scenario)          - 9 fires / 0 FP, some noise
 D3  Trigger-on-use (API-gated)       3        live SUSPECT (fuzz scenario)         ! 2 fires / 1 FP (nodemailer;
                                                                                      structural). Item 7
 E1  Self-propagating worm            1+2      L1: category SUSPECT, >=2-category   OK 194 fires, 5/5 detected;
                                               aggregate or IOC hash BLOCK (v18)       IOC matched real Shai-Hulud
                                                                                      / 2 FP (fabric, node-sass)
                                                                                      now SUSPECT, was BLOCK
 B4  Destructive / persistence        2+3      live BLOCK (wiper: mass-deletion;    - 3 fires / 0 FP, but arm E
                                               persistence: sensitive-file write —     B4 recall is 0/1: the
                                               .npmrc/.bashrc/authorized_keys/         labelled wiper node-ipc@
                                               cron/git-hooks/node_modules/.bin),      12.0.1 was caught as a
                                               baseline-diffed                         package (TP via B2/C1),
                                                                                      but no B4 rule fired
 MET age/downloads + signatures       0        SUSPECT / INFO (expired key)         OK 0 FP (was 11). The
                                                                                      signature time bomb is
                                                                                      FIXED in v18 — all 45
                                                                                      findings are now INFO

 OK = good   ! = works but imprecise   X = fires mainly/only on legitimate packages   - = not exercised

Every finding carries a "vector" tag (A1…E1, or "META" for heuristic metadata signals) so
JSON consumers can map detections to the taxonomy.


-------------------------------------------------------------------------------
 LAYER 0 — METADATA CHECKS  [DONE]
-------------------------------------------------------------------------------
Runs on registry metadata only; nothing is downloaded or executed.

  typosquat       Levenshtein distance against ~1137 popular packages
                  (data/top_packages.txt, embedded at compile time; optionally
                  augmented live via --refresh-top — see DATA FILES). The name is
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
                  version, when the latest version shipped <30 days ago. → CAPABILITY
                  (30-day window trades slow-hijack recall for lower FPs.)
                  (v19: A3 has produced ZERO true positives across every
                   evaluation arm ever run, against 3 false positives on 27
                   legitimate packages. Ownership transfers and co-maintainer
                   additions are ordinary. It stays visible and still counts
                   toward a capability cluster; it no longer accuses alone.)

  signatures      Verifies the npm registry's ECDSA-P256 signature on the latest
                  version (equivalent to `npm audit signatures`).       (vector META)
                    verifies, key current      → no finding
                    verifies, key EXPIRED      → INFO   (see below)
                    verification FAILS         → BLOCK  (tampering)
                    keyid not published        → SUSPECT (unverifiable)
                    signature missing          → SUSPECT
                    keys unavailable (network) → INFO note (never false-BLOCKs)

                  ✅ FIXED in v18 (was a time bomb). npm rotated its registry
                  signing key; the old key (SHA256:jl3bws…) expired 2025-01-29.
                  The check used to filter expired keys OUT of the lookup, so
                  for any package not republished since the rotation it found no
                  key, never verified anything, and returned BLOCK. v17 measured
                  11 of 27 legitimate popular packages BLOCK'd by this alone,
                  worsening every month, and 23 of arm B's 32 "true positives"
                  were this check firing on npm's own takedown stubs.
                  It now verifies against the key that actually signed and
                  treats expiry as informational — an expired key means the
                  package predates a rotation, not that it was tampered with.
                  Measured after: 45 of 45 signature findings are INFO, and
                  BLOCK-level false positives on the benign corpus went 14 → 0
                  in arm B. See eval/REPORT.md #1.

  ✅ A3 `maintainer` fired on legitimate packages far more than on malicious ones
    (4 of 27 legit, zero true positives across all six v17 arms) — FIXED in v19 by
    moving it to the capability tier. It can no longer drive a verdict alone.


-------------------------------------------------------------------------------
 LAYER 1 — STATIC ANALYSIS  [DONE]
-------------------------------------------------------------------------------
Downloads and unpacks the package tarball (or reads a local directory);
recursively scans all .js / .cjs / .mjs / .ts / .tsx / .jsx files. No execution.

  install_script     command fetches/executes (curl, |sh, node -e, URL,
                       base64 -d, child_process)                            → BLOCK
                     preinstall / postinstall, ordinary command             → SUSPECT
                     install / prepare, or a recognised build step
                       (node-gyp, prebuild-install, husky, tsc, make)      → CAPABILITY
                     (test/prepack/prepublishOnly are out of scope — not run
                      at consumer install time.)
                     (v19: measured — preinstall appears 169x in malware and
                      0x in the 27 legitimate packages; an exec/exfil command
                      shape appears in 79 malicious packages and 0 benign.
                      `node <file>` is NOT an exec shape: node-sass ships
                      "postinstall": "node scripts/build.js".)

  obfuscation        eval(Buffer.from(...,'base64'))                        → BLOCK
                     atob(...) whose file also has eval() or a Function("…")
                       string-constructor (decoded-and-executed)           → BLOCK
                     bare eval(), long hex (8+ consecutive \xNN), long base64 → SUSPECT
                     atob() alone, Function("…") constructor                → SUSPECT
                     (base64 inside a data: URI and short ANSI escape runs
                      are excluded to reduce false positives; a bare `atob`
                      identifier / comment mention and Function.prototype are
                      not flagged.)

  hex_identifier     ≥25 DISTINCT `_0x[0-9a-f]{4,}` identifiers in one file → BLOCK
     (v18)           ≥5                                                    → SUSPECT
                     Counts distinct names, not occurrences: a minifier reusing
                     one such name is nothing like a generator emitting hundreds.
                     Raw `0x` literal counts are deliberately NOT used — d3 ships
                     174 of them legitimately.

                     ✅ FIXED in v18 a gap that let a real attack through. The
                     \xNN rule needs 8+ CONSECUTIVE escapes, which the
                     javascript-obfuscator family does not emit at all — so
                     ansi-styles@6.2.2, the real Sept-2025 crypto clipper,
                     passed ALL FOUR layers: 80 KB of payload with only 4 \xNN
                     escapes and zero eval / atob / Buffer.from / Function /
                     process.env / network require. Raising the threshold 4→8 in
                     v14 bought precision on chalk-style ANSI strings and cost
                     this whole attack family.
                     Measured separation: that payload carries 314 distinct `_0x`
                     identifiers; jquery, lodash, d3, react, chalk, debug,
                     node-sass and fabric carry ZERO between them. The sample now
                     scores BLOCK. See eval/REPORT.md #3.

  computed_load      computed dynamic import() — import(<var>) or import(x+y) → SUSPECT
                     systematic split-string obfuscation ('ht'+'tp', ≥3 in a file) → SUSPECT

  suspicious_strings /etc/passwd, /etc/shadow, ~/.ssh                       → BLOCK
                     os.homedir(), incl. require('os').homedir()           → SUSPECT
                     process.env                                          → CAPABILITY
                     (v19: process.env is INVERTED — 36.3% of real malware
                      vs 44.4% of legitimate packages. os.homedir() is
                      14.4% vs 0.0%. Same check, opposite evidence.)

  network_imports    require/import of axios, node-fetch, cross-fetch, got,
                     superagent, request, ws, socket.io, http(s)-proxy-agent,
                     undici                                                → SUSPECT
  shell_exfil        child_process exec/spawn of curl / wget / nc / ncat /
                     python / perl / ruby, a /dev/tcp/ socket, or `base64 -d` → SUSPECT

  capability_notes   worker_threads import, *.wasm reference                → INFO
                     (low-weight capability surface — common in benign code)

  dynamic_require    require(<variable>) — non-literal argument           → CAPABILITY
                     (v19: INVERTED — 7.6% of real malware vs 14.8% of
                      legitimate packages. A bundler emits this by construction.)

  version_diff       Diffs previous vs latest published tarball; new lines only:
                       eval(Buffer.from) / sensitive path                  → BLOCK
                       eval / network import / process.env                 → SUSPECT
                       worm propagation indicators                         → BLOCK (vector B3)

  worm_signature     Three-category heuristic + SHA-256 IOC lookup
                     (data/worm_iocs.txt, embedded at compile time):
                       self_propagation   npm publish + _authToken        → SUSPECT
                       credential_harvest TruffleHog / IMDS / creds        → SUSPECT
                       exfil_persistence  webhook.site / GH-API            → SUSPECT
                       ioc_hash           SHA-256 matches known IOC        → BLOCK
                       worm aggregate     ≥2 categories present            → BLOCK (vector E1)

                     ✅ FIXED in v18. Each category used to BLOCK on its own,
                     independently of the ≥2 rule — so the aggregate never
                     actually gated anything and the documented behaviour was
                     wrong. One ordinary maintainer script was enough to refuse a
                     package: v17 BLOCK'd `fabric` (publish-next.js) and
                     `node-sass` (3 files under scripts/util and lib/), all
                     self_propagation only, and `fabric` passes Layers 2 and 3
                     cleanly so nothing corroborated it.
                     Publishing to npm is what a release script is FOR — it takes
                     a second category (stealing credentials, or exfiltrating
                     them) to make it worm-shaped. A known-IOC hash keeps BLOCK
                     because it is identity, not inference. The Shai-Hulud fixture
                     still BLOCKs via two categories plus its IOC.

Per-layer scoring:  BLOCK=50, SUSPECT=15, INFO=2; weighted sum capped at 100.

CAPABILITY TIER (v19). A rule measured as non-discriminating emits INFO with a
`capability` tag instead of accusing. Reading process.env is what configuration IS;
a bundler emits require(variable) by construction. But capabilities are not
independent: a package that reads the environment AND resolves modules dynamically
AND ships an encoded blob is a different proposition from one that does any single
one of those. A package carrying >=3 DISTINCT capabilities gets a `capability_cluster`
SUSPECT finding (vector META). Distinct ids, not findings — obfuscation and
suspicious_strings emit one finding per file.


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

  ⚠ MEASURED (v17, arm F) — the score does NOT determine the verdict, and it
    saturates on legitimate packages. The verdict is worst-of-severity, as above;
    the noisy-OR score is reported, not used as a gate. On the 27 legitimate
    packages:

      jquery, react    1.00 (the maximum)  → SUSPECT
      ffmpeg           0.50                → BLOCK
      BLOCK range      0.50 – 1.00
      SUSPECT range    0.17 – 1.00
      chalk            0.02  (the only clean package)

    The two ranges overlap completely, and six of the 27 sit at 1.00. Two
    consequences:

      1. Raising a score threshold CANNOT fix the false-positive rate. The
         worst-scoring legitimate packages already tie with the BLOCK'd ones, so
         there is no cut point that separates them. Threshold tuning is the
         obvious cheap fix and it does not work here.
      2. The score is saturated on ordinary packages, so it carries little
         ranking information in its top half.

    Severity assignment and score aggregation therefore have to be revisited
    together, after the per-check fixes land. See eval/REPORT.md.

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
    npm-pre-scan [--json] [--no-color] [-v|--verbose] [--refresh-top] <pkg> [<pkg> ...]
    npm-pre-scan --local  <dir>          # Layer 1 static scan of a local directory
    npm-pre-scan --layer2 <dir>          # Layer 2 dynamic analysis (requires Docker)
    npm-pre-scan --layer3 <dir>          # Layer 3 condition mutation (requires Docker)
    npm-pre-scan --full   <name|dir>     # full pipeline + aggregate risk report
    npm-pre-scan --eval   <manifest>     # batch-evaluate a corpus → result data + metrics

Modes:
    <pkg> …            registry scan: Layer 0, then Layer 1 (skips L1 if L0 BLOCKs);
                       emits an aggregate RiskReport (layer_2/layer_3 = not_run).
    --full <name>      the unified single-tool path: resolves the name, downloads
                       the tarball once, and runs ALL four layers → RiskReport.
    --full <dir>       full pipeline (L1+L2+L3) on a local directory (Layer 0 = not_run,
                       no registry identity).
    --local/--layer2/--layer3 <dir>   run a single layer on a local directory.
    --eval <manifest>  batch mode: scan a ground-truth corpus and write result data
                       (records.jsonl / results.csv / findings.csv / metrics.json).
                       Repeatable — several manifests share one output directory and
                       one metrics summary. See eval/README.md.

Flags:
    --json        emit raw JSON instead of the human-readable report
    --no-color    disable ANSI color output
    -v, --verbose per-layer progress + per-scenario diff evidence
    --refresh-top live-refresh the Layer 0 top-package lists before scanning
                  (24h on-disk cache; also via NPM_PRE_SCAN_REFRESH_TOP=1 —
                  see DATA FILES)

Evaluation flags (--eval only):
    --out-dir <dir>        where to write result data (default eval/runs/<timestamp>)
    --eval-mode <mode>     depth ceiling: name-only | registry | full | auto (default
                           auto). Effective layers per entry = the manifest's `layers`
                           column ∩ this ceiling. `name-only` is fully offline and
                           byte-reproducible.
    --docker-timeout <s>   wall-clock cap per `docker run`. Unset = unbounded, which is
                           the pre-existing behaviour — but one package whose npm
                           install hangs then stalls the whole batch. Also settable via
                           NPM_PRE_SCAN_DOCKER_TIMEOUT.
    --eval-evidence        keep full `evidence` arrays in records.jsonl (off by default;
                           L2/L3 diffs can attach hundreds of events per finding)

Exit codes (worst verdict across all packages / layers):
    0 = PASS    1 = SUSPECT    2 = BLOCK    3 = ERROR

Exit codes in --eval mode (0-3 stay reserved for per-package verdicts, which are
meaningless for a corpus that deliberately contains known-malicious entries):
    0 = batch complete    4 = completed but degraded (an entry errored, timed out,
                              or a layer failed)
    5 = could not run (bad manifest, unwritable output directory)

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
                                   (holds ONE real-world hash — v17 confirmed it is the
                                   RIGHT one: it matched the actual Shai-Hulud patient-zero
                                   sample. Coverage is one sample wide; extend without
                                   recompiling via NPM_PRE_SCAN_IOCS.)

    eval/corpus/*.tsv              ground-truth corpora for --eval (v17). Tracked:
                                   dummies, real_malicious_holders, parent_benign,
                                   datadog_static, datadog_dynamic.
                                   NOT tracked (regenerate — see eval/README.md):
                                     eval/corpus/ossf_npm_names.tsv  216,861 names, 12 MB
                                   NEVER commit:
                                     eval/samples/  live malware, encrypted at rest (102 MB)
                                     eval/runs/     per-run result data (287 MB for 6 arms)

All three are embedded into the binary at compile time via include_str! and carry a
provenance header (source + date). One entry per line; blank lines and '#' comments
are ignored. Add entries and rebuild to extend coverage.

Runtime-extensible lists (no recompile): point these env vars at a file (same
one-per-line format) to ADD to the embedded defaults (additive, never replacing):
    NPM_PRE_SCAN_IOCS           extra worm IOC SHA-256 hashes (data/worm_iocs.txt)
    NPM_PRE_SCAN_EGRESS_HOSTS   extra worm-egress hostnames (Layer 2/3 classifier)
See src/runtime_lists.rs (merge_runtime_lines — additive-over-embedded, never panics).

Live top-package refresh (--refresh-top, opt-in; src/toplist.rs):
    Sweeps the npm registry search API (~24 two-letter seeds, one page of 250 each,
    1.2s apart — the API 429s on faster bursts) and keeps names with >=500k weekly
    downloads (the API has no top-N endpoint and its popularity ranking is noisy,
    so ranking is done client-side on the per-result downloads.weekly field).
    Fetched names are UNION-merged after the embedded snapshot — coverage can only
    grow, and the curated list stays a stable prefix (typosquat tie-breaking is
    order-dependent). Results are cached for 24h at
    $NPM_PRE_SCAN_CACHE_DIR > $XDG_CACHE_HOME > ~/.cache, under npm-pre-scan/,
    in the same one-per-line format (human-inspectable/editable).
    Failure ladder: fresh cache → silent reuse (no network); fetch failure or a
    rejected sweep (<200 names over the floor) → stale cache, else embedded lists,
    with one `note:` line on stderr. A refresh problem never changes a verdict.
    Enable per-run with --refresh-top or persistently with NPM_PRE_SCAN_REFRESH_TOP=1.
    Default OFF: scans stay reproducible and `cargo test` stays network-free.
    Known limit: seed-page coverage is fuzzy (a top package can miss the sweep) —
    harmless, since the embedded snapshot is always the floor.


-------------------------------------------------------------------------------
 TESTING
-------------------------------------------------------------------------------
    cargo test                                     # offline suite (no network, no Docker)
    cargo test --no-fail-fast -- --ignored         # live Docker tests (requires Docker)

Test counts (current):
    357 offline tests — unit (Levenshtein, namespace, scoring, aggregation, Layer 1
        static checks incl. atob/Function-ctor/computed-load/capability-notes, Layer 2/3
        diff+classify incl. file-write/mass-deletion/ip-literal, homoglyph fold, FP-controls,
        toplist parse/rank/merge/cache incl. a recorded search-API fixture, …),
        Layer 0/1 dummy integration, Layer 2 fixture classify, Layer 3 diff,
        plus the evaluation harness: manifest parsing (eval_corpus), metric arithmetic
        (eval_metrics — confusion matrices, ARTIFACT_FN exclusion, sole-detector
        attribution, null-vs-zero rates), output writers (eval_writers — CSV column
        alignment, JSONL round-trip), and the offline Layer 0 scan path
        (eval_offline_l0, which pins the known A1 suffix gap as documented behaviour).
    20  live Docker tests (#[ignore]d, require Docker):
        8 layer2_dynamic (B1/C1/C2/C3/E1 + B4 wiper + B4 persistence + C1 ip-egress),
        4 layer3_dynamic (D1/D2/D3 + benign control),
        2 full_pipeline (timebomb + benign), 1 full_registry (registry-name smoke),
        5 eval_batch_docker (batch driver end-to-end, memoized-build coverage,
          metrics.json round-trip, skipped-entry handling, one real DataDog sample).

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

  ⚠ dummy_timebomb EXPIRES 2026-09-01. After that its payload fires at baseline too,
    the D1 diff goes empty, and D1 detection silently drops to zero — taking
    d1_timebomb_live_run and dummy_timebomb_full_pipeline_flags_risk with it. D1 is
    the flagship of the project's stated core contribution, so this is a dated item
    at the top of CLAUDE.md's Task Checklist. Preferred fix: pin the harness clock
    rather than re-date the fixture, so it cannot recur.

  Two further caveats found by running the dummies through the batch harness:
    dummy_persistence is mis-attributed to D2 — its .bashrc write is unconditional
    at import, so the Layer 3 env scenario claims credit for behaviour it did not
    trigger. dummy_slow_exfil takes 467 s (24× the arm C median) from 35 sequential
    sinkholed DNS lookups.


-------------------------------------------------------------------------------
 EVALUATION  (v17 — measured against packages the tool did not ship with)
-------------------------------------------------------------------------------
The dummy table above verifies that each layer WORKS. It cannot measure precision:
every fixture was authored by this project. `--eval` closes that gap. Full corpus
and safety notes in eval/README.md; results and a ranked fix list in eval/REPORT.md.

    Arm  Corpus                                        n        Layers  Result
    ---  --------------------------------------------  -------  ------  --------------------
    A    OSV MAL-* names + parents (offline)           216,888  L0      flag rate 1.6%, FPR 7.4%
    B    curated real names + parents (registry)            65  L0 /    25.7% recall / 6.7% FPR *
                                                                L0+L1   (L0 only on the malicious
                                                                        half — see footnote)
    C    the project's own dummy packages                   19  L0-L3   16/16 packages, 15/16 vectors †
    D    real malicious payloads, static (DataDog)         499  L1      88.8% recall
    E    real malicious payloads, all layers                40  L1-L3   95.0% recall
    F    legitimate packages through L2/L3                  27  L0-L3   FPR 96.3% (26/27) — headline

    * mechanism-attributed. As shipped arm B reports 91.4% recall at 93.3% FPR (28 of
      30 benign-labelled entries — the 27 parents plus three reclaimed names carried in
      real_malicious_holders.tsv), but 23 of its 32 "true positives" come solely from
      the `signatures` check firing on npm's own takedown stub rather than from any name
      detection. Arm B ran Layer 1 on the 27 benign parents ONLY; all 38 malicious
      holder entries were Layer 0 only (metrics.json by_layer[1]: ran 27, skipped 38),
      so the 91.4% is a Layer 0 figure — consistent with by_layer[0].sole_detector = 32.

    † package-level recall is 16/16, but the B3 rule itself detected nothing (by_vector
      B3: expected 1, detected 0). That package was caught by B2, so the verdict is a
      true positive while the vector is a miss; B3 has no path through the harness,
      which needs a paired prev/latest manifest kind. Only 9 of the 16 reach BLOCK
      (overall_block_only.recall = 0.5625).

  ── v19 FIX PASS (2026-08-10) — items 4,10 done; 7,8,9 open ──
  All six arms re-run against eval/baseline/v18/; snapshot in eval/baseline/v19/.

      arm   recall v18 -> v19      any-finding FPR      BLOCK-level FPR
      ---   ------------------     -----------------    ---------------
      A         1.3% ->  1.3%       3.7% ->  3.7%        3.7%
      B        85.7% -> 85.7%      66.7% -> 46.7%        0.0%
      C     16/16 pkgs, unchanged    0.0% ->  0.0%        0.0%
      D        88.8% -> 87.6%        (no benign control)  floor 86.8% HELD
      E        97.5% -> 97.5%        (no benign control)  floor 95.5% HELD
      F              —              70.4% -> 48.1%        0.0%

  ✅ Four non-discriminating rules became CAPABILITIES (INFO alone, escalate at >=3):
     process.env (36.3% malicious vs 44.4% benign — INVERTED), dynamic_require (7.6%
     vs 14.8% — INVERTED), long-base64 (lift 1.16), and maintainer/A3 (zero true
     positives across every arm ever run).
  ✅ install_script now reads the hook NAME and its COMMAND, not just key presence.
     preinstall appears 169x in malware and 0x in the 27 legitimate packages; an
     exec/exfil command shape appears in 79 malicious packages and 0 benign ones.
     Arm D BLOCK-level recall rose 21.6% -> 35.1%.
  ✅ Zero recall lost on arm E: the one package the demotions cost (naniod, a real
     nanoid typosquat) turned out to expose a rule GAP — it calls
     require('os').homedir(), which the bare os.homedir() pattern missed. os.homedir
     is 14.4% malicious vs 0.0% benign, so widening it was free.

  ── v18 FIX PASS (2026-08-04) — items 0,1,2,3,5,6 done; 4,7,8,9,10 open ──
  Arms A, B, C, F re-run against eval/baseline/v17/; new snapshot in eval/baseline/v18/.
  D and E not re-run (Layer-1-on-malware; unaffected except via item 3).

      arm   any-finding FP    BLOCK-level FP     recall            FPR
      ---   --------------    --------------     ------            ---------------
      A          2 -> 1            2 -> 1        1.6% -> 1.3%      7.4% -> 3.7%
      B         28 -> 20          14 -> 0       91.4% -> 85.7%    93.3% -> 66.7%
      C          0 -> 0            0 -> 0       16/16 pkgs (=)     0.0% -> 0.0%
      F         26 -> 19          12 -> 0        —                96.3% -> 70.4%

  ✅ ZERO BLOCK-level false positives. No legitimate package is BLOCK'd, and arm F
     produced no BLOCK-severity finding of any check at all (BLOCK-only FPR 44.4% ->
     0.0%, true negatives 1 -> 8). The v17 target was 12/27 -> 4/27; the expected
     residue {fabric, node-sass, sqlite, babel-cli} cleared too.
  ✅ signatures no longer props up recall. All 45 signature findings are INFO, and all
     18 of arm B's true positives now come from A1 name detection — where in v17, 23 of
     32 came from signatures firing on npm's own takedown stubs.
  ✅ Honest name-detection recall went UP: 25.7% -> 85.7%. The fix was predicted to drop
     arm B to ~25.7%; item 5 raised real detection at the same time (nine suffix squats
     plus ffmepg now caught by name), so the number that fell was the artefact.
  ✅ ARTIFACT_FN went 0 -> 14. The safeguard v17 could never exercise now works: a clean
     verdict on a defanged takedown stub is kept out of recall's denominator.
  ✅ ansi-styles@6.2.2, the real Sept-2025 crypto clipper, went PASS -> BLOCK.
  ✅ dummy_timebomb's 2026-09-01 expiry neutralised by pinning the Layer 3 clock at both
     ends, so D1 detection no longer depends on the real date.

  ⚠ OPEN AT v18 (addressed in v19, see above): arm F's any-finding FPR was 70.4%,
    all of it SUSPECT-level static-heuristic noise. Arms D and E were not re-run in
    v18; v19 ran both, and arm E's v18 baseline turned out to be 97.5% — item 3's
    hex-identifier rule caught ansi-styles@6.2.2, taking arm E's FN count from 2 to 1.

  ⚠ WHAT v17 FOUND — the measurement that drove the above. Numbers below are the v17
    state; see the v18 block above for what they are now.
  The layers detect well; the scoring on top of them did not. On 27 legitimate popular
  packages the v17 configuration accused 26, with 12 hard BLOCKs (only chalk came
  through clean) — as shipped it
  would have refused to install lodash, react, express, jquery, d3, ms and mysql. Two
  single-check causes dominated, and BOTH are now fixed:

    1. signatures.rs is a time bomb. npm rotated its registry signing key and the old
       one expired 2025-01-29; every package not republished since is BLOCK'd with
       "no valid/unexpired signing key". This gets worse over time.
       Demoting this ONE check to INFO takes BLOCK-level false positives from 12/27
       (44.4%) to 4/27 (14.8%): eight packages — d3, escape-string-regexp, ffmpeg,
       grunt-cli, http-proxy, ms, mysql, shadowsocks — are BLOCK'd by `signatures`
       and nothing else, and clear with no other change. The residue is fabric,
       node-sass, sqlite and babel-cli.
    2. The static heuristics were tuned without a benign corpus. worm_signature —
       the headline E1 differentiator — BLOCKs `fabric` and `node-sass` for containing
       the string "npm publish" in a legitimate release script.

  ✅ BLOCK severity had no discriminative power — FIXED. v17 measured legitimate
    packages reaching BLOCK at 44.4% (12/27, arm F) versus real malicious ones at 37.5%
    (187/499, arm D): the BLOCK rate was HIGHER on legitimate packages than on real
    malware, so the tool's strongest signal carried negative information.
    Quote both sides from the same version: v18 was 0.0% vs 21.6% (the worm-category
    demotion lowered the malware side too), v19 is 0.0% vs 35.1%. The score-saturation
    half of that finding (below) is untouched.

  Also: ansi-styles@6.2.2 (the real Sept-2025 crypto clipper) passes all four layers,
  because the v14 hex threshold (4 → 8 consecutive \xNN) does not see the
  javascript-obfuscator family used in the real attacks — 5,662 `0x` literals and 314
  `_0x` identifiers, but zero \xNN runs, eval, atob, Buffer.from or process.env.

  Dynamic-layer cost and coverage (arm F). Of the 27 legitimate packages, 11 declare
  zero dependencies, but only 10 completed a valid dynamic run: chalk,
  escape-string-regexp, fabric, jquery, lodash, ms, nodemailer, react, semver, sqlite.
  Layer 2 produced ZERO false positives across those 10 — the first real validation of
  the v13 baseline-subtraction work. Note that fabric is BLOCK'd by Layer 1
  (worm_signature) yet passes L2 and L3 cleanly. The other 16 declare dependencies the
  --offline / --network=none sandbox cannot install, so their empty behaviour profiles
  are vacuous rather than clean and are excluded from the dynamic denominators.

  ⚠ KNOWN LIMITATION — the dynamic timeout can be exhausted with no finding and no
    recorded cause. shadowsocks, a dependency-free LEGITIMATE package, hit the
    --docker-timeout 600 wall in BOTH dynamic layers (l2_status=error 605074 ms,
    l3_status=error 605070 ms) and produced nothing. It alone is 84% of arm F's
    24.0-minute wall clock; without it the arm takes 3.8 minutes. This is a different
    cost risk from dummy_slow_exfil's 467 s, which is deliberate sinkholed DNS doing
    what it was built to do — here there is no diagnosis at all.

  On the positive side: Layer 1 alone catches 88.8% of 499 real malicious packages, and
  E1 is validated against real malware — the single real-world IOC hash in
  data/worm_iocs.txt matched the actual Shai-Hulud patient-zero sample
  (@ctrl/tinycolor@4.1.1), with all three worm categories firing.

  No detection logic was changed in v17 — it was a measurement pass. The fixes for the
  above landed in v18; see the v18 block at the top of this section for what moved.


-------------------------------------------------------------------------------
 PROJECT LAYOUT
-------------------------------------------------------------------------------
    src/
      main.rs              CLI, report formatting, --verbose, exit codes
      lib.rs               module declarations + public re-exports
      docker.rs            docker_available/docker_version, SYS_PTRACE preflight probe,
                           ensure_layer_image() (one build per process, OnceLock-memoized),
                           timeout_argv/run_docker (wall-clock cap + container cleanup)
      checker.rs           run_layer0() — orchestrates Layer 0 checks;
                           run_layer0_name_only() — name checks only, zero network
      registry.rs          npm registry + downloads API; signing keys;
                           FetchStatus/fetch_package_info (404 vs transient failure)
      typosquat.rs         levenshtein() + homoglyph fold + check_typosquat()
      age_check.rs         package age + download-spike detection
      maintainer.rs        first-vs-latest maintainer-set comparison
      signatures.rs        ECDSA-P256 registry signature verification
      namespace.rs         unscoped-vs-scoped namespace-conflict detection
      combosquat.rs        popular-token + suspicious-affix heuristic (A4)
      runtime_lists.rs     additive runtime extension of embedded IOC/egress lists (env-file loader)
      toplist.rs           --refresh-top: live top-package sweep + 24h cache + union merge
      models.rs            Verdict enum, Finding, CheckResult, scoring
      report.rs            RiskReport, aggregate(), run_full_local/registry(), LayerStatus,
                           FullScan/LayerMask + run_full_*_collect() (per-layer results +
                           timings retained; version-pinned scanning)
      eval/                evaluation harness (--eval); see eval/README.md
        corpus.rs          ground-truth TSV manifest parsing (pure)
        record.rs          EvalRecord/LayerRecord + JSONL and CSV writers (pure)
        metrics.rs         confusion matrices, per-layer/vector rollups, timing (pure)
        runner.rs          batch driver: scan each entry, stream results, flush per entry
        samples.rs         DataDog sample fetch + encrypted-zip extraction (see SAFETY)
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
                           + recorded search-API page (toplist)
    dummy_packages/        per-vector test packages (gitignored; never published)


-------------------------------------------------------------------------------
 REFERENCES
-------------------------------------------------------------------------------
    Ladisa et al., "SoK: Taxonomy of Attacks on OSS Supply Chains",
      IEEE S&P 2023 — classification base (107 vectors; npm-consumer scope defined here)
    Zheng et al., "OSCAR", ASE 2024 — comparison target; basis for Layer 3 gap
    Duan et al., "MalOSS", NDSS 2021 — comparison target
    Huang et al., "DONAPI", USENIX Security 2024 — comparison target
    OSSF malicious-packages / OSV MAL-* feed — evaluation corpus for Layer 0 name
      checks at scale (216,861 names; see eval/README.md)
    DataDog/malicious-software-packages-dataset (Apache-2.0) — real malicious payloads
      for Layers 1-3, since npm's takedown process defangs them (see eval/README.md)
    npm registry signatures: docs.npmjs.com/about-registry-signatures
