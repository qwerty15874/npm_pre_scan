# CLAUDE.md
> Last updated: 2026-09-18 (v22)

---

## Progress

```
Pipeline: package name → Layer 0 → Layer 1 → Layer 2 → Layer 3 → risk score

Layer 0  [████████████████████] DONE   Metadata check        (no execution, Rust)
Layer 1  [████████████████████] DONE   Static analysis       (no execution, Rust)
Layer 2  [████████████████████] DONE   Dynamic — baseline-subtraction diff, live Docker verified
Layer 3  [████████████████████] DONE   Dynamic — condition mutation, live Docker verified
Scoring  [████████████████████] DONE   Aggregate risk score (noisy-OR, --full pipeline)
Eval     [████████████████████] DONE   --eval harness; 8 arms (v22 added the arm-D benign controls)
Precision[███████████████████░] PART   v21: BLOCK 0/27, any-finding FPR 29.6% → 25.9%.
Coverage [███████████████████░] PART   v21: L2 reach 10→26 of 27; arm C 14/14 vectors (B3 closed).
F1 & prec[███████████████████░] PART   v22: FIRST F1 0.8455 any / 0.7711 BLOCK (matched arm G).
```

> ✅ **v22 — arm D finally has a benign control, and the project has its first precision and F1.**
> Every prior section called this the single most valuable missing measurement. Two controls were
> built, because the 499-sample corpus holds two populations:
> **arm G (matched)** — 100 compromised libraries vs **83 of their own clean predecessors** (the
> version published just before each compromise) — **F1 0.8455** any-finding (recall 93.0%,
> precision 77.5%) and **0.7711** BLOCK-only (recall 64.0%, precision **96.97%**, FPR **2.41%**);
> **arm H (broad)** — 399 purpose-built fakes vs 500 top-downloads packages — F1 0.7881 any-finding.
>
> ⚠ **Arm G's any-finding FPR is 32.5% — HIGHER than arm F's 25.9%.** A matched control (real
> libraries of the same shape) is harder than popular packages, which is precisely the optimism a
> popular-package control hides. `obfuscation` is 24 of the 27 false positives, confirming v20's
> item 11 on 83 matched libraries instead of 27 hand-picked parents.
>
> ⚠ **Arm H is biased in the tool's favour and its precision is bounded, not exact.** The
> establishment guard fires on 19 benign records and cannot fire on the malicious half (no registry
> document), so FPR 26.2% → worst case **30.0%**, precision 72.6% → **69.8%**. Arm G is clean on
> this axis — the guard fires on **zero** of its records, which was checked before quoting it.
>
> **Below OSCAR's F1 0.95, and said plainly.** Never merge arms G and H.

> ✅ **v21 coverage pass — items 7, 8 and 9 closed; the dynamic layers roughly doubled their reach.**
> Layer 2 now runs on **26 of 27** legitimate packages (was 10) and Layer 3 on 25, with `dyn_valid`
> 12 → **24**, because dependencies are resolved on the host and mounted read-only at `/vendor`.
> Arm F's any-finding FPR fell **29.6% → 25.9%** while that happened, BLOCK-level FPR stayed
> **0.0%**, and every floor held — arm D **87.58%**, arm E **97.50%**, arm C **16/16 packages** and
> now **14/14 vectors**, B3 having produced the first true positive in the project's history.
>
> ⚠ **Quote the two together.** The pipeline being measured got larger at the same time the number
> fell, so 25.9% is *not* a like-for-like improvement on 29.6%. The expansion also exposed two
> false positives that had always existed and had merely never been looked for: `ffmpeg` (D3, fixed
> by the same relatedness gate as `nodemailer`) and `bcrypt` (C3 `native_addon` — **C3's first
> measured false positive**).
>
> ⚠ **The IOC extension adds ZERO recall.** `data/worm_iocs.txt` went from 1 hash to the full
> 7-variant Shai-Hulud fingerprint; 44 packages now match by hash instead of 25, **0 as sole
> detector**, arm D recall bit-identical. It is identity-level confirmation, not detection, and must
> never be cited as if it improved recall.
>
> **Method note that changed a conclusion:** the before-side was re-measured at HEAD
> (`eval/baseline/v21base/`) rather than reusing `eval/baseline/v20/`. Between the two, with no code
> change, arm B's FPR drifted 30.0% → 26.7% because `nodemailer` was republished. Arms B and F hit
> the live registry; always re-measure before quoting a delta.

> ✅ **v18 fix pass — BLOCK is now trustworthy; SUSPECT is not yet.** Queue items 0, 1, 2, 3, 5, 6
> are implemented and measured. **No legitimate package is BLOCK'd any more**: arm F went from 12 of
> 27 hard-BLOCK'd to **zero**, with no BLOCK-severity finding of any check on the benign corpus
> (BLOCK-only FPR 44.4% → **0.0%**). Arm B's BLOCK-level FPs went 14 → 0.
>
> ✅ **v19 nearly halved the remaining noise at no recall cost.** Arm F's *any-finding* FPR went to
> **48.1%** (13 of 27; 14 packages completely clean, was 8), arm B **46.7%**, with BLOCK-level FPR
> still **0.0%** and both recall floors held — arm D 87.6%, arm E **97.5% with zero packages lost**.
> Four rules measured as non-discriminating (two of them *inverted*) became **capabilities**: INFO
> alone, escalating only when ≥3 co-occur (that escalation was REFUTED and removed in v20).
>
> ✅ **v20 cut it again and overturned one of v19's own decisions.** Arm F any-finding FPR
> **48.1% → 29.6%** (13 → 8 accused; **19 of 27 completely clean**, was 14), arm B **46.7% → 30.0%**,
> with BLOCK-level FPR still **0.0%** and every recall figure *bit-identical* — arm D **437/499
> (87.6%)**, arm E **39/40 (97.5%)**, arm C 16/16. v19's ≥3-capability escalation measured at **lift
> 0.11** (2.0% of malware vs 18.5% of legitimate packages) and was the sole accusing detector on
> **zero of 539** malicious samples, so the conjunction rule was **removed as refuted** while the
> capability tier stays. Also: a sole uncorroborated network import on an established package became
> a capability, and unreachable build/release tooling is exempt from the worm heuristic.
> Baselines: `eval/baseline/v17|v18|v19|v20/`.
>
> ⚠ **Still open, and now provably calibration's ceiling.** The remaining 8 genuinely *have* the
> capability — `node-sass` runs a postinstall, `jquery` ships an `eval`. **A third demotion is not
> available**: solitude-gating the two residual `obfuscation` sub-rules takes arm D to **85.6%**,
> below the 86.8% floor, and arm D has no registry path for an establishment gate to rescue it.
> Telling "has" from "abuses" needs dynamic corroboration, and Layer 2/3 reaches only 11/27
> legitimate and 28/40 malicious packages. **That is a coverage problem** — items 7, 7b, 8.
> Full before/after: **`eval/REPORT.md`**, section "v20 — precision pass 2".
>
> **The BLOCK-severity inversion is fixed.** v17 measured BLOCK firing on legitimate packages
> (44.4%) *more often* than on real malware (37.5%, arm D) — the severity ladder carried negative
> information. That inversion is gone. **Quote both sides from the same version**: v18 was 0.0%
> (legit) vs 21.6% (malware — the worm demotion lowered it from v17's 37.5%); v19 is 0.0% vs
> **35.1%**, the install-hook exec-shape rule having recovered the malware side without touching
> the legit side. The score-saturation half of that finding is untouched and is still item 10's.
>
> **Recall did not collapse, and the reason matters.** Fixing `signatures` was expected to drop arm
> B from 91.4% to ~25.7%. It landed at **85.7%**, because item 5 fixed real name detection at the
> same time: all 18 true positives now come from **A1**, where in v17 23 of 32 came from
> `signatures` firing on npm's own takedown stubs. The honest comparison is **25.7% → 85.7%**.

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

> **The coverage matrix lives in `README.md`, section `ATTACK-VECTOR COVERAGE`.** It is the single
> source of truth for per-vector implementation status and measured evidence; this file used to
> carry a second copy, and the two drifted apart until the numbers disagreed. Do not reintroduce a
> copy here — add to the README table and, if an agent needs the fact, point at it.
>
> **Reading the measured columns (this trips people up).** `fires` is a **cross-arm total**.
> `FP` is **distinct legitimate packages out of the 27 in `eval/corpus/parent_benign.tsv`, from
> arm F only** — arm F is the only arm that ran all four layers over the benign corpus.
> `metrics.json`'s `by_vector[].false_hits` is a distinct-package count *within one arm*, so
> **summing it across arms is meaningless**: `parent_benign.tsv` was scanned in arms A, B and F, and
> summing double- or triple-counts the same packages. That mistake is exactly how this file's old
> copy came to claim 36 B2 false positives when the real figure is 18.

> A4 and B3 promoted from candidates to DONE (implemented and verified via integration tests).
> E1 Layer 1 static detection done (worm_signature.rs); Layer 2 dynamic worm-egress live-verified (BLOCK); Layer 3 deferred.
> D1/D2/D3 promoted to DONE (Layer 3 condition mutation, live Docker verified 2026-07-01).
> **All in-scope detection vectors (A1–E1) are DONE and verified.**
> v14: added **B4** (destructive/persistence + wiper, Layer 2/3) plus IP-literal egress, Layer 1 static broadening (atob/Function-ctor/computed-import/expanded shell-exfil/worker_threads/.wasm), and runtime-extensible IOC/egress lists — deepening detection beyond the original A1–E1 set.
> **v17: coverage confirmed, precision measured and found wanting.** Three checks (A3, B3, and
> `signatures`) fired mainly or exclusively on legitimate packages across six arms. Coverage was
> the v5 hard requirement and it is met; the v17 result is that *coverage without a measured
> false-positive rate was never sufficient*, and the fix queue is in the Task Checklist.

---

## Change Log

### v22: Arm D benign control — the project's first precision and F1 (2026-09-18)

Closes the measurement every prior section named as the most valuable one missing. Write-up:
`eval/REPORT.md` section "v22". Baselines: `eval/baseline/v22/`.

- **Two controls, because the corpus holds two populations, and they are never merged.**
  The 499 samples split into 100 `compromised_lib` (real libraries with an injected payload) and
  399 `malicious_intent` (published to be malicious, no legitimate twin).
- **Arm G — matched.** For each compromised library, the version published immediately *before* the
  compromise, pulled from the live registry: same package, same author, same style, differing only
  by the payload. 94 of 100 had a recoverable predecessor → **83 distinct `package@version`** rows
  (several packages were compromised across two consecutive versions). Result: **F1 0.8455**
  any-finding (TP 93 / FP 27 / FN 7 / TN 56; recall 93.0%, precision 77.5%) and **F1 0.7711**
  BLOCK-only (TP 64 / FP 2; recall 64.0%, precision **96.97%**, FPR **2.41%**).
- **Arm H — broad.** 399 fakes vs 500 top-downloads names. F1 0.7881 any-finding (recall 86.2%,
  precision 72.6%), 0.4245 BLOCK-only.
- **New corpus group `benign_control`** so these can never blend into `parent_benign`'s rollups,
  plus four manifests: `datadog_compromised`, `datadog_clean`, `datadog_intent`, `top_benign`.
  A test asserts the compromised/intent split partitions `datadog_static.tsv` exactly, and another
  asserts every control row is benign, expects no vector, and is scored at layer 1 only.

⚠ **Three things to carry forward, all uncomfortable:**
1. **Arm G's any-finding FPR is 32.5%, higher than arm F's 25.9%.** A matched control is harder
   than popular packages — the optimism a popular-package control hides, now quantified.
   `obfuscation` is 24 of the 27 FPs, confirming v20's item 11 on 83 matched libraries.
2. **Arm H's precision is a range, not a point.** The establishment guard fires on 19 benign
   records and cannot fire on the malicious half (no registry document): FPR 26.2% → worst case
   **30.0%**, precision 72.6% → **69.8%**. Arm G is clean — the guard fires on **zero** of its
   records, verified before the figure was quoted.
3. **Below OSCAR's F1 0.95.** Stated plainly, not framed away.

### v21: Coverage pass — items 7, 8, 9; L2 reach 10→26 of 27, arm F FPR 29.6% → 25.9% (2026-09-15)

Closes everything v20 left open. Full write-up: `eval/REPORT.md`, section "v21". Baselines:
`eval/baseline/v21/`, with the drift-free before-side in `eval/baseline/v21base/`.

- **Item 7 — D3's premise.** Implemented the literal §7b fix first and **measured it as wrong**:
  `dummy_api_triggered` trips none of Layer 2's four "stronger sub-signals", so requiring one would
  have deleted the project's own D3 detection (arm C 16/16 → 15/16). Used *relatedness* instead —
  a D3 accusation is demoted to a capability when every observed side effect points back at the
  package itself: its own API host (`nodemailer` → `api.nodemailer.com`) or its own binary
  (`ffmpeg` → `/usr/bin/ffmpeg`). Narrow on four axes: bare `import_side_effect` only, SUSPECT only,
  *every* observation must match, and never with a durable write/delete.
  Required preserving `l2_check` — `classify_scenario` overwrote `check` with the scenario name, so
  a credential read reaching D3 was indistinguishable from a bare side effect.
- **Item 8a — the timeout was never detected.** `code() == Some(124)` could not match, because
  `timeout -k` re-raises SIGKILL on itself. The diagnosis was lost **and** the `docker rm -f`
  orphan-container cleanup lived in the same branch, so it never ran on the path that occurs. Two
  orphaned containers from a dead PID were found running during this pass. `Outcome::Timeout` — 
  declared, counted, classified and never once constructed — now has a construction site, but is
  raised **only when the timeout left nothing observed**: promoting it unconditionally would have
  dropped `shadowsocks` from arm F's benign denominator and improved the FPR by losing a false
  positive to a Docker stall.
- **Item 8b — `--package-timeout`** bounds both dynamic layers together (`shadowsocks` 1210 s →
  905 s). The remaining-seconds clamp is load-bearing: `timeout 0` means *no* timeout in coreutils.
  `dyn_valid` now also requires that no dynamic layer was killed.
- **Item 8c — vendoring.** Dependencies resolved on the host with `npm install --ignore-scripts`,
  mounted read-only at `/vendor`, copied into the work tree at every rebuild so Layer 2's
  baseline/real install symmetry stays byte-identical. Layer 1 must never see `node_modules`
  (`js_files` has no exclusion), hence the separate mount. **Safety posture changed and
  `eval/README.md` corrected**: the host now resolves dependency trees declared by malicious
  samples — never their own code, never executing anything.
- **Item 9(a) — IOCs 1 → 7 variants**, the closed Shai-Hulud fingerprint across 48 compromised
  package-versions. **Measured separately and found to add zero recall** (44 matched vs 25, 0 sole
  detector, arm D bit-identical).
- **Item 9(b) — `Kind::Pair`** gives B3 its first path: 0/1 → **1/1**, arm C 13/14 → **14/14**
  vectors. `run_version_diff_local` had had zero production call sites.
- **Item 9(c) — D2 mis-attribution root-caused** to the env scenario's `HOME` mutation; fixed in
  `normalize_path`. Arm E's D2 noise fell 7 → 2 fires.
- **Item 9(d) — NOT fixed, and cannot be by a rule change.** `node-ipc`'s wiper is geo-gated and
  never executes under `--network=none`.

⚠ **The coverage expansion exposed two previously-hidden false positives** — `ffmpeg` (D3) and
`bcrypt` (C3, **C3's first**). 25.9% is therefore not a like-for-like improvement on 29.6%: the
pipeline being measured got larger at the same time the number fell.

### v20: Precision pass 2 — arm F FPR 48.1% → 29.6%, recall bit-identical (2026-09-07)
Scope: user asked for three precision fixes from `eval/REPORT.md`. **All three were already
implemented** (v18/v19) — see the note at the end of this entry, it matters for reading the request.
The user then chose to do the one genuinely-missing sub-clause **plus** a fresh recalibration of what
arm F actually still fires. Fix-queue items **4 (continued)** and **9 (partial)**, plus the
unimplemented half of item 2. Offline **422 passed** (was 407); arms B, C, D, E, F re-run; baselines
in `eval/baseline/v20/`. Full write-up: `eval/REPORT.md`, section "v20 — precision pass 2".

- **THE HEADLINE: false positives cut again with ZERO recall cost.** Arm F any-finding FPR
  **48.1% → 29.6%** (13 → 8 accused, clean packages 14 → **19**), arm B **46.7% → 30.0%** (FP 14 → 9,
  TN 16 → 21), while BLOCK-level FPR stayed **0.0%** everywhere and every recall figure came back
  *bit-identical*: arm D **437/499 (87.6%)**, arm E **39/40 (97.5%)**, arm C 16/16. Cleared exactly
  `axios`, `fabric`, `http-proxy`, `mongoose`, `proxy`, with **zero newly accused**.
- **v19's own escalation was the largest remaining false-positive source, and it is refuted.**
  Re-running v19's lift method (arm D 499 malicious vs arm F 27 legitimate):
  | rule | malicious | benign | lift | sole accuser |
  |---|---|---|---|---|
  | `capability_cluster` | 10/499 (2.0%) | 5/27 (**18.5%**) | **0.11** | **0 of 539 malicious**, 1 benign |
  | `network_imports` | 174/499 (34.9%) | 4/27 (14.8%) | 2.35 | 13 malicious, 3 benign |
  `capability_cluster` is inverted ninefold — far past v19's own lift<1.2 demotion bar — and across
  five arms was the sole accusing detector on exactly one package, `mongoose`, which is legitimate.
  **It also has no operating point at all**: capability counts are bounded at 3 in *both* corpora
  (benign `{0:13,1:7,2:2,3:5}`, malicious `{0:289,1:153,2:47,3:10}`), so the threshold is inverted at
  3 and unreachable dead code at 4. The capability *tier* stays; the **conjunction rule is removed**.
  **Do not reintroduce it.**
- **Removed, not demoted to INFO — and the reason is not stylistic.** v19 justified emitting a real
  finding (rather than only bumping the verdict) so `by_vector`/`sole_detector` stay consistent with
  `classification`. That justification holds *only while the finding accuses*: `is_accusing` ignores
  INFO, so a demotion sends arm B's META to 0 fires exactly as removal does. **(a) pays the full cost
  of (b) and keeps ~75 lines plus 6 tests.** It would also leave a feedback loop armed — a package
  demoted for solitude gains a capability id and could trip the cluster, re-accusing it via META.
- **`network_imports`: demote only when SOLE *and* established.** Wholesale demotion would be wrong
  (lift 2.35, comparable to `shell_exfil`'s 4.3 which v19 deliberately kept). **Solitude alone breaks
  both floors** — applied everywhere it costs arm D 19 records (437 → 418, 83.8%) and arm E one
  (39 → 38, 95.0%). The establishment gate confines it to the registry path, and the three-state
  `Option<bool>` is load-bearing: `None` means "never asked" and never demotes. *Absence of evidence
  of establishment is not evidence of establishment.*
- **Why that is safe for a COMPROMISED ESTABLISHED package — the dangerous class.** `version_diff` is
  a built-in veto: it emits SUSPECT for a **newly introduced** network import and runs on exactly the
  path where the guard is active, so the guard only ever suppresses an import that is **not new**. A
  compromise that *adds* network I/O breaks solitude and the guard stands down. `ansi-styles@6.2.2`
  (the real Sept-2025 clipper) confirms it twice: its only finding is an `obfuscation` BLOCK (314
  distinct `_0x…`), and `network_imports` never fires on it at all. Pinned by
  `a_newly_introduced_network_import_keeps_its_severity` — a future change to `version_diff` must
  fail there, not in an arm run.
- **⚠ THE REQUEST'S WORDING, IMPLEMENTED LITERALLY, BREAKS THE ARM D FLOOR.** Item 2's second half
  said exclude build tooling "unless reached from an **install hook**". 13 malicious packages ship
  exactly `package.json` plus a root `publishScript.js`, declare it as **`main`**, and have **no
  install hook at all**; their whole Layer 1 output is one `self_propagation` finding on that file.
  Hooks-only loses all 13: arm D 87.58% → **84.97%** against an 86.8% floor. Reachability therefore
  spans **install hooks ∪ `main` ∪ `bin` ∪ `exports`** — which is also the precise definition of
  build tooling: *code that ships in the tarball but is not what a consumer executes.* Measured loss
  on that basis: **zero** across arms B/C/D/E. Pinned by
  `root_publish_script_that_is_main_is_still_scanned`, comment carrying the numbers.
- **The IOC hash is checked BEFORE the exclusion.** Most important structural detail of the worm
  change: a hash is identity, not inference, and must never become evadable by choosing a directory
  name. Pinned behaviourally by `ioc_hash_is_not_suppressed_by_the_build_tooling_path_exclusion`.
- **`lib/` is deliberately NOT a tooling pattern**, which bounds what the fix can clear. `node-sass`
  keeps all three worm findings: `lib/extensions.js` is shipped runtime code, and
  `scripts/util/{proxy,rejectUnauthorized}.js` are genuinely *reachable* from
  `"install": "node scripts/install.js"` — verified live. It keeps `install_script` regardless.
- **The worm aggregate now requires categories to CO-OCCUR IN ONE FILE.** The count accumulated
  package-wide, so a `semantic-release`-shaped repo with `npm publish` in one script and
  `GITHUB_TOKEN` in another was a **BLOCK on wholly legitimate code**. It had not fired on the
  27-package corpus but nothing prevented it, and BLOCK-level FPR 0.0% is the headline v18/v19 claim.
  Measured cost **zero**: all 77 real `worm` aggregates across arms C/D/E already have ≥2 categories
  in a single file; **none** relies on cross-file accumulation.
- **The default CLI was bypassing every post-pass.** `main.rs` called `aggregate` directly, so
  `npm-pre-scan axios` would have kept reporting a false positive that `--full axios` no longer
  reports. `capability_cluster` had the identical asymmetry and it went unnoticed for a release.
  Now routed through `finish_scan`'s post-passes via `report::aggregate_name_scan`, which returns the
  layer results because the CLI prints them per layer and a demotion must be visible there too.
  `mark_skipped(1)` semantics (pinned by `tests/full_pipeline.rs`) preserved.
- **Bug found by running the tool, not by reasoning — a trap for the next agent.** Entry points
  disagree on what `dir` is: `run_layer1` passes the tarball **extraction root**, which still contains
  npm's `package/` wrapper, while `run_full_registry_collect` passes `…/package`. Paths read
  `package/publish-next.js`, matched no pattern, resolved no seed, and **the whole exclusion silently
  did nothing** while every test passed (unit fixtures put files at the tempdir root). Fixed inside
  the module via `package_root()`. **Recorded but NOT fixed: every Layer 1 finding's `file` field is
  `package/`-prefixed on the default CLI path and unprefixed under `--full`.**
- **Three test pins added, each mutation-verified.** Two guarded a real decision and asserted nothing:
  `obfuscation_long_base64_literal_is_suspect` checked only the *message*, so it passed identically
  before and after v19's INFO demotion while its name and comment both said SUSPECT — the shape that
  gets "restored" by mistake. `ioc_hash_alone_still_blocks` `include_str!`d its **own source file**
  and grepped 400 characters for `"BLOCK"`. Both replaced; demoting the IOC branch now fails two
  tests and re-promoting base64 fails one, and all pass restored.
- **One delta that is registry DRIFT, not this pass.** Arm F/B `B3` false hits went 1 → **2**:
  `nodemailer` was republished between the v19 run (2026-08-10) and this one, restructuring into
  `dist/cjs`+`dist/esm`, which `version_diff` reports as newly introduced `process.env` in new files;
  its `network_imports` finding vanished at the same time. It was an accused FP before and after via
  a different check, so the package count is unaffected. **Arms B and F hit the live registry —
  attribute every delta on a check a pass did not touch before quoting a headline.**
- **Metric movement that is NOT recall movement.** Arm D `E1` fires 174 → 171: three packages
  (`@emilgroup/tenant-sdk`, `@emilgroup/public-api-sdk-node`, `@emilgroup/insurance-sdk-node`) lose
  E1 from `detected_vectors` while staying **TRUE_POSITIVE** via `B1;B2`. Arm D `B2` fires 299 → 299
  confirms the network guard is inert on the local path — the floor mechanism verified in situ.
- **Two limits to state honestly.** (1) **The establishment guard's *discrimination* is unmeasured.**
  It is *safe* in every arm, but structurally: arms D/E have no registry path, and `network_imports`
  fires on **zero** of arm B's 35 malicious entries — the only malicious registry-path corpus. The
  "malicious sole-accusers are fresh spam names" rationale rests on `is_established` requiring age
  ≥365d **and** ≥10 versions, which fresh packages fail. Sound, but not demonstrated. (2) **The
  remaining 29.6% cannot be closed by a third demotion at this floor** — the four residual
  `obfuscation` cases split into bare `eval()` (lift 1.81) and `Function()`-ctor (1.54), and a
  solitude-gated demotion takes arm D to **85.6%**, below 86.8%, with no registry path to rescue it.
  Coverage's problem, not calibration's — items 7, 7b, 8.
- **Refactor: `is_accusing` hoisted to `models`** beside `verdict_from_findings`. Two consumers must
  agree on what an accusation is (the eval harness, and now `finish_scan`); v19 collapsed four copies
  of the verdict rule for exactly this reason. `finish_scan`'s three trailing context `Option`s became
  a `ScanContext` struct — clippy's `too_many_arguments` at 8/7 forced it, and it groups better.
- **⚠ READ THIS BEFORE ACTING ON A REQUEST THAT CITES `eval/REPORT.md` VERSIONS.** The v20 request
  asked for three fixes that were **all already implemented** — signatures expired-key (v18), worm
  single-category BLOCK (v18, though its build-path half was genuinely missing), and hex-identifier
  density (v18). The cause is worth remembering: **`Cargo.toml`'s `version` has been `0.1.0` across
  v17, v18 and v19**, and so is `provenance.tool_version` in every `metrics.json`. The v17/v18/v19
  labels exist ONLY as `eval/baseline/<ver>/` directory names and this changelog. So "the v0.1.0
  REPORT.md" is the *current* one and already contains the later sections. **Verify implementation
  status in the source before planning a fix pass.** Also: the request predicted arm B recall would
  fall 91.4% → ~25.7%; it actually landed at **85.7%**, because v18 fixed real A1 name detection in
  the same pass. The honest comparison is **25.7% → 85.7%**.

### v19: Capability-vs-attack severity model — arm F FPR 70.4% → 48.1% (2026-08-10)
Scope: user asked to make the project "perfect — coverage to all attack surface, increase analysis
speed and high-end accuracy", and chose **accuracy → coverage → speed** with a hard floor: arm D/E
recall must stay within 2 points. This is pass 1 of 3 (accuracy). Fix-queue items **4 and 10**.
Offline **407 passed** (was 395); live Docker 20/20. All six arms re-run; baselines in
`eval/baseline/v19/`. Full write-up: `eval/REPORT.md`, section "v19 — capability model".

- **THE HEADLINE: false positives nearly halved with no recall cost.** Arm F any-finding FPR
  **70.4% → 48.1%** (19 → 13 accused, clean packages 8 → **14**), arm B **66.7% → 46.7%**, while
  BLOCK-level FPR stayed **0.0%** and BOTH recall floors held: arm D 88.8% → **87.6%** (floor 86.8%)
  and arm E 97.5% → **97.5%** — zero packages lost. Arm C unchanged at 16/16, no vector moved.
- **The design came from measurement, not intuition.** Comparing arm D (499 real malicious) against
  arm F (27 legitimate) per check and per sub-rule showed two rules are *inverted* — they fire more
  often on legitimate packages than on malware:
  | rule | malicious | benign | lift |
  |---|---|---|---|
  | `suspicious_strings` on `process.env` | 36.3% | **44.4%** | **0.82** |
  | `dynamic_require` | 7.6% | **14.8%** | **0.51** |
  | `obfuscation` long-base64 | 8.6% | 7.4% | 1.16 |
  | `maintainer` (A3) | — | 11.1% | 0 true positives, ever |
  These four became **capabilities** (INFO alone). `process.env` on its own reached 12 of the 27
  benign packages — the single largest false-positive source in the tool.
- **Capability tier + cross-layer escalation (item 10).** A capability finding carries a
  `capability` key and is INFO; a package with **≥3 distinct capabilities** gets a synthetic
  `capability_cluster` SUSPECT finding. Counting is over **distinct capability ids, not findings** —
  `obfuscation` and `suspicious_strings` emit one finding per file, so counting findings would let
  one capability in three files trip a three-capability threshold and every minified bundle would
  escalate.
  It lives in `report::finish_scan`, which owns the four `CheckResult`s, **not** in `aggregate`,
  which only borrows them and returns a findings-less `RiskReport`. That placement is load-bearing:
  the eval harness reads `classification` from `RiskReport.verdict` but `detected_vectors` /
  `by_vector` / `by_layer.sole_detector` from per-finding severity, so escalating the verdict alone
  would have moved the confusion matrix while leaving every per-vector metric flat. Emitting a real
  finding keeps them consistent — verified: arm B `by_vector` META went 0 → 5 fires.
- **`install_script` rewritten from key-presence to hook-name + command-body (item 4).** It used to
  call `scripts.get(k).is_some()` and throw the command away, so `"postinstall": "node-gyp rebuild"`
  and `"preinstall": "curl … | sh"` were the same finding. Measured across the DataDog corpus and
  the benign parents: `preinstall` appears **169 times in malware and 0 times in the 27 legitimate
  packages**; an exec/exfil command shape appears in **79 malicious packages and 0 benign ones**.
  Now: exec shape → **BLOCK**, `pre`/`postinstall` → SUSPECT, `install`/`prepare` or a recognised
  build step (`node-gyp`, `prebuild-install`, `husky`) → capability. B1 fires on the benign corpus
  went 5 → 1, and arm D's BLOCK-level recall rose **21.6% → 35.1%**.
- **`node <file>` is deliberately NOT an exec shape.** `node-sass` ships
  `"postinstall": "node scripts/build.js"` and most malicious hooks look identical — it separates
  nothing. The hook NAME carries that weight instead.
- **Four duplicate verdict rules collapsed into `models::verdict_from_findings`.** `aggregate_verdict`
  existed in `checker.rs`, `layer1/mod.rs`, and inline in `layer2/mod.rs` and `layer3/mod.rs`, plus a
  fifth dead `report::worst_verdict` with no callers. They agreed, but nothing made them agree, and
  this pass changes severity semantics across several checks at once. Behaviour-preserving; the dead
  one is deleted.
- **A one-package recall loss, found and then fixed at the root.** The capability demotions initially
  cost arm E exactly one package: `naniod`, a real `nanoid` typosquat whose only detectable signal
  was `process.env`. Reading it revealed the actual bug — it calls **`require('os').homedir()`**, and
  the `os.homedir()` pattern only matched the bare form. `os.homedir` is 14.4% malicious vs **0.0%**
  benign, so widening the pattern to the indirect form is free: arm E returned to 97.5% with zero
  benign cost. **Fix the rule, don't restore the noise.**
- **Process failure worth recording: six arms were measured against a stale binary.** The
  `dynamic-require` capability tag was added after the release build used for the first v19 arm runs,
  so `dynamic_require` was demoted to INFO but never counted toward a cluster — the escalation was
  measured with 4 of 5 capabilities. Caught only because arm B's false-positive count moved between
  two runs that should have been identical. **Rebuild `--release` immediately before any arm run, and
  treat an unexplained delta between two supposedly-identical runs as a bug in the harness, not
  registry drift.** All six arms were re-run.
- **Correction to the v18 write-up**: it compared BLOCK rates across versions — v18's legitimate
  figure (0.0%) against v17's malware figure (37.5%). After v18 the malware figure was 21.6%, the
  worm-category demotion having lowered it too. Corrected in place; v19 is 0.0% vs **35.1%**.
- **The ceiling is real and it is coverage's problem, not calibration's.** 48.1% is close to the
  static-only limit at this recall floor. What remains accused are packages that genuinely *have* the
  capability — `axios` imports http, `node-sass` runs a postinstall. Separating "has" from "abuses"
  needs a second evidence source, and Layer 2/3 currently reaches only 11/27 legitimate and 28/40
  malicious packages. That is pass 2.

### v18: First precision fix pass — zero BLOCK-level false positives (2026-08-04)
Scope: user asked to "do next build task", which is the precision fix queue from `eval/REPORT.md`.
Implemented items **0, 1, 2, 3, 5, 6**; items 4, 7, 8, 9, 10 remain open. Offline **395 passed**
(was 357); live Docker **20/20**. Arms A, B, C, F re-run against `eval/baseline/v17/`; new snapshot
at `eval/baseline/v18/`. Full before/after: `eval/REPORT.md`, section "v18 — first fix pass".

- **THE HEADLINE: no legitimate package is BLOCK'd any more.** Arm F went from 12 of 27 hard-BLOCK'd
  to **0**, with no BLOCK-severity finding of ANY check on the benign corpus (BLOCK-only FPR
  44.4% → **0.0%**, true negatives 1 → 8). Arm B's BLOCK-level FPs went 14 → 0. The v17 target was
  4/27; the expected residue `{fabric, node-sass, sqlite, babel-cli}` cleared too.
- **Item 1 — `signatures` expired-key time bomb, fixed.** The key lookup filtered expired keys OUT,
  so a package not republished since npm's 2025-01-29 rotation matched no key, was never verified,
  and fell through to an unconditional BLOCK. It now verifies against the key that ACTUALLY signed:
  verifies+expired → INFO, verification fails → BLOCK, unpublished keyid → SUSPECT. All 45 signature
  findings in arm B are now INFO. **Do not re-add an expiry filter to the lookup.** Pinning tests use
  real ECDSA-P256 material (deterministic RFC6979 signing, no RNG, still network-free).
- **The predicted recall drop did not happen, and the reason matters.** Arm B was expected to fall
  91.4% → ~25.7%. It landed at **85.7%**, because item 5 fixed real detection in the same pass: all
  18 TPs are now caught by **A1 name detection**, where in v17 23 of 32 came from `signatures` firing
  on takedown stubs. The honest comparison is **25.7% → 85.7%**.
- **`ARTIFACT_FN` went 0 → 14 — the safeguard is no longer inert.** With `signatures` no longer
  BLOCK-ing npm's defanged stubs, a clean verdict on a `holder` entry is finally classified
  `ARTIFACT_FN` and kept out of recall's denominator, exactly as designed. v17 documented it as
  untested; it is now exercised. Arm B's denominator is honestly 21, not 35.
- **Item 3 — the javascript-obfuscator recall hole, closed.** New `hex_identifier` rule counts
  DISTINCT `_0x[0-9a-f]{4,}` names per file: ≥25 → BLOCK, ≥5 → SUSPECT. Measured separation is
  total: `ansi-styles@6.2.2` (the real Sept-2025 chalk/debug crypto clipper) carries **314**;
  `jquery`, `lodash`, `d3`, `react`, `chalk`, `debug`, `node-sass` and `fabric` carry **zero between
  them**. That sample went **PASS with zero findings → BLOCK**. Count identifiers, NOT `0x` literals
  — `d3` ships 174 of those legitimately.
- **Item 2 — `worm_signature` one-category BLOCK, fixed.** Each category BLOCK'd independently of
  the documented ≥2-category aggregate, so the aggregate never gated anything. Categories are now
  SUSPECT; only the aggregate or a known-IOC hash BLOCKs. Verified against the real packages:
  `fabric` (1 finding) and `node-sass` (3, all `self_propagation`) drop to SUSPECT; the Shai-Hulud
  fixture keeps BLOCK via two categories plus its IOC.
- **Item 5 — A1 suffix squats + absent parents.** A trailing `.js`/`-js`/`_js` is folded for the
  DISTANCE compare only; a name matching exactly *after* folding is a suffix-squat BLOCK. Added
  `ffmpeg`, `fabric`, `shadowsocks`, `tkinter`, `sqlite` to `data/top_packages.txt` (1137 → 1142).
  Also added the missing name-length guard to the distance-2 branch. Arm A: 98 new suffix-squat
  detections, FPR 7.4% → 3.7%, precision 99.94% → 99.96%, and 608 of the 610 lost detections have a
  bare name ≤4 chars — the coincidental matches the guard exists to remove.
- **Item 6 — established-package guard.** A post-pass in `run_layer0`, after the registry fetch,
  downgrades an A1/A2 **BLOCK to INFO** when the accused package is itself established. Registry
  path only: `run_layer0_name_only` has no `info` and must stay network-free, so arm A keeps its one
  `babel-cli` FP by construction.
- **Item 0 — `dummy_timebomb`'s 2026-09-01 expiry, neutralised.** Every Layer 3 scenario now
  LD_PRELOADs libfaketime at a PINNED date (`FAKETIME_BASE` for baseline/env/fuzz, `FAKETIME_CLOCK`
  for the clock scenario), so the D1 differential no longer depends on the real date and the only
  difference between baseline and clock is the date itself. `tests/layer3_clock_pin.rs` enforces
  `BASE < fixture trigger < CLOCK` **offline** — the live D1 tests do fail loudly, but they are
  `#[ignore]`d and would not have caught the drift under a plain `cargo test`.
- **Three bugs found by running the tool, not by reasoning — each is a trap for the next agent:**
  - **The suffix fold must be a MINIMUM over both forms, not a replacement.** 17 top-list entries
    themselves end in `.js`/`-js` (`discord.js`, `crypto-js`, `highlight.js`, `uglify-js`, …), so
    comparing `dezcord.js` only as `dezcord` puts it at distance 3 from `discord.js` instead of 2.
    Caught by an arm A diff: 8 real names silently dropped out.
  - **The establishment guard keys on VERSION COUNT, not age.** Age does not discriminate at all —
    the 2017-campaign squats are 3302–5046 days old, as old as their victims. Release history does:
    every measured squat has 3–5 versions, every legitimate package 10+. A first draft used `>= 5`
    and downgraded `expres`, a genuine typosquat and a true positive.
  - **A bulk regex edit demoting "the worm categories" also demoted the IOC-hash branch** (which
    must stay BLOCK) **and missed `exfil_persistence`**. Caught by a test written in the same commit;
    the per-category assertions are now written out one category at a time for that reason.
- **Correction to the v17 write-up**: an earlier note claimed the `worm_signature` evidence paths
  were unrecoverable from the archive and needed an `--eval-evidence` re-run. Both halves were
  wrong. They are in `records.jsonl` on each finding's `file` field, and `--eval-evidence` would not
  have helped — Layer 1 findings have no `evidence` field at all (`RiskReport.evidence` is Layer 2/3
  diff events only). A re-run with the flag produced evidence on 1 finding of 128.
- **Not established by this pass**: arms D and E were not re-run, so item 3's effect on real-malware
  recall is unmeasured (`ansi-styles@6.2.2` was verified directly instead). Arm F's *any-finding* FPR
  was 70.4% at v18 and is 48.1% after v19's capability model; what remains is packages that
  genuinely hold the capability, which needs coverage work (items 7-9), not calibration.

### v17: Evaluation harness + first real-corpus measurement (2026-07-30)
Scope: user asked to select real malicious packages, dummy packages and parent packages, run them,
**add a feature to output data based on the results**, then run an experiment to identify areas for
improvement. Delivered `--eval` (batch scan → `records.jsonl`/`results.csv`/`findings.csv`/
`metrics.json`), a six-manifest ground-truth corpus, and six experiment arms. **No detection logic
was changed** — per the user's decision this pass identifies and documents weaknesses and stops.
Offline **357 passed** (was 243); live Docker **20** (was 15). Full write-up in `eval/REPORT.md`.

- **THE HEADLINE: the detection layers work; the scoring on top of them does not.** 16/16 packages
  (15/16 vectors) / 0% FPR on the project's own dummies, and Layer 1 alone gets **88.8% recall on
  499 real malicious packages**. But on 27 *legitimate popular* packages the tool accuses **26**
  (**FPR 96.3%, arm F** — the headline), with **12 hard BLOCKs** (only `chalk` came through clean) —
  as shipped it would refuse to install `d3`, `ms`, `mysql`, `ffmpeg`, `http-proxy`, `node-sass`,
  `grunt-cli`, `babel-cli`, `escape-string-regexp`, `fabric`, `shadowsocks` and `sqlite`, and would
  raise suspicion on `lodash`, `react`, `express` and `jquery`.
- **Cause 1 — a time bomb in `signatures.rs`.** npm rotated its registry signing key; the old key
  (`SHA256:jl3bws…`) **expired 2025-01-29**. Packages not republished since are still signed with it,
  `key_expired()` filters it out, no unexpired key matches, and the check returns **BLOCK "no
  valid/unexpired signing key"**. Accounts for 11 of the 12 BLOCK-level FPs (the twelfth is
  `fabric`, via `worm_signature`) and gets worse with time.
  **Demoting this one check to INFO takes BLOCK-level FPs from 12/27 (44.4%) to 4/27 (14.8%)** —
  eight packages (`d3`, `escape-string-regexp`, `ffmpeg`, `grunt-cli`, `http-proxy`, `ms`, `mysql`,
  `shadowsocks`) are BLOCK'd by `signatures` and nothing else and clear with no other change; the
  residue is `fabric` (worm_signature), `node-sass` (worm_signature), `sqlite` (typosquat) and
  `babel-cli` (namespace).
  It also fabricates recall: **23 of arm B's 32 "true positives" were credited solely to this check
  firing on npm's own security-holder stub**, not to any name detection. Mechanism-attributed, Layer
  0's real name-check performance is **25.7% recall at 6.7% FPR**, not the 91.4% recall / 93.3% FPR
  (28 of 30 benign-labelled entries) the shipped configuration reports.
- **Cause 2 — static heuristics tuned with no benign corpus.** `suspicious_strings` (43 findings
  across **12** of 27 packages), `obfuscation` (20 across **5**), `dynamic_require` (8 across 4),
  `install_script` (5 across 5) fire on ordinary minified and build-script-bearing packages.
  Two more fired on legitimate packages and appear in no earlier FP accounting: `shell_exfil`
  SUSPECT on `shadowsocks`, and `version_diff` SUSPECT on `bcrypt`. `worm_signature` — the headline
  E1 differentiator — **BLOCKs `fabric` (1 finding) and `node-sass` (3)** for containing the string
  `npm publish` in a legitimate release script.
  *Package counts, not finding counts, are the number a calibration change has to move.*
- **The v14 hex threshold opened a real recall hole.** `ansi-styles@6.2.2` (the Sept-2025
  chalk/debug compromise, a crypto clipper) **passes all four layers**. Its 80 KB payload has 4
  `\xNN` escapes where the rule needs 8 consecutive, and zero `eval`/`atob`/`Buffer.from`/`Function`/
  `process.env`/network-`require` — but **5,662 `0x` literals and 314 distinct `_0x`-prefixed
  identifiers** (the `javascript-obfuscator` family used in the real 2025 npm attacks). Layer 2/3 also
  missed it: the clipper gates on `window.ethereum`, which never exists under `node -e require()`.
  Recommended fix: a hex-identifier-density check; legitimate minifiers do not emit `_0x` names.
- **E1 validated against real malware.** The single real-world IOC hash in `data/worm_iocs.txt`
  **matched the actual Shai-Hulud patient-zero sample** (`@ctrl/tinycolor@4.1.1`) and all three worm
  categories fired → BLOCK. Prediction "IOC coverage ≈ 0" refuted in the tool's favour.
- **A1 misses split into two independent causes**, separable via the `closest`/`distance` fields:
  **suffix blindness** (9/21 — `bare_name` strips only `@scope/`, so `jquery.js` is distance 3 from
  `jquery`) and **absent parents** (12/21 — `ffmpeg`, `fabric`, `shadowsocks`, `tkinter` are not in
  `data/top_packages.txt`). Also: 2 of the 9 A1 "hits" are accidental (`d3.js`→`dayjs` d=2,
  `smb`→`pm2` d=2), so the mechanistically-correct count is 7/30.
- **Layer 2's baseline subtraction is genuinely precise — first measurement on real software.** Arm F
  put 27 legitimate packages through the dynamic layers. **11 are dependency-free**, but only **10
  completed a valid dynamic run** (`chalk`, `escape-string-regexp`, `fabric`, `jquery`, `lodash`,
  `ms`, `nodemailer`, `react`, `semver`, `sqlite`) — keep those two counts apart, they are not the
  same set. **L2 false positives 0/10.** Previously this was evidenced only by `dummy_benign_l3`,
  whose entire body is `add(a, b)`. Note `fabric`: BLOCK'd by Layer 1 (`worm_signature`) yet clean
  through both dynamic layers — direct evidence for fix #2. L3 scored 1/10: `nodemailer` → D3
  `trigger_on_use`, because the
  fuzzer invoked an SMTP export and it opened a connection — D3 caused the behaviour it flagged. That
  is structural, not a threshold: for any package whose purpose *is* network I/O, "an export touched
  the network" carries no signal. Fix: require one of L2's stronger sub-signals (unrelated egress host,
  IP literal, encoded DNS label, credential read) rather than a bare `import_side_effect`.
- **Layers 2/3 earn their keep on the dummies but added nothing on real malware.** Sole detector for
  **7 of 16** malicious dummies (D1/D2/D3 via L3 alone) — but on 40 real malicious samples, **L2 and L3
  were sole detector 0 times** while L1 was 16 times, at 6 ms vs 34 s per package. The dummies were
  built to require the dynamic layers; real npm malware mostly runs unconditionally at install or
  import, where static analysis sees it plainly. State the L3 contribution as *coverage of a class
  static analysis cannot reach in principle*, not as measured recall, until a condition-gated
  real-malware corpus shows otherwise. Cost: p90 16.2 s (L2) / 31.1 s (L3); `dummy_slow_exfil` took
  **467 s**, 24× the median. Also: only 11/27 legitimate (of which 10 completed a valid run) and
  28/40 malicious packages were dynamically analysable at all — the `--offline` sandbox cannot
  install dependencies.
- **A dependency-free legitimate package can exhaust the dynamic timeout with no finding and no
  recorded cause.** `shadowsocks` hit the `--docker-timeout 600` wall in **both** dynamic layers
  (`l2_status=error` 605074 ms, `l3_status=error` 605070 ms, `declared_deps=0`) and produced
  nothing. It alone is **84% of arm F's 24.0-minute wall clock**; without it arm F takes **3.8 min**.
  This is a different cost risk from `dummy_slow_exfil`'s 467 s: that one is deliberate sinkholed DNS
  doing what it was built to do, whereas here there is no diagnosis at all. Not a `dyn_valid`
  problem — the package declares zero dependencies, so the harness was right to try.
- **Layer 1's 11% miss rate is mostly "nothing to analyse"**: 50% of missed samples carry <200 B of
  JavaScript (15 carry none) vs 12% of detected ones — dependency-confusion name-claims where the
  malice is in publishing to a name. A plausible "implausible version number (99.x/500.x)" heuristic
  was **tested and rejected**: 7/56 misses vs 63/443 detections.
- **New corpus facts (verified live 2026-07-30, do NOT re-litigate):** npm cannot supply real
  malicious code — takedowns become 404s or *security holding* stubs, and the stubs that retain their
  original version numbers were **republished defanged** (`crossenv@1.0.0`, `ffmepg@1.0.2`,
  `jquery.js@1.0.2` all contain only `console.log('this package is no longer dangerous')`). Real
  payloads come from `DataDog/malicious-software-packages-dataset` (Apache-2.0, ZipCrypto, password
  `infected`). The authoritative name list is the OSV bulk export (**216,885** npm `MAL-*` names); the
  GitHub tree API truncates well below the full set.
- **Harness design decisions that keep the numbers honest**: `ARTIFACT_FN` for defanged stubs (kept
  out of recall's denominator — **but see below: it never actually fired**); `dyn_valid` gating on
  `declared_deps` because the `--network=none` +
  `--offline` sandbox cannot install dependencies, so a dep-bearing package's empty profile is vacuous
  rather than clean; INFO findings never count as positives (`check_typosquat` returns INFO on an
  exact popular-list match, so every benign control would otherwise read as an FP); every rate is
  `Option<f64>` so a zero denominator serializes to `null`, never `0.0`.
- **Code (additive; the five edits to existing files are wrapper- or note-preserving):**
  new `src/eval/{corpus,record,metrics,runner,samples}.rs`; `checker::run_layer0_name_only`
  (name-only Layer 0, zero HTTP — the 216k sweep runs in **43.7 s** and is byte-reproducible);
  `registry::{FetchStatus, fetch_package_info}` (404 vs transient failure, so a timeout can no longer
  masquerade as "removed" and corrupt recall); `report::{FullScan, LayerMask,
  run_full_{local,registry}_collect}` keeping the four `CheckResult`s + per-layer `Instant` timings
  alongside the `RiskReport` (`CheckResult` still **not** `Clone` — borrow, aggregate, then move);
  **version-pinned scanning** wiring the previously-unused `get_version_tarball_url`;
  `docker::{docker_version, ensure_layer_image (OnceLock), timeout_argv, run_docker, container_name}`
  — one probe+build per process instead of per layer (also collapses `--full` from 3 builds to 1) and
  a `--docker-timeout` wall-clock cap that force-removes the container on exit 124. One new
  dependency: `zip` (ZipCrypto, for the sample archives). CSV is hand-rolled — writer-only need, and
  free text never enters a CSV.
- **Two bugs found in the harness itself and fixed** (both would have looked like corpus gaps):
  `merge_manifests` was O(n²) and hung on 216k entries; `find_package_root`'s `max_depth(8)` silently
  skipped 38/499 macOS-collected samples nested under `/var/folders/…`.
- **One regression caught by the existing suite**: masking Layer 0 off for a local-directory scan
  initially reported it `Skipped`, but `tests/full_pipeline.rs` correctly requires `NotRun` — "not
  applicable" is not "deliberately declined". `finish_scan` now takes both a *requested* and an
  *applicable* mask.
- **Known limitations of this measurement**: arm A's ground truth is "has a malicious-code advisory",
  not "is a typosquat", so its 1.6% is a **flag rate**, not per-vector recall (that corpus is mostly
  mass-registered spam outside A1/A2/A4's design). B3 shows 0% recall in arm C only because the
  manifest cannot yet express a paired prev/latest directory. `dummy_persistence` is mis-attributed to
  D2 (its `.bashrc` write is unconditional at import). Everything runs serially — concurrency would
  perturb the very timings and behaviours being measured.
- **Three measurement caveats re-derived from the archived artifacts (2026-08-04), each of which the
  original write-up got wrong or omitted:**
  - **Arm B never ran Layer 1 on the malicious half.** `armB/metrics.json` → `by_layer[1]:
    ran 27, skipped 38`. The 27 are the benign parents; **all 38 malicious holder entries were
    Layer 0 only.** So arm B is `L0 (malicious) / L0+L1 (benign)`, not `L0+L1`, and its 91.4% recall
    is a **Layer 0 figure** — consistent with `by_layer[0].sole_detector = 32`, and one more reason
    the number is a `signatures` artefact rather than detection.
  - **The `ARTIFACT_FN` safeguard never fired.** `overall.artifact_fn = 0` in all six arms. It is
    documented in `eval/README.md` as the mechanism keeping defanged takedown stubs out of recall's
    denominator, but because the content layers never ran on `holder` entries (above), the
    classification was **never assigned even once**. It is not wrong — it is **untested by this
    run**, an inert safeguard. Do not cite it as validated.
  - **Arm C is 16/16 at package level but 15/16 at vector level.** `overall.recall = 1.0` while
    `by_vector` B3 reports `expected 1, detected 0`. Both are true: the package was caught by B2, so
    the package-level verdict is a TP, but the B3 rule itself detected nothing. Say "16/16 packages,
    15/16 vectors". Also `overall_block_only.recall = 0.5625` — even on the tool's own dummy corpus
    only **9 of 16 reach BLOCK**.
  - **Arm E has two labelled vector misses, not one.** `by_vector` shows B3 `expected 1, detected 0`
    (`ansi-styles@6.2.2`) **and** B4 `expected 1, detected 0` (`node-ipc@12.0.1`). node-ipc is a
    package-level **TP** — caught via B2;C1 — but no B4 rule fired, so B4 recall in arm E is 0/1.
    Separately, `stringmaster-pro@2.0.2` is the second package-level FN; it carries **no vector
    label**, so it belongs to no per-vector row. Its 23 declared dependencies set `dyn_valid=false`
    and invalidate L2/L3 only — **Layer 1 ran validly and returned zero findings**, so it is a
    genuine Layer 1 miss, not a "weaker" one.

### v16: Live top-package refresh (`--refresh-top`) — Layer 0 lists augmented from the npm search API (2026-07-12)
Scope: user asked for "a feature to check top projects on NPM in real time"; clarified to **live-refresh
of the Layer 0 comparison lists** (typosquat/namespace/combosquat corpus), NOT a scan-the-top-packages
mode. Planning/docs Fable, coding Sonnet (reviewed + cargo-verified between), live-verified with real
network. Offline **243 passed** (was 217); live Docker suite untouched (15, not re-run — no L2/L3 change).
- **New `src/toplist.rs` + `--refresh-top` flag (also `NPM_PRE_SCAN_REFRESH_TOP=1|true`), default OFF**
  (reproducibility + network-free `cargo test` by construction). `load_effective_lists(false)` is
  byte-identical to the embedded loaders (regression-tested), zero fs/network.
- **Verified npm search-API facts (2026-07-12 — do NOT re-litigate from folklore):** `text` param is
  REQUIRED, 2–64 chars (`ERR_TEXT_LENGTH`); the community `text=boost-exact:false` match-all trick does
  NOT work (treated as literal text); every result carries `downloads:{weekly,monthly}`; server-side
  popularity ranking is relevance-dominated/noisy but popular packages float into page 1 of short-seed
  queries (page 2+ empirically junk); `size` up to 250 works; **the API rate-limits with HTTP 429
  (`retry-after: 0`) behind a ~10-request-burst token bucket — 150ms spacing died at seed #11, 1.2s
  spacing measured 15/15 clean**.
- **Fetch strategy:** ~24 two-letter seeds × one page of 250, 1.2s apart, ≤2 retries/seed (2s backoff);
  harvest `(name, downloads.weekly)`, dedup (max wins), floor ≥500k weekly, sort desc, cap 1500;
  sanity guard rejects a sweep with <200 floored names (API-drift protection). Live run harvested
  371 unscoped + 112 scoped names in ~35s.
- **Merge = UNION, embedded-first** (case-insensitive dedup keeps embedded casing/order — typosquat's
  first-min-wins tie-break is order-dependent; a bad fetch can never shrink coverage). Scoped-FP
  filter: fetched scoped names whose flattened form (`namespace::normalize`, now `pub(crate)`) exists
  in the fetched unscoped set are dropped (`babel-core`/`@babel/core` legit-twin class).
- **Cache:** `$NPM_PRE_SCAN_CACHE_DIR` > `$XDG_CACHE_HOME` > `~/.cache`, `npm-pre-scan/`, same
  one-per-line `#`-comment format, 24h TTL by mtime, atomic `.tmp`+rename. Cache hit measured 0.088s
  (vs ~35s sweep). Failure ladder: fresh cache → silent; fetch fail/rejected → stale cache, else
  embedded, one stderr `note:` line — **never changes a verdict** (live-verified: `lodahs` BLOCK
  identical in all paths).
- **Plumbing:** `report.rs` split `run_full_registry` → `run_full_registry_with_lists` (+ thin
  back-compat wrapper); `main.rs` computes lists once and passes down (no double fetch);
  `registry.rs::fetch_search_page`. No new dependencies.
- **Live-verified new coverage:** `abbrevv` → PASS with embedded lists, **BLOCK (typosquat of
  live-fetched `abbrev`, distance=1)** with `--refresh-top`.
- **Known limitations (documented):** seed-page coverage is fuzzy — giants like `lodash`/`react`
  don't surface in seed page 1 and rely on the embedded snapshot (union makes this harmless; fetched
  names are additive). Verdicts are non-reproducible when the flag is on (inherent; hence opt-in).
  Residual namespace-FP class: legit flat twin absent from the fetched set still collides.

### v15: Environment migration (WSL Ubuntu → WSL Arch) + doc re-sync, re-verified on Arch (2026-07-12)
Scope: user moved the dev box from WSL2/Ubuntu 26.04 to **WSL2/Arch Linux** and asked to read
CLAUDE.md + README.md in full, verify all documented context against the actual repo, and reflect the
environment change. **No detection logic changed.** The only source edit was a fixture-hash refresh
(below); everything else is docs + regenerated gitignored fixtures.
- **Environment**: now Windows 11 → WSL2 → **Arch Linux (rolling)**, repo at `/home/hkkarch/dev/npm_pre_scan`
  (username changed hkkhpsc→hkkarch). Fresh Arch had no Rust and no Docker: installed **rustup** (user-level,
  stable 1.97) + **docker** (pacman, systemd `enable --now`; Arch WSL runs systemd as PID 1 → `systemctl`,
  not `service`). Repo was checked out **root:root** (as after the v10 machine move) → `sudo chown -R` +
  `git config --add safe.directory` before cargo could build. Docker group needs a re-login; ran the live
  suite under `sg docker -c '…'`. See the **Environment** section for specifics.
- **Doc drift fixed (README was last written at v13, never synced for v14; CLAUDE.md's per-layer sections
  lagged its own v14 changelog)**: added the **B4** vector row (destructive/persistence) to the coverage
  table; added v14 Layer 1 static checks (atob/Function-ctor, computed `import()`, split-string,
  expanded shell-exfil, worker_threads/.wasm INFO); added v14 Layer 2 rules (sensitive_file_write,
  mass_deletion, ip_literal_egress, file_writes/file_deletes profile, broadened syscall set, ephemeral
  filter); documented the runtime-extensible lists (`NPM_PRE_SCAN_IOCS` / `NPM_PRE_SCAN_EGRESS_HOSTS`);
  added `src/runtime_lists.rs` to the layout; Layer 3 env-scenario widening (NODE_ENV/TERM); corrected
  test counts to **217 offline / 15 live**; Arch/systemd docker-start note.
- **Regenerated gitignored `dummy_packages/`** (absent on a fresh clone, same as the v10 move): all 15
  dummies recreated from their specs + the assertions in `tests/*.rs`. The `dummy_shai_hulud/infected/bundle.js`
  IOC hash could not be reversed, so — exactly as at v10 — bundle.js was recreated and its SHA-256 refreshed
  in `data/worm_iocs.txt` (line 18) **and** in the `load_iocs_skips_header_comments` unit-test assertion
  (`src/layer1/worm_signature.rs`). New hash: `a93763f6…eaa10`. infected/index.js drives the live E1 path
  with an import-time DNS lookup to api.github.com (payload-free, sinkholed).
- **Re-verified on Arch**: offline `cargo test` = **217 passed / 0 failed**; live
  `cargo test --no-fail-fast -- --ignored` (Docker 29.6.1, image rebuilt) = **15/15** — 8 layer2_dynamic
  (B1/C1/C2/C3/E1 + B4 wiper + B4 persistence + C1 ip-egress), 4 layer3_dynamic (D1/D2/D3 + benign),
  2 full_pipeline, 1 full_registry. libfaketime + baseline-diff behave identically on Arch's WSL2 kernel.

### v14: Detection-coverage expansion — file-tampering class, IP-literal egress, static broadening, runtime-extensible lists (2026-07-03)
Scope: user asked to "review the project, make better workflows, expand detect and defense coverage."
After a 3-agent audit (detection map / pipeline map / tests-data map) + 3-agent design pass, the user
chose **detection-first** for this build; workflow + defense (policy/allowlist, npm-safe-install wrapper,
project CI, GitHub scan action) + evaluation are fully designed and sequenced as follow-up passes (see
`.claude/plans/`). Planning/review Fable, coding Sonnet (per-phase, reviewed + cargo-verified between),
docs Fable. Offline **217 passed** (was 164); live Docker **15/15** (8 layer2_dynamic + 4 layer3_dynamic
+ 2 full_pipeline + 1 full_registry).
- **New vector B4 — destructive/persistence + wiper (Layer 2/3).** strace previously traced only
  reads/execve/connect, so file WRITES/DELETES/RENAMES/CHMOD were invisible. Broadened `STRACE_SYSCALLS`
  in run_layer2.sh/run_layer3.sh with `unlink,unlinkat,rename,renameat,renameat2,chmod,fchmodat` (bare
  `write` deliberately omitted — log-volume). `Layer2Profile` gained `file_writes`/`file_deletes`
  (`#[serde(default)]`); `parse_strace` gained `open_is_write` (O_WRONLY/O_RDWR/O_CREAT/O_TRUNC flag
  detection) + `parse_unlink`/`parse_rename`/`parse_chmod`. New classify rules `sensitive_file_write`
  (.npmrc/.bashrc/authorized_keys/cron/git-hooks/node_modules/.bin → BLOCK) and `mass_deletion` (≥20
  package-attributable deletes → BLOCK, wiper). Auto-live in Layer 3 via `classify_scenario`. All new
  rules are baseline-diffed, and writes/deletes to ephemeral/system scratch (`/tmp`, `/dev` incl.
  `/dev/shm`, `/proc`, `/sys`, `/run`, `/var/tmp`) are excluded via `is_ephemeral_or_system_path` — this
  is what keeps the Layer 3 **clock** scenario honest (libfaketime, LD_PRELOAD'd only in the mutated run,
  writes/unlinks its own `/dev/shm/faketime_*` shm+sem files; without the filter they survived the
  baseline diff and false-positived every benign package). `diff.rs` `normalize_path` also gained
  node_modules atomic-staging + `.tmp`/`~` folds; `evidence_lines` renders `write:`/`delete:`.
- **IP-literal egress (Layer 2/3, C1).** `connect()` to a public IPv4 (std `Ipv4Addr`, excludes
  private/loopback/link-local/CGNAT/etc.) → SUSPECT `ip_literal_egress` — closes the DNS-sinkhole bypass
  where malware hardcodes a C2 IP. **Fixed a latent `parse_connect` bug found via this path**: modern
  strace on node:lts-alpine emits `sin_addr=inet_addr("1.2.3.4")`, not `sin_addr="1.2.3.4"` — the parser
  only handled the latter, so connect-based detection (incl. the IMDS worm-egress rule) had NEVER worked
  live, only in hand-written fixtures. Parser now reads the first quoted string after `sin_addr=`
  (handles both forms); fixtures corrected to real strace output.
- **Layer 1 static broadening (B2).** `atob(` + `Function("…")` constructor (BLOCK when combined with
  eval/atob-execution), computed `import(x+y)` + systematic split-string obfuscation (`'ht'+'tp'`, ≥3
  occurrences), expanded shell-exfil binaries (python/perl/ruby, `/dev/tcp/`, `base64 -d`), and INFO
  capability notes (`worker_threads`, `.wasm`). New `check_computed_load`/`check_capability_notes` wired
  into `collect_dir_findings`.
- **Runtime-extensible detection lists.** New `src/runtime_lists.rs` (`merge_lines` pure + `merge_runtime_lines`
  env-file loader, additive-over-embedded, never-panics). Operators can extend worm IOCs
  (`NPM_PRE_SCAN_IOCS`) and egress hosts (`NPM_PRE_SCAN_EGRESS_HOSTS`) without recompiling. Network-module
  list left compile-time (its regex-fragment form doesn't merge cleanly) — noted future work.
- **Layer 3 D2 mutation** widened: env scenario now also sets `NODE_ENV=production`/`TERM` (catches more
  env gates). Second clock date deferred (needs mod.rs scenario wiring, low marginal value).
- **Phase 0 hygiene**: fixed the 3 known clippy nits (clippy `-D warnings` clean). The three
  speculative refactor-extractions from the plan (run_name_scan/ensure_layer_image/colorize_verdict) were
  deferred to the workflow/defense passes that consume them (no current consumer → avoid speculative code).
- **Known follow-ups (designed, not built this pass)**: workflow (manifest/lockfile scan, batch, parallel
  L2/L3, SARIF), defense (policy/allowlist, npm-safe-install.sh, .github CI, composite scan action),
  evaluation harness (OSSF malicious-names recall + benign-top-N FPR). Full designs in
  `.claude/plans/review-all-of-this-logical-parrot.md`.

> **v1–v13 have been moved to `docs/CHANGELOG-archive.md`** — verbatim, in their original
> order. They are resolved history; the operational content that still matters (the CRLF
> shebang footgun, the `parse_connect` sockaddr form, the `chmod -R a+r /out` requirement)
> is carried by the per-layer sections below, which is where an agent will look for it.

---

## Implementation Status

### Layer 0 — DONE
```
src/
  checker.rs      run_layer0(name) → CheckResult {verdict, findings}
                  run_layer0_name_only(name) — A1/A2/A4 only, ZERO network (v17; the
                  216k-name sweep runs in 43.7s and is byte-reproducible)
  registry.rs     npm registry + downloads API (reqwest blocking)
                  fetch_package_info → (FetchStatus, Option<Value>): 404 vs transient
                  failure kept apart, so a timeout can't masquerade as "removed" (v17)
  typosquat.rs    levenshtein() + check_typosquat() vs top_packages.txt (~1137 pkgs)
  age_check.rs    age < 7 days + download spike ratio (5× threshold)
  maintainer.rs   first-version vs latest-version maintainer set comparison
  signatures.rs   registry ECDSA-P256 signature verification (npm audit signatures)
  namespace.rs    unscoped name vs top_scoped_packages.txt (94 scoped pkgs)
  combosquat.rs   popular-token + suspicious-affix heuristic (A4)
  toplist.rs      --refresh-top: live top-package sweep (npm search API) + 24h cache + union merge (v16)
  eval/           evaluation harness (--eval): corpus/record/metrics/runner/samples (v17)
  models.rs       Verdict enum, Finding type, CheckResult struct
  main.rs         CLI: npm-pre-scan [--json] [--no-color] [--refresh-top] <pkg> [<pkg>...]

data/top_packages.txt        — embedded at compile time (base; --refresh-top unions live names on top)
data/top_scoped_packages.txt — embedded at compile time (base; --refresh-top unions live names on top)

Binary:
  npm-pre-scan [--json] [--no-color] [-v|--verbose] <pkg> [<pkg>...]
  npm-pre-scan --local <dir>       (Layer 1 only on local dir)
  npm-pre-scan --layer2 <dir>      (Layer 2 dynamic analysis — requires Docker)
  npm-pre-scan --layer3 <dir>      (Layer 3 condition mutation — requires Docker)
  npm-pre-scan --full <name|dir>   (full pipeline → aggregate risk report; requires Docker)
                                    <name>: L0+L1+L2+L3 (download once); <dir>: L1+L2+L3
  npm-pre-scan --eval <manifest>   (v17: batch-scan a ground-truth corpus → records.jsonl,
                                    results.csv, findings.csv, metrics.json; repeatable.
                                    --out-dir / --eval-mode name-only|registry|full|auto /
                                    --docker-timeout <s> / --eval-evidence. See eval/README.md.
                                    Exit 0=complete, 4=degraded, 5=unrunnable — 0-3 stay
                                    reserved for per-package verdicts.)
  exit 0=PASS  1=SUSPECT  2=BLOCK  3=ERROR
  (name scans also emit the aggregate RiskReport: L0+L1, layer_2/layer_3 not_run)
  (-v/--verbose: per-layer progress + per-scenario diff evidence)
  (--refresh-top / NPM_PRE_SCAN_REFRESH_TOP=1: live-refresh the L0 top lists, 24h cache
   at $NPM_PRE_SCAN_CACHE_DIR > $XDG_CACHE_HOME > ~/.cache; failure never changes a verdict)

Severity rules: see README.md, section `LAYER 0 — METADATA CHECKS`. That is the single
source of truth for the check → severity mapping; do not keep a second copy here.
The verdict rule itself is worst-of: any BLOCK → BLOCK; any SUSPECT and no BLOCK → SUSPECT.

✅ FIXED IN v18 (was: MEASURED DEFECTS, v17). Kept here because an agent must not
   re-introduce any of these. Full before/after: eval/REPORT.md.
  • `signatures` was a TIME BOMB — FIXED. It filtered expired keys OUT of the lookup, so
    for any package not republished since npm's 2025-01-29 key rotation it found no key,
    never verified anything, and returned BLOCK. 11 of 27 legitimate packages, worsening
    monthly, plus 23 of arm B's 32 "true positives" were this check firing on npm's own
    security-holder stubs. It now verifies against the key that ACTUALLY signed and treats
    expiry as INFO; BLOCK is reserved for a signature that verifies and fails, SUSPECT for
    an unpublished keyid. Measured after: 45/45 signature findings INFO, arm B BLOCK-level
    FPs 14 → 0. DO NOT re-add an expiry filter to the key lookup.
  • `typosquat`/`namespace` BLOCK on legitimate packages — FIXED, two independent ways.
    `sqlite` was added to top_packages.txt (exact match → INFO, works in name-only mode
    too); `babel-cli` is handled by the establishment guard in `checker.rs`, which
    downgrades an A1/A2 BLOCK to INFO when the accused package is itself old and
    frequently released. NOTE the guard is registry-path only — `run_layer0_name_only`
    has no `info` and must stay network-free, so a name-only scan still reports the raw
    name verdict.
  • A1 recall was 25.7% — FIXED, both causes. Suffix squats: a trailing `.js`/`-js`/`_js`
    is folded for the DISTANCE compare only, and a name matching exactly only after
    folding is a suffix-squat BLOCK. Absent parents: `ffmpeg`, `fabric`, `shadowsocks`,
    `tkinter`, `sqlite` added to top_packages.txt. Arm B's honest name-detection recall
    went 25.7% → 85.7%, with all 18 TPs now caught by A1 rather than by `signatures`.
  • Also fixed: the distance-2 branch had no name-length guard, so a 3-character name was
    within 2 edits of much of the top list by chance (`smb`→`pm2`). It now requires the
    same `len >= 5` the distance-1 branch always had.

⚠ TWO TRAPS in the above — both were hit during v18 and caught only by running the tool:
  • The suffix fold must be a MINIMUM over both forms, not a replacement. 17 top-list
    entries themselves end in `.js`/`-js` (`discord.js`, `crypto-js`, …), so comparing
    `dezcord.js` only as `dezcord` puts it at distance 3 from `discord.js` instead of 2
    and loses the detection.
  • The establishment guard keys on VERSION COUNT, not age. Age does not discriminate at
    all: the 2017-campaign squats are 3300–5000 days old, as old as their victims. What
    separates them is release history — every measured squat has 3–5 versions, every
    legitimate package 10+. An earlier draft used `>= 5` and downgraded `expres`, a
    genuine typosquat and a true positive.
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

Checks and their severities: see README.md, section `LAYER 1 — STATIC ANALYSIS`.
That is the single source of truth; do not keep a second copy here.

Scoring: BLOCK=50, SUSPECT=15, INFO=2 weighted sum, capped at 100
Pipeline: Layer 0 BLOCK → Layer 1 skipped
Local test: npm-pre-scan --local <dir>

✅ RECALIBRATED in v19 (was: MEASURED DEFECTS, v17). The v17 benign-corpus counts, and
  what each rule is now. Package counts, not finding counts — that is what a calibration
  change has to move.
  suspicious_strings  12 of 27 packages   SPLIT: process.env -> CAPABILITY (36.3% mal vs
                                          44.4% benign, INVERTED); os.homedir() stays
                                          SUSPECT (14.4% vs 0.0%) and now also matches
                                          require('os').homedir(); /etc/* stay BLOCK.
  obfuscation          5 of 27 packages   long-base64 -> CAPABILITY (lift 1.16). atob,
                                          hex-identifier and hex-sequence keep their
                                          severities (all 0.0% benign).
  dynamic_require      4 of 27 packages   -> CAPABILITY (7.6% mal vs 14.8% benign, INVERTED)
  install_script       5 of 27 packages   -> exec-shape command BLOCK / pre+postinstall
                                          SUSPECT / install+prepare+build-step CAPABILITY
  maintainer (A3)      3 of 27 packages   -> CAPABILITY (zero true positives, ever)
  shell_exfil          1 (shadowsocks)    unchanged — lift 5.14, it earns its severity
  version_diff         1 (bcrypt)         unchanged — too few observations to calibrate
  network_imports      4 of 27 packages   v20: -> CAPABILITY only when it is the SOLE
                                          accusation AND the package is established.
                                          NOT demoted wholesale — lift 2.35 (34.9% mal
                                          vs 14.8% benign), comparable to shell_exfil.
                                          Registry path only; `None` never demotes.
  Result: arm F any-finding FPR 70.4% -> 48.1%, BLOCK-level still 0.0%, and NO recall
  lost (arm D 87.6%, arm E 97.5%). What still fires genuinely has the capability —
  going lower needs dynamic corroboration, i.e. coverage (items 7-9), not calibration.

  ✅ worm_signature — FIXED in v18. Was 4 findings across 2 packages, `fabric` (1) and
     `node-sass` (3), each a BLOCK for shipping a release script containing `npm publish`;
     `fabric` passes L2 and L3 cleanly, so nothing corroborated the accusation. Each
     category now emits SUSPECT and only the ≥2-category aggregate (or a known-IOC hash)
     BLOCKs — which is what this module's own doc comment always claimed it did.
     DO NOT restore a per-category BLOCK.
  ✅ The javascript-obfuscator gap — FIXED in v18. The \xNN rule needs 8+ CONSECUTIVE
     escapes, which that family never emits, so ansi-styles@6.2.2 (the real Sept-2025
     clipper) passed all four layers with zero findings. New `hex_identifier` rule counts
     DISTINCT `_0x[0-9a-f]{4,}` names: ≥25 BLOCK, ≥5 SUSPECT. Measured 314 in the payload
     versus 0 across jquery/lodash/d3/react/chalk/debug/node-sass/fabric. Count distinct
     identifiers, NOT `0x` literals — d3 ships 174 of those legitimately.
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

Profile (v14): Layer2Profile also carries file_writes / file_deletes (both #[serde(default)]),
populated by parse_open's O_WRONLY/O_RDWR/O_CREAT/O_TRUNC write detection + parse_unlink/parse_rename/
parse_chmod. Broadened strace set: execve,open,openat,openat2,connect,unlink,unlinkat,rename,renameat,
renameat2,chmod,fchmodat (bare `write` deliberately omitted — log volume).

Detection rules (classify):
  E1 worm egress       DNS/connect to registry.npmjs.org, api.github.com, webhook.site, 169.254.169.254 → BLOCK
  C1 ip_literal_egress connect() to a public IPv4 literal (DNS-sinkhole bypass)                        → SUSPECT (v14)
  B1 install script    child process (unexpected) during install phase; +network/sensitive/write/wipe → BLOCK → SUSPECT/BLOCK
  sensitive file read  /etc/passwd, /etc/shadow, ~/.ssh, .npmrc, .aws/credentials, .git-credentials   → BLOCK
  B4 sensitive_file_write .npmrc/.bashrc/authorized_keys/cron/git-hooks/node_modules/.bin written     → BLOCK (v14)
  B4 mass_deletion     ≥20 package-attributable unlinks (wiper behavior)                               → BLOCK (v14)
  C1 import side effect network/process/file-write/delete activity during import phase                 → SUSPECT/BLOCK
  C2 DNS tunneling     many distinct qnames, or long base32/hex-looking labels                         → SUSPECT/BLOCK
  C3 native addon      *.node file opened/loaded at import                                             → SUSPECT

  All write/delete rules are baseline-diffed; writes/deletes to ephemeral/system scratch (/tmp, /dev
  incl. /dev/shm, /proc, /sys, /run, /var/tmp, /var/cache, /etc/localtime, */faketime*) are excluded
  via is_ephemeral_or_system_path — this is what keeps the Layer 3 clock scenario honest (libfaketime's
  own /dev/shm/faketime_* artifacts would otherwise survive the baseline diff and false-positive).

  Runtime-extensible lists (v14, src/runtime_lists.rs): operators can extend worm IOCs
  (NPM_PRE_SCAN_IOCS) and egress hosts (NPM_PRE_SCAN_EGRESS_HOSTS) via env-file paths without
  recompiling (additive over the embedded defaults, never replacing).

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

BASELINE SUBTRACTION (v13): each phase is traced TWICE — an unmutated baseline and the real run —
and mod.rs diffs real-vs-baseline (reusing layer3::diff::diff_profiles_phase) before classifying, so
npm/node's own toolchain reads (.npmrc, /etc/passwd) cancel and only package-attributable behavior
survives. Four runs: install {base=`npm install --ignore-scripts`, real=scripts-enabled} on the SAME
`/work` (reset pristine between so CWD-relative reads cancel), import {base=`node -e "0"`, real=require}
sharing `/work`. Each run has its own per-run dnsmasq log. Findings de-duplicated. This makes Layer 2
PRECISE at the source (a benign package is a true PASS), superseding v10's over-approximation.

Live-verified (2026-07-02, WSL2/Ubuntu 26.04 + Docker 29.1.3): all 5 Docker-gated tests in
tests/layer2_dynamic.rs pass through the baseline diff — B1/C1/C2/C3/E1 fire via their intended
vectors on the package's own behavior; dummy_benign_l3 → PASS. Run: `cargo test --no-fail-fast -- --ignored`.

Residual limitation: a payload that ONLY reads .npmrc at install cancels against npm's own .npmrc read
(Layer 1 static suspicious_strings still flags .npmrc references in source). Network-time bombs
(NTP/HTTP Date) remain out of scope under --network=none.
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
  RiskReport { package, risk_score: f64, verdict, detections, layer_status: [LayerStatus;4], evidence }
  aggregate(pkg, [Option<&CheckResult>; 4]) -> RiskReport
  run_full_local(name, dir) -> RiskReport    (L1_local + L2 + L3; layer_0 not_run for local)
  run_full_registry(name)   -> RiskReport    (L0 + download-once + L1 + L2 + L3 — unified single tool)

Score: weighted NOISY-OR  risk_score = 1 − ∏(1 − wᵢ·scoreᵢ/100)  over layers that ran & verdict≠Error.
  Weights [L0,L1,L2,L3] = [1.0, 1.0, 1.0, 1.0]. (v13: L2 weight restored to 1.0 and the SUSPECT
  verdict-cap REMOVED — Layer 2's baseline subtraction makes it precise, so it is a first-class
  trusted layer that can force BLOCK on genuine package-attributable egress/credential-theft.)
  Rounded to 2 dp; an Error layer (e.g. Docker absent) contributes nothing to risk.
Verdict: worst-of layers that ran (BLOCK>SUSPECT>ERROR>PASS).
detections: each Finding → "{vector}: {check} ({message})".
layer_status: per layer — "ran" | "skipped" (L1 when L0 BLOCK short-circuits) | "not_run" | "error".
evidence: per layer — the exact new diff events (dns/connect/file/proc) L2/L3 findings fired on (shown under -v).

⚠ MEASURED (v17, arm F — read before touching the score). The verdict is decided by
  worst-of-severity, as above. **risk_score is reported, NOT used as a gate**, and it
  SATURATES on legitimate packages:
    jquery, react   1.00 (the maximum)  → SUSPECT
    ffmpeg          0.50                → BLOCK
    BLOCK spans     0.50 – 1.00
    SUSPECT spans   0.17 – 1.00         (the two ranges overlap completely)
    chalk           0.02                (the only clean package of the 27)
    six of the 27 legitimate packages sit at 1.00
  Two consequences, both load-bearing for anyone planning a fix:
  1. RAISING A SCORE THRESHOLD CANNOT FIX THE FALSE-POSITIVE RATE. The worst-scoring
     legitimate packages already tie with the BLOCK'd ones, so no cut point separates
     them. Threshold tuning is the obvious cheap fix; it does not work here. Do not
     spend a pass on it.
  2. The score is saturated in its top half, so it carries little ranking information
     there.
  Severity assignment and score aggregation have to be revisited TOGETHER, after the
  per-check fixes land — see fix-queue item 10.

v17 additions (additive; the two existing entry points became one-line wrappers):
  FullScan { report, layers: [Option<CheckResult>;4], layer_ms, registry_status, declared_deps }
  LayerMask([bool;4])  — ALL / from_indices / intersect; a layer this path COULD have run but
    the caller masked off is `Skipped`, one that was never applicable stays `NotRun`
  run_full_local_collect(name, dir, mask) / run_full_registry_collect(name, version, …, mask)
    — keep every layer's `note`, `severity` and `vector` (which `aggregate` discards), plus
    per-layer Instant timings; `version=Some(v)` pins the tarball via get_version_tarball_url
    and passes info:None so pkg_json comes from the pinned tarball and version_diff is skipped.
    CheckResult is still NOT Clone — borrow, aggregate, then move.

CLI: npm-pre-scan --full <name|dir> (Docker); name scans (`<pkg>`) emit RiskReport from L0+L1.
Tests: tests/report_aggregate.rs (offline, incl. 1.00 canonical example, L2-forces-BLOCK, layer_status);
       tests/full_pipeline.rs (dummy_timebomb→SUSPECT+layer_3, dummy_benign_l3→PASS);
       tests/full_registry.rs (registry-name smoke).
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

> **The per-package dummy verification table lives in `README.md`, section `TESTING`.** That copy is
> the more complete of the two (it carries `dummy_wiper`, `dummy_persistence` and `dummy_ip_egress`,
> which this file's copy omitted). Do not reintroduce a second table here.

**Why this table is not evidence of precision.** Every fixture was authored by this project, so it
can show that a rule *works* and can never show whether it *over-fires*. Arm C re-verified all of
them through the batch harness at **16/16 packages, 15/16 vectors, 0% FPR** — and the same layers
scored a **96.3% false-positive rate on 27 real popular packages** (arm F). Treat arm C as a
per-vector functional check, never as a precision result.

Three caveats an agent must not lose:

- ✅ **`dummy_timebomb`'s 2026-09-01 expiry is closed, and v20 proved it.** v18 pinned the harness
  clock (libfaketime in every Layer 3 scenario) rather than re-dating the fixture. Arm C ran on
  **2026-09-07 — six days past the trigger — and D1 still fires**, so the differential really is
  date-invariant. No pre-deadline run could have shown that. Do not "fix" this by re-dating the
  fixture; that buys a year and then recurs.
- **`dummy_persistence` is mis-attributed to D2.** Its `.bashrc` write is unconditional at import, so
  the Layer 3 env scenario claims credit for behaviour it did not trigger.
- **`dummy_slow_exfil` takes 467 s** (24× the arm C median) from 35 sequential sinkholed DNS lookups.
  Compare the arm F `shadowsocks` timeout, which is the same cost hit with no diagnosis attached.

---

## Evaluation — DONE (harness built v17; all six arms re-run at v18, v19 and v20)

`npm-pre-scan --eval <manifest>` batch-scans a ground-truth corpus and emits `records.jsonl` (lossless
per-package records), `results.csv` (45 cols), `findings.csv` (tidy, one row per finding),
`metrics.json` (confusion matrices + per-group/layer/vector rollups + timing + provenance). Corpus and
safety posture: `eval/README.md`. Results and ranked weaknesses: **`eval/REPORT.md`**.

> **The arm table lives in `README.md`, section `EVALUATION`**, with the canonical, most detailed
> version (including per-arm cost) in `eval/REPORT.md`, section `What was measured`. Committed
> before/after baselines for the six arms: `eval/baseline/v{17,18,19,20}/arm{A..F}.metrics.json`.

Agent-facing notes on reading those numbers:

- **The headline FPR is arm F's, and as of v20 it is 29.6% (8/27)** — from 96.3% (v17) → 70.4%
  (v18) → 48.1% (v19) → **29.6%**. Full pipeline, benign-only corpus. Quote the BLOCK-level figure
  alongside it, because they differ sharply: **0.0% BLOCK-level** versus 29.6% any-finding. Arm B's
  FPR is a different arm and a different denominator (30 benign-labelled entries: the 27 parents plus
  three reclaimed names carried in `real_malicious_holders.tsv`) — 93.3% v17, 66.7% v18, 46.7% v19,
  **30.0% v20**. Always give the denominator.
- **Arm B is `L0 (malicious) / L0+L1 (benign)`**, not `L0+L1`. All 38 malicious holder entries were
  Layer 0 only (`by_layer[1]: ran 27, skipped 38`), so its 91.4% recall is a Layer 0 figure.
- **Arm C is 16/16 packages, 15/16 vectors** (B3 has no path through the harness), and only
  **9 of 16 reach BLOCK** (`overall_block_only.recall = 0.5625`).
- **`ARTIFACT_FN` was inert in v17 and is ACTIVE as of v18.** All six v17 arms reported
  `overall.artifact_fn = 0`, because the content layers never ran on `holder` entries so the
  classification was never assigned once. Fixing `signatures` (item 1) activated it: with the
  takedown stubs no longer BLOCK'd, a clean verdict on a `holder` entry is now correctly classified
  and kept out of recall's denominator. Arm B: **0 → 14**, and its recall denominator is honestly
  21 rather than 35.
- **BLOCK severity had no discriminative power — FIXED in v18.** v17 measured legitimate packages
  reaching BLOCK at **44.4%** (12/27, arm F `overall_block_only.fpr`) versus real malicious ones at
  **37.5%** (187/499, arm D `overall_block_only_rates.recall`) — a *higher* rate on legitimate
  packages than on real malware. The inversion is gone, but **read both sides from the same
  version**: v17 was 44.4% vs 37.5%; v18 was 0.0% vs **21.6%** (the worm-category demotion lowered
  the malware side too); v19 is 0.0% vs **35.1%**. An earlier note here paired v18's legit figure
  with v17's malware figure — corrected. The score-saturation half of that v17 finding is untouched
  and still belongs to item 10.
- **v18 before/after lives in `eval/baseline/v17/` vs `eval/baseline/v18/`** (arms A, B, C, F).
  Arms D and E were NOT re-run in v18, so their v17 numbers still stand and item 3's effect on
  real-malware recall is unmeasured.

Comparison context: OSCAR reports F1 0.95 (npm) on a real benchmark. **As of v22 this project can
finally answer in kind** — arm D's benign control was the single most valuable missing measurement
and it now exists, in two forms because the corpus holds two populations:

- **Arm G (matched)** — 100 compromised libraries vs **83 of their own clean predecessors**, the
  version published immediately before each compromise. **F1 0.8455** any-finding (recall 93.0%,
  precision 77.5%) and **0.7711** BLOCK-only (recall 64.0%, precision **96.97%**, FPR **2.41%**).
  This is the defensible headline, and it is **below OSCAR's 0.95** — say so plainly.
- **Arm H (broad)** — 399 purpose-built fakes vs 500 top-downloads packages. F1 0.7881 any-finding.
  **Biased in the tool's favour by construction** (popular packages vs obscure fakes) and its
  precision is optimistic by a bounded amount: the establishment guard fires on 19 benign records
  and cannot fire on the malicious half, so FPR 26.2% → worst case **30.0%**, precision 72.6% →
  **69.8%**. Quote the range.

**Never merge the two arms.** Two populations, two questions, and one carries a known asymmetry.
The most uncomfortable number is arm G's **32.5% any-finding FPR on matched clean libraries** —
*higher* than arm F's 25.9% on popular parents, which is exactly the optimism a popular-package
control hides. BLOCK-level remains the trustworthy operating point everywhere.

---

## Task Checklist

### ⏰ DATED — DONE in v18, and PROVEN IN THE FIELD at v20 (was: do this before 2026-09-01)
- [x] 0. **`dummy_timebomb` expires 2026-09-01 — NEUTRALISED in v18 by pinning the harness
        clock.** The hazard was: once the real date crossed the fixture's trigger, its payload
        would fire at baseline too, the D1 diff would go empty, and **D1 detection would
        silently drop to zero** — taking `d1_timebomb_live_run` and
        `dummy_timebomb_full_pipeline_flags_risk` with it. D1 is the flagship of the project's
        stated core contribution, so a silent zero there guts the headline claim.
        **FIXED by pinning the harness clock** rather than re-dating the fixture (re-dating
        buys one year and then recurs). `docker/run_layer3.sh` now LD_PRELOADs libfaketime in
        EVERY scenario: baseline/env/fuzz at `FAKETIME_BASE`, the clock scenario at
        `FAKETIME_CLOCK`. The D1 differential is now absolute — it no longer depends on the
        real date at all — and the only difference between baseline and clock is the date.
        Invariant: `FAKETIME_BASE < every fixture trigger < FAKETIME_CLOCK`, enforced OFFLINE
        by `tests/layer3_clock_pin.rs` (the live D1 tests do fail loudly, but they are
        `#[ignore]`d, so a plain `cargo test` would not have caught the drift).
        Changing the script requires a Docker image rebuild — it is COPY'd in.
        **v20 CONFIRMS THE FIX EMPIRICALLY.** Arm C was re-run on **2026-09-07, six days
        past the fixture's trigger date**, and `dummy_timebomb` is still detected via D1
        (it also picked up C1 this run). No run before the deadline could establish that
        the differential is genuinely date-invariant; this one does. The dated hazard is
        closed, not merely deferred.

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
- [x] Finalize evaluation method (v17: `--eval` harness + 6 arms; see Evaluation section)

### Precision fixes — items 1-11 ALL CLOSED as of v21 (from eval/REPORT.md, ranked)
- [x] 1. signatures.rs: stop treating an expired signing key as tampering (11/12 BLOCK-level FPs,
        worsens with time). Verify against the key that signed; expiry → INFO. Add a pinning test.

      > **⚠ EXPECTED EFFECT OF THIS FIX: arm B's headline recall drops from 91.4% to roughly
      > 25.7%, and arm A's flag rate falls. THIS IS THE CORRECT OUTCOME, NOT A REGRESSION.**
      > The 91.4% was produced by `signatures` firing on npm's own security-holding stubs (23 of
      > 32 true positives), which is post-hoc takedown information a consumer already gets from an
      > advisory feed — not detection. **Do not revert the fix to restore the number.**
      >
      > Acceptance criteria:
      > - BLOCK-level false positives on `eval/corpus/parent_benign.tsv` fall from **12/27 to
      >   4/27** (44.4% → 14.8%). Eight packages — `d3`, `escape-string-regexp`, `ffmpeg`,
      >   `grunt-cli`, `http-proxy`, `ms`, `mysql`, `shadowsocks` — are BLOCK'd by `signatures`
      >   and nothing else and must clear with no other change. The expected residue is exactly
      >   `{fabric, node-sass, sqlite, babel-cli}` (items 2, 5 and 6 own those).
      > - No package is BLOCK'd solely for carrying a signature from an expired-but-valid key.
      > - Report before/after against `eval/baseline/v17/arm{A..F}.metrics.json`.

- [x] 2. worm_signature: don't let ONE category BLOCK alone (`fabric`, `node-sass` flagged for
        shipping a release script); exclude build tooling unless reached from an install hook.
        Note `fabric` passes Layer 2 AND Layer 3 cleanly in arm F — the BLOCK is Layer 1's alone,
        with no dynamic behaviour to corroborate it. Finding split: `fabric` 1, `node-sass` 3.
        **First half done in v18 (per-category SUSPECT); the BUILD-PATH half only landed in
        v20** — it had been marked complete while no path predicate existed anywhere in the
        module. Two corrections v20 had to make to the wording above:
        (a) "reached from an **install hook**" breaks the arm D floor — 13 malicious packages
        declare a root `publishScript.js` as `main` with no hook at all, so reachability must
        span hooks ∪ `main` ∪ `bin` ∪ `exports`;
        (b) the ≥2-category aggregate also had to require **co-location in one file**, since it
        accumulated package-wide and two ordinary release scripts could BLOCK a legitimate
        package. `fabric` is now fully clean; `node-sass` keeps 3 findings by design
        (`lib/` is runtime code, and its `scripts/util/*` ARE hook-reachable).
- [x] 3. obfuscation: add a hex-IDENTIFIER-density check (`_0x[0-9a-f]{4,}` count / `0x` literal
        ratio). The v14 hex 4→8 change let the javascript-obfuscator family through, and
        ansi-styles@6.2.2 (real Sept-2025 clipper) passes all four layers.
- [x] 4. Recalibrate the static SUSPECT rules against the now-available benign corpus.
        **Target the PACKAGE count, not the finding count** — the package count is what a
        calibration change has to move: suspicious_strings 12 of 27 packages (43 findings),
        obfuscation 5 (20), dynamic_require 4 (8), install_script 5 (5). Also unaccounted for
        until now: shell_exfil on `shadowsocks`, version_diff on `bcrypt`. As a vector, B2
        reaches 18 of 27 legitimate packages (67%).
- [x] 5. A1: fold a trailing `.js`/`-js`/`_js` before the distance compare; widen top_packages.txt;
        consider scaling the distance threshold by name length (kills the d3.js→dayjs class).
- [x] 6. typosquat/namespace: don't accuse an established package (use the age/downloads already fetched).
- [x] 7. D3: gate on what the invoked export did. **DONE in v21 — but NOT as written here.**
        Requiring "one of L2's stronger sub-signals" was implemented and *measured as wrong*:
        `dummy_api_triggered`'s single `dns.lookup('evil.example.com')` trips none of the four, so
        the literal form deletes the project's own D3 detection (arm C 16/16 → 15/16).
        The discriminator that works is **relatedness**: demote when every observed side effect
        points back at the package itself — its own API host (`nodemailer` → `api.nodemailer.com`)
        or its own binary (`ffmpeg` → `/usr/bin/ffmpeg`). `ffmpeg` is the second instance and only
        became visible once item 8 let the dynamic layers reach it.
- [x] 8. Vendor dependencies into the L2/L3 mount. **DONE in v21.** Resolved on the host with
        `npm install --ignore-scripts`, mounted read-only at `/vendor`. Arm F Layer 2 reach
        **10 → 26 of 27**, Layer 3 10 → 25, `dyn_valid` 12 → 24; arm E `dyn_valid` 28 → 34.
        The wall-clock half is also done: the timeout was never *detected* (`timeout -k` re-raises
        SIGKILL, so `code() == Some(124)` could not match — which also meant the orphan-container
        cleanup never ran), and `--package-timeout` now bounds both layers together
        (`shadowsocks` 1210 s → 905 s). ⚠ Safety posture changed — see `eval/README.md`.
- [x] 9. Smaller items. **DONE in v21, except (d), which is not doable by a rule change.**
        (a) IOCs 1 → **7 variants** (the closed Shai-Hulud fingerprint, 48 package-versions) —
        **measured to add ZERO recall**: 44 matched vs 25, 0 as sole detector, arm D bit-identical.
        Identity confirmation, not detection; never cite it as recall.
        (b) `Kind::Pair` gives B3 its first path: **0/1 → 1/1**, arm C 13/14 → **14/14** vectors.
        (c) D2 mis-attribution root-caused to the env scenario's `HOME=/home/developer` vs the
        baseline's `/root` — an unconditional `~/.bashrc` write produced two different path strings
        that never cancelled. Fixed in `normalize_path`; arm E's D2 noise fell 7 → 2 fires.
        (d) `node-ipc@12.0.1` **cannot** be made to fire B4: the wiper is geo-gated, its lookups
        fail under `--network=none`, and the destructive branch never executes — there are no
        writes or deletes to detect. A sandbox-coverage limit on a single observation.
- [x] 11. **Do NOT attempt a third static demotion — measured dead end (v20).** After v20 the
        residual arm F false positives are dominated by `obfuscation` SUSPECT on four packages
        (`jquery`, `babel-cli` via bare `eval()`, lift 1.81; `lodash`, `d3` via the `Function()`
        constructor with a string body, lift 1.54). A solitude-gated demotion of those two
        sub-rules takes arm D to **427/499 = 85.6%**, below the 86.8% floor, and the
        establishment guard cannot rescue it because arm D has no registry path at all. This is
        recorded as DONE-as-in-SETTLED, not as work to do: **calibration is exhausted at this
        recall floor.** The remaining gains are items 7, 7b and 8.

- [x] 10. **Revisit severity assignment and score aggregation TOGETHER.** DONE in v19 as the
        capability tier + `capability_cluster` escalation. Severity is now three-tier in practice
        (capability / accusation / block); the noisy-OR `risk_score` is still reported-not-gating and
        its saturation is untouched — revisit if a scoring consumer ever needs it.
        Two measured facts drive this, both in the Risk-score section above: BLOCK fires on
        legitimate packages *more often* than on real malware (44.4% vs 37.5%), and `risk_score`
        does not gate the verdict and saturates (BLOCK spans 0.50–1.00, SUSPECT 0.17–1.00, six
        legitimate packages at 1.00). **Raising a score threshold cannot fix the FPR** — do not
        spend a pass trying. This item is sequenced last on purpose: per-check fixes move the
        inputs, so calibrating the aggregation first would just have to be redone.

---

## Tech Stack
- Language: Rust (Layer 0, 1), Docker + shell (Layer 2, 3)
- Container: Docker
- Monitoring: strace, tcpdump, DNS logging
- Clock manipulation: libfaketime
- Static analysis: custom Rust (regex + string patterns)
- Typosquatting: Levenshtein (custom Rust)
- Evaluation: `--eval` batch harness (pure-Rust metrics; hand-rolled CSV — writer-only need,
  and free text never enters a CSV). Corpora: OSV bulk export (`MAL-*` names) +
  DataDog/malicious-software-packages-dataset (real payloads; `zip` crate for ZipCrypto).

## Constraints
- npm-only (justification: most dangerous ecosystem due to install-time execution; independent of measurement paper)
- Docker required — host protection
- Dummy packages: local test only (never npm publish)
- Layer 0 → 1 → 2 → 3 sequential, single entry point npm-pre-scan
- Scope: only vectors an npm consumer can detect at install time (VCS/build compromise excluded)
- Evaluation corpora are NEVER committed: eval/samples/ holds live malware (encrypted at rest,
  gitignored), eval/runs/ holds result data, eval/corpus/ossf_npm_names.tsv is 12 MB generated.
  Only the curated manifests + eval/README.md + eval/REPORT.md are tracked.

## Environment
- Windows 11 → WSL2 → **Arch Linux (rolling)**. Location: **/home/hkkarch/dev/npm_pre_scan**
  (moved off WSL2/Ubuntu 26.04 on 2026-07-12; previously moved off NixOS 2026-07-01).
- Toolchain on this machine: Rust via **rustup** (user-level, `~/.cargo`; stable 1.97) — installed
  because a fresh Arch WSL had no `cargo`/`rustc`. Docker via **pacman** + systemd
  (`systemctl enable --now docker`); Arch WSL ships systemd as PID 1, so it is `systemctl`, NOT
  `service`. Repo was checked out **root:root** on this box (as after the v10 NixOS→Ubuntu move) and
  needed `sudo chown -R hkkarch:hkkarch` before cargo could write `target/`; `git config --global
  --add safe.directory` was also required.
- Docker group membership takes effect on next login; in a session where the shell predates
  `usermod -aG docker`, run docker-invoking commands under `sg docker -c '…'` (or `sudo docker`).

## References (independent justification base)
- Ladisa et al., "SoK: Taxonomy of Attacks on OSS Supply Chains", IEEE S&P 2023 — classification base
- Zheng et al., "OSCAR", ASE 2024 — comparison target, basis for Layer 3 gap
- Duan et al., "MalOSS", NDSS 2021 — comparison target (simplistic testing limitation)
- Huang et al., "DONAPI", USENIX Security 2024 — comparison target
- OSSF malicious-packages / OSV `MAL-*` bulk export — evaluation corpus for Layer 0 name checks
  at scale (216,885 names; the GitHub tree API truncates, the OSV zip does not)
- DataDog/malicious-software-packages-dataset (Apache-2.0) — real malicious payloads for Layers 1-3,
  since npm's takedown process defangs them (see eval/README.md for the safety posture)
- (KIISC measurement paper decoupled — no citation required)

---

## Coding Guidelines
1. Think Before Coding: state assumptions, ask if uncertain, surface tradeoffs.
2. Simplicity First: only what's asked, no speculative features, rewrite if overcomplicated.
3. Surgical Changes: touch only what's needed, don't improve adjacent code, match existing style.
4. Goal-Driven: define success criteria first; multi-step → plan then verify.

---
> This file is auto-maintained by the code-sync skill. Do not edit manually unless necessary.
