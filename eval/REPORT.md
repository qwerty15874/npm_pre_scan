# Evaluation report — npm-pre-scan v0.1.0

**Run date:** 2026-07-30 · **Host:** WSL2 / Arch Linux, Docker 29.6.2 · **Lists:** embedded snapshot (1137 unscoped / 94 scoped), not refreshed

First measurement of this tool against packages it did not ship with. Every prior
verification used a dummy package authored by this project, which confirms each layer *works as
designed* but cannot produce a recall figure, a false-positive rate, or an answer to "which layer
earns its keep."

Raw data for **most** claims below is in `eval/runs/arm{A..F}/` — `records.jsonl` (one lossless
record per package), `results.csv`, `findings.csv`, `metrics.json`. Reproduce with the commands in
each arm's section. A committed snapshot of the six `metrics.json` files is tracked at
`eval/baseline/v17/arm{A..F}.metrics.json` (`eval/runs/` itself is gitignored).

**Where to find per-finding file paths.** `findings.csv` is a flat summary and has no `file`
column, and its `evidence_count` refers only to Layer 2/3 **diff evidence** — so every row of
`armF/findings.csv` reads `evidence_count = 0` for Layer 0/1 findings whether or not the run used
`--eval-evidence`. The file path a Layer 1 finding fired on is carried by the `file` field of the
finding itself, inside `records.jsonl`, which is lossless. The four `worm_signature` paths cited in
§2 below are all present in `eval/runs/armF/records.jsonl`, and were re-derived independently by
scanning the published tarballs.

> Corrects an earlier note here which claimed those paths were unrecoverable and could be restored
> by re-running with `--eval-evidence`. Both halves were wrong: they were always in
> `records.jsonl`, and `--eval-evidence` would not have helped, because Layer 1 findings have no
> `evidence` field at all — `RiskReport.evidence` holds Layer 2/3 diff events only. A v18 re-run
> with the flag produced evidence on exactly one finding of 128 (`nodemailer`'s D3
> `trigger_on_use`, 15 lines), which is the expected result.

---

## Headline

**The detection layers work. The scoring on top of them does not.**

On its own dummy corpus the tool catches **16/16 packages — but 15/16 vectors** — with 0 false
positives, and only 9 of the 16 reach BLOCK. On 499 real malicious packages Layer 1 alone reaches
**88.8% recall**, and on 40 real payloads through all layers, **95.0%**.

But run it over 27 *legitimate, popular* packages and it accuses **26 of them** — **12 with a hard
`BLOCK`**. Only `chalk` comes through clean. As shipped, the tool would refuse to install `d3`,
`ms`, `mysql`, `ffmpeg`, `http-proxy`, `node-sass`, `grunt-cli`, `babel-cli`, `escape-string-regexp`,
`fabric`, `shadowsocks` and `sqlite`, and would raise suspicion on `lodash`, `react`, `express` and
`jquery`.

Two root causes account for most of it, and both are single-check problems rather than
architectural ones:

1. **A time-bomb in the signature check.** npm rotated its registry signing key; the old key
   expired 2025-01-29. `signatures.rs` treats "no unexpired key matches this signature" as evidence
   of tampering and returns `BLOCK`. Every package not republished since January 2025 is therefore
   blocked. This one check accounts for 11 of the 12 `BLOCK`-level false positives, and it will get
   worse over time, not better.
2. **Static heuristics tuned without a benign corpus.** `obfuscation`, `suspicious_strings`,
   `dynamic_require` and `worm_signature` fire on ordinary minified and build-script-bearing
   packages. `worm_signature` — the project's headline E1 differentiator — `BLOCK`s `fabric` and
   `node-sass` for containing the string `npm publish`.

Two results run the other way and are worth stating as plainly as the problems:

- **E1 is validated against real malware.** The single real-world IOC hash in `data/worm_iocs.txt`
  matched the actual Shai-Hulud patient-zero sample (`@ctrl/tinycolor@4.1.1`), all three worm
  heuristic categories fired, and E1 recall on the hand-labelled Shai-Hulud samples is 4/4.
- **Layer 2's baseline subtraction is genuinely precise.** Zero false positives across the 10
  legitimate, dependency-free packages that could be dynamically analysed — the first time that has
  been measured against real software rather than a two-line dummy.

---

## What was measured

| Arm | Corpus | n | Layers | Cost |
|---|---|---|---|---|
| A | Every npm name with a malicious-code advisory (OSV `MAL-*`) + legitimate parents | 216,888 | L0 name checks, offline | 43.7 s |
| B | Curated real malicious names + legitimate parents, via the live registry | 65 | L0 (malicious) / L0+L1 (benign) | 25.6 s |
| C | The project's own dummy packages | 19 | L0/L1 + L2 + L3 | 13.2 min |
| D | Real malicious payloads (DataDog dataset), static | 499 | L1 | 5.2 s |
| E | Real malicious payloads, all layers | 40 | L1 + L2 + L3 | 23.0 min |
| F | Legitimate packages through the dynamic layers — the first measured L2/L3 false-positive rate | 27 | L0–L3 | 24.0 min (37.1 at v21) |
| G | **Matched control (v22)** — 100 compromised libraries vs 83 of their *own* clean predecessors | 183 | L1 | 63 s |
| H | **Broad control (v22)** — 399 purpose-built fakes vs a 500-package top-downloads control | 899 | L1 | 3.2 min |

Arms G and H exist because arm D could produce a recall figure and nothing else. They are the only
arms that yield a precision or an F1, and they must never be merged — see the v22 section.

Corpus construction, provenance and the safety posture for the live-malware samples are documented
in `eval/README.md`.

### Three facts that shaped the design

1. **npm cannot supply real malicious code.** A taken-down package becomes either a 404 or a
   *security holding* stub. Some stubs retain their original version numbers with downloadable
   tarballs — but the content was republished defanged: verified 2026-07-30, `crossenv@1.0.0`,
   `ffmepg@1.0.2` and `jquery.js@1.0.2` all contain nothing but
   `console.log('this package is no longer dangerous')`. Real payloads therefore come from the
   DataDog corpus, and a clean verdict on a stub is classified `ARTIFACT_FN`, never `FN`.
2. **The sandbox cannot install dependencies** (`--network=none` + `npm install --offline`), so a
   dependency-bearing package yields an empty behaviour profile indistinguishable from a clean one.
   The harness records `declared_deps` and marks such entries `dyn_valid=false`, excluding them from
   Layer 2/3 denominators rather than counting a vacuous PASS as precision.
3. **Advisory feeds carry no vector labels.** Arm A's ground truth is "this name has a malicious-code
   advisory", not "this name is a typosquat", so arm A reports a *flag rate*, not per-vector recall.
   Per-vector recall is only claimed where the label was hand-verified (arms B and C).

---

## Arm A — Layer 0 name checks at scale (216,888 names, offline)

```sh
npm-pre-scan --eval eval/corpus/ossf_npm_names.tsv --eval eval/corpus/parent_benign.tsv \
             --eval-mode name-only --out-dir eval/runs/armA
```

| | value |
|---|---|
| Flag rate on malicious names | **1.6%** (3,451 / 216,861) |
| Precision | 99.9% (2 false positives out of 3,453 accusations) |
| FPR on legitimate parents | **7.4%** (2 / 27) |
| Wall clock | 43.7 s, zero network requests |
| Reproducibility | verified byte-identical across two runs (timestamps/timings excluded) |

**The 1.6% is not the indictment it looks like.** That corpus is dominated by mass-registered
dependency-confusion and spam names (median name length 19 characters; 8,614 names contain a run of
3+ digits; 6,331 exceed 40 characters) which are not typosquats of anything and lie outside what
A1/A2/A4 are designed to catch. A1 accounted for 3,042 of the 3,451 flags, A4 for 409, A2 for 2.

**The 7.4% FPR is the real finding.** Both false positives are hard `BLOCK`s on legitimate packages:

| Package | Check | Why |
|---|---|---|
| `sqlite` | A1 typosquat `BLOCK` | Levenshtein distance 1 from `sqlite3`, which is in the popular list. `sqlite` is itself a real package (5.1.1). |
| `babel-cli` | A2 namespace `BLOCK` | Flattens to the same form as `@babel/cli`, so a legitimate unscoped package reads as a dependency-confusion attack. |

The second is the "legit flat twin" class CLAUDE.md v16 already flagged as a residual risk. It is
now confirmed on a real, widely-installed package rather than hypothesised.

---

## Arm B — the shipped pipeline against real names (65 packages, live registry)

```sh
npm-pre-scan --eval eval/corpus/real_malicious_holders.tsv --eval eval/corpus/parent_benign.tsv \
             --eval-mode registry --out-dir eval/runs/armB
```

**This arm ran Layer 1 on the benign parents ONLY.** `metrics.json` → `by_layer[1]: ran 27,
skipped 38`: the 27 are the parents, and **all 38 malicious holder entries were Layer 0 only**. So
the arm is `L0 (malicious) / L0+L1 (benign)`, and everything below about its recall is a **Layer 0
figure** — consistent with `by_layer[0].sole_detector = 32`, and one more reason the number is a
`signatures` artefact rather than detection.

As shipped, this arm reports recall 91.4% and **FPR 93.3%**. Both numbers are misleading, and the
reason is the same check. Note the FPR denominator is **30**, not 27: `real_malicious_holders.tsv`
labels three reclaimed names (`mariadb`, `opencv.js`, `openssl.js`) `benign`, and two of them
(`opencv.js`, `openssl.js`) are BLOCK'd via META. The project's headline FPR is arm F's 96.3%
(26/27), which is the full pipeline over a benign-only corpus.

Restricting which checks are allowed to accuse separates the mechanisms (35 malicious, 30 benign):

| Checks allowed to accuse | TP | FN | FP | TN | Recall | FPR |
|---|---|---|---|---|---|---|
| All, as shipped | 32 | 3 | 28 | 2 | 91.4% | **93.3%** |
| Name checks only (A1/A2/A4) | 9 | 26 | 2 | 28 | **25.7%** | **6.7%** |
| Everything except `signatures` | 9 | 26 | 21 | 9 | 25.7% | 70.0% |
| `signatures` only | 32 | 3 | 13 | 17 | 91.4% | 43.3% |

**The apparent 91.4% recall is an artefact.** 23 of the 32 true positives were credited *solely* to
the `signatures` check firing on npm's own takedown stub — no name-attack detection took place. That
same check fires on 43% of legitimate packages. A check that accuses 91% of one class and 43% of the
other is not carrying the discrimination its `BLOCK` severity implies.

**The honest Layer 0 name-detection figure is 25.7% recall at 6.7% FPR.**

### What fires on legitimate packages (n=27 parents)

**Package counts, not finding counts, are the decision-relevant figure** — a calibration change has
to move the number of packages it touches. Both are given below. (Arm B and arm F produce an
identical benign finding set apart from arm F's one extra `trigger_on_use`, so this table doubles
as the arm F breakdown.)

| Layer | Check | Severity | Findings | Packages hit |
|---|---|---|---|---|
| L0 | `signatures` | **BLOCK** | 11 | **11** |
| L1 | `suspicious_strings` | SUSPECT | 43 | **12** |
| L1 | `obfuscation` | SUSPECT | 20 | **5** |
| L1 | `dynamic_require` | SUSPECT | 8 | 4 |
| L1 | `install_script` | SUSPECT | 5 | 5 |
| L1 | `worm_signature` | **BLOCK** | 4 | **2** — `fabric` 1, `node-sass` 3 |
| L0 | `maintainer` | SUSPECT | 4 | 4 |
| L1 | `network_imports` | SUSPECT | 4 | 4 |
| L0 | `typosquat` / `namespace` | **BLOCK** | 1 each | 1 each |
| L1 | `shell_exfil` | SUSPECT | 1 | 1 — `shadowsocks` |
| L1 | `version_diff` | SUSPECT | 1 | 1 — `bcrypt` |
| L3 | `trigger_on_use` | SUSPECT | 1 | 1 — `nodemailer` (arm F only) |

The last three appear in no earlier false-positive accounting in this project's docs.

Only `chalk` came through clean out of 27.

### Per-vector false positives — read the denominator

`metrics.json` → `by_vector[].false_hits` is a **distinct-package count within one arm**. It is
**not** additive across arms: `parent_benign.tsv` was scanned in arms A, B *and* F, so summing
double- and triple-counts the same packages. The figures below are **arm F only** — the one arm
that ran all four layers over the benign corpus — and are distinct legitimate packages out of 27.

| Vector | FP (arm F) | Packages |
|---|---|---|
| A1 | 1 | `sqlite` |
| A2 | 1 | `babel-cli` |
| A3 | 4 | `axios`, `mongoose`, `mssql`, `react` |
| B1 | 5 | `axios`, `bcrypt`, `fabric`, `node-sass`, `sqlite3` |
| B2 | **18 of 27 (67%)** | two thirds of the corpus carry at least one B2 finding |
| B3 | 1 | `bcrypt` |
| D3 | 1 | `nodemailer` |
| E1 | 2 | `fabric`, `node-sass` |
| META | 11 | `babel-cli`, `d3`, `escape-string-regexp`, `ffmpeg`, `grunt-cli`, `http-proxy`, `ms`, `mysql`, `node-sass`, `shadowsocks`, `sqlite` |
| A4, B4, C1–C3, D1, D2 | 0 | — |

### BLOCK-level false positives decompose almost entirely to one check

Per-package BLOCK causes, from `armF/findings.csv`:

| Cause | Packages |
|---|---|
| `signatures` only | `d3`, `escape-string-regexp`, `ffmpeg`, `grunt-cli`, `http-proxy`, `ms`, `mysql`, `shadowsocks` (8) |
| `signatures` + `typosquat` | `sqlite` |
| `signatures` + `namespace` | `babel-cli` |
| `signatures` + `worm_signature` | `node-sass` |
| `worm_signature` only | `fabric` |

**Demote `signatures` to INFO and the BLOCK-level false-positive set becomes exactly
`{fabric, node-sass, sqlite, babel-cli}` — 4/27 (14.8%), down from 12/27 (44.4%).** Eight packages
clear with no other change. That is the expected outcome of weakness #1 and its acceptance
criterion.

### BLOCK severity has no discriminative power

- Legitimate packages reaching BLOCK: **44.4%** (12/27, arm F `overall_block_only.fpr`).
- Real malicious packages reaching BLOCK: **37.5%** (187/499, arm D `overall_block_only_rates.recall`).

The BLOCK rate is *higher* on legitimate packages than on real malware. This is a sharper statement
of the precision problem than "26 of 27 accused", because it indicts the **severity ladder** rather
than the volume of findings: the tool's strongest signal currently carries negative information.

### A1 on the hand-labelled 2017 campaign: 9/30

Detected: `babelcli`, `crossenv`, `d3.js`, `gruntcli`, `mongose`, `mysqljs`, `nodesass`, `smb`,
`sqliter`. Two of those nine are **accidental** — `d3.js` matched `dayjs` at distance 2 (not `d3`),
and `smb` matched `pm2`. The mechanistically-correct count is 7/30.

Missed (21), in two distinct classes that the recorded `closest`/`distance` fields let us separate:

- **Suffix blindness (9):** `cross-env.js`, `fabric-js`, `http-proxy.js`, `jquery.js`, `mssql.js`,
  `nodemailer-js`, `nodemailer.js`, `proxy.js`, `sqlite.js`. `typosquat::bare_name` strips only the
  `@scope/` prefix, so `jquery.js` sits at distance 3 from `jquery` and never trips the ≤2 threshold.
- **Absent parent (12):** `ffmepg`, `nodecaffe`, `nodefabric`, `node-fabric`, `nodesqlite`,
  `mssql-node`, `shadowsock`, `sqlserver`, `tkinter`, and the three 404 names. Their parents
  (`ffmpeg`, `fabric`, `shadowsocks`, `tkinter`, …) are absent from `data/top_packages.txt`, so there
  is nothing for the distance check to be near. This is a corpus-coverage limit, not an algorithm one.

---

## Arm C — the dummy corpus (19 entries, all four layers)

```sh
npm-pre-scan --eval eval/corpus/dummies.tsv --eval-mode full --docker-timeout 900 \
             --out-dir eval/runs/armC
```

**16/16 packages, 15/16 vectors. FPR 0%.** All three benign controls (`dummy_benign_l3`,
`dummy_shai_hulud/clean`, `dummy_malicious_update/prev`) came through clean. This reproduces the
project's existing claims independently, through the batch driver — with two qualifications the
"100% recall" phrasing hid:

- **`overall.recall = 1.0` but `by_vector` B3 reports `expected 1, detected 0`.** Both are true:
  `dummy_malicious_update` was caught by B2, so the package-level verdict is a true positive while
  the B3 rule itself detected nothing. B3 has no path through the harness — it needs a paired
  prev/latest manifest kind that does not exist yet — so its recall is unmeasured, not zero. State
  this as **16/16 packages, 15/16 vectors**.
- **`overall_block_only.recall = 0.5625`.** Even on the tool's own dummy corpus, only **9 of 16**
  malicious fixtures reach BLOCK; the other 7 stop at SUSPECT. This figure appears in no other
  document, and it is the arm C counterpart to the BLOCK-severity problem measured in arms D and F.

Per-layer attribution — the "which layer earns its keep" number:

| Layer | Ran | BLOCK | SUSPECT | Sole detector | p90 |
|---|---|---|---|---|---|
| L0 | 3 | 2 | 1 | 3 | 311 ms |
| L1 | 16 | 3 | 3 | 2 | 3 ms |
| L2 | 13 | 5 | 3 | **5** | 16.2 s |
| L3 | 13 | 1 | 3 | **2** | 31.1 s |

Layers 2 and 3 were the *only* detector for 7 of 16 malicious dummies — the clearest available
evidence that the dynamic layers are not redundant with static analysis. D1/D2/D3 (`dummy_timebomb`,
`dummy_env_triggered`, `dummy_api_triggered`) are detected by Layer 3 alone, which is the project's
core claimed contribution.

Two caveats, both harness-side rather than detector-side:

- **B3 reports 0% recall** because the version-diff check needs *two* directories and this manifest
  scans `dummy_malicious_update/latest` alone. The package was still caught (via B2 `obfuscation`);
  the dedicated `version_diff` check simply had nothing to compare against. Expressing a paired-
  directory entry is a manifest-format gap.
- **`dummy_persistence` is attributed to D2** (`env_triggered`) as well as B4. Its `.bashrc` write is
  unconditional at import, so the Layer 3 env scenario is taking credit for behaviour it did not
  trigger — a mis-attribution in scenario diffing, not a missed or spurious detection.

Timing: median 19.7 s per package, but `dummy_slow_exfil` took **467 s** — 24× the median, from 35
sequential DNS lookups against the sinkhole. Worth knowing before anyone runs the dynamic layers over
a large corpus.

---

## Arm D — Layer 1 against real malware (499 samples, static)

```sh
npm-pre-scan --eval eval/corpus/datadog_static.tsv --eval-mode registry --out-dir eval/runs/armD
```

| | value |
|---|---|
| Recall (BLOCK or SUSPECT) | **88.8%** (443 / 499) |
| Recall (BLOCK only) | 37.5% (187 / 499) |
| Wall clock | 5.2 s for 499 packages (p50 2 ms) |

This is the strongest positive result in the report: Layer 1's static checks catch **89% of real,
in-the-wild malicious npm packages** with no execution and no network. B1 fired 311 times, B2 319,
E1 174.

**The 56 misses are dominated by packages with nothing to analyse.** Comparing scannable JS bytes
(`.js`/`.cjs`/`.mjs`/`.ts`) between detected and missed samples:

| | n | median JS | zero bytes | <200 B |
|---|---|---|---|---|
| Detected | 120 (sampled) | 5,461 B | 9 | 12% |
| Missed | 56 (all) | **402 B** | 15 | **50%** |

Half the missed samples contain under 200 bytes of JavaScript; 15 contain none at all
(`cassandra-driver-examples` and `mcp-lumin` ship only a `package.json`; `deploy-cdk`'s `index.js` is
zero bytes). These are dependency-confusion name-claims: the malice is in publishing to a name, not
in code, so a content scanner has nothing to find. None of the 56 declares an install hook.

I also tested and **rejected** a plausible-sounding hypothesis: that implausible version numbers
(`99.x`, `500.x`) mark these out. They appear in 7/56 misses but 63/443 detections, so the signal
runs the wrong way.

---

## Arm E — real malware through all layers (40 samples, Docker)

```sh
npm-pre-scan --eval eval/corpus/datadog_dynamic.tsv --eval-mode full --docker-timeout 600 \
             --out-dir eval/runs/armE
```

| | value |
|---|---|
| Recall (BLOCK or SUSPECT) | **95.0%** (38 / 40) |
| Recall (BLOCK only) | 67.5% (27 / 40) |
| E1 recall on the hand-labelled Shai-Hulud samples | **100%** (4 / 4) |
| Cost | 34 s per package (L1 6 ms, L2 15.8 s, L3 18.4 s mean) |

**E1 is validated against real malware.** `@ctrl/tinycolor@4.1.1` and `4.1.2` (Shai-Hulud patient
zero) and `ngx-bootstrap@20.0.5`/`20.0.6` were all caught, and the single real-world IOC hash in
`data/worm_iocs.txt` matched exactly:
`46faab8ab153fae6e80e7cca38eab363075bb524edd79e42269217a083628f09`. All three worm heuristic
categories (self-propagation, credential harvest, exfil/persistence) fired. This is the strongest
evidence in the report that the project's headline E1 work generalises beyond its own dummy.

### The dynamic layers added no unique detections on real malware

| Layer | Accused | **Sole detector** |
|---|---|---|
| L1 (static) | 38 / 38 | **16** |
| L2 (dynamic) | 22 | **0** |
| L3 (condition mutation) | 6 | **0** |

Compare arm C, where L2 and L3 were the sole detector for **7 of 16** dummies. Every real-malware
detection L2 or L3 made, Layer 1 had already made statically — at 6 ms instead of 34 s.

This is not evidence that the dynamic layers are worthless; it is evidence that **the dummy corpus
was built to require them and real-world malware mostly does not**. Real npm malware overwhelmingly
runs its payload from an install hook or at import with no condition gating, which static analysis
sees plainly. The condition-gated classes Layer 3 targets are real (D1/D2/D3 are documented attack
patterns) but rare in this sample of 40 — and, crucially, *the one real condition-gated payload here
went undetected anyway* (see `ansi-styles` below).

Two further caveats on this arm's dynamic numbers:

- **12 of 40 samples were excluded from the L2/L3 statistics** (`dyn_valid=false`) because they
  declare dependencies the offline sandbox cannot install. Their empty behaviour profiles are vacuous,
  not clean.
- L3 produced 6 findings total, all SUSPECT, none BLOCK, with D2 (`env_triggered`) firing 7 times.
  Given `dummy_persistence`'s known D2 mis-attribution in arm C, some of those are likely scenario
  noise rather than genuine environment gating.

### The two misses

Two entries are package-level false negatives (`classification = FN`): `ansi-styles@6.2.2` and
`stringmaster-pro@2.0.2`. Separately — and not the same list — `by_vector` records **two labelled
vector misses**: B3 `expected 1, detected 0` (`ansi-styles@6.2.2`) and B4 `expected 1, detected 0`
(`node-ipc@12.0.1`). `node-ipc` is a package-level **TP**, caught via B2;C1, so it does not appear
among the FNs, but **no B4 rule fired on it and B4 recall in arm E is 0/1.** `stringmaster-pro`
carries no vector label at all, so it belongs to no per-vector row.

**`ansi-styles@6.2.2` — the Sept-2025 chalk/debug compromise — passes all four layers.** This is the
most consequential single finding in the report: a crypto clipper injected into a package with
hundreds of millions of weekly downloads, and the tool returns `PASS` with zero findings. All four
layers ran validly (the package is dependency-free, so L2/L3 were meaningful, not vacuous).

The payload is 80 KB of hex-identifier-obfuscated JavaScript appended to the legitimate 2 KB
`index.js`, containing a `checkethereumw()` clipper. Measured against each Layer 1 rule:

| Layer 1 rule | Looks for | Present in the payload |
|---|---|---|
| `obfuscation` (hex) | 8+ **consecutive** `\xNN` escapes | only **4** `\xNN` escapes in the whole file |
| `obfuscation` (eval/atob/Buffer) | `eval(`, `atob(`, `Buffer.from(`, `Function(` | **zero** of all four |
| `suspicious_strings` | `process.env`, `/etc/passwd`, `~/.ssh` | **zero** |
| `network_imports` | `require('https'/'axios'/…)` | **zero** |
| — | | but **5,662** `0x…` literals and **314** distinct `_0x…` identifiers |

Two things went wrong together:

1. **The v14 precision fix opened this hole.** Raising the hex threshold from 4 to 8 consecutive
   escapes reduced false positives on `chalk`-style ANSI strings — and let the entire
   `javascript-obfuscator` family through. That family is exactly what the real 2025 npm attacks
   used, and it does not emit `\xNN` runs at all; it emits `_0x`-prefixed identifiers and short hex
   numeric literals.
2. **Layers 2/3 could not compensate**, because the clipper gates on `window.ethereum` — a browser
   wallet object that never exists under `node -e "require(...)"`. Layer 3's env scenario mutates
   `CI`/`HOME`/`USER`/`NODE_ENV`/`TERM`, none of which is a DOM global.

**`stringmaster-pro@2.0.2` is a genuine Layer 1 miss, not a weaker one.** Its 23 declared
dependencies set `dyn_valid=false`, which invalidates **Layers 2 and 3 only**. Layer 1 ran validly
and returned `PASS` with **zero findings** on a 9.8 KB `malicious_intent` sample. The dependency
count explains why the dynamic layers could not corroborate; it does not excuse the static miss.
Because the entry carries no `expected_vectors` label, it does not move any per-vector recall
figure — which is precisely why it needs stating here instead.

**`node-ipc@12.0.1` — B4 recall in this arm is 0/1.** The labelled protestware wiper was caught as
a package (`SUSPECT`, TP) but via **B2;C1**, not B4: the destructive file overwrite never triggered
the `mass_deletion` or `sensitive_file_write` rules that B4 exists for. It declares 4 dependencies,
so `dyn_valid=false` and the dynamic layers are excluded from its denominators, but Layer 1 ran and
produced 2 findings. A package-level TP obtained through the wrong vector is worth as little as a
miss when the question is "does B4 work on real malware" — and on the only real B4 sample in the
corpus, the answer is no.

---

## Arm F — the first measured Layer 2/3 false-positive rate (27 legitimate packages)

```sh
npm-pre-scan --eval eval/corpus/parent_benign.tsv --eval-mode full --docker-timeout 600 \
             --out-dir eval/runs/armF
```

Arm B capped the legitimate packages at Layer 1, so the dynamic layers' precision on real software had
still never been measured. This arm closes that.

Of 27 legitimate packages, **11 are dependency-free**, but only **10 completed a valid dynamic
run** — keep those two counts apart, they are not the same set. The other **16** declare
dependencies the offline sandbox cannot install; their empty profiles are vacuous and are excluded.
The eleventh dependency-free package, `shadowsocks`, errored out on the wall-clock timeout (below).

| Layer | False positives | Rate |
|---|---|---|
| L2 (dynamic, baseline-subtracted) | **0 / 10** | **0%** |
| L3 (condition mutation) | 1 / 10 | 10% |

**Layer 2's baseline subtraction holds up on real software.** Not one of `chalk`,
`escape-string-regexp`, `fabric`, `jquery`, `lodash`, `ms`, `nodemailer`, `react`, `semver` or
`sqlite` produced a single Layer 2 finding. That is a real validation of the v13 baseline-diff work
— previously evidenced only by `dummy_benign_l3`, a package whose entire body is `add(a, b)`.

**`fabric` is the instructive one in that list.** Layer 1 BLOCKs it via `worm_signature`, yet it
passes both dynamic layers cleanly — there is no behaviour to corroborate the static accusation.
That is direct evidence for weakness #2 below.

⚠ **`shadowsocks` exhausted the dynamic timeout in BOTH layers, with no finding and no recorded
cause.** From `results.csv`: `l2_status=error, l2_ms=605074, l3_status=error, l3_ms=605070,
total_ms=1210623, declared_deps=0`. A dependency-free, legitimate package hit the
`--docker-timeout 600` wall twice over. Consequences:

- It is **not** one of the ten packages that "produced no Layer 2 finding" — it produced no
  *result*. Earlier drafts of this report and of `CLAUDE.md` listed it there and omitted `fabric`.
- It alone accounts for **84% of arm F's 24.0-minute wall clock** (`timing.total_ms = 1437470`).
  **Without it, arm F takes 3.8 minutes.**
- This is a **different cost risk** from `dummy_slow_exfil`'s 467 s. That one is deliberate
  sinkholed DNS doing exactly what the fixture was built to do. Here there is no diagnosis at all:
  no finding, no error class beyond `error`, no partial profile. `dyn_valid` cannot screen for it,
  because the package legitimately declares zero dependencies. Known limitation, currently unfixed.

**Layer 3's one false positive names a structural limit of D3.** `nodemailer` →
`trigger_on_use (D3) SUSPECT: Import-phase side effect detected: network activity`. The fuzz scenario
enumerated `nodemailer`'s exports, invoked them, and one of them opened a network connection — because
that is what an SMTP library does when you call it. The fuzzer *caused* the behaviour it then reported
as suspicious.

This is not a tuning problem. D3's premise is "invoke the public API and see whether anything
happens", and for any package whose legitimate purpose *is* network I/O, something always happens.
Distinguishing a trigger-on-use payload from a library doing its job needs a signal beyond "an export
touched the network" — the destination, for instance (an egress host or IP literal unrelated to the
package's stated purpose), which Layer 2's classifier already reasons about.

Note also that arm F's headline FPR is **96.3% (26/27)**, unchanged from arm B: the extra layers added
essentially no new false positives, because Layers 0 and 1 had already accused nearly everything.

---

## v22 — arm D gets a benign control: the project's first precision and F1 (2026-09-18)

Closes the item every previous section named as the most valuable missing measurement: **arm D had
no benign control, so 499 real malicious samples could produce a recall figure and nothing else.**
Two controls were built, because the corpus contains two populations that need different ones, and
they are reported separately throughout. Baselines: `eval/baseline/v22/`.

**Headline: on a matched control the tool reaches F1 0.8455 at any-finding and 0.7711 at
BLOCK-only, and BLOCK-level precision is 96.97% at a 2.41% false-positive rate.** The same
measurement shows the flip side plainly: **any-finding FPR against matched clean libraries is
32.5%, higher than arm F's 25.9% against popular packages.** Precision measured against popular
packages was optimistic, and now there is a number for how much.

### Why two controls

`datadog_static.tsv`'s 499 samples are two different things:

- **100 `compromised_lib`** — real, legitimate libraries with an injected payload. For these a
  *matched* control exists: the last version published **before** the compromise. Same package,
  same author, same code style, differing only by the payload. 94 of the 100 had a recoverable
  predecessor on the live registry (3 packages fully unpublished, 3 with no earlier version); they
  collapse to **83 distinct `package@version`** rows because several packages were compromised
  across two consecutive versions.
- **399 `malicious_intent`** — packages published to be malicious. They have no legitimate twin at
  all, so the only available control is a broad legitimate sample.

Blending these into one figure would be meaningless, so they are two arms with two manifests and
two runs. A new corpus group, `benign_control`, keeps them out of `parent_benign`'s rollups.

### Arm G — matched: 100 compromised libraries vs 83 of their own clean predecessors

| operating point | TP | FP | FN | TN | recall | FPR | precision | **F1** |
|---|---|---|---|---|---|---|---|---|
| any finding | 93 | 27 | 7 | 56 | **0.9300** | 0.3253 | 0.7750 | **0.8455** |
| BLOCK only | 64 | 2 | 36 | 81 | 0.6400 | **0.0241** | **0.9697** | 0.7711 |

**This is the strongest control the corpus admits**, and it says two things at once.

**BLOCK is trustworthy.** 2 false positives across 83 clean libraries, 96.97% precision. A BLOCK
verdict on a real package is worth acting on. The cost is recall: BLOCK alone catches 64 of 100.

**SUSPECT is still noise-dominated, and worse than arm F suggested.** 27 of 83 clean predecessors
collect at least one accusation — **32.5%**, against arm F's 25.9% on 27 popular parents. The
composition is the familiar one: `obfuscation` accounts for 24 of the 27, exactly the source v20's
item 11 measured as non-demotable at this recall floor. That conclusion now rests on 83 matched
libraries rather than 27 hand-picked parents.

**The comparison is clean.** The establishment guard (`demote_sole_network_import`) fires on
**zero** records in this arm, so the benign half received no leniency the malicious half could not
also receive — a real risk here, since the benign entries carry a registry document and the sample
entries do not.

### Arm H — broad: 399 purpose-built fakes vs a 500-package top-downloads control

| operating point | TP | FP | FN | TN | recall | FPR | precision | F1 |
|---|---|---|---|---|---|---|---|---|
| any finding | 344 | 130 | 55 | 367 | 0.8622 | 0.2616 | 0.7257 | 0.7881 |
| BLOCK only | 111 | 13 | 288 | 484 | 0.2782 | 0.0262 | 0.8952 | 0.4245 |

**Read this arm with two corrections applied.**

**It is biased in the tool's favour by construction.** Popular, well-maintained packages versus
tiny, obscure, freshly-published fakes: the two populations differ in every respect except being npm
packages. It answers "does the tool cry wolf on what people actually install?", not "can it separate
malicious from legitimate packages of similar shape".

**Its precision is optimistic by a bounded amount.** The establishment guard fired on **19 benign
records, all of which are true negatives only because of it** — and it cannot fire on the malicious
half, which has no registry document. Worst case, those 19 are false positives: FPR
26.2% → **30.0%**, precision 72.6% → **69.8%**. Quote the range, not the point estimate.

Three entries returned `registry_not_found` and are correctly excluded from every denominator.

### Side effect: B3 finally has enough observations to judge

Arm H's 500-name control gives per-check false-positive rates on a population large enough to
matter — the previous benign corpus was 27 packages:

| check | distinct legitimate packages flagged | rate |
|---|---|---|
| `obfuscation` | 76 | 15.2% |
| `version_diff` (B3) | 37 | **7.4%** |
| `computed_load` | 37 | 7.4% |
| `network_imports` | 23 | 4.6% |
| `worm_signature` (E1) | 17 | 3.4% |
| `suspicious_strings` | 13 | 2.6% |
| `install_script` | 9 | 1.8% |
| `shell_exfil` | 6 | 1.2% |

**B3 is measurably noisy.** Before v22 it had two benign observations and one dummy true positive;
it now has **37 false positives across 500 legitimate packages** and still no real-malware true
positive. The v21 note that "B3's precision is still unmeasured on real malware" stands, but the
benign side is no longer unmeasured — and it is not good. `obfuscation` leading at 15.2% is
consistent with arm G and with v20's item 11.

C3 is untouched by these arms: both are Layer 1 only, and `native_addon` is a Layer 2 check.

### What this establishes, and what it does not

- **The project can now state a precision and an F1.** It could not before. The defensible headline
  is arm G: **F1 0.8455 any-finding, 0.7711 BLOCK-only, on a matched control.**
- **It is below OSCAR's reported F1 0.95 (npm).** Stated plainly rather than framed away. Arm G is
  also a harder test than a mixed benchmark — every benign entry is a real library that was
  compromised one version later.
- **The two arms must never be merged.** Different populations, different questions, and one of them
  carries a known asymmetry.
- **Neither arm exercises Layers 0, 2 or 3.** Both are Layer 1 only, matching arm D. The dynamic
  layers' contribution to precision is still unmeasured on real malware.
- **83 is not 100.** Six compromised entries have no usable control, and the 83 rows cover 94
  compromised versions, so the matched arm is not a perfect partition of the compromised half.
- **The clean predecessors are assumed clean.** They are the version published before the known
  compromise; nothing here proves an earlier compromise did not exist.

---

## v21 — coverage pass: the three open items (2026-09-15)

Queue items **7, 8 and 9** — everything v20 left open. Baselines in `eval/baseline/v21/`, with the
drift-free before-side preserved alongside in `eval/baseline/v21base/`.

**Headline: the dynamic layers roughly doubled their reach, and arm F's any-finding FPR fell
29.6% → 25.9% while that happened.** Layer 2 went from running on 10 of 27 legitimate packages to
**26**, Layer 3 from 10 to **25**, and admissibility (`dyn_valid`) from 12 to **24**. Every floor
held: arm D **87.58%** (floor 86.8%), arm E **97.50%** (floor 95.5%), arm C **16/16 packages**, and
BLOCK-level FPR **0.0%** in both benign arms. Arm C also closed its last gap — **14/14 vectors at
full recall**, B3 having produced the first true positive in the project's history.

v20 closed the calibration road: item 11 measured that a third static demotion takes arm D to
85.6%, below its floor. Everything here is **coverage** work — reaching packages and vectors the
tool could not previously reach — not threshold tuning.

### Method change: the before-side was re-measured at HEAD first

Arms B and F hit the live registry, and v20 had already lost a per-check figure to republication.
Every v21 figure below is therefore compared against a **fresh run of the unmodified HEAD binary**
(`eval/baseline/v21base/`), not against `eval/baseline/v20/`.

That was not ceremony. Between the v20 arms (2026-09-07) and this baseline (2026-09-15), with **no
code change whatsoever**, arm B's any-finding FPR fell **30.0% → 26.7%**: `nodemailer`'s
`version_diff` (B3) finding disappeared because the package was republished again. Measured against
the committed v20 baseline, that drift would have been credited to this pass. **Arms A and D came
back bit-identical**, which is what makes the arm B delta attributable rather than noise.

The same drift changed what item 7 could achieve. In the v20 arm F run `nodemailer` was accused by
*both* B3 and D3, so removing D3 could not have moved the package count; at the v21 baseline it is
accused by **D3 alone**. The fix did not get better — the corpus moved underneath it. This is the
concrete argument for re-measuring the before-side rather than reusing a committed one.

### Item 7 — D3's premise, fixed by relatedness rather than by strength

§7b proposed requiring "one of L2's stronger sub-signals" instead of a bare `import_side_effect`.
**Implemented literally, that deletes the project's own D3 detection.** `dummy_api_triggered`
beacons with a single `dns.lookup('evil.example.com')`, which trips none of the four: not a known
egress host, not an IP literal, 1 query against a 10-query DNS-tunnel threshold, a 4-character
label against a 20-character encoded-label threshold, no credential read. Arm C would have gone
16/16 → 15/16 packages and D3's only true positive to 0/1.

A live capture said what the real discriminator is. No run in `eval/runs/` had ever recorded it —
`records.jsonl` stores only `evidence_count` — so `nodemailer` was scanned directly:

```
dns:api.nodemailer.com
connect:127.0.0.1:65535      <- the in-container sinkhole, not a real peer
```

Everything else in the diff was the harness's own scaffolding. The egress is to a host bearing
**the package's own name**, which is precisely §7b's "an egress host *unrelated to the package's
stated purpose*", read from evidence the finding already carries.

`demote_self_referential_d3` demotes a D3 accusation to a capability when every observed side
effect points back at the package itself. It is narrow on four axes: only findings originating from
a bare `import_side_effect`; only SUSPECT severity, since a BLOCK one implies a sensitive read that
raises its own finding; only when **every** observation matches, so one unrelated lookup alongside a
related one still accuses; and never when a durable write or delete is present.

This required preserving which Layer 2 rule fired. `classify_scenario` overwrote `check` with the
scenario name, so a credential read reaching D3 was indistinguishable from a bare side effect;
findings now carry `l2_check`, a diagnostic improvement in its own right.

**The rule covers two dimensions because the corpus produced two instances.** The second,
`ffmpeg`, only became visible once item 8 let the dynamic layers reach it:

```
proc:/bin/ffmpeg   proc:/usr/bin/ffmpeg   proc:/usr/local/bin/ffmpeg   ...
```

— a PATH search for the one binary the package exists to run. Same premise failure, process
dimension instead of network. A payload spawning `/bin/sh` or `curl` matches neither.

### Item 8 — the two failures that kept the dynamic layers small

**8a. A timeout was never recognised as one.** `run_docker` tested `status.code() == Some(124)`.
The wrapper is `timeout -k 5`, and when the grace period escalates GNU `timeout` re-raises SIGKILL
**on itself**, so the caller observes a signal death: `code()` is `None`, never `Some(124)`. The
branch could not fire. Both consequences were load-bearing:

- the diagnosis degraded to `Docker run failed (exit signal: 9 (SIGKILL))`, and `metrics.json`
  reported `"timeout": 0` for a run containing two 605-second kills;
- the `docker rm -f` cleanup lived inside that same branch, so **the orphan-container guard never
  ran on the path that actually occurs**. During this pass two orphaned containers from a dead PID
  were found still running and had to be removed before the arms could be trusted — exactly the
  "holding its mounts and skewing every subsequent measurement" failure the function's own doc
  comment warns about.

Timeouts are now detected by signal as well as by code, and `Outcome::Timeout` — declared, counted,
classified, and **never once constructed** — has a construction site.

**It is deliberately not promoted whenever a layer times out.** `Outcome::Timeout` classifies as
`Error`, which drops a record from every denominator. `shadowsocks` times out in both dynamic layers
but its Layer 1 `shell_exfil` finding is a genuine arm F false positive: promoting unconditionally
would have taken the benign denominator from 27 to 26 and improved the headline FPR **by losing a
false positive to a Docker stall**. A record is disqualified only when the timeout left *nothing*
observed; otherwise the stall is recorded in `outcome_detail` and the record is still scored.
`dyn_valid` additionally now requires that no dynamic layer was killed — at the baseline
`shadowsocks` reported `dyn_valid: true` on two layers that had observed nothing at all.

Read `outcomes.timeout` accordingly: it counts records *disqualified* by a timeout, not records
containing one. Layer-level stalls are visible in `dyn_valid`, the per-layer `note`, and
`outcome_detail`.

**8b. `--package-timeout`.** One `--docker-timeout` bounded a single `docker run`, so a package
stalling in both layers cost twice the budget. The budgets compose: each run gets the smaller of the
per-run budget and what remains of the package's. `shadowsocks` went **1210 s → 905 s**, its Layer 3
note reading `exceeded its 294s wall-clock budget`. The remaining-seconds clamp is load-bearing
rather than cosmetic: `timeout 0 CMD` means *no* timeout in GNU coreutils, so an exhausted budget
reaching the command line as `0` would make the tightest case unbounded.

**8c. Vendoring.** `npm install --offline` under `--network=none`, against a loopback registry
nothing listens on, cannot fetch anything; the install failed, `require()` threw
`MODULE_NOT_FOUND`, both were swallowed by `|| true`, and the layer produced an empty profile
indistinguishable from a clean package. Dependencies are now resolved **on the host** with
`npm install --ignore-scripts` and mounted read-only at `/vendor`; the container hydrates its work
tree from it at every rebuild, which is what keeps Layer 2's baseline/real install symmetry
byte-identical.

Two invariants constrained the design. Layer 1 must never see `node_modules` — `js_files` walks the
whole tree with no exclusion, so vendoring into the package directory would have made Layer 1 scan
every dependency's source and detonate the FPR; a separate mount avoids that entirely. And
`--ignore-scripts` is what keeps the host safe: install-hook behaviour is precisely what Layer 2
exists to observe, and it is still observed only inside the container.

⚠ **This changes the project's stated safety posture, and `eval/README.md` has been corrected rather
than left standing.** The host now resolves dependency trees *declared by* real malicious samples.
It never installs their own code (only `package.json` is copied across) and no lifecycle script runs
anywhere in the tree — so "nothing is ever executed on the host" still holds, while "nothing is ever
installed" no longer does.

### What item 8 bought

Arm F (27 legitimate packages):

| | v21base | v21 |
|---|---|---|
| Layer 2 ran | 10 | **26** |
| Layer 3 ran | 10 | **25** |
| admissible to the dynamic denominators (`dyn_valid`) | 12 | **24** |
| packages whose dependencies were vendored | 0 | 14 |
| `shadowsocks` wall clock | 1210 s | **905 s** |
| arm wall clock | 24.1 min | 37.1 min |

Arm E (40 real payloads): `dyn_valid` **28 → 34**, 6 samples vendored.

The arm got 13 minutes longer because 16 more packages now run two Docker layers each. That is the
cost of the coverage, and it is the expected shape.

### The coverage expansion exposed false positives that were previously hidden

This cuts against the headline and belongs next to it. With only 10 of 27 packages reaching the
dynamic layers, arm F's false-positive rate had been measured over a **partially-blind pipeline**.
Running all 27 surfaced two Layer 2/3 false positives that had always been there and had simply
never been looked for:

- **`ffmpeg` → `trigger_on_use` (D3)** — the `nodemailer` defect in the process dimension, now
  covered by item 7's gate;
- **`bcrypt` → `native_addon` (C3)**, which fired only once vendoring let its prebuilt
  `bcrypt.musl.node` actually load. `bcrypt` was already accused via B3, so the package count did
  not move — but **C3 now has its first false positive**, and its coverage-matrix row changes from
  "dummy only, no real sample" to a measured FP on a legitimate package.

An intermediate arm F carrying the network-only form of the gate is preserved at
`eval/runs/v21netgate-armF`: it shows `nodemailer` clean and `ffmpeg` newly accused — **29.6% held
exactly flat while its composition changed completely**. Without that intermediate the final 25.9%
would look like a simple two-package win rather than one fix, one newly-exposed defect, and a
second fix.

### Item 9(b) — B3 finally has a path, and it is a true positive

B3 reported 0/1 in arms B, C and E alike. The cause was never the rule: `run_version_diff_local`
had **zero production call sites**, and no manifest shape could hand a check two versions. The
prev/latest fixture pair had been sitting in `dummy_packages/` the whole time, carried in
`dummies.tsv` as two independent `dir` rows whose note named a function nothing called.

`Kind::Pair` (`prev::latest`) closes it. Arm C: **B3 0/1 → 1/1**, `version_diff` BLOCK firing on
`dummy_malicious_update` for the first time, taking arm C from **13/14 to 14/14 vectors at full
recall**. A malformed pair is a parse error rather than a half-scan, because diffing against a
missing predecessor would report every file as newly introduced — a fabricated detection, which is
worse than a miss.

The `prev` directory is **kept** as its own benign `dir` entry: it is a genuine precision control,
and dropping it would have quietly removed one of only three in the dummy corpus — which is how
`dummies_manifest_has_benign_precision_controls` caught the first attempt. Separately,
`fixture_exercises_every_kind` was hardcoding five kinds, so it did not enforce its own name and
passed unchanged when a sixth was added; it now iterates `Kind::ALL`.

**B3's precision is still unmeasured on real malware.** One dummy true positive is not a
calibration, and B3 still carries 1 false positive on the benign corpus (`bcrypt`).

### Item 9(c) — `dummy_persistence`'s D2, root-caused

The env scenario runs with `HOME=/home/developer`; the baseline runs as root. The fixture appends
to `os.homedir()/.bashrc` **unconditionally at import**, so it happened in both runs — but as
`/root/.bashrc` and `/home/developer/.bashrc`, two strings that did not cancel in the normalized set
difference. Layer 3 then claimed credit for behaviour the env mutation did not trigger.
`normalize_path` now folds home roots to `$HOME`, exactly as it already folded `/tmp` and the npm
cache.

Arm C: `dummy_persistence` loses both D2 findings and keeps its `B4 sensitive_file_write` BLOCK, so
it stays a true positive attributed to the vector it actually exercises. `dummy_env_triggered` keeps
its D2 — the control proving the phantom was removed and not the capability.

**Second effect, on real malware:** arm E's `env_triggered` fires fell **7 → 2** with recall
bit-identical. The report had already suspected "some of those are likely scenario noise rather than
genuine environment gating". Confirmed and quantified: five of the seven were the `HOME` artifact.

### Item 9(a) — the IOC set is 7 variants wide, and adds no recall

`data/worm_iocs.txt` held one real hash. Hashing every `bundle.js` across all 539 DataDog sample
zips returns a small closed set: **7 distinct payload variants across 48 compromised
package-versions**, clustered by victim organisation — what one campaign shipping per-victim
rebuilds looks like. All 7 are embedded with per-variant provenance.

**These hashes come from the corpus arms D and E score against, so the contribution is reported
separately and never folded into a headline.** Measured on arm D:

| | v21base | v21 |
|---|---|---|
| packages with a known-IOC hash match | 25 | **44** |
| IOC hash as **sole** detector | 0 | **0** |
| overall recall | 0.8758 | **0.8758** (bit-identical) |

**The extension adds identity-level confirmation, not recall.** Every one of the 44 was already
detected by other checks, so the self-grading risk is not merely disclosed — it is *measured at
zero*. Arm E's BLOCK-level recall does rise 0.6500 → **0.6750**, which is the same effect: existing
detections hardening to BLOCK, not new packages caught. **The IOC list must not be cited as evidence
that hash matching improves detection on this corpus.**

### Item 9(d) — not fixed, and why it cannot be

`node-ipc@12.0.1` is the corpus's **only** real B4 sample and its B4 recall is 0/1. The cause is not
a rule gap: the wiper is **geo-gated**, its lookups to 8.8.8.8/1.1.1.1 fail under `--network=none`,
and the destructive branch therefore never executes — producing no writes and no deletes at all. No
loosening of `SENSITIVE_WRITE_PATHS` or `WIPER_DELETE_THRESHOLD` can fire on behaviour that never
happened, and Layer 3's three scenarios (clock, env, fuzz) mutate none of the conditions involved.
Recorded as a **sandbox-coverage limitation resting on a single observation**, not as tuning work.
Closing it needs a mutation scenario that satisfies network-condition gates.

### v21 results, all six arms

All figures `eval/baseline/v21base/` → `eval/baseline/v21/`.

| arm | n | metric | v21base | v21 |
|---|---|---|---|---|
| A — names at scale | 216,888 | recall / FPR | 0.0131 / 0.0370 | **bit-identical** |
| B — L0+L1, live registry | 65 | recall / FPR | 0.8571 / 0.2667 | **bit-identical** |
| C — dummies, all layers | 19 | packages / vectors | 16/16, 13/14 | **16/16, 14/14** |
| D — 499 malicious, L1 | 499 | recall | 0.8758 | **0.8758** (floor 0.868) |
| E — 40 malicious, all layers | 40 | recall | 0.9750 | **0.9750** (floor 0.955) |
| E — " | 40 | BLOCK-only recall | 0.6500 | **0.6750** |
| F — 27 legitimate, all layers | 27 | any-finding FPR | 0.2963 | **0.2593** |
| F — " | 27 | BLOCK-level FPR | 0.0000 | **0.0000** |

### What this pass does NOT establish

- **25.9% is not comparable to 29.6% as a like-for-like precision improvement.** The pipeline
  measuring it changed underneath: 16 more packages now reach the dynamic layers. The number fell
  *and* the thing being measured got larger. Both facts must be quoted together.
- **The remaining 7 are unchanged in character.** `obfuscation` ×4 (`jquery`, `babel-cli`, `d3`,
  `lodash`), `node-sass` (install_script + worm_signature, by design), `bcrypt` (B3 + C3), and
  `shadowsocks` (shell_exfil). v20's item 11 finding stands: these are packages that genuinely
  *have* the capability, and calibration remains exhausted at this recall floor.
- **C3 and B3 are now measurably imprecise and were not before.** C3's first false positive appears
  here; B3's sole true positive is a dummy. Neither has enough real-malware observations to
  calibrate against.
- **No F1 should be claimed.** Arm D still has no benign control — the single most valuable missing
  measurement in the project, unchanged by this pass. *(Closed in v22: arm G reaches F1 0.8455
  any-finding / 0.7711 BLOCK-only against a matched control.)*
- **The IOC extension contributes no recall** and must not be cited as if it did.
- **`node-ipc`'s B4 miss is untested, not fixed.**

---

## v20 — precision pass 2: false positives cut again, recall untouched

Queue items **4 (continued) and 9 (partial)**, plus the unimplemented half of item 2. Items 7, 8
and 7b remain open. Baselines in `eval/baseline/v20/`.

**Headline: arm F any-finding FPR 48.1% → 29.6% and arm B 46.7% → 30.0%, with every recall figure
bit-identical to v19.** Arm D stayed at exactly 437/499 true positives (87.6%), arm E at 39/40
(97.5%), arm C at 16/16, and BLOCK-level FPR remained **0.0%** in every arm. Arm F's clean count
went 14 → **19** of 27; arm B's true negatives 16 → 21.

### What the measurement said, and why it overturned a v19 decision

Decomposing arm F's 13 remaining false positives per check, and re-running v19's own lift method
(arm D's 499 real malicious samples against arm F's 27 legitimate parents), found that **the largest
single false-positive source in the tool was a rule v19 itself had introduced**:

| rule | malicious | benign | lift | sole accusing detector |
|---|---|---|---|---|
| `capability_cluster` | 10/499 (2.0%) | 5/27 (**18.5%**) | **0.11** | **0 of 539 malicious**; 1 benign (`mongoose`) |
| `network_imports` | 174/499 (34.9%) | 4/27 (14.8%) | 2.35 | 13 malicious; 3 benign |

`capability_cluster` is inverted by a factor of nine — far worse than the lift < 1.2 bar v19 used to
demote four rules — and across arms B, C, D, E and F it was the sole accusing detector on exactly
one package, which is legitimate. It also has **no operating point at all**: capability counts are
bounded at 3 in *both* corpora (benign `{0:13, 1:7, 2:2, 3:5}`, malicious `{0:289, 1:153, 2:47,
3:10}`), so the threshold is inverted at 3 and unreachable dead code at 4. The capability sets
overlap almost entirely — benign clusters draw `{dynamic-require, env-read, install-hook,
maintainer-change}` and malicious ones `{dynamic-require, encoded-blob, env-read}` — which is why
counting members of a pool of individually-inverted signals cannot discriminate.

**v19's conjunction hypothesis is refuted, not mis-tuned.** The capability *tier* stays; the
conjunction rule is removed. It was removed rather than demoted to INFO because the stated reason
for emitting a real finding — keeping `by_vector`/`sole_detector` consistent with `classification` —
holds only while the finding accuses, and `is_accusing` does not count INFO. A demotion pays the
full metric cost of removal and keeps the code.

`network_imports` is the opposite case: it genuinely discriminates (lift 2.35, comparable to
`shell_exfil`'s ~4.3, which v19 deliberately kept), so demoting it wholesale would be wrong. But as
a **sole** signal it inverts, and every legitimate package it fires on is a library whose *purpose*
is network I/O. It is now demoted to a `network-io` capability only when it is the only accusation
**and** the package is itself established.

### Two places where the requested fix, implemented literally, breaks a recall floor

Both were caught by measuring before writing code, and both are pinned by tests carrying the
numbers so a future simplification fails in `cargo test` rather than six hours into an arm run.

- **Solitude alone as the `network_imports` gate.** Applied everywhere it costs arm D 19 records
  (437 → 418, 83.8%) and arm E one (39 → 38, 95.0%) — *both* floors. The establishment gate confines
  it to the registry path, and the three-state `Option<bool>` is the load-bearing part: `None` means
  "never asked" and never demotes. All 539 arm D/E entries are local samples with no registry
  document, so the guard is structurally incapable of firing there — the floors hold **by
  construction**, which the arm D run confirmed (`B2` fires 299 → 299, unchanged).
- **"Unless reached from an install hook" as the `worm_signature` exclusion.** 13 malicious packages
  ship exactly `package.json` plus a root `publishScript.js`, declare it as `main`, and have **no
  install hook at all**; their entire Layer 1 output is one `self_propagation` finding on that file.
  A hooks-only rule loses all 13: arm D 87.58% → **84.97%**, against an 86.8% floor. Reachability
  therefore spans **install hooks ∪ `main` ∪ `bin` ∪ `exports`**, which is also the precise
  definition of build tooling — code that ships in the tarball but is not what a consumer executes.
  Measured loss on that basis: **zero** across arms B, C, D and E.

### Why the guard is safe for a compromised established package

That class — `ansi-styles@6.2.2`, the Sept-2025 chalk/debug crypto clipper — is the most dangerous
one, and suppressing a signal for established packages could plausibly weaken it. It does not, for a
structural rather than a lucky reason: **`version_diff` is a built-in veto.** It emits SUSPECT for a
*newly introduced* network import and runs on exactly the path where the guard is active, so the
guard only ever suppresses an import that is **not new**. A compromise that *adds* network I/O — the
definition of the attack class — breaks solitude and the guard stands down.

`ansi-styles@6.2.2` confirms it twice over: its only finding is an `obfuscation` BLOCK for 314
distinct `_0x…` identifiers, and `network_imports` never fires on it at all (the clipper hooks
browser globals rather than requiring an HTTP client).

### Package-level attribution, arm F

Cleared: **`axios`, `fabric`, `http-proxy`, `mongoose`, `proxy`**. **Newly accused: none.**

| package | v19 | v20 |
|---|---|---|
| `axios` | `capability_cluster`, `network_imports` | **clean** |
| `mongoose` | `capability_cluster` | **clean** |
| `http-proxy` | `network_imports` | **clean** |
| `proxy` | `network_imports` | **clean** |
| `fabric` | `capability_cluster`, `worm_signature` | **clean** |
| `bcrypt` | `capability_cluster`, `version_diff` | `version_diff` |
| `node-sass` | `capability_cluster`, `install_script`, `worm_signature` | `install_script`, `worm_signature` |
| `nodemailer` | `network_imports`, `trigger_on_use` | `trigger_on_use`, `version_diff` |
| `jquery`, `lodash`, `d3`, `babel-cli` | `obfuscation` | `obfuscation` |
| `shadowsocks` | `shell_exfil` | `shell_exfil` |

Per-vector false hits: `META` **5 → 0**, `B2` 9 → 5, `E1` 2 → 1, `B3` 1 → **2**, `B1` and `D3`
unchanged at 1.

**`node-sass` is the documented limit of the worm fix.** Its `lib/extensions.js` is shipped runtime
code, not build tooling, and its `scripts/util/{proxy,rejectUnauthorized}.js` are genuinely
*reachable* from `"install": "node scripts/install.js"`, so all three findings correctly survive —
and it keeps `install_script` regardless. No defensible path pattern clears it.

### One delta that is registry drift, not this pass

**`B3` false hits went 1 → 2, and that is not a regression.** `nodemailer` was republished between
the v19 arm run (2026-08-10) and this one: it restructured into `dist/cjs` and `dist/esm`, which
`version_diff` reports as newly introduced `process.env` access in new files. Its `network_imports`
finding disappeared entirely at the same time. `nodemailer` was an accused false positive before and
after, via a different check, so the package count is unaffected — but the per-check figure moves for
reasons this pass did not cause. Arms B and F hit the live registry and every delta on a check this
pass did not touch must be attributed this way before a headline is quoted.

### The E1 metric movement is not a recall movement

`E1` fires fell 174 → 171 in arm D. Three packages — `@emilgroup/tenant-sdk`,
`@emilgroup/public-api-sdk-node`, `@emilgroup/insurance-sdk-node` — lose E1 from
`detected_vectors` while remaining **TRUE_POSITIVE** via `B1;B2`. Recorded here so the per-vector
drop is not later misread as lost detection.

### v17 → v20 side by side, and what the recall changes actually mean

All figures from `eval/baseline/v17|v18|v19|v20/arm{A..F}.metrics.json`. Arms B, D, E and F need
network; C, E and F need Docker; all six were re-run at v20.

**False-positive rate (any finding)** — the metric the three fix passes targeted:

| arm | corpus | v17 | v18 | v19 | **v20** |
|---|---|---|---|---|---|
| B | 30 benign-labelled entries, registry | 93.3% | 66.7% | 46.7% | **30.0%** |
| F | 27 legitimate parents, all 4 layers | 96.3% | 70.4% | 48.1% | **29.6%** |
| A | 27 parents, name-only | 7.4% | 3.7% | 3.7% | **3.7%** |
| C | 3 benign dummies | 0.0% | 0.0% | 0.0% | **0.0%** |

**False-positive rate (BLOCK level only)** — settled at v18 and held since:

| arm | v17 | v18 | v19 | **v20** |
|---|---|---|---|---|
| B | 46.7% | 0.0% | 0.0% | **0.0%** |
| F | 44.4% | 0.0% | 0.0% | **0.0%** |

**Recall (any finding)**, with false-positive counts alongside so the trade is visible:

| arm | v17 | v18 | v19 | **v20** | FP count v17 → v20 |
|---|---|---|---|---|---|
| A | 1.6% | 1.3% | 1.3% | **1.3%** | 2 → **1** |
| B | 91.4% | 85.7% | 85.7% | **85.7%** | 28 → **9** |
| C | 100.0% | 100.0% | 100.0% | **100.0%** | 0 → **0** |
| D | 88.8% | 88.8% | 87.6% | **87.6%** | 0 → **0** |
| E | 95.0% | **97.5%** | 97.5% | **97.5%** | 0 → **0** |
| F | — | — | — | — | 26 → **8** |

Precision, arm B: 53.3% → 47.4% → 56.2% → **66.7%**. Arm A: 99.94% → **99.96%**.

#### The recall figures that fell are illusion removal, not regression

Three numbers in that table went down, and all three did so *before* v20. None is a detection loss.

1. **Arm B recall 91.4% → 85.7%, and true positives 32 → 18 (v18).** This is the single most
   misread number in the project. **23 of v17's 32 "true positives" were the `signatures` check
   firing on npm's own *security-holding stub***, not on any name detection — post-hoc takedown
   information a consumer already gets free from an advisory feed. `signatures` had a time bomb: it
   filtered expired keys *out* of the lookup, so any package not republished since npm's 2025-01-29
   key rotation matched no key, was never verified, and fell through to an unconditional BLOCK.
   Fixing it necessarily removed those credits. Mechanism-attributed, **v17's real name-detection
   recall was 25.7% at 6.7% FPR**, so the honest comparison is **25.7% → 85.7%** — a large
   *improvement*, achieved in the same pass by fixing A1 suffix squats and absent parents. All 18
   current true positives come from A1.
   The 32 → 18 drop in TP count is the same fact seen from the other side, and it is accompanied by
   `ARTIFACT_FN` going **0 → 14**: with the stubs no longer BLOCK'd, a clean verdict on a defanged
   takedown stub is now correctly excluded from recall's denominator instead of inflating it. Arm
   B's denominator is honestly 21, not 35.
2. **Arm D recall 88.8% → 87.6% (v19).** 1.2 points, six packages, the cost of demoting four
   measured-non-discriminating rules to capabilities — taken deliberately against a stated 2-point
   floor, in exchange for arm F 70.4% → 48.1%. Held exactly at v20.
3. **Arm A true positives 3451 → 2841 (v18).** The distance-2 branch had no name-length guard, so a
   3-character name sat within two edits of much of the top list by chance. **608 of the 610 lost
   detections have a bare name ≤4 characters** — the coincidental matches the guard exists to
   remove. Precision rose 99.94% → 99.96% and FPR halved.

**v20 itself cost no recall at all.** Every recall figure came back bit-identical to v19 — arm D
437/499, arm E 39/40, arm C 16/16, arm B 18, arm A 2841 — while arm F fell 48.1% → 29.6% and arm B
46.7% → 30.0%. That is the whole result: the two rules it recalibrated were measured *inverted* or
inverted-when-sole, so removing their accusations subtracted false positives without subtracting
detections.

### What this pass does NOT establish

- **The establishment guard's *discrimination* is unmeasured.** It is *safe* in every arm, but for a
  structural reason: arms D and E have no registry path at all, and `network_imports` fires on **zero**
  of arm B's 35 malicious entries — the only malicious registry-path corpus. The rationale that
  malicious sole-accusers are freshly published spam names rests on `is_established` requiring both
  age ≥365 days and ≥10 versions, which fresh packages fail. That argument is sound but **not
  demonstrated by these arms**. Do not write it up as measured.
- **The remaining 29.6% cannot be closed by a third demotion at this recall floor.** What is left in
  arm F is four packages on `obfuscation` SUSPECT, from two sub-rules: bare `eval()` (`jquery`,
  `babel-cli`; 13.4% malicious, lift 1.81) and the `Function()` constructor with a string body
  (`lodash`, `d3`; 11.4%, lift 1.54). A solitude-gated demotion of those two takes arm D to 427/499
  = **85.6%**, below the floor, and the establishment gate cannot rescue it because arm D has no
  registry path. This confirms v19's own closing conclusion: the ceiling is coverage's problem, not
  calibration's — items 7, 7b and 8.
- **The default CLI's `file` paths are still `package/`-prefixed.** Fixing the worm exclusion
  surfaced that `run_layer1` passes the tarball extraction root while `run_full_registry_collect`
  passes `…/package`, so every Layer 1 finding's `file` field differs between `npm-pre-scan X` and
  `npm-pre-scan --full X`. Worked around inside `worm_signature` via `package_root()`; the wider
  inconsistency is recorded, not fixed.

## v19 — capability model: false positives nearly halved at no recall cost

Queue items **4 and 10** (2026-08-10). Items 7, 8, 9 remain open. All six arms re-run against
`eval/baseline/v18/`; new snapshot at `eval/baseline/v19/`.

| arm | recall v18 → v19 | any-finding FPR v18 → v19 | BLOCK-level FPR |
|---|---|---|---|
| A — 216,888 names, offline | 1.3% → 1.3% | 3.7% → 3.7% | 3.7% |
| B — 65, live registry | 85.7% → **85.7%** | 66.7% → **46.7%** | **0.0%** |
| C — 19 dummies | 16/16 pkgs, 15/16 vectors — unchanged | 0.0% | 0.0% |
| D — 499 malicious, L1 | 88.8% → **87.6%** (floor 86.8%) | — | — |
| E — 40 malicious, all layers | 97.5% → **97.5%** (floor 95.5%) | — | — |
| F — 27 legitimate | — | 70.4% → **48.1%** | **0.0%** |

Arm F clean packages went **8 → 14**; arm B **13 → 14**. Arm A is unchanged by construction — it is
name-only, and a capability cluster needs findings the name checks never produce.

### The measurement that drove it

Per-check and per-sub-rule discrimination, arm D (499 real malicious, L1) vs arm F (27 legitimate,
all layers). Only Layer 1 rows are comparable — **arm D never ran Layers 0/2/3**.

| rule | malicious | benign | lift | action |
|---|---|---|---|---|
| `suspicious_strings` `os.homedir()` | 14.4% | **0.0%** | ∞ | keep SUSPECT |
| `suspicious_strings` `/etc/passwd`,`/etc/shadow`,`~/.ssh` | 4.0/1.4/1.0% | **0.0%** | ∞ | keep BLOCK |
| `obfuscation` atob / hex-ident / hex-seq | 9.4/6.2/1.6% | **0.0%** | ∞ | keep |
| `shell_exfil` | 19.0% | 3.7% | 5.14 | keep |
| `worm_signature` | 34.9% | 7.4% | 4.71 | keep |
| `install_script` | 62.3% | 18.5% | 3.37 | **split by hook + body** |
| `network_imports` | 38.1% | 14.8% | 2.57 | keep |
| `obfuscation` long-base64 | 8.6% | 7.4% | 1.16 | **capability** |
| `suspicious_strings` `process.env` | 36.3% | **44.4%** | **0.82** | **capability (inverted)** |
| `dynamic_require` | 7.6% | **14.8%** | **0.51** | **capability (inverted)** |
| `maintainer` (A3) | — | 11.1% | 0 TPs ever | **capability** |

Two rules fire *more often on legitimate packages than on malware*. `process.env` alone reached 12
of the 27 benign packages. Note the contrast **inside** `suspicious_strings`: its `os.homedir()`
pattern is 14.4% vs 0.0% while its `process.env` pattern is inverted — the check was never broken,
one of its five patterns was.

### What changed

**Capability tier.** The four non-discriminating rules now emit INFO with a `capability` key. A
package carrying **≥3 distinct capabilities** gets a synthetic `capability_cluster` SUSPECT finding.
Distinct *ids*, not findings — `obfuscation` and `suspicious_strings` emit one finding per file.

It is emitted in `report::finish_scan`, which owns the four `CheckResult`s. `aggregate` only borrows
them and returns a findings-less `RiskReport`, and the harness reads `classification` from
`RiskReport.verdict` but `by_vector`/`sole_detector` from per-finding severity — so escalating the
verdict alone would have moved the confusion matrix while leaving every per-vector metric flat.
Verified: arm B `by_vector` META 0 → 5 fires.

**`install_script`, from key-presence to hook-name + command-body.** It called
`scripts.get(k).is_some()` and discarded the command, so `node-gyp rebuild` and `curl … | sh` were
the same finding.

| | malicious | benign |
|---|---|---|
| `preinstall` | 169 | **0** |
| `postinstall` | 136 | 1 (`node-sass`) |
| `install`/`prepare` only | 6 | 4 |
| exec/exfil command shape | **79 packages** | **0** |
| build-toolchain command shape | 9 hooks | 4 of 6 hooks |

Exec shape → BLOCK; `pre`/`postinstall` → SUSPECT; `install`/`prepare` or a recognised build step →
capability. B1 fires on the benign corpus went 5 → 1, and **arm D's BLOCK-level recall rose 21.6% →
35.1%**. `node <file>` is deliberately not an exec shape: `node-sass` ships
`"postinstall": "node scripts/build.js"` and most malicious hooks look the same.

### `naniod` — the one loss, and why fixing the rule beat restoring the noise

The demotions initially cost arm E exactly one package. `naniod` is a real `nanoid` typosquat whose
entire payload is 239 bytes:

```js
var _ld = require('locale-loader-pro');
_ld.configure && _ld.configure({ env: process.env, root: require('os').homedir() });
```

Its only accusation had been `process.env`. But it also calls **`require('os').homedir()`**, and the
`os.homedir()` pattern only matched the bare form — a rule gap, not a calibration problem.
`os.homedir` is 14.4% malicious vs 0.0% benign, so widening the pattern cost nothing and returned
arm E to 97.5%. Restoring `process.env` as an accusation would have cost 12 legitimate packages to
save this one.

### Process failure: six arms measured against a stale binary

The first v19 arm runs used a `--release` build that predated the `dynamic-require` capability tag,
so that capability was demoted to INFO but never counted toward a cluster — the escalation was
measured with 4 of 5 capabilities. It surfaced only because arm B's false-positive count moved
between two runs that should have been identical, which initially looked like live-registry drift.
All six arms were re-run. **Rebuild `--release` immediately before an arm run, and treat an
unexplained delta between identical runs as a harness bug until proven otherwise.**

### The ceiling

48.1% is close to the static-only limit at this recall floor. The 13 still accused genuinely have
the capability: `axios` imports http, `node-sass` runs a postinstall, `jquery`/`lodash`/`d3` ship
minified `eval()`. Telling "has" from "abuses" needs a second evidence source, and Layer 2/3 reaches
only 11/27 legitimate and 28/40 malicious packages. **That is a coverage problem** — items 7, 8, 9.

---

## v18 — first fix pass, measured against the v17 baseline

Queue items **0, 1, 2, 3, 5, 6** implemented (2026-08-04). Items 4, 7, 8, 9, 10 remain open. Arms
A, B, C and F re-run; D and E not re-run (Layer-1-on-malware arms, unaffected by these fixes except
via item 3, which arm E would show — see the caveat at the end of this section). Before/after is
against `eval/baseline/v17/`, and the new numbers are archived at `eval/baseline/v18/`.

| arm | any-finding FP | **BLOCK-level FP** | recall | FPR | ARTIFACT_FN |
|---|---|---|---|---|---|
| A (216,888 names, offline) | 2 → 1 | 2 → 1 | 1.6% → 1.3% | 7.4% → **3.7%** | 0 → 0 |
| B (65, live registry) | 28 → 20 | **14 → 0** | 91.4% → 85.7% | 93.3% → **66.7%** | 0 → **14** |
| C (19 dummies) | 0 → 0 | 0 → 0 | 16/16 pkgs, 15/16 vectors — unchanged | 0% → 0% | 0 → 0 |
| F (27 legitimate) | 26 → 19 | **12 → 0** | — | 96.3% → **70.4%** | 0 → 0 |

**The headline: zero BLOCK-level false positives.** Not one of the 27 legitimate packages is
BLOCK'd any more, and arm F produced **no BLOCK-severity finding of any kind**. The v17 target was
12/27 → 4/27; the residue `{fabric, node-sass, sqlite, babel-cli}` was cleared as well, by items 2,
5 and 6 respectively. Arm F's BLOCK-only FPR is 44.4% → **0.0%**, and its true negatives went 1 →
8.

Per-vector false positives on the benign corpus (distinct legitimate packages, arm F):

| vector | v17 | v18 | owner |
|---|---|---|---|
| META (`signatures`) | 11 | **0** | item 1 |
| A1 (`typosquat`) | 1 | **0** | item 5 |
| A2 (`namespace`) | 1 | **0** | item 6 |
| A3 (`maintainer`) | 4 | 3 | still open |
| B1 (`install_script`) | 5 | 5 | item 4 |
| B2 (obfuscation / suspicious_strings) | 18 | 18 | item 4 |
| B3, D3 | 1, 1 | 1, 1 | items 4, 7 |
| E1 (`worm_signature`) | 2 | 2 | now SUSPECT, no longer BLOCK |

Everything still firing is SUSPECT-level. That is why arm F's *any-finding* FPR only falls 96.3% →
70.4%: the static heuristics of item 4 still touch two thirds of the corpus, they just no longer
refuse an install.

### Four results worth stating separately

**1. `signatures` no longer props up recall.** All 45 signature findings across arm B are now INFO
— zero BLOCK, zero SUSPECT. All 18 of arm B's true positives are caught by **A1 name detection**;
in v17, 23 of 32 came from `signatures` firing on npm's own takedown stubs. The v17 report's
central criticism is resolved at the mechanism level, not just in the aggregate.

**2. The honest name-detection figure went UP, not down.** The fix was predicted to drop arm B's
recall from 91.4% to roughly 25.7% — the mechanism-attributed Layer 0 figure. It landed at
**85.7%**, because item 5 genuinely fixed detection at the same time: nine suffix squats
(`cross-env.js`, `d3.js`, `fabric-js`, `http-proxy.js`, `jquery.js`, `mssql.js`, `nodemailer-js`,
`nodemailer.js`, `proxy.js`) and `ffmepg` are now caught by name, where before they were missed
entirely. So the comparison that matters is **25.7% → 85.7% on real name detection**, and the
91.4% it replaced was never detection at all.

**3. `ARTIFACT_FN` is no longer inert — it went 0 → 14.** The safeguard documented in
`eval/README.md`, which v17 could never exercise, is now doing its job: with `signatures` no longer
BLOCK-ing npm's defanged takedown stubs, a clean verdict on a `holder` entry is correctly
classified `ARTIFACT_FN` and kept out of recall's denominator. Arm B's denominator is therefore 21,
not 35 — which is the honest one, since the corpus cannot deliver those 14 packages' malice.

**4. Arm A trades coincidental hits for a halved false-positive rate.** Detections fall 3,451 →
2,841. Of the 610 lost, **608 have a bare name of 4 characters or fewer** — the accidental
distance-2 matches the new length guard removes (`smb`→`pm2` was the measured example). The other 2
are `@cap-js/sqlite` and `@nativescript-community/sqlite`, which bare-match the newly-added
`sqlite` and now return INFO instead of an accidental distance-1 hit on `sqlite3`. Meanwhile 98
names are newly caught as suffix squats, precision ticks up 99.94% → 99.96%, and BLOCK-level true
positives rise 421 → 483. `sqlite` is cleared; `babel-cli` remains arm A's one false positive,
because the establishment guard is registry-path only and arm A is name-only by construction.

### What this pass did NOT establish

- **Arm E was not re-run**, so the effect of item 3 on real-malware recall is unmeasured here.
  `ansi-styles@6.2.2` was verified directly instead: it scored **PASS with zero findings** in v17
  and now scores **BLOCK** on 314 distinct `_0x` identifiers. Arm E is where that would show up as
  a recall number, and it should be re-run before any recall figure is quoted.
- **Arm D was not re-run** either; it is Layer-1-only on 499 malicious payloads and item 3 can only
  raise it.
- **The remaining 70.4% arm F FPR is untouched by this pass** and belongs to item 4.
- **Item 10 (severity + score aggregation) is still open**, and the v17 finding that motivates it
  is now half-answered: BLOCK no longer fires on legitimate packages at all (0% vs arm D's 37.5%),
  which fixes the inversion but says nothing about the score's saturation.

---

## Ranked weaknesses

Ordered by (severity × breadth), each with the evidence and a proposed fix. Nothing below has been
implemented — per the plan this pass measures and stops.

### 1. `signatures.rs` blocks every package not republished since 2025-01-29

**Severity: critical. This is a time bomb that gets worse, not better.**

npm rotated its registry signing key. The old key `SHA256:jl3bwswu80PjjokCgh0o2w5c2U4LhQAE57gj9cz1kzA`
carries `"expires": "2025-01-29T00:00:00.000Z"`; the new key
`SHA256:DhQ8wR5APBvFHLF/+Tc+AYvPOdTpcIDqOhxsBHRwC7U` has `"expires": null`. Packages last published
before the rotation are still signed with the old keyid. `check_signatures` filters candidate keys
with `!key_expired(k)`, finds no match, falls out of the loop and returns
**`BLOCK` "no valid/unexpired signing key"**.

Evidence: verified directly against the registry — `ms@2.1.3` and `d3@7.9.0` are signed with the
expired keyid, `lodash@4.18.1` with the current one (and `lodash` is the only parent that escapes this
particular BLOCK). 11 of 27 legitimate packages BLOCK'd: `ms`, `mysql`, `d3`,
`escape-string-regexp`, `ffmpeg`, `grunt-cli`, `http-proxy`, `node-sass`, `shadowsocks`, `sqlite`,
`babel-cli`. It also fires on 32/35 malicious entries, which is why arm B's headline recall looks
excellent while measuring almost nothing (`eval/runs/armB/records.jsonl`).

**Fix.** An expired key is not evidence of tampering. Verify the signature against the key that
actually signed it, and treat key expiry as informational — `npm audit signatures` itself does not
reject on a rotated key. Reserve `BLOCK` for a signature that verifies *and fails*. Recommend also
adding a regression test that pins this distinction, since the failure is silent and time-dependent.

### 2. `worm_signature` BLOCKs legitimate packages for shipping a release script

**Severity: high** — it is a `BLOCK`, and it is the project's headline E1 differentiator.

`fabric` and `node-sass` are BLOCK'd with "Self-propagation indicator … (npm publish / authToken /
registry PUT)", from `publish-next.js`, `scripts/util/rejectUnauthorized.js`, `scripts/util/proxy.js`
and `lib/extensions.js`. These are ordinary maintainer tooling.

All four paths are archived — in `eval/runs/armF/records.jsonl`, on the `file` field of each
finding (not in `findings.csv`, which has no `file` column). Re-scanning the published tarballs in
v18 reproduced them exactly.

The split is not even: **4 findings across 2 of 27 packages — `fabric` 1, `node-sass` 3.** A single
self-propagation hit was enough to BLOCK, which is the defect. Note also that `fabric` passes
**both** dynamic layers cleanly in this same arm: no observed behaviour anywhere in the pipeline
corroborated the accusation.

> **FIXED in v18.** Each category now emits SUSPECT; only the ≥2-category aggregate, or a
> known-IOC hash, BLOCKs — which is what `worm_signature`'s own doc comment always claimed. Both
> packages verified after the change: `fabric` and `node-sass` drop to SUSPECT, and the
> Shai-Hulud fixture keeps its BLOCK via two categories plus its IOC hash.

**Fix.** The self-propagation category is doing too much work alone. Require corroboration before
`BLOCK` (the aggregate `worm` rule already demands ≥2 categories — the *individual* category should
not BLOCK by itself), and exclude paths that are plainly build tooling (`scripts/`, `publish*.js`)
unless the file is also reached from an install hook.

### 3. The hex threshold misses the obfuscator family used in real attacks

**Severity: high** — a complete four-layer miss on a real, high-profile compromise (arm E,
`ansi-styles@6.2.2`; full mechanism above).

**Fix.** Add a hex-identifier-density check: count distinct `_0x[0-9a-fA-F]{4,}` identifiers, or the
ratio of `0x…` literals to file size. Legitimate minifiers (terser, esbuild) produce short
alphabetic identifiers, not `_0x`-prefixed hex ones, so the false-positive story is clean — and the
present measurement provides the benign corpus to verify that against, which is precisely what was
missing when the threshold was last tuned.

### 4. Static heuristics were tuned without a benign corpus

**Severity: high in aggregate** (drives the 70% FPR that remains after removing `signatures`), though
each individual finding is only `SUSPECT`.

On 27 legitimate packages — **package counts are the number a calibration change has to move**, so
both are given: `suspicious_strings` 43 findings across **12** packages, `obfuscation` 20 across
**5** (9 on `jquery` alone, 5 on `lodash`), `dynamic_require` 8 across 4, `install_script` 5 across
5, `network_imports` 4 across 4. Two more fired here and were missing from every earlier FP
accounting: `shell_exfil` SUSPECT on `shadowsocks`, `version_diff` SUSPECT on `bcrypt`. As a
vector, B2 reaches **18 of the 27 (67%)**. Only `chalk` came through clean.

**Fix.** This is a calibration problem, and the harness now supplies the missing input. Suggested
order: demote `suspicious_strings` on `process.env`/`os.homedir()` to INFO unless combined with a
network or exfil indicator; exclude minified bundles (long single lines, `.min.js`) from the
`obfuscation` hex/base64 rules; treat `install_script` presence as INFO on its own — arm E shows 36
malicious samples had install hooks, but so do `node-sass`, `sqlite3`, `bcrypt`, `axios` and `fabric`.

### 5. A1 typosquat detection is at 25.7% recall, from two independent causes

**Severity: medium** — this is the tool's flagship Layer 0 check.

- **Suffix blindness (9/21 misses).** `bare_name` strips only `@scope/`. Fix: also fold a trailing
  `.js`/`-js`/`_js` before the distance comparison, exactly as homoglyphs are already folded. Verify
  against the benign corpus first — `chalk` and friends must stay clean.
- **Absent parents (12/21 misses).** `ffmpeg`, `fabric`, `shadowsocks`, `tkinter`, `nodecafe` are not
  in `data/top_packages.txt`. Fix: widen the embedded snapshot, or make `--refresh-top` the default
  once its reproducibility caveat is addressed.

Also worth fixing: **2 of 9 A1 hits are accidental** (`d3.js`→`dayjs` at distance 2, `smb`→`pm2` at
distance 2). Very short names and short distances produce coincidental matches; consider requiring the
distance to be small *relative to name length*.

### 6. `sqlite` and `babel-cli`: legitimate packages BLOCK'd by name alone

**Severity: medium** (2/27, but both hard `BLOCK`s, and both are real packages people install).

`sqlite` is distance 1 from `sqlite3`; `babel-cli` flattens to the same form as `@babel/cli`. Fix:
before accusing, check whether the candidate is *itself* an established package — the metadata Layer 0
already fetches (age, download count) is enough to distinguish a 10-year-old package with real
downloads from a fresh squat. The namespace check needs the same treatment; this is the "legit flat
twin" class CLAUDE.md v16 predicted, now confirmed on a real package.

### 7. Layers 2/3 cost 34 s per package and added no unique real-malware detections

**Severity: medium — a cost/benefit finding, not a correctness one.**

Sole-detector count on real malware: L2 **0**, L3 **0**, versus L1 16 (arm E). On the dummy corpus the
same layers were sole detector 7 times (arm C). The dummies were built to require them; real malware
in this sample did not.

**Fix.** Do not remove them — D1/D2/D3 are real attack patterns, Layer 3 is this project's claimed
contribution, and arm F shows Layer 2's precision on real software is *perfect* (0/10 FPR), which is a
result worth keeping. But the contribution should be stated honestly as *coverage of a class static
analysis cannot reach in principle*, not as a measured recall improvement, until a corpus of genuinely
condition-gated real malware demonstrates the latter. Practically: make L2/L3 opt-in for large sweeps,
and consider running them only when L1 is clean — the cases where they could actually change a verdict.

### 7b. D3's premise cannot distinguish a payload from a library doing its job — FIXED in v21

**Severity: medium** — the only measured Layer 3 false positive, and it is structural.

`nodemailer` → `trigger_on_use (D3) SUSPECT: network activity` (arm F). The fuzz scenario invoked
`nodemailer`'s exports, one opened a connection, and D3 reported it. The fuzzer caused the behaviour it
flagged. For any package whose legitimate purpose is network I/O, "an export touched the network" is
not a signal.

**Fix.** Gate D3 on *what* the invoked export did, not merely that it did something: an egress host or
IP literal unrelated to the package's stated purpose, an encoded DNS label, a credential read. Layer
2's classifier already makes these distinctions — D3 currently accepts a bare
`import_side_effect` where it should require one of the stronger sub-signals.

> **v21: fixed, but NOT by requiring a stronger sub-signal — that form was measured and rejected.**
> `dummy_api_triggered` trips none of the four, so the literal fix would have deleted the project's
> own D3 detection (arm C 16/16 → 15/16). The discriminator used instead is *relatedness*: a D3
> accusation is demoted when every observed side effect points back at the package itself — its own
> API host (`nodemailer` → `api.nodemailer.com`) or its own binary (`ffmpeg` → `/usr/bin/ffmpeg`).
> See the v21 section.

### 8. The offline sandbox cannot analyse dependency-bearing packages — FIXED in v21

**Severity: medium — a coverage ceiling on the dynamic layers.**

`--network=none` + `npm install --offline` means dependencies never install; `require()` then throws
`MODULE_NOT_FOUND`, and both are swallowed. 12 of 40 arm E samples and 16 of 27 benign parents are
affected. The harness flags these (`dyn_valid=false`) rather than scoring them, but the underlying
coverage gap is real: **the dynamic layers can only analyse dependency-free packages**, which is a
minority of real npm packages.

**Fix.** Vendor dependencies into the mount before the container runs (resolve and download on the
host, where network access is already used for the tarball), or run a local registry mirror. Either
way, record in the report which packages were dynamically analysable.

> **v21: done, host-side, via `npm install --ignore-scripts` mounted read-only at `/vendor`.** Arm F
> Layer 2 reach 10 → 26 of 27, `dyn_valid` 12 → 24; arm E `dyn_valid` 28 → 34. Which packages were
> analysable is now recorded per entry (`dyn_valid`, `vendored`). Note the safety-posture change
> documented in `eval/README.md`, and that the expansion exposed two previously-hidden false
> positives (`ffmpeg` D3, `bcrypt` C3).

### 9. Smaller items

- **`data/worm_iocs.txt` holds one real hash.** It is the *right* hash — it matched real
  Shai-Hulud — but coverage is one sample wide. `NPM_PRE_SCAN_IOCS` already allows extension
  without recompiling; the DataDog corpus is a ready source of additional hashes.
  ✅ **v21: extended to the full 7-variant campaign fingerprint — and measured to add ZERO recall**
  (44 packages matched vs 25, 0 as sole detector, arm D bit-identical). See the v21 section.
- **`dummy_slow_exfil` takes 467 s** (24× the arm C median) from 35 sequential sinkholed DNS lookups.
  Worth knowing before running the dynamic layers over a large corpus.
- **A dependency-free legitimate package can exhaust the dynamic timeout with no finding and no
  recorded cause.** `shadowsocks` hit the `--docker-timeout 600` wall in *both* layers
  (`l2_status=error` 605074 ms, `l3_status=error` 605070 ms, `declared_deps=0`) and yielded nothing
  — 84% of arm F's 24.0-minute total; the arm takes 3.8 min without it. This is a **different** cost
  risk from `dummy_slow_exfil` above: that one is deliberate sinkholed DNS behaving as designed,
  whereas here there is no diagnosis at all and `dyn_valid` cannot screen for it, because the
  package genuinely declares zero dependencies. Worth an error class that distinguishes "timed out"
  from "errored", and a per-package budget below the arm budget.
  ✅ **v21: both done.** The timeout was never *detected* — `timeout -k` re-raises SIGKILL on itself,
  so the `code() == Some(124)` test could not match, which also meant the orphan-container cleanup
  never ran. Detection now keys on the signal too; `--package-timeout` bounds both dynamic layers
  together (`shadowsocks` 1210 s → 905 s); and `dyn_valid` is false whenever a dynamic layer was
  killed, so a stalled package no longer contributes vacuous "clean" dynamic layers.
- **`dummy_persistence` is mis-attributed to D2.** Its `.bashrc` write is unconditional at import,
  so the Layer 3 env scenario is claiming credit for behaviour it did not trigger.
  ✅ **v21: root-caused to the env scenario's `HOME=/home/developer` mutation (the baseline runs as
  root, so the two paths never cancelled) and fixed in `normalize_path`.** Arm E's D2 noise fell
  7 → 2 fires as a second effect.
- **`ARTIFACT_FN` has never fired.** `overall.artifact_fn = 0` in all six arms. The classification is
  documented in `eval/README.md` as what keeps defanged takedown stubs out of recall's denominator,
  but because the content layers never ran on `holder` entries (arm B is Layer 0 only on the
  malicious half), it was never assigned once. The safeguard is not wrong — it is **untested by this
  run**. Do not cite it as validated until an arm exercises it.
- **B3 has no path through the harness.** It is 0/1 in arms B, C and E alike, for want of a `pair`
  manifest kind expressing a prev/latest directory — not for want of a rule. Its recall is
  unmeasured, not zero.
  ✅ **v21: closed by `Kind::Pair`** — B3 0/1 → 1/1 in arm C, the first B3 true positive in the
  project's history; arm C now reaches 14/14 vectors.
- **B4 did not fire on the one real B4 sample.** `node-ipc@12.0.1` was caught via B2;C1 instead, so
  arm E's B4 recall is 0/1 even though the package is a package-level true positive.
  ⚠ **v21: investigated, NOT fixable by any rule change.** The wiper is geo-gated; its lookups fail
  under `--network=none`, so the destructive branch never executes and there are no writes or
  deletes to detect. Recorded as a sandbox-coverage limit resting on a single observation.
- *(The B3 item above was stated twice in this list; the duplicate is folded into it as of v21.)*

---

## Verdict on the pre-registered predictions

Predictions were written down in the plan **before** the harness was built, so this table is a real
test rather than a retrospective narrative.

| # | Prediction | Outcome |
|---|---|---|
| 1 | A1 misses `.js`-suffix typosquats because `bare_name` strips only `@scope/` | **Confirmed.** 9 of 21 campaign misses are this class. |
| 2 | A second, independent miss cause: parents absent from `top_packages.txt` | **Confirmed.** 12 of 21. The recorded `closest`/`distance` fields separate the two causes as designed. |
| 3 | E1 IOC coverage ≈ 0 (one real hash) | **Refuted, in the tool's favour.** The one hash matched the real Shai-Hulud patient-zero sample. Coverage is narrow but not zero, and the hash is correct. |
| 4 | Dynamic-layer false positives from `install_script`, `native_addon`, `import_side_effect` on real packages | **Partly confirmed, and displaced.** `install_script` fires on 5/27 legitimate packages, but the dominant FP sources turned out to be `signatures` (BLOCK, 11) and `suspicious_strings`/`obfuscation` (SUSPECT) — none of which were predicted. |
| 5 | (implicit) The dummy corpus would show high recall | **Confirmed**, 100% — which is exactly why it could not have surfaced any of the above. |

The prediction I did *not* make, and the most consequential finding, is the expired-signing-key
time bomb.

---

## Validity of the measurement itself

The harness is new code, so the numbers depend on it being right. What was checked:

- **The existing suite still passes unchanged.** 357 offline tests (was 243) and all 20 Docker-gated
  tests, including the 15 that predate this work. `cargo clippy --all-targets -- -D warnings` clean.
- **A regression was caught by the pre-existing tests.** Masking Layer 0 off for a local-directory scan
  initially reported it `Skipped`; `tests/full_pipeline.rs` correctly requires `NotRun`, because "not
  applicable" is not "deliberately declined". `finish_scan` now takes both a *requested* and an
  *applicable* mask.
- **Reproducibility.** Arm A was run twice: `records.jsonl` is byte-identical after removing timestamps
  and timings.
- **Two bugs in the harness were found and fixed**, both of which would have looked like corpus gaps
  rather than tooling faults:
  - `merge_manifests` did an O(n²) duplicate-id scan and hung on 216k entries (now keyed).
  - `find_package_root`'s `max_depth(8)` silently skipped 38 of 499 arm D samples — the ones collected
    on macOS, nested under `/var/folders/…`. Arm D was re-run from scratch after the fix; the
    reported 499/499 figure is post-fix.
- **A plausible hypothesis was tested and rejected** rather than asserted: that implausible version
  numbers (`99.x`, `500.x`) identify arm D's misses. They appear in 7/56 misses but 63/443 detections.
- **Sanity anchors held.** `dummy_benign_l3` is TN, `dummy_shai_hulud/infected` is TP via E1, and
  INFO-only findings never produce a positive (verified directly, since `check_typosquat` returns INFO
  on an exact popular-list match and every benign control carries one).

### What this measurement does *not* establish

- **Arm A's 1.6% is a flag rate, not recall.** Its ground truth is "this name has a malicious-code
  advisory", not "this name is a typosquat". Per-vector recall is only claimed for arms B and C, where
  labels were hand-verified.
- **Arm D had no benign control** at the time of this run, so its 88.8% recall and F1 0.94 could not
  be compared against OSCAR's F1 0.95. **Superseded by v22**, which built two controls: the matched
  arm G reaches F1 0.8455 any-finding and 0.7711 BLOCK-only — genuinely comparable, and below 0.95.
- **The dynamic layers were measured on a minority of each corpus.** 11/27 legitimate packages are
  dependency-free but only **10 completed a valid run** (`shadowsocks` timed out in both layers);
  28/40 malicious. The offline sandbox cannot install dependencies.
- **40 samples is a small dynamic corpus.** The "L2/L3 sole detector = 0" result is suggestive, not
  conclusive; it would take a larger and deliberately condition-gated sample to settle.
- **Everything ran serially.** Concurrency would perturb the very timings and container behaviours
  being measured.

## Reproducing

```sh
cargo build --release
# A: offline, 44 s, no network
./target/release/npm-pre-scan --eval eval/corpus/ossf_npm_names.tsv \
    --eval eval/corpus/parent_benign.tsv --eval-mode name-only --out-dir eval/runs/armA
# B: live registry, 26 s
./target/release/npm-pre-scan --eval eval/corpus/real_malicious_holders.tsv \
    --eval eval/corpus/parent_benign.tsv --eval-mode registry --out-dir eval/runs/armB
# C: Docker, 13 min                     D: network, 5 s
./target/release/npm-pre-scan --eval eval/corpus/dummies.tsv --eval-mode full \
    --docker-timeout 900 --package-timeout 1200 --out-dir eval/runs/armC
./target/release/npm-pre-scan --eval eval/corpus/datadog_static.tsv --eval-mode registry \
    --out-dir eval/runs/armD
# E: Docker + live malware, 23 min      F: Docker, 37 min at v21 (all 27 now
#                                          reach L2/L3; shadowsocks bounded at 905 s)
./target/release/npm-pre-scan --eval eval/corpus/datadog_dynamic.tsv --eval-mode full \
    --docker-timeout 600 --package-timeout 900 --out-dir eval/runs/armE
./target/release/npm-pre-scan --eval eval/corpus/parent_benign.tsv --eval-mode full \
    --docker-timeout 600 --package-timeout 900 --out-dir eval/runs/armF
# G: matched benign control, 63 s    H: broad benign control, 3.2 min
./target/release/npm-pre-scan --eval eval/corpus/datadog_compromised.tsv \
    --eval eval/corpus/datadog_clean.tsv --eval-mode registry --out-dir eval/runs/armG
./target/release/npm-pre-scan --eval eval/corpus/datadog_intent.tsv \
    --eval eval/corpus/top_benign.tsv --eval-mode registry --out-dir eval/runs/armH
```

⚠ **Write each arm to a FRESH `--out-dir`.** `--eval` is repeatable so that several manifests can
share one output directory, which means `records.jsonl`, `results.csv` and `findings.csv` are
**appended** — but `metrics.json` is rewritten. Re-running an arm into a directory that already
holds one leaves the row-level artifacts carrying both runs while the metrics describe only the
last, which is a silent trap when comparing before/after.

`eval/corpus/ossf_npm_names.tsv` is gitignored (12 MB); regenerate it with the recipe in
`eval/README.md`. Arms B, D, E and F need network access; C, E and F need Docker. Arms D, E and F
download real malware samples — read the safety section of `eval/README.md` first.
