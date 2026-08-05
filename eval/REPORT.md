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
| F | Legitimate packages through the dynamic layers — the first measured L2/L3 false-positive rate | 27 | L0–L3 | 24.0 min |

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

### 7b. D3's premise cannot distinguish a payload from a library doing its job

**Severity: medium** — the only measured Layer 3 false positive, and it is structural.

`nodemailer` → `trigger_on_use (D3) SUSPECT: network activity` (arm F). The fuzz scenario invoked
`nodemailer`'s exports, one opened a connection, and D3 reported it. The fuzzer caused the behaviour it
flagged. For any package whose legitimate purpose is network I/O, "an export touched the network" is
not a signal.

**Fix.** Gate D3 on *what* the invoked export did, not merely that it did something: an egress host or
IP literal unrelated to the package's stated purpose, an encoded DNS label, a credential read. Layer
2's classifier already makes these distinctions — D3 currently accepts a bare
`import_side_effect` where it should require one of the stronger sub-signals.

### 8. The offline sandbox cannot analyse dependency-bearing packages

**Severity: medium — a coverage ceiling on the dynamic layers.**

`--network=none` + `npm install --offline` means dependencies never install; `require()` then throws
`MODULE_NOT_FOUND`, and both are swallowed. 12 of 40 arm E samples and 16 of 27 benign parents are
affected. The harness flags these (`dyn_valid=false`) rather than scoring them, but the underlying
coverage gap is real: **the dynamic layers can only analyse dependency-free packages**, which is a
minority of real npm packages.

**Fix.** Vendor dependencies into the mount before the container runs (resolve and download on the
host, where network access is already used for the tarball), or run a local registry mirror. Either
way, record in the report which packages were dynamically analysable.

### 9. Smaller items

- **`data/worm_iocs.txt` holds one real hash.** It is the *right* hash — it matched real Shai-Hulud —
  but coverage is one sample wide. `NPM_PRE_SCAN_IOCS` already allows extension without recompiling;
  the DataDog corpus is a ready source of additional hashes.
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
- **`dummy_persistence` is mis-attributed to D2.** Its `.bashrc` write is unconditional at import, so
  the Layer 3 env scenario is claiming credit for behaviour it did not trigger.
- **`ARTIFACT_FN` has never fired.** `overall.artifact_fn = 0` in all six arms. The classification is
  documented in `eval/README.md` as what keeps defanged takedown stubs out of recall's denominator,
  but because the content layers never ran on `holder` entries (arm B is Layer 0 only on the
  malicious half), it was never assigned once. The safeguard is not wrong — it is **untested by this
  run**. Do not cite it as validated until an arm exercises it.
- **B3 has no path through the harness.** It is 0/1 in arms B, C and E alike, for want of a `pair`
  manifest kind expressing a prev/latest directory — not for want of a rule. Its recall is
  unmeasured, not zero.
- **B4 did not fire on the one real B4 sample.** `node-ipc@12.0.1` was caught via B2;C1 instead, so
  arm E's B4 recall is 0/1 even though the package is a package-level true positive.
- **B3 has no path through the harness.** `version_diff` needs a prev/latest pair, which the manifest
  format cannot express; arm C reports B3 recall 0% for that reason alone (the package was still
  caught via B2). A `pair` manifest kind would close this.

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
- **Arm D has no benign control**, so its 88.8% recall and F1 0.94 cannot be compared against
  OSCAR's F1 0.95 — precision there is measured on arms B and F, and it is poor.
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
    --docker-timeout 900 --out-dir eval/runs/armC
./target/release/npm-pre-scan --eval eval/corpus/datadog_static.tsv --eval-mode registry \
    --out-dir eval/runs/armD
# E: Docker + live malware, 23 min      F: Docker, 24 min (84% of it is shadowsocks
#                                          hitting the 600 s timeout twice; 3.8 min without it)
./target/release/npm-pre-scan --eval eval/corpus/datadog_dynamic.tsv --eval-mode full \
    --docker-timeout 600 --out-dir eval/runs/armE
./target/release/npm-pre-scan --eval eval/corpus/parent_benign.tsv --eval-mode full \
    --docker-timeout 600 --out-dir eval/runs/armF
```

`eval/corpus/ossf_npm_names.tsv` is gitignored (12 MB); regenerate it with the recipe in
`eval/README.md`. Arms B, D, E and F need network access; C, E and F need Docker. Arms D, E and F
download real malware samples — read the safety section of `eval/README.md` first.
