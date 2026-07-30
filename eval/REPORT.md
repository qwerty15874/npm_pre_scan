# Evaluation report — npm-pre-scan v0.1.0

**Run date:** 2026-07-30 · **Host:** WSL2 / Arch Linux, Docker 29.6.2 · **Lists:** embedded snapshot (1137 unscoped / 94 scoped), not refreshed

First measurement of this tool against packages it did not ship with. Every prior
verification used a dummy package authored by this project, which confirms each layer *works as
designed* but cannot produce a recall figure, a false-positive rate, or an answer to "which layer
earns its keep."

Raw data for every claim below is in `eval/runs/arm{A..F}/` — `records.jsonl` (one lossless record
per package), `results.csv`, `findings.csv`, `metrics.json`. Reproduce with the commands in each
arm's section.

---

## Headline

**The detection layers work. The scoring on top of them does not.**

On its own dummy corpus the tool is perfect (16/16 vectors, 0 false positives). On 499 real
malicious packages Layer 1 alone reaches **88.8% recall**, and on 40 real payloads through all
layers, **95.0%**.

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
| B | Curated real malicious names + legitimate parents, via the live registry | 65 | L0 + L1 | 25.6 s |
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

As shipped, this arm reports recall 91.4% and **FPR 93.3%**. Both numbers are misleading, and the
reason is the same check.

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

| Layer | Check | Severity | Packages hit |
|---|---|---|---|
| L0 | `signatures` | **BLOCK** | **11** |
| L1 | `suspicious_strings` | SUSPECT | 43 findings across 13 |
| L1 | `obfuscation` | SUSPECT | 20 findings across 6 |
| L1 | `dynamic_require` | SUSPECT | 8 |
| L1 | `install_script` | SUSPECT | 5 |
| L1 | `worm_signature` | **BLOCK** | **4 findings across 2** |
| L0 | `maintainer` | SUSPECT | 4 |
| L1 | `network_imports` | SUSPECT | 4 |
| L0 | `typosquat` / `namespace` | **BLOCK** | 1 each |

Only `chalk` came through clean out of 27.

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

**Recall 100%, FPR 0%.** Every vector fired via its intended layer; all three benign controls
(`dummy_benign_l3`, `dummy_shai_hulud/clean`, `dummy_malicious_update/prev`) came through clean. This
reproduces the project's existing claims independently, through the batch driver.

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

**`stringmaster-pro@2.0.2`** is a weaker miss: it declares 23 dependencies, so `dyn_valid=false` and
only Layer 1 observed it meaningfully.

---

## Arm F — the first measured Layer 2/3 false-positive rate (27 legitimate packages)

```sh
npm-pre-scan --eval eval/corpus/parent_benign.tsv --eval-mode full --docker-timeout 600 \
             --out-dir eval/runs/armF
```

Arm B capped the legitimate packages at Layer 1, so the dynamic layers' precision on real software had
still never been measured. This arm closes that.

Of 27 legitimate packages, **10 were dependency-free and therefore dynamically analysable** (the other
17 declare dependencies the offline sandbox cannot install; their empty profiles are vacuous and are
excluded).

| Layer | False positives | Rate |
|---|---|---|
| L2 (dynamic, baseline-subtracted) | **0 / 10** | **0%** |
| L3 (condition mutation) | 1 / 10 | 10% |

**Layer 2's baseline subtraction holds up on real software.** Not one of `jquery`, `lodash`, `react`,
`ms`, `semver`, `chalk`, `escape-string-regexp`, `nodemailer`, `shadowsocks` or `sqlite` produced a
single Layer 2 finding. That is a real validation of the v13 baseline-diff work — previously evidenced
only by `dummy_benign_l3`, a package whose entire body is `add(a, b)`.

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
and `lib/extensions.js`. These are ordinary maintainer tooling. 4 findings across 2 of 27 packages.

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

On 27 legitimate packages: `suspicious_strings` 43 findings across 13 packages, `obfuscation` 20
across 6 (9 on `jquery` alone, 5 on `lodash`), `dynamic_require` 8, `install_script` 5,
`network_imports` 4. Only `chalk` came through clean.

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
- **`dummy_persistence` is mis-attributed to D2.** Its `.bashrc` write is unconditional at import, so
  the Layer 3 env scenario is claiming credit for behaviour it did not trigger.
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
- **The dynamic layers were measured on a minority of each corpus** (10/27 legitimate, 28/40 malicious),
  because the offline sandbox cannot install dependencies.
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
# E: Docker + live malware, 23 min      F: Docker, ~45 min
./target/release/npm-pre-scan --eval eval/corpus/datadog_dynamic.tsv --eval-mode full \
    --docker-timeout 600 --out-dir eval/runs/armE
./target/release/npm-pre-scan --eval eval/corpus/parent_benign.tsv --eval-mode full \
    --docker-timeout 600 --out-dir eval/runs/armF
```

`eval/corpus/ossf_npm_names.tsv` is gitignored (12 MB); regenerate it with the recipe in
`eval/README.md`. Arms B, D, E and F need network access; C, E and F need Docker. Arms D, E and F
download real malware samples — read the safety section of `eval/README.md` first.
