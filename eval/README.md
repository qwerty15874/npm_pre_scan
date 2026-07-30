# Evaluation harness

Measures what `npm-pre-scan` actually detects, against packages it did not ship with.

Until now every "verification" in this project used a dummy package authored by the project
itself. That confirms each layer *works as designed*, but it cannot produce a recall figure, a
false-positive rate, or an answer to "which layer earns its keep". This directory adds the corpus
and the machinery for those numbers.

```
eval/
  corpus/       ground-truth manifests (TSV, checked in)
  runs/         per-run output data (gitignored)
  samples/      downloaded malware samples, encrypted at rest (gitignored)
  REPORT.md     experiment write-up (produced by the run)
```

Run it with:

```sh
npm-pre-scan --eval eval/corpus/dummies.tsv --out-dir eval/runs/<name>
```

`--eval` is repeatable, so several manifests can share one output directory and one metrics
summary.

---

## Safety

`eval/corpus/datadog_*.tsv` reference **live malware published by real threat actors.**

- Sample zips stay **encrypted at rest** in the gitignored `eval/samples/` (password `infected`,
  as published).
- Extraction happens into a `TempDir` for the duration of a single scan, then is dropped.
- Nothing is ever installed or executed on the host. Layers 2 and 3 run inside the existing
  container: `--network=none`, in-container DNS sinkhole, read-only `/pkg` mount, and a
  wall-clock cap via `--docker-timeout`.
- Never `npm install` one of these outside that container.

---

## Manifest format

Tab-separated, one entry per line. `#` comments and blank lines are skipped — the same line
discipline as `data/top_packages.txt`. TSV rather than CSV because npm names, labels, and vector
IDs cannot contain a tab, so the input needs no escaping at all.

```
kind  id  group  label  vectors  layers  [note]
```

| Column | Values |
|---|---|
| `kind` | `name` \| `version` \| `dir` \| `holder` \| `sample` |
| `id` | package name, `name@version`, a repo-relative dir, or a sample path |
| `group` | `real_malicious` \| `dummy` \| `parent_benign` \| `datadog` |
| `label` | `malicious` \| `benign` — the ground truth |
| `vectors` | comma-separated `A1`–`E1`/`META`, or `-` for none/unknown |
| `layers` | comma-separated subset of `0,1,2,3`, or `-` |
| `note` | optional free text, echoed into the record |

`kind` distinguishes the four ways a package can be reached, plus one ground-truth annotation:

- `name` — registry name, `dist-tags.latest`.
- `version` — `name@version`, tarball pinned via `tarball::get_version_tarball_url`.
- `dir` — local path. Layer 0 never applies (no registry identity). A missing directory is
  recorded `skipped_missing` and excluded from every denominator, so the other groups stay
  runnable on a fresh clone where the gitignored `dummy_packages/` does not exist.
- `holder` — a name npm replaced with a *security holding* stub. A content-layer PASS is
  classified `ARTIFACT_FN`, never `FN` (see below).
- `sample` — a DataDog sample zip path.

`holder` and `sample` are **manifest annotations, not runtime inferences.** Deriving ground truth
at scan time (e.g. sniffing `description == "security holding package"`) is how an evaluation
harness ends up grading itself.

`group` and `label` are deliberately independent axes: `dummy_benign_l3` is `dummy`/`benign`, and
the three reclaimed 2017-campaign names are `real_malicious`/`benign`.

A parse error **aborts the batch** (exit 5). Same reasoning as `toplist::MIN_ACCEPT`: a manifest
that silently shrinks corrupts the denominators.

---

## The corpus

| Manifest | Entries | What it measures |
|---|---|---|
| `dummies.tsv` | 19 | per-vector recall B1–E1, D1–D3; the project's own precision controls |
| `real_malicious_holders.tsv` | 38 | Layer 0 against real attacker-chosen names, via the live registry |
| `parent_benign.tsv` | 27 | **false-positive rate** — the legitimate packages the malicious names imitate |
| `ossf_npm_names.tsv` | 216,861 | Layer 0 name-check flag rate at scale, fully offline and reproducible |
| `datadog_static.tsv` | 499 | Layer 1 static recall on real payloads |
| `datadog_dynamic.tsv` | 40 | Layers 1–3 on real payloads, including the Shai-Hulud and Sept-2025 incidents |

### Why npm cannot supply real malicious code

Verified live on 2026-07-30. A taken-down npm package ends up in one of two states:

- **404** — fully unpublished.
- **"security holding package"** — a stub owned by maintainer `npm`, latest version
  `0.0.x-security`. The registry still answers **HTTP 200**.

Some security-holder packages *retain* their original version numbers with downloadable tarballs
— `crossenv@1.0.0`, `ffmepg@1.0.2`, `jquery.js@1.0.2` and friends all fetch successfully. But the
content was **republished defanged**: the payload is literally

```js
console.log('this package is no longer dangerous');
```

So scanning them yields a truthful PASS on harmless content. That is an artefact of the takedown,
not a detection failure, which is why the harness classifies it `ARTIFACT_FN` and keeps it out of
recall's denominator. Real payloads therefore come from the DataDog corpus.

### Why `vectors` is often `-`

Neither the OSV feed nor the DataDog dataset carries a per-advisory vector taxonomy. Labelling
216,861 names with A1–E1 by guesswork would fabricate ground truth. Entries with `-` contribute to
the overall detection rate and to the "which vector fired" breakdown, but not to per-vector
recall.

Expect the arm-A flag rate to be **low**, and read it carefully: that corpus is dominated by
mass-registered dependency-confusion and spam names which are not typosquats of anything, and so
lie outside what A1/A2/A4 are designed to catch. The diagnostic value is in the breakdown, not the
headline number.

### Why only some benign entries carry `layers=2,3`

The sandbox runs `npm install --offline` under `--network=none`, so **dependencies cannot be
fetched**. A package with dependencies fails its install (swallowed by `|| true`), then
`require()` throws `MODULE_NOT_FOUND` (swallowed by the `try/catch`) — producing an empty
behaviour profile that reads as a clean PASS. That is a vacuous result, not evidence of precision.

So dynamic layers are requested only for packages verified to declare zero dependencies. The
runner records `declared_deps` from the extracted `package.json` and marks anything else
`dyn_valid=false`, excluding it from the dynamic denominators rather than inflating the
true-negative count.

---

## Regenerating the derived manifests

Both generated manifests carry a provenance header (source, date, entry count, and for the OSV
sweep a SHA-256 of its data lines). `ossf_npm_names.tsv` is gitignored because it is 12 MB.

**`ossf_npm_names.tsv`** — from the authoritative OSV bulk export rather than the GitHub tree API,
whose response is truncated well below the full set:

```sh
curl -sO https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip
python3 - <<'PY'
import zipfile, json
z = zipfile.ZipFile('all.zip')
pkgs = set()
for n in z.namelist():
    if not n.startswith('MAL-'):
        continue
    for a in json.loads(z.read(n)).get('affected', []):
        p = a.get('package', {})
        if p.get('ecosystem') == 'npm' and p.get('name'):
            pkgs.add(p['name'])
print(len(pkgs))          # 216,885 on 2026-07-30
PY
```

Then drop any name that appears in `data/top_packages.txt` or `data/top_scoped_packages.txt` (24
names on 2026-07-30: `chalk`, `debug`, `ansi-styles`, `axios`, …). Those advisories are
**compromised-version** incidents — a legitimate package whose maintainer account or CI was
subverted — not name attacks. `chalk` is not a malicious *name*, so scoring a name-check PASS on
it as a miss would be wrong; that vector is B3, measured on real payloads in
`datadog_dynamic.tsv`.

**`datadog_static.tsv` / `datadog_dynamic.tsv`** — enumerate the `samples/npm` subtree of
`DataDog/malicious-software-packages-dataset` (24,437 zips visible on 2026-07-30: 1,443
`compromised_lib` + 22,994 `malicious_intent`), then sample with a fixed seed. The dynamic set is
the published incidents plus the smallest samples, capped by zip size so fetch and extract stay
cheap; the static set is a size-capped stratified random sample (seed `31337`).

Note the dataset's own quirk: a scoped package is `@scope@name` in the directory path but
`@scope_name` in the zip filename. The manifest stores the full path rather than reconstructing
it.
