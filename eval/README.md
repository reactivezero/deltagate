# DeltaGate evaluation harness

This measures the two numbers the whole design lives or dies on:

- **False-positive rate** — how often the gate holds a *benign* update. A gate
  that cries wolf gets turned off, so this is the headline metric.
- **Recall** — how many real attack *shapes* the gate catches.

It runs the deterministic engine (`analyzeArtifacts` from `../src/analyze.js`)
against three kinds of case and prints a confusion matrix. It is a **report, not
a gate**: it always exits 0 and writes `eval/last-report.json`.

## Why the corpus is split three ways

Detecting supply-chain malware needs *labels* (which package was malicious),
*payload bytes* (what the malicious code actually looked like), and *negatives*
(normal updates that must not trip). No single public source gives all three, so
we combine them — and reconstruct the malicious bytes ourselves.

### Labels — `ossf/malicious-packages` (advisory list, no payloads)

[github.com/ossf/malicious-packages](https://github.com/ossf/malicious-packages)
is the OpenSSF's OSV-format **advisory** corpus. Layout (verified Aug 2026):

```
osv/malicious/npm/<pkg>/<MAL-YYYY-N>.json          # unscoped
osv/malicious/npm/@scope/<pkg>/<MAL-YYYY-N>.json   # scoped
```

Each file is an [OSV](https://ossf.github.io/osv-schema/) record naming a
malicious package. It is **labels only — there are no payload bytes here.** Once
a package is reported, the registry takes it down, which removes the very code
the advisory is about. In practice the records don't even pin a version: the
`affected` range is almost always `{"introduced": "0"}`, i.e. *the whole package
is malicious*, which our fetcher surfaces honestly as `"versions": ["*"]`.

`fetch-ossf.mjs` samples this list into `eval/labels-npm.json` (see below).

### Real bytes — `DataDog/malicious-software-packages-dataset` (not redistributed)

[github.com/DataDog/malicious-software-packages-dataset](https://github.com/DataDog/malicious-software-packages-dataset)
*does* ship the actual samples, as **encrypted zips with the password
`infected`** (the AV convention), laid out as
`samples/<ecosystem>/<category>/<pkg>/<version>/<file>.zip`, with a
`manifest.json` per ecosystem and an `extract.sh` helper.

We deliberately **do not vendor, download, or redistribute those bytes** — it is
live malware, and DeltaGate is a zero-dependency tool that pulls nothing into the
repo. If you want to measure against real payloads, clone that dataset yourself,
extract with the `infected` password, load a sample directory with `loadDir`
from `../src/loaders.js`, and pass the two Maps to `analyzeArtifacts`. Until then
we reconstruct the attack **shapes** in code (see `run.mjs`), which exercises the
exact rule surface without shipping a weapon.

### Negatives — live benign updates (`benign.json`)

The negatives that actually matter are real, popular packages doing normal
version bumps. `benign.json` is a hand-curated list of ~27 widely-used npm
packages with two adjacent published versions each; `run.mjs` fetches both live
from the registry (via `fetchNpm`) and checks the update scores clear.

## Files

| file | what it is |
|------|-----------|
| `run.mjs` | the evaluation runner — synthetic attacks + hard negatives + live benign; prints metrics, writes `last-report.json` |
| `benign.json` | ~27 real npm packages × two adjacent versions — the negatives |
| `fetch-ossf.mjs` | samples `ossf/malicious-packages` → `labels-npm.json` |
| `worker-analyze.mjs` | runs one analysis in a worker thread so a hung (ReDoS) analysis can be hard-killed instead of taking the harness down |
| `labels-npm.json` | generated: a sample of real malicious npm package labels |
| `last-report.json` | generated: the full machine-readable result of the last run |

## Running

```sh
node eval/run.mjs          # full eval; live-fetches benign.json, ~20–30s online
node eval/fetch-ossf.mjs   # refresh labels-npm.json (default sample cap 200)
node eval/fetch-ossf.mjs 400   # larger sample
GITHUB_TOKEN=ghp_… node eval/fetch-ossf.mjs   # 5000 req/hr instead of 60
```

`run.mjs` skips live pairs gracefully when offline (the FP rate then reflects the
synthetic hard-negatives only). Suggested `package.json` script:

```json
"scripts": { "eval": "node eval/run.mjs" }
```

### `fetch-ossf.mjs`, rate limits, and truncation

The metadata call goes through the GitHub API (60 req/hr unauthenticated, 5000
with `GITHUB_TOKEN`); record bodies are then read from the `raw.githubusercontent.com`
CDN, which spends no API quota. The npm advisory tree has ~37k records — more
than GitHub's tree API returns in one response, so the listing is **truncated**
(flagged in the output and in `labels-npm.json.listedTruncated`). We sample the
listed subset round-robin across MAL years so the sample spans 2022→2026 rather
than the head of the alphabet. Dropped records (non-200, parse errors) are
logged with reasons.

## What the harness measures — and what it found

Recall is computed over the **npm** synthetic shapes; a PyPI `.pth`-in-wheel
shape is included but scored separately as a documented cross-ecosystem gap (the
Phase-1 engine has no wheel/.pth rule). `verdict === 'HOLD'` (score < 50) counts
as *flagged*.

Latest run (Aug 2026, engine sentinel v0.0.1):

- **Synthetic npm attack recall: 8/8 (100%)** — keyv dropper, GlassWorm invisible
  unicode, PhantomRaven remote dep, chalk/debug decode-exec, packed obfuscation,
  native binary drop, net+exec loader, modified install hook.
- **Cross-ecosystem: 0/1** — the LiteLLM `.pth`-in-wheel passes (ALLOW). Expected:
  it is a PyPI shape and a tracked blind spot for the npm engine.
- **False-positive rate: 7.1% (2/28 negatives)** — `rimraf` and `glob` both trip
  `INSTALL_HOOK_MODIFIED` because their `prepare` script changed (a `tshy`
  build-tooling migration). See "Known findings" below.
- **DoS / ReDoS suspects: 3** — `lodash`, `prettier`, and `zod`: the analysis
  never terminated within 20s on these real, popular packages. See below.

### Known findings (for the engine owner — not fixable from `eval/`)

These live in shared `src/` files the harness must not edit; they are what an
eval is *for*:

1. **ReDoS in `heuristics.js` R7 (`OBFUSCATION_PACKED`).** The pattern
   `\\x[0-9a-f]{2}(?:.*\\x[0-9a-f]{2}){40,}` backtracks catastrophically on large
   minified bundles. Reproduced on real packages (`prettier` `plugins/flow.js`,
   `glimmer.js`, `html.js`, `markdown.js`, …; `lodash.js`; `zod` `index.umd.js`) —
   `analyzeArtifacts` never returns. This is a denial-of-service in the real
   `deltagate npm` CLI, not just the eval. A backtracking-free equivalent such as
   `/(?:\\x[0-9a-f]{2}){40,}|_0x[0-9a-f]{4,}/i` (require consecutive escapes) plus
   a line-length guard removes it. The harness itself is hardened against this by
   running each live analysis in a killable worker thread.
2. **`prepare` is FP-prone in `INSTALL_HOOKS`.** `prepare` does **not** run when a
   package is installed as a normal registry dependency (only `preinstall` /
   `install` / `postinstall` do); it runs for the package's own local/git
   installs and on publish. Flagging a changed `prepare` on a consumed dependency
   produced both false positives above. Dropping `prepare` from `INSTALL_HOOKS`
   (or gating it to git/local sources) takes the measured FP rate to 0% on this
   corpus without weakening any real-attack detection.
