# DeltaGate

A cross-language dependency-update gate. When a package you depend on has an
update, DeltaGate fetches both versions **as published artifacts**, diffs them,
and holds the update if the change looks dangerous — leaving your current stable
version in place. It never modifies your machine beyond allowing or holding an
update, and every verdict (with its reasoning) is meant to be published in the
open so the next person benefits from your analysis.

> **Status: Phase 1 — the deterministic engine, npm only.**
> This is the *Sentinel* layer: fast, rule-based, zero-AI, zero-dependency. It
> catches most 2024–26 supply-chain attacks on its own and is the trust anchor
> the AI and enforcement layers build on. See the full architecture in the
> design doc.

## Run it

Needs Node ≥ 20. **No dependencies to install.**

```bash
# analyze a live update — npm, PyPI, Cargo, or RubyGems
node bin/deltagate.js npm   left-pad 1.2.0 1.3.0
node bin/deltagate.js pypi   requests 2.31.0 2.32.0
node bin/deltagate.js cargo  anyhow 1.0.85 1.0.86
node bin/deltagate.js gem    colorize 0.8.1 1.0.0

# analyze two local package directories (offline)
node bin/deltagate.js diff ./pkg-old ./pkg-new

# add the AI intent layer (needs an Anthropic API key, not a Claude.ai subscription)
ANTHROPIC_API_KEY=sk-ant-... node bin/deltagate.js npm <pkg> <from> <to> --ai

# raw verdict record (what gets published to the open DB)
node bin/deltagate.js npm <pkg> <from> <to> --json

# run the test suite
npm test
```

## The AI layer (`--ai`)

On top of the deterministic rules, an LLM reads the changed code for *intent*.
The harness is built to survive a hostile diff:

- The model **never emits a score** — it returns typed, evidence-anchored
  capability findings, and a fixed table turns those into caps/penalties.
- Findings can only **lower** the score, never raise it. A fully
  prompt-injected model degrades the system to deterministic-rules-only.
- The diff is fed as **untrusted data**: comments split into a separate channel,
  all non-ASCII armored to visible escapes, wrapped in a per-run nonce.
- A **seeded probe** every run detects a suppressed or instruction-following
  model; a compliance nonce catches a model that can't follow the contract.
- Every finding is **grounded** (its cited token must exist in the sent code) or
  it's dropped. Detected prompt-injection text caps the score at 5.

Model is configurable via `DELTAGATE_MODEL` (default `claude-haiku-4-5`). The
API client uses raw `fetch` — no SDK dependency, keeping the tool zero-dep.

The CLI exits `1` when the gate would **hold** an update and `0` when it allows
it, so it drops straight into CI.

## What the Sentinel layer detects today

Each rule sets a score *ceiling* (the final score is the **minimum** of all
ceilings), and each traces to a real attack:

| Rule | Signal | Attack it mirrors |
|---|---|---|
| `INSTALL_HOOK_NEW` / `_MODIFIED` | new/changed pre/post/install script | Shai-Hulud, keyv, LiteLLM |
| `OPAQUE_BLOB_NEW` | new large high-entropy unreadable file | keyv 727 KB second stage |
| `INSTALL_HOOK_WITH_BLOB` | install hook **+** opaque blob together | keyv dropper shape |
| `NATIVE_BINARY_NEW` | first machine-code binary in a source pkg | xz-style planted binaries |
| `INVISIBLE_UNICODE` | invisible/bidi codepoints in code | GlassWorm |
| `NON_REGISTRY_DEP` | dependency resolves outside the registry | PhantomRaven remote deps |
| `EVAL_DECODE_EXEC` | decodes a string then executes it | chalk/debug clipper |
| `OBFUSCATION_PACKED` | packed / hex-escaped code | obfuscated payloads |
| `NET_PLUS_EXEC` | new file that fetches **and** executes | Ultralytics / axios loaders |

Everything runs on **raw bytes**, never rendered text — that's what makes
invisible-unicode and opaque blobs visible.

## How it's built

```
bin/deltagate.js     CLI
src/loaders.js       fetch from npm (integrity-verified) or a local dir
src/untar.js         dependency-free tar reader
src/normalize.js     per-file profile: sha256, entropy, unicode, magic bytes
src/heuristics.js    Sentinel — the deterministic rules (score ceilings)
src/score.js         MIN-fusion of ceilings + penalties → score / band / verdict
src/analyze.js       orchestrator → verdict record (selects the ecosystem adapter)
src/heuristics.js    Sentinel — ecosystem-agnostic rules
src/unpack.js        dependency-free tar / tar.gz / zip reader (wheels, crates, gems)
src/ecosystems/      per-ecosystem adapters (npm, pypi, cargo, rubygems): fetch + install-hook rules
src/ai/              injection-resistant LLM harness (schema, encode, client, harness)
test/run.js          golden tests reconstructing real attack shapes
test/ai.test.js      AI-harness tests (stub model, no API key needed)
eval/                corpus + eval harness (recall / false-positive measurement)
```

## Evaluation

`node eval/run.mjs` measures the engine against reconstructed attack shapes and
live benign updates. Current deterministic engine: **8/8 recall** on the
synthetic npm attack shapes, **0% false positives** across 31 benign updates.
The corpus uses `ossf/malicious-packages` for labels and Datadog's dataset for
real sample bytes (see `eval/README.md`).

## Not built yet (next phases)

- **Open verdict DB** — a miss fires a request; our backend analyzes it and
  publishes the signed verdict to a public repo so everyone benefits.
- **Local enforcement** — the metadata-filtering proxy / wrappers that actually
  hold the update in each package manager.
- **More ecosystems** — Maven, NuGet, Go, Composer round out the set.

## License

Apache-2.0 (client/engine). See `LICENSE`.
