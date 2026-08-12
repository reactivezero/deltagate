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
# analyze a live npm update
node bin/deltagate.js npm left-pad 1.2.0 1.3.0

# analyze two local package directories (offline)
node bin/deltagate.js diff ./pkg-old ./pkg-new

# raw verdict record (what gets published to the open DB)
node bin/deltagate.js npm <pkg> <from> <to> --json

# run the test suite
npm test
```

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
src/score.js         MIN-fusion of ceilings → score / band / verdict
src/analyze.js       orchestrator → verdict record
test/run.js          golden tests reconstructing real attack shapes
```

## Not built yet (next phases)

- **AI layer** — an LLM reads the changed code for intent on diffs that pass the
  rules. It never emits the score; it returns typed, evidence-anchored findings
  that can only *lower* the score. (Judges the "clean, low confidence" cases.)
- **Open verdict DB** — a miss fires a request; our backend analyzes it and
  publishes the signed verdict to a public repo so everyone benefits.
- **Local enforcement** — the metadata-filtering proxy / wrappers that actually
  hold the update in each package manager.
- **More ecosystems** — PyPI next, then the rest via per-ecosystem adapters.

## License

Apache-2.0 (client/engine). See `LICENSE`.
