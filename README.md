# DeltaGate

**The gate the whole ecosystem built — and left empty.**

Every package manager now delays new releases at the gate (`pnpm` defaults to a
24-hour cooldown; npm, uv, Bun, Dependabot all followed). Every one of those
gates is a **dumb timer**. DeltaGate reads the actual code **diff** between the
version you have and the update, scores its intent, and holds anything dangerous
back — locally, across every language, with the reasoning in the open.

![license](https://img.shields.io/badge/license-Apache--2.0-blue)
![node](https://img.shields.io/badge/node-%E2%89%A520-informational)
![dependencies](https://img.shields.io/badge/runtime%20deps-0-brightgreen)
![ecosystems](https://img.shields.io/badge/ecosystems-npm%20·%20PyPI%20·%20Cargo%20·%20RubyGems-8A63D2)
![false positives](https://img.shields.io/badge/eval%20FP-0%25%20·%208%2F8%20recall-brightgreen)

```text
  npm keyv  5.9.0 → 6.0.0
  ● BLOCK  8/100  verdict HOLD  confidence high
  + "preinstall": "node setup.mjs"
  + Math_Symbol.js  (727 KB, entropy 7.98)

  → INSTALL_HOOK_WITH_BLOB   install-time script paired with a new opaque blob
  → OPAQUE_BLOB_NEW          727 KB high-entropy blob — unreadable, so unauditable
  → INSTALL_HOOK_NEW         new "preinstall" runs code on install

  Held. You stay on 5.9.0.   Override: deltagate allow keyv@6.0.0
```

---

## Why

For the majority of high-impact supply-chain attacks of 2024–26 — chalk/debug,
`@solana/web3.js`, both Shai-Hulud worm waves, keyv/cacheable, TanStack, axios —
the payload shipped **inside** the published version: diff-visible, and flaggable
by reading the change. A peer-reviewed prototype (RAID 2025) hit **209/209**
historical malicious npm updates at a **0.4%** false-positive rate.

And provenance no longer saves you: TanStack shipped malware with a valid SLSA
Build L3 attestation, keyv with valid npm provenance. Signatures prove *who built
it* — never *what it does*. Reading the code is the thing that still works.

## Quickstart

Needs Node ≥ 20. **Zero dependencies to install.**

```bash
git clone https://github.com/reactivezero/deltagate && cd deltagate

# analyze a live update — npm, PyPI, Cargo, or RubyGems
node bin/deltagate.js npm   chalk 5.3.0 5.3.1
node bin/deltagate.js pypi   requests 2.31.0 2.32.0
node bin/deltagate.js cargo  anyhow 1.0.85 1.0.86
node bin/deltagate.js gem    colorize 0.8.1 1.0.0

# add the AI intent layer (needs an Anthropic API key — see below)
ANTHROPIC_API_KEY=sk-ant-... node bin/deltagate.js npm <pkg> <from> <to> --ai

# analyze two local package directories, or emit the raw record
node bin/deltagate.js diff ./old ./new
node bin/deltagate.js npm <pkg> <from> <to> --json
```

The CLI exits `1` when the gate would **hold** and `0` when it allows — it drops
straight into CI.

## How it works

Three independent layers, fused by **MIN** so an attacker has to beat all three
at once — and beating the most attackable one (the LLM) buys nothing.

| Layer | What it does |
|---|---|
| **1 · Sentinel** (deterministic) | ~9 signed rules over the raw bytes of the diff. Each hit sets a score **ceiling**. Catches most real attacks alone, and is immune to prompt injection because no model is involved. |
| **2 · Adapters** (per-ecosystem) | Install/build-hook and dependency rules that only the ecosystem knows — npm scripts, `setup.py`/`.pth`, `build.rs`, gemspec extensions. |
| **3 · AI** (optional, `--ai`) | An LLM reads the changed code for *intent*. It **never emits a score** — it returns typed, evidence-anchored findings that can only **lower** it. |

> **The invariant:** deterministic evidence sets ceilings that nothing downstream
> can raise. A fully prompt-injected or compromised model degrades the system to
> "deterministic rules only" — which already catch most attacks. Injection,
> poisoning, even a bad model can cause a *false hold*, never a *false allow*. And
> a false hold is nearly free: you just stay on the version you already had.

## What the deterministic layer detects

Each rule sets a score *ceiling* (the final score is the **minimum** of all
ceilings), and each traces to a real attack:

| Rule | Signal | Mirrors |
|---|---|---|
| `INSTALL_HOOK_NEW` / `_MODIFIED` | new/changed pre/post/install script | Shai-Hulud, keyv |
| `INSTALL_HOOK_WITH_BLOB` | install hook **+** opaque blob together | keyv dropper |
| `OPAQUE_BLOB_NEW` | new large high-entropy unreadable file | keyv 727 KB stage |
| `NATIVE_BINARY_NEW` | first machine-code binary in a source pkg | xz-style plant |
| `INVISIBLE_UNICODE` | invisible/bidi codepoints in code | GlassWorm |
| `NON_REGISTRY_DEP` | dependency resolves outside the registry | PhantomRaven |
| `EVAL_DECODE_EXEC` | decodes a string then executes it | chalk/debug clipper |
| `OBFUSCATION_PACKED` | code that *became* obfuscated this version | packed payloads |
| `NET_PLUS_EXEC` | new file that fetches **and** executes | axios / Ultralytics |
| PyPI · Cargo · Ruby | `setup.py`/`.pth`, `build.rs`, gemspec extensions | LiteLLM `.pth` |

Everything runs on **raw bytes**, never rendered text — that's what makes
invisible unicode and opaque blobs visible.

## The score

One number, 0–100 (100 = clean). The default gate blocks below 50, coupled with
confidence so a low-confidence low score *holds and re-analyzes* rather than
asserting the package is bad.

| Band | Range | Behavior |
|---|---|---|
| 🟥 **Block** | 0–24 | filtered; override needs a typed reason |
| 🟧 **Hold** | 25–49 | held; you stay on stable; one-line override |
| 🟨 **Caution** | 50–69 | allowed, annotated |
| 🟩 **Clear** | 70–100 | installs silently |

## The AI layer (`--ai`)

The diff is attacker-controlled, and malware already embeds text to fool LLM
scanners (the Hades PyPI campaign). The harness is built to survive that:

- The model returns **typed capability findings, never a score**; findings can
  only lower it, and a fixed table does the scoring.
- The diff is fed as **untrusted data** — comments split off, all non-ASCII
  armored to visible escapes, wrapped in a per-run nonce.
- A **seeded probe** each run detects a suppressed or instruction-following
  model; every finding must be **grounded** in the sent code or it's dropped;
  detected prompt-injection text caps the score at **5**.

Uses raw `fetch`, **no SDK dependency** (a supply-chain tool shouldn't ship a
dependency tree). Model via `DELTAGATE_MODEL` (default `claude-haiku-4-5`).
Needs an **Anthropic API key** (`console.anthropic.com`) — a Claude.ai / Claude
Max subscription is billed separately and does not grant API access.

## Hold the update, don't just report it

DeltaGate can sit in front of your package manager and *hold* a risky version so
the resolver never selects it — no build break, you simply stay on what you have.

```bash
# run any install through the gate, one-off (nothing written to disk)
deltagate run -- npm install left-pad

# or wire it in persistently (reversible)
deltagate proxy &     # localhost npm registry filter
deltagate enable      # point ~/.npmrc at the proxy
deltagate status      # what's wired
deltagate disable     # revert, byte-for-byte
```

It works by **filtering the version list**, not rewriting bytes: a held version
disappears from the packument the resolver sees, so npm settles on the newest
allowed version — and because tarball bytes are never touched, npm's integrity
check still passes on whatever it installs. (npm today; other managers follow
the same adapter pattern.)

## Open verdict database

One analysis of a given diff should serve everyone. Every verdict is a
**content-addressed record** — keyed by the exact artifact digests, so a cache
hit is the same bytes — and analysis is read-through: local cache → a public
static DB (`DELTAGATE_DB_URL`, servable straight from GitHub raw or a CDN) →
analyze-it-yourself on a miss.

```bash
deltagate lookup npm chalk 5.3.0 5.3.1   # query the DB, no analysis
deltagate export verdicts.jsonl          # your local records, shareable
deltagate npm <pkg> <from> <to> --fresh  # bypass the cache
```

Records store finding **codes only** — never the attacker-controlled finding
text — so a published verdict can't carry a second-order prompt injection into
the next person's analysis. (The central service that pre-analyzes popular
packages and publishes the static tree is the next milestone; the record format,
local cache, and read-through are here today.)

## How it compares

| | AI on the **diff** | Blocks locally | Every language | **Open** verdicts |
|---|---|---|---|---|
| Socket.dev | whole package | malware only | 10+ | closed |
| Aikido Safe Chain | feed lookup | ✅ | JS + Py | positives only |
| cargo-vet | human audit | CI gate | Rust only | ✅ |
| **DeltaGate** | ✅ **the diff** | ✅ | 4 → more | ✅ **+ reasoning** |

The wedge: **diff-scoped AI + open reasoning + a local cross-ecosystem gate.**
Verdicts (and *why*) are meant to be published in the open so one analysis serves
everyone — free for every developer and team, forever, on open-source packages.

## Evaluation

`node eval/run.mjs` measures the engine against reconstructed 2024–26 attack
shapes and live benign updates:

```text
  Synthetic npm attack recall : 8/8   (100.0%)
  False positives             : 0/31  (0.0%)
  32 unit tests green (14 Sentinel + 18 AI harness)
```

The corpus uses `ossf/malicious-packages` for labels and Datadog's dataset for
real sample bytes — see [`eval/README.md`](eval/README.md).

## Project layout

```
bin/deltagate.js     CLI  (npm | pypi | cargo | gem | diff)
src/heuristics.js    Sentinel — ecosystem-agnostic rules
src/ecosystems/      per-ecosystem adapters (fetch + install-hook rules)
src/unpack.js        dependency-free tar / tar.gz / zip reader
src/normalize.js     per-file profile: sha256, entropy, unicode, magic bytes
src/score.js         MIN-fusion of ceilings + penalties → score / band / verdict
src/ai/              injection-resistant LLM harness
src/verdict/         open verdict DB: content-addressed records, cache, read-through
src/enforce/         local npm enforcement: filtering proxy, wrapper, reversible wiring
src/analyze.js       orchestrator → verdict record (+ verdict-DB read-through)
eval/                corpus + recall / false-positive harness
test/                golden tests (no API key needed)
```

## Status & roadmap

**Shipped:** deterministic engine · injection-resistant AI layer · npm, PyPI,
Cargo, RubyGems · eval harness · open verdict DB (records, cache, read-through) ·
local npm enforcement (filtering proxy + reversible wiring).
**Next:** the central publish backend (pre-analyze popular packages → public
static DB) · verdict signing & consensus · enforcement for PyPI/Cargo/RubyGems ·
Maven, NuGet, Go, Composer.

## Contributing & security

Issues and PRs welcome. Found a way past the gate? That's the most valuable kind
of report — open an issue with the diff shape that slips through.

## License

Apache-2.0. See [`LICENSE`](LICENSE).
