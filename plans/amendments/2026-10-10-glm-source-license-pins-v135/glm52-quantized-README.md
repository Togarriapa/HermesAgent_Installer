---
license: mit
base_model: zai-org/GLM-5.2
pipeline_tag: text-generation
tags:
- colibri
- glm
- glm-5.2
- glm-5
- int4
- moe
- quantized
- gpu-poor
---

# GLM-5.2 — colibri int4 g64 container (grouped scales, int8 MTP head)

GLM-5.2 (744B MoE) converted for the [colibri](https://github.com/JustVugg/colibri)
streaming engine: **fmt=4 grouped int4 (group size 64)** expert weights with an
**int8 MTP head** for speculative decoding.

**Status (2026-08-10): fully GPU-validated. Run colibrì v1.5.0 or newer** — v1.3.0 is
the oldest build that runs this container correctly, but v1.5.0 patches two heap
out-of-bounds writes in the model loader that fire *before* inference, and downloading
a preconverted container from a third-party Hugging Face repo is exactly the trust
boundary those advisories name. See [Requirements](#requirements). The fmt=4 CUDA
path merged upstream (colibri #298), the engine validates this container
token-exact against the transformers oracle (32/32), and an independent quality
A/B measured grouped int4 **ahead of** per-row int4 (hellaswag acc_norm 87.0%
vs 83.5%, n=200 — colibri #326). This is the reference grouped-int4 container
for the engine.

**Independently reproduced as the fix for the reasoning-loop / EOS-starvation
failure** (colibri #455): a third-party 5-cell capture matrix — same engine,
same prompts, same flags, *only the container swapped* from per-row int4 to
this one — went 5/5 clean, including the `TEMP=0.9 NUCLEUS=0.95` setting that
was catastrophic on per-row. On this container the sampling knobs stop being
safety-critical.

## There is now a smaller, faster sibling — read this first

A **[3.06 bpw E8/IQ3 build of these same weights](https://huggingface.co/mastouri/GLM-5.2-colibri-E8-IQ3-with-int8-mtp)**
is available: **289 GB instead of 429 GB**, converted from the same FP8 parent, with no measurable
quality loss across hellaswag, arc_challenge and mmlu.

**Which one you want depends on whether your experts fit in memory**, and the answer genuinely
flips:

| your host | take |
|---|---|
| Streaming from NVMe, expert hit rate below ~99% | **E8.** Measured 22–33% *faster* than this container on a 16 GB card, because smaller experts raise residency from 93.5% to 97.4% and the disk wait collapses. |
| Experts fully resident, no disk reads | **This container.** E8's decode is dearer per expert (`expert-matmul` 24.1 s against 20.9 s), and with no misses left to eliminate that cost is all you get. Measured as a decode *regression* on 6×RTX 5090 ([colibri#452](https://github.com/JustVugg/colibri/issues/452)). |
| Want the reference container, or need colibrì older than v1.4.0 | **This container.** E8 requires v1.4.0+; earlier builds crash on fmt=6. |

Full measurements, methodology and caveats for both:
[colibri#452](https://github.com/JustVugg/colibri/issues/452#issuecomment-5155461138).

## Contents

- `out-00000..00140.safetensors` — 141 shards, 390.5 GB, int4 gs=64 experts
  (per-group f32 scales), int8 embed/lm_head, f32 norms
- `out-mtp-00000.safetensors` — 9.3 GB, MTP head at **int8** (int4 MTP heads
  give ~0% draft acceptance; int8 measures 39–59%)
- `config.json`, `tokenizer.json`, `tokenizer_config.json`, `generation_config.json`

## Why g64 over the per-row int4 container

Per-row scales let one outlier poison a whole row's precision and are implicated
in the repetition-attractor reports (colibri #225/#307). Grouped scales (one per
64 elements) cost ~12% more disk and measurably improve quality: hellaswag
acc_norm **87.0% vs 83.5%** per-row in the #326 A/B.

The same difference shows up as *stopping reliability*, not just accuracy. In
the #455 container-swap matrix (5 sampling cells, engine and prompts held
fixed), per-row int4 produced reasoning loops that never emitted EOS and ran to
the token budget; this container stopped cleanly in all 5, worst case included.
Run colibri **v1.3.0** or later alongside it — v1.2.0 carried the upstream fix
for the CUDA-path EOS-starvation bug and v1.3.0 adds the grouped-scale
attention fix, and container plus engine together are what make the stop
behaviour reliable.

## Requirements

- **Use colibrì v1.5.0 or newer.** The version notes below describe the *functional* floor for
  this container and still hold. Separately, v1.5.0 published
  [eight security advisories](https://github.com/JustVugg/colibri/security/advisories), two of
  them in the model loader itself — a crafted `tokenizer.json` or an unvalidated safetensors
  header gives heap out-of-bounds writes at load time, **before inference runs**
  ([GHSA-wc4x-3786-cxh7](https://github.com/JustVugg/colibri/security/advisories/GHSA-wc4x-3786-cxh7),
  [GHSA-4gw4-j89j-4c8r](https://github.com/JustVugg/colibri/security/advisories/GHSA-4gw4-j89j-4c8r)).
  The trust boundary the advisory names is downloading a preconverted model from a third-party
  Hugging Face repo, which is exactly what this is. Nothing in this container is hostile — I
  converted it myself from the official FP8 parent — but you cannot verify that from where you
  are standing. Run a patched loader.
- **colibri v1.3.0 (`01abef3`) is the functional floor.** The hard floor is commit
  `c98e5f8` (the #298 merge, 2026-07-20) — earlier builds either exit without
  loading fmt=4, silently fall back to CPU, or — with `CUDA_DENSE=1` — apply
  grouped scales per-row and produce garbage. Two later fixes matter enough to
  make v1.3.0 the version to use: **v1.2.0** fixed the thinking-loop /
  EOS-starvation bug, and **v1.3.0** fixed a ragged-attention kernel that
  applied *per-row* scales to this container's *group* scales, producing
  fluent-then-collapsing gibberish under `COLI_CUDA_ATTN=1` in served mode
  (colibri #685 / #692). v1.3.0 also fixes an expert-cache corruption where
  slots could be evicted mid-computation.
- **On any build before v1.3.0, do not set `COLI_CUDA_ATTN=1` with this
  container.** That is the ragged-attention path above. The failure is quiet
  and easy to misread — it hits prefill tiles, so answers begin as plausible
  text and then degrade into random tokens. Confirmed independently on 4×A100
  and H100. Fixed in v1.3.0; harmless there.
- ~400 GB of local NVMe — on one drive, **or split across several**:
  `COLI_MODEL_DIRS=<dir2>[;<dir3>...]` (in `dev` since #469) reads a distinct
  subset of the shards from each drive, so two 250 GB drives can host it
  together. Metadata stays in the primary model dir.
- 16 GB+ RAM minimum; RAM is the dominant performance lever (see below).

## Recommended config & measured performance

Reference box: RTX 5080 (sm_120, 16 GB) / Core Ultra 9 285K / 128 GB DDR5 /
Windows 11, full K=8, greedy. Full 12-cell benchmark record: colibri #467
(raw logs linked there).

```
COLI_CUDA=1  CUDA_DENSE=1  CUDA_EXPERT_GB=4  CUDA_RESERVE_GB=1  PIPE=1  DIRECT=1
# balanced (recommended): + CACHE_ROUTE=1 ROUTE_J=3 ROUTE_M=16 ROUTE_ALPHA=0.5
# speed:                   + CACHE_ROUTE=1 ROUTE_J=2 ROUTE_M=24 ROUTE_ALPHA=0.5
```

**Set `THINK=1` if you are asking anything that needs reasoning.** Without it the engine
writes an already-closed `<think></think>` into the prompt (`c/coli:676`), so GLM-5.2 is
instructed by its own template not to think and answers from reflex. On a question with a
trap in it the result looks like a broken model rather than a disabled feature — this was
reported against *this container* as "reasoning ability is basically zero"
([colibri#814](https://github.com/JustVugg/colibri/issues/814)), and the answer was the
flag, not the quantisation.

```bash
THINK=1 ./coli chat          # Windows:  set THINK=1
```

| config | decode tok/s | expert hit | notes |
|---|---:|---:|---|
| **speed** (CR M24) | **1.41** | 97% | swap 23% — experimental routing, label results accordingly |
| **balanced** (CR J3/M16) | **1.31** | 93% | swap 18%, route_agree 82% — recommended default |
| faithful (no CR, greedy-identical) | 0.89–0.96 | 79–87% | 0.96 with `PILOT_EVICT_GUARD=0` |
| same, without `DIRECT=1`/overlap | 0.67 | 84% | |
| true CPU (`--gpu none`), 128 GB RAM | 0.62 | 77% | |
| any compute, RAM capped to 25 GB | 0.31–0.38 | 16–33% | |

The two CR rows were measured on **colibri v1.3.0 (`01abef3`)**, warm-up run
discarded, two replicates for balanced (1.29 / 1.32) and one for speed;
run-to-run tok/s noise on this box is ~±0.04. Fidelity is unchanged from
v1.1.1 (route_kl 2.90–2.98, route_agree ~82% on both). The lower rows are from
the earlier #467 matrix (`dev` ≥ 2026-07-21: #495 tier fix, #497
eviction-guard fix, #477 AVX-512 MLA) and have not been re-run.

For reference, the same two cells measured **1.27 balanced / 1.38 speed on
v1.1.1** with the same prompt and config, so v1.3.0 is at parity or marginally
ahead — there is no version regression on this path.
`CACHE_ROUTE` is the opt-in cache-aware routing from colibri #161 — not
greedy-identical to true top-8 (quality evidence: MMLU A/B n.s. at n=200,
colibri #161); label CR results as experimental.

Notes from the measurements:

- **RAM dominates everything — until the working set fits, then it saturates.**
  Starving RAM is catastrophic: capped to 25 GB this box runs 0.31–0.38 tok/s at
  16–33% expert hit, against 1.31 at ~93% with the full 128 GB. That is the
  ~150% swing, and GPU is worth ~30–44% at full RAM and close to nothing when
  RAM-starved. But past the point where the hot working set fits, extra budget
  buys nothing: sweeping `RAM_GB` at 115 / auto (120.9) / 122 moved the resident
  set 2,291 → 2,431 → 2,456 experts and expert hit rate by **0.3 points**
  (93.0 / 93.3 / 93.1%). Give it enough RAM to hold the working set; there is no
  reward for more.

  Taken together with the VRAM-tier rows above, **expert hit rate on this
  container sits at ~93% across every residency knob** — a 4.4× VRAM tier range
  and a 165-expert RAM range all land at 93.0–93.8%. Routing is concentrated
  enough that the marginal expert is essentially never requested, so the
  remaining ~7% are genuinely cold and no cache size reaches them. That tail is
  the ceiling on a streaming host, and it is what the fully-resident hosts
  (DGX Spark, ~11 tok/s) are buying their way past.
- **`DIRECT=1` is drive-dependent**: +34% on this box's NVMe (DRAM-cached);
  QLC/DRAM-less or virtualised disks can be neutral to negative. Measure it.
- **Keep `CUDA_DENSE=1`. A bigger VRAM *expert* tier is not the lever it looks
  like.** Measured on this box, warm, same prompt, balanced config:

  | config | VRAM expert tier | decode tok/s | expert hit |
  |---|---:|---:|---:|
  | `CUDA_DENSE=1 CUDA_EXPERT_GB=4` (recommended) | 156 experts, 3.31 GB | **1.29** | 93.8% |
  | `CUDA_DENSE=1 CUDA_EXPERT_GB=auto` | 156, 3.31 GB | **1.30** | 93.3% |
  | `CUDA_DENSE=0 CUDA_EXPERT_GB=13` | 612, 13.0 GB | 1.15 (−11%) | 93.0% |
  | `CUDA_DENSE=0 CUDA_EXPERT_GB=auto` | 692, 14.69 GB | **0.57 (−56%)** | 93.5% |

  Hit rate is flat at 93.0–93.8% while the VRAM tier varies **4.4×**. That is
  the whole result: a RAM-resident expert already counts as a hit, so enlarging
  the VRAM tier does not raise residency — it only moves some hits closer, and
  it costs you the dense weights. The principle is that **VRAM should hold what
  is touched on every token (the ~10.9 GB of dense tensors), not what is touched
  occasionally (individual experts)**. Expert residency belongs in RAM, which is
  cheap and plentiful. `CUDA_EXPERT_GB=auto` sizes to 3.3 GB here and is within
  noise of the explicit `4` — the auto-sizing is already right.

  The last row is a hazard worth stating plainly: with dense off and the tier
  sized to the whole card, 14.69 GB of a 17.1 GB card leaves almost nothing for
  activations, prefill blows out (36 s vs 15 s for the same 19 tokens) and
  decode more than halves — at *unchanged* hit rate, so it is memory pressure,
  not routing. Do not chase a large expert tier on a 16 GB card.
- **`CUDA_RELEASE_HOST=1` scales with your VRAM tier, not with the flag.** It
  frees the duplicate host copy of every VRAM-tier expert so the RAM tier can
  use that memory (colibri #686). On this box the tier is only 3.31 GB and the
  effect is **within noise** — balanced 1.29/1.32 default vs 1.33/1.30 with it
  on, a 0.01 gap against a ±0.04 band. On a single GPU with a *large* tier it
  is transformative: 1.10 → 4.18–5.37 tok/s measured upstream on 1×H200/235 GB,
  and it matters most on unified-memory hosts (GB10) where the duplicate copy
  competes for the same physical pool. v1.3.0 enables it by default when
  `PIN_GB` is large. Rule of thumb: worth setting if your VRAM expert tier is a
  meaningful fraction of system RAM; ignore it if it isn't.
- **Speculation under CUDA — leave it off on streaming boxes.** Measured on
  this box at the balanced config (v1.1.1, warm, `NGEN=96`, `TEMP=0`): baseline
  1.28 tok/s → n-gram PLD `DRAFT=3` **0.67 (−48%)** → MTP head
  `COLI_CUDA_MTP=1 DRAFT=3` **0.61 (−52%)**. Drafting itself works (PLD accepts
  2.46 tokens/forward at 49% acceptance); what kills it is that the multi-token
  verify forward widens the per-forward expert union, so hit rate falls
  92.5% → 86% and each forward costs >2× on disk. The deciding variable is
  **expert residency**, not the speculator: the same PLD lever measures **+66%**
  on a ~100%-resident host (DGX Spark, colibri #161). Break-even sits between
  ~92% and ~99.9% hit — above it speculation pays, below it it costs. On CPU,
  MTP is on by default and helps.
- Residency at the recommended config: 12.48 GB dense (952 tensors) + 109 hot
  experts (2.31 GB) in VRAM; no TDR, zero fallbacks.

## What is inside this container

All 19,200 routed experts have been probed and mapped against a 17-category set — see
[colibri#175](https://github.com/JustVugg/colibri/issues/175) and the artefacts in
[`traces-175`](https://github.com/mohamedmastouri2000-boop/colibri/releases/tag/traces-175).
Short version for `PIN` users: every topic touches ~85% of the model on its own, so domain
*exclusion* does not work, but domain *weighting* is well supported — and a profile built from
English probes largely transfers to other languages, because routing tracks topic more strongly
than it tracks language.

## Benchmarking this container: two traps

Both of these cost real time to discover, so they are worth stating.

**`.coli_usage` is shared mutable state between your benchmark arms.** The
engine appends expert-selection history to `<model>/.coli_usage` on every turn,
and `PIN=auto` derives the pinned tier from it. So each run silently changes the
placement the *next* run inherits. Comparing configs back-to-back therefore
compares config *plus* an evolving pin history, and the effect is not small: in
one session here a control arm at identical settings drifted from 1.29 to 0.81
tok/s across roughly twenty-five runs. If you are measuring anything finer than
a ~20% effect, snapshot `.coli_usage` before the sweep and restore it before
each arm. An unexplained "this version got slower" is very often this.

**As of colibrì v1.7.0 you can simply set `USAGE_SAVE=0`.** On earlier builds that flag was
silently ignored on this engine (implemented in `inkling.c` and `kimi_k3.c` only, while
`colibri.c` wrote the history unconditionally) — reported as
[#1039](https://github.com/JustVugg/colibri/issues/1039), fixed in
[#1122](https://github.com/JustVugg/colibri/pull/1122). Below v1.7.0, snapshot and restore is the
only isolation that actually works.

**Warm-up matters more than usual, and single runs mislead.** Prefill and decode
both improve substantially between a cold first run and a warm one. Discard a
warm-up run, then take at least two replicates per arm: on this box the
run-to-run noise is ~±0.04 tok/s in a settled session, but arms that change the
per-forward expert union (any speculation) are far noisier — one such arm here
spread 0.66 → 1.04 tok/s while its acceptance and hit-rate metrics replicated
tightly to within a point. The speculation behaviour is stable; the wall-clock
is not, because the variance lives in disk service time.

## Windows notes

Current `dev` auto-enables CUDA on a bare run when a GPU is present (no flags
needed). To force a true CPU run use `--gpu none`, or `COLI_CUDA=0` (honoured
since #468 — on older builds it was silently overridden by the auto-enable, so
pre-#468 Windows "CPU" benchmarks taken on GPU boxes were GPU-assisted).

## Provenance

Converted from the official FP8 checkpoint with colibri's
`c/tools/convert_fp8_to_int4.py` (`--group-size 64`, ebits 4, io-bits 8) plus a
corrected local MTP pass (int8; see colibri #355 for the converter footgun and
fix). License follows the base model (zai-org/GLM-5.2, MIT).

## Author

Container built and tested by [Mohamed Mastouri](https://github.com/mohamedmastouri2000-boop)
on the colibri issue-306 reference box, at the request of the colibri
maintainers. Related upstream work by the same author: the #298 fmt=4
correctness validation, the `COLI_MODEL_DIRS` N-drive split (#469), the Windows
`COLI_CUDA=0` fix (#468), and the resource-matrix benchmark record (#467).
