# Performance Review — euRedact 0.3.6 (Python + TypeScript)

**Status (2026-07-31): the three high-impact findings and most mediums are
fixed.** Measured after the work, on the same corpus and machine: Python 1 MB
3,597 ms to 2,354 ms, TypeScript 1 MB 1,176 ms to 311 ms, with byte-identical
redacted output and cross-SDK parity unchanged. The two architectural items
(candidate-span deduplication, and the 346 always-on regex passes) are **not**
done — they are noted as remaining work in the closing summary. This document is
kept as the point-in-time review that prompted the work.

---

**Date:** 2026-07-31

**Method:** two profiling agents (cProfile on Python with and without the `fast`
extra; `--cpu-prof` on Node) plus a macro-benchmark agent feeding both packages a
byte-identical corpus. The two headline cross-package findings were independently
verified. Hardware: Apple M3 Pro, 12 cores, 36 GB, Python 3.14.3 / Node 22.12.
Nothing was modified during the review.

**Bottom line:** Correctness-wise the engines agree exactly — identical detection
counts (32 / 683 / 8,374) on every shared corpus. But **TypeScript is 4–14× faster
than Python** on the same input, and **both packages scale superlinearly** for
reasons that are a handful of specific loops, not the regex engine. Two fixes —
one per package, both small and local — remove essentially all the superlinearity.
Sub-100KB documents are healthy today; the problems only bite at scale.

---

## Baseline (shared corpus, cache off, all countries)

| | 5 KB | 50 KB | 1 MB | peak RSS @1MB |
|---|---|---|---|---|
| **py-plain** | 17.0 ms (319k c/s) | 252 ms (199k c/s) | 5,107 ms (196k c/s) | 107 MB |
| **py-fast** | 4.2 ms (1.31M c/s) | 147 ms (341k c/s) | 3,597 ms (278k c/s) | 108 MB |
| **TypeScript** | 1.2 ms (4.47M c/s) | 27.7 ms (1.81M c/s) | 1,176 ms (852k c/s) | 235 MB |

Cold start: Node 73 ms, Python ~110 ms (the `fast` extras add no measurable import
cost). TS buys its speed with ~2× the memory.

---

## High impact

### P1 — Fragment-check loop is O(candidates × failed_spans); dominant Python cost

`euredact-python/src/euredact/rules/engine.py:422-428`. For every validator-less
candidate it does a `bisect_right` and then walks — and *list-slice copies* — the
failed-span prefix. At 1M chars that is 70,377 candidates × 3,574 spans =
**125.6M inner iterations**, growing 100× for a 10× size increase. Standalone
replay: **5.85 s vs 0.012 s** for a prefix-max-of-end array producing identical
output (957 fragments) — ~480×. This is **43% of plain / 57% of fast** runtime at
1M and the sole cause of Python's superlinear scaling.

The TS sibling has the same shape at `engine.ts:347-357` but much cheaper (part of
a ~180 ms residual); notably the demotion check just above it already uses binary
search, so the technique is right there.

*Fix:* precompute prefix-max of span ends over sorted `all_failed`; skip when
`prefix_max[hi] < match.end`, else scan backwards with the same bound. No slicing.

### P2 — Quadratic string-splice in the redaction loop (both packages)

`euredact-python/src/euredact/sdk.py:189` and `euredact-ts/src/sdk.ts:177-184`
both do `redacted = redacted[:start] + replacement + redacted[end:]` per detection,
copying the whole document each time. Measured directly on the Python pattern:
**268 ms vs 0.7 ms (362×)** at 1M chars / 8,000 detections.

Impact differs sharply by package — **61% of total TS runtime** (1,678 ms vs 2.0 ms
measured) but only 3–5% in Python, because Python's other phases dwarf it.

*Fix (identical in both):* one forward pass appending slices into a list, joined
once. Detections are already sorted and non-overlapping.

### P3 — `occursAsLowercaseWord` scans the whole document per BIC candidate

`euredact-ts/src/rules/suppressors.ts:592-610` and
`euredact-python/src/euredact/rules/suppressors.py:939` (both confirmed). Per BIC
candidate it runs a fresh word-boundary regex over the entire text. TS measured
cleanly quadratic on BIC-dense input: 91 ms @100k → 419 ms @200k →
**1,584 ms @400k**. Python's C-level substring pre-check hides it on realistic
documents (invisible in a 1.9 MB profile with 300 BICs), so this is **acute in TS,
latent in Python**.

*Fix:* tokenize the document once per `detect()` into a lowercase-word Set and test
membership.

---

## Medium impact

- **~69% of candidates are duplicate spans, each re-suppressed (TS-measured,
  applies to both).** At 1M chars: 152,521 raw matches but only 47,731 unique
  `(span, entityType)`. POSTAL_CODE alone is 99,325 — 65% of all candidates —
  because SI/BG/HU/CY register byte-identical 4-digit patterns that each match the
  same spans. Validation and the whole suppressor chain run per raw match. Deduping
  before suppression saves an estimated ~400 ms at 1M; merging identical patterns
  across countries at compile time would also cut scan passes.

- **`ID_CUE_BEFORE` backtracks.** `euredact-ts/src/rules/suppressors.ts:672` — five
  alternatives each starting `[\w\-]*` means quintuple quadratic retry per position.
  197 ms isolated, the single most expensive regex in the TS engine. Factor to
  `[\w\-]*(?:Nr|N[°ºo]|Nummer|...)`.

- **Result cache is capped by entry count, not bytes — in both packages.**
  `cache.py:15` and `cache.ts:18` cap at 1024 *entries*, each holding a full
  `redacted_text`. Measured: 200 cached 1MB results = **+205 MB RSS** (Python);
  50 × 200k = 56 MB (TS). At the default cap that is on the order of a gigabyte of
  retained PII-bearing text — which compounds the retention concern from the
  security review, where `clear()` exists precisely to free this. Use a byte budget,
  or skip caching above a size threshold.

- **346 full-text regex passes per call, most matching nothing.**
  `matchers.py:394` / `matchers.ts:50-65`. This is 77% of Python's 100KB runtime,
  and the cost is *flat-spread* — the top 20 patterns are only 12.3% of scan time,
  so there is no single hot regex to fix. On the TS mixed corpus 255 of 346 patterns
  produced zero matches yet each paid a full scan. It is only ~7% of TS runtime
  today, but it becomes the floor once P1–P3 are fixed. A required-literal prefilter
  or folding same-shape patterns is the structural answer.

---

## Notable non-findings

**Restricting `countries=` buys nothing** — 50KB doc: NL vs all is 259 vs 252 ms
(Python plain), 26.7 vs 27.7 ms (TS). Both engines always call
`load_countries(None)` and run all patterns; the `countryCodes` parameter on
`MultiPatternMatcher.scan` is dead by contract. This is the documented country-blind
design, not a bug, but it is worth stating in the docs since the API strongly
implies otherwise — users will reasonably expect narrowing scope to speed things up.

**The cache is enormously effective when it hits** — 11,100× (Python) / 47× (TS) on
a repeated 50KB document.

Startup and compilation are lazy, cached, and fine (~16–28 ms to compile all 346
patterns). `_deduplicate` is **not** O(n²) — it is O(n log n) sort plus an int-set,
~1.3% of runtime. IBAN mod-97 is properly chunked. The normalizer has a fast path
that skips offset mapping when NFC is length-preserving. No per-call regex
recompilation anywhere except the P3 site.

---

## Minor

- Per-candidate `new Set([...])` allocation in `suppressors.ts:319,328` (~260k
  allocations per 1MB; GC is 10.7% of the TS profile — hoist to module constants
  like every other suppressor does).
- `tierOf` called inside the sort comparator rather than precomputed
  (`engine.ts:451`).
- `structural.py:38-63` runs two full-text passes even when `detect_dates=False`
  filters the results away.
- `add_custom_pattern` rebuilds both automata per call (~11 ms), so registering
  patterns in a loop is quadratic.
- `cache.key` builds a full copy of the input before hashing (0.7 ms/MB).

---

## Suggested priority

1. **P1 (Python `engine.py:422`)** — biggest single win, restores linear scaling.
   Estimated 1M: plain 6.4 s → ~3.6 s, fast 4.8 s → ~1.9 s.
2. **P2 (both `sdk` splice loops)** — trivial fix, 61% of TS runtime. Estimated TS
   1M: 2.73 s → ~1.06 s.
3. **P3 + candidate dedup + `ID_CUE_BEFORE`** — together these take TS to roughly
   0.55–0.65 s at 1M (~4.5×) and eliminate the remaining superlinear cliff.
4. **Cache byte-budgeting** — memory correctness, and it overlaps the PII-retention
   finding from the security review.

After 1–3, both engines are dominated by the matcher scan itself, and further gains
require the architectural change (prefilter or pattern merging) rather than bug
fixes.

---

## Caveat on the numbers

The two profiling agents used their own generated corpora, so their absolute timings
differ from the shared-corpus table above (e.g. the TS agent's 1M doc had 15.4k
detections vs 8.4k in the shared one). Percentages and scaling classes are consistent
across all three runs; treat the shared-corpus table as the canonical cross-package
comparison.
