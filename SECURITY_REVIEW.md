# Security Review — euRedact (Python + TypeScript)

**Status (2026-07-31): all High and Medium findings below are fixed**, plus
every Low except those noted as deliberately deferred in the closing summary.
See the `Unreleased` sections of both CHANGELOGs for what changed. This document
is kept as the point-in-time review that prompted the work; the findings are
described in the present tense as they were when found.

> **Action still required by a human:** the publish jobs now declare
> `environment: release`. Publishing **fails closed** until a GitHub environment
> of that name exists and both the PyPI and npm trusted-publisher entries name
> it too. See `.claude/skills/release/SKILL.md`.

---

**Date:** 2026-07-31
**Scope:** `euredact-python`, `euredact-ts`, CI/CD, supply chain, secrets/PII.

Reviewed by five parallel audits plus cross-package verification of every ReDoS
claim (timings measured live). Nothing was modified during the review.

**Bottom line:** The package is well-built in the ways that usually go wrong —
zero runtime dependencies, no `eval`/`pickle`/`subprocess`/network in shipped
code, OIDC-based publishing, SHA-pinned Actions, no real secrets in 39 commits of
history, synthetic fixtures, and the SSH keypair at the repo root is correctly
gitignored and never committed. The real risk is concentrated in **denial-of-service
via regex** and **one thread-safety bug that silently drops PII** — both serious
for a library whose whole job is to run untrusted text through many regexes and
never miss an entity.

---

## High severity

### H1 — ReDoS in the shared SECRET high-entropy pattern (both packages)

`euredact-python/.../rules/countries/_shared.py:390` and
`euredact-ts/src/rules/countries/index.ts:178` both use
`\b[A-Za-z0-9_\-+/]{24,}[A-Za-z0-9_\-+/=]*\b`. Two adjacent quantified classes
over overlapping alphabets backtrack **quadratically** when the trailing `\b`
can't be satisfied. This pattern runs on *every* `redact()` call regardless of
country/context (the context gate filters *after* the regex runs).

Measured, clean 4×-per-doubling:

| input | Python | TypeScript |
|-------|--------|------------|
| 10k   | 0.62s  | 0.13s      |
| 20k   | 2.48s  | 0.53s      |
| 40k   | 9.90s  | 2.1s       |
| 80k   | 39.8s  | 8.3s       |

Needs **no attacker** — a plain-text horizontal rule (`x--------…`) triggers it,
and at the default 10 MB input cap a single document pins a CPU core for hours.
Neither package's own custom-pattern ReDoS guard catches this shape.

### H2 — ReDoS in the EMAIL pattern (Python only)

`_shared.py:82`: `\b[\w._%+\-]+@(?:[\w\-]+\.)+[a-zA-Z]{2,}\b`. Because `.` is in
the local-part class, a long unbroken dotted token plus any `@` in the document
backtracks O(L²). Measured: 8k→0.09s, scaling to ~44 hours at the 10 MB cap.
Fires on machine-generated input (manifests, minified blobs, stack traces).

**The TypeScript EMAIL pattern is NOT vulnerable** — it uses a negative lookbehind
`(?<![...])` instead of `\b`, which anchors the match; measured flat at 0ms up to
16k. Porting the TS anchoring style to Python fixes it.

### H3 — Data race silently drops PII detections (Python)

`rules/matchers.py:262-333`: `add_custom_pattern()` → `compile()` clears and
repopulates the matcher's index in place while holding `RuleEngine._lock`, but
`engine.py:178` releases that lock *before* `self._matcher.scan()`. A concurrent
scan indexes a half-built structure; the `zip()` at `matchers.py:379` truncates
to the shorter list and skips patterns. Reproduced: 464 anomalous scans, some
**missing baseline spans** carrying `NATIONAL_ID`/`TAX_ID` candidates — no
exception, the PII is just returned unredacted. `README.md:659` claims
thread-safety that doesn't hold for detect-vs-`add_custom_pattern`.

---

## Medium severity

- **Custom-pattern ReDoS guard is trivially bypassable (Python).** `engine.py:21`
  only matches the literal shape `+)+`/`*)*`. `(a|a)+$`, `(a{1,10})+$`,
  `^(\w+\s?)*$` all pass, then run exponentially — yet the docstring promises
  "catastrophic backtracking (ReDoS)" protection. Medium now; **high** if
  `add_custom_pattern` is ever reachable from untrusted config.

- **Process-global singleton retains raw PII, unbounded and cross-tenant (Python).**
  `sdk.py` + `__init__.py:55`: the module singleton's `ReferentialMapper._mapping`
  is an unbounded `{raw PII → label}` dict, and the result cache stores
  `detections[].text` in cleartext (1024 entries). With `referential_integrity=True`,
  labels carry across *unrelated documents* — a shared label discloses that two
  tenants' inputs contain the same value. `clear()` exists but nothing calls it.
  A heap snapshot exposes everything ever redacted.

- **FNV-1a cache-key collision can serve another tenant's PII (TypeScript).**
  `cache.ts:23` keys the shared singleton cache on length + dual 32-bit FNV-1a —
  non-cryptographic and constructible. In a multi-tenant server an attacker who
  can predict a victim's input crafts a same-length collision and receives (or
  poisons) the victim's cached `RedactResult`, which contains raw PII. Python's
  cache correctly uses SHA-256; the fix is `crypto.createHash("sha256")` (Node
  builtin, no new dep).

- **Publish jobs have no environment protection (CI).**
  `.github/workflows/publish.yml:53-98`: neither job declares `environment:`, so
  anyone with repo write (or a hijacked maintainer session) publishing a Release —
  or running `workflow_dispatch` on any branch — ships to PyPI and npm with no
  second reviewer.

- **Unpinned tool install inside the publish job (CI).** `publish.yml:89`:
  `npm install -g npm@^11` runs floating inside the job holding the npm OIDC
  identity; a compromised npm CLI in that range could tamper with the tarball or
  the token. The one unpinned executable in an otherwise fully SHA-pinned pipeline.

---

## Low severity

- **VIN checksum disabled behind `if False`** — `validators.py:236`. `validate_vin`
  degrades to a length/charset check but still claims `validator="vin"`, earning
  priority tier 3 in dedup, so false VINs outrank genuine candidates.

- **Hardcoded maintainer home path in 6 committed files** — `/Users/jorenjanssens/...`
  in `scripts/presidio_benchmark.py`, `tests/metrics.py`, `benchmark.py`,
  `eval_full.py`, `sweep.py`, `test_structdata.py`. Personal-info disclosure in a
  public repo; violates the repo's own "no PII in code" rule. Use `EUREDACT_CORPUS`
  with a relative default.

- **`_silence_stderr` redirects process-wide fd 2** — `matchers.py:69`.
  `os.dup2(devnull, 2)` discards *any* thread's stderr (incl. security logs) during
  automaton construction. Small window, `try/finally`-wrapped.

- **Dead nested workflow** — `euredact-python/.github/workflows/ci.yml` never runs
  on GitHub and has drifted from root CI (different checkout SHA,
  `mypy continue-on-error`). Editing it gives false confidence. Delete it.

- **`publish-ts` publishes a rebuild, not the tested artifact** — `publish.yml:81-98`
  re-checks-out and rebuilds without running tests; under `workflow_dispatch` the
  tested and published commits can differ. Python side does this correctly.

- **Eval script writes full `source_text` PII to repo root** — `tests/eval_full.py:592`.
  Currently synthetic and gitignored (verified untracked), but pointed at a real
  corpus it writes real PII to a 0644 file.

- **Live-registrable example emails** — `jan.vandenberg@gmail.com`, `info@jansen.nl`
  in docs/examples/rules; prefer RFC-2606 domains.

- **MongoDB example credential** — `suppressors.py:435` and `conformance/vectors.json`
  contain `mongodb://admin:DFKDKi1eb51OO...@rds-main...`. Evidence says synthetic
  (impossible RDS-hosts-MongoDB shape), but the random-looking password is worth
  confirming came from the generator, not a copy-paste.

- **Minor:** floating dev-tool versions in `pyproject.toml`; TS `exports` map points
  CJS `types` at ESM declarations; `ReferentialMapper` collapses identical text
  across entity types (cosmetic); `Claude-Session:` URLs in public commit trailers;
  stale lockfile top-level version; root `LICENSE` is mode 600.

---

## Verified clean

No `eval`/`exec`/`pickle`/`yaml.load`/`os.system`/`subprocess shell=True`; no
filesystem writes or user-controlled paths in shipped code; **zero network calls**
outside a `cloud/` module that is entirely stubbed (`NotConfiguredError`, no
crypto/HTTP exists yet); no raw input or detected PII in any log or exception
message; no prototype-pollution surface in TS; zero runtime dependencies in both
packages; tight npm tarball (`files` allowlist, no source maps, no install scripts);
OIDC trusted publishing with no long-lived tokens; SHA-pinned third-party Actions
with `permissions: {}`; lockfile-enforced installs; synthetic test fixtures
throughout; and no real secrets in any tracked file or commit.

---

## Suggested priority

1. **H1/H2 ReDoS** — the only issues reachable by non-adversarial input on the
   default code path, in the shipped library, in both packages. Bound the
   SECRET/EMAIL patterns (adopt the TS lookbehind anchoring; add a per-regex time
   or input-run cap). Fix first.
2. **H3 race** — hold `_lock` across the scan, or snapshot the matcher; a
   redaction tool silently missing PII is the worst-case failure.
3. **M-tier** — the bypassable ReDoS guard and the unbounded cross-tenant PII
   singleton matter most for anyone embedding this in a multi-tenant service; add
   `environment:` protection to the publish jobs.
