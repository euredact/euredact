# Changelog

## 0.4.0 (2026-08-31)

The cloud tier, which the package has advertised since 0.3.x and never had.
**It ships in private alpha:** closed testing, keys issued to alpha
participants only, not public beta and not generally available. The rules
engine is unaffected and `mode="rules"` remains the default.

`redact(mode="cloud")` sends the document to the euRedact inference service: the
same deterministic rules engine, followed by a fine-tuned model asked only *what
did the rules miss?* It returns the redacted document and located spans, so the
types marked `[CLOUD EXTENSION]` — person names, organisations, job titles,
diagnoses — are populated for the first time.

```python
pip install 'euredact[cloud]'

import euredact
euredact.configure(api_key="erk_...")          # or EUREDACT_API_KEY
result = euredact.redact(text, countries=["BE"], mode="cloud")
```

Detection accuracy of the local rules engine is unchanged. Nothing in
`mode="rules"` — the default — behaves differently, and `dependencies` is still
empty: the HTTP client lives behind the new `cloud` extra.

All 841 pre-existing tests pass untouched; the suite is now **868** with the 27
new cloud tests. Detection was proved unchanged rather than assumed: every one
of the 152,300 corpus documents was run through the published 0.3.9 and through
this build, under both `detect_dates` settings — 304,600 runs, 1,387,430
detections — and the `(type, start, end, text, source)` tuples plus
`redacted_text` hash identically under SHA-256
(`546e681a4eb0ad7abf69bc5623af51c7c5b1de0d4cb2603492ccfa04c4a20763`).

Cross-SDK masking parity was re-measured rather than carried forward: **0.30%**
divergence over 2,000 documents (11,272 identically masked spans, type
divergence 0.00%), and **0.41%** over the entire 204,327-document corpus
(1,167,027 identically masked spans). The 0.61% quoted in the 0.3.8 notes and
repeated in 0.3.9 does not reproduce on the current corpus and is superseded by
these figures.

The property sweep was run over every document rather than the sampled default:
all 204,327 hold every structural property (offsets, non-overlap, determinism,
cache transparency, and `countries` never changing which spans are found).

### Fixed

- **`redact(mode="cloud")` silently returned rules-only output.** No error, no
  warning, `source="rules"`, and a plausible-looking redacted document with
  every person name still in it. The guard that should have caught this —
  `NotConfiguredError`, whose message already read *"Call
  euredact.configure(api_key=...) first"* — was unreachable, because nothing
  ever constructed `CloudClient` and `euredact.configure()` did not exist.

  This is the worst failure shape this library can have: the caller believes
  names, employers and diagnoses were checked, sees a redacted document, and
  ships it. It now raises `NotConfiguredError`, and an unknown `mode` raises
  `ValueError` instead of being treated as `"rules"`.

### Added

- `euredact.configure(api_key=..., base_url=..., ...)`, reading
  `EUREDACT_API_KEY` and `EUREDACT_BASE_URL` so a key never has to be written
  into source.
- `euredact.cloud.CloudClient` and `AsyncCloudClient`. Both retry with full
  jitter, obey `Retry-After` rather than second-guessing it, and send an
  `Idempotency-Key` per document so a retry after a timeout cannot create a
  second job or bill twice. A document that outlives the service's sync window
  returns a job handle, which the client polls transparently — callers never
  write that branch.
- `TooLargeError` (413, permanent — the service refuses oversized input rather
  than chunking, because the model has never seen a chunk boundary),
  `QuotaExceededError` (429), and `CloudError` for everything else.
- Nine cloud-only entity types, matching the detection canon the service is
  trained and evaluated against: `ORGANISATION_NAME`, `JOB_TITLE`,
  `MEDICAL_CONDITION`, `SENSITIVE_ATTRIBUTE`, `BIOMETRIC_REF`,
  `FINANCIAL_AMOUNT`, `QUASI_IDENTIFIER`, `CREDENTIAL`, `URL`. The rule engine
  never emits these — there is no shape to match on, which is precisely why the
  model exists.

### Changed

- **`EntityType.NAME` is now a legacy alias of `EntityType.PERSON_NAME`**, the
  name the detection canon uses, following the existing `IBAN` →
  `BANK_ACCOUNT` precedent. `EntityType.NAME` keeps working and
  `EntityType("NAME")` still resolves; `EntityType.NAME.value` is now
  `"PERSON_NAME"`. Nothing could have depended on the old value: the type was
  cloud-only and the cloud tier was stubbed, so it was never emitted.

  Two names for one type is how a whole category goes missing when someone
  filters on the spelling they happened to know. `STREET_ADDRESS` →
  `ADDRESS` and `NATIONALITY_ETHNICITY` → `SENSITIVE_ATTRIBUTE` are recognised
  as aliases for the same reason.
- Options the service cannot honour now raise in cloud mode rather than being
  ignored: multiple `countries`, `country_hint`, `context`/`chunk_offset`,
  `referential_integrity` and `coref`. Silently dropping one returns a result
  that is not what was asked for. `detect_dates` is the deliberate exception —
  the service always runs with dates on, because that is what the model was
  trained against, and the difference can only cause *more* to be detected.

### Removed

- `euredact.cloud.hasher` and `euredact.cloud.shuffler`. Both were empty stubs
  describing segment hashing and cross-client shuffling — a privacy
  architecture the service does not implement. Leaving them in place implied a
  guarantee that was never made.

### Known issues

- **One cross-SDK type disagreement, visible only at full-corpus scale.** Over
  all 204,327 documents the two engines masked 1,167,027 spans identically and
  disagreed on the type of exactly one: a Hungarian address-like email,
  `vezetéknév.keresztnév@vallalat.hu`, which Python files as `EMAIL` and Node as
  `SECRET`. Both mask precisely the same characters, so no PII is exposed by it.

  It is **not new in 0.4.0** — a build from the 0.3.9 tree reproduces the same
  `SECRET`, and this release changes no detection code in either SDK. The
  default `make parity` sample of 2,000 documents does not contain the document,
  which is why the gate is green at its configured limit and only the full
  corpus surfaces it. Left unfixed deliberately: 0.4.0 adds a network tier and
  must not move a rules detection. Tracked for a following release.

### Note for operators of the inference stack

**Shipping 0.4.0 is not a reason to upgrade the euRedact inference gateway.**

The gateway pins `euredact[fast]==0.3.9` exactly, because the rules-engine
version is part of the served model's training contract: the gateway refuses to
serve when a model bundle's `euredact_version` does not match the installed
package. Upgrading it to 0.4.0 without a matching rebuilt model bundle takes it
out of service.

Nothing in 0.4.0 gives the gateway a reason to move. The cloud client is what
*calls* the service; the gateway is the server, and does not use it. Detection
behaviour is byte-identical to 0.3.9 (verified over the full 152,300-document
corpus, both `detect_dates` settings), so there is no accuracy argument either.

## 0.3.9 (2026-08-11)

The labels the corpus actually contains, and the gate that should have caught
the rest of this. Reported by the training pipeline against 0.3.8: over 4,273
adjudicated documents, 530 of the spans the rules engine claimed were filed
under the wrong type, and — separately — the two SDKs disagreed on type for
three of twenty-two hand-written cases while `make parity` reported
byte-identical masking and stayed green.

Accuracy over the 152,300-document corpus is unchanged: 99.8% recall / 99.8%
precision with country hints, 99.8% / 99.6% blind. False positives are unmoved
with hints (1,232) and up 11 blind (2,361 → 2,372). Cross-SDK masking parity is
unchanged at 0.61% over 2,000 documents; cross-SDK **type** divergence is 0.

### Fixed

- **The cue table held the abbreviation and not the word.** `BSN:` was cued and
  `Burgerservicenummer:` — the same identifier, spelled out, in the same
  language — was not. `Companies House Registration:`, `Company Registration
  Number:`, `Medical Card No.:`, `AGB-code:`, `sort code`, `account number` and
  `PLZ-Bereiche:` are all the official name of an identifier in the document's
  own language, and all were typed `PHONE`. `sort code 20-45-91` was typed
  `LICENSE_PLATE`: a UK sort code is `NN-NN-NN`, which collides with a plate,
  and the label sat right in front of it.

  Measured on 4,000 corpus documents: 18 spans re-filed to the correct type, 8
  newly detected, 5 suppressed — and no change in recall or precision.

- **`Sozialversicherungsnummer:` was in the table the whole time and could not
  be reached.** At 27 characters the label did not fit `CUE_WINDOW = 22`, so
  the window held `"lversicherungsnummer: "` and the label's own start was
  outside it, where the `(?<![A-Za-z0-9_])` boundary anchors. That reads
  exactly like a missing label and is not one — the window is now 32, which
  covers `"Companies House Registration: "`, the longest label the corpus
  contains. The window bounds how long a *label* may be, never how far it may
  sit from the value: every pattern is anchored to the end of the window, so
  the tail still has to reach the span.

- **The two SDKs filed the same value under different types.** Two unrelated
  causes, neither of them the cue table:

  *Ranking.* For a bare digit run that several national schemes accept, all
  seven sort fields tie — same span, no cue, same priority, no country
  evidence, both out of scope — and the stable sort then fell through to
  country *registration* order. Python registers alphabetically
  (`AT, BE, BG, CH, CY, CZ, ...`) and TypeScript in a curated order
  (`NL, BE, DE, AT, CH, FR, ..., PT, LU, PL, ..., CZ`), so
  `Burgerservicenummer (BSN): 274839165` was a Czech `NATIONAL_ID` in Python
  and a Portuguese `PHONE` in Node. There is now a shared tie-break, and it
  reproduces the order Python already had rather than inventing one: every
  accuracy figure this engine has published was measured with Python resolving
  these ties that way.

  *`\w`.* Slovak `telefón 0956550012` needs the cue's run-on to absorb "efón"
  after `tel`, and Bulgarian `пощенски кодове 4000-4999` needs "ове" after
  `пощенски код`. `\w` is Unicode-aware in Python and ASCII-only in JavaScript,
  so Python matched and Node did not. 0.3.8 fixed exactly this for `\b` and for
  the qualifier class, and left `\w*` in the run-on.

- **A four-digit run became a `POSTAL_CODE` as soon as any real postal code
  established the country**, which is to say in almost every real document:
  `Opgericht in 2016`, `Fondée en 2017` and telephone extensions
  `(toest. 3841)`, `(ext. 3214)`, `poste interne 3318`. The mirror image of a
  cue — a word that rules a type *out* rather than in.

  Ambiguous prepositions need a founding or payment participle in front of
  them, and unambiguous ones (`sinds`, `since`, `depuis`) do not. That
  distinction is load-bearing: Belgian postal codes are year-shaped, Antwerp's
  is 2018, and disqualifying on a bare `in` suppressed the real postal code in
  `rustige ligging in 2018, vlakbij openbaar vervoer`. A miss is the worse
  error for a redaction tool, so the ambiguous case now needs the verb.

- **A label ending in more than one mark now reaches its value.**
  `Steuer-IdNr.:`, `Passport No.:` and `Numéro de sécurité sociale (NIR) :`
  need an abbreviating full stop *and* a colon, or a closing parenthesis first.
  German tax IDs, a French NIR and Belgian VAT numbers that 0.3.8 left entirely
  unmasked are now detected.

### Added

- **`make parity` compares types, not just characters.** It reports type
  disagreement over the spans both engines masked identically, separately from
  character divergence, and fails above `--max-type-divergence` — now 0.0,
  because 0.3.9 closed the last case and 10,344 identically-masked spans agree
  on all 10,344.

  This is the gate that should have caught the divergence above. Character
  parity cannot see it by construction: all three reported cases masked exactly
  the same characters. The 0.3.8 release notes quoted this script's 0.61% as
  evidence the SDKs agreed, and it was never evidence of that.

- **Cue targets for `HEALTHCARE_PROVIDER`, `BANK_ACCOUNT`, `PASSPORT` and
  `SECRET`.** `HEALTHCARE_PROVIDER` identifies the clinician or practice (the
  Dutch AGB-code, the German LANR, the UK GMC number) as distinct from
  `HEALTH_INSURANCE`, which identifies the insured person.

  The training pipeline's report asks for a `CREDENTIAL` type for
  `TAN-activatiecode`; this SDK has no such type, so those are `SECRET`.
  Adding a public `EntityType` is a caller-facing decision and is not made here.

### Changed

- **Re-typing and rescuing are no longer the same set.** `_CUE_TARGETS` decides
  what a label may relabel a span *to*; `_RESCUE_TARGETS` decides what it may
  re-admit after a checksum *failed*. `BANK_ACCOUNT` joins the first so
  `sort code 20-45-91` stops being a `LICENSE_PLATE`, and stays out of the
  second for exactly the reason 0.3.8 gave: mod-97 failing really does mean
  "not an account number".

- **`NATIONAL_ID` is retypable, but only at country score 0.0.** A checksum
  says the digits fit *some* national scheme, and a weak one fits by luck; when
  the document supports that country not at all, an explicit `Passport No.:` is
  the better evidence. Gated this way it cannot touch a domestic identifier — a
  Dutch BSN in a Dutch document scores above zero and keeps its type whatever
  label sits near it.

- 20 new shared conformance vectors (127 → 147), including guards for the
  Antwerp postal code, for `Privat:` staying an e-mail, and for a real postal
  code surviving in the same sentence as a disqualified year.

## 0.3.8 (2026-08-11)

A label in front of a value now decides what that value is called. Reported by
the training pipeline: over 400 adjudicated documents, 110 of the 490 spans the
rules engine handed over (22%) were filed under the wrong type, 71 of them as
`PHONE`. Recall and precision over the 152,300-document corpus are unchanged
(99.8% / 99.8% with hints, 99.8% / 99.6% blind); false positives fall by 320 in
blind detection and are unmoved with hints; cross-SDK parity is byte-identical
to before at 0.61% over 2,000 documents.

### Fixed

- **An explicit identifier label no longer loses to the phone pattern.**
  `Αρ. Ταυτότητας: 00892341` (Cypriot ID), `ΑΦΜ: 147382965` (Greek tax number),
  `IČO: 08234567` (Czech company register), `Cod postal: 040171` and
  `medarbejdernummer: 2023-1156` were all typed `PHONE`, in seven countries.
  This is the general form of the defect 0.3.3 fixed for one Belgian case; the
  conformance suite had encoded that example rather than the rule, which is why
  it went unnoticed for four releases.

  The cue table that already resolved `Phone: 0705237535` against the Swedish
  personnummer checksum now lives in `rules/cues.py`, covers the languages the
  report named, and does two things it could not do before: relabel a winning
  generic candidate whose type a label contradicts, and re-admit a candidate
  whose checksum failed when the label names that same type.

  Relabelling, never suppression. Which characters are masked does not change —
  a cue decides the label and can never move a span, so invariant I1 holds.

- **A labelled identifier that fails its checksum is masked instead of
  dropped.** `redact("Rijksregisternummer: 85.03.19-284.73", countries=["BE"])`
  returned the text *unchanged*: the national-number rule declined on the check
  digit, the generic phone rule was denied the span as a fragment, and a
  redaction library printed in full an identifier it had recognised and
  rejected. The conformance case covering it asserted only that the value was
  not a `PHONE`, so it passed throughout. Such a span is now emitted as its own
  type with `confidence="low"`.

  Restricted to checksummed identifiers. `BIC` is excluded because its validator
  is a registry lookup rather than a checksum — a failure there means "no such
  bank", which no label can talk you out of — and `CREDIT_CARD` and
  `BANK_ACCOUNT` because Luhn and mod-97 are strong enough that a failure really
  does mean "not one of these".

- **`ΑΦΜ` reaches `TAX_ID`.** Greece's ΑΦΜ is issued by the tax authority; the
  identity-document number is the ΑΔΤ. A value cued `ΑΦΜ:` was returned as
  `NATIONAL_ID`, attributed to whichever foreign scheme happened to validate.

### Added

- **`EntityType.INTERNAL_ID`** — an employee, badge or customer number tied to a
  person. Emitted **only** behind an explicit label (`medarbejdernummer:`,
  `Personalnummer:`, `Employee No:`); there is no pattern for one, because
  without the label a digit run is not distinguishable from any other. The type
  exists so that a labelled employee number is filed correctly instead of being
  claimed by the phone pattern.

- **`Detection.confidence` is now meaningful.** `"high"` — a pattern matched and
  its checksum passed. `"medium"` — the type comes from a label, because no
  pattern of that type claimed the span. `"low"` — a pattern matched, its
  checksum failed, and the document labels the span as that very type. Every
  detection is masked regardless; filter on `"high"` for checksum-backed types
  only.

### Changed

- `suppress_phone_after_id_label` and its `_ID_LABEL_BEFORE` table are gone.
  Their labels are typed entries in `rules/cues.py` and now relabel rather than
  delete. Dropping was the wrong verb: the span is found either way, so removing
  the claim decided only whether the value was masked.

- The `VAT` cue gained the word boundary it never had, so `Privat:` no longer
  reads as a VAT label via `iva`. Boundaries across the table are written
  `(?<![A-Za-z0-9_])` rather than `\b`, because JavaScript's `\b` is ASCII-only
  and `\bΑΦΜ` cannot match there — with `\b` the two SDKs would disagree on
  every non-Latin label.

## 0.3.7 (2026-07-31)

Findings from a security and performance review of the package. Detection
output is unchanged: the shared benchmark corpus produces byte-identical
redacted text before and after, and cross-SDK parity is unmoved at 0.52%
divergence over 1,500 documents.

### Security

- **Two patterns could be made to backtrack quadratically (ReDoS).** The
  high-entropy `SECRET` rule ended in `\b`, which cannot match when a token run
  ends on `-`, `+` or `/` — so an ordinary dashed rule line (`x-----…`) sent the
  engine backtracking across two overlapping quantified classes. 80 KB of that
  took **39.8 s**; it now takes 28 ms and scales linearly. The `EMAIL` rule had
  the same shape at its start: because `.` is in the local-part class, a long
  dotted token (a dependency manifest, a stack trace) plus any `@` in the
  document cost O(n²). Both are now pinned with class lookarounds instead of
  `\b`. Neither needed an attacker — ordinary machine-generated text triggers
  them. The `EMAIL` fix adopts the anchoring the TypeScript SDK already used.
  One visible consequence: base64 padding (`==`) is now inside the redacted
  span rather than trailing outside it, and an email preceded by a dot has that
  dot included.

- **A pattern registered during detection could silently drop PII.**
  `add_custom_pattern` rebuilt the matcher's scan structures in place while
  scans — which deliberately run without the lock, so concurrent `detect()`
  calls do not serialise — were reading them. A scan racing the rebuild could
  zip a fresh slot list against a stale pattern list, truncate to the shorter
  of the two, and skip patterns, returning fewer detections with no error
  raised. `compile()` now builds a whole new plan and publishes it in one
  assignment, so a scan sees the pattern set as of before or after the
  registration, never a mixture. Covered by `tests/test_thread_safety.py`,
  which fails against the previous implementation.

- **The custom-pattern ReDoS screen only recognised one spelling.** It searched
  for the literal shape `+)+`, so `(a|a)+$`, `(a{1,10})+$` and `^(\w+\s?)*$`
  all passed and then ran exponentially — while the error message promised the
  pattern had been checked for catastrophic backtracking. It now rejects
  quantifiers inside repeated groups and repeated groups whose alternatives
  overlap, and the docstring says plainly that it is a conservative heuristic
  over known-bad shapes, not a proof of safety.

- **The VIN check digit is now an explicit decision rather than dead code.**
  `validate_vin` carried a full ISO 3779 check-digit implementation behind
  `if False`, which read as an oversight. It is not, and enabling it was
  measured to be wrong: over the 152,300-document corpus it turned **1,502
  labelled VINs into misses**. A VIN that fails its checksum is still a VIN
  sitting in the text, and real documents carry OCR slips and transcription
  errors — dropping it leaves it unredacted, which is a leak, while keeping it
  costs at worst an over-masked 17-character token. That is the same trade the
  deduplication ranking already makes when it puts span length above
  validation. The dead branch is gone and the reasoning, including the caveat
  that VIN therefore claims validator priority on shape alone, is in the
  docstring. The TypeScript SDK carries the matching note.

- **The result cache was bounded by entry count, not by size.** 1024 entries
  said nothing about memory: 1024 cached 1 MB documents is a gigabyte of
  PII-bearing text held live. The cache now also enforces a character budget
  (`DEFAULT_MAX_CHARS`, ~16M) and skips results too large to fit.

- **The referential-integrity mapping is documented as unevicted and shared.**
  It is keyed on the raw PII value and cannot be evicted without breaking the
  guarantee it exists to provide, so it grows until `clear()` is called — now
  warned about once past 100,000 entries. Its labels are also shared by every
  caller of the module-level `redact()`, which means a repeated label discloses
  that two documents contain the same value; the README now says to give each
  tenant its own `EuRedact` instance.

- The maintainer's home directory is no longer hardcoded in six committed
  files; the corpus path comes from `EUREDACT_CORPUS` with a repo-relative
  default. The false-positive export writes a 120-character context window
  instead of every source document. Example addresses use RFC 2606 domains.

### Performance

Measured on a 12-core M3 Pro with the `[fast]` extra, cache disabled:

| document | before | after |
|---|---:|---:|
| 5 KB | 4.2 ms | 4.1 ms |
| 50 KB | 146.9 ms | 128.4 ms |
| 1 MB | 3,597 ms | 2,354 ms |

- **The BIC context window walked the whole document per candidate.**
  `_structural_unit` expanded to the enclosing paragraph and only *then*
  applied its 600-character cap, so on text with no blank lines — a CSV, a log,
  a bank-details export — each BIC-shaped token cost O(document). A 256 KB file
  took 32 s, which extrapolates to roughly 14 hours at the 10 MB input limit.
  Both walks now stop once the paragraph is too wide to be used, which is the
  point past which the result was discarded anyway. Measured on a BIC-dense
  136 KB document: 1,051 ms to 422 ms, byte-identical output.

- **The fragment check was O(candidates × failed spans).** For every
  validator-less candidate it walked — and list-sliced — the whole prefix of
  failed spans: 125.6 million inner iterations on a 1 MB document, 43% of
  runtime, and the sole cause of superlinear scaling. A running maximum of the
  span ends answers the same question in O(1) for all but an exact-end tie.

- **Redaction rebuilt the whole document per detection.** `redacted[:start] +
  label + redacted[end:]` in a loop is O(document × detections) — 268 ms of
  pure copying on a 1 MB document with 8,000 detections, against 0.7 ms for a
  single forward pass joined once. Labels are still resolved right-to-left, so
  referential numbering is unchanged.

- The cache key no longer copies the entire input into an f-string before
  hashing it, and a dead loop in the normalizer that ran a per-character NFC
  pass and discarded the result is gone (with its `F841` ruff exemption).

- **Regression check.** The full 152,300-document corpus scores identically to
  0.3.6 on every entity type in both detection modes — same support, TP, FP and
  FN — so none of the above changed what is detected. Two regressions were
  caught this way and fixed before landing: enforcing the VIN check digit (see
  above), and anchoring the high-entropy rule with a lookbehind, which widened
  its span over a leading `//` and let the endpoint suppressor drop an SSH key.
  The latter is now pinned by conformance vector
  `secret-ssh-key-preceded-by-slashes`, which runs in both SDKs.

### CI

- Both publish jobs now run in a `release` environment, so shipping to PyPI and
  npm waits on that environment's reviewers rather than being available to
  anyone with repo write. **This requires matching configuration on all three
  sides — the GitHub environment and both trusted-publisher entries — and a
  publish fails closed until they agree.** See the release skill.
- The npm upgrade inside the publish job is pinned to an exact version instead
  of floating on `^11`; that job holds the npm OIDC identity.
- `publish-ts` runs the test suite before publishing, since it re-checks-out
  rather than consuming the tested artifact and can resolve a different commit
  under `workflow_dispatch`.
- Removed `euredact-python/.github/workflows/ci.yml`: nested workflow
  directories are never executed by GitHub, so it was dead config that had
  drifted from the real pipeline while looking like coverage.

## 0.3.6 (2026-07-30)

### Fixed

False positives only. Every change here corrects a case that was wrong on its
own terms — a broken regex, a missing entry in a list that was meant to be
complete, a suppressor wired to every numeric type but one — rather than tuning
a threshold against a corpus. Measured on the same 152,300 documents and
667,129 labels as 0.3.5: **false positives fell from 3,294 to 1,232** with
hints, and from 4,782 to 2,720 blind. Recall did not fall; it rose slightly.

| | precision | recall | F1 |
|---|---:|---:|---:|
| 0.3.5, with country hints | 99.51% | 99.71% | 99.61% |
| **0.3.6** | **99.82%** | **99.72%** | **99.77%** |
| 0.3.5, blind | 99.28% | 99.49% | 99.39% |
| **0.3.6** | **99.59%** | **99.50%** | **99.55%** |

No dataset regressed on either metric, and the eight that moved are
independently generated country groups.

- **A currency amount ending a clause was a postal code.** The currency test
  ended every alternative with `\b`, but `€`, `£` and `$` are not word
  characters, so `€\b` required a *letter* after the symbol and could never
  match the ordinary `20744 €.` or `1163 €,`. Symbols are now matched
  separately from the alphabetic codes, and the amount-label list gained the
  Spanish, Italian, Polish, Czech and Hungarian words for "amount". The
  TypeScript SDK used a Unicode lookahead here and never had this defect.

- **Ticket and incident numbers were postal codes.** `suppress_reference` was
  wired to every numeric entity type except `POSTAL_CODE`, so `Ticket #94730`
  and `Incident report IR-43433` were masked as addresses. A five-digit ticket
  number is exactly the shape of a German or French postcode. Support-desk
  vocabulary was added in nine languages, and `#` and `IR-`-style tags are now
  recognised adjacently — deliberately *not* through the 150-character keyword
  window, which is what made the postal rule claim years in dates.

- **`desember` was missing from the month list.** Ten other spellings of
  December were present, so `1. desember 2025` was a Norwegian postcode. The
  Icelandic month names were absent for the same reason and were added with it.

- **Crypto tickers were licence plates.** `4499 BTC` matched Spain's
  four-digits-then-three-consonants plate shape. The fiat ISO 4217 codes were
  already excluded; a ticker is a unit in the same way.

- **API endpoints, hostnames and LDAP names were secrets.** The high-entropy
  rules anchor on `:` and `=`, so a published endpoint such as
  `https://api.sendgrid.com/v3/mail/send` scored as a credential, as did
  `api.example.eu`, `cn=github-actions,dc=corp,dc=eu` and service names like
  `analytics-engine`. A URL that *carries* a credential — a
  `mongodb://user:password@host` connection string, or a URL with an
  `?api_key=` parameter — is still a secret, and is now covered by a
  conformance vector so the distinction cannot be lost.

- **`SECRET` no longer claims an email address**, on the same reasoning that
  already stopped it claiming UUIDs and BICs: the `EMAIL` rule owns that span.

Thirteen conformance vectors were added (93 → 106), run by both SDKs, covering
each fix above and the guard cases that must keep firing.

## 0.3.5 (2026-07-30)

### Fixed

Eleven detection defects, found by measuring precision, recall and F1 per entity
type rather than by report. Across all 152,300 corpus documents and 667,129
labelled entities, false positives fell from 8,905 to 3,294 and misses from
5,162 to 1,915.

| | precision | recall | F1 |
|---|---:|---:|---:|
| 0.3.4, with country hints | 98.67% | 99.23% | 98.95% |
| **0.3.5** | **99.51%** | **99.71%** | **99.61%** |
| 0.3.4, blind | 98.36% | 98.91% | 98.63% |
| **0.3.5** | **99.28%** | **99.49%** | **99.39%** |

- **Every Latvian phone number was suppressed.** `NIS`, the Belgian
  national-number label, was listed without a word boundary and matched
  case-insensitively — so it matched the *tail* of `tālrunis`, the Latvian for
  "telephone". The word for "phone" was being read as "this is not a phone".
  653 misses. The same flaw in the reference-label list (`ref` matching the tail
  of `kortref`) is fixed with it.

- **Spanish numbers grouped 3-2-2-2 matched no pattern at all.** `705 97 55 11`
  is as common as the 3-3-3 and 2-3-2-2 groupings that were present. 674 misses,
  the single largest phone gap.

- **A generic secret claimed spans belonging to specific types.** The
  high-entropy rules are broad *and* carry a validator, so they reached the top
  priority tier while the structured detector for the same characters sat at the
  bottom with nothing to offer. 687 UUIDs and 140 BICs were reported as
  `SECRET` — each counted twice over, as a false positive for `SECRET` and a
  miss for the type that should have had it. `UUID` and `SWIFT_BIC` recall both
  reach 100%.

- **A four-digit year inside a date was masked as a postal code.** The existing
  year guard deferred to any address cue within 150 characters, and `Adresse`,
  `rue` and `Str.` head essentially every business letter. Adjacent date
  evidence now settles it. 1,691 of 3,322 postal false positives were plausible
  years, 1,636 of them literally `2025`. *(Reported separately; the guard cases
  from that report ship as conformance vectors.)*

- **Money amounts read as Spanish licence plates.** The plate shape is four
  digits then three consonants, and the Nordic and Central European currency
  codes are all consonants: `2297 DKK`. The separator also matched a line break,
  so a year ending one line and a label starting the next (`2002\nCPR`) read as
  one registration. 667 false positives.

- **Timestamps, ordinary words and cloud regions were reported as secrets.**
  `57:22.283Z]`, `Sozialversicherungsnummer` and `us-east-1` all sit after a
  colon and clear the entropy threshold. 437 false positives.

- **A dotted quad was reported as a German tax number.** That shape allows dots
  between digit groups, making it a superset of IPv4.

- **Year ranges and decimal tails were reported as phone numbers.**
  `Schooljaar 2025-2026`, and `034865` out of `0.034865 BTC`. The Dutch
  two-word invoice form `Factuur nr.` was also missing where `factuurnummer`
  was present.

- **Belgian enterprise numbers were missed when introduced by the registry's own
  name** — `Kruispuntbank van Ondernemingen onder nummer`. Same shape of gap as
  0.3.4's German `SVNR`.

- **A label touching a value now outranks a checksum.** Country evidence
  resolved which *national scheme* owned an ambiguous value but never looked at
  the word in front of it, so `Phone: 0705237535` was reported as a Swedish
  national ID. The cue ranks candidates only *within* a span, so it decides the
  label and can never change which characters are masked — the property that
  keeps the generation invariant intact. `CHAMBER_OF_COMMERCE` misses fell from
  205 to 1.

- **A value filling an entire field of a delimited row now counts as context.**
  Export formats carry meaning in the column, not in a nearby word. Restricted
  to narrow shapes: applied to every type it was a net loss, because a broad
  pattern paired with a required cue is a deliberate pairing.

### Added

- 25 shared conformance vectors covering all of the above (68 → 93), run by both
  runtimes.
- `tests/metrics.py` gains `--engine python|typescript|both` and `--per-file`.
  The TypeScript SDK is measured by dumping its detections and scoring them with
  the *same* scorer, so a difference between the two reports says something
  about the engines rather than about the measurement.

## 0.3.4 (2026-07-30)

### Fixed

- **Recovered the latency 0.3.3 gave away, without giving back its recall.**
  0.3.3 made `\b` catch identifiers glued to a non-ASCII letter by rewriting it
  to a three-branch lookaround union on all 303 patterns. Correct, but it cost
  **1.8× on short records and 2.8× on real documents**, and its ASCII branch
  manufactured boundaries *inside* words at non-ASCII letters — truncating
  `@Ciarán` to `@Ciar` and typing `FICIAIRES`, a fragment of `BÉNÉFICIAIRES`,
  as a national ID.

  The boundary is now chosen per occurrence. Next to a digit, the ASCII reading
  alone is *exactly* the union — a Unicode letter is never an ASCII word
  character, so the ASCII branch already succeeds everywhere the Unicode branch
  does — and one lookaround replaces the alternation. Everywhere else plain `\b`
  stays, which is what a Greek e-mail local part needs.

  | | 186 chars | 3,424 chars |
  |---|---:|---:|
  | pure Python | 3.0 ms → **907 µs** | 58 ms → **13.6 ms** |
  | with `pyahocorasick` | 2.3 ms → **775 µs** | 42 ms → **10.9 ms** |
  | with `[fast]` | 878 µs → **516 µs** | 14.4 ms → **5.3 ms** |

  Within 4% of the pre-0.3.3 baseline, with all five glued-identifier cases and
  both Unicode e-mail cases still detected. Per-type precision, recall and F1
  are **byte-identical** across all 152,300 corpus documents.

- **Social handles containing a non-ASCII letter were masked only up to it.**
  `@Ciarán` came back as `@Ciar`, leaving `án` in the clear, because the pattern's
  character class was ASCII-only and the old boundary let the match stop mid-word.
  The class is now Unicode-aware, so the whole handle is masked. The TypeScript
  SDK already had this right; the two now agree.

- **German social-security numbers were unredacted whenever the document used
  the abbreviation `SVNR`.** The pattern and its context gate were both correct;
  the cue list simply had `SV-Nummer` and `Sozialversicherung` and not the short
  form people actually type.

  Measured across all 152,300 corpus documents, this was **every** German
  social-security number the rule missed — 204 of them, in the clear:

  | | recall before | after |
  |---|---:|---:|
  | `SOCIAL_SECURITY`, country hints | 84.16% | **100.00%** |
  | `SOCIAL_SECURITY`, blind | 83.77% | **99.61%** |

  No false-positive cost: 0 before, 0 after, and no other entity type moved.
  `SV-Nr` and `RVNR` are added alongside it — the same gap for the other two
  spellings, and the health-insurance rule already carries `KVNR` next to
  `KV-Nummer` for exactly this reason.

  Found by per-type measurement rather than a report. `SOCIAL_SECURITY` was the
  only type below 90% recall that was not a known cloud-tier case, which is
  what made it worth chasing.

### Added

- **`tests/metrics.py`** — per-entity-type precision, recall, F1 and
  false-positive counts over the corpus, both detection modes, with `--csv`.
  `eval_full.py` renders an HTML report; this is the plain-text counterpart with
  its matching rules stated in the module docstring, so a figure quoted from it
  can be reproduced and argued with.

  Writing it surfaced two flaws in the shared evaluation config, both of which
  had been quietly distorting published numbers:

  - `HEALTH_ID` had no entry in `CATEGORY_MAP`, so its 252 labels could never be
    matched — counted as 252 misses *and* charging the engine's correct
    `HEALTH_INSURANCE` detections as 252 false positives. `SECRET` was also
    unmapped and worked only by accident, its fallback happening to be a real
    entity type. Both are mapped now, which slightly raises measured recall.
  - False positives were attributed to a category that may carry no labels at
    all: every `BIC` detection was charged to a zero-support `BIC` row while the
    corpus labels them `SWIFT_BIC`, splitting one type's precision across two
    rows and reporting it as 0.00%.

## 0.3.3 (2026-07-29)

### Fixed

- **A shorter validated match could re-cut a longer one and leak the
  remainder.** Under `countries` `["NL"]` the Dutch national-ID pattern
  validates on `194.232.104`, outranked the IP address `194.232.104.77`, and
  left `.77` in the output. The TypeScript SDK did the same with no country
  declared at all.

  Span length now outranks every other signal, including validation. Priority
  still decides between candidates of *equal* length, which is where it was
  always meant to apply — a valid IBAN beats a coincidental match on the same
  characters. Masking more than necessary is recoverable; masking less is not.

- **`countries` could change which spans were found, not just how they were
  labelled.** Promotion depends on whether the document corroborates a
  country, so the declared country decided which of two overlapping candidates
  won. Two cases were found, the second only after fixing the first.

  Ordering between different spans is now country-blind by construction —
  length, then the span's structural tier, then leftmost — and `(length, start)`
  identifies a span uniquely, so the country-aware signals can only choose the
  **label within a span**, never its extent. The invariant holds by design
  rather than by test.

- **A bare string for `countries` silently discarded every detection.**
  `countries="NL"` is iterable, so it was walked into the codes `"N"` and `"L"`.
  Neither resolves, so nothing was declared — and every detection carrying a
  country came back flagged out of scope, while the redacted text still looked
  correct. The README tells callers to filter on exactly that field, so a
  documented pipeline kept none of them. It failed toward "no PII here", from a
  one-character typo.

  Both SDKs now raise `TypeError` naming the argument and showing the fix, on
  every entry point. A wrong *code* still only warns: raising there would invite
  callers to wrap redaction in try/except and skip it. A wrong *type* is a
  programming error with no correct interpretation to fall back on.

- **The generic phone pattern claimed fragments of rejected identifiers.**
  `Rijksregisternummer: 85.03.19-284.73` was reported as a `PHONE`. The Belgian
  national-number pattern matched the whole value and failed its checksum; the
  separator-tolerant phone pattern then took characters 3-14 of it.

  A candidate covering only *part* of a rejected identifier is a fragment of
  that identifier, not a separate entity, and is now dropped. An equal span is
  left alone: that is two schemes competing for the whole value, and demoting
  those is what previously handed a Swedish phone number to a Danish CPR.

  Fragment detection ignores the declared country by design. It removes
  candidates, so making it country-aware would let `countries` change which
  spans are found — the invariant in `test_invariant_generation.py`.

  No measurable cost: recall, precision and type-correct rate are unchanged on
  all 152,300 corpus documents.

- **Identifiers glued to a non-ASCII letter were missed.** Python's `\b` is
  Unicode-aware, so it saw no boundary between a Cyrillic or accented letter
  and a digit: `ЕГН7523169263`, `PESELŁ44051401359`, `čísloř7401011233`,
  `Steuerß12345678911` and `kodasž38605181232` were all detected by the
  TypeScript SDK and silently missed by this one.

  `\b` is now compiled to the *union* of the Unicode and ASCII readings.
  Swapping to ASCII-only — the obvious fix — trades one silent miss for
  another: it drops Greek and Cyrillic e-mail local parts, which are
  deliberately supported. `re.ASCII` is unusable for the same reason, since it
  would also narrow `\w`.

  **This is expensive.** The rewritten boundary is a lookaround union rather
  than a single opcode, and every pattern carries it: **1.8× on short records
  and 2.8× on real documents** (497 µs → 878 µs, and 5.2 ms → 14.4 ms, with
  `[fast]` installed). An earlier revision of this entry said "about 20%" —
  that was measured on 186-character synthetic records only and extrapolated,
  wrongly, to real documents.

  `[fast]` is close to required as a result: the RE2 prefilter absorbs most of
  the cost by not running patterns that cannot match. Accuracy on the corpus is
  unchanged.

  Recovering the speed without giving back the five silent misses is open — the
  likely route is to ASCII-ise only those boundaries that abut a digit or an
  ASCII-only class, and leave plain `\b` where the neighbouring element is
  Unicode-capable, rather than applying the union to all 303 patterns.

### Added

- **`make check` and `make verify`.** One entry point for every check.
  `make check` is what CI runs; `make verify` adds the corpus checks CI cannot
  run, because the corpus lives outside the repository.

  - `tests/sweep.py` — structural properties over ~187,000 documents: offsets
    index the text, spans do not overlap, detection is deterministic, the cache
    is transparent, and no country argument changes which spans are found. Both
    ranking bugs above were found here; the twenty-document version that runs in
    CI showed nothing.
  - `scripts/parity.py` — do both SDKs mask the same *characters*, over whole
    corpora. Conformance vectors pin named cases; this is the broad counterpart,
    and it is how a 19,014-character gap was found that no vector showed.


### Known issues

- A checksum-invalid identifier occupying a span no other detector claims can
  still be reported under the wrong type — `7401011234` with `countries` `["CZ"]`
  is masked as a Romanian `PHONE` at `countryConfidence` 0. The span *is*
  redacted; only the label is wrong. The fragment rule above does not apply
  because the spans are equal rather than nested.

## 0.3.2 (2026-07-29)

### Changed

- **`countries=` no longer gates detection — it scores it.** Every pattern now
  runs on every document regardless of what the caller declares. The declared
  country decides how a match is *labelled*, never whether it is *found*.

  This fixes a silent recall failure. `countries=["BE"]` made a valid Dutch BSN
  vanish entirely, because the Dutch patterns were never run:

  ```python
  euredact.redact("Werknemer met BSN 111222333", countries=["BE"])
  # before: 'Werknemer met BSN 111222333'   <- leaked
  # now:    'Werknemer met BSN [NATIONAL_ID]'
  ```

  Entities attributed outside the declared set are flagged via the new
  `Detection.out_of_scope`, not dropped. The invariant — no value of
  `countries=` may change which spans are detected — is enforced by
  `tests/test_invariant_generation.py`.

  **Behaviour change for callers:** documents processed with a single
  `countries=[...]` value will now detect *more* than before, including
  entities belonging to other countries. Downstream code that assumed every
  detection belonged to the declared country should read `detection.country`
  or filter on `out_of_scope`.

- **Failed-checksum spans no longer delete overlapping detections.** A span
  that matched a checksummed pattern but failed the checksum created a
  "suppression zone" that removed any regex-only detection inside it. With more
  than one country loaded, one country's failed checksum silently deleted
  another country's correct detection.

  Measured across the corpus: the mechanism removed 454 detections, of which
  **454 overlapped real labelled PII** — it bought no precision at all. Such a
  candidate is now demoted below every other candidate rather than deleted, so
  it can still claim a span nothing else wants but can never silence one.

  On 10,000 documents:

  | | recall before | after | precision before | after |
  |---|---:|---:|---:|---:|
  | with country hints | 97.98% | **98.89%** | 98.98% | 98.97% |
  | blind | 91.23% | **96.11%** | 95.87% | 95.79% |

  No entity type regressed. Largest gains: `TAX_ID` 0.0% → 61.5% blind,
  `CHAMBER_OF_COMMERCE` 81.4% → 98.6% hinted, `PHONE` 71.2% → 85.1% blind,
  `NATIONAL_ID` 87.6% → 98.4% blind.

- **Suppression now runs only on candidates that win their span.** Previously
  every surviving match was suppressed before deduplication, though most lose
  their span immediately afterwards. Output is unchanged — verified zero-diff
  on 8,000 documents in both modes — and detection is 1.28x faster with country
  hints, 2.67x faster blind.

### Added

- **Country inference.** The engine works out which countries a document
  belongs to from entities that carry their country in the string — IBAN
  prefixes, `+CC` dialling codes, VAT prefixes, BIC country codes, email
  ccTLDs — and uses it to decide which national scheme owns an ambiguous
  value. 36.6% of national-ID values in the corpus validate under more than one
  country's checksum, so the digits alone cannot decide it.

  ```python
  euredact.redact("Bereikbaar op telefoon 0612345678, mail jan@test.nl")
  # -> PHONE (NL)

  euredact.redact("Kontakt: 0612345678, e-mail jens@test.dk")
  # -> NATIONAL_ID (DK)
  ```

  Identical digits: `0612345678` is both a valid Dutch mobile number and a
  valid Danish CPR. Only the document distinguishes them.

  On all 152,300 documents, blind detection (no `countries=`) improved from
  **95.6% to 98.3% precision** and from **96.10% to 98.84% type-correct**,
  closing the precision gap to hinted detection from 3.4 points to 0.3.

  (An earlier revision of this entry quoted 94.90% → 98.38% for type-correct.
  Those came from a 30,000-document prefix of the corpus, which is drawn from
  one dataset and is not representative; they were labelled as full-corpus in
  error. The figures above are measured over all 152,300.)

  Weights are derived from the corpus, not hand-tuned. Inference influences
  scoring only; it can never cause a miss.

- **RE2 scan prefilter, via `pip install euredact[fast]`.** One DFA pass per
  1 KB window reports which patterns can match in it; only those are then run
  over the text. A real 3,424-character document matches 42 of 314 prefiltered
  patterns, so the other 272 are skipped entirely.

  Measured on 611 real documents (mean 3,424 chars) and 3,000 synthetic
  records, end to end:

  | Input | Before | After |
  |---|---:|---:|
  | Short record (186 chars) | 723 µs | **496 µs** (1.46×) |
  | Real document (3,424 chars) | 10.4 ms | **5.4 ms** (1.94×) |

  **Output is unchanged, by construction.** The prefilter only decides which
  patterns are worth running; each survivor is then run over the whole text
  exactly as before, so skipping a pattern that matches nowhere cannot change
  the result. Verified identical to the plain-Python scan on all 4,611
  documents of both corpora.

  Restricting each pattern to its window instead is faster still (3.21× vs
  2.70× on the scan alone) but diverges from the reference scan on 44 matches,
  which was not judged worth a third set of scan semantics.

  Patterns RE2 cannot express (11 of 345 — lookbehind-based postal-code and
  secret rules) and those that can match further than the window overlap
  (31 more) always run. `tests/test_scan_path_parity.py` now exercises every
  available scan path against the plain-Python one, and CI runs the suite both
  with and without the optional extras.

- **`DocumentContext`** — shares country evidence across the chunks of one
  document, via `redact(..., context=ctx, chunk_offset=n)`. Without it, a chunk
  carrying no country signal of its own is scored as if the rest of the
  document did not exist:

  ```python
  euredact.redact("Telefoon 0612345678")          # -> NATIONAL_ID (DK)
  # page 1 established the document is Dutch; with a context:
  euredact.redact("Telefoon 0612345678", context=ctx)   # -> PHONE (NL)
  ```

  Thread-safe, deduplicated so a re-run chunk cannot vote twice, and spans are
  rebased by `chunk_offset` so recorded evidence points into the whole
  document. Caching is disabled while a context is in use, since the result no
  longer depends on the text alone.

- `RedactResult.inferred_countries` — `(country, confidence)` pairs, strongest
  first. Confidences are per-country and do not sum to 1: document countries
  are not mutually exclusive, and a Belgian supplier invoicing a German
  customer is genuinely both.
- `RedactResult.evidence` — every signal behind the inference, with the span
  that produced it. The audit trail for a country attribution.
- `RedactResult.detection_mode` — `"declared"` or `"inferred"`. Named
  `detection_mode` rather than `mode` because `redact(mode=...)` already means
  the tier selector.
- `Detection.country_confidence` — how strongly the document supports the
  attributed country, in [0, 1]. `0.0` is the signal that an attribution rests
  on a checksum alone.
- `Detection.out_of_scope` — attributed outside the declared `countries`.
- `country_hint=[...]` on every entry point — a prior that resolves ambiguity
  **without** narrowing scope or flagging anything out of scope, as distinct
  from `countries=`, which does both.

### Fixed

- **A failed checksum no longer demotes unrelated entity types on the same
  span.** A span that failed a checksum demoted *every* validator-less
  candidate covering it, whatever its type. So Sweden's own personnummer
  checksum failing on `0708787668` demoted the Swedish *phone* candidate for
  the same digits, handing the span to a Danish CPR that happened to validate.

  A failed checksum is evidence against *that type*, not against the span.
  Zones are now per entity type. Worth 878 mistyped phone numbers per 30,000
  documents.

- **A passing checksum from an uncorroborated country no longer outranks
  everything.** A weak checksum fits by luck — a mod-11 scheme accepts a random
  number about one time in eleven — so a validated candidate from a country the
  document shows no trace of is now treated as coincidence rather than
  evidence. Entities that carry their own country still vouch for themselves,
  so a foreign IBAN in a domestic invoice keeps its rank.


### Fixed — security

- **Installing the optional `fast` extra disabled private-key redaction.**
  Prefix-indexed patterns are only run over a bounded window after their prefix
  hit, but 15 SECRET patterns can match beyond it — the PEM private-key pattern
  matches up to 16 KB. With `pyahocorasick` installed those matches were never
  found, and a PEM block passed through into `redacted_text` unmasked.

  Reproduced on 0.3.1, identical input:

  ```
                            SECRET spans   key material in output?
  with    pyahocorasick     [15]           LEAKED
  without pyahocorasick     [542, 15]      not leaked
  ```

  Patterns whose maximum match width exceeds the window are now routed to the
  sequential path. Verified: the two scan paths produce identical output on
  12,000 corpus documents, where they previously diverged.

  Affects anyone who installed `euredact[fast]`. The pure-Python default was
  never affected, and the TypeScript package does not window its scans so was
  never affected either.

- `tests/test_scan_path_parity.py` runs **both** scan paths in one process and
  compares them, so the optional extra can no longer change behaviour silently.
  A >200-character PEM block is now a shared conformance vector.

## 0.3.1 (2026-07-27)

### Fixed

- **German plates are now validated against the district-code list.** The
  pattern accepted any 1-3 uppercase letters as a city code, so document
  references kept the plate shape: `REF-A12`, `SYS-B3`, `KTO-A1`, `JOB-C4`
  were all detected. The ~790 *Unterscheidungszeichen* are a closed set fixed
  by the Fahrzeug-Zulassungsverordnung, which makes membership a whitelist
  rather than the open-ended blocklist of standards prefixes it replaces —
  references of that shape now fail without needing to be enumerated.

  Applied as a tier, not a filter: a code on the list emits with no cue, a
  code absent from it still emits when a plate cue (`Kennzeichen`, `Kfz`,
  `Fahrzeug`) is nearby, and only the combination of neither is rejected. A
  code missing from the list therefore costs recall solely where there is no
  other evidence. Verified on the corpus: 548 true positives, 0 false
  positives, 0 missed.

  The standards guard is kept alongside it, because `DIN` is both a standards
  body and the district code for Dinslaken — a whitelist alone cannot tell
  `DIN A4` from a Dinslaken plate.

- **German `LICENSE_PLATE` matched standards codes and document references.**
  With `countries=["DE"]`, `ICD-10`, `ISO-9001`, `EN-1090`, `DIN-4102`,
  `RFC-2822`, `COVID-19`, `POL-2025` and similar were replaced with
  `[LICENSE_PLATE]`, corrupting the returned text —
  `Diagnose: ... ([LICENSE_PLATE]: E11.9)`. Measured at 98 occurrences across
  68 documents in a 5,010-document corpus, and the same token shape occurs
  14,563 times corpus-wide, so the blast radius grows sharply if `DE` is passed
  for a cross-border document.

  The cause was not that the letter group after the hyphen was optional — it
  never was. The *first* separator was optional, so a contiguous letter run
  split across both groups and the hyphen was consumed as the second
  separator: `ICD-10` parsed as city `IC` + letters `D` + `-` + `10`. The
  separator after the city code is now mandatory, which is correct for a real
  plate (`B-AB 1234`, `M-XY 99`) since that is where the seal sits.

  A standards-prefix guard (`ICD`, `ISO`, `DIN`, `IEC`, `RFC`, `DSM`, `ATC`,
  `MDR`) covers the residue that is genuinely plate-shaped, such as `ATC-N06`.
  It is gated on the absence of a plate cue, so `Kennzeichen ATC-N 06` is still
  detected.

### Added

- **Shared conformance suite** (`conformance/vectors.json`). Language-neutral
  input/expectation pairs run by both SDKs, so a behavioural difference between
  Python and TypeScript fails a test rather than surfacing later as a corpus
  diff. Verified to work: reverting the plate fix in one engine alone fails
  five shared vectors.

## 0.3.0 (2026-07-27)

### Measured effect

Full evaluation over 152,300 generated records (`tests/eval_full.py`), measured
against the same engine with the detection changes below reverted, on identical
ground truth:

| | 0.2.0 | 0.3.0 |
|---|---|---|
| Recall, `countries=[...]` supplied | 98.11% | **98.28%** |
| Precision, `countries=[...]` supplied | 98.21% | **98.97%** |
| False positives | 12,468 | **7,160** |
| Recall / precision, blind (no `countries`) | — | 94.39% / 95.22% |

Net: recall up, false positives down 43%. DOB is excluded (40.6%; deferred to
the LLM tier by design).

The Python and TypeScript engines now produce **byte-identical redacted output
on 2,500 corpus documents** and agree to within 0.01 points on recall.

Two figures published previously do not reproduce and should not be reused:
"99.1% recall / 147K records" (the set is 152,300 records and the engine
measured 98.11% before these changes), and "0.02 ms per page" — that is the
cache-hit path; uncached, a 2,000-character page takes **4.6 ms** in Python and
**0.28 ms** in the TypeScript engine.

### Breaking

- **`IBAN` is renamed to the canonical `BANK_ACCOUNT`.** The engine emitted a
  legacy type name; the canon (`config/entity_types.json` → `legacy_aliases`)
  defines `"IBAN": "BANK_ACCOUNT"`. `detection.entity_type.value` is now
  `"BANK_ACCOUNT"` and the placeholder written into redacted text is
  `[BANK_ACCOUNT]`, not `[IBAN]`.

  `EntityType.IBAN` is kept as an **alias** of `EntityType.BANK_ACCOUNT`, and
  `EntityType("IBAN")` still resolves, so code referring to the member keeps
  working. Code matching on the *string* `"IBAN"` — or on the `[IBAN]`
  placeholder — must be updated. `euredact.types.LEGACY_TYPE_ALIASES`
  publishes the mapping.

  An audit against the canon found this to be the only mismatch: every other
  emitted type name is canonical (`NAME` and `OTHER` are cloud-tier internals
  with no rules-engine emission).

### Fixed

- **BIC no longer matches ordinary ALL-CAPS words.** The rule was shape-only:
  any 8- or 11-character uppercase run was treated as a BIC, so section
  headings and shouted words (`DRINGEND`, `HOSPITAL`, `GEGEVENS`,
  `MAANDELIJKS`) were masked. Measured on a 5,010-document corpus, 78% of
  `BIC` detections were false positives. Because a masked span is replaced in
  the document body, this destroyed text rather than merely mislabelling it —
  `QUEEN ELIZABETH [BIC] BIRMINGHAM` left the hospital name unlabelable.

  Structural validation alone is not enough: characters 5-6 of ordinary words
  are frequently valid ISO 3166 country codes (`DRINGEND` -> `GE`,
  `HOSPITAL` -> `IT`), and BIC is the only bank identifier here with no check
  digit. Detection is now tiered — see "BIC detection" in the README.

- **Bare 4-digit postal codes no longer shred longer identifiers.** Any bare
  digit run was claimable as a postal code, including digits inside a longer
  number: `SV-Nummer: [POSTAL_CODE] 040390` cut an Austrian social security
  number in half, and `+43 664 [POSTAL_CODE] 907` took digits belonging to a
  phone number. A digits-only match is now rejected when it is directly
  adjacent to another digit; when `. - / _` **joins it to another digit
  group** (`0456.2398.71-02`); when a further digit group follows on the same
  line; when an identifier label introduces it (`DiNr.`, `Policen-Nr.`, `N°`);
  or when it follows an international dialling prefix.

  Note the punctuation rule is deliberately narrow: the separator only counts
  when a digit sits on the far side of it. Treating a trailing `.` as a
  separator rejects every postal code that ends a sentence
  (`Domicilio: Palma, 13867. Pagos a ...`) — measured at 18,977 lost true
  positives, POSTAL_CODE recall 96.2% -> 61.0%, on the 152,300-record set.

- **International phone numbers were missed in 11 countries.** Each country's
  international pattern hard-coded a single grouping, so `+43 664 8213 907`
  was invisible to the Austrian pattern (which expects an unbroken subscriber
  number) while `+32 498 22 67 31` matched fine. 16 of 59 realistic formats
  went undetected, including every `(0)` trunk-prefix form. A missed phone
  number in a redaction product is leaked PII.

  This was also the **root cause of the postal-code split**: with no phone
  match to claim the span, the bare-4-digit rule took `8213` out of the middle
  of the number. A country-independent E.164 pattern now runs alongside the
  per-country ones — a leading `+` is self-identifying, so it is not gated.

- **IBANs were gated by `countries=[...]`.** `BE68 5390 0754 7034` was
  detected with `countries=["BE"]` and missed with `countries=["AT"]`, so
  every cross-border document leaked the account number. An IBAN carries its
  own country code and a mod-97 checksum; it is now detected on structure and
  checksum alone, whatever the caller requests. `countries` still prioritises,
  never gates.

- **`countries=["GB"]` raised `ValueError`.** The registry uses the EU/VAT
  spellings (`UK`, `EL`) while the documented contract is ISO 3166-1 alpha-2
  (`GB`, `GR`), so a caller passing correct ISO codes crashed. Both spellings
  are now accepted and are exactly equivalent.

  An unrecognised code no longer raises at all: it emits an
  `UnknownCountryWarning` and continues with the shared, country-independent
  patterns. Throwing invited callers to wrap the call in `try/except` and skip
  redaction — failing open, with unredacted PII.

- **Austrian national numbers with a short area code were missed.**
  `01 53460 2215` (Vienna) did not match, because the national pattern
  requires 3-4 digits after the trunk `0`. A grouped variant now covers short
  area codes; both separators are mandatory so date fragments like `01 2025`
  stay out.

- **Space-separated bank codes were missed** — `RZBA AT WW`, `NICA BE BB`.
  Added as a separate pattern requiring a space between every group rather
  than making spaces optional in the existing one, which would have let
  `GEBABEBB KBC` match as a single 11-character code and claim the following
  word. Only literal spaces are allowed, so a match cannot span a line break.

- **Place names beginning "St." suppressed the postal code before them.**
  The unit filter's bare `st` (stuks/pieces) matched the `St.` in
  `8386 St. Gallen` and `9600 St. Paul's Bay`. It now requires that `st` not be
  followed by `.` and a capital.

- **Country-prefixed postal codes were read as subtraction.** `A-1010 Wien`,
  `B-2000 Antwerpen` and `D-10115 Berlin` were discarded because the hyphen
  looked like a minus sign to the maths filter. Genuine arithmetic
  (`Ergebnis = 1010`, `Rabatt -2000 EUR`) is still suppressed.

- **Residence phrasing now counts as postal context.** `wonende te 2000
  Antwerpen` and `domicilié à 1000 Bruxelles` were dropped by the
  year-as-postal filter, which only recognised explicit address words.

### Changed

- `validate_bic()` now requires a real ISO 3166-1 alpha-2 code at positions
  5-6. `ISO_3166_ALPHA2` is exported from `euredact.rules.validators`.
- The IBAN length table is hoisted to `euredact.rules.validators.IBAN_LENGTHS`
  and drives the country-independent IBAN pattern, which pins each country's
  exact length so a match cannot absorb a following word.
- Some spans are now **relabelled** rather than newly masked, because a
  checksum-validated detector reclaims them from a weaker one: `RO57` at the
  head of an IBAN is no longer a Romanian `VAT`, and `+31 621036924` is a
  `PHONE` rather than a Dutch `NATIONAL_ID`. Verified on 28,852 documents: no
  character that was masked before is unmasked now.
- POSTAL_CODE now resolves **last** in overlap deduplication, so it can only
  claim spans no structured detector (PHONE, SSN, NATIONAL_ID, IBAN, VAT,
  CREDIT_CARD...) wants, regardless of span length.

### Added

- `euredact.set_bic_registry()` — install a BIC registry consulted ahead of
  the bundled seed prefixes. Accepts a membership callable, an iterable of
  BICs, a path to a newline-delimited file, or `None` to remove. Entries may
  be full BIC8/BIC11 codes or bare BIC6 prefixes.
- A bundled seed list of BIC6 institution+country prefixes for major European
  banks, compiled from publicly published bank data. No licensed directory is
  bundled.

## 0.1.0 (2026-03-30)

Initial release of the EuRedact rule engine.

### Features

- **31 countries**: All EU-27 member states plus UK, Switzerland, Iceland, and Norway
- **20+ PII entity types**: National IDs, IBANs, phone numbers, email, VAT, license plates, VIN, credit cards, BIC/SWIFT, IMEI, GPS coordinates, UUIDs, social handles, MAC/IP addresses
- **Checksum validation**: IBAN (mod-97), Luhn, and 20+ country-specific national ID validators
- **Two-pass detection**: Liberal pattern matching followed by suppression filters for false positive reduction
- **Context-aware detection**: Keyword proximity checks and structural detection (JSON field names, CSV headers)
- **Batch processing**: `redact_batch()`, `redact_iter()`, `aredact_batch()` for bulk workloads
- **True async**: `aredact()` offloads to thread pool, non-blocking for async frameworks
- **Referential integrity**: Consistent label mapping within a session (`referential_integrity=True`)
- **Aho-Corasick acceleration**: Optional `pyahocorasick` for faster pattern scanning
- **Zero required dependencies**: Pure Python, works with `pip install euredact`

### Performance

- Sub-millisecond per page (~0.5ms for typical documents)
- ~2,000 records/second on mixed workloads
- 99.1% recall, 99.3% precision on 147K-record evaluation across all 31 countries
