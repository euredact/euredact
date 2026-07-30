# Changelog

## 0.3.6 (2026-07-30)

### Fixed

False positives only, ported from the Python SDK so the two engines stay in
step. Every change corrects a case that was wrong on its own terms — a broken
regex, a missing entry in a list meant to be complete, a suppressor wired to
every numeric type but one — rather than tuning a threshold against a corpus.
Measured on 152,300 documents and 667,129 labels: **false positives fell from
3,294 to 1,232** with country hints, and from 4,782 to 2,720 blind. Recall did
not fall.

| | precision | recall | F1 |
|---|---:|---:|---:|
| 0.3.5, with country hints | 99.51% | 99.71% | 99.61% |
| **0.3.6** | **99.82%** | **99.72%** | **99.77%** |
| 0.3.5, blind | 99.28% | 99.49% | 99.39% |
| **0.3.6** | **99.59%** | **99.50%** | **99.55%** |

- **Ticket and incident numbers were postal codes.** `suppressReference` was
  wired to every numeric entity type except `POSTAL_CODE`, so `Ticket #94730`
  and `Incident report IR-43433` were masked as addresses. Support-desk
  vocabulary was added in nine languages, and `#` and `IR-`-style tags are now
  recognised adjacently rather than through the 150-character keyword window.

- **`desember` was missing from the month list**, so `1. desember 2025` was a
  Norwegian postcode. The Icelandic month names were absent for the same reason.

- **Crypto tickers were licence plates.** `4499 BTC` matched Spain's
  four-digits-then-three-consonants shape; the fiat ISO 4217 codes were already
  excluded and a ticker is a unit in the same way.

- **API endpoints, hostnames and LDAP names were secrets** —
  `https://api.sendgrid.com/v3/mail/send`, `api.example.eu`,
  `cn=github-actions,dc=corp,dc=eu`, `analytics-engine`. A URL that *carries* a
  credential (`mongodb://user:password@host`, or a URL with `?api_key=`) is
  still a secret and is covered by a conformance vector.

- **`SECRET` no longer claims an email address**, on the same reasoning that
  already stopped it claiming UUIDs and BICs.

- The currency lists were widened to match the Python SDK (more ISO codes,
  symbols held separately from alphabetic codes, and the Spanish, Italian,
  Polish, Czech and Hungarian words for "amount"). The `\b`-after-`€` defect
  fixed in the Python engine never affected this one, which used a Unicode
  lookahead.

Thirteen conformance vectors were added (93 → 106), run by both SDKs.

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

- **`DocumentContext.evidence` was a method while `.size` was a getter.** The
  inconsistency was the hazard rather than the style: `ctx.size()` and
  `ctx.evidence` both *succeed* and return something useless — a number is not
  callable, a function object is truthy — so the mistake surfaced later as an
  empty result. `evidence` is now a getter, and the wrong form throws.
  (The Python SDK keeps `evidence()`, following its own idiom.)

- Node already handled non-ASCII word boundaries correctly; the matching Python
  fix means both runtimes now agree on all five cases. They are pinned as
  shared conformance vectors, since the divergence was undetectable by testing
  either package alone.

### Known issues

- A checksum-invalid identifier occupying a span no other detector claims can
  still be reported under the wrong type — `7401011234` with `countries` `["CZ"]`
  is masked as a Romanian `PHONE` at `countryConfidence` 0. The span *is*
  redacted; only the label is wrong. The fragment rule above does not apply
  because the spans are equal rather than nested.

## 0.3.2 (2026-07-29)

### Changed

- **`countries` no longer gates detection — it scores it.** Every pattern now
  runs on every document regardless of what the caller declares. The declared
  country decides how a match is *labelled*, never whether it is *found*.

  This fixes a silent recall failure. `countries: ["BE"]` made a valid Dutch
  BSN vanish entirely, because the Dutch patterns were never run:

  ```ts
  redact("Werknemer met BSN 111222333", { countries: ["BE"] });
  // before: 'Werknemer met BSN 111222333'   <- leaked
  // now:    'Werknemer met BSN [NATIONAL_ID]'
  ```

  Entities attributed outside the declared set are flagged via the new
  `Detection.outOfScope`, not dropped. The invariant — no value of `countries`
  may change which spans are detected — is enforced by
  `src/__tests__/inference.ts`.

  **Behaviour change for callers:** documents processed with a single
  `countries` value will now detect *more* than before, including entities
  belonging to other countries. Code that assumed every detection belonged to
  the declared country should read `detection.country` or filter on
  `outOfScope`.

  This also closes a large gap against the Python SDK. Measured on 611 real
  documents (mean 3,424 chars), comparing which characters each SDK masks:

  | | documents masking identically | divergence | characters TS failed to mask |
  |---|---:|---:|---:|
  | before | 213 / 611 | 13.47% | 19,014 |
  | after | **571 / 611** | **1.46%** | 1,021 |

### Added

- **Country inference.** The engine works out which countries a document
  belongs to from entities that carry their country in the string — IBAN
  prefixes, `+CC` dialling codes, VAT prefixes, BIC country codes, email
  ccTLDs — and uses it to decide which national scheme owns an ambiguous
  value. 36.6% of national-ID values in the corpus validate under more than one
  country's checksum, so the digits alone cannot decide it.

  ```ts
  redact("Bereikbaar op telefoon 0612345678, mail jan@test.nl"); // -> PHONE (NL)
  redact("Kontakt: 0612345678, e-mail jens@test.dk");            // -> NATIONAL_ID (DK)
  ```

  Identical digits: `0612345678` is both a valid Dutch mobile number and a
  valid Danish CPR. Only the document distinguishes them.

  Weights are derived from the corpus and kept identical to the Python SDK's.
  Inference influences scoring only; it can never cause a miss.

- `RedactResult.inferredCountries` — `[country, confidence]` pairs, strongest
  first. Confidences are per-country and do not sum to 1: document countries
  are not mutually exclusive, and a Belgian supplier invoicing a German
  customer is genuinely both.
- `RedactResult.evidence` — every signal behind the inference, with the span
  that produced it, in document order. The audit trail for an attribution.
- `RedactResult.detectionMode` — `"declared"` or `"inferred"`. Named
  `detectionMode` rather than `mode` because `redact({ mode })` already means
  the tier selector.
- `Detection.countryConfidence` — how strongly the document supports the
  attributed country, in [0, 1]. `0` is the signal that an attribution rests on
  a checksum alone.
- `Detection.outOfScope` — attributed outside the declared `countries`.
- `countryHint` — a prior that resolves ambiguity **without** narrowing scope or
  flagging anything out of scope, as distinct from `countries`, which does both.
- **`DocumentContext`** — shares country evidence across the chunks of one
  document, via `redact(text, { context, chunkOffset })`. Without it, a chunk
  carrying no country signal of its own is scored as if the rest of the
  document did not exist. Deduplicated so a re-run chunk cannot vote twice, and
  spans are rebased by `chunkOffset`. Caching is disabled while a context is in
  use, since the result no longer depends on the text alone.

### Fixed

- **A failed checksum no longer demotes unrelated entity types on the same
  span.** A span that failed a checksum demoted *every* validator-less
  candidate covering it, whatever its type. So Sweden's own personnummer
  checksum failing on `0708787668` demoted the Swedish *phone* candidate for
  the same digits, handing the span to a Danish CPR that happened to validate.
  A failed checksum is evidence against *that type*, not against the span.

- **A passing checksum from an uncorroborated country no longer outranks
  everything.** A weak checksum fits by luck — a mod-11 scheme accepts a random
  number about one time in eleven — so a validated candidate from a country the
  document shows no trace of is now treated as coincidence rather than
  evidence. Entities that carry their own country still vouch for themselves,
  so a foreign IBAN in a domestic invoice keeps its rank.

- **Deduplication no longer truncates an entity to honour the declared
  country.** Span length now outranks scope, so preferring the declared
  country can change *which* country is attributed but never *what* is masked.

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
  With `countries: ["DE"]`, `ICD-10`, `ISO-9001`, `EN-1090`, `DIN-4102`,
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

Brings the TypeScript engine to parity with `euredact` 0.3.0 for Python. The two
engines now agree to within 0.01 points on a 152,300-record evaluation set
(recall 98.28%, precision 98.97% with country hints) and produce
**byte-identical redacted output on 2,500 corpus documents**.

### Breaking

- **`IBAN` is renamed to the canonical `BANK_ACCOUNT`.** `detection.entityType`
  is now `"BANK_ACCOUNT"` and the placeholder written into redacted text is
  `[BANK_ACCOUNT]`, not `[IBAN]`.

  `EntityType.IBAN` is kept as an alias with the same value, so
  `EntityType.IBAN === EntityType.BANK_ACCOUNT` and code referring to the member
  keeps working. Code matching the *string* `"IBAN"` — or the `[IBAN]`
  placeholder — must be updated. `LEGACY_TYPE_ALIASES` publishes the mapping.

### Fixed

- **BIC no longer matches ordinary ALL-CAPS words.** The rule was shape-only, so
  headings and shouted words (`DRINGEND`, `HOSPITAL`, `GEGEVENS`) were masked.
  BIC is the only bank identifier with no check digit, and characters 5-6 of
  everyday words are frequently valid ISO 3166 country codes, so structure alone
  cannot decide. Detection is now tiered — see "BIC detection" in the README.

- **Bare 4-digit postal codes no longer shred longer identifiers.**
  `SV-Nummer: [POSTAL_CODE] 040390` cut an Austrian social security number in
  half. A digits-only match is now rejected when adjacent to another digit, when
  `. - / _` joins it to another digit group, when a further digit group follows
  on the same line, when an identifier label introduces it, or when it follows
  an international dialling prefix.

- **International phone numbers were missed in 11 countries.** Each country's
  pattern hard-coded a single grouping, so `+43 664 8213 907` was invisible.
  A country-independent E.164 pattern now runs alongside them — a leading `+`
  is self-identifying, so it is not gated. This was also the root cause of the
  postal-code split above.

- **Austrian national numbers with a short area code were missed** —
  `01 53460 2215` (Vienna).

- **IBANs were gated by `countries`.** A Belgian IBAN was missed when processing
  with `countries: ["AT"]`, so every cross-border document leaked the account
  number. IBANs are now detected on structure and mod-97 checksum alone.

- **`countries: ["GB"]` silently degraded to shared patterns only.** The country
  table uses the EU/VAT spellings (`UK`, `EL`) while the documented contract is
  ISO 3166-1 alpha-2 (`GB`, `GR`). Both spellings are now accepted and
  equivalent. An unrecognised code logs an `[euredact]` warning and continues
  with the shared, country-independent patterns.

- **Space-separated bank codes were missed** — `RZBA AT WW`, `NICA BE BB`.

- **`EMAIL` and `SOCIAL_HANDLE` missed non-ASCII local parts.** JavaScript's
  `\w` and `\b` are ASCII-only, so `petras_ž@example.com` was missed entirely
  (and sometimes mis-tagged as a social handle), while the Python engine
  matched it. Both patterns now use `\p{L}\p{N}` with the `u` flag. This
  affected Baltic, Polish, Czech and Greek text and was the last behavioural
  difference between the two engines.

- **Country-prefixed postal codes** (`A-1010 Wien`) were read as subtraction,
  and **residence phrasing** (`wonende te 2000 Antwerpen`) did not count as
  postal context. Both ported from the Python engine.

### Changed

- `validateBic()` now requires a real ISO 3166-1 alpha-2 code at positions 5-6.
  `ISO_3166_ALPHA2` is exported from `rules/validators`.
- The IBAN length table is hoisted to `IBAN_LENGTHS` and drives the
  country-independent IBAN pattern, which pins each country's exact length so a
  match cannot absorb a following word.
- POSTAL_CODE now resolves **last** in overlap deduplication, so it can only
  claim spans no structured detector wants, regardless of span length.

### Added

- `setBicRegistry()` — install a BIC registry consulted ahead of the bundled
  seed prefixes. Accepts a membership callable, an iterable of BICs, or `null`
  to remove. Entries may be full BIC8/BIC11 codes or bare BIC6 prefixes.
- A bundled seed list of BIC6 institution+country prefixes for major European
  banks, compiled from publicly published bank data. No licensed directory is
  bundled.
- `npm test` now runs **142 assertion tests** (`src/__tests__/spec.ts`) covering
  every fix above. The previous sampled evaluation moved to `npm run test:eval`;
  `npm run test:eval:full` runs the whole corpus with throughput reporting.

### Known issues

None outstanding for this release.

## 0.2.0

Initial TypeScript port of the EuRedact rule engine.
