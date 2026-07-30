# Changelog

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
