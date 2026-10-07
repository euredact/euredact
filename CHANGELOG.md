# Changelog

All notable changes to **both** SDKs in this repository — `euredact` on PyPI
(`euredact-python/`) and `euredact` on npm (`euredact-ts/`) — are recorded here.
The two ship from one tag and always carry the same version number.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

**How to read this file.** Every entry is one scannable line under one of the
six Keep a Changelog types — `Added`, `Changed`, `Deprecated`, `Removed`,
`Fixed`, `Security`. Two further blocks appear where a release needs them and
are not change types: `Known issues` and `Notes`. An entry that applies to only
one SDK is marked *(Python only)* or *(TypeScript only)*; everything else landed
in both, because cross-SDK parity is tested rather than assumed.

**Where the reasoning lives.** This file answers *what changed*. The per-package
changelogs answer *why*, at length — the measurement that motivated a fix, the
false positives a wider pattern cost, the alternative that was rejected:

- [`euredact-python/CHANGELOG.md`](euredact-python/CHANGELOG.md)
- [`euredact-ts/CHANGELOG.md`](euredact-ts/CHANGELOG.md)

Both are kept; this file does not replace them. A behavioural entry here almost
always corresponds to a case in [`conformance/vectors.json`](conformance/vectors.json),
which both test suites run.

## [Unreleased]

### Added

- Batches for the cloud tier: `create()` masks locally and uploads only masked text, keeping originals in a private local batch file; `results()` maps the answers back from it after a hash check, once, then wipes the originals. Both SDKs share the file format. `custom_id`s are checked against the gateway's character rule before any document is masked. *(rules-engine#84, #88)*
- About 10,400 BIC6 prefixes for the 31 supported countries from the GLEIF BIC-to-LEI mapping (developed by SWIFT, redistributable under the BIC/LEI Mapping Table License Agreement; notice in `NOTICE`), with `scripts/refresh_bic_registry.py` to regenerate them. *(rules-engine#57)*

- Polish identity card (dowód osobisty, with its check digit) as `NATIONAL_ID`, REGON (9 or 14 digits, mod-11) as `CHAMBER_OF_COMMERCE`, and the driving-licence number and document number as `DRIVERS_LICENSE`, each behind its label; beside a passport mention they no longer come out as `[PASSPORT]`. *(rules-engine#75, #76, #77)*

### Changed

- A pattern RE2 rejects only for a lookaround keeps the RE2 prefilter through a lookaround-free superset; patterns outside it fall from 35 to 23. *(Python only)* *(rules-engine#72)*

- A label touching a value rescues a failed checksum on a label-gated pattern too (`Numer dowodu osobistego ABA912345`), as it already did on the others. *(rules-engine#75)*

### Fixed

- A Polish domestic account number (NRB, the IBAN without `PL`) was not detected, and an 8-digit fragment of it was masked as `PHONE`; it is now `BANK_ACCOUNT`, spaced or compact, validated by the IBAN check digits. *(rules-engine#93)*
- A Polish NIP in the grouping used for natural persons (`XXX-XX-XX-XXX`) was not detected; it is now `TAX_ID`, like the company grouping. *(rules-engine#94)*
- A Swiss AVS/AHV number with a bad check digit was left in the clear even behind its own label (`Numéro AVS`, `AHV-Nr.`, `n° AVS`); the label, or `AVS`/`AHV` nearby for the dotted form, now masks it as `NATIONAL_ID`. *(rules-engine#82)*
- A Polish KRS number was masked as `PHONE`; behind its `KRS` label it is now `CHAMBER_OF_COMMERCE`. *(rules-engine#90)*
- A licence plate was matched inside a reference joined by `/`, `.`, `_` or `+`, or after `#`/`№`/`n°` (`Ref #FR-S2-2026-009182`, `FR-S2/2026`); a plate must now be a token of its own, unless a plate cue is nearby. *(rules-engine#81)*
- A Luxembourg matricule grouped other than compact or fully spaced was half-masked, or not at all, leaving the birth date readable: `19710314 12345` and `1971 0314 123 45` are now one `NATIONAL_ID`. *(rules-engine#49)*
- German phone numbers with trailing two-digit groups were cut short (`+49 170 1234567 85 21` left `85 21` readable), and a prefix set off by ` / ` was not detected at all. *(rules-engine#51)*
- A postal code with a two-letter country prefix (`CH-8004 Zürich`, `DE-10115 Berlin`, `NL-1012 LG Amsterdam`) was not masked: the prefix was read as a reference tag. References such as `IR-43433` and `PV-2026-LU-09143` stay unmasked. *(rules-engine#58)*
- A place name with a non-ASCII letter (`Zürich`) did not count as one in the address-structure check. *(TypeScript only)* *(rules-engine#58)*
- A UK National Insurance number (NINO) is typed `SSN`, as the canon defaults it, instead of `NATIONAL_ID`; the placeholder changes, the masked characters do not. *(rules-engine#47)*
- A licence plate was cut out of a longer hyphen-joined reference (`TF-284-KL-00874` → `[LICENSE_PLATE]-00874`); a plate candidate glued to more of the token by a hyphen is no longer a plate. *(rules-engine#50)*
- A residence-permit number behind a permit label (`Aufenthaltstitel Nr.:`, `Verblijfsvergunning`, `Titre de séjour`, …) is typed `RESIDENCE_PERMIT` instead of the `NATIONAL_ID`, `PASSPORT` or `PHONE` pattern that happened to fit it; a Spanish NIE stays `NATIONAL_ID`. *(rules-engine#53)*
- Every date in a document took its type from whichever date label the document carried (an admission date as `DATE_OF_DEATH`, a death date as `DOB`, an invoice date as `DOB`); a `DOB` or `DATE_OF_DEATH` keyword now counts only as the date's own label, or as its column header in a table. *(rules-engine#52)*
- An insurance claim number behind its label (`Schadeclaim 2026-0412`, `numéro de sinistre`, `claim number`) was masked as a Cypriot `PHONE`; it is now `INTERNAL_ID`, like `Dossiernummer`. *(rules-engine#54)*
- Surnames and ALL-CAPS words near an IBAN were masked as `[BIC]` (`Dr. Joëlle NGUYEN-[BIC]`, `BETALING`); a letters-only code that misses the registry now needs a `BIC`/`SWIFT` label, unless the bundled GLEIF mapping knows the institution, and a hyphen-joined token or one after a personal title is never a BIC. *(rules-engine#57)*
- A phone number followed by a date took the date's day (`[PHONE].03.2024`); the Austrian grouped phone pattern no longer ends on the start of a date or time. *(rules-engine#60)*
- Token suffixes could contain `A`, `E`, `U` and `Y`, against the documented "no vowels" (`POSTAL_CODE_KENE`); the alphabet is now `BCDFGHJKLMNPQRSTVWXZ23456789`. *(rules-engine#55)*
- The package can be bundled for a browser: `node:crypto` is no longer imported outside a platform module, and the `browser` field selects a Web-Crypto build. *(TypeScript only)* *(rules-engine#56)*

### Security

- The cloud base URL must use TLS: a non-`https` URL (from `configure`, `EUREDACT_BASE_URL` or a hand-built config) now raises instead of sending the API key and text over plain HTTP; `http://` stays allowed to `localhost`, `127.0.0.1` and `::1`. *(rules-engine#86)*

## [0.6.0] - 2026-10-05

### Added

- This file: a root changelog covering both SDKs, strictly categorised, with SDK-specific entries marked.
- `What \`countries\` actually controls` in both package READMEs — the parameter scores and attributes, it does not decide what is found, shown with output from all four call shapes.
- `Batch processing and concurrency` in both package READMEs, covering `redact_batch` / `aredact_batch` / `redact_iter` and why the TypeScript batch is synchronous.
- `What leaves your machine` in both package READMEs: in `mode="cloud"` the rules engine runs locally first and only the masked text is sent; names, diagnoses and whatever the rules miss still travel. *(rules-engine#28)*
- `Keeping identifiers local`: the `tokenize` → model → `restore` composition, including the part it cannot do.
- `tests/test_changelog.py`, which holds this file to its declared vocabulary. *(Python only)*
- Separator tolerance in 22 VAT patterns, so the spaced form printed on invoices is recognised.
- `tests/test_idempotence.py` — redaction over already-redacted text is a no-op on its own markers. *(Python only)*
- `DOB_CONTEXT`, one shared birth-date keyword list covering all 31 countries, replacing two divergent copies. *(rules-engine#38)*
- `tests/test_dob_context.py`, which asserts the substring screen that keeps a short keyword from hiding inside an unrelated word. *(Python only)*
- 45 conformance vectors closing gaps where a change was pinned in fewer countries than it touched: one per changed VAT pattern, one per country whose birth-date keyword had none, the Belgian and French national passport patterns, and the account-run guard. *(rules-engine#44)*
- `TestNoDateBearingValidatorAcceptsAnImpossibleDate`, a property over the whole validator table; it found three more validators with the `#37` defect. *(Python only)* *(rules-engine#44)*

### Changed

- **Breaking, cloud tier (private alpha):** `mode="cloud"` is local-first. The SDK runs the rules engine on the caller's machine and sends only the `[TYPE]`-masked text; it used to send the whole document. Needs a service that answers with spans relative to the text it received (euredact-inference#14). *(rules-engine#28)*
- Cloud results are assembled locally: the service's spans are mapped from the masked text back onto the original and merged with the local detections, so `detections` index the caller's document and carry the local pass's country attribution, `inferred_countries` and `evidence`. *(rules-engine#28)*
- A service span that does not match the text that was sent raises `CloudError` on every cloud call, not only under `tokenize` or an allowlist. *(rules-engine#28)*
- Custom patterns apply in cloud mode: they run in the local pass and are masked before the request. *(rules-engine#28)*
- `tokenize` and the allowlists never change what is sent: the wire always carries `[TYPE]` placeholders, and an allowlisted value is masked in the request and restored in the result. *(rules-engine#28)*

### Removed

- `rules_only` / `rulesOnly` on `CloudClient.redact()` and in the request body. It had no surface on `redact()`, and from a local-first client the rules have already run. *(rules-engine#28)*

### Fixed

- A stale duplicate `## Performance` section in the TypeScript README quoted 0.02 ms latency and an 86 KB package; both were wrong. Removed, with the measured figures (150 kB tarball) kept in the real section. *(TypeScript only)*
- A space inside a VAT number made it `PHONE`: `ATU 36438508` was typed `PHONE` with `ATU` left in the clear, because no VAT pattern tolerated the separator and Denmark's eight-digit phone shape did. *(rules-engine#30)*
- The tail of a hyphenated case reference was masked as a postal code — `PV-2026-LU-09143` became `PV-2026-LU-[POSTAL_CODE]`. *(rules-engine#31)*
- One address in a document made every later four-digit year a postal code, including law citations and CV date ranges. *(rules-engine#32)*
- The engine's own `[POSTAL_CODE]` marker was detected as `SECRET` on a second pass, corrupting the first pass's output. *(rules-engine#33)*
- A Czech mobile number could be typed `NATIONAL_ID` at `confidence="high"`: the birth-number validator checked mod 11 but never the date, so an impossible month was accepted. 284 per corpus pass, the largest single false-positive bucket in the evaluation. *(rules-engine#37)*
- **DOB recall 62.8% -> 100.0% in all 31 countries.** 33,441 birth dates were unmasked because the context list covered seven languages of thirty-one; per-country recall was bimodal, eleven countries at exactly 100% against twenty at 42-51%. DOB false positives did not move. *(rules-engine#38)*
- An assigned secret's span swallowed the sentence's full stop, and with it the type: `credentials. Reisepass: CA1234567.` reported `SECRET 'CA1234567.'` instead of a `PASSPORT`. *(rules-engine#35)*
- Postal codes were unmasked in five countries: a missing inflection in France and Belgium, a missing generic label in Iceland, Norway and Sweden, and — in Norway, Denmark and Finland — a suppressor whose identifier cue matched the postal label itself, so the pattern was dead behind `postnummer:`. Recall 98.07% → 99.99%. *(rules-engine#41)*
- A Handelsregister number's court suffix was left outside the span, so the output read `[CHAMBER_OF_COMMERCE] B`. German recall 77.18% → 100.00%. *(rules-engine#42)*
- `polish_pesel`, `romanian_cnp` and `slovenian_emso` accepted an impossible birth date, so a phone-shaped run could be typed `NATIONAL_ID` at high confidence. *(rules-engine#43)*

## [0.5.1] - 2026-09-25

### Added

- Passport detection in all 31 supported countries rather than four, behind one shared multilingual label set, so a foreign passport in a German, Polish or Greek document is recognised.

### Fixed

- A German tax identifier was left in the clear under its own official label: `Steuerliche Identifikationsnummer` was longer than the cue window and read as no label at all.
- `Exemption` is exported from the package root; `from euredact import Exemption` previously raised. *(Python only)*
- `make sweep` and `make parity` refuse to run on an incomplete corpus instead of silently sampling a different population. *(Python only)*

## [0.5.0] - 2026-09-24

### Added

- Reversible tokenization: `redact(text, tokenize=True)` / `redact(text, { tokenize: true })` and `restore()`, so a prompt sent to a model can come back with the real values restored.
- Allowlist: values that are never redacted, settable per call and per instance.
- The allowlist reports what it exempted, matches structured identifiers across differences in spacing, and can take a whole domain.
- Conformance vectors can carry per-call options and an expected redacted output.

### Changed

- `make eval` measures whole-identifier masking, so a partially masked value no longer scores as a hit. *(Python only)*

### Fixed

- An apostrophe in an email local part left the prefix unmasked.
- Compressed IPv6 addresses were only half masked.
- A parenthesised international phone number swallowed the closing bracket.
- A capitalised heading word was masked as a German ID card.
- `referential_integrity=True` / `referentialIntegrity: true` no longer returns a cached bracketed result from an earlier unlabelled call.
- Cloud detections landed on the wrong characters after an emoji, because service offsets are code points and JavaScript slices UTF-16 units. *(TypeScript only)*
- Both SDKs now share one evaluation definition, so a reported score means the same thing in each.

## [0.4.0] - 2026-08-31

### Added

- `euredact.configure(api_key=..., base_url=...)` / `configure({ apiKey, baseUrl })`, reading `EUREDACT_API_KEY` and `EUREDACT_BASE_URL` so a key never has to be written into source.
- `CloudClient` and an async client, retrying with full jitter, obeying `Retry-After`, and sending an `Idempotency-Key` per document.
- `TooLargeError` (413, permanent — the service refuses oversized input rather than chunking), plus quota and authentication errors.
- Nine cloud-only entity types matching the canon the service is trained against, including `ORGANISATION_NAME`, `JOB_TITLE` and `MEDICAL_CONDITION`.
- `redactAsync(text, options)` and `EuRedact#redactAsync`. *(TypeScript only)*
- `canonicalType(name)`, mirroring `EntityType._missing_` in Python. *(TypeScript only)*

### Changed

- `EntityType.NAME` is now a legacy alias of `EntityType.PERSON_NAME`.
- Options the cloud service cannot honour now raise rather than being ignored — multiple `countries`, `country_hint`, `context`/`chunk_offset`, `referential_integrity`. Silently dropping one would be under-redaction wearing a plausible face.

### Removed

- `euredact.cloud.hasher` and `euredact.cloud.shuffler`, both empty stubs. *(Python only)*

### Fixed

- `redact(mode="cloud")` silently returned rules-only output instead of reaching the service.

### Known issues

- One cross-SDK type disagreement, visible only at full-corpus scale.

### Notes

- The cloud tier needs a global `fetch`, so Node 18 or newer. *(TypeScript only)*

## [0.3.9] - 2026-08-11

### Added

- `make parity` compares detected types, not just masked characters — the only check that could see the two engines disagreeing on a type.
- Cue targets for `HEALTHCARE_PROVIDER`, `BANK_ACCOUNT`, `PASSPORT` and `SECRET`.
- 20 new shared conformance vectors (127 → 147).

### Changed

- Re-typing and rescuing are no longer the same set of types.
- `NATIONAL_ID` is retypable only at country score 0, so a label can overrule a checksum that passed by luck but never a domestic identifier.

### Fixed

- The cue table held an abbreviation and not the word it abbreviates.
- `Sozialversicherungsnummer:` was in the cue table the whole time and could not be reached, because the label was longer than the window.
- The two SDKs filed the same value under different types.
- A four-digit run became a `POSTAL_CODE` as soon as any real postal code established the country.
- A label ending in more than one mark now reaches its value.

## [0.3.8] - 2026-08-11

### Added

- `EntityType.INTERNAL_ID`.
- `Detection.confidence` is now meaningful: it records how the type was arrived at.

### Changed

- `suppress_phone_after_id_label` and its untyped label table are gone; those labels are typed cue entries that relabel rather than delete.
- Cue boundaries are written `(?<![A-Za-z0-9_])` rather than `\b`, because JavaScript's `\b` is ASCII-only and would never match a Greek or Cyrillic label.

### Fixed

- An explicit identifier label no longer loses to the phone pattern.
- A labelled identifier that fails its checksum is masked instead of dropped.
- `ΑΦΜ` reaches `TAX_ID` rather than being read as a national identity number.

## [0.3.7] - 2026-07-31

### Changed

- The BIC context window no longer walks the whole document per candidate.
- Redaction no longer rebuilds the whole document once per detection.
- The fragment check uses a binary search plus a running maximum instead of a linear walk.
- The cache key no longer copies the entire input into a formatted string before hashing it.
- Both publish jobs run in a `release` environment, so shipping to PyPI and npm waits on that environment's reviewers. *(Python only)*
- The npm upgrade inside the publish job is pinned to an exact version rather than floating. *(Python only)*

### Security

- Two patterns could be made to backtrack quadratically (ReDoS).
- A pattern registered during detection could silently drop PII.
- The custom-pattern ReDoS screen only recognised one spelling of the dangerous construct.
- Cache keys used a non-cryptographic hash. *(TypeScript only)*
- The result cache was bounded by entry count rather than by size, so a few large documents could exhaust memory.
- The referential-integrity mapping is documented as unevicted and shared.
- VIN validation is now an explicit shape-only decision rather than dead check-digit code.
- The maintainer's home directory is no longer hardcoded in committed files; the corpus path comes from `EUREDACT_CORPUS`.

## [0.3.6] - 2026-07-30

### Fixed

- Ticket and incident numbers were masked as postal codes.
- A currency amount ending a clause was masked as a postal code. *(Python only)*
- `desember` was missing from the month list, so Norwegian December dates were not recognised.
- Crypto tickers were masked as licence plates.
- API endpoints, hostnames and LDAP names were masked as secrets.
- `SECRET` no longer claims an email address.

## [0.3.5] - 2026-07-30

### Added

- 25 shared conformance vectors covering every fix in this release (68 → 93), run by both runtimes.
- `tests/metrics.py` gains `--engine python|typescript|both` and `--per-file`.

### Fixed

- Every Latvian phone number was suppressed.
- Spanish numbers grouped 3-2-2-2 matched no pattern at all.
- A generic secret claimed spans belonging to specific types.
- A four-digit year inside a date was masked as a postal code.
- Money amounts were read as Spanish licence plates.
- Timestamps, ordinary words and cloud region names were reported as secrets.
- A dotted quad was reported as a German tax number.
- Year ranges and decimal tails were reported as phone numbers.
- Belgian enterprise numbers were missed when introduced by the registry's own name.
- A label touching a value now outranks a checksum.
- A value filling an entire field of a delimited row now counts as context.

## [0.3.4] - 2026-07-30

### Added

- `tests/metrics.py`. *(Python only)*

### Changed

- Recovered the latency 0.3.3 gave away, without giving back its recall.

### Fixed

- Social handles containing a non-ASCII letter were masked only up to it.
- German social-security numbers were left unredacted whenever the document used the abbreviation `SVNR`.

## [0.3.3] - 2026-07-29

### Added

- `make check` and `make verify`. *(Python only)*

### Fixed

- A shorter validated match could re-cut a longer one and leak the remainder.
- `countries` could change which spans were **found**, not just how they were labelled.
- A bare string for `countries` silently discarded every detection.
- The generic phone pattern claimed fragments of rejected identifiers.
- Identifiers glued to a non-ASCII letter were missed. *(Python only)*
- `DocumentContext.evidence` was a method while `.size` was a getter. *(TypeScript only)*

### Known issues

- A checksum-invalid identifier occupying a span no other detector claims can still be reported under the wrong type.

## [0.3.2] - 2026-07-29

### Added

- Country inference, so a document with no declared country is still attributed.
- `DocumentContext`, carrying evidence across the chunks of one document.
- `RedactResult.inferred_countries` / `inferredCountries` — `(country, confidence)` pairs, strongest first.
- `RedactResult.evidence` — every signal behind the inference, with the span that produced it.
- `RedactResult.detection_mode` / `detectionMode` — `"declared"` or `"inferred"`.
- `Detection.country_confidence` / `countryConfidence` — how strongly the document supports the attributed country, in [0, 1].
- `Detection.out_of_scope` / `outOfScope` — attributed outside the declared `countries`.
- `country_hint` / `countryHint` on every entry point: a prior that resolves ambiguity **without** narrowing scope or flagging anything out of scope.
- RE2 scan prefilter, via `pip install euredact[fast]`. *(Python only)*

### Changed

- `countries=` no longer gates detection — it scores it. A value is found regardless and the declared countries decide attribution.
- Failed-checksum spans no longer delete overlapping detections.
- Suppression runs only on candidates that win their span.

### Fixed

- A failed checksum no longer demotes unrelated entity types on the same span.
- A passing checksum from an uncorroborated country no longer outranks everything.
- Deduplication no longer truncates an entity to honour the declared country. *(TypeScript only)*

### Security

- Installing the optional `fast` extra disabled private-key redaction.
- `tests/test_scan_path_parity.py` runs **both** scan paths in one process and compares them, so an optional extra can no longer change behaviour.

## [0.3.1] - 2026-07-27

### Added

- Shared conformance suite, run by both SDKs.

### Fixed

- German licence plates are validated against the district-code list.
- German `LICENSE_PLATE` matched standards codes and document references.

## [0.3.0] - 2026-07-27

### Added

- A bundled seed list of BIC6 institution+country prefixes for major European banks, compiled from publicly published bank data.
- `euredact.set_bic_registry()` / `setBicRegistry()` — install a BIC registry consulted ahead of the bundled prefixes.

### Changed

- **BREAKING** `IBAN` is renamed to the canonical `BANK_ACCOUNT`.
- `validate_bic()` / `validateBic()` requires a real ISO 3166-1 alpha-2 code at positions 5–6; `ISO_3166_ALPHA2` is exported.
- The IBAN length table is hoisted to `IBAN_LENGTHS` and drives the country-independent IBAN pattern, pinning each country's exact length.
- `POSTAL_CODE` resolves **last** in overlap deduplication, so it can only claim spans no structured detector wanted.
- Some spans are now relabelled rather than newly masked, because a checksum-validated detector reclaims them from a weaker one. *(Python only)*

### Fixed

- BIC no longer matches ordinary ALL-CAPS words.
- Bare four-digit postal codes no longer shred longer identifiers.
- International phone numbers were missed in 11 countries.
- IBANs were gated by `countries`.
- `countries=["GB"]` raised `ValueError` in Python and silently degraded to shared patterns only in TypeScript.
- Austrian national numbers with a short area code were missed.
- Space-separated bank codes were missed.
- Country-prefixed postal codes were read as subtraction.
- Place names beginning `St.` suppressed the postal code before them. *(Python only)*
- Residence phrasing now counts as postal context. *(Python only)*
- `EMAIL` and `SOCIAL_HANDLE` missed non-ASCII local parts. *(TypeScript only)*

## [0.2.0]

### Added

- Initial TypeScript SDK, bringing the engine to npm. *(TypeScript only)*

## 0.1.0 - 2026-03-30

### Added

- First release. *(Python only)* 31 countries, 20+ PII entity types, checksum validation, two-pass detection, context-aware detection, batch processing, true async, referential integrity, Aho-Corasick acceleration, and zero required dependencies.

[Unreleased]: https://git.euredact.dev/euredact/rules-engine/compare/v0.6.0...main
[0.6.0]: https://git.euredact.dev/euredact/rules-engine/compare/v0.5.1...v0.6.0
[0.5.1]: https://git.euredact.dev/euredact/rules-engine/compare/v0.5.0...v0.5.1
[0.5.0]: https://git.euredact.dev/euredact/rules-engine/compare/v0.4.0...v0.5.0
[0.4.0]: https://git.euredact.dev/euredact/rules-engine/compare/v0.3.9...v0.4.0
[0.3.9]: https://git.euredact.dev/euredact/rules-engine/compare/v0.3.8...v0.3.9
[0.3.8]: https://git.euredact.dev/euredact/rules-engine/compare/v0.3.7...v0.3.8
[0.3.7]: https://git.euredact.dev/euredact/rules-engine/compare/v0.3.6...v0.3.7
[0.3.6]: https://git.euredact.dev/euredact/rules-engine/compare/v0.3.5...v0.3.6
[0.3.5]: https://git.euredact.dev/euredact/rules-engine/compare/v0.3.4...v0.3.5
[0.3.4]: https://git.euredact.dev/euredact/rules-engine/compare/v0.3.3...v0.3.4
[0.3.3]: https://git.euredact.dev/euredact/rules-engine/compare/v0.3.2...v0.3.3
[0.3.2]: https://git.euredact.dev/euredact/rules-engine/compare/v0.3.1...v0.3.2
[0.3.1]: https://git.euredact.dev/euredact/rules-engine/compare/v0.3.0...v0.3.1
[0.3.0]: https://git.euredact.dev/euredact/rules-engine/compare/v0.2.0...v0.3.0
[0.2.0]: https://git.euredact.dev/euredact/rules-engine/src/tag/v0.2.0
