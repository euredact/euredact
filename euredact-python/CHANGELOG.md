# Changelog

Changes to this SDK, with the reasoning behind them: the measurement that
motivated a fix, what a wider pattern cost in false positives, the alternative
that was rejected.

For a scannable, strictly categorised view of **both** SDKs in one place, see
the [root CHANGELOG.md](../CHANGELOG.md). It follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); this file is where the
narrative lives. Sections here use that vocabulary
(`Added` / `Changed` / `Deprecated` / `Removed` / `Fixed` / `Security`) for
0.6.0 onward; earlier releases keep the headings they were written with.

## Unreleased

### Added

- **Everything an API key can do, through the SDK.** *(rules-engine#89)*
  - `RedactResult.cloud` (`CloudInfo`) on cloud results: the service's
    `job_id`, `model_version`, `usage` and `unlocated` (what the model found
    but could not place, so nothing was masked for it). `None` on rules-only
    results. `usage` is what the request cost and why (euredact-inference#53):
    `tokens`, `billing_rate`, `credits` and `factors` (`UsageFactor`), a total
    and its reasons, never a cost per step. Batch documents carry
    `model_version` and `unlocated`.
  - `redact(..., mode="cloud", idempotency_key=...)` (and `aredact`): the
    request's `Idempotency-Key`, so a caller retrying after its own timeout
    gets the same job instead of a second, billed one.
  - `euredact.cloud.Account`: `summary()`, `credits()`, `credit_history()`,
    `usage()`, `usage_by_key()`, `keys()` and `revoke_key()`.
  - `euredact.cloud.Jobs.retrieve(job_id)`: a past job's state and result.
  - `Batches.list()`, and `Batch.documents`, `tokens`, `credits_charged` and
    `billing_rate`.
  - Errors `NotFoundError` (404), `ResultExpiredError` (410: the result is no
    longer retained, rather than an empty-looking document) and
    `RateLimitedError`.
  - Every typed value keeps the service's JSON in `raw`. A field of the wrong
    type reads as absent rather than failing the call; the parsing is shared
    with TypeScript through `conformance/cloud_result.json` and
    `conformance/cloud_usage.json`.
- **Batches.** `euredact.cloud.Batches`
  creates, tracks and resolves cloud batches while keeping the structured PII
  local: `create()` masks each document here and uploads only the masked
  text, writing a private local batch file (`~/.euredact/batches/<id>.json`,
  `0600`) with the originals, the local detections and a SHA-256 of what was
  sent; `results()` maps the service's spans back from that file once the
  batch has ended, after checking the hash, then wipes the originals and
  leaves a text-free receipt, so a batch is mapped once. `pending()`,
  `retrieve()`, `cancel()`, `purge()` and an expiry sweep round it out;
  `batch_dir=`, `store=` and `cipher=` choose where and how the file is kept.
  The file format is shared with the TypeScript SDK, so either can resolve
  the other's batch. The gateway endpoint (euredact-inference#40) is not
  deployed yet. Every document is validated before any is masked, and
  `custom_id`s are held to the gateway's rule (1-64 characters of
  `A-Z a-z 0-9 _ . : -`, `CUSTOM_ID`), with its wording, so a bad id fails
  at once instead of after masking and then at upload. Shared conformance vectors in
  `conformance/batches.json`. *(rules-engine#84, #88)*

- **About 10,400 BIC6 prefixes for the 31 supported countries**, from the GLEIF
  BIC-to-LEI mapping (September 2026), which SWIFT develops and licenses for
  redistribution; its required notice ships in `NOTICE` and in the generated
  module. `scripts/refresh_bic_registry.py` regenerates the list from the
  monthly file. The mapping decides whether a letters-only code beside an IBAN
  is a bank or a word; it does not license a code in bare prose, because some
  ordinary words begin with a real prefix (`DERNIERS` → `DERN`+`IE`). That stays
  the hand-kept seed's job. Adds about 54 kB to each package's source.
  *(rules-engine#57)*

- **Polish identity card, REGON and driving-licence numbers.** None had a
  pattern, so behind their own labels they were left in the clear, and beside a
  passport mention the passport rule took them: `dowód osobisty ABA212345` and
  `REGON: 123456785` came out as `[PASSPORT]`.
  - Identity card (dowód osobisty): 3 letters + 6 digits with its check digit
    (weights 7,3,1,9,7,3,1,7,3; letters A=10…Z=35) → `NATIONAL_ID`.
    *(rules-engine#75)*
  - REGON: 9 digits, or 14 for a local unit, each with its mod-11 check digit
    → `CHAMBER_OF_COMMERCE`. *(rules-engine#76)*
  - Driving licence: the field-5 number (`01234/12/1234`, slash-separated digit
    groups whose widths vary with the year of issue) and the document number
    (two letters and six or seven digits) → `DRIVERS_LICENSE`. No check digit
    exists, so both are label-only. *(rules-engine#77)*

  All three need their label nearby (`dowód osobisty`, `dowodu osobistego`,
  `REGON`, `prawo jazdy`, `prawa jazdy`, …), and the labels join the cue table,
  so each wins its span over the passport rule. Thirteen conformance vectors.

### Changed

- **A daily-quota `429` is no longer retried.** The gateway's quota answer
  (JSON with `detail.used` and `detail.limit`) will not clear before the day
  does, so retrying it only delayed `QuotaExceededError` through every
  backoff; it now raises at once. The edge's rate-limit `429` (HTML from
  nginx) is still retried with backoff, and when it persists raises
  `RateLimitedError`, a subclass of `QuotaExceededError`, so existing
  handlers keep working. *(rules-engine#89)*
- **About a quarter faster on long documents.** The label lookup that ranks
  candidates ran up to 17 anchored regexes per candidate, and most candidates
  share their start with others (every country's pattern for the same digits)
  and have no label at all: over the pipeline documents, 38,400 lookups covered
  8,500 offsets, 543 of them labelled. The lookup is now read once per offset,
  and a single union of all labels answers "none here" before the table is
  walked. Over 2,000 pipeline documents (three alternating runs, `google-re2`)
  the run takes 13.5 s against 18.3 s on the previous `main` and 16.9 s on
  0.6.0. Output is identical on the 152,468-document corpus and the 8,810
  pipeline documents. The per-date label check named in the issue was 3% of
  the time and is unchanged. The TypeScript lookup showed no measurable gain
  from the same change and was left as it was. *(rules-engine#79)*

- **A pattern RE2 rejects only for a lookaround keeps the RE2 prefilter**, via
  the same pattern with its lookarounds stripped. Removing a lookaround only
  drops a constraint, so the stripped form matches a superset: it can let a
  pattern run needlessly, never skip a window where the exact pattern matches.
  Patterns outside the prefilter fall from 35 to 23, including the three phone
  patterns the #51/#60 guards had pushed out. Measured over 2,000 pipeline
  documents with `[fast]`, this recovers about 0.25 s of the ~1.0 s the last
  batch added; most of the remainder is the per-date label check from #52, not
  the prefilter. *(Python only; the TypeScript SDK has no RE2 path.)*
  *(rules-engine#72)*

- **A label touching a value now rescues a failed checksum on a label-gated
  pattern too**, as it already did on the others. `Numer dowodu osobistego
  ABA912345` has a bad check digit and is still an identity card; before, a
  pattern that needs its label in the window was dropped on any checksum
  failure, however close the label sat. The rescue needs the cue to touch the
  value, which is stronger evidence than the keyword anywhere in the window
  that gates the pattern. *(rules-engine#75)*

### Fixed

- **A Polish military booklet number with a two-letter series was split or
  missed.** The pattern added for #102 took a three-letter series only; the
  usual series has two letters. `EL 0473218` was `EL [PHONE]`, and
  `EL0473218` or `seria MS nr 6620419` were not masked. Two or three letters,
  with or without a space or "nr", are now one `INTERNAL_ID`. *(rules-engine#102)*
- **A Polish case reference was masked as a MAC address.** The last three
  groups of `WSO-II.6151.4471.2025` (znak sprawy) fit the dotted MAC shape,
  so they were `[MAC_ADDRESS]` and `WSO-II.` stayed readable. Behind its label
  ("znak sprawy", "decyzja", "sygnatura", …) the whole reference is one
  `INTERNAL_ID`, and a dotted MAC glued to more of a reference by a connector
  is no longer a MAC. Real dotted MACs, including all-digit ones, still are.
  *(rules-engine#105)*
- **A card number was carved out of a longer run of digit groups.** Sixteen
  Luhn-valid digits inside a Polish account number that fails its own
  checksum were masked as `CREDIT_CARD`, leaving the outer groups readable. A
  card candidate with a four-digit group joined by its own separator on either
  side is dropped. The account number itself stays unmasked when its check
  digits fail, as for an IBAN (#93). *(rules-engine#106)*
- **Polish event dates were masked as `NATIONAL_ID`, and a call-up date as
  `DOB`.** The Spanish `DNI` label, allowed to run on into a longer word,
  matched the Polish "dnia"/"dniu" ("on the day") and rescued a failed dotted
  BSN match on the date after it: `z dnia 12.08.2026` → `[NATIONAL_ID]`. It now
  counts only as `DNI` or `DNIe`. Separately, birth-date keywords matched
  inside any word, so "DOB" matched "**dob**rowolnej" and
  `Data powołania do dobrowolnej … służby wojskowej: 03.03.2026` became a date
  of birth; an all-capitals keyword now counts only as a word of its own (a
  plural "DOBs" still does). *(rules-engine#100)*
- **A date-time stamp was cut and masked as `PHONE`.** The French phone
  pattern read `07.10.2026 08` as five pairs, leaving `[PHONE]:42`. A phone
  candidate that is a full date and an hour, with the minutes after it, is
  dropped. *(rules-engine#101)*
- **A Polish military booklet number was half-masked as `PHONE`.** Behind
  "książeczka wojskowa" (any case), the series and seven digits
  (`MON 0451287`) are one `INTERNAL_ID`. *(rules-engine#102)*
- **A Polish visa sticker or residence card number was not masked.** Behind
  "naklejka wizowa" or "karta pobytu" (also "karta pobytu CUKR"), two letters
  and seven digits are `RESIDENCE_PERMIT`. *(rules-engine#103)*
- **A Polish domestic account number (NRB) was not detected.** The NRB is
  the PL IBAN without its country code, and the form Polish invoices and bank
  letters print; 0 of 160 generated NRBs were masked whole, and in the spaced
  form the last eight digits came out as `[PHONE]`, leaving 18 digits readable.
  A PL pattern for the 26 digits (spaced `2+4x6` or compact) validated by the
  IBAN's own mod-97 now types it `BANK_ACCOUNT`, with or without a country.
  An NRB whose check digits fail is not masked, as for an IBAN. *(rules-engine#93)*
- **A Polish NIP in the personal grouping was not detected.** The PL pattern
  accepted only the company grouping `XXX-XXX-XX-XX`; `XXX-XX-XX-XXX`, used
  for natural persons, is now `TAX_ID` too, with the same check. *(rules-engine#94)*
- **A Swiss AVS/AHV number with a bad check digit was left in the clear behind
  its own label.** `Numéro AVS 756.2209.8834.13` produced no detection: the
  EAN-13 check failed, and no cue named `AVS` or `AHV`, so the label could not
  rescue it. `AHV`, `AHV-Nr.`, `AHV-Nummer` and `AVS` are now `NATIONAL_ID`
  cues, and the dotted form `756.XXXX.XXXX.XX` is accepted without its check
  digit when `AVS` or `AHV` appears nearby, which covers `AVS (756.…)`,
  ``AHV-Nummer `756.…` `` and `AVS de l'assurée : 756.…`. The same number
  with no such word is still declined. *(rules-engine#82)*
- **A Polish KRS number was masked as `PHONE`.** `KRS: 0000123456` had no
  Polish pattern and no cue, so a phone pattern took the ten digits. A KRS
  pattern (ten digits beginning `00`, behind `KRS`) and a `KRS` cue now type it
  `CHAMBER_OF_COMMERCE`, like REGON. *(rules-engine#90)*
- **A value at the end of a line was left unmasked when the next line began
  with a bullet or a Markdown rule.** The math-context check looked for an
  operator after the value with `\s*`, which crosses the line break, so
  `"- BSN: 111222333\n- Adres"` and `"Telefoon: 06 12345678\n- Notitie"`
  were read as subtractions and printed in full. The check now stays on the
  value's own line. Over the 8,810 rebuilt pipeline documents, 1,134 more
  values are masked (663 phones, 268 postal codes, 130 national IDs, 45 social
  security numbers) and none are unmasked; the 152,300-document generation
  corpus is unchanged. *(rules-engine#91)*
- **A licence plate was matched inside a reference joined by `/`, `.`, `_` or
  `+`, or after a reference marker.** #50 stopped plates inside hyphen-joined
  references; the same fragment still fired with any other connector:
  `#FR-S2-2026-009182` on 0.6.0, and on `main` `Ref #FR-S2`, `FR-S2/2026`,
  `FR-S2.2026`, each `[LICENSE_PLATE]` through the German pattern (`FR` is the
  Freiburg district code). A plate must now be a token of its own: a connector
  (`- / . _ +`) joining it to a letter or digit on either side rules it out, and
  so does a reference marker (`#`, `№`, `n°`) directly before it, unless a
  plate cue is nearby (`Plaque d'immatriculation n° AB-123-CD` stays a plate).
  Spaced separators, sentence punctuation, brackets and quotes still bound a
  plate. On 7,571 pipeline documents this removed 133 false plates — `AVS 756`
  cut out of Swiss AVS numbers, `Peugeot 308 SW 1.6`, `EUR 2.640,00 EUR 1`,
  `BV-ZK-07/2021`, `CK 245 U/l` — and added none; corpus plate recall is
  unchanged. Twelve conformance vectors. *(rules-engine#81)*

- **A Luxembourg matricule in any grouping but two was half-masked, and its
  birth date stayed readable.** The pattern accepted the number compact
  (`1971031412345`) or fully spaced (`1971 03 14 123 45`) and nothing between,
  so `19710314 12345` was left entirely in the clear on 0.6.0 (0.5.1 masked the
  tail as `POSTAL_CODE`) and `1971 0314 123 45` lost only `0314 123 45`, as
  `PHONE`. The first eight digits are the date of birth. One space is now
  optional at each boundary of `YYYY MM DD XXX XX`; a line break never joins
  groups.

  The cost: a 13-digit run whose first eight digits are a valid date, spaced
  `8 + 5`, now reads as a matricule — `Bestellung 20231105 99812` is
  `[NATIONAL_ID]` where it was `[PHONE] 99812`. It was over-masked before as
  well; it is now masked whole under a different type. Seven conformance
  vectors, all groupings plus the line-break case. *(rules-engine#49)*

- **German phone numbers with trailing two-digit groups were cut short, and
  `0170 / 123 45 85 21` was not detected at all.** Both German phone patterns
  allowed one separator and one subscriber block, so `+49 170 1234567 85 21`
  left `85 21` readable and `0151-2345 85 21` left `21`; a slash with spaces
  round it (`0170 / …`, `030 / 1234567`) matched nothing. The prefix may now be
  set off by ` / `, and up to three two-digit groups may follow the subscriber
  block. A pair followed by `.`, `,`, `/` or `:` and a digit is not taken, so the
  day of a following date stays out of the span, and one followed by `-` and a
  digit (an extension, `059133 60-3333`) is left to the shorter match. The
  units guard now reads only the number's own line: with the longer span,
  `+49 172 634 85 21` followed by an e-mail address starting `m.` on the next
  line read as "21 m" and the whole number was dropped. Eight conformance
  vectors. *(rules-engine#51)*

- **A postal code with a two-letter country prefix was not masked.**
  `Hauptstrasse 5, CH-8004 Zürich`, `DE-10115 Berlin`, `NL-1012 LG Amsterdam`
  and the AT, BE and LU forms came out unchanged, with or without `countries`;
  `D-10115` and `L-1611` were masked only because the prefix had one letter.
  `suppress_reference` reads 2-5 capitals and a hyphen before a number as a
  document tag (`IR-43433`, `INC-2024`), and `CH-` has that shape. A two-letter
  tag is now an address when it is a supported country code, it opens an
  address line (after a comma or at a line start) and a capitalised place name
  follows the code. `IR-43433`, `Ticket: IT-20431 Drucker` and the #31
  references (`PV-2026-LU-09143`) stay unmasked.

  Switzerland needed one more step: its postal pattern is context-gated and
  its address-structure fallback required the code straight after the comma.
  The fallback now also accepts `, CH-` and a `CH-` line start. Adding the Swiss
  spelling `Strasse` to the context keywords was tried and rejected: it masked
  `Zimmer 2041`, `4500 Franken` and a year in the same sentence as a street.
  Eleven conformance vectors, three of them references that must stay
  unmasked. *(rules-engine#58)*

- **A UK National Insurance number is `SSN`, not `NATIONAL_ID`.** The NINO
  pattern returned `NATIONAL_ID`; the project canon types a NINO as a
  social-security number by default, and as `TAX_ID` only on a purely fiscal
  form, which a pattern cannot see. Callers see `[SSN]` where they saw
  `[NATIONAL_ID]`; what is masked does not change. Three conformance vectors.
  *(rules-engine#47)*

- **A licence plate was cut out of a longer reference.** `Référence dossier :
  TF-284-KL-00874` became `[LICENSE_PLATE]-00874`, and `LU-TS-2023-004512`
  became `[LICENSE_PLATE]-004512`: the plate patterns matched a plate-shaped run
  that a hyphen joined to more letters or digits, so the reference was masked
  under the wrong type and its tail stayed readable. A plate candidate glued by
  a hyphen to a letter or digit on either side is now part of a longer token
  and is not a plate; a spaced dash (`AB-123-CD - stationné`) does not join.
  Plates in NL, BE, DE, FR and IT forms are unaffected. Five conformance
  vectors. *(rules-engine#50)*

- **A residence-permit number was masked as a national ID, a passport or a
  phone number, never as `RESIDENCE_PERMIT`.** The engine has no permit
  patterns, since permit numbers have no shape of their own, so whichever
  pattern fitted the value named it: 129 of 344 planted permit numbers across
  BE, LU, DE, AT and NL came back under a wrong type. A permit label touching
  the value (`Aufenthaltstitel Nr.:`, `Verblijfsvergunning nr.:`, `Titre de
  séjour n°`, `residence permit`, `karta pobytu`, …) now types it
  `RESIDENCE_PERMIT`. It overrules a `PHONE` as any label does, and also a
  `NATIONAL_ID` or `PASSPORT` the country supports, because a German eAT number
  fits the identity-card pattern and a Dutch permit the passport one, and the
  label is the better evidence. A Spanish NIE stays `NATIONAL_ID`, as the canon
  requires. The Belgian card category before the number (`B 565992336`) is
  allowed between label and value and is not masked: it is a status, not part
  of the number. A permit number nothing detects is still not detected; that
  is the LLM tier's. Eight conformance vectors. *(rules-engine#53)*

- **Every date in a document took its type from one date label.** With
  `detect_dates=True`, `DOB` and `DATE_OF_DEATH` are one date shape gated by
  their keywords, and the gate passed when a keyword appeared anywhere in the
  150-character window. So `Date of Admission: 12/02/2024` became
  `DATE_OF_DEATH` because `Date of Death:` sat two lines down; with a birth date
  present, the death date became `DOB`; and `Factuurdatum 12/03/1984.
  Geboortedatum: …` masked the invoice date as `DOB`. A keyword now licenses a
  date only when it is that date's own label: before it with no other date in
  between, or after it in the same sentence without running straight into a
  date of its own (`Verstorben am 01.02.2020, geboren am 12.03.1940`). In a
  table the column header decides, so `Name | Aufnahme | Sterbedatum` leaves the
  admission column alone and `Name;Geburtsdatum;Sterbedatum` types both columns.
  A date with neither label is no longer masked as either. Measured over the
  152,300-record corpus, DOB recall stays at 100% and DOB false positives fall
  from 267 to 5. A run over 7,571 longer pipeline documents shaped the rest:
  a label asked as a question labels the answer below it (call transcripts),
  a label labels each date of a list after it, `°` directly before a date is
  the birth sign (not `n°`), and `datum van overlijden`, `décédée le` and
  `Sterbetag` join the death labels. Twenty-four conformance vectors.
  *(rules-engine#52)*

- **An insurance claim number was masked as a Cypriot phone number.**
  `Schadeclaim 2026-0412` became `[PHONE]` (country CY), even under
  `countries=["NL"]`: eight digits starting with 2 is a Cypriot landline, and no
  label claimed the value. Claim-number labels (`Schadeclaim`, `Schadenummer`,
  `Schadensnummer`, `numéro de sinistre`, `numero di sinistro`, `número de
  siniestro`, `skadenummer`, `claim number`, …) now join the `INTERNAL_ID` cue,
  so the reference is typed `INTERNAL_ID`, as `Dossiernummer` already was. Seven
  conformance vectors. *(rules-engine#54)*

- **Surnames and ALL-CAPS words near an IBAN were masked as `[BIC]`.** A BIC
  missing from the registry was emitted on banking context alone, and that
  admitted any word whose letters 5-6 are a country code: `Dr. Joëlle
  NGUYEN-[BIC]` two lines under an IBAN (which also breaks the name apart for
  the model), `BETALING`, `VIREMENT`, `DOCUMENT`, `JANSSENS`. Hyphen-joined
  tokens and tokens right after a personal title are refused outright; any other
  **letters-only** code (eight letters, or eleven without the `XXX` branch) that
  misses the registry now needs a `BIC`/`SWIFT` label touching it, unless the
  bundled GLEIF mapping knows the institution. Measured on 7,571 pipeline
  documents: 38 false `[BIC]` removed, every real bank code kept, nothing else
  changed. A code with a digit or an `XXX` branch is no word and keeps the
  context gate. Five pinned tier-2 inputs were letters-only invented codes; they
  now pin the label requirement, and the context gate keeps its coverage with
  digit-bearing codes. *(rules-engine#57)*

- **A phone number followed by a date took the date's day.** `Mob: 0170
  1234567 12.03.2024` became `[PHONE].03.2024`: the Austrian grouped phone
  pattern accepted `12` as its last group because `\b` sits between `12` and
  `.`. The last group may no longer be followed by `.`, `,`, `/` or `:` and a
  digit. Four conformance vectors. *(rules-engine#60)*

- **Token suffixes contained vowels despite the documented "no vowels".**
  `TOKEN_ALPHABET` held `A`, `E`, `U` and `Y`, so a suffix could spell a word —
  a real call produced `POSTAL_CODE_KENE`. The alphabet is now
  `BCDFGHJKLMNPQRSTVWXZ23456789`: 28 characters, about 615,000 four-character
  suffixes. Tokens minted by earlier versions are still recognised as the
  engine's own markers on a second pass, and `restore()` reads the mapping,
  not the alphabet, so existing mappings keep working. A test holds the
  alphabet to its contract. *(rules-engine#55)*

### Security

- **The cloud base URL must use TLS.** `configure(base_url=...)`,
  `EUREDACT_BASE_URL` and a hand-built config accepted any scheme, so a typo or
  a test value left in production sent the API key and the document text over
  plain `http://`. A non-`https` URL now raises at configuration, except
  `http://` to `localhost`, `127.0.0.1` or `::1` for a local gateway or a
  TLS-terminating proxy on the same machine. The default was and is
  `https://api.euredact.dev`, with certificate verification on.
  *(rules-engine#86)*

## 0.6.0 (2026-10-05)

### Added

- **Documentation: what `countries` actually controls.** It decides how a
  detection is attributed and scored, not what is found — every country's
  patterns run on every document, so a Belgian identifier in a document declared
  `countries=["NL"]` is still masked and merely flagged `out_of_scope`. The new
  section shows the output of all four call shapes side by side, because the
  masked text is byte-identical in each and only the metadata moves. Misreading
  this parameter as a filter is the most likely route to under-redaction.
- **Documentation: batch processing and concurrency.** `redact_batch`,
  `aredact_batch(max_concurrency=...)` and `redact_iter` in one place, with what
  each costs in memory, why reusing an instance matters for the cache, and the
  fact that tokens do not span a batch.
- **Documentation: what leaves your machine in cloud mode.** Written first to
  say that the whole document was sent, because the opposite was believed; then
  rewritten in the same cycle when cloud mode became local-first (below). It now
  shows the text as passed, as sent and as returned, and names what still
  travels: names and diagnoses, the rules' misses, and the prose. The
  `tokenize` → model → `restore` composition is documented beside it as the same
  pattern with a model of your own. *(rules-engine#28)*
- **A root [`CHANGELOG.md`](../CHANGELOG.md)** covering both SDKs in strict
  [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) form, and
  `tests/test_changelog.py` to keep it that way: sixteen distinct section names
  had accumulated across the two package changelogs because nothing enforced a
  vocabulary.
- **A test for every rules-engine change, not most of them.** An audit of this
  cycle's changes against the suite found three gaps, all of the same shape:
  a change applied across many countries and pinned in only a few.

  - `#30` gave **22** VAT patterns the separator that invoices print, and three
    were pinned. There is now one vector per changed pattern.
  - `#38`'s birth-date keywords are shared across all 31 countries, but
    `tests/test_dob_context.py` is Python-only, so the **TypeScript** SDK had no
    DOB coverage for 14 of them. Each now has a vector, which both SDKs run.
  - `#23` added 27 passport vectors for the shared label-gated rule and four
    boundary cases, but left the Belgian and French **national** patterns
    unpinned. Both now have vectors.

  43 vectors in total, plus two more for the account-run guard, which had one.

- **`TestNoDateBearingValidatorAcceptsAnImpossibleDate`**, a property over the
  whole validator table rather than one validator at a time. `#37` was a
  checksum accepted as evidence that a date was real; running the same check
  across every validator found it in three more — `polish_pesel`,
  `romanian_cnp` and `slovenian_emso` — which are `xfail`ed against
  `rules-engine#43` so the gap is visible rather than hidden.

  `test_every_validator_is_classified` is the durable half: every name in
  `VALIDATORS` must appear in `DATE_BEARING` or `NO_DATE`, so a new validator
  cannot arrive untested. The lists are explicit because the name heuristic I
  first used was wrong in both directions — it matched `german_tax_id`, which
  has no date, and missed `polish_pesel`, which does. That blind spot is how
  PESEL escaped the first pass. *(rules-engine#44)*

### Changed

- **Cloud mode is local-first: the rules run on the caller's machine and only
  the masked text is sent.** *(Breaking for the cloud tier, which is in private
  alpha.)* `redact(mode="cloud")` used to hand off to the cloud path before any
  local work, so the request body was the document as passed in — a wire capture
  on 0.5.1 shows `... to Nick Bols on NL91 ABNA 0417 1643 00` in `text`. It now
  runs the local pipeline first and sends `... to Nick Bols on [BANK_ACCOUNT]`:
  one `text` field, with no types, offsets or values beside it. The service
  answers with spans relative to that masked text; `_onto_original` carries them
  back across the labels, and the result is assembled here from the local
  detections plus the service's.

  Decisions that are not obvious from the diff:

  - *The wire is always `[TYPE]`.* That is the placeholder syntax the model is
    trained on, where it means "already handled". `tokenize` therefore does not
    change what is sent; tokens are minted locally, after the response.
  - *An allowlisted value is still masked in the request.* An exemption says
    what the caller wants back, not what may leave. It is restored in the
    result, and reported in `exempted`, as before.
  - *Dates are always on in the local pass*, whatever `detect_dates` says. The
    service ran its rules with dates on for the same reason: it is what the
    model was trained against. It can only cause more to be masked.
  - *A span that touches a label snaps outward.* An offset inside `[POSTAL_CODE]`
    has no counterpart in the original, so an address the model reports around
    one covers the whole postal code. A span wholly inside a label is dropped;
    the local detection behind it stands.
  - *A span that does not match the sent text raises `CloudError`*, now on every
    cloud call. This check used to run only under `tokenize` or an allowlist,
    because only then did the SDK place spans itself. It always does now.

  Side effects: custom patterns apply in cloud mode (they never reached the
  service), and a cloud result carries the local pass's country attribution,
  `inferred_countries` and `evidence`.

  This is minimisation, not an exemption. Names and diagnoses still travel, as
  does anything the rules miss. It also needs the matching service: one that
  reports spans relative to the text it received (euredact-inference#14).
  *(rules-engine#28)*

### Removed

- **`rules_only` on `CloudClient.redact()` / `AsyncCloudClient.redact()`**, and
  the field in the request body. `redact()` never exposed it, and from a
  local-first client it means nothing: the rules have already run. The service
  defaults it to false. *(rules-engine#28)*

### Fixed

- **Postal codes were unmasked in five countries, for two different reasons.**
  `POSTAL_CODE` recall was 98.07% overall but 63.15% for France — 1,035 unmasked
  codes across FR, IS, NO, SE and, latent, DK and FI.

  **A missing inflection.** The French keyword list held the participle
  `domicilié` but not the noun `domicile`, and neither contains the other, so
  `Domicile : Lille, 77249.` matched nothing while `adresse :` worked in the
  same sentence. Belgium had the same gap, where French is an official language.
  Same class as `#38`.

  **A label suppressing its own value.** `suppress_postal_in_longer_identifier`
  drops a digit run introduced by a record-number label, and its cue is *any*
  word ending in `Nummer`, `Nr`, `Numero` or `Numéro` — the wildcard is
  `[\w\-]*`. So it matched `postnummer`, `postnr` and `postinumero`, the
  canonical postal labels of Norway, Denmark and Finland. Those countries write
  a bare four- or five-digit code, which passes the `isdigit()` guard, so
  `postnummer: 5020 Bergen` produced **nothing at all**. Sweden escaped only
  because it spaces its code, and Germany and Iceland because `Postleitzahl` and
  `póstnúmer` do not end in any of those four words. A cue beginning `post` is
  now treated as a postal label rather than a record-number label.

  Iceland, Norway and Sweden also lacked the generic `Postal:` label that twenty
  other countries carry. Sweden keeps three copies of its keyword list, one per
  postal pattern, so it had to be added to all three — that duplication is worth
  removing separately.

  **`POSTAL_CODE` recall 98.07% → 99.99%** (52,872 → 53,907 of 53,914). Ten
  vectors, including two that pin the suppressor still firing for a genuine
  record-number label, since that is the case it exists for. *(rules-engine#41)*

- **A space inside a VAT number made it a phone number.** `ATU 36438508` was
  typed `PHONE` with the `ATU` prefix left in the clear, while the unspaced
  `ATU36438508` was already correct. Attributing the span explained why: the
  digits were claimed by the **Danish** eight-digit phone pattern -- the most
  permissive shape in the engine -- in a call that declared `countries=["AT"]`,
  with `country_confidence` 0.0 and `out_of_scope` true. Every Austrian phone
  pattern requires a leading `0` or `+43`, so nothing Austrian matched; and
  because `\bATU\d{8}\b` had no separator tolerance there was no VAT candidate
  for it to lose to.

  Separator tolerance after the country prefix is now consistent across all 22
  VAT patterns that lacked it -- `BE`, `DK`, `DE`, `FR`, `LU`, `NO` and `CH`
  already had it -- and the UK's nine digits accept their official 3-4-2
  grouping. A related case is fixed by `suppress_phone_inside_account_run`: in
  `FR76 3000 4008 0300 0109 5374`, which fails its IBAN checksum, the phone
  pattern took two digit groups out of the middle and left the rest visible.
  0.3.3 fixed that shape of defect for the cases reachable then; a spaced
  account run was not one of them. *(rules-engine#30)*

- **The tail of a hyphenated reference was masked as a postal code.**
  `PV-2026-LU-09143` became `PV-2026-LU-[POSTAL_CODE]` -- an address claimed
  where there was none, with the rest of a police file number left in the
  clear. The Luxembourg and Swiss postal patterns were not at fault; the value
  was claimed by the German five-digit pattern, and the guard that should have
  stopped it has an escape hatch for country-prefixed codes (`A-1010 Wien`,
  `L-1234`) that accepted **any** one or two capitals before a hyphen. In
  `PV-2026-LU-09143` the `LU` is itself preceded by a hyphen, so it is a
  segment rather than a prefix; the boundary now excludes a hyphen, which is
  what distinguishes the two. *(rules-engine#31)*

- **One address in a document made every later four-digit year a postal code.**
  Law citations (`dem Börsegesetz 2018`), CV date ranges (`2000 -- 2008`) and
  ordinary prose (`seit Herbst 2024`) were masked as addresses, which makes the
  document unreadable and the redaction report wrong.

  `suppress_year_as_postal` already suppresses years, unless address context
  appears nearby -- and "nearby" was `_CONTEXT_CHARS`, 150 characters either
  side. Its own docstring recorded the consequence: "'Adresse', 'rue' and
  'Str.' appear in the header of essentially every business letter."

  Narrowing the window is not enough, and measuring said so. In

      Déclaration de revenus 2022. Laurent Leroy. Numéro fiscal :
      1167724166806. Adresse : rue du Commerce 130, 89654 Angers.

  the year and a real address share one line, so no paragraph separates them
  and "Adresse" sits 60 characters away. 47 of the 81 `POSTAL_CODE` false
  positives on the 152,300-record corpus were bare years of this shape.

  So a year-shaped value is now kept only when it sits in address *structure*,
  which is local to it rather than somewhere in a window: after the comma of an
  address line (`Amsterdam, 2026`), behind a postal label with nothing but
  punctuation between (`PLZ: 2011`), before a capitalised place name
  (`wonende te 2000 Antwerpen`), or with an address word in its **own
  sentence** -- which is what keeps `Te huur: Lange Nieuwstraat 12, rustige
  ligging in 2018` (2018 is Antwerp) while dropping the cases above, where the
  address is in a later sentence and carries its own code. All 47 are resolved
  and the general `_CONTEXT_CHARS` window is untouched for every other
  suppressor, so the blast radius is this rescue only. *(rules-engine#32)*

- **The engine's own placeholders are no longer detected.** `[POSTAL_CODE]` is
  thirteen characters of mixed case with an underscore, so the entropy-based
  `SECRET` rule read it as a credential: a second pass turned it into
  `[SECRET]`, corrupting the first pass's output and reporting a credential
  that never existed. Reported as irreducible over a 68-line document; it is
  one line -- `credentials: [POSTAL_CODE] rotated.` -- and what looked
  cumulative was the ±150-character keyword window cutting differently from the
  ±20-*line* windows that had been tried.

  All three emitted forms are guarded, since all three come back as input in a
  re-processing pipeline: `[TYPE]`, `TYPE_1` (`referential_integrity`) and
  `TYPE_K7Q2` (`tokenize`, where a false detection breaks `restore()`). Only
  real entity-type names count: guarding any bracketed upper-case token would
  also swallow `[AKIAIOSFODNN7EXAMPLE]`, a live AWS key, and a redaction
  library may not trade a false negative for tidiness. Idempotence is asserted
  as a property in `tests/test_idempotence.py` rather than as a single case.
  *(rules-engine#33)*

- **A Czech mobile number could be typed `NATIONAL_ID` at high confidence.**
  `validate_czech_birth_number` checked the mod-11 remainder and never the date,
  so it accepted an impossible month -- `606666032` reads as `YY=60 MM=66
  DD=60`. A Czech mobile is nine digits opening `6` or `7`, which is exactly the
  rodné číslo shape, so any mobile divisible by 11 was reported as a national
  identity number with `confidence="high"` and `country_confidence=0.88`.
  Nothing downstream had a reason to doubt it, which is what made this worse
  than an ordinary mistype.

  It was the largest single false-positive bucket in the evaluation: 427 of
  1,230, of which 284 Czech and 21 Slovak (the validator is shared). The date is
  now checked, with all four month conventions -- `1`-`12` for a man, `+50` for
  a woman, and since 2004 `+20` for a birth on a day whose sequence numbers were
  exhausted, so `+70` for a woman on such a day. February is capped at 29
  because a two-digit year does not reveal the century, so a leap year cannot be
  ruled out.

  Measured over the 152,300-record corpus: false positives **1,230 -> 967**
  with hints and **2,370 -> 1,940** blind, `NATIONAL_ID` false positives
  **427 -> 164** (CZ 284 -> 38, SK 21 -> 4), precision **99.8% -> 99.9%**, and
  blind recall **99.4% -> 99.5%** as the phone numbers return to `PHONE`.

  The Portuguese (64) and Bulgarian (53) residue is deliberately untouched and
  is not this defect: the Portuguese NIF is a nine-digit checksum with no date
  component, so NIF and phone genuinely collide on shape. The 38 Czech cases
  that remain are mobiles that also form a legal date, which the validator
  cannot separate -- those need the phone cue, not the checksum.
  *(rules-engine#37)*

- **33,441 dates of birth were left unmasked because the context list covered
  seven languages of thirty-one.** `DOB` recall was 62.8% over the
  152,300-record corpus -- the largest recall gap in the evaluation, and
  excluded from the headline figure, so "99.6% recall (excl DOB)" was true while
  DOB itself sat at 63%.

  The pattern was never the problem. Per-country recall was bimodal: **eleven
  countries at exactly 100%** -- German, Dutch, French, Spanish, Portuguese,
  precisely the languages the list carried -- against twenty at 42-51%. Every
  missed value was a standard date in a format the pattern already matched,
  behind a birth keyword the list did not hold:

      født 15/05/1994        (DK, NO)    syntynyt 08.04.1994     (FI)
      född 1958-04-23        (SE)        fæddur 12.06.1962       (IS)
      γεννηθείς/είσα ...     (EL, CY)    urodzony 12.06.1958     (PL)
      born 07/05/1980        (UK, IE)    nato/a il 13/06/1994    (IT)

  The last two are gaps *inside* covered languages, and the reason the UK,
  Ireland and Italy were not at 100% either: the list held `date of birth` but
  not bare `born`, and `nato il`/`nata il` but not the combined `nato/a il`.

  One shared `DOB_CONTEXT` now covers all 31 countries, and it replaces **two**
  divergent copies -- the ISO-format list was a shorter duplicate missing
  `nato il`, `nascido` and `geburtstag`, so `YYYY-MM-DD` dates were gated on
  fewer keywords than `DD/MM/YYYY` ones for no stated reason.

  **DOB recall is now 100.0% in all 31 countries**, all 33,441 recovered.

  Every entry was screened against the 29.2-million-character corpus for
  occurrences inside a longer word, because context matching is substring and
  not word-boundary. Two candidates were rejected by that screen: `fædd`, which
  lives inside `fæddur`, and bare `born`, found inside `gabornagy` and
  `gabornemeth` -- Hungarian names appearing as e-mail local parts. `"born "`
  with the trailing space has 5,581 corpus hits and no embedded occurrences, so
  that is the listed form. The same reasoning kept bare `pass` out of
  `PASSPORT_CONTEXT` in 0.5.1. `tests/test_dob_context.py` asserts it, with one
  named case per language so removing a keyword fails loudly. *(rules-engine#38)*

- **An assigned secret's span swallowed the sentence's full stop, and with it
  the type.** `credentials. Reisepass: CA1234567.` reported
  `SECRET 'CA1234567.'` -- a passport number plus the period that ended the
  sentence. The pattern was `(?<=[:=] )[^\s]{8,}`, and `[^\s]` does not stop at
  a full stop.

  The mistype was a consequence rather than a second defect: `PASSPORT` claimed
  `CA1234567` and `SECRET` claimed `CA1234567.`, so deduplication saw two
  overlapping candidates instead of one contested span and the cue table's
  promotion of `PASSPORT` never applied. With the span corrected the two are
  identical, the cue resolves it, and all three reported cases return
  `PASSPORT`. The final character may now be anything except sentence
  punctuation, so base64 padding stays inside the span
  (`secret: aGVsbG8=`) while a period does not
  (`password: Tr0ub4dor&3xKcd.`). *(rules-engine#35)*

## 0.5.1 (2026-09-25)

### Added

- **Passport detection in all 31 countries, not four.** `BE`, `DE`, `FR` and
  `NL` had a passport pattern; the other 27 had none, so a passport was
  recognised in four countries out of thirty-one. A country-independent,
  label-gated rule now covers the rest, alongside the per-country patterns
  which stay and still decide their own cases.

  The real defect was narrower than "26 missing patterns" and is fixed by the
  same change. Every passport pattern kept its own context keywords, so a
  passport was only recognised when its *shape* and its *label* came from the
  same country: `Reisepass: CA1234567` was missed because the German pattern
  rejects that alphabet while the Dutch pattern, whose shape fits, had never
  heard of `Reisepass`. A foreign passport recorded in a German, Polish or
  Greek document is the ordinary case, not the exotic one. All passport
  patterns now share one multilingual keyword list.

  The shapes come from the project canon (`prompts/pii_definitions.md`,
  PASSPORT) rather than from invention: the EU pattern is 1–2 letters + 7
  digits, and the UK is 9 digits, optionally `GBR`-prefixed. The canon's
  position is that the EU converged on one shape, so 27 national regexes would
  contradict it as well as being unverifiable against a corpus that carries
  passports for four countries. Aligning to the canon also fixed a real miss:
  an all-numeric passport was not detected at all while the rule required a
  leading letter, the UK's own format among them. Requiring *exactly* nine
  digits for the numeric form rejects an eight-digit date beside the word
  "passport" on shape, before the label is consulted. The generic rule is deliberately permissive in shape and
  leans entirely on the label, which is how the four existing patterns already
  worked.

  The bare Scandinavian `pass`, Finnish `passi`, Latvian `pase` and Lithuanian
  `pasas` are deliberately absent from that list. Context matching is
  substring, not word-boundary, so they fire inside `password`, `Passwort`,
  `passenger`, `Passstrasse`, `passive`, `phase` — and `db_password=…` took
  the span away from `SECRET`. Only compound forms are listed, and a test
  asserts no keyword is short enough to hide inside another word.

  One conformance vector per country that relies on the shared rule -- 27 of
  them, so removing a keyword fails a named test rather than silently dropping
  a country -- plus four covering the boundaries, and `tests/test_passport_coverage.py`. Corpus
  figures are unchanged: `make eval` reports the same recall, precision and
  **the same false-positive counts** (1,230 / 2,370), so the wider keyword set
  costs nothing measurable. *(rules-engine#23)*

### Fixed

- **A German tax identifier was left in the clear under its own official
  label.** `Steuerliche Identifikationsnummer 47 362 819 054` masked nothing
  (and, run on, masked only the last two groups); the same happened to
  `Steueridentifikationsnummer lautet:` and `Steuer-IdNr lautet:`. A German
  Steuer-ID that fails its checksum is masked only on the strength of the
  label beside it, so when the label was not read the value was emitted
  verbatim. Two independent causes, both fixed:

  - `CUE_WINDOW` was 32 characters, which is how long a *label* may be.
    `"Steuerliche Identifikationsnummer "` is 34 and
    `"Steueridentifikationsnummer lautet: "` is 36, so the label's own start
    fell outside the window and the `(?<![A-Za-z0-9_])` boundary had nothing
    to anchor against — the label read as no label at all. This is the same
    failure that made `sozialversicherungsnummer` unreachable for the whole of
    0.3.8, recurring on a longer compound. The window is now 44, which admits
    the longest label the table carries together with one qualifier word
    (`"Steuerliche Identifikationsnummer lautet: "`, 42 characters).

  - A cue may use its run-on **or** one qualifier word, never both. `steuer-?id`
    spent its run-on reaching the end of `Steuer-IdNr` and had none left for
    `lautet`. The German long forms are now spelled out in the cue
    (`steuerliche identifikations-nummer`, `steuer-identifikations-nummer`,
    `steuer-id-nr`), so the label matches whole and its qualifier stays free.
    `Steuerliche Identifikationsnummer` matched nothing before: it is two
    words, and `steuer-?id` cannot reach across `liche `.

  Widening the window does not widen how far a cue may sit from its value —
  that is bounded by the run-on/qualifier tail, not by the window — and a
  vector pins it: a tax label a sentence away still licenses nothing.
  Nine conformance vectors cover the four forms that leaked, the three that
  already worked, the longest form with a qualifier, and that boundary.
  A parametrised test now asserts every long label in the cue table is
  reachable both adjacent to its value and across a qualifier word, so a
  label too long for the window fails loudly instead of silently going dead.
  *(rules-engine#26)*

- **`Exemption` is exported from the package root.** It shipped in 0.5.0
  documented in the README and present in `euredact.types`, but never
  re-exported, so `from euredact import Exemption` raised while the TypeScript
  SDK exported it correctly. No functional loss — `result.exempted` was always
  populated — but the documented import path did not resolve. A contract test
  now asserts every name in `__all__` is importable and that the public types
  resolve at the root. *(rules-engine#20)*

- **`make sweep` and `make parity` refuse to run on an incomplete corpus.**
  Both loaders skipped any file they could not read and carried on. Because a
  `--limit` takes an evenly spaced sample across the whole corpus, losing one
  file shifts every document in the sample, so two runs printing the same
  document count could describe different populations — cross-SDK parity read
  0.05% on one population and 0.30% on another, from an identical engine. The
  loaders now raise `CorpusUnreadable`, naming each file and how to restore it,
  and both commands print the population they sampled from. The check covers
  the training `.jsonl` splits as well, which supply 60,773 of the 213,073
  documents and were the larger hole: an iCloud-evicted file there reads as
  empty rather than failing, which is indistinguishable from an empty split
  unless the size is checked. With this in place parity reproduces at **0.30%**
  across consecutive runs. *(rules-engine#18)*

## 0.5.0 (2026-09-24)

### Added

- **The allowlist reports what it exempted, matches structured identifiers
  across spacing, and can take a whole domain.** Three changes to one feature:

  `RedactResult.exempted` lists every span the allowlist kept, with the rule
  that matched and whether it was a value or a domain rule. An exemption is a
  deliberate decision to leave a direct identifier in a document that otherwise
  claims to be redacted; it was previously indistinguishable from never having
  detected it. *(rules-engine#16)*

  A structured identifier now matches however the document spaces it, so
  `allowlist=["NL91ABNA0417164300"]` exempts `NL91 ABNA 0417 1643 00` — the
  spelling a company's own IBAN usually appears in. Applies to IBAN, BIC, card,
  phone, VAT, national and tax IDs, passport, licence, permit, health,
  chamber-of-commerce, IMEI and VIN. Free-text types stay literal, because
  folding would exempt values the caller never listed: `jan.devries@acme.be`
  and `jandevries@acme.be` are different mailboxes at most providers.
  *(rules-engine#15)*

  `allowlist_domains=["acme.be"]` exempts every address at an owned domain
  without enumerating each mailbox, which drifts as people join and leave. It
  applies to `EMAIL` and `URL` only, covers subdomains, and matches on a label
  boundary so `acme.be` does not exempt `evilacme.be`. There are deliberately
  no wildcards: the allowlist is the only option that turns redaction *off*, so
  an over-broad entry fails toward under-redaction silently. *(rules-engine#17)*

- **Reversible tokenization: `redact(text, tokenize=True)` and `restore()`.**
  Each value is replaced by a token that names its type and nothing else —
  `EMAIL_K7Q2`, `PERSON_NAME_W3NB` — and the result carries the way back:

  ```python
  result = euredact.redact(prompt, countries=["BE"], tokenize=True)
  reply = llm(result.redacted_text)          # sees EMAIL_K7Q2, never the address
  euredact.restore(reply, result.tokens)     # the reply, with the real values back
  ```

  The same value gets the same token within a call, so a prompt that names
  someone twice still reads as one person. Across calls it gets a different
  one: nothing is retained on the instance, and two tokenized documents never
  reveal a shared value — which is where this differs from
  `referential_integrity`, and why the two cannot be combined. Tokens are
  kept clear of any token-shaped string already in the document, so an LLM's
  reply to a tokenized prompt can itself be redacted without `restore()`
  putting the wrong value back. `RedactResult` gains `tokens`, a
  token → value mapping that is empty unless `tokenize=True`.

  Works in cloud mode: the SDK rebuilds the text from the spans the service
  returns. The service builds its own output from exactly those spans, so
  nothing it masked is lost; a span whose offsets do not match the document
  raises `CloudError` rather than masking the wrong characters.

- **Allowlist: values that are never redacted.** A customer's own email
  address or organisation name is not PII to them. `redact(text,
  allowlist=[...])` exempts exact values for one call; `EuRedact(allowlist=
  [...])` does so for every call on the instance, and the two merge.

  ```python
  sdk = euredact.EuRedact(allowlist=["ACME NV", "info@acme.be"])
  sdk.redact("Mail info@acme.be or jan@acme.be", countries=["BE"]).redacted_text
  # 'Mail info@acme.be or [EMAIL]'
  ```

  Matching is whole-span and case-insensitive, and nothing more: `acme.be` does
  not exempt every address at that domain, because a broader match is how "our
  domain" turns into "everyone who ever mailed us". A bare string raises
  `TypeError` rather than being iterated into single letters that exempt
  nothing. Works in cloud mode, where the SDK drops the exempted spans and
  rebuilds the text from the rest.

- **Conformance vectors can carry options and expected output.** A case may
  now set `options` (today: `allowlist`) and `expectRedactedText`, so
  behaviour that only shows in the masked text — not in which spans were
  found — is pinned across both SDKs. Four allowlist vectors use it.

### Fixed

- **Both SDKs now share one evaluation definition.** The stricter recall rule
  landed in the Python harness first; `evalFull.ts` now shares the same
  coverage-based outcome, and its category map gained the `HEALTH_ID` and
  `SECRET` entries Python already carried — `HEALTH_ID` had no engine type to
  fall back on, so its 252 labels were scored against a name the engine never
  emits. With both aligned the SDKs agree on every per-type row and on the
  total: 664,360 of 667,268 labels fully masked, hinted.
  *(rules-engine#12)*

### Accuracy

Re-measured on the 152,300-document corpus for this release; the full
breakdown, including what each fix moved, is in
[`docs/v0.5.0-corpus-results.md`](../docs/v0.5.0-corpus-results.md).

| engine | mode | recall | precision |
|---|---|---:|---:|
| Python | hinted | 99.56% | 99.78% |
| Python | blind | 99.39% | 99.63% |
| TypeScript | hinted | 99.56% | 99.78% |
| TypeScript | blind | 99.39% | 99.63% |

**Measured with the improved harness, so not directly comparable with the
0.4.0 figures.** Recall now requires the whole identifier to be masked, where
it previously accepted an identifier as found once its literal text was absent
from the output. On equal terms — the 0.4.0 engine measured with the current
harness — recall was 99.4% hinted and 99.2% blind, so this release adds
**+0.16pp** and **+0.19pp** respectively.

- **`make eval` measures whole-identifier masking.** A gold identifier counted
  as recalled once its literal text was absent from the output — which masking
  a *single character* already achieves — with a fallback that accepted one
  character of span overlap, so a truncated span could score as a complete
  detection. The IPv6 work in this release surfaced it: those 636 entities
  scored 100% while the tail of each compressed address was still in the
  clear. Recall now requires every character of the span to be masked, and the
  report
  distinguishes four outcomes: fully masked, **partially masked** (a new
  column), masked under another type, and not present in the document (no
  longer silently credited). Re-measured on the 152,300-document corpus:
  **99.4% recall / 99.8% precision with country hints, 99.2% / 99.6% blind**,
  against 99.7%/99.8% and 99.7%/99.6% under the old rule. Precision is
  unchanged; the recall figures are lower because they are now counting what
  they always claimed to. Harness only — no engine behaviour changes.
  *(rules-engine#8)*
- **An apostrophe in an email local part left the prefix unmasked.**
  `johno'neill@outlook.ie` masked as `johno'[EMAIL]`: the local-part class had
  no apostrophe, so the match began after it and the surname — the identifying
  half — survived into output that looked redacted. **1,415 entities** in the
  152,300-document corpus, and the failure correlates with Irish and Southern
  European names rather than falling evenly across the people in the data. The
  apostrophe is now accepted *between* word characters, so a quote belonging to
  the surrounding text (`'john@x.ie'`) is still left alone. Four conformance
  vectors. *(rules-engine#10)*

- **Compressed IPv6 addresses were only half masked.** `2001:db8::ff00:42:8329`
  came back as `[IPV6_ADDRESS]ff00:42:8329` — the interface identifier, the
  most identifying half, survived into output that looked redacted. `::1` and
  `2001:db8::` were not detected at all, and `::ffff:192.0.2.128` had only its
  IPv4 tail masked. Two causes in one pattern: alternation is leftmost-first
  rather than longest-match, so the bare `X::` branch won before the branches
  that consume the tail; and `\b` cannot anchor a token that begins or ends
  with `:`, a non-word character. The pattern now orders its branches
  longest-first, leads with the IPv4-embedded forms (every group of a dotted
  quad is also valid hex), bounds the token with lookarounds, and covers zone
  indices (`fe80::1%eth0`). A bare `::` is deliberately not matched: it is the
  unspecified address, not an identifier, and matching it would redact the
  scope operator in `MyClass::method`. Ten conformance vectors (`ipv6-*`).
  *(rules-engine#5)*
- **A parenthesised international phone number swallowed the closing bracket.**
  `Call (+32 475 12 34 56) today.` masked as `Call ([PHONE] today.` — the
  punctuation vanished from the output and `detections[].text` carried a `)`
  that is not part of the number, which any consumer of that field (parity,
  eval, referential labels keyed on the text) then saw as the value. The
  pattern wrote its parentheses as two independent optionals, `\(?` and `\)?`,
  so nothing required them to pair; they are now matched as a pair inside one
  group. The trunk prefix the optionals were written for, `+32 (0)475 12 34
  56`, still matches. Three conformance vectors. *(rules-engine#3)*

- **A capitalised heading word was masked as a German ID card.** The
  Personalausweis pattern accepted any 9–10 upper-case alphanumerics after its
  first letter, and its context cue `Perso` is a substring of `PERSONAL` and
  `PERSOONLIJKE`, so `CURRICULUM VITAE` above a *Personal details* heading came
  back as `[NATIONAL_ID] VITAE` — in every CV of that layout, whatever
  `countries` the caller passed. The pattern (and the passport pattern, same
  shape) now uses the card's own alphabet: digits and `CFGHJKLMNPRTVWXYZ`, nine
  characters, optional check digit. No vowels, so no words. Four conformance
  vectors (`de-idcard-*`), two of them proving real numbers still detect.
  *(rules-engine#1)*

- **`referential_integrity=True` no longer returns a cached bracketed result.**
  The option was not part of the result-cache key, so on the same instance
  `redact(text)` followed by `redact(text, referential_integrity=True)`
  returned the first call's `[EMAIL]` output instead of `EMAIL_1`. The option
  now keys the cache alongside `mode`, `detect_dates` and `country_hint`.

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
