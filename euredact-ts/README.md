# euredact

**European PII detection and redaction for Node.js / TypeScript**

---

Fast, zero-dependency European PII detection and redaction SDK. Detects and
redacts personal data across **31 European countries** using rule-based pattern
matching with checksum validation, context-aware false-positive suppression,
and priority-based deduplication.

## Install

```bash
npm install euredact
```

## Quick Start

```ts
import { redact } from "euredact";

const result = redact("Mijn BSN is 123456782 en email jan@example.com", {
  countries: ["NL"],
});

console.log(result.redactedText);
// "Mijn BSN is [NATIONAL_ID] en email [EMAIL]"

console.log(result.detections);
// [{ entityType: "NATIONAL_ID", text: "123456782", start: 12, end: 21, ... }, ...]
```

## Features

- **31 European countries** with country-specific patterns
- **25+ PII entity types:** national IDs, IBANs, phone numbers, email, VAT
  numbers, license plates, credit cards, BIC/SWIFT, VIN, IMEI, GPS coordinates,
  UUIDs, social handles, IP/IPv6, MAC addresses, secrets/API keys, and more
- **Secret/API key detection:** known-prefix patterns for AWS, GitHub, Stripe,
  OpenAI, Slack, JWT, SendGrid, plus Shannon entropy-based detection for generic
  high-entropy tokens near context keywords
- **Custom patterns:** register your own regex patterns for domain-specific PII
- **Checksum validation:** IBAN mod-97, Luhn (credit cards/IMEI), and 30+
  country-specific validators
- **Priority-aware deduplication:** validated (checksum, corroborated by the
  document's country) > custom > regex-only
- **Country self-detection:** infers a document's countries from the entities
  that carry one, so an ambiguous value resolves without the caller naming a
  country — and `countries` never gates what is looked for
- **Context-aware:** keyword proximity checks and structural detection (JSON field
  names, CSV headers) for ambiguous patterns
- **Zero runtime dependencies**
- **ESM and CommonJS** dual-published

### Supported Countries

| Region | Countries |
|---|---|
| Western Europe | AT, BE, CH, DE, FR, LU, NL |
| Southern Europe | CY, EL, ES, IT, MT, PT |
| Northern Europe | DK, EE, FI, IS, LT, LV, NO, SE |
| Eastern Europe | BG, CZ, HR, HU, PL, RO, SI, SK |
| British Isles | IE, UK |

## API Reference

### Module-Level Functions

#### `redact(text, options?)`

```ts
function redact(text: string, options?: RedactOptions): RedactResult;
```

Main entry point. Detects and redacts PII in the given text.

```ts
interface RedactOptions {
  countries?: string[] | null;    // Scope. Flags anything attributed elsewhere as
                                  // outOfScope. Never gates what is looked for.
  countryHint?: string[] | null;  // A prior only — resolves ambiguity without
                                  // narrowing scope or flagging anything
  context?: DocumentContext | null; // Share country evidence across the chunks
                                  // of one document (see "Chunked documents")
  chunkOffset?: number;           // Where this chunk starts in the document
  referentialIntegrity?: boolean; // Replace with consistent labels (default: false)
  detectDates?: boolean;          // Include DOB/date-of-death detections (default: false)
  cache?: boolean;                // Enable result caching (default: true)
}
```

| Parameter | Default | Description |
|---|---|---|
| `countries` | `null` | ISO 3166-1 alpha-2 codes to restrict detection. `null` loads all 31 countries. |
| `referentialIntegrity` | `false` | Replace PII with consistent labels instead of entity-type labels. |
| `detectDates` | `false` | Include date-of-birth and date-of-death detections. Off by default. |
| `cache` | `true` | Cache results for identical inputs. |

#### `redactBatch(texts, options?)`

```ts
function redactBatch(texts: string[], options?: RedactOptions): RedactResult[];
```

Process multiple texts efficiently. Loads country configs once. Returns results
in the same order as the input.

#### `addCustomPattern(name, pattern)`

```ts
function addCustomPattern(name: string, pattern: string): void;
```

Register a custom regex pattern. Matches are reported with `name` as the entity
type. See [Custom Patterns](#custom-patterns) below.

#### `availableCountries()`

```ts
function availableCountries(): string[];
```

Returns a sorted list of supported ISO country codes.

### Instance-Based API (`EuRedact` Class)

For applications that need isolated instances with separate caches and custom
pattern registrations:

```ts
import { EuRedact } from "euredact";

const instance = new EuRedact();
instance.addCustomPattern("CASE_REF", "CASE-\\d{8}");

const result = instance.redact("See CASE-20260401 for details", {
  countries: ["NL", "BE"],
});
console.log(result.redactedText);
// "See [CASE_REF] for details"
```

The `EuRedact` class exposes: `redact()`, `redactBatch()`, and
`addCustomPattern()`.

### Return Types

#### `RedactResult`

```ts
interface RedactResult {
  redactedText: string;       // The input text with PII replaced
  detections: Detection[];    // All PII spans found
  source: string;             // Detection backend ("rules")
  degraded: boolean;          // True if the engine fell back to a simpler mode
}
```

#### `Detection`

```ts
interface Detection {
  entityType: EntityType | string; // PII category (enum or custom name)
  start: number;                   // Start offset in the original text
  end: number;                     // End offset (exclusive)
  text: string;                    // The matched substring
  source: DetectionSource;         // "rules" or "cloud"
  country: string | null;          // ISO code or null for shared/custom patterns
  confidence: string;              // "high" | "medium" | "low" — see below
  countryConfidence?: number;      // How strongly the document supports `country`,
                                   // in [0, 1]. 0 means the attribution rests on
                                   // a checksum alone.
  outOfScope?: boolean;            // Attributed outside the declared `countries`.
                                   // Flagged, never dropped.
}
```

**`confidence`** describes how the *type* was arrived at. It never says anything
about whether the span is masked — every detection is, at every level.

| value | meaning |
|---|---|
| `"high"` | a pattern matched and, where one exists, its checksum passed |
| `"medium"` | the type comes from a label touching the span, because no pattern of that type claimed it — `Αρ. Ταυτότητας: 00892341` is a `NATIONAL_ID` although nothing can checksum it |
| `"low"` | a pattern matched, its checksum *failed*, and the document labels the span as that very type — `Rijksregisternummer: 85.03.19-284.73` is a national number with a bad check digit |

Filter on it when you need only checksum-backed detections:

```ts
const strict = result.detections.filter(d => d.confidence === "high");
```

A `"low"` detection is the honest description of a mistyped, OCR'd or invented
identifier: the shape and the label agree, the check digit does not. Earlier
versions dropped these, which meant a redaction library printed in full an
identifier it had recognised and rejected.

#### `RedactResult`

```ts
interface RedactResult {
  redactedText: string;
  detections: Detection[];
  source: string;
  degraded: boolean;

  // Country inference — see "Country-independent detection"
  inferredCountries: Array<[string, number]>; // [country, confidence], strongest first
  evidence: CountryEvidence[];                // every signal, with the span behind it
  detectionMode: string;                      // "declared" if countries was passed,
                                              // "inferred" otherwise
}
```

#### `EntityType`

String enum with all supported PII categories:

```
NAME              ADDRESS           BANK_ACCOUNT      BIC
CREDIT_CARD       PHONE             EMAIL             DOB
DATE_OF_DEATH     NATIONAL_ID       SSN               TAX_ID
PASSPORT          DRIVERS_LICENSE   RESIDENCE_PERMIT  LICENSE_PLATE
VIN               VAT               POSTAL_CODE       IP_ADDRESS
IPV6_ADDRESS      MAC_ADDRESS       HEALTH_INSURANCE  HEALTHCARE_PROVIDER
CHAMBER_OF_COMMERCE  IMEI          GPS_COORDINATES   UUID
SOCIAL_HANDLE     SECRET            INTERNAL_ID       OTHER
```

`INTERNAL_ID` — an employee, badge or customer number tied to a person — is
emitted **only** when an explicit label names it (`medarbejdernummer:`,
`Personalnummer:`, `Employee No:`). There is no pattern for one, because there
is no shape for one: without the label, a digit run is not distinguishable from
any other. The type exists so that a labelled employee number is filed
correctly instead of being claimed by the phone pattern.

For custom patterns, `entityType` is a plain string (e.g. `"EMPLOYEE_ID"`).

## Country codes

`countries` accepts **ISO 3166-1 alpha-2** codes. The two EU/VAT spellings are
accepted as equivalents: `GB`/`UK` and `GR`/`EL`. Codes are case-insensitive
and whitespace-tolerant.

An **unrecognised** code does not throw — it logs an `[euredact]` warning and
detection continues with the shared, country-independent patterns. Throwing on
an unknown locale invites callers to wrap the call in `try/catch` and skip
redaction entirely, failing open with unredacted PII.

## Country-independent detection

**`countries` never gates detection.** Every pattern runs on every document,
whatever you pass. The country you declare decides *how a match is labelled*,
never *whether it is found*.

This is the engine's central invariant, enforced by
`src/__tests__/inference.ts`: no value of `countries` may change which spans are
detected. A wrong or missing country cannot cause a miss — silent recall loss is
invisible in testing and surfaces in a breach report, whereas a false positive
is recoverable.

It was not always so. `countries: ["BE"]` used to make a valid Dutch BSN vanish
entirely, because the Dutch patterns were never run:

```ts
redact("Werknemer met BSN 111222333", { countries: ["BE"] });
// before: 'Werknemer met BSN 111222333'   <- leaked
// now:    'Werknemer met BSN [NATIONAL_ID]'
```

Entities found outside the countries you declared are **flagged, not dropped**:

```ts
const [det] = redact("BSN 111222333", { countries: ["BE"] }).detections;
det.outOfScope; // true — detected, masked, and marked as outside your scope
```

So a Belgian IBAN in a document processed with `countries: ["AT"]` is still
detected:

```ts
redact("Rekening: BE68 5390 0754 7034", { countries: ["AT"] });
// -> 'Rekening: [BANK_ACCOUNT]'
```

### Which country a value belongs to

Because every pattern runs, the same digits often match several countries'
schemes. 36.6% of national-ID values in our corpus validate under more than one
country's checksum, so the digits alone cannot decide it — the *document* does.

The engine infers the document's countries from entities that carry their
country in the string, then uses that to resolve the ambiguity:

```ts
redact("Bereikbaar op telefoon 0612345678, mail jan@test.nl");
// inferredCountries: [["NL", 0.98]]   detections: [PHONE (NL), EMAIL]

redact("Kontakt: 0612345678, e-mail jens@test.dk");
// inferredCountries: [["DK", 0.98]]   detections: [NATIONAL_ID (DK), EMAIL]
```

Identical digits, different answer — `0612345678` is both a valid Dutch mobile
number and a valid Danish CPR. Only the surrounding document distinguishes them.

Every inference is auditable: `result.evidence` lists each signal, its weight,
and the span that produced it, in document order.

| Signal | Weight (log-odds) | Measured reliability |
|---|---:|---|
| `e164Prefix` | 4.00 (capped) | 41,402 / 41,402 |
| `bicCountry` | 4.00 (capped) | 2,588 / 2,588 |
| `emailTld` | 4.00 (capped) | 97,865 / 98,949 |
| `vatPrefix` | 2.84 | 19,022 / 20,136 |
| `ibanPrefix` | 1.94 | 110,572 / 126,428 |

Weights are derived from the corpus, not chosen by hand, and are kept identical
to the Python SDK's. The IBAN prefix being weakest is real: a Belgian IBAN in a
Dutch invoice is ordinary, so an account's country is only weak evidence about
the document's.

Confidences are per-country and do **not** sum to 1 — document countries are not
mutually exclusive. A Belgian supplier invoicing a German customer is genuinely
both.

## Chunked documents

A long document is usually redacted in pieces. Each piece is scanned
independently, so a chunk carrying no country signal of its own infers nothing —
even when page 1 identified the document beyond doubt.

```ts
import { DocumentContext } from "euredact";

const ctx = new DocumentContext();
let offset = 0;
for (const page of pages) {
  const result = redact(page, { context: ctx, chunkOffset: offset });
  offset += page.length;
}

// page 1: "Factuur — IBAN NL91ABNA0417164300, info@example.nl"
// page 7: "Telefoon 0612345678"  -> PHONE (NL), not NATIONAL_ID (DK)
```

`chunkOffset` rebases spans recorded in the context so they point into the whole
document; returned detections stay relative to the chunk you passed in. Caching
is disabled automatically while a context is in use, because the result then
depends on evidence the text alone does not determine.

Reuse a context only for chunks of the **same** document.

## BIC detection

BIC is the only bank identifier here with **no check digit**, and characters
5-6 of ordinary uppercase words are frequently valid ISO 3166 country codes
(`DRINGEND` -> `GE`, `HOSPITAL` -> `IT`). Detection is therefore gated:

| Stage | Condition | Result |
|---|---|---|
| Gate 0 | the token also occurs as an ordinary lowercase word in the same document | never emitted |
| Tier 1 | registry hit on the BIC6 institution+country prefix | emitted |
| Gate 2 | heading / shouted-word shape | never emitted |
| Tier 2 | `BIC`/`SWIFT` keyword, an IBAN, or a bank block in the enclosing line, record or paragraph | emitted |
| — | none of the above | never emitted |

The package bundles **no licensed BIC data** — only a small seed list of BIC6
prefixes compiled from publicly published bank data. Deployments holding a
licensed directory install it at startup:

```ts
import { setBicRegistry } from "euredact";

setBicRegistry(["ABNANL2A", "INGBNL2A", "BBRUBE"]);   // iterable
setBicRegistry(bic => myDirectory.has(bic));          // membership callable
setBicRegistry(null);                                 // remove
```

The registry is an **accept** signal, never a filter: a code missing from it
falls through to the context gate and is still detected when banking context is
present. A stale list costs a little recall on bare, contextless BICs — it
never causes a leak. Annual review is sufficient.

## `IBAN` is now `BANK_ACCOUNT`

The canonical type name is `BANK_ACCOUNT`; `IBAN` was a legacy alias.
`detection.entityType` is now `"BANK_ACCOUNT"` and the placeholder written into
redacted text is `[BANK_ACCOUNT]`.

`EntityType.IBAN` is kept as an alias with the same value, so
`EntityType.IBAN === EntityType.BANK_ACCOUNT` and code referring to the member
keeps working. Code matching the *string* `"IBAN"` — or the `[IBAN]`
placeholder — must be updated. `LEGACY_TYPE_ALIASES` publishes the mapping.


## Custom Patterns

Register domain-specific PII patterns at runtime:

```ts
import { addCustomPattern, redact } from "euredact";

// Register patterns
addCustomPattern("EMPLOYEE_ID", "EMP-\\d{6}");
addCustomPattern("CASE_REF", "CASE-\\d{8}");

// They are detected alongside built-in PII
const result = redact(
  "Employee EMP-123456, email jan@example.com, ref CASE-20260401"
);
console.log(result.redactedText);
// "Employee [EMPLOYEE_ID], email [EMAIL], ref [CASE_REF]"
```

### How Custom Patterns Work

- `name` becomes the entity type in detections and replacement tags
- `pattern` is a JavaScript regular expression (same syntax as `RegExp`)
- Custom patterns are always active regardless of the `countries` option
- In overlap resolution, custom patterns have higher priority than built-in
  regex-only patterns but lower priority than built-in patterns with a passing
  checksum validator

### Instance Isolation

Custom patterns registered on the module-level function apply to the shared
singleton. For isolated registrations, use separate `EuRedact` instances:

```ts
import { EuRedact } from "euredact";

const a = new EuRedact();
a.addCustomPattern("EMPLOYEE_ID", "EMP-\\d{6}");

const b = new EuRedact();
b.addCustomPattern("CASE_REF", "CASE-\\d{8}");
```

## Secret and API Key Detection

Built-in detection for API keys, tokens, and passwords. Always active -- no
configuration required.

### Known-Prefix Patterns

| Pattern | Description |
|---|---|
| `AKIA...` | AWS Access Key ID |
| `ghp_`, `gho_`, `ghs_`, `github_pat_` | GitHub tokens (PAT, OAuth, app, server) |
| `sk_live_`, `pk_live_`, `sk_test_`, `pk_test_` | Stripe secret and publishable keys |
| `sk-`, `sk-ant-` | OpenAI and Anthropic API keys |
| `xoxb-`, `xoxp-`, `xoxa-`, `xoxs-` | Slack tokens |
| `eyJ...` (3-part base64url) | JWT tokens |
| `SG.` | SendGrid API keys |

```ts
const result = redact("My API key is sk-proj-abc123def456ghi789jkl0");
console.log(result.redactedText);
// "My API key is [SECRET]"
```

### Entropy-Based Detection

High-entropy strings (32+ alphanumeric characters) near context keywords like
`key`, `token`, `secret`, `password`, `credential`, `auth`, or `bearer`
(including 12 European language translations) are flagged via Shannon entropy
analysis:

```ts
redact("The api_key is xK9mPqR7vLnW2bFjY8cGhT4sDfAeU6iO").redactedText;
// "The api_key is [SECRET]"

// Without a context keyword -- not flagged:
redact("identifier: xK9mPqR7vLnW2bFjY8cGhT4sDfAeU6iO").redactedText;
// "identifier: xK9mPqR7vLnW2bFjY8cGhT4sDfAeU6iO"
```

## Country Hints

Two options tell the engine about country, and neither restricts what is looked
for:

| Option | Meaning |
|---|---|
| `countries` | **Scope.** Resolves ambiguity, and flags anything attributed elsewhere as `outOfScope`. |
| `countryHint` | **Prior only.** Resolves ambiguity without narrowing scope or flagging anything. |

```ts
// You know this batch is Swedish, but don't want foreign PII marked out of scope:
redact(text, { countryHint: ["SE"] });

// You want anything non-Swedish flagged for review:
redact(text, { countries: ["SE"] });
```

Declaring a country helps where a value is genuinely ambiguous and the document
carries no other signal:

```ts
redact("Telefon: 0708787668", { countryHint: ["SE"] }).detections[0];
// PHONE / SE — without the hint this is a valid Danish CPR and nothing says otherwise
```

`result.detectionMode` reports which happened: `"declared"` if you passed
`countries`, `"inferred"` otherwise.

Passing neither is safe, and is the right default for mixed-origin data: the
engine infers what it can and reports it in `result.inferredCountries`.

## Referential Integrity

When `referentialIntegrity: true`, each unique PII value is mapped to a consistent
label:

```ts
const result = redact(
  "BSN 123456782 en later weer 123456782",
  { countries: ["NL"], referentialIntegrity: true }
);
console.log(result.redactedText);
// "BSN NATIONAL_ID_1 en later weer NATIONAL_ID_1"
```

## Architecture

```
Input text
    |
    v
[Normalizer] -- Unicode normalization, whitespace cleanup
    |
    v
[Pass 1: Pattern Matching] -- All country + shared + custom regexes
    |
    v
[Pass 2a: Validation] -- Checksum validators (mod-97, Luhn, entropy, ...)
    |                     Failed spans are recorded, per entity type
    v
[Evidence]     -- Which countries does this document belong to? From IBAN
    |              prefixes, +CC codes, VAT prefixes, BIC, email ccTLDs
    v
[Pass 2b: Suppression] -- Remove false positives (currency amounts, units,
    |                      references). Failed checksums demote same-type
    |                      matches rather than deleting them
    v
[Deduplication] -- Priority-aware, country-evidence-weighted
    |               Longer span outranks declared country
    v
[Replacement] -- Right-to-left substitution with [ENTITY_TYPE] labels
    |              or labels
    v
RedactResult
```

### Suppression Zones

When a regex matches a pattern that has a checksum validator but the checksum
fails, the span is recorded. A validator-less match of **the same entity type**
contained in it is *demoted* below every other candidate — not deleted. A failed
checksum is evidence against that type, not against the span, and demotion can
never silence a detection the way deletion could.

### Deduplication Priority

When multiple patterns match overlapping spans, the engine resolves conflicts
using a priority system:

| Tier | What |
|---:|---|
| 3 | **Validated** — a checksum validator passes *and* the document corroborates its country |
| 2 | **Custom patterns** registered via `addCustomPattern()` |
| 1 | **Regex-only**, and validated patterns whose country the document does not corroborate |
| 0 | **Postal codes** — a bare digit run, the weakest evidence in the engine |
| -1 | **Demoted** — a validator-less match inside a failed checksum of *its own type* |

Within a tier, ranking is: longer span, then stronger country evidence, then
whether the country was declared. **Span length outranks country** deliberately:
preferring the declared country over the longest match truncates entities — with
`countries: ["BE"]` the Belgian phone pattern claimed 11 of the 14 characters of
`06 12 34 56 78` and left three digits exposed. Country can change *which*
country is attributed, never *what* is masked.

Two tiers are less obvious than they look:

- **A passing checksum does not automatically win.** A weak checksum fits by
  luck — a mod-11 scheme accepts a random number about one time in eleven — so a
  validated candidate from a country the document shows no trace of drops to
  tier 1. Entities that carry their own country vouch for themselves (an IBAN
  emits evidence for its own country), so a foreign IBAN in a domestic invoice
  keeps tier 3.
- **Nothing is deleted for failing a checksum.** A failed checksum demotes
  rather than removes, and only candidates of *the same entity type*: it is
  evidence against that type, not against the span. Deleting instead removed 454
  detections across the corpus, of which 454 overlapped real labelled PII.

## Performance

Measured on one core, all 31 countries loaded, `detectDates: true`. Cost scales
with document length, so the input size is stated rather than averaged away.

| Input | Latency | Throughput |
|---|---:|---:|
| Short record (186 chars) | 155 µs | 6,462 docs/s |
| Real document (3,424 chars) | 1.56 ms | 643 docs/s |

No optional accelerator is needed or offered. The Python SDK ships an
`[fast]` extra (RE2 / Aho-Corasick) because CPython's regex engine is the
bottleneck there; V8's has literal prefilters that make it unnecessary here.
Measured on the same 611 documents, this SDK runs about 3× faster than the
accelerated Python path, so adding a native addon — and with it the loss of
bundler, edge-runtime and Deno compatibility — would buy nothing.

## CommonJS

```js
const { redact } = require("euredact");
```

## Performance

| Metric | Value |
|---|---|
| Latency per redaction | ~0.02 ms |
| Package size | ~86 KB |
| Runtime dependencies | 0 |

## License

Apache-2.0
