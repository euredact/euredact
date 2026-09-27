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
- **41 PII entity types** (30 from the rules engine, 11 from the
  [cloud tier](#cloud-tier)): national IDs, IBANs, phone numbers, email, VAT
  numbers, license plates, credit cards, BIC/SWIFT, VIN, IMEI, GPS coordinates,
  UUIDs, social handles, IP/IPv6, MAC addresses, secrets/API keys, and more
- **Secret/API key detection:** known-prefix patterns for AWS, GitHub, Stripe,
  OpenAI, Slack, JWT, SendGrid, plus Shannon entropy-based detection for generic
  high-entropy tokens near context keywords
- **Custom patterns:** register your own regex patterns for domain-specific PII
- **Reversible tokenization:** `tokenize: true` swaps values for `EMAIL_K7Q2`-style
  tokens and `restore()` puts them back — for prompts that go to an LLM and
  come back
- **Allowlist:** values that are never redacted, such as your own organisation's
  name and addresses, per call or per instance
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

### Which option do I need?

| I want to… | Use |
|---|---|
| redact a document with no further setup | `redact(text)` — all 31 countries, `[ENTITY_TYPE]` output |
| restrict scope to the countries I operate in | `{ countries: ["NL", "BE"] }` |
| keep detection wide but resolve ambiguity | `{ countryHint: ["DE"] }` |
| send a prompt to an LLM and restore the reply | `{ tokenize: true }`, then [`restore()`](#restoretext-tokens) |
| keep relationships visible across a whole session | `{ referentialIntegrity: true }` |
| never redact my own company name or addresses | `{ allowlist: [...] }`, or `new EuRedact({ allowlist })` |
| never redact anything at my own domain | `{ allowlistDomains: ["acme.be"] }` |
| audit what the allowlist kept in the document | `result.exempted` |
| catch person names, employers, job titles, diagnoses | `redactAsync(text, { mode: "cloud" })` — see [Cloud tier](#cloud-tier) |
| include dates of birth | `{ detectDates: true }` |
| redact a document too large for one call | `context` + `chunkOffset` — see [Chunked documents](#chunked-documents) |
| detect an identifier the engine does not know | [`addCustomPattern()`](#addcustompatternname-pattern) |
| isolate tenants from each other | one `new EuRedact()` each |
| free PII held in memory | `clear()` |


### Module-Level Functions

#### `redact(text, options?)`

```ts
function redact(text: string, options?: RedactOptions): RedactResult;
```

Main entry point. Detects and redacts PII in the given text.

```ts
interface RedactOptions {
  countries?: string[] | null;      // scope (see below); null = all 31
  countryHint?: string[] | null;    // a prior only; does not narrow scope
  context?: DocumentContext | null; // share evidence across chunks
  chunkOffset?: number;             // where this chunk starts
  mode?: string;                    // "rules" (default) | "cloud"
  referentialIntegrity?: boolean;   // consistent labels, EMAIL_1
  tokenize?: boolean;               // reversible tokens, EMAIL_K7Q2
  allowlist?: string[] | null;      // values never redacted
  allowlistDomains?: string[] | null; // domains never redacted (EMAIL/URL)
  detectDates?: boolean;            // include DOB / date of death
  cache?: boolean;                  // reuse results for identical input
}
```

**What is looked for**

| Parameter | Default | Description |
|---|---|---|
| `text` | — | Input text to scan. Longer than `maxInputLength` throws. |
| `countries` | `null` | ISO 3166-1 alpha-2 codes that define **scope**. `null` loads all 31. This never gates what is looked for: a detection attributed elsewhere is flagged `outOfScope`, never dropped. A bare string throws `TypeError`. See [Country codes](#country-codes). |
| `countryHint` | `null` | A **prior only**. Resolves an ambiguous value without narrowing scope. See [Country Hints](#country-hints). |
| `detectDates` | `false` | Include `DOB` and `DATE_OF_DEATH`. Off by default: a bare date without keyword or structural context is deferred to the cloud tier. |

**How the output looks** — pick at most one of the first three.

| Parameter | Default | Description |
|---|---|---|
| *(none)* | — | Default: each span becomes `[ENTITY_TYPE]`. |
| `referentialIntegrity` | `false` | Consistent label per distinct value (`EMAIL_1`), persisting **on the instance** across calls. See [Referential Integrity](#referential-integrity). |
| `tokenize` | `false` | Reversible token per value (`EMAIL_K7Q2`), with the mapping in `result.tokens` for [`restore()`](#restoretext-tokens). Unique to the **call**. Cannot be combined with `referentialIntegrity`. See [Reversible tokenization](#reversible-tokenization). |
| `allowlist` | `null` | Values never to redact, whole-span and case-insensitive, merged with the instance's list. Structured identifiers (IBAN, phone, VAT, …) also match across spacing and hyphenation. Applies to cloud-tier types too. See [Allowlist](#allowlist). |
| `allowlistDomains` | `null` | Domains whose addresses are never redacted, e.g. `["acme.be"]`. Applies to `EMAIL` and `URL` only, and covers subdomains. See [Allowlist](#allowlist). |

**Long documents and tiers**

| Parameter | Default | Description |
|---|---|---|
| `mode` | `"rules"` | `"rules"` runs locally and synchronously. `"cloud"` must go through [`redactAsync()`](#redactasynctext-options) — `redact()` is synchronous and a network call cannot be. See [Cloud tier](#cloud-tier). |
| `context` | `null` | Share country evidence across the chunks of one document. Pass the same `DocumentContext` to every chunk. Disables the cache. See [Chunked documents](#chunked-documents). |
| `chunkOffset` | `0` | Where this chunk starts in the whole document. Only rebases spans recorded in `context`; returned detections stay relative to `text`. |
| `cache` | `true` | Reuse the result for an identical input and configuration. |

TypeScript has no `coref` option; the Python SDK accepts one as a reserved
no-op.

#### `redactAsync(text, options?)`

```ts
function redactAsync(text: string, options?: RedactOptions): Promise<RedactResult>;
```

The asynchronous entry point, and the only way to reach the [cloud
tier](#cloud-tier). With `mode: "rules"` (the default) it resolves immediately
with exactly what `redact()` returns, so a caller that may or may not use the
cloud tier can keep one code path:

```ts
const result = await redactAsync(text, { countries: ["BE"], mode: "cloud" });
```

Takes the same `RedactOptions` as `redact()`. Options the service cannot honour
throw rather than being ignored — see [Cloud tier](#cloud-tier).

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

#### `restore(text, tokens)`

```ts
function restore(text: string, tokens: Record<string, string>): string;
```

Put the original values back into text that derives from a `tokenize: true`
result — typically an LLM's reply to the tokenized prompt. `tokens` is
`result.tokens`. See [Reversible tokenization](#reversible-tokenization).

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

The `EuRedact` class exposes `redact()`, `redactAsync()`, `redactBatch()`,
`clear()` and `addCustomPattern()`.

```ts
new EuRedact({
  maxInputLength?: number,   // default 10_485_760 (~10 MB)
  allowlist?: string[] | null,
})
```

| Parameter | Default | Description |
|---|---|---|
| `maxInputLength` | `10_485_760` | Longest document `redact()` accepts, in characters. Above it, it throws — split the input or raise the ceiling. |
| `allowlist` | `null` | Values never to redact, for every call on this instance. Merged with the per-call `allowlist`. See [Allowlist](#allowlist). |
| `allowlistDomains` | `null` | Domains never to redact, for every call on this instance. |

The result cache, referential-integrity labels and custom patterns are all per
instance, which is what makes one instance per tenant the right default.
`clear()` releases the cache and the label mapping.

### Return Types

#### `RedactResult`

```ts
interface RedactResult {
  redactedText: string;       // The input text with PII replaced
  detections: Detection[];    // All PII spans found
  source: string;             // Detection backend ("rules")
  degraded: boolean;          // True if the engine fell back to a simpler mode
  tokens: Record<string, string>; // token -> original value; only with tokenize: true
  exempted: Exemption[];          // spans the allowlist kept, with the rule that matched
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
  tokens: Record<string, string>;             // token -> original value; only with tokenize: true
}
```

#### `EntityType`

String enum with all supported PII categories:

```
PERSON_NAME       ADDRESS           BANK_ACCOUNT      BIC
CREDIT_CARD       PHONE             EMAIL             DOB
DATE_OF_DEATH     NATIONAL_ID       SSN               TAX_ID
PASSPORT          DRIVERS_LICENSE   RESIDENCE_PERMIT  LICENSE_PLATE
VIN               VAT               POSTAL_CODE       IP_ADDRESS
IPV6_ADDRESS      MAC_ADDRESS       HEALTH_INSURANCE  HEALTHCARE_PROVIDER
CHAMBER_OF_COMMERCE  IMEI          GPS_COORDINATES   UUID
SOCIAL_HANDLE     SECRET            INTERNAL_ID       OTHER

Cloud tier only — the rule engine never emits these, because there is no shape
to match on. That is precisely why the model exists:

ORGANISATION_NAME JOB_TITLE         MEDICAL_CONDITION SENSITIVE_ATTRIBUTE
BIOMETRIC_REF     FINANCIAL_AMOUNT  QUASI_IDENTIFIER  CREDENTIAL
URL
```

`INTERNAL_ID` — an employee, badge or customer number tied to a person — is
emitted **only** when an explicit label names it (`medarbejdernummer:`,
`Personalnummer:`, `Employee No:`, `Betriebsstättennr.`, `Badge`). There is no
pattern for one, because there is no shape for one: without the label, a digit
run is not distinguishable from any other. The type exists so that a labelled
employee number is filed correctly instead of being claimed by the phone
pattern.

### What a label in front of a value decides

A label touching the left edge of a value decides what that value is called.
The label may be the abbreviation or the word it abbreviates — `BSN:` and
`Burgerservicenummer:` both reach `NATIONAL_ID` — and it may be the official
name in the document's own language:

| label | type |
|---|---|
| `Companies House Registration:`, `Company Registration Number:` | `CHAMBER_OF_COMMERCE` |
| `Sozialversicherungsnummer:` | `SSN` |
| `Passport No.:`, `Paspoortnummer:` | `PASSPORT` |
| `AGB-code:`, `LANR`, `GMC Number:` | `HEALTHCARE_PROVIDER` |
| `Medical Card No.:` | `HEALTH_INSURANCE` |
| `sort code`, `account number` | `BANK_ACCOUNT` |
| `TAN-activatiecode`, `activation code` | `SECRET` |

A label can also *rule a type out*. A four-digit run is not a postal code when
a founding or payment participle introduces it (`Opgericht in 2016`,
`Fondée en 2017`) or when it sits in a telephone parenthetical (`(toest. 3841)`,
`(ext. 2219)`). Postal codes that merely look like years are unaffected —
Antwerp's `2018` in `rustige ligging in 2018` is still a `POSTAL_CODE`.

A label never moves a span; it only decides the label. Which characters are
masked is unchanged either way.

For custom patterns, `entityType` is a plain string (e.g. `"EMPLOYEE_ID"`).

## Batch processing and concurrency

`redactBatch` loads the country configurations once instead of per document,
which is the whole reason to prefer it to a loop:

```ts
import { redactBatch } from "euredact";

const docs = ["Mijn BSN is 111222333.", "IBAN NL91ABNA0417164300."];

redactBatch(docs, { countries: ["NL"] }).map((r) => r.redactedText);
// [ 'Mijn BSN is [NATIONAL_ID].', 'IBAN [BANK_ACCOUNT].' ]
```

`redactBatch` is **synchronous**, and deliberately so: the rules engine is
CPU-bound, so wrapping it in a promise would add scheduling without adding
parallelism. There is no `redactBatchAsync`. Where the Python SDK offers
`aredact_batch(..., max_concurrency=n)` — it can offload to a thread pool —
this SDK has one thread, so the honest equivalent is either `redactBatch` on the
main thread or real workers:

```ts
// Keep the event loop responsive across a large batch.
import { redactBatch } from "euredact";

async function* redactInChunks(docs: string[], size = 200) {
  for (let i = 0; i < docs.length; i += size) {
    yield redactBatch(docs.slice(i, i + size), { countries: ["NL"] });
    await new Promise((resolve) => setImmediate(resolve));
  }
}
```

For genuine parallelism use `node:worker_threads` and give each worker its own
`EuRedact`; for true throughput at scale that is the only thing that helps,
because the cost is regex matching rather than waiting.

`redactAsync` is for the **cloud tier**, not for parallelism — it exists because
a network call cannot be synchronous. With `mode: "rules"` it resolves
immediately with exactly what `redact()` returns. Cloud calls *are* I/O, so
those parallelise properly:

```ts
import { redactAsync } from "euredact";

const results = await Promise.all(
  docs.map((d) => redactAsync(d, { countries: ["BE"], mode: "cloud" })),
);
```

Bound that yourself if the batch is large — the service enforces quotas and will
answer `429`, which the client honours via `Retry-After`.

### Reuse one instance

The module-level functions share a single hidden instance, which is usually what
you want. Construct your own when the configuration must be per-tenant: custom
patterns, an allowlist and the result cache all live on the instance.

```ts
import { EuRedact } from "euredact";

const engine = new EuRedact({ allowlist: ["ACME Corporation"] });
engine.addCustomPattern("CASE_REF", String.raw`CASE-\d{8}`);

engine.redactBatch(
  ["ACME Corporation, ref CASE-20260401, BSN 111222333."],
  { countries: ["NL"] },
)[0].redactedText;
// 'ACME Corporation, ref [CASE_REF], BSN [NATIONAL_ID].'
```

### Tokens and referential labels do not span a batch

`tokenize: true` mints tokens **per call**, so item 3 of a batch does not share a
token with item 1 even for the same value. If two documents must agree on a
label, redact them as one text, or use `referentialIntegrity: true`, whose
`TYPE_n` numbering is per instance rather than per call.

## Cloud tier

> **Status: private alpha.** The cloud tier is in closed testing — it is **not**
> in public beta and is not generally available. Keys are issued to alpha
> participants only, and the request/response surface may still change between
> releases. The rules engine below is unaffected and is the supported path:
> `mode="rules"` is the default and carries no alpha caveat.

The rule engine catches what has a shape: IBANs, national IDs, phone numbers,
anything with a checksum. It cannot catch what does not — a person's name, an
employer, a diagnosis, a job title. The cloud tier adds a fine-tuned model
asked only *what did the rules miss?*

```ts
import { configure, redactAsync } from "euredact";

configure({ apiKey: "erk_..." });               // or set EUREDACT_API_KEY
const result = await redactAsync(text, { countries: ["BE"], mode: "cloud" });

result.source;                                   // "cloud"
result.detections.map(d => [d.entityType, d.text]);
// [["PERSON_NAME", "Bas Verhoeven"], ["PHONE", "+32 ..."]]
```

**`redact()` is synchronous and cannot serve the cloud tier**, so
`redact(text, { mode: "cloud" })` throws and names `redactAsync`. It never
falls back to rules-only output: a caller who believes names and diagnoses were
checked, and ships a document that only had its phone numbers masked, is the
one failure this library must not have.

`redactAsync` with `mode: "rules"` resolves immediately with exactly what
`redact()` returns, so a caller that may or may not use the cloud tier can hold
one code path.

Retries carry an `Idempotency-Key`, so a retry after a timeout cannot bill
twice. `Retry-After` is obeyed. A document that outlives the service's sync
window is polled transparently. Oversized input rejects with `TooLargeError`
(413): the service refuses it rather than chunking, because the model has never
seen a chunk boundary.

Options the service cannot honour reject rather than being ignored: multiple
`countries`, `countryHint`, `context`/`chunkOffset` and `referentialIntegrity`.
`tokenize`, `allowlist` and `allowlistDomains` are honoured: the SDK applies them to the spans the
service returns and rebuilds the text from those.

The package stays **zero-dependency** — the client uses the platform's own
`fetch`. Node 18+ provides one; on Node 16 the rules engine is unaffected and a
`fetchImpl` can be supplied.

### What leaves your machine

Be precise about this, because it is the question a security review asks first
and the answer is not "only the leftovers".

In `mode: "cloud"` the **whole document** is sent to the service over TLS. The
local rules engine does not run first and nothing is stripped before the
request: the cloud path is taken before normalisation, and the request body is
the text you passed in.

```
mode: "cloud"     your text ──TLS──▶ service (its own rules engine + model)
                  masked text ◀────── spans + redactedText
```

The service runs the same rules engine server-side and adds the model, which is
why cloud results are a superset of rules results rather than a different
answer. The local SDK touches the response, not the request: when `tokenize` or
an `allowlist` is set it rebuilds the masked text from the spans the service
returned, and it verifies every span still matches the document first — which is
load-bearing here, because service offsets are code points and JavaScript slices
UTF-16 units.

`detectDates` is the one option not forwarded: the service always runs with
dates on, because that is what the model was trained against. It can only cause
more to be detected, never less.

### Keeping identifiers local

If your requirement is that structured identifiers **never leave your
infrastructure**, do not use `mode: "cloud"` for that — compose the local engine
with whatever model you like instead. This is what `tokenize` is for:

```ts
import { redact, restore } from "euredact";

const prompt = "Stuur een mail naar Bas Verhoeven (bas@example.nl) over NL91ABNA0417164300.";

// 1. Mask locally. Nothing has left the process.
const local = redact(prompt, { countries: ["NL"], tokenize: true });
local.redactedText;
// 'Stuur een mail naar Bas Verhoeven (EMAIL_S5SH) over BANK_ACCOUNT_5XXR.'
local.tokens;
// { BANK_ACCOUNT_5XXR: 'NL91ABNA0417164300', EMAIL_S5SH: 'bas@example.nl' }

// 2. Send only the masked text to any model, ours or someone else's.
const answer = await callYourModel(local.redactedText);

// 3. Put the real values back locally.
restore(answer, local.tokens);
```

The token suffixes are random per call, so yours will differ.

**Read that output carefully: `Bas Verhoeven` is still there.** That is the whole
trade-off and it is why the cloud tier exists. The local engine masks what has a
shape — the IBAN and the address — and cannot mask a name, an employer or a
diagnosis, because it cannot find them. So this pattern keeps every structured
identifier inside your process and sends the prose, names included.
`mode: "cloud"` sends everything and gets both back.

These are different trust boundaries, not two speeds of the same thing. If names
must be masked *and* identifiers must not leave your infrastructure, neither
option does that today; run the model yourself against `local.redactedText`.


## `NAME` is now `PERSON_NAME`

The canonical type name is `PERSON_NAME`; `NAME` is a legacy alias, exactly as
`IBAN` aliases `BANK_ACCOUNT`. The placeholder written into redacted text is
`[PERSON_NAME]`.

Nothing could have depended on the old value: the type is cloud-only and the
cloud tier was stubbed until this release, so it was never emitted. Code
matching the *string* `"NAME"` should be updated; `LEGACY_TYPE_ALIASES`
publishes the mapping, and `STREET_ADDRESS` → `ADDRESS` and
`NATIONALITY_ETHNICITY` → `SENSITIVE_ATTRIBUTE` are recognised the same way.

## What `countries` actually controls

This is the parameter most often misread, and reading it wrongly leads to
under-redaction in exactly the case you care about — a foreign identifier in a
domestic document. So, precisely:

> `countries` decides how a detection is **attributed and scored**.
> It does **not** decide what gets **found**.

Country-specific patterns for every supported country run on every document,
whatever you declare. Declaring `countries: ["NL"]` does not switch the Belgian
patterns off; it says "this document is Dutch", and anything Belgian that turns
up is still detected and still masked — it is just flagged as sitting outside
what you declared.

The same Belgian national number, under four different calls:

```ts
import { redact } from "euredact";

const text = "Rijksregisternummer 85.07.30-033.61 van onze klant.";

for (const options of [{ countries: ["NL"] },
                       { countries: ["BE"] },
                       {},
                       { countries: ["NL"], countryHint: ["BE"] }]) {
  const result = redact(text, options);
  const [detection] = result.detections;
  console.log(result.redactedText, "|", result.detectionMode,
              "| country:", detection.country,
              "| countryConfidence:", detection.countryConfidence,
              "| outOfScope:", detection.outOfScope);
}
```

```
Rijksregisternummer [NATIONAL_ID] van onze klant. | declared | country: BE | countryConfidence: 0 | outOfScope: true
Rijksregisternummer [NATIONAL_ID] van onze klant. | declared | country: BE | countryConfidence: 0.8807970779778823 | outOfScope: false
Rijksregisternummer [NATIONAL_ID] van onze klant. | inferred | country: BE | countryConfidence: 0 | outOfScope: false
Rijksregisternummer [NATIONAL_ID] van onze klant. | declared | country: BE | countryConfidence: 0.8807970779778823 | outOfScope: true
```

**The masked output is byte-identical in all four.** What moved is the metadata.

| You pass | Effect on what is found | Effect on labelling |
|---|---|---|
| `countries: ["NL"]` | None — every country's patterns still run | Attributed normally; a non-Dutch hit gets `outOfScope: true` and `countryConfidence: 0` |
| `countries: ["BE"]` | None | The Belgian hit is corroborated: `countryConfidence` ~0.88, `outOfScope: false` |
| `countries` omitted | None | `detectionMode: "inferred"`; the country is inferred from the document and nothing is out of scope, because nothing was declared |
| `countryHint: ["BE"]` | None | A *prior*: it corroborates Belgian attribution **without** widening or narrowing scope, so `out_of_scope` still reflects `countries` alone |

### How to use each one

- **`countries: [...]`** — you know where the document is from. Use it. It
  improves attribution and makes `out_of_scope` meaningful, and it is the
  cheapest path because country inference is skipped.
- **`countries` omitted** — you do not know. The engine infers from the document
  and reports `inferredCountries` with confidences.
- **`countryHint: [...]`** — you have a weak signal (the customer's billing
  country, the mailbox a document arrived in) that should resolve ambiguity
  without declaring scope. Added in 0.3.2 precisely so that a hint could not be
  mistaken for a scope restriction.

### Why it works this way

Until 0.3.2, `countries` *did* gate detection, and 0.3.3 fixed the remaining
case where it "could change which spans were found, not just how they were
labelled". Both were changed deliberately: a redaction library that hides a
Belgian national number because you told it the document was Dutch has failed
at the only job it has. Scoping is a reporting concern; masking is not.

The practical consequence: **do not use `countries` as a filter.** If you only
want Dutch detections in your output, filter on
`detection.country === "NL"` or on `detection.outOfScope` after the call —
the value was still masked in the text either way.

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
schemes. Of the national-ID values in our corpus that pass any country's checksum,
34.7% pass more than one country's (32,827 of 94,528), so the digits alone
cannot decide it — the *document* does.

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

## Reversible tokenization

`tokenize: true` is for text that has to come back. Each value is replaced by a
token that names its type and nothing else, and the result carries the mapping
that turns tokens back into values:

```ts
import { redact, restore } from "euredact";

const prompt = "Write an email to Joren at joren.janssens@euredact.be or call +32 475 12 34 56 about the invoice.";
const result = redact(prompt, { countries: ["BE"], tokenize: true });
console.log(result.redactedText);
// "Write an email to Joren at EMAIL_K7Q2 or call PHONE_P4RT about the invoice."
console.log(result.tokens);
// { EMAIL_K7Q2: "joren.janssens@euredact.be", PHONE_P4RT: "+32 475 12 34 56" }

const reply = await callYourLlm(result.redactedText);  // sees tokens, never the values
console.log(restore(reply, result.tokens));
// the reply, with the real address and number back in it
```

The suffixes are random; yours will differ. With the [cloud tier](#cloud-tier)
the name is tokenized too (`PERSON_NAME_W3NB`), since person names have no
shape for the rules tier to match on.

Within one call the same value gets the same token, so a prompt that names
someone twice still reads as one person. Across calls it gets a different
token: nothing is retained on the instance, `result.tokens` is the only copy,
and two tokenized documents never reveal that they share a value. That is the
opposite retention model from `referentialIntegrity`, which is why the two
cannot be combined. `redactBatch` tokenizes each text on its own.

A token is `TYPE_` plus four characters from `ABCDEFGHJKLMNPQRSTUVWXYZ23456789`
(no vowels, no `0`/`1`/`I`/`O`). Tokens are kept clear of any token-shaped
string already in the document, so an LLM's reply to a tokenized prompt can
itself be redacted without `restore()` putting the wrong value back.
`restore()` replaces every occurrence, including a token an LLM glued to other
characters (`EMAIL_P4RTs`) — leaving a token behind is the worse failure.

Works in cloud mode via `redactAsync`: the SDK rebuilds the text from the spans
the service returns, which is exactly what the service built its own output
from.

## Allowlist

Values a caller declares are not PII to them — their own organisation's name,
their own addresses. Set it per call, on the instance, or both; the two merge:

```ts
import { EuRedact } from "euredact";

const sdk = new EuRedact({ allowlist: ["ACME NV", "info@acme.be"] });

const text = "ACME NV: mail info@acme.be or jan@acme.be about IBAN NL91 ABNA 0417 1643 00.";
console.log(sdk.redact(text, { countries: ["NL"] }).redactedText);
// "ACME NV: mail info@acme.be or [EMAIL] about IBAN [BANK_ACCOUNT]."

console.log(sdk.redact(text, { countries: ["NL"], allowlist: ["jan@acme.be"] }).redactedText);
// "ACME NV: mail info@acme.be or jan@acme.be about IBAN [BANK_ACCOUNT]."
```

Matching is whole-span and case-insensitive. A bare string
(`allowlist: "ACME NV"`) throws `TypeError` rather than being iterated into
single letters that exempt nothing. Works in cloud mode via `redactAsync` —
including on types only the model finds, such as `ORGANISATION_NAME` — and
together with `tokenize`.

### Spacing and punctuation

For **structured identifiers** separators are presentational, so an allowlisted
value matches however the document writes it:

```ts
const sdk = new EuRedact({ allowlist: ["NL91ABNA0417164300"] });
sdk.redact("Pay to NL91 ABNA 0417 1643 00.", { countries: ["NL"] }).redactedText;
// 'Pay to NL91 ABNA 0417 1643 00.'   — exempt, despite the spacing
```

Applies to `BANK_ACCOUNT`, `BIC`, `CREDIT_CARD`, `PHONE`, `VAT`, `NATIONAL_ID`,
`SSN`, `TAX_ID`, `PASSPORT`, `DRIVERS_LICENSE`, `RESIDENCE_PERMIT`,
`HEALTH_INSURANCE`, `CHAMBER_OF_COMMERCE`, `IMEI` and `VIN`. It widens the
*spelling*, never the *scope*: a different account is still redacted. Free-text
types stay literal, because `jan.devries@acme.be` and `jandevries@acme.be` are
different mailboxes at most providers.

### Exempting a whole domain

```ts
const sdk = new EuRedact({ allowlistDomains: ["acme.be"] });
sdk.redact("Mail jan@acme.be or piet@acme.be", { countries: ["NL"] }).redactedText;
// 'Mail jan@acme.be or piet@acme.be'
```

`EMAIL` and `URL` only, covering subdomains (`mail.acme.be`). The match is on a
label boundary, so `acme.be` does **not** exempt `evilacme.be`. Entries may be
written `acme.be`, `@acme.be` or `.acme.be`.

There are deliberately **no wildcards**. The allowlist is the only option that
turns redaction *off*, so an over-broad entry fails toward under-redaction and
does so silently.

### What was exempted

```ts
const r = redact("Mail jan@acme.be", { countries: ["NL"], allowlistDomains: ["acme.be"] });
for (const e of r.exempted) console.log(e.entityType, e.text, e.rule, e.ruleKind);
// EMAIL jan@acme.be acme.be domain
```

`Exemption` carries `entityType`, `start`, `end`, `text`, the `rule` that
matched as you wrote it, and `ruleKind` (`"value"` or `"domain"`). An exempted
span is absent from `detections`, so `exempted` is the only record that it was
found at all.

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

Measured on one core (Apple Silicon M3 Pro, Node 22.12), all 31 countries
loaded, `detectDates: true`, cache off, over two cohorts sampled evenly from the
corpus: 3,000 distinct short records and 611 distinct real documents. Median per
document, 10th–90th percentile in brackets:

| Input | Latency | Throughput |
|---|---:|---:|
| Short record (~190 chars) | 154 µs <br><sub>89 – 237</sub> | 6,494 docs/s |
| Real document (~3,450 chars) | 1.43 ms <br><sub>1.04 – 1.96</sub> | 699 docs/s |

Cost tracks identifier density rather than length: the per-candidate cue and
suppressor checks dominate, so a form-like document dense in national IDs costs
several times an ordinary chat log of the same size.

No optional accelerator is needed or offered. The Python SDK ships an
`[fast]` extra (RE2 / Aho-Corasick) because CPython's regex engine is the
bottleneck there; V8's has literal prefilters that make it unnecessary here.
Measured on the same 611 documents, this SDK runs about 6–7× faster than the
accelerated Python path, so adding a native addon — and with it the loss of
bundler, edge-runtime and Deno compatibility — would buy nothing.

| Package | |
|---|---:|
| Tarball | 150 kB |
| Unpacked | 629 kB |
| Runtime dependencies | **0** |

Measured with `npm pack --dry-run` at 0.5.1. A stale duplicate of this section
previously quoted 0.02 ms and 86 KB; both were wrong, and the figures above are
the measured ones.

## CommonJS

```js
const { redact } = require("euredact");
```

## License

Apache-2.0
