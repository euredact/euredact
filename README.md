# euRedact

**European PII detection and redaction SDK** -- available for Python and Node.js.

euRedact detects and redacts personally identifiable information across **31 European countries** using a two-pass rule engine: liberal pattern matching followed by checksum validation, context-aware suppression, and priority-based deduplication. Zero required dependencies in both languages.

## Quick Start

### Python

```bash
pip install euredact
```

```python
import euredact

result = euredact.redact("Mijn BSN is 111222333 en IBAN NL91ABNA0417164300.")
print(result.redacted_text)
# "Mijn BSN is [NATIONAL_ID] en IBAN [BANK_ACCOUNT]."
```

### Node.js / TypeScript

```bash
npm install euredact
```

```ts
import { redact } from "euredact";

const result = redact("Mijn BSN is 123456782 en email jan@example.com", {
  countries: ["NL"],
});
console.log(result.redactedText);
// "Mijn BSN is [NATIONAL_ID] en email [EMAIL]"
```

## Features

- **31 European countries** with country-specific patterns
- **41 PII entity types:** national IDs, IBANs, phone numbers, email, VAT numbers, license plates, credit cards, BIC/SWIFT, VIN, IMEI, GPS coordinates, UUIDs, social handles, IP/IPv6, MAC addresses, secrets/API keys, and more
- **Optional [cloud tier](#cloud-tier) (private alpha):** `mode="cloud"` adds a fine-tuned model for the categories that have no shape to match on — person names, organisations, job titles, diagnoses
- **Checksum validation:** IBAN (mod-97), Luhn (credit cards/IMEI), and 30+ country-specific validators (Dutch BSN 11-proof, Belgian national number, French NIR, etc.)
- **Secret/API key detection:** known-prefix patterns for AWS, GitHub, Stripe, OpenAI, Slack, JWT, SendGrid + Shannon entropy-based fallback for generic secrets near context keywords
- **Context-aware:** keyword proximity checks and structural detection (JSON field names, CSV headers) for ambiguous patterns like dates of birth
- **Custom patterns:** register your own regex patterns for domain-specific PII
- **Priority-aware deduplication:** validated matches (checksum, corroborated by the document's country) > custom patterns > regex-only; a failed checksum demotes same-type matches rather than deleting them, so it can never silence a detection
- **Country self-detection:** infers a document's countries from the entities that carry one — IBAN prefixes, `+CC` dialling codes, VAT prefixes, BIC, email ccTLDs — so an ambiguous value resolves without the caller naming a country. `countries` never gates what is looked for; it scores and flags
- **Referential integrity:** consistent label mapping within a session (same PII value always gets the same label)
- **Fast:** see [Performance](#performance)
- **Zero required dependencies** in both Python and Node.js
- **Thread-safe** (Python), immutable detection objects

### Supported Countries

| Region | Countries |
|---|---|
| Western Europe | AT, BE, CH, DE, FR, LU, NL |
| Southern Europe | CY, EL, ES, IT, MT, PT |
| Northern Europe | DK, EE, FI, IS, LT, LV, NO, SE |
| Eastern Europe | BG, CZ, HR, HU, PL, RO, SI, SK |
| British Isles | IE, UK |

### Detected PII Types

`EntityType` has **41 distinct values**. The rule engine emits the 30 that have
a shape to match on:

```
NATIONAL_ID       BANK_ACCOUNT      PHONE             EMAIL
CREDIT_CARD       VAT               TAX_ID            SSN
PASSPORT          DRIVERS_LICENSE   LICENSE_PLATE     POSTAL_CODE
BIC               VIN               IMEI              SECRET
IP_ADDRESS        IPV6_ADDRESS      MAC_ADDRESS       UUID
GPS_COORDINATES   SOCIAL_HANDLE     DOB               DATE_OF_DEATH
HEALTH_INSURANCE  HEALTHCARE_PROVIDER  CHAMBER_OF_COMMERCE
RESIDENCE_PERMIT  INTERNAL_ID       OTHER
```

The remaining 11 are the [cloud tier](#cloud-tier)'s. The rule engine never
emits them — there is no shape to match on, which is precisely why the model
exists:

```
PERSON_NAME       ADDRESS           ORGANISATION_NAME JOB_TITLE
MEDICAL_CONDITION SENSITIVE_ATTRIBUTE  BIOMETRIC_REF  FINANCIAL_AMOUNT
QUASI_IDENTIFIER  CREDENTIAL        URL
```

Two names are **legacy aliases** kept so existing code keeps working:
`IBAN` → `BANK_ACCOUNT` and `NAME` → `PERSON_NAME`. The alias resolves to the
canonical member, so the placeholder written into redacted text is
`[BANK_ACCOUNT]` and `[PERSON_NAME]`. `LEGACY_TYPE_ALIASES` publishes the full
mapping, which also recognises the string forms `STREET_ADDRESS` → `ADDRESS`
and `NATIONALITY_ETHNICITY` → `SENSITIVE_ATTRIBUTE`.

Each detection carries a `confidence` of `"high"` (a pattern matched and its
checksum passed), `"medium"` (the type comes from a label touching the span,
because no pattern of that type claimed it) or `"low"` (a pattern matched, its
checksum failed, and the document labels the span as that very type). Every
detection is masked regardless; filter on `confidence == "high"` if you need
only checksum-backed types.

## Cloud tier

> **Status: private alpha.** The cloud tier is in closed testing — it is **not**
> in public beta and is not generally available. Keys are issued to alpha
> participants only, and the request/response surface may still change between
> releases. The rules engine below is unaffected and is the supported path:
> `mode="rules"` is the default and carries no alpha caveat.

The rule engine catches what has a shape: IBANs, national IDs, phone numbers,
anything with a checksum. It cannot catch what does not — a person's name, an
employer, a diagnosis, a job title. The cloud tier sends the document to the
euRedact inference service, which runs the same deterministic rules engine and
then asks a fine-tuned model only *what did the rules miss?*

### Python

```bash
pip install 'euredact[cloud]'
```

```python
import euredact

euredact.configure(api_key="erk_...")          # or set EUREDACT_API_KEY
result = euredact.redact(text, countries=["BE"], mode="cloud")

result.source                                   # "cloud"
```

### Node.js / TypeScript

`redact()` is synchronous and a network call cannot be, so the cloud tier has
its own entry point. With `mode: "rules"` it resolves immediately with exactly
what `redact()` returns, so a caller that may or may not use the cloud tier can
hold one code path.

```ts
import { configure, redactAsync } from "euredact";

configure({ apiKey: "erk_..." });               // or EUREDACT_API_KEY
const result = await redactAsync(text, { countries: ["BE"], mode: "cloud" });
```

The TypeScript client uses the platform's own `fetch`, so the package stays
zero-dependency. Node 18+ provides one; on Node 16 the rules engine is
unaffected and a `fetchImpl` can be supplied. `engines` is unchanged at
`>=16.0.0`.

### It never falls back

`mode="cloud"` **raises** `NotConfiguredError` when the tier is not configured.
It does not quietly return rules-only output: a caller who believes names and
diagnoses were checked, and ships a document that only had its phone numbers
masked, is the one failure this library must not have. Options the service
cannot honour — multiple `countries`, `country_hint`, `context`/`chunk_offset`,
`referential_integrity` — raise rather than being silently dropped.

Retries carry an `Idempotency-Key`, so a retry after a timeout cannot bill
twice; `Retry-After` is obeyed; a document that outlives the service's sync
window is polled transparently. Oversized input raises `TooLargeError` (413) —
the service refuses it rather than chunking, because the model has never seen a
chunk boundary. `QuotaExceededError` (429) and `CloudError` cover the rest.

**The local rules engine is unchanged by any of this.** `mode="rules"` is the
default and behaves exactly as it did in 0.3.9; both packages keep zero required
dependencies, with the Python HTTP client behind the `cloud` extra.

## Custom Patterns

Register domain-specific PII patterns at runtime:

### Python

```python
import euredact

euredact.add_custom_pattern("EMPLOYEE_ID", r"EMP-\d{6}")

result = euredact.redact("Contact EMP-123456 for details")
print(result.redacted_text)
# "Contact [EMPLOYEE_ID] for details"
```

### Node.js

```ts
import { addCustomPattern, redact } from "euredact";

addCustomPattern("EMPLOYEE_ID", "EMP-\\d{6}");

const result = redact("Contact EMP-123456 for details");
// result.redactedText === "Contact [EMPLOYEE_ID] for details"
```

Custom patterns slot into the priority-aware deduplication system between validated built-in patterns and regex-only built-in patterns.

## Secret / API Key Detection

Built-in detection for API keys, tokens, and passwords:

**Known prefixes** (always active, high confidence):
- AWS Access Keys (`AKIA...`)
- GitHub tokens (`ghp_`, `gho_`, `ghs_`, `github_pat_`)
- Stripe keys (`sk_live_`, `pk_live_`, `sk_test_`, `pk_test_`)
- OpenAI / Anthropic keys (`sk-`, `sk-ant-`)
- Slack tokens (`xoxb-`, `xoxp-`, `xoxa-`, `xoxs-`)
- JWT tokens (`eyJ...`)
- SendGrid keys (`SG.`)

**Entropy-based fallback** (requires context keyword):
Any 32+ character high-entropy string near keywords like `key`, `token`, `secret`, `password`, `credential`, `auth`, `bearer` (plus translations in 12 European languages) is detected via Shannon entropy validation.

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
    |              or referential-integrity labels
    v
RedactResult
```

## API Reference

See the package-specific READMEs for full API documentation:

- **Python:** [`euredact-python/README.md`](euredact-python/README.md) -- `redact()`, `aredact()`, `redact_batch()`, `aredact_batch()`, `redact_iter()`, `add_custom_pattern()`, `available_countries()`, `configure()`
- **TypeScript:** [`euredact-ts/README.md`](euredact-ts/README.md) -- `redact()`, `redactAsync()`, `redactBatch()`, `addCustomPattern()`, `availableCountries()`, `configure()`

Both SDKs take `mode="rules"` (default) or `mode="cloud"` — see
[Cloud tier](#cloud-tier). In TypeScript the cloud path is `redactAsync()`,
because `redact()` is synchronous and a network call cannot be.

## Performance

Measured on one core (Apple Silicon M3 Pro, CPython 3.12.13, Node 22.12) with
all 31 countries loaded, `detect_dates` on and the cache off, over two cohorts
sampled evenly from the corpus: 3,000 short records (~190 chars) and 611 real
documents (~3,450 chars), each document distinct.

**Median** per document, with the 10th–90th percentile in brackets:

| Input | Python | Python `[fast]` | Node.js |
|---|---:|---:|---:|
| Short record (~190 chars) | 1.61 ms <br><sub>1.07 – 2.42</sub> | **1.14 ms** <br><sub>0.60 – 1.96</sub> | **154 µs** <br><sub>89 – 237</sub> |
| Real document (~3,450 chars) | 18.9 ms <br><sub>15.3 – 25.5</sub> | **9.4 ms** <br><sub>6.2 – 15.8</sub> | **1.43 ms** <br><sub>1.04 – 1.96</sub> |
| Memory per country | ~50 KB | ~50 KB | ~50 KB |

A spread is quoted because a single number misleads here: **cost tracks
identifier density, not length.** Documents of *identical* length range over 4×
— an ordinary chat log of 3,400 characters costs ~4.6 ms on `[fast]`, a
form-like document of the same size dense in national IDs and IBANs costs
~20 ms. Most of the time is not in the pattern scan but in the per-candidate
cue and suppressor checks that run for every match found, so the count of
*candidates* is what you pay for.

Making `\b` catch identifiers glued to a non-ASCII letter costs something, but
only where it must — next to a digit, one lookaround is exactly equivalent to
the three-way alternation 0.3.3 applied everywhere.

`pip install euredact[fast]` adds two optional accelerators (`google-re2`,
`pyahocorasick`). Neither changes what is detected — `tests/test_scan_path_parity.py`
runs every available scan path against the plain-Python one and requires them to
agree.

The TypeScript SDK needs no such extra and offers none: V8's regex engine has
literal prefilters CPython lacks, so on the same documents it runs about 6–7×
faster than the accelerated Python path. Adding a native addon there would cost
bundler, edge-runtime and Deno compatibility for nothing.

### Accuracy

Full corpus, 152,300 documents and 667,268 labelled entities. Span match plus
type match, so a value masked under the wrong label counts as both a miss and a
false positive — see `euredact-python/tests/metrics.py`, which reproduces this.

| | precision | recall | F1 |
|---|---:|---:|---:|
| With country hints | 99.8% | 99.8% | **99.8%** |
| Blind (no `countries` passed) | 99.6% | 99.8% | **99.7%** |

Blind detection is within 0.2 points of hinted on every measure — recall is
identical and precision costs 0.2 — so the engine does not need to be told the
country. False positives are the whole of the difference: 1,232 with hints,
2,372 blind.

Dates of birth are excluded from these figures: the rules engine emits one only
with a keyword or structural cue, because bare dates are the
[cloud tier](#cloud-tier)'s job. Measured on its own, DOB recall is 62.8%.

## Running the checks

```bash
make check     # lint + both test suites + conformance   (what CI runs)
make verify    # check + corpus sweep + cross-SDK parity + accuracy
```

`make check` needs nothing but the repo. `make verify` also runs the checks
that need the generated corpus, which lives outside the repository — set
`EUREDACT_CORPUS` if yours is not at `../Data-Generation`.

The split matters. The corpus checks are where ranking bugs surface: a sweep of
structural properties over ~187,000 documents found a case where a shorter
validated match re-cut a longer one and left part of an IP address in the
output. The same properties over twenty documents in CI showed nothing.

| target | what it checks |
|---|---|
| `make sweep` | offsets, non-overlap, determinism, cache transparency, and that `countries` never changes which spans are found |
| `make parity` | do both SDKs mask the same characters, over whole corpora |
| `make eval` | recall and precision |
| `make bench` | latency, both runtimes |

Run `make help` for the full list.

## Repository Structure

```
euredact-python/    Python SDK (pip install euredact)
euredact-ts/        TypeScript/Node.js SDK (npm install euredact)
```

## License

Apache 2.0
