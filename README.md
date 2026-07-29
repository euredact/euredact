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
- **25+ PII entity types:** national IDs, IBANs, phone numbers, email, VAT numbers, license plates, credit cards, BIC/SWIFT, VIN, IMEI, GPS coordinates, UUIDs, social handles, IP/IPv6, MAC addresses, secrets/API keys, and more
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

```
NATIONAL_ID       IBAN              PHONE             EMAIL
CREDIT_CARD       VAT               TAX_ID            SSN
PASSPORT          DRIVERS_LICENSE   LICENSE_PLATE      POSTAL_CODE
BIC               VIN               IMEI              SECRET
IP_ADDRESS        IPV6_ADDRESS      MAC_ADDRESS        UUID
GPS_COORDINATES   SOCIAL_HANDLE     DOB               DATE_OF_DEATH
HEALTH_INSURANCE  HEALTHCARE_PROVIDER  CHAMBER_OF_COMMERCE
RESIDENCE_PERMIT  NAME              ADDRESS
```

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

- **Python:** [`euredact-python/README.md`](euredact-python/README.md) -- `redact()`, `aredact()`, `redact_batch()`, `aredact_batch()`, `redact_iter()`, `add_custom_pattern()`, `available_countries()`
- **TypeScript:** [`euredact-ts/README.md`](euredact-ts/README.md) -- `redact()`, `redactBatch()`, `addCustomPattern()`, `availableCountries()`

## Performance

Measured on one core with all 31 countries loaded and date detection enabled,
against 3,000 short records and 611 real documents. Cost scales with document
length, so the input size is stated rather than averaged away.

| Input | Python | Python `[fast]` | Node.js |
|---|---:|---:|---:|
| Short record (186 chars) | 723 µs | **496 µs** | **155 µs** |
| Real document (3,424 chars) | 10.4 ms | **5.4 ms** | **1.56 ms** |
| Memory per country | ~50 KB | ~50 KB | ~50 KB |

`pip install euredact[fast]` adds two optional accelerators (`google-re2`,
`pyahocorasick`). Neither changes what is detected — `tests/test_scan_path_parity.py`
runs every available scan path against the plain-Python one and requires them to
agree.

The TypeScript SDK needs no such extra and offers none: V8's regex engine has
literal prefilters CPython lacks, so on the same documents it runs about 3×
faster than the accelerated Python path. Adding a native addon there would cost
bundler, edge-runtime and Deno compatibility for nothing.

### Accuracy

Full corpus, 152,300 documents:

| | recall | precision |
|---|---:|---:|
| With country hints | 99.6% | 98.6% |
| Blind (no `countries` passed) | 99.6% | 98.3% |

Blind detection is within 0.3 points of hinted, so the engine does not need to
be told the country.

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
