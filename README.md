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
# "Mijn BSN is [NATIONAL_ID] en IBAN [IBAN]."
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
- **Priority-aware deduplication:** validated matches (checksum) > custom patterns > regex-only; suppression zones prevent false positives from claiming spans of failed-validation matches
- **Pseudonymization:** consistent pseudonym mapping within a session
- **Fast:** sub-millisecond per page, ~2,000 records/second
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
    |                     Failed-validation spans become suppression zones
    v
[Pass 2b: Suppression] -- Remove false positives (currency amounts, units,
    |                      references, overlapping matches in suppression zones)
    v
[Deduplication] -- Priority-aware: validated > custom > regex-only
    |               Within same tier, longer span wins
    v
[Replacement] -- Right-to-left substitution with [ENTITY_TYPE] labels
    |              or consistent pseudonyms
    v
RedactResult
```

## API Reference

See the package-specific READMEs for full API documentation:

- **Python:** [`euredact-python/README.md`](euredact-python/README.md) -- `redact()`, `aredact()`, `redact_batch()`, `aredact_batch()`, `redact_iter()`, `add_custom_pattern()`, `available_countries()`
- **TypeScript:** [`euredact-ts/README.md`](euredact-ts/README.md) -- `redact()`, `redactBatch()`, `addCustomPattern()`, `availableCountries()`

## Performance

| Metric | Python | Node.js |
|---|---|---|
| Latency per page (~500 words) | < 1 ms | ~0.02 ms |
| Throughput | ~2,000 records/s | ~50,000 records/s |
| Memory per country | ~50 KB | ~50 KB |

Python optionally uses `pyahocorasick` for Aho-Corasick accelerated pattern matching on large batches.

## Repository Structure

```
euredact-python/    Python SDK (pip install euredact)
euredact-ts/        TypeScript/Node.js SDK (npm install euredact)
```

## License

Apache 2.0
