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
- **Priority-aware deduplication:** validated (checksum) > custom > regex-only
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
  countries?: string[] | null; // Country codes (e.g. ["NL", "BE"]) — null loads all
  pseudonymize?: boolean;      // Replace with consistent pseudonyms (default: false)
  detectDates?: boolean;       // Include DOB/date-of-death detections (default: false)
  cache?: boolean;             // Enable result caching (default: true)
}
```

| Parameter | Default | Description |
|---|---|---|
| `countries` | `null` | ISO 3166-1 alpha-2 codes to restrict detection. `null` loads all 31 countries. |
| `pseudonymize` | `false` | Replace PII with consistent pseudonyms instead of entity-type labels. |
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
  confidence: string;              // Confidence level
}
```

#### `EntityType`

String enum with all supported PII categories:

```
NAME              ADDRESS           IBAN              BIC
CREDIT_CARD       PHONE             EMAIL             DOB
DATE_OF_DEATH     NATIONAL_ID       SSN               TAX_ID
PASSPORT          DRIVERS_LICENSE   RESIDENCE_PERMIT  LICENSE_PLATE
VIN               VAT               POSTAL_CODE       IP_ADDRESS
IPV6_ADDRESS      MAC_ADDRESS       HEALTH_INSURANCE  HEALTHCARE_PROVIDER
CHAMBER_OF_COMMERCE  IMEI          GPS_COORDINATES   UUID
SOCIAL_HANDLE     SECRET            OTHER
```

For custom patterns, `entityType` is a plain string (e.g. `"EMPLOYEE_ID"`).

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

When you know which countries appear in your data, pass them explicitly:

```ts
const result = redact(text, { countries: ["NL", "BE"] });
```

This restricts pattern matching to Dutch and Belgian rules (plus shared patterns
and custom patterns). Benefits:

- **Fewer false positives.** A 9-digit number that passes the Dutch BSN checksum
  won't also be tested against unrelated country patterns.
- **Faster.** Fewer patterns to compile and scan.

## Pseudonymization

When `pseudonymize: true`, each unique PII value is mapped to a consistent
pseudonym:

```ts
const result = redact(
  "BSN 123456782 en later weer 123456782",
  { countries: ["NL"], pseudonymize: true }
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
    |                     Failed-validation spans become suppression zones
    v
[Pass 2b: Suppression] -- Remove false positives (currency amounts, units,
    |                      references, overlapping matches in suppression zones)
    v
[Deduplication] -- Priority-aware: validated > custom > regex-only
    |               Within same tier, longer span wins
    v
[Replacement] -- Right-to-left substitution with [ENTITY_TYPE] labels
    |              or pseudonyms
    v
RedactResult
```

### Suppression Zones

When a regex matches a pattern that has a checksum validator but the checksum
fails, the matched span becomes a "suppression zone." Any purely regex-based
detection fully contained within that zone is suppressed as a false positive.

### Deduplication Priority

1. **Validated patterns** (checksum passes) -- highest priority
2. **Custom patterns** (registered via `addCustomPattern()`)
3. **Regex-only patterns** (no validator) -- lowest priority

Within the same tier, the longer span wins.

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
