# EuRedact

**European PII redaction SDK -- rule engine**

---

EuRedact is a pure-Python SDK for detecting and redacting personally identifiable
information (PII) in European text data. It covers 31 countries with a two-pass
architecture: liberal pattern matching in the first pass, followed by suppression
filters and checksum validation in the second. The library has zero required
dependencies, is thread-safe, and produces immutable detection objects.

## Quick Start

```bash
pip install euredact
```

```python
import euredact

result = euredact.redact("Mijn BSN is 111222333 en IBAN NL91ABNA0417164300.")
print(result.redacted_text)
# "Mijn BSN is [NATIONAL_ID] en IBAN [IBAN]."

print(result.detections)
# [Detection(entity_type=<EntityType.NATIONAL_ID>, ...), Detection(entity_type=<EntityType.IBAN>, ...)]
```

## Features

- **31 European countries** (see list below)
- **25+ PII entity types:** national IDs, IBANs, phone numbers, email addresses,
  VAT numbers, license plates, VIN, credit cards, BIC/SWIFT, IMEI, GPS
  coordinates, UUIDs, social handles, MAC addresses, IP/IPv6 addresses, health
  insurance numbers, passport numbers, driver's licenses, secrets/API keys, and more
- **Secret/API key detection:** known-prefix patterns for AWS, GitHub, Stripe,
  OpenAI, Slack, JWT, SendGrid, plus Shannon entropy-based detection for generic
  high-entropy tokens near context keywords
- **Custom patterns:** register your own regex patterns for domain-specific PII
  types at runtime via `add_custom_pattern()`
- **Checksum validation:** IBAN mod-97, Luhn (credit cards), and 30+ country-specific
  national ID checksums (e.g., Dutch BSN 11-proof, Belgian national number modulo)
- **Priority-aware deduplication:** when matches overlap, validated patterns
  (with passing checksums) win over custom patterns, which win over regex-only
  patterns; suppression zones prevent false positives from claiming spans that
  belong to a recognized-but-invalid pattern (e.g., license plate fragments
  inside an invalid IBAN)
- **Two-pass detection:** liberal regex matching followed by suppression filters
  that eliminate false positives
- **Context-aware:** keyword proximity checks and structural detection (JSON field
  names, CSV headers) for ambiguous patterns like dates of birth
- **Fast:** sub-millisecond per page, approximately 2,000 records/second
- **Zero required dependencies** (`pyahocorasick` optional for acceleration)
- **Thread-safe,** immutable `Detection` objects (frozen dataclasses)

### Supported Countries

| Region | Countries |
|---|---|
| Western Europe | AT, BE, CH, DE, FR, LU, NL |
| Southern Europe | CY, EL, ES, IT, MT, PT |
| Northern Europe | DK, EE, FI, IS, LT, LV, NO, SE |
| Eastern Europe | BG, CZ, HR, HU, PL, RO, SI, SK |
| British Isles | IE, UK |

## API Reference

EuRedact provides both module-level functions (using a shared singleton) and an
instance-based `EuRedact` class. The module-level API is the easiest way to get
started; the class-based API gives you isolated instances with separate caches
and custom pattern registrations.

### Module-Level Functions

#### `euredact.redact()`

```python
euredact.redact(
    text: str,
    *,
    countries: list[str] | None = None,
    mode: str = "rules",
    pseudonymize: bool = False,
    detect_dates: bool = False,
    cache: bool = True,
) -> RedactResult
```

Main entry point. Detects and redacts PII in the given text.

| Parameter | Default | Description |
|---|---|---|
| `text` | -- | Input text to scan. |
| `countries` | `None` | ISO 3166-1 alpha-2 codes to restrict detection (e.g. `["NL", "BE"]`). `None` loads all 31 countries. |
| `mode` | `"rules"` | Detection mode. Currently only `"rules"` is supported. |
| `pseudonymize` | `False` | Replace PII with consistent pseudonyms instead of entity-type labels. |
| `detect_dates` | `False` | Include date-of-birth and date-of-death detections. Off by default because bare dates without strong context are better handled by an LLM tier. When enabled, the engine applies keyword and structural (JSON/CSV) checks. |
| `cache` | `True` | Cache results for identical inputs. |

#### `euredact.redact_batch()`

```python
euredact.redact_batch(
    texts: list[str],
    *,
    countries: list[str] | None = None,
    mode: str = "rules",
    pseudonymize: bool = False,
    detect_dates: bool = False,
    cache: bool = True,
) -> list[RedactResult]
```

Redact PII from multiple texts at once. More efficient than calling `redact()` in
a loop because country configs are loaded once. Returns results in the same order
as the input.

#### `euredact.aredact()`

```python
async euredact.aredact(
    text: str,
    **kwargs,
) -> RedactResult
```

Async version of `redact()`. Offloads CPU-bound work to a thread pool so it
doesn't block the event loop. Accepts the same keyword arguments.

#### `euredact.aredact_batch()`

```python
async euredact.aredact_batch(
    texts: list[str],
    *,
    max_concurrency: int = 4,
    **kwargs,
) -> list[RedactResult]
```

Async batch redaction with controlled concurrency. Processes texts concurrently in
a thread pool. `max_concurrency` limits parallel threads (default 4). Returns
results in input order.

#### `euredact.redact_iter()`

```python
euredact.redact_iter(
    texts: Iterator[str],
    **kwargs,
) -> Iterator[RedactResult]
```

Lazy iterator that yields results one at a time. Useful for processing large
datasets without loading all results into memory. Loads country configs once on
the first item.

#### `euredact.add_custom_pattern()`

```python
euredact.add_custom_pattern(name: str, pattern: str) -> None
```

Register a custom regex pattern. Matches are reported with `name` as the entity
type. See [Custom Patterns](#custom-patterns) below for details and examples.

#### `euredact.available_countries()`

```python
euredact.available_countries() -> list[str]
```

Returns a sorted list of supported ISO country codes (e.g. `["AT", "BE", "BG", ...]`).

### Instance-Based API (`EuRedact` Class)

For applications that need isolated instances (separate caches, separate custom
patterns), use the `EuRedact` class directly:

```python
from euredact import EuRedact

instance = EuRedact()

# Register custom patterns on this instance only
instance.add_custom_pattern("CASE_REF", r"CASE-\d{8}")

# Redact using this instance's configuration
result = instance.redact("See CASE-20260401 for details", countries=["NL", "BE"])
print(result.redacted_text)
# "See [CASE_REF] for details"
```

The `EuRedact` class exposes the same methods as the module-level API: `redact()`,
`redact_batch()`, `aredact()`, `aredact_batch()`, `redact_iter()`, and
`add_custom_pattern()`.

### Return Types

#### `RedactResult`

Returned by `redact()` and all batch/async variants.

```python
@dataclass
class RedactResult:
    redacted_text: str          # The input text with PII replaced
    detections: list[Detection] # All PII spans found
    source: str = "rules"       # Detection backend ("rules")
    degraded: bool = False      # True if the engine fell back to a simpler mode
```

#### `Detection`

A single PII span. Frozen dataclass (immutable, hashable).

```python
@dataclass(frozen=True)
class Detection:
    entity_type: EntityType | str  # PII category (EntityType enum or custom name)
    start: int                     # Start offset in the original text
    end: int                       # End offset (exclusive) in the original text
    text: str                      # The matched substring
    source: DetectionSource        # "rules" or "cloud"
    country: str | None            # ISO code of the matched country, or None for shared/custom patterns
    confidence: str = "high"       # Confidence level
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

For custom patterns registered via `add_custom_pattern()`, `entity_type` is a
plain string (e.g. `"EMPLOYEE_ID"`) rather than an `EntityType` enum member.

#### `DetectionSource`

String enum: `"rules"` or `"cloud"`.

## Custom Patterns

Register domain-specific PII patterns at runtime. Custom patterns are detected
alongside built-in patterns and participate in the same deduplication pipeline.

```python
import euredact

# Register patterns
euredact.add_custom_pattern("EMPLOYEE_ID", r"EMP-\d{6}")
euredact.add_custom_pattern("CASE_REF", r"CASE-\d{8}")

# They are detected alongside built-in PII
result = euredact.redact(
    "Employee EMP-123456, email jan@example.com, ref CASE-20260401"
)
print(result.redacted_text)
# "Employee [EMPLOYEE_ID], email [EMAIL], ref [CASE_REF]"

# Check detections
for d in result.detections:
    print(f"  {d.entity_type}: {d.text}")
# EMPLOYEE_ID: EMP-123456
# EMAIL: jan@example.com
# CASE_REF: CASE-20260401
```

### How Custom Patterns Work

- `name` becomes the entity type reported in detections and used in replacement
  tags (e.g. `[EMPLOYEE_ID]`)
- `pattern` is a Python regular expression (same syntax as `re` module)
- Custom patterns are always active regardless of the `countries` parameter
- Custom patterns have no validator (they are purely regex-based)
- In overlap resolution, custom patterns have higher priority than built-in
  regex-only patterns but lower priority than built-in patterns with a passing
  checksum validator

### Instance Isolation

Custom patterns registered on the module-level function apply to the shared
singleton. For isolated pattern registrations, use separate `EuRedact` instances:

```python
from euredact import EuRedact

# Instance A detects employee IDs
a = EuRedact()
a.add_custom_pattern("EMPLOYEE_ID", r"EMP-\d{6}")

# Instance B detects case references
b = EuRedact()
b.add_custom_pattern("CASE_REF", r"CASE-\d{8}")

# Each instance only detects its own custom patterns
result_a = a.redact("EMP-123456 CASE-20260401")
result_b = b.redact("EMP-123456 CASE-20260401")
```

## Secret and API Key Detection

EuRedact includes built-in detection for API keys, tokens, and passwords. This is
always active -- no configuration required.

### Known-Prefix Patterns

The following token formats are detected with high confidence based on their
distinctive prefixes:

| Pattern | Description |
|---|---|
| `AKIA...` | AWS Access Key ID |
| `ghp_`, `gho_`, `ghs_`, `github_pat_` | GitHub tokens (PAT, OAuth, app, server) |
| `sk_live_`, `pk_live_`, `sk_test_`, `pk_test_` | Stripe secret and publishable keys |
| `sk-`, `sk-ant-` | OpenAI and Anthropic API keys |
| `xoxb-`, `xoxp-`, `xoxa-`, `xoxs-` | Slack tokens |
| `eyJ...` (3-part base64url) | JWT tokens |
| `SG.` | SendGrid API keys |

```python
result = euredact.redact("My API key is sk-proj-abc123def456ghi789jkl0")
print(result.redacted_text)
# "My API key is [SECRET]"
```

### Entropy-Based Detection

For secrets that don't have a recognizable prefix, EuRedact uses Shannon entropy
analysis. A high-entropy string (32+ characters of alphanumeric/base64 content) is
flagged as `SECRET` when it appears near context keywords like `key`, `token`,
`secret`, `password`, `credential`, `auth`, or `bearer` (including translations in
12 European languages).

```python
result = euredact.redact("The api_key is xK9mPqR7vLnW2bFjY8cGhT4sDfAeU6iO")
print(result.redacted_text)
# "The api_key is [SECRET]"

# Without a context keyword, the same string is not flagged:
result = euredact.redact("identifier: xK9mPqR7vLnW2bFjY8cGhT4sDfAeU6iO")
print(result.redacted_text)
# "identifier: xK9mPqR7vLnW2bFjY8cGhT4sDfAeU6iO"  (unchanged)

# Low-entropy strings are also not flagged, even with context:
result = euredact.redact("The password is aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
print(result.redacted_text)
# "The password is aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"  (unchanged)
```

## Country Hints

When you know which countries appear in your data, pass them explicitly:

```python
result = euredact.redact(text, countries=["NL", "BE"])
```

This restricts pattern matching to Dutch and Belgian rules (plus shared patterns
like IBAN, email, credit card, and secrets). Benefits:

- **Fewer false positives.** A 9-digit number that passes the Dutch BSN checksum
  will not also be tested against unrelated country patterns.
- **Faster.** Fewer patterns to compile and scan.

Custom patterns are always active regardless of the `countries` parameter.

When `countries=None` (the default), all 31 country rule sets are loaded. This is
the safest option when processing mixed-origin data.

## Pseudonymization

When `pseudonymize=True`, each unique PII value is mapped to a consistent
pseudonym within the session. The same input always produces the same pseudonym:

```python
import euredact

text = "BSN 111222333 en later weer 111222333, IBAN NL91ABNA0417164300."
result = euredact.redact(text, pseudonymize=True)
print(result.redacted_text)
# "BSN NATIONAL_ID_1 en later weer NATIONAL_ID_1, IBAN IBAN_1."
```

The mapping is scoped to the `EuRedact` instance. The module-level `redact()`
function uses a shared singleton, so pseudonyms are consistent across calls within
the same process.

## Architecture

```
Input text
    |
    v
[Normalizer] -- Unicode normalization, whitespace cleanup
    |
    v
[Pass 1: Pattern Matching] -- All country + shared + custom regexes
    |                          via MultiPatternMatcher (Aho-Corasick optional)
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
    |               or pseudonyms
    v
RedactResult
```

The engine is **thread-safe**: a `threading.Lock` guards country loading, and all
detection state is local to each `detect()` call. `Detection` objects are frozen
dataclasses and can be safely shared across threads.

### Suppression Zones

When a regex matches a pattern that has a checksum validator but the checksum
fails, the matched span becomes a "suppression zone." Any purely regex-based
detection fully contained within that zone is suppressed as a false positive.

For example, the text `BE71 0012 3456 7890` matches the Belgian IBAN regex but
fails mod-97 validation. Without suppression zones, sub-parts of this span might
be incorrectly detected as a license plate (`BE71`) or a phone number
(`0012 3456`). The suppression zone prevents these false positives while
correctly not reporting an invalid IBAN.

### Deduplication Priority

When multiple patterns match overlapping spans, the engine resolves conflicts
using a priority system:

1. **Validated patterns** (has a checksum validator that passes) -- highest priority
2. **Custom patterns** (registered via `add_custom_pattern()`)
3. **Regex-only patterns** (built-in patterns without a validator) -- lowest priority

Within the same priority tier, the longer span wins. This ensures that a valid
IBAN always beats a coincidental phone number match on the same text.

## Adding a New Country

Each country is a single Python file in `src/euredact/rules/countries/`. The
registry discovers new countries automatically -- no manual registration required.

1. Create a file, e.g. `src/euredact/rules/countries/gr.py`.
2. Define a `CountryConfig` subclass with patterns:

```python
"""Greece (GR) PII patterns."""

from euredact.rules.countries._base import CountryConfig, PatternDef
from euredact.types import EntityType


class GRConfig(CountryConfig):
    def __post_init__(self) -> None:
        self.code = "GR"
        self.name = "Greece"
        self.patterns = [
            PatternDef(
                entity_type=EntityType.NATIONAL_ID,
                pattern=r"\b[A-Z]{2}[0-9]{6}\b",
                validator=None,
                description="Greek national ID (example)",
            ),
        ]
```

That is all. The `CountryRegistry` scans the `countries/` package at startup and
picks up any module that defines a `CountryConfig` subclass with a non-empty
`code`. Files prefixed with `_` (like `_base.py` and `_shared.py`) receive
special treatment and are not treated as standalone countries.

Each `PatternDef` can specify:
- `entity_type` -- which `EntityType` this pattern detects
- `pattern` -- a regular expression
- `validator` -- an optional named validator (e.g. `"bsn"`, `"luhn"`, `"iban"`)
- `context_keywords` -- proximity keywords that boost confidence
- `requires_context` -- if `True`, the match is discarded without a nearby keyword

## Performance

| Metric | Value |
|---|---|
| Latency per page (~500 words) | < 1 ms |
| Throughput | ~2,000 records/second |
| Memory per country | ~50 KB compiled patterns |

The optional `pyahocorasick` dependency replaces the regex scan with an
Aho-Corasick automaton for keyword-heavy workloads, improving throughput on
large batches.

## License

Apache 2.0
