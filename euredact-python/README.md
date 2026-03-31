# EuRedact

**European PII redaction SDK -- rule engine**

---

EuRedact is a pure-Python SDK for detecting and redacting personally identifiable
information (PII) in European text data. It covers 28 countries with a two-pass
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

- **28 European countries** (see list below)
- **20+ PII entity types:** national IDs, IBANs, phone numbers, email addresses,
  VAT numbers, license plates, VIN, credit cards, BIC/SWIFT, IMEI, GPS
  coordinates, UUIDs, social handles, MAC addresses, IP/IPv6 addresses, health
  insurance numbers, passport numbers, driver's licenses, and more
- **Checksum validation:** IBAN mod-97, Luhn (credit cards), and country-specific
  national ID checksums (e.g., Dutch BSN 11-proof, Belgian national number modulo)
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
| Southern Europe | ES, IT, PT |
| Northern Europe | DK, EE, FI, IS, LT, LV, NO, SE |
| Eastern Europe | BG, CZ, HR, HU, PL, RO, SI, SK |
| British Isles | IE, UK |

## API Reference

### `euredact.redact()`

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
| `countries` | `None` | ISO 3166-1 alpha-2 codes to restrict detection (e.g. `["NL", "BE"]`). `None` loads all 28 countries. |
| `mode` | `"rules"` | Detection mode. Currently only `"rules"` is supported. |
| `pseudonymize` | `False` | Replace PII with consistent pseudonyms instead of entity-type labels. |
| `detect_dates` | `False` | Include date-of-birth and date-of-death detections. Off by default because bare dates without strong context are better handled by an LLM tier. When enabled, the engine applies keyword and structural (JSON/CSV) checks. |
| `cache` | `True` | Cache results for identical inputs. |

### `euredact.aredact()`

```python
async euredact.aredact(
    text: str,
    **kwargs,
) -> RedactResult
```

Async wrapper around `redact()`. Accepts the same keyword arguments. In rules-only
mode this is a thin synchronous call; it exists so that async callers can `await` it
without wrapping manually.

### `euredact.available_countries()`

```python
euredact.available_countries() -> list[str]
```

Returns a sorted list of supported ISO country codes (e.g. `["AT", "BE", "BG", ...]`).

### `RedactResult`

Returned by `redact()` and `aredact()`.

```python
@dataclass
class RedactResult:
    redacted_text: str          # The input text with PII replaced
    detections: list[Detection] # All PII spans found
    source: str = "rules"       # Detection backend ("rules")
    degraded: bool = False      # True if the engine fell back to a simpler mode
```

### `Detection`

A single PII span. Frozen dataclass (immutable, hashable).

```python
@dataclass(frozen=True)
class Detection:
    entity_type: EntityType       # PII category
    start: int                    # Start offset in the original text
    end: int                      # End offset (exclusive) in the original text
    text: str                     # The matched substring
    source: DetectionSource       # "rules" or "cloud"
    country: str | None           # ISO code of the matched country, or None for shared patterns
    confidence: str = "high"      # Confidence level
```

### `EntityType`

String enum with all supported PII categories:

```
NAME              ADDRESS           IBAN              BIC
CREDIT_CARD       PHONE             EMAIL             DOB
DATE_OF_DEATH     NATIONAL_ID       SSN               TAX_ID
PASSPORT          DRIVERS_LICENSE   RESIDENCE_PERMIT  LICENSE_PLATE
VIN               VAT               POSTAL_CODE       IP_ADDRESS
IPV6_ADDRESS      MAC_ADDRESS       HEALTH_INSURANCE  HEALTHCARE_PROVIDER
CHAMBER_OF_COMMERCE  IMEI          GPS_COORDINATES   UUID
SOCIAL_HANDLE     OTHER
```

### `DetectionSource`

String enum: `"rules"` or `"cloud"`.

## Country Hints

When you know which countries appear in your data, pass them explicitly:

```python
result = euredact.redact(text, countries=["NL", "BE"])
```

This restricts pattern matching to Dutch and Belgian rules (plus shared patterns
like IBAN, email, and credit card). Benefits:

- **Fewer false positives.** A 9-digit number that passes the Dutch BSN checksum
  will not also be tested against unrelated country patterns.
- **Faster.** Fewer patterns to compile and scan.

When `countries=None` (the default), all 28 country rule sets are loaded. This is
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

## Architecture

```
Input text
    |
    v
[Normalizer] -- Unicode normalization, whitespace cleanup
    |
    v
[Pass 1: Pattern Matching] -- All country regexes via MultiPatternMatcher
    |
    v
[Pass 2a: Checksum Validation] -- IBAN mod-97, Luhn, BSN 11-proof, etc.
    |
    v
[Pass 2b: Suppression Filters] -- Remove false positives (short numbers
    |                               in non-PII context, overlapping matches)
    v
[Structural Detectors] -- JSON field names, CSV headers (for dates)
    |
    v
[Deduplication] -- Keep longer/more-specific match on overlap
    |
    v
[Replacement] -- Right-to-left substitution with [ENTITY_TYPE] labels
    |               or pseudonyms
    v
RedactResult
```

The engine is **thread-safe**: a `threading.Lock` guards country loading, and all
detection state is local to each `detect()` call. `Detection` objects are frozen
dataclasses and can be safely shared across threads.

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
