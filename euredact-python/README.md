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
# "Mijn BSN is [NATIONAL_ID] en IBAN [BANK_ACCOUNT]."

print(result.detections)
# [Detection(entity_type=<EntityType.NATIONAL_ID>, ...), Detection(entity_type=<EntityType.BANK_ACCOUNT>, ...)]
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
  (with passing checksums, corroborated by the document's country) win over
  custom patterns, which win over regex-only patterns; a failed checksum demotes
  same-type matches rather than deleting them, so it can never silence a
  detection
- **Two-pass detection:** liberal regex matching followed by suppression filters
  that eliminate false positives
- **Context-aware:** keyword proximity checks and structural detection (JSON field
  names, CSV headers) for ambiguous patterns like dates of birth
- **Country self-detection:** infers a document's countries from the entities
  that carry one, so an ambiguous value resolves without the caller naming a
  country — and `countries=` never gates what is looked for
- **Fast:** ~0.5 ms for a short record, ~5 ms for a 3,400-character document
  with `[fast]` installed (see [Performance](#performance))
- **Zero required dependencies** (`pip install euredact[fast]` adds optional acceleration)
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
    referential_integrity: bool = False,
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
| `referential_integrity` | `False` | Replace PII with consistent labels instead of entity-type labels. |
| `detect_dates` | `False` | Include date-of-birth and date-of-death detections. Off by default because bare dates without strong context are better handled by an LLM tier. When enabled, the engine applies keyword and structural (JSON/CSV) checks. |
| `cache` | `True` | Cache results for identical inputs. |

#### `euredact.redact_batch()`

```python
euredact.redact_batch(
    texts: list[str],
    *,
    countries: list[str] | None = None,
    mode: str = "rules",
    referential_integrity: bool = False,
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

    # Country inference — see "Country-independent detection"
    inferred_countries: tuple[tuple[str, float], ...] = ()  # (country, confidence), strongest first
    evidence: tuple[CountryEvidence, ...] = ()              # every signal, with the span behind it
    detection_mode: str = "declared"                        # "declared" if countries= was passed,
                                                            # "inferred" otherwise
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
    country_confidence: float = 0.0  # How strongly the document supports `country`, in [0, 1].
                                     # 0.0 means the attribution rests on a checksum alone.
    out_of_scope: bool = False       # True when attributed outside the declared `countries`.
                                     # Flagged, never dropped.
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
SOCIAL_HANDLE     SECRET            OTHER
```

For custom patterns registered via `add_custom_pattern()`, `entity_type` is a
plain string (e.g. `"EMPLOYEE_ID"`) rather than an `EntityType` enum member.

#### `DetectionSource`

String enum: `"rules"` or `"cloud"`.

## Country codes

`countries=[...]` accepts **ISO 3166-1 alpha-2** codes. The two EU/VAT
spellings are accepted as equivalents:

| ISO 3166-1 | EU/VAT | |
|---|---|---|
| `GB` | `UK` | United Kingdom |
| `GR` | `EL` | Greece |

Codes are case-insensitive and whitespace-tolerant. An **unrecognised** code
does not raise — it emits an `UnknownCountryWarning` and detection continues
with the shared, country-independent patterns:

```python
euredact.redact(text, countries=["ZZ"])
# UnknownCountryWarning: Unknown country code: 'ZZ'. Continuing with shared
# country-independent patterns only (email, IBAN, international phone, ...).
```

This is deliberate. Raising on an unknown locale invites callers to wrap the
call in `try/except` and skip redaction entirely — failing open, with
unredacted PII in the output.

## Country-independent detection

**`countries=[...]` never gates detection.** Every pattern runs on every
document, whatever you pass. The country you declare decides *how a match is
labelled*, never *whether it is found*.

This is the engine's central invariant, enforced by
`tests/test_invariant_generation.py`: no value of `countries=` may change which
spans are detected. A wrong or missing country cannot cause a miss — silent
recall loss is invisible in testing and surfaces in a breach report, whereas a
false positive is recoverable.

It was not always so. `countries=["BE"]` used to make a valid Dutch BSN vanish
entirely, because the Dutch patterns were never run:

```python
euredact.redact("Werknemer met BSN 111222333", countries=["BE"])
# before: 'Werknemer met BSN 111222333'   <- leaked
# now:    'Werknemer met BSN [NATIONAL_ID]'
```

Entities found outside the countries you declared are **flagged, not dropped**:

```python
det = euredact.redact("BSN 111222333", countries=["BE"]).detections[0]
det.out_of_scope   # True — detected, masked, and marked as outside your scope
```

So a Belgian IBAN in a document processed with `countries=["AT"]` is still
detected — cross-border traffic (a foreign invoice in a local file, an employee
paid to a foreign account) does not leak:

```python
euredact.redact("Rekening: BE68 5390 0754 7034", countries=["AT"])
# -> 'Rekening: [BANK_ACCOUNT]'
```

### Which country a value belongs to

Because every pattern runs, the same digits often match several countries'
schemes. 36.6% of national-ID values in our corpus validate under more than one
country's checksum, so the digits alone cannot decide it — the *document* does.

The engine infers the document's countries from entities that carry their
country in the string, then uses that to resolve the ambiguity:

```python
r = euredact.redact("Bereikbaar op telefoon 0612345678, mail jan@test.nl")
r.inferred_countries          # (('NL', 0.98),)
r.detections[0].entity_type   # PHONE

r = euredact.redact("Kontakt: 0612345678, e-mail jens@test.dk")
r.inferred_countries          # (('DK', 0.98),)
r.detections[0].entity_type   # NATIONAL_ID
```

Identical digits, different answer — `0612345678` is both a valid Dutch mobile
number and a valid Danish CPR. Only the surrounding document distinguishes them.

Every inference is auditable: `result.evidence` lists each signal, its weight,
and the span that produced it.

| Signal | Weight (log-odds) | Measured reliability |
|---|---:|---|
| `e164_prefix` | 4.00 (capped) | 41,402 / 41,402 |
| `bic_country` | 4.00 (capped) | 2,588 / 2,588 |
| `email_tld` | 4.00 (capped) | 97,865 / 98,949 |
| `vat_prefix` | 2.84 | 19,022 / 20,136 |
| `iban_prefix` | 1.94 | 110,572 / 126,428 |

Weights are derived from the corpus, not chosen by hand. The IBAN prefix being
weakest is real and worth knowing: a Belgian IBAN in a Dutch invoice is
ordinary, so an account's country is only weak evidence about the document's.

Confidences are per-country and do **not** sum to 1 — document countries are
not mutually exclusive. A Belgian supplier invoicing a German customer is
genuinely both.

International phone numbers are matched by a generic E.164 pattern (`+`
followed by 8-15 digits, any grouping or separators, including `(0)` trunk
prefixes) that runs alongside the per-country patterns.

## BIC detection

BIC is the only bank identifier in the engine with **no check digit** — IBAN
has mod-97, VAT has country-specific checksums. ISO 9362 structure alone
cannot decide a match, because characters 5-6 of ordinary uppercase words are
frequently valid ISO 3166 country codes (`DRINGEND` → `GE`, `HOSPITAL` →
`IT`). Detection is therefore gated:

| Stage | Condition | Result |
|---|---|---|
| Gate 0 | the token also occurs as an ordinary lowercase word in the same document | never emitted |
| Tier 1 | registry hit on the BIC6 institution+country prefix | emitted |
| Gate 2 | heading / shouted-word shape | never emitted |
| Tier 2 | `BIC`/`SWIFT` keyword, an IBAN, or a bank block in the enclosing line, record or paragraph | emitted |
| — | none of the above | never emitted |

The context window is the enclosing **line, record or paragraph**, not a
character count — a banking cue often sits several fields away in the same
CSV row.

### Supplying your own BIC registry

The package bundles **no licensed BIC data**. The authoritative SWIFTRef BIC
Directory is a commercial product, and redistributing it inside a package
requires a specific redistribution licence. What ships is a small seed list of
BIC6 prefixes for major European banks, compiled from publicly published bank
data.

Deployments holding a licensed directory install it at startup:

```python
import euredact

# A path to a newline-delimited file of BICs...
euredact.set_bic_registry("/etc/euredact/swiftref-bics.txt")

# ...an iterable...
euredact.set_bic_registry({"ABNANL2A", "INGBNL2A", "BBRUBE"})

# ...or any membership callable.
euredact.set_bic_registry(lambda bic: bic in my_directory)

# Remove it again:
euredact.set_bic_registry(None)
```

Entries may be full BIC8/BIC11 codes or bare BIC6 prefixes; both are matched,
case-insensitively and ignoring spaces.

The registry is an **accept** signal, never a filter. A code missing from it
falls through to the context gate and is still detected when banking context
is present, so a stale list costs a little recall on bare, contextless BICs —
it never causes a leak. Annual review is sufficient.

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

Two arguments tell the engine about country, and neither restricts what is
looked for:

| Argument | Meaning |
|---|---|
| `countries=[...]` | **Scope.** Resolves ambiguity, and flags anything attributed elsewhere as `out_of_scope`. |
| `country_hint=[...]` | **Prior only.** Resolves ambiguity without narrowing scope or flagging anything. |

```python
# You know this batch is Swedish, but do not want foreign PII marked out of scope:
euredact.redact(text, country_hint=["SE"])

# You want anything non-Swedish flagged for review:
euredact.redact(text, countries=["SE"])
```

Declaring a country helps where a value is genuinely ambiguous and the document
carries no other signal:

```python
euredact.redact("Telefon: 0708787668", country_hint=["SE"]).detections[0]
# PHONE / SE  — without the hint this is a valid Danish CPR and nothing says otherwise
```

`result.detection_mode` reports which happened: `"declared"` if you passed
`countries=`, `"inferred"` otherwise.

Custom patterns are always active regardless of either parameter.

Passing neither is safe, and is the right default for mixed-origin data: the
engine infers what it can and reports it in `result.inferred_countries`. On our
152,300-document corpus, blind detection scores 98.3% precision against 98.6%
with country hints — a 0.3-point gap, down from 3.4 points before inference.

## Chunked documents

A long document is usually redacted in pieces. Each piece is scanned
independently, so each infers its own country — and a chunk that happens to
contain no IBAN, no `+CC` number and no ccTLD infers nothing at all, even when
page 1 identified the document beyond doubt:

```python
euredact.redact("Telefoon 0612345678")
# -> NATIONAL_ID (DK)   <- a valid Danish CPR, and nothing here says otherwise
```

Pass a `DocumentContext` to carry evidence forward across chunks:

```python
from euredact import DocumentContext

ctx = DocumentContext()
offset = 0
for page in pages:
    result = euredact.redact(page, context=ctx, chunk_offset=offset)
    offset += len(page)

# page 1: "Factuur — IBAN NL91ABNA0417164300, info@jansen.nl"
# page 7: "Telefoon 0612345678"  -> PHONE (NL)
```

`chunk_offset` rebases spans recorded in the context so they point into the
whole document. Returned detections stay relative to the chunk you passed in.

A context is thread-safe — `aredact_batch` fans chunks across a thread pool.
Caching is disabled automatically while one is in use, because the result then
depends on evidence the text alone does not determine.

Reuse a context only for chunks of the **same** document. Sharing one across
unrelated documents mixes their countries together. That cannot hide anything
— the invariant still holds — but it will attribute values to the wrong
national scheme.

## Referential Integrity

When `referential_integrity=True`, each unique PII value is mapped to a consistent
label within the session. The same input always produces the same label:

```python
import euredact

text = "BSN 111222333 en later weer 111222333, IBAN NL91ABNA0417164300."
result = euredact.redact(text, referential_integrity=True)
print(result.redacted_text)
# "BSN NATIONAL_ID_1 en later weer NATIONAL_ID_1, IBAN BANK_ACCOUNT_1."
```

The mapping is scoped to the `EuRedact` instance. The module-level `redact()`
function uses a shared singleton, so labels are consistent across calls within
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
    |               or labels
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

| Tier | What |
|---:|---|
| 3 | **Validated** — a checksum validator passes *and* the document corroborates its country |
| 2 | **Custom patterns** registered via `add_custom_pattern()` |
| 1 | **Regex-only**, and validated patterns whose country the document does not corroborate |
| 0 | **Postal codes** — a bare digit run, the weakest evidence in the engine |
| -1 | **Demoted** — a validator-less match inside a failed checksum of *its own type* |

Within a tier, ranking is: longer span, then stronger country evidence, then
whether the country was declared. **Span length outranks country** deliberately:
preferring the declared country over the longest match truncates entities — with
`countries=["BE"]` the Belgian phone pattern claimed 11 of the 14 characters of
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

Measured on one core, all 31 countries loaded, `detect_dates=True`. Cost scales
with document length, so the input size is stated rather than averaged away.

| Input | Pure Python | Aho-Corasick | With `[fast]` |
|---|---:|---:|---:|
| Short record (186 chars) | 907 µs — 1,103/s | 775 µs — 1,290/s | **516 µs — 1,938/s** |
| Real document (3,424 chars) | 13.6 ms — 73/s | 10.9 ms — 92/s | **5.3 ms — 190/s** |
| Memory per country | ~50 KB | ~50 KB | ~50 KB |

Making `\b` catch identifiers glued to a non-ASCII letter costs something, but
only where it must: next to a digit the ASCII reading alone is exactly
equivalent, so one lookaround replaces a three-way alternation, and plain `\b`
stays everywhere else. 0.3.3 applied the union to all 303 patterns and was
1.8×/2.8× slower for it.

```bash
pip install euredact[fast]
```

The `fast` extra installs two optional accelerators. Neither changes what is
detected — both are covered by `tests/test_scan_path_parity.py`, which runs
every available scan path against the plain-Python one and requires them to
agree:

- **`google-re2`** builds a prefilter over every pattern it can express (334 of
  345). One DFA pass per 1 KB window reports which patterns match anywhere in
  it — typically 42 of 314 for a real document — and only those are then run.
  Patterns RE2 cannot express, such as the lookbehind-based `SECRET` rules,
  always run.

  Asking the question per window matters: over a long document nearly every
  pattern matches *somewhere*, so a whole-document prefilter stops filtering
  (2.48× on a short record, decaying to 1.11× at 12 KB).

- **`pyahocorasick`** indexes patterns that begin with a literal and runs them
  only near a prefix hit. Used when `google-re2` is unavailable.

Detection cost is dominated by how much prose surrounds the PII, not by
document size alone: the same engine runs 1.4× faster on dense records and
~3× faster on prose-heavy documents where whole windows can be skipped.

The TypeScript SDK needs no such extra — V8's regex engine has literal
prefilters CPython lacks, and measured on the same documents it runs roughly 3×
faster than the accelerated Python path.

## License

Apache 2.0
