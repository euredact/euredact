# euredact

Fast, zero-dependency European PII detection and redaction for Node.js.

Detects and redacts personal data across **31 European countries** using rule-based pattern matching with checksum validation and context-aware false-positive suppression.

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

## API

### `redact(text, options?)`

Returns a `RedactResult` with the redacted text and a list of detections.

```ts
interface RedactOptions {
  countries?: string[];    // Country codes (e.g. ["NL", "BE"]) — recommended for best precision
  pseudonymize?: boolean;  // Replace with consistent pseudonyms (EMAIL_1, EMAIL_2, ...)
  detectDates?: boolean;   // Include DOB/date-of-death detections (off by default)
  cache?: boolean;         // Enable result caching (default: true)
}
```

### `redactBatch(texts, options?)`

Process multiple texts efficiently. Loads country configs once.

### `availableCountries()`

Returns the list of supported country codes.

## Supported Countries

AT, BE, BG, CH, CY, CZ, DE, DK, EE, EL, ES, FI, FR, HR, HU, IE, IS, IT, LT, LU, LV, MT, NL, NO, PL, PT, RO, SE, SI, SK, UK

## Detected PII Types

| Category | Examples |
|----------|---------|
| `NATIONAL_ID` | BSN, Personalausweis, NIR, CPR, personnummer, ... |
| `IBAN` | Country-specific IBAN with ISO 13616 checksum |
| `PHONE` | National and international formats per country |
| `EMAIL` | RFC 5322 simplified |
| `POSTAL_CODE` | Country-specific formats with context validation |
| `TAX_ID` | Steuer-ID, NIF, NIP, ... with checksums |
| `CREDIT_CARD` | Visa, Mastercard, Amex with Luhn check |
| `LICENSE_PLATE` | Country-specific formats |
| `PASSPORT` | Context-required per country |
| `VAT` | EU VAT numbers |
| `BIC` | SWIFT/BIC codes |
| `VIN` | ISO 3779 vehicle identification |
| `IP_ADDRESS` | IPv4 and IPv6 |
| `MAC_ADDRESS` | Colon, dash, and Cisco dot notation |
| `UUID` | RFC 4122 versions 1-5 |
| `IMEI` | 15-digit with Luhn check |
| `GPS_COORDINATES` | Decimal degrees with 4+ decimal places |
| `SOCIAL_HANDLE` | @username format |
| `DOB` | Date of birth (context-required, opt-in) |

## Performance

- **0.02ms** per redaction (typical text)
- **Zero runtime dependencies**
- **86KB** total package size
- Checksum validators eliminate false positives at the pattern level
- Context-aware suppressors filter currency amounts, units, references, and legal citations

## CommonJS

```js
const { redact } = require("euredact");
```

## License

Apache-2.0
