"""Basic EuRedact usage examples."""

import euredact

# --- 1. Simple redaction ---
result = euredact.redact("Mijn BSN is 111222333 en mijn IBAN is NL91ABNA0417164300.")
print(result.redacted_text)
# "Mijn BSN is [NATIONAL_ID] en mijn IBAN is [IBAN]."

# --- 2. With country hints (faster + more precise) ---
result = euredact.redact(
    "Contact: jan@example.nl, +31 6 12345678",
    countries=["NL"],
)
print(result.redacted_text)

# --- 3. Inspect detections ---
for det in result.detections:
    print(f"  {det.entity_type.value}: '{det.text}' at [{det.start}:{det.end}]")

# --- 4. Pseudonymization ---
result = euredact.redact(
    "Jan (jan@example.nl) en Piet (piet@example.nl). Jan weer: jan@example.nl",
    pseudonymize=True,
)
print(result.redacted_text)
# "Jan (EMAIL_1) en Piet (EMAIL_2). Jan weer: EMAIL_1"

# --- 5. Check available countries ---
print(f"\n{len(euredact.available_countries())} countries: {euredact.available_countries()}")
