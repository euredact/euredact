"""Strip PII before sending text to an LLM.

EuRedact removes structured PII (IBANs, IDs, phones, emails) locally.
The LLM never sees this data. Contextual PII (names, addresses) can
be handled by the LLM itself or by the EuRedact Cloud tier.
"""

import euredact

# Simulate a user document
document = """
Beste meneer Van den Berg,

Naar aanleiding van uw hypotheekaanvraag bevestigen wij de ontvangst
van uw documenten.

BSN: 111222333
IBAN: NL91ABNA0417164300
Telefoon: 06-12345678
E-mail: jan.vandenberg@gmail.com

Graag ontvangen wij nog een kopie van uw identiteitsbewijs.

Met vriendelijke groet,
Hypotheekteam
"""

# Step 1: Strip structured PII locally
result = euredact.redact(document, countries=["NL"])

print("=== Redacted text (safe to send to LLM) ===")
print(result.redacted_text)
print()

print(f"=== {len(result.detections)} PII items removed ===")
for det in result.detections:
    print(f"  {det.entity_type.value}: '{det.text}'")

# Step 2: Send result.redacted_text to your LLM
# response = openai.chat.completions.create(
#     messages=[{"role": "user", "content": result.redacted_text}]
# )
