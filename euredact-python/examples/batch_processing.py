"""Batch processing examples for large datasets."""

import asyncio
import euredact


# --- 1. Synchronous batch ---
texts = [
    "BSN: 111222333, email jan@test.nl",
    "IBAN: BE68539007547034, tel +32 2 123 45 67",
    "DNI: 12345678Z, tel +34 612 345 678",
]

results = euredact.redact_batch(texts, countries=["NL", "BE", "ES"])
for i, r in enumerate(results):
    print(f"[{i}] {r.redacted_text}")


# --- 2. Lazy iterator (memory-efficient for large files) ---
def read_lines(path: str):
    with open(path) as f:
        for line in f:
            yield line.strip()

# Uncomment to process a file line by line:
# for result in euredact.redact_iter(read_lines("big_file.txt"), countries=["NL"]):
#     print(result.redacted_text)


# --- 3. Async batch with concurrency control ---
async def process_async():
    texts = [f"Contact user{i}: user{i}@example.com" for i in range(100)]
    results = await euredact.aredact_batch(
        texts,
        max_concurrency=8,  # 8 parallel threads
    )
    print(f"\nAsync batch: {len(results)} texts processed")
    print(f"First: {results[0].redacted_text}")
    print(f"Last:  {results[-1].redacted_text}")

asyncio.run(process_async())
