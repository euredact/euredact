/**
 * Dump detections as JSON, so the two SDKs can be scored by the same scorer.
 *
 * Used by `scripts/parity.py` and `euredact-python/tests/metrics.py`. Dumping
 * rather than reimplementing the metrics in TypeScript is deliberate: if the
 * scoring rules drifted between the two reports, a difference in the numbers
 * would tell you nothing about the engines.
 *
 *   npm run dump -- <input.json> <out.json>
 *
 * Input is a list of strings, or a list of `{text, countries}` when the caller
 * wants hinted detection. Output is one array of
 * `[start, end, entityType, country]` per input document, in order.
 */
import { readFileSync, writeFileSync } from "node:fs";
import { EuRedact } from "../index.js";

const [input, output] = process.argv.slice(2);
if (!input || !output) {
  console.error("usage: npm run dump -- <input.json> <out.json>");
  process.exit(2);
}

type Item = string | { text: string; countries?: string[] | null };

const items: Item[] = JSON.parse(readFileSync(input, "utf8"));
const sdk = new EuRedact();

const dumped = items.map(item => {
  const text = typeof item === "string" ? item : item.text;
  const countries = typeof item === "string" ? null : (item.countries ?? null);
  return sdk
    .redact(text, { countries, detectDates: true, cache: false })
    .detections.map(d => [d.start, d.end, String(d.entityType), d.country]);
});

writeFileSync(output, JSON.stringify(dumped));
console.error(`dumped ${dumped.reduce((a, r) => a + r.length, 0)} detections`);
