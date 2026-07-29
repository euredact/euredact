/**
 * Dump detections as JSON, so the two SDKs can be compared on the same input.
 *
 * Used by `scripts/parity.py`. The SDKs share `conformance/vectors.json`, but
 * that pins named cases; this compares them over a whole corpus, which is how
 * the 19,014 characters TypeScript was failing to mask were found.
 *
 *   npm run dump -- <documents.json> <out.json>
 */
import { readFileSync, writeFileSync } from "node:fs";
import { EuRedact } from "../index.js";

const [input, output] = process.argv.slice(2);
if (!input || !output) {
  console.error("usage: npm run dump -- <documents.json> <out.json>");
  process.exit(2);
}
const docs: string[] = JSON.parse(readFileSync(input, "utf8"));
const sdk = new EuRedact();
const dumped = docs.map(text =>
  sdk.redact(text, { detectDates: true, cache: false }).detections
     .map(d => [d.start, d.end, String(d.entityType), d.country]));
writeFileSync(output, JSON.stringify(dumped));
console.error(`dumped ${dumped.reduce((a, r) => a + r.length, 0)} detections`);
