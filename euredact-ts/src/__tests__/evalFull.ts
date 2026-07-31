import { fileURLToPath } from "url";
/**
 * Full-corpus evaluation, mirroring the Python `tests/eval_full.py` methodology
 * exactly so the two engines' numbers are directly comparable:
 *
 *  - every record, not a per-file sample;
 *  - country hints taken from the record's own PII annotations;
 *  - a label counts as found when its text is gone from the redacted output,
 *    or a detection overlaps its span **with an acceptable entity type**;
 *  - DOB is reported separately (deferred to the LLM tier by design);
 *  - precision counts each detection as TP/FP by span+type match.
 *
 * Run with `npm run test:eval:full`.
 */

import { readFileSync, readdirSync } from "fs";
import { EuRedact } from "../sdk.js";
import { availableCountries } from "../index.js";

// The corpus lives beside the code checkout, not inside it. `EUREDACT_CORPUS`
// is the same override the Python tooling honours.
const DATA_DIR =
  process.env.EUREDACT_CORPUS ??
  fileURLToPath(new URL("../../../../Data-Generation", import.meta.url));

interface Pii { PII_identifier: string; PII_category: string; PII_country: string }
interface Entry { source_text: string; PII: Pii[] }

// Expected category -> acceptable emitted entity types.
const CATEGORY_MAP: Record<string, string[]> = {
  NATIONAL_ID: ["NATIONAL_ID", "SSN", "TAX_ID"],
  NATIONAL_ID_CARD: ["NATIONAL_ID"],
  SOCIAL_SECURITY: ["NATIONAL_ID", "SSN"],
  TAX_ID: ["TAX_ID"],
  TAX_ID_PERSONAL: ["TAX_ID"],
  TAX_ID_BUSINESS: ["VAT", "TAX_ID"],
  IBAN: ["BANK_ACCOUNT"],
  CREDIT_CARD: ["CREDIT_CARD"],
  VAT_NUMBER: ["VAT", "CHAMBER_OF_COMMERCE"],
  PHONE: ["PHONE"],
  EMAIL: ["EMAIL"],
  DOB: ["DOB"],
  POSTAL_CODE: ["POSTAL_CODE"],
  LICENSE_PLATE: ["LICENSE_PLATE"],
  VIN: ["VIN"],
  PASSPORT: ["PASSPORT"],
  HEALTH_INSURANCE: ["HEALTH_INSURANCE", "NATIONAL_ID"],
  CHAMBER_OF_COMMERCE: ["CHAMBER_OF_COMMERCE", "VAT"],
  IP_ADDRESS: ["IP_ADDRESS"],
  IPV6_ADDRESS: ["IPV6_ADDRESS"],
  MAC_ADDRESS: ["MAC_ADDRESS"],
  BIC: ["BIC"],
  IMEI: ["IMEI"],
  GPS_COORDINATES: ["GPS_COORDINATES"],
  SWIFT_BIC: ["BIC"],
  IP_ADDRESS_V6: ["IPV6_ADDRESS"],
  UUID: ["UUID"],
  SOCIAL_HANDLE: ["SOCIAL_HANDLE"],
};

const EXCLUDED = new Set(["CRYPTO_ADDRESS_BTC", "CRYPTO_ADDRESS_ETH"]);
const DOB_CATEGORIES = new Set(["DOB"]);

const known = new Set(availableCountries());

const files = readdirSync(DATA_DIR).filter(f => f.endsWith(".json") && !f.endsWith(".bak")).sort();
const data: Entry[] = [];
for (const f of files) {
  const recs: Entry[] = JSON.parse(readFileSync(`${DATA_DIR}/${f}`, "utf-8"));
  data.push(...recs);
  console.log(`Loaded ${f}: ${recs.length} records`);
}
console.log(`Combined: ${data.length} records\n`);

function run(useCountryHints: boolean) {
  const sdk = new EuRedact();
  const catTp = new Map<string, number>();
  const catTotal = new Map<string, number>();
  const detTp = new Map<string, number>();
  const detFp = new Map<string, number>();
  const bump = (m: Map<string, number>, k: string) => m.set(k, (m.get(k) ?? 0) + 1);

  let chars = 0;
  let docs = 0;
  const t0 = process.hrtime.bigint();

  for (const item of data) {
    const expected = item.PII;
    if (!expected || expected.length === 0) continue;
    const text = item.source_text;

    const itemCountries = [...new Set(expected.map(p => p.PII_country).filter(Boolean))];
    const valid = itemCountries.filter(c => known.has(c));
    const countries = useCountryHints && valid.length > 0 ? valid : null;

    const result = sdk.redact(text, { countries, detectDates: true, cache: false });
    chars += text.length;
    docs++;

    for (const pii of expected) {
      const cat = pii.PII_category;
      if (EXCLUDED.has(cat)) continue;
      const acceptable = CATEGORY_MAP[cat] ?? [cat];
      bump(catTotal, cat);

      let found = !result.redactedText.includes(pii.PII_identifier);
      if (!found) {
        const idx = text.indexOf(pii.PII_identifier);
        if (idx >= 0) {
          const end = idx + pii.PII_identifier.length;
          for (const det of result.detections) {
            if (det.start < end && det.end > idx && acceptable.includes(det.entityType as string)) {
              found = true;
              break;
            }
          }
        }
      }
      if (found) bump(catTp, cat);
    }

    const spans: Array<[number, number, string]> = [];
    for (const pii of expected) {
      if (EXCLUDED.has(pii.PII_category)) continue;
      const idx = text.indexOf(pii.PII_identifier);
      if (idx >= 0) spans.push([idx, idx + pii.PII_identifier.length, pii.PII_category]);
    }
    for (const det of result.detections) {
      const etype = det.entityType as string;
      let matches = false;
      for (const [s, e, ecat] of spans) {
        if (det.start < e && det.end > s) {
          const acceptable = CATEGORY_MAP[ecat] ?? [ecat];
          if (acceptable.includes(etype)) { matches = true; break; }
        }
      }
      bump(matches ? detTp : detFp, etype);
    }
  }

  const elapsedMs = Number(process.hrtime.bigint() - t0) / 1e6;
  return { catTp, catTotal, detTp, detFp, elapsedMs, chars, docs };
}

const sumExclDob = (m: Map<string, number>) =>
  [...m.entries()].filter(([k]) => !DOB_CATEGORIES.has(k)).reduce((a, [, v]) => a + v, 0);
const pct = (n: number, d: number) => (d > 0 ? (n / d) * 100 : 0);

for (const hints of [true, false]) {
  const label = hints ? "With Country Hints" : "Without Country Hints (blind)";
  const r = run(hints);
  const tp = sumExclDob(r.catTp);
  const total = sumExclDob(r.catTotal);
  const detTpTotal = [...r.detTp.values()].reduce((a, b) => a + b, 0);
  const detFpTotal = [...r.detFp.values()].reduce((a, b) => a + b, 0);
  const dobTp = r.catTp.get("DOB") ?? 0;
  const dobTotal = r.catTotal.get("DOB") ?? 0;

  console.log(`=== ${label} ===`);
  console.log(`  recall    ${pct(tp, total).toFixed(2)}%  (${tp.toLocaleString()}/${total.toLocaleString()}, excl DOB)`);
  console.log(`  precision ${pct(detTpTotal, detTpTotal + detFpTotal).toFixed(2)}%  (${detFpTotal.toLocaleString()} FPs of ${(detTpTotal + detFpTotal).toLocaleString()})`);
  console.log(`  DOB       ${pct(dobTp, dobTotal).toFixed(1)}%`);
  console.log(`  THROUGHPUT`);
  console.log(`    ${(r.elapsedMs / 1000).toFixed(1)}s for ${r.docs.toLocaleString()} docs`);
  console.log(`    ${(r.elapsedMs / r.docs).toFixed(3)} ms/doc`);
  console.log(`    ${Math.round(r.docs / (r.elapsedMs / 1000)).toLocaleString()} docs/sec`);
  console.log(`    ${(r.chars / (r.elapsedMs / 1000) / 1e6).toFixed(2)} MB/sec  (${r.chars.toLocaleString()} chars total)`);

  console.log(`  BY CATEGORY`);
  const cats = [...r.catTotal.entries()].filter(([c]) => !DOB_CATEGORIES.has(c)).sort((a, b) => b[1] - a[1]);
  for (const [cat, tot] of cats) {
    const hit = r.catTp.get(cat) ?? 0;
    console.log(`    ${cat.padEnd(22)} ${String(hit).padStart(7)}/${String(tot).padStart(7)}  ${pct(hit, tot).toFixed(1)}%`);
  }
  console.log("");
}
