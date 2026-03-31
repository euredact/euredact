import { readFileSync } from "fs";
import { redact } from "../index.js";
import { COUNTRY_CONFIGS } from "../rules/countries/index.js";
import type { Detection } from "../types.js";

interface PiiAnnotation {
  PII_identifier: string;
  PII_category: string;
  PII_country: string;
}

interface DataEntry {
  source_text: string;
  PII: PiiAnnotation[];
}

const DATA_DIR =
  "/Users/jorenjanssens/Library/Mobile Documents/com~apple~CloudDocs/Werken/JNJS/Apps/PII-EuroMask/Data-Generation";

const FILES = [
  "euromask_training_core2.json",
  "euromask_training_core.json",
  "euromask_nordic_20k.json",
  "euromask_international_10k.json",
  "euromask_ie_baltics_uk_20k.json",
  "euromask_el_cy_mt_20k.json",
  "euromask_eastern_20k.json",
  "euromask_dach_south_20k.json",
  "euromask_allcountries_20k.json",
];

const SAMPLE_SIZE = 500;
const MAX_EXAMPLES = 5;

interface FPExample {
  matchedText: string;
  context: string;
  country: string | null;
  entryIndex: number;
  file: string;
  descriptions: string[];
}

interface FNExample {
  expectedText: string;
  context: string;
  expectedCountry: string;
  entryIndex: number;
  file: string;
  tsDetections: { entityType: string; text: string }[];
}

function getContext(text: string, start: number, end: number, pad = 50): string {
  const cStart = Math.max(0, start - pad);
  const cEnd = Math.min(text.length, end + pad);
  let ctx = text.slice(cStart, cEnd);
  if (cStart > 0) ctx = "..." + ctx;
  if (cEnd < text.length) ctx = ctx + "...";
  return ctx.replace(/\n/g, "\\n");
}

function findContextForIdentifier(text: string, identifier: string, pad = 50): string {
  const idx = text.indexOf(identifier);
  if (idx === -1) {
    // Try normalized search
    const normText = text.replace(/[\s.\-]/g, "");
    const normId = identifier.replace(/[\s.\-]/g, "");
    const normIdx = normText.indexOf(normId);
    if (normIdx === -1) return `[identifier not found in text: "${identifier.slice(0, 40)}"]`;
    // Approximate position in original text
    return getContext(text, Math.max(0, normIdx - 20), Math.min(text.length, normIdx + normId.length + 20), pad);
  }
  return getContext(text, idx, idx + identifier.length, pad);
}

function lookupDescriptions(entityType: string, country: string | null): string[] {
  const descriptions: string[] = [];
  const codes = country ? [country, "SHARED"] : Object.keys(COUNTRY_CONFIGS);
  for (const code of codes) {
    const config = COUNTRY_CONFIGS[code];
    if (!config) continue;
    for (const p of config.patterns) {
      if (p.entityType === entityType && p.description) {
        descriptions.push(`[${code}] ${p.description}`);
      }
    }
  }
  return descriptions;
}

const phoneFP: FPExample[] = [];
const cocFP: FPExample[] = [];
const socialFP: FPExample[] = [];
const postalFN: FNExample[] = [];

let phoneFPCount = 0;
let cocFPCount = 0;
let socialFPCount = 0;
let postalFNCount = 0;

for (const file of FILES) {
  const path = `${DATA_DIR}/${file}`;
  let data: DataEntry[];
  try {
    data = JSON.parse(readFileSync(path, "utf-8"));
  } catch (e) {
    console.log(`SKIP ${file}: ${(e as Error).message}`);
    continue;
  }

  const sample = data.slice(0, SAMPLE_SIZE);

  for (let i = 0; i < sample.length; i++) {
    const entry = sample[i];
    const result = redact(entry.source_text, { detectDates: true });

    // --- FALSE POSITIVES ---
    // For each detection of the target type, check if it corresponds to an expected PII of the same type
    for (const det of result.detections) {
      const isExpected = entry.PII.some((p) => {
        if (p.PII_category !== det.entityType) return false;
        const detNorm = det.text.replace(/[\s.\-]/g, "");
        const expNorm = p.PII_identifier.replace(/[\s.\-]/g, "");
        return detNorm.includes(expNorm) || expNorm.includes(detNorm);
      });

      if (!isExpected) {
        const example: FPExample = {
          matchedText: det.text,
          context: getContext(entry.source_text, det.start, det.end),
          country: det.country,
          entryIndex: i,
          file,
          descriptions: lookupDescriptions(det.entityType, det.country),
        };

        if (det.entityType === "PHONE") {
          phoneFPCount++;
          if (phoneFP.length < MAX_EXAMPLES) phoneFP.push(example);
        } else if (det.entityType === "CHAMBER_OF_COMMERCE") {
          cocFPCount++;
          if (cocFP.length < MAX_EXAMPLES) cocFP.push(example);
        } else if (det.entityType === "SOCIAL_HANDLE") {
          socialFPCount++;
          if (socialFP.length < MAX_EXAMPLES) socialFP.push(example);
        }
      }
    }

    // --- FALSE NEGATIVES: POSTAL_CODE ---
    const expectedPostals = entry.PII.filter((p) => p.PII_category === "POSTAL_CODE");
    for (const exp of expectedPostals) {
      const found = result.detections.some((d) => {
        if (d.entityType !== "POSTAL_CODE") return false;
        const detNorm = d.text.replace(/[\s.\-]/g, "");
        const expNorm = exp.PII_identifier.replace(/[\s.\-]/g, "");
        return detNorm.includes(expNorm) || expNorm.includes(detNorm);
      });

      if (!found) {
        postalFNCount++;
      }
      if (!found && postalFN.length < MAX_EXAMPLES) {
        postalFN.push({
          expectedText: exp.PII_identifier,
          context: findContextForIdentifier(entry.source_text, exp.PII_identifier),
          expectedCountry: exp.PII_country,
          entryIndex: i,
          file,
          tsDetections: result.detections
            .filter((d) => {
              // Show detections that overlap with the expected postal code position
              const idx = entry.source_text.indexOf(exp.PII_identifier);
              if (idx === -1) return false;
              return d.start < idx + exp.PII_identifier.length + 10 && d.end > idx - 10;
            })
            .map((d) => ({ entityType: d.entityType, text: d.text })),
        });
      }
    }

  }
}

function printFPExamples(label: string, examples: FPExample[]) {
  console.log(`\n${"=".repeat(80)}`);
  console.log(`FALSE POSITIVES: ${label} (${examples.length} examples)`);
  console.log("=".repeat(80));
  for (const ex of examples) {
    console.log(`\n  File: ${ex.file}, Entry: ${ex.entryIndex}`);
    console.log(`  Matched text: "${ex.matchedText}"`);
    console.log(`  Country: ${ex.country ?? "null"}`);
    console.log(`  Context: ${ex.context}`);
    if (ex.descriptions.length > 0) {
      console.log(`  Pattern descriptions:`);
      for (const d of ex.descriptions.slice(0, 3)) {
        console.log(`    - ${d}`);
      }
      if (ex.descriptions.length > 3) {
        console.log(`    ... and ${ex.descriptions.length - 3} more`);
      }
    }
  }
}

function printFNExamples(label: string, examples: FNExample[]) {
  console.log(`\n${"=".repeat(80)}`);
  console.log(`FALSE NEGATIVES: ${label} (${examples.length} examples)`);
  console.log("=".repeat(80));
  for (const ex of examples) {
    console.log(`\n  File: ${ex.file}, Entry: ${ex.entryIndex}`);
    console.log(`  Expected text: "${ex.expectedText}"`);
    console.log(`  Expected country: ${ex.expectedCountry}`);
    console.log(`  Context: ${ex.context}`);
    if (ex.tsDetections.length > 0) {
      console.log(`  Nearby TS detections:`);
      for (const d of ex.tsDetections) {
        console.log(`    - ${d.entityType}: "${d.text}"`);
      }
    } else {
      console.log(`  Nearby TS detections: none`);
    }
  }
}

console.log("\n=== TOTAL COUNTS ===");
console.log(`  PHONE FP:               ${phoneFPCount}`);
console.log(`  CHAMBER_OF_COMMERCE FP: ${cocFPCount}`);
console.log(`  SOCIAL_HANDLE FP:       ${socialFPCount}`);
console.log(`  POSTAL_CODE FN:         ${postalFNCount}`);

printFPExamples("PHONE", phoneFP);
printFPExamples("CHAMBER_OF_COMMERCE", cocFP);
printFPExamples("SOCIAL_HANDLE", socialFP);
printFNExamples("POSTAL_CODE", postalFN);

console.log("\nDone.");
