import { readFileSync } from "fs";
import { redact, availableCountries, type RedactResult } from "../index.js";

interface PiiAnnotation {
  PII_identifier: string;
  PII_category: string;
  PII_country: string;
}

interface DataEntry {
  source_text: string;
  PII: PiiAnnotation[];
}

const DATA_DIR = "/Users/jorenjanssens/Library/Mobile Documents/com~apple~CloudDocs/Werken/JNJS/Apps/PII-EuroMask/Data-Generation";

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

// Map data PII categories → our EntityType values
const CATEGORY_MAP: Record<string, string> = {
  EMAIL: "EMAIL",
  IBAN: "IBAN",
  PHONE: "PHONE",
  NATIONAL_ID: "NATIONAL_ID",
  NATIONAL_ID_CARD: "NATIONAL_ID",
  POSTAL_CODE: "POSTAL_CODE",
  VAT_NUMBER: "VAT",
  SWIFT_BIC: "BIC",
  TAX_ID: "TAX_ID",
  TAX_ID_PERSONAL: "TAX_ID",
  TAX_ID_BUSINESS: "TAX_ID",
  SOCIAL_SECURITY: "SSN",
  IP_ADDRESS: "IP_ADDRESS",
  IP_ADDRESS_V6: "IPV6_ADDRESS",
  VIN: "VIN",
  CHAMBER_OF_COMMERCE: "CHAMBER_OF_COMMERCE",
  UUID: "UUID",
  LICENSE_PLATE: "LICENSE_PLATE",
  CREDIT_CARD: "CREDIT_CARD",
  MAC_ADDRESS: "MAC_ADDRESS",
  IMEI: "IMEI",
  SOCIAL_HANDLE: "SOCIAL_HANDLE",
  GPS_COORDINATES: "GPS_COORDINATES",
  PASSPORT: "PASSPORT",
  HEALTH_INSURANCE: "HEALTH_INSURANCE",
  HEALTH_ID: "HEALTHCARE_PROVIDER",
  DOB: "DOB",
  // Not supported by rule engine:
  // CRYPTO_ADDRESS_BTC, CRYPTO_ADDRESS_ETH
};

const cleanStr = (s: string) => s.replace(/[\s.\-]/g, "");

console.log("Available countries:", availableCountries().join(", "));
console.log("");

let totalExpected = 0;
let totalDetected = 0;
let totalTruePositive = 0;

const categoryStats: Record<string, { expected: number; detected: number; tp: number }> = {};

for (const file of FILES) {
  const path = `${DATA_DIR}/${file}`;
  let data: DataEntry[];
  try {
    data = JSON.parse(readFileSync(path, "utf-8"));
  } catch (e) {
    console.log(`SKIP ${file}: ${(e as Error).message}`);
    continue;
  }

  let fileExpected = 0;
  let fileDetected = 0;
  let fileTp = 0;

  const sampleSize = Math.min(data.length, 500);
  const sample = data.slice(0, sampleSize);

  for (const entry of sample) {
    // Map and filter expected PII (exclude DOB and unsupported categories)
    const expectedPii = entry.PII
      .filter(p => CATEGORY_MAP[p.PII_category] && CATEGORY_MAP[p.PII_category] !== "DOB")
      .map(p => ({ ...p, mappedCategory: CATEGORY_MAP[p.PII_category] }));

    fileExpected += expectedPii.length;

    // Extract country hints from the PII annotations
    const countries = [...new Set(entry.PII.map(p => p.PII_country).filter(Boolean))];

    // Run detection WITH country hints
    const result: RedactResult = redact(entry.source_text, {
      countries: countries.length > 0 ? countries : null,
      detectDates: false, // DOB excluded like in the original report
    });

    // Count non-DOB detections
    const nonDobDetections = result.detections.filter(d => d.entityType !== "DOB" && d.entityType !== "DATE_OF_DEATH");
    fileDetected += nonDobDetections.length;

    // Check which expected PII were found (by text overlap)
    for (const expected of expectedPii) {
      const cat = expected.mappedCategory;
      if (!categoryStats[cat]) categoryStats[cat] = { expected: 0, detected: 0, tp: 0 };
      categoryStats[cat].expected++;

      const found = nonDobDetections.some(d => {
        const detectedClean = cleanStr(d.text);
        const expectedClean = cleanStr(expected.PII_identifier);
        return detectedClean.includes(expectedClean) || expectedClean.includes(detectedClean);
      });

      if (found) {
        fileTp++;
        categoryStats[cat].tp++;
      }
    }

    for (const d of nonDobDetections) {
      const cat = d.entityType;
      if (!categoryStats[cat]) categoryStats[cat] = { expected: 0, detected: 0, tp: 0 };
      categoryStats[cat].detected++;
    }
  }

  const recall = fileExpected > 0 ? (fileTp / fileExpected * 100).toFixed(1) : "N/A";
  const fp = fileDetected - fileTp;
  const precision = fileDetected > 0 ? (fileTp / fileDetected * 100).toFixed(1) : "N/A";
  console.log(`${file.padEnd(40)} samples=${sampleSize} expected=${fileExpected} detected=${fileDetected} TP=${fileTp} FP=${fp} recall=${recall}% precision=${precision}%`);

  totalExpected += fileExpected;
  totalDetected += fileDetected;
  totalTruePositive += fileTp;
}

const totalFp = totalDetected - totalTruePositive;
console.log("");
console.log("=== OVERALL (excl. DOB) ===");
const overallRecall = totalExpected > 0 ? (totalTruePositive / totalExpected * 100).toFixed(1) : "N/A";
const overallPrecision = totalDetected > 0 ? (totalTruePositive / totalDetected * 100).toFixed(1) : "N/A";
const f1 = totalExpected > 0 && totalDetected > 0 ? (2 * totalTruePositive / (totalExpected + totalDetected)).toFixed(3) : "N/A";
console.log(`Expected: ${totalExpected}, Detected: ${totalDetected}, TP: ${totalTruePositive}, FP: ${totalFp}`);
console.log(`Recall: ${overallRecall}%, Precision: ${overallPrecision}%, F1: ${f1}`);

console.log("");
console.log("=== BY CATEGORY ===");
const sortedCats = Object.entries(categoryStats).sort((a, b) => b[1].expected - a[1].expected);
for (const [cat, stats] of sortedCats) {
  const recall = stats.expected > 0 ? (stats.tp / stats.expected * 100).toFixed(1) : "N/A";
  const precision = stats.detected > 0 ? (stats.tp / stats.detected * 100).toFixed(1) : "N/A";
  console.log(`  ${cat.padEnd(25)} expected=${String(stats.expected).padStart(5)} detected=${String(stats.detected).padStart(5)} TP=${String(stats.tp).padStart(5)} recall=${recall}% precision=${precision}%`);
}
