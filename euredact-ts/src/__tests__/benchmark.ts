import { fileURLToPath } from "url";
import { readFileSync } from "fs";
import { writeFileSync } from "fs";
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

// The corpus lives beside the code checkout, not inside it. `EUREDACT_CORPUS`
// is the same override the Python tooling honours.
const DATA_DIR =
  process.env.EUREDACT_CORPUS ??
  fileURLToPath(new URL("../../../../Data-Generation", import.meta.url));

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
  "euromask_secrets_5k.json",
];

const CATEGORY_MAP: Record<string, string> = {
  EMAIL: "EMAIL",
  IBAN: "BANK_ACCOUNT",
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
  SECRET: "SECRET",
  DOB: "DOB",
};

const cleanStr = (s: string) => s.replace(/[\s.\-]/g, "");

// --- Argument parsing ---
const jsonMode = process.argv.includes("--json");
const sizeIdx = process.argv.indexOf("--sample-size");
const SAMPLE_SIZE = sizeIdx >= 0 ? parseInt(process.argv[sizeIdx + 1]) : 500;
const outIdx = process.argv.indexOf("--output");
const outputPath = outIdx >= 0 ? process.argv[outIdx + 1] : null;

// --- Read library version ---
const pkgJson = JSON.parse(readFileSync(new URL("../../package.json", import.meta.url), "utf-8"));

interface FileResult {
  filename: string;
  n: number;
  expected: number;
  detected: number;
  tp: number;
  elapsed_s: number;
}

function runBenchmark() {
  const countries = availableCountries();
  const fileResults: FileResult[] = [];
  const filesSkipped: string[] = [];
  let totalExpected = 0;
  let totalDetected = 0;
  let totalTp = 0;
  let totalSamples = 0;
  let totalElapsedMs = 0;
  const categoryStats: Record<string, { expected: number; detected: number; tp: number }> = {};

  for (const file of FILES) {
    const path = `${DATA_DIR}/${file}`;
    let data: DataEntry[];
    try {
      data = JSON.parse(readFileSync(path, "utf-8"));
    } catch {
      filesSkipped.push(file);
      continue;
    }

    const sampleSize = Math.min(data.length, SAMPLE_SIZE);
    const sample = data.slice(0, sampleSize);
    totalSamples += sampleSize;

    let fileExpected = 0;
    let fileDetected = 0;
    let fileTp = 0;

    const t0 = performance.now();

    for (const entry of sample) {
      const expectedPii = entry.PII
        .filter(p => CATEGORY_MAP[p.PII_category] && CATEGORY_MAP[p.PII_category] !== "DOB")
        .map(p => ({ ...p, mappedCategory: CATEGORY_MAP[p.PII_category] }));

      fileExpected += expectedPii.length;

      const entryCountries = [...new Set(entry.PII.map(p => p.PII_country).filter(Boolean))];

      const result: RedactResult = redact(entry.source_text, {
        countries: entryCountries.length > 0 ? entryCountries : null,
        detectDates: false,
      });

      const nonDobDetections = result.detections.filter(d => d.entityType !== "DOB" && d.entityType !== "DATE_OF_DEATH");
      fileDetected += nonDobDetections.length;

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

    const elapsed = performance.now() - t0;
    totalElapsedMs += elapsed;

    fileResults.push({
      filename: file,
      n: sampleSize,
      expected: fileExpected,
      detected: fileDetected,
      tp: fileTp,
      elapsed_s: parseFloat((elapsed / 1000).toFixed(4)),
    });

    totalExpected += fileExpected;
    totalDetected += fileDetected;
    totalTp += fileTp;
  }

  return {
    runtime: "typescript",
    runtime_version: process.version,
    library_version: pkgJson.version as string,
    timestamp: new Date().toISOString(),
    sample_size_per_file: SAMPLE_SIZE,
    countries,
    files: fileResults,
    files_skipped: filesSkipped,
    overall: {
      samples: totalSamples,
      expected: totalExpected,
      detected: totalDetected,
      tp: totalTp,
      total_time_s: parseFloat((totalElapsedMs / 1000).toFixed(2)),
    },
    categories: categoryStats,
  };
}

function printTextReport(result: ReturnType<typeof runBenchmark>) {
  console.log(`euredact benchmark — TypeScript`);
  console.log(`Available countries: ${result.countries.join(", ")}`);
  console.log(`Sample size per file: ${result.sample_size_per_file}`);
  console.log("");

  for (const f of result.files) {
    const recall = f.expected > 0 ? (f.tp / f.expected * 100).toFixed(1) : "N/A";
    const precision = f.detected > 0 ? (f.tp / f.detected * 100).toFixed(1) : "N/A";
    const msPerSample = (f.elapsed_s / f.n * 1000).toFixed(2);
    console.log(`${f.filename.padEnd(40)} n=${f.n} expected=${f.expected} detected=${f.detected} TP=${f.tp} recall=${recall}% precision=${precision}% ${msPerSample}ms/sample`);
  }

  for (const skip of result.files_skipped) {
    console.log(`SKIP ${skip}: not found`);
  }

  const o = result.overall;
  console.log("");
  console.log("=== OVERALL (excl. DOB) ===");
  const overallRecall = o.expected > 0 ? (o.tp / o.expected * 100).toFixed(1) : "N/A";
  const overallPrecision = o.detected > 0 ? (o.tp / o.detected * 100).toFixed(1) : "N/A";
  const f1 = o.expected > 0 && o.detected > 0 ? (2 * o.tp / (o.expected + o.detected)).toFixed(3) : "N/A";
  console.log(`Samples: ${o.samples}, Expected: ${o.expected}, Detected: ${o.detected}, TP: ${o.tp}`);
  console.log(`Recall: ${overallRecall}%, Precision: ${overallPrecision}%, F1: ${f1}`);
  console.log(`Total time: ${o.total_time_s.toFixed(2)}s, avg: ${(o.total_time_s / o.samples * 1000).toFixed(2)}ms/sample`);

  console.log("");
  console.log("=== BY CATEGORY ===");
  const sortedCats = Object.entries(result.categories).sort((a, b) => b[1].expected - a[1].expected);
  for (const [cat, stats] of sortedCats) {
    const recall = stats.expected > 0 ? (stats.tp / stats.expected * 100).toFixed(1) : "N/A";
    const precision = stats.detected > 0 ? (stats.tp / stats.detected * 100).toFixed(1) : "N/A";
    console.log(`  ${cat.padEnd(25)} expected=${String(stats.expected).padStart(5)} detected=${String(stats.detected).padStart(5)} TP=${String(stats.tp).padStart(5)} recall=${recall}% precision=${precision}%`);
  }
}

// --- Main ---
const result = runBenchmark();

if (jsonMode) {
  const out = JSON.stringify(result, null, 2);
  if (outputPath) {
    writeFileSync(outputPath, out);
  } else {
    process.stdout.write(out + "\n");
  }
} else {
  printTextReport(result);
}
