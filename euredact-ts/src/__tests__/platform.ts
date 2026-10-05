/**
 * The browser build of `platform.ts` (rules-engine#56).
 *
 * `platform.browser.ts` replaces `node:crypto` when the package is bundled for a
 * page, so it has to agree with it: the cache key is a security property (see
 * `ResultCache.key`), and two SDK builds hashing the same document differently
 * would be a defect nobody could see. Run with `npm run test:platform`.
 */

import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import * as node from "../platform.js";
import * as browser from "../platform.browser.js";

const SRC = join(fileURLToPath(new URL(".", import.meta.url)), "..");
const PKG = JSON.parse(readFileSync(join(SRC, "..", "package.json"), "utf-8"));

let passed = 0;
const failures: string[] = [];

function test(name: string, fn: () => void): void {
  try {
    fn();
    passed++;
  } catch (e) {
    failures.push(`${name}\n      ${e instanceof Error ? e.message.split("\n")[0] : e}`);
  }
}

function sourceFiles(dir: string): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap(entry => {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) return entry.name === "__tests__" ? [] : sourceFiles(path);
    return entry.name.endsWith(".ts") ? [path] : [];
  });
}

test("no module but platform.ts imports from node:", () => {
  const offenders = sourceFiles(SRC)
    .filter(path => !path.endsWith(`${"/"}platform.ts`))
    .filter(path => /from\s+["']node:|require\(\s*["']node:|from\s+["'](?:crypto|fs|path|os)["']/
      .test(readFileSync(path, "utf-8")));
  assert.deepEqual(offenders.map(p => p.slice(SRC.length + 1)), []);
});

test("the browser field swaps platform.js in both builds", () => {
  assert.equal(PKG.browser?.["./dist/esm/platform.js"], "./dist/esm/platform.browser.js");
  assert.equal(PKG.browser?.["./dist/cjs/platform.js"], "./dist/cjs/platform.browser.js");
});

test("browser SHA-256 equals node:crypto, byte for byte", () => {
  const inputs: string[][] = [
    [""], ["abc"], ["a".repeat(55)], ["a".repeat(56)], ["a".repeat(64)], ["a".repeat(1000)],
    ["Jan Peeters, BE68 5390 0754 7034", "|", "BE|NL", "|", "rules"],
    ["Zürich – Ελλάδα – Łódź – 東京"], ["emoji 😀 and 𝔘𝔫𝔦𝔠𝔬𝔡𝔢"], ["lone \uD800 surrogate \uDC00"],
  ];
  let seed = 7;
  for (let i = 0; i < 200; i++) {
    let s = "";
    const len = (seed = (seed * 1103515245 + 12345) >>> 0) % 300;
    for (let j = 0; j < len; j++) {
      seed = (seed * 1103515245 + 12345) >>> 0;
      s += String.fromCharCode(seed % 0x2fff);
    }
    inputs.push([s, "|", "x"]);
  }
  for (const parts of inputs) assert.equal(browser.sha256Hex(parts), node.sha256Hex(parts), JSON.stringify(parts).slice(0, 60));
});

test("browser randomIndex stays in range and reaches every value", () => {
  const n = 28;
  const seen = new Set<number>();
  for (let i = 0; i < 5000; i++) {
    const r = browser.randomIndex(n);
    assert.ok(Number.isInteger(r) && r >= 0 && r < n, String(r));
    seen.add(r);
  }
  assert.equal(seen.size, n);
});

console.log(`${passed} passed, ${failures.length} failed`);
if (failures.length) {
  console.log("\nFAILURES:");
  for (const f of failures) console.log(`  - ${f}`);
  process.exit(1);
}
