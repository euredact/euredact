/**
 * The two things the SDK needs from a crypto library: a SHA-256 digest for the
 * result-cache key and a uniform random index for token suffixes.
 *
 * This is the Node implementation, on `node:crypto`. A browser bundle gets
 * `platform.browser.ts` instead, through the `browser` field in package.json,
 * because `node:crypto` does not exist there and importing it from `cache.ts`
 * and `sdk.ts` made the package unbundleable for a page (rules-engine#56).
 * Every other module imports these two functions from here and nothing from
 * `node:`; a test holds the source tree to that.
 */
import { createHash, randomInt } from "node:crypto";

/** Hex SHA-256 of the UTF-8 encoding of `parts`, joined with nothing between. */
export function sha256Hex(parts: string[]): string {
  const hash = createHash("sha256");
  for (const part of parts) hash.update(part);
  return hash.digest("hex");
}

/** A uniformly random integer in `[0, n)`. */
export function randomIndex(n: number): number {
  return randomInt(n);
}
