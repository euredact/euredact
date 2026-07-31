import { createHash } from "node:crypto";
import type { RedactResult } from "./types.js";

// Default ceiling on retained characters, not entries. A count-only cap of
// 1024 entries says nothing about memory: 1024 cached 1 MB documents is a
// gigabyte of PII-bearing text held live. ~16M characters is a few tens of MB.
const DEFAULT_MAX_CHARS = 16_000_000;

/** Approximate retained size of a cached result, in characters. */
function resultChars(result: RedactResult): number {
  let chars = result.redactedText.length;
  for (const d of result.detections) chars += d.text.length;
  return chars;
}

export class ResultCache {
  private maxsize: number;
  private maxChars: number;
  private enabled: boolean;
  private store = new Map<string, RedactResult>();
  private sizes = new Map<string, number>();
  private chars = 0;

  constructor(maxsize = 1024, enabled = true, maxChars = DEFAULT_MAX_CHARS) {
    this.maxsize = maxsize;
    this.maxChars = maxChars;
    this.enabled = enabled;
  }

  key(text: string, countries: string[], mode: string): string {
    const sorted = [...countries].sort();
    // SHA-256, matching the Python implementation. The previous dual FNV-1a
    // was non-cryptographic and collidable by construction: in a shared-process
    // deployment an attacker who can guess a victim's document could submit a
    // same-length colliding one and be served the victim's cached result,
    // detections and raw matched PII included.
    return createHash("sha256")
      .update(text)
      .update("|")
      .update(sorted.join("|"))
      .update("|")
      .update(mode)
      .digest("hex");
  }

  get(key: string): RedactResult | null {
    if (!this.enabled) return null;
    const result = this.store.get(key);
    if (result !== undefined) {
      // Move to end (LRU)
      this.store.delete(key);
      this.store.set(key, result);
      return result;
    }
    return null;
  }

  put(key: string, result: RedactResult): void {
    if (!this.enabled) return;
    const size = resultChars(result);
    // A single result bigger than the whole budget would evict everything else
    // and still not fit; skip it rather than empty the cache for one document.
    if (size > this.maxChars) {
      this.evict(key);
      return;
    }
    this.evict(key);
    this.store.set(key, result);
    this.sizes.set(key, size);
    this.chars += size;
    while (this.store.size > this.maxsize || this.chars > this.maxChars) {
      const first = this.store.keys().next().value;
      if (first === undefined) break;
      this.evict(first);
    }
  }

  private evict(key: string): void {
    const size = this.sizes.get(key);
    if (size !== undefined) {
      this.chars -= size;
      this.sizes.delete(key);
    }
    this.store.delete(key);
  }

  clear(): void {
    this.store.clear();
    this.sizes.clear();
    this.chars = 0;
  }
}
