import type { RedactResult } from "./types.js";

// Simple hash function (FNV-1a) - no crypto dependency needed for cache keys
function fnv1aHash(str: string): string {
  let hash = 0x811c9dc5;
  for (let i = 0; i < str.length; i++) {
    hash ^= str.charCodeAt(i);
    hash = (hash * 0x01000193) >>> 0;
  }
  return hash.toString(16).padStart(8, "0");
}

export class ResultCache {
  private maxsize: number;
  private enabled: boolean;
  private store = new Map<string, RedactResult>();

  constructor(maxsize = 1024, enabled = true) {
    this.maxsize = maxsize;
    this.enabled = enabled;
  }

  key(text: string, countries: string[], mode: string): string {
    const sorted = [...countries].sort();
    const raw = `${text}|${sorted.join("|")}|${mode}`;
    // Use multiple FNV-1a hashes on different slices for reduced collisions
    const h1 = fnv1aHash(raw);
    const h2 = fnv1aHash(raw.slice(Math.floor(raw.length / 2)) + raw.slice(0, Math.floor(raw.length / 2)));
    return h1 + h2;
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
    this.store.delete(key);
    this.store.set(key, result);
    while (this.store.size > this.maxsize) {
      const first = this.store.keys().next().value;
      if (first !== undefined) this.store.delete(first);
    }
  }

  clear(): void {
    this.store.clear();
  }
}
