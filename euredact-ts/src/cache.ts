import { sha256Hex } from "./platform.js";

const NEEDS_ESCAPE = /[\uFFFF\uD800-\uDFFF]/;

/**
 * `text`, with lone surrogates spelled out so that the cache key tells them
 * apart. `sha256Hex` hashes UTF-8, which writes every lone surrogate as U+FFFD:
 * "…\ud800" was answered with the cached result of "…\ufffd", so the caller
 * got back a text that was not theirs (rules-engine#175). A lone surrogate
 * becomes U+FFFF and its four hex digits, and U+FFFF itself, a noncharacter,
 * is doubled, which keeps the mapping one-to-one. Text with neither is
 * returned as it is.
 */
function injective(text: string): string {
  if (!NEEDS_ESCAPE.test(text)) return text;
  let out = "";
  for (let i = 0; i < text.length; i++) {
    const unit = text.charCodeAt(i);
    if (unit >= 0xd800 && unit <= 0xdbff && i + 1 < text.length) {
      const next = text.charCodeAt(i + 1);
      if (next >= 0xdc00 && next <= 0xdfff) {
        out += text[i] + text[i + 1];
        i++;
        continue;
      }
    }
    if (unit >= 0xd800 && unit <= 0xdfff) out += "\uFFFF" + unit.toString(16);
    else if (unit === 0xffff) out += "\uFFFF\uFFFF";
    else out += text[i];
  }
  return out;
}
import type { RedactResult } from "./types.js";

// Default ceiling on retained characters, not entries. A count-only cap of
// 1024 entries says nothing about memory: 1024 cached 1 MB documents is a
// gigabyte of PII-bearing text held live. ~16M characters is a few tens of MB.
const DEFAULT_MAX_CHARS = 16_000_000;

/** Approximate retained size of a cached result, in characters. */
export function resultChars(result: RedactResult): number {
  let chars = result.redactedText.length;
  for (const d of result.detections) chars += d.text.length;
  for (const [token, value] of Object.entries(result.tokens)) chars += token.length + value.length;
  for (const e of result.exempted) chars += e.text.length + e.rule.length;
  return chars;
}

/**
 * `result` with containers and detections of its own. A cached result was
 * handed out as is, so a caller emptying `detections` emptied them for every
 * later call on the same text (rules-engine#150).
 */
function copy(result: RedactResult): RedactResult {
  return {
    ...result,
    detections: result.detections.map(d => ({ ...d })),
    exempted: result.exempted.map(e => ({ ...e })),
    // Arrays in TypeScript, where Python has tuples (rules-engine#159).
    evidence: result.evidence.map(e => ({ ...e })),
    inferredCountries: result.inferredCountries.map(([c, w]) => [c, w] as [string, number]),
    tokens: { ...result.tokens },
  };
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
    return sha256Hex([injective(text), "|", sorted.join("|"), "|", mode]);
  }

  get(key: string): RedactResult | null {
    if (!this.enabled) return null;
    const result = this.store.get(key);
    if (result !== undefined) {
      // Move to end (LRU)
      this.store.delete(key);
      this.store.set(key, result);
      return copy(result);
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
    this.store.set(key, copy(result));
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
