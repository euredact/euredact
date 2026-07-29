/**
 * Country evidence shared across the chunks of one document.
 *
 * A long document is usually redacted in pieces. Each piece is scanned
 * independently, so each infers its own country — and a chunk that happens to
 * contain no IBAN, no `+CC` number and no ccTLD infers nothing at all, even
 * when the first page identified the document beyond doubt:
 *
 *     page 1   "Factuur — IBAN NL91ABNA0417164300, info@jansen.nl"
 *     page 7   "Telefoon 0612345678"        <- Dutch mobile, or Danish CPR?
 *
 * Scanned alone, page 7 has nothing to go on. Sharing a context across the two
 * carries page 1's evidence forward, and the number resolves as a Dutch phone.
 *
 * Spans are rebased by `chunkOffset` on the way in, so evidence collected from
 * a chunk points at offsets in the whole document rather than the chunk.
 *
 * A context influences **scoring only**. It can change which national scheme is
 * attributed to a value. It can never change which spans are found, so a
 * context carried over from the wrong document cannot cause a miss.
 */

import type { CountryEvidence } from "../types.js";

export class DocumentContext {
  // Deduped on the same key evidence.collect() uses, so re-running a chunk — a
  // retry, an overlapping window — cannot let one entity vote twice and
  // outweigh the rest of the document.
  private seen = new Set<string>();
  private items: CountryEvidence[] = [];

  /** Record evidence from a chunk starting at `chunkOffset`. */
  add(evidence: CountryEvidence[], chunkOffset = 0): void {
    for (const ev of evidence) {
      const span: [number, number] = [ev.span[0] + chunkOffset, ev.span[1] + chunkOffset];
      const key = `${span[0]}:${span[1]}:${ev.source}`;
      if (this.seen.has(key)) continue;
      this.seen.add(key);
      this.items.push(chunkOffset === 0 ? ev : { ...ev, span });
    }
  }

  /**
   * Everything recorded so far, spans rebased to the whole document.
   *
   * A getter, to match {@link DocumentContext.size}. These were a method and a
   * getter on the same class, which is a trip hazard rather than a style
   * question: `ctx.size()` and `ctx.evidence` both *succeed* and return
   * something useless — a number is not callable, and a function object is
   * truthy — so the mistake surfaces later as an empty result rather than as
   * an error. Both are property reads now, and the wrong form throws.
   *
   * Returns a fresh copy each call, so mutating it cannot corrupt the context.
   * (The Python SDK spells this `evidence()`, following its own idiom.)
   */
  get evidence(): CountryEvidence[] {
    return [...this.items];
  }

  get size(): number {
    return this.items.length;
  }
}
