/**
 * Scoring rules shared by the corpus evaluation and its unit tests.
 *
 * Mirrors `_covered_chars` / `_recall_outcome` in
 * euredact-python/tests/eval_full.py so the two SDKs are measured by the same
 * definition (issue rules-engine#12; the rule itself is #8). Kept in its own
 * module because importing `evalFull.ts` runs the corpus evaluation.
 */

/**
 * Characters of `[start, end)` masked by `detections`, overlaps merged.
 * `acceptable` limits the count to those entity types; null counts any.
 */
export function coveredChars(
  detections: Array<{ start: number; end: number; entityType: unknown }>,
  start: number,
  end: number,
  acceptable: string[] | null,
): number {
  const spans = detections
    .filter(d => d.start < end && d.end > start
      && (acceptable === null || acceptable.includes(d.entityType as string)))
    .map(d => [Math.max(d.start, start), Math.min(d.end, end)] as [number, number])
    .sort((a, b) => a[0] - b[0]);
  let covered = 0;
  let cursor = start;
  for (const [a, b] of spans) {
    if (b <= cursor) continue;
    covered += b - Math.max(a, cursor);
    cursor = Math.max(cursor, b);
  }
  return covered;
}

/**
 * Classify one gold identifier. Mirrors `_recall_outcome` in
 * euredact-python/tests/eval_full.py, so the two SDKs are measured by the
 * same definition (issue rules-engine#12; the rule itself is #8).
 *
 * A redaction library is judged on whether the whole identifier is gone, so
 * "hit" means every character of the span is masked. The old test --
 * `!redactedText.includes(identifier)` with an any-overlap fallback -- was
 * satisfied by masking a single character, because that already destroys the
 * literal.
 */
export function recallOutcome(
  text: string,
  detections: Array<{ start: number; end: number; entityType: unknown }>,
  piiText: string,
  acceptable: string[],
): "hit" | "mistyped" | "partial" | "miss" | "unlocatable" {
  const idx = text.indexOf(piiText);
  if (idx < 0) return "unlocatable";
  const end = idx + piiText.length;
  const width = end - idx;
  if (coveredChars(detections, idx, end, acceptable) === width) return "hit";
  const anyType = coveredChars(detections, idx, end, null);
  if (anyType === width) return "mistyped";
  return anyType > 0 ? "partial" : "miss";
}
