/**
 * Windows of text measured in code points, as the Python SDK measures them.
 *
 * `text.slice(start - 150, start)` counts UTF-16 units: an emoji takes two,
 * so the TypeScript window reached half as far back across them as Python's,
 * and "Passport" followed by fifty emoji was context in Python and out of
 * reach here (rules-engine#151).
 */

const isHigh = (c: number) => c >= 0xd800 && c <= 0xdbff;
const isLow = (c: number) => c >= 0xdc00 && c <= 0xdfff;

/** The `n` code points before `pos`: Python's `text[pos - n:pos]`. */
export function cpBefore(text: string, pos: number, n: number): string {
  let i = pos;
  for (let k = 0; k < n && i > 0; k++) {
    i--;
    if (i > 0 && isLow(text.charCodeAt(i)) && isHigh(text.charCodeAt(i - 1))) i--;
  }
  return text.slice(i, pos);
}

/** The `n` code points from `pos`: Python's `text[pos:pos + n]`. */
export function cpAfter(text: string, pos: number, n: number): string {
  let i = pos;
  for (let k = 0; k < n && i < text.length; k++) {
    i += isHigh(text.charCodeAt(i)) && i + 1 < text.length && isLow(text.charCodeAt(i + 1)) ? 2 : 1;
  }
  return text.slice(pos, i);
}

/** Where the next code point starts: one past `pos`, or two past a surrogate pair. */
export function nextCodePoint(text: string, pos: number): number {
  return pos + (isHigh(text.charCodeAt(pos)) && pos + 1 < text.length && isLow(text.charCodeAt(pos + 1)) ? 2 : 1);
}
