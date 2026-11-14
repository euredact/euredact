/**
 * The zero of every run of decimal digits in the Basic Multilingual Plane
 * outside ASCII (Unicode 16; each run is 0-9 in order). The Python SDK carries
 * the same list, so both fold the same characters whatever Unicode version
 * their runtime has.
 */
const DIGIT_ZEROS = [
  0x0660, 0x06F0, 0x07C0, 0x0966, 0x09E6, 0x0A66, 0x0AE6, 0x0B66, 0x0BE6,
  0x0C66, 0x0CE6, 0x0D66, 0x0DE6, 0x0E50, 0x0ED0, 0x0F20, 0x1040, 0x1090,
  0x17E0, 0x1810, 0x1946, 0x19D0, 0x1A80, 0x1A90, 0x1B50, 0x1BB0, 0x1C40,
  0x1C50, 0xA620, 0xA8D0, 0xA900, 0xA9D0, 0xA9F0, 0xAA50, 0xABF0, 0xFF10,
];

const ASCII_DIGITS = new Map<string, string>(
  DIGIT_ZEROS.flatMap(zero => Array.from({ length: 10 }, (_, k) => [String.fromCharCode(zero + k), String(k)] as [string, string])),
);
const NON_ASCII_DIGIT = new RegExp(
  "[" + DIGIT_ZEROS.map(z => `\\u${z.toString(16).padStart(4, "0")}-\\u${(z + 9).toString(16).padStart(4, "0")}`).join("") + "]", "g",
);

/**
 * NFC, and digits folded to ASCII, before pattern matching. Returns the text
 * and a mapping from its offsets to the original's (null when NFC left the
 * text as it was).
 *
 * The mapping is built whenever NFC changed the text, not only its length: a
 * composition and an expansion (U+0958) cancel out in the length and still
 * move the characters between them (rules-engine#150). Digits are folded one
 * character for one, so offsets stay put: the patterns expect ASCII digits,
 * and a phone number in full-width digits was left whole (rules-engine#150).
 */
export function normalize(text: string): [string, number[] | null] {
  const nfc = text.normalize("NFC");
  const mapping = nfc === text ? null : buildOffsetMapping(text, nfc);
  return [nfc.replace(NON_ASCII_DIGIT, d => ASCII_DIGITS.get(d) ?? d), mapping];
}

function buildOffsetMapping(original: string, normalized: string): number[] {
  // By code point, one entry per UTF-16 unit of the normalised text. Walking
  // units called normalize() on each half of a surrogate pair, and after an
  // astral character NFC changes (U+2F800, U+1D15E) every later mask was off
  // and left characters of an e-mail visible (rules-engine#159).
  const normNfdCum: number[] = [0];
  const normUnitStart: number[] = [];
  for (const ch of normalized) {
    for (let k = 0; k < ch.length; k++) normUnitStart.push(normNfdCum.length - 1);
    normNfdCum.push(normNfdCum[normNfdCum.length - 1] + ch.normalize("NFD").length);
  }
  const origNfdCum: number[] = [0];
  const origUnitOf: number[] = [];
  let unit = 0;
  for (const ch of original) {
    origUnitOf.push(unit);
    unit += ch.length;
    origNfdCum.push(origNfdCum[origNfdCum.length - 1] + ch.normalize("NFD").length);
  }

  // Two-pointer scan over code points; each normalised unit maps to the
  // original unit where its code point's NFD run starts.
  const normToOrig: number[] = [];
  const cpOrig = origUnitOf.length;
  let origPtr = 0;
  for (let u = 0; u < normalized.length; u++) {
    const nfdStart = normNfdCum[normUnitStart[u]];
    while (origPtr + 1 < cpOrig && origNfdCum[origPtr + 1] <= nfdStart) origPtr++;
    normToOrig.push(cpOrig === 0 ? 0 : origUnitOf[origPtr]);
  }
  // The end of the text maps to the end of the original (rules-engine#159).
  normToOrig.push(original.length);
  return normToOrig;
}

export function mapOffsetToOriginal(offset: number, mapping: number[] | null): number {
  if (mapping === null) return offset;
  if (offset >= mapping.length) {
    if (mapping.length > 0) return mapping[mapping.length - 1] + (offset - mapping.length + 1);
    return offset;
  }
  return mapping[offset];
}
