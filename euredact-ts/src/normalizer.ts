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
  // Precompute cumulative NFD lengths for normalized characters
  const normNfdCum = [0];
  for (let i = 0; i < normalized.length; i++) {
    normNfdCum.push(normNfdCum[i] + normalized[i].normalize("NFD").length);
  }

  // Precompute cumulative NFD lengths for original characters
  const origNfdCum = [0];
  for (let i = 0; i < original.length; i++) {
    origNfdCum.push(origNfdCum[i] + original[i].normalize("NFD").length);
  }

  // Two-pointer scan: map each normalized position to its original position
  const normToOrig: number[] = [];
  let origPtr = 0;
  for (let normIdx = 0; normIdx < normalized.length; normIdx++) {
    const nfdStart = normNfdCum[normIdx];
    while (origPtr + 1 < original.length && origNfdCum[origPtr + 1] <= nfdStart) {
      origPtr++;
    }
    normToOrig.push(origPtr);
  }
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
