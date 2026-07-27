export function normalize(text: string): [string, number[] | null] {
  const normalized = text.normalize("NFC");
  if (normalized.length === text.length) return [normalized, null];
  return [normalized, buildOffsetMapping(text, normalized)];
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
