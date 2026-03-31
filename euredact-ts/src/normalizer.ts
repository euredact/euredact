export function normalize(text: string): [string, number[] | null] {
  const normalized = text.normalize("NFC");
  if (normalized.length === text.length) return [normalized, null];
  return [normalized, buildOffsetMapping(text, normalized)];
}

function buildOffsetMapping(original: string, normalized: string): number[] {
  const nfdOriginal = original.normalize("NFD");
  const nfdNormalized = normalized.normalize("NFD");

  // Build: normalized index -> original index via NFD as intermediate
  const normToOrig: number[] = [];
  for (let normIdx = 0; normIdx < normalized.length; normIdx++) {
    const nfdOfNormChar = normalized[normIdx].normalize("NFD");
    let nfdStart = 0;
    for (let i = 0; i < normIdx; i++) {
      nfdStart += normalized[i].normalize("NFD").length;
    }
    let targetOrig = 0;
    let running = 0;
    for (let oi = 0; oi < original.length; oi++) {
      const nfdOc = original[oi].normalize("NFD");
      if (running + nfdOc.length > nfdStart) {
        targetOrig = oi;
        break;
      }
      running += nfdOc.length;
    }
    normToOrig.push(targetOrig);
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
