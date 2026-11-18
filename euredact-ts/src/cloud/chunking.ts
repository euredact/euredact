/**
 * Cloud mode for documents over the service's input cap (rules-engine#183).
 *
 * The service refuses a request over 5,000 tokens with 413. In cloud mode the
 * SDK splits such a document itself, sends the parts and returns one result,
 * so a long document takes the same single call as a short one.
 *
 * What is split is the *masked* text: the local rules pass has already
 * replaced every structured identifier with a placeholder, a cut never falls
 * inside one, and only masked text is sent. Parts are cut at a blank line, a
 * line break, a sentence end or a space, in that order of preference, and
 * overlap their neighbour so that a name near a cut is seen whole by one of
 * them. The Python SDK cuts at the same places: planning counts code points
 * and tests only ASCII characters (`conformance/cloud_chunking.json`).
 *
 * Fail closed: if any part fails, the call throws, and the error says how
 * many parts were completed and billed.
 */

import { sha256Hex } from "../platform.js";
import type { ChunkInfo, CloudInfo, Detection, RedactResult, Review, Unlocated, Usage, UsageFactor } from "../types.js";
import { DetectionSource } from "../types.js";
import { uuid } from "./client.js";

/** Characters per part; see the Python module for the reasoning. */
export const DEFAULT_MAX_CHARS = 12_000;
/** Characters each part repeats of the one before. Provisional. */
export const DEFAULT_OVERLAP_CHARS = 300;
/** A part this short that still draws a 413 is not halved again. */
export const MIN_PART_CHARS = 500;

/** How cloud mode splits a document over the input cap. */
export interface ChunkingOptions {
  /** The longest part, in characters (code points) of the masked text. */
  maxChars?: number;
  /** How much each part repeats of the one before. 0 for none. */
  overlapChars?: number;
  /** Given the masked text, the positions (UTF-16 indices) to cut it at. A part
   *  it leaves over `maxChars` is split further at the built-in boundaries. */
  splitter?: (text: string) => number[];
  /** Parts sent at once. 1 by default: a free plan queues further requests. */
  concurrency?: number;
  /** Refuse, before anything is sent, a document needing more parts. */
  maxChunks?: number;
  /** Mask a value the model found in one part wherever the same text occurs in
   *  the others. On by default. */
  propagate?: boolean;
  /** Called after each part is answered, for progress on long documents. */
  onChunk?: (chunk: ChunkInfo) => void;
}

/** @internal The options with their defaults, checked. */
export interface ResolvedChunking {
  maxChars: number;
  overlapChars: number;
  splitter: ((text: string) => number[]) | null;
  concurrency: number;
  maxChunks: number | null;
  propagate: boolean;
  onChunk: ((chunk: ChunkInfo) => void) | null;
}

/** `"auto"` -> the defaults, `"off"` -> null, options -> checked. @internal */
export function resolveChunking(chunking: unknown): ResolvedChunking | null {
  if (chunking === "off") return null;
  if (chunking !== "auto" && (chunking === null || typeof chunking !== "object")) {
    throw new Error(`chunking must be "auto", "off" or an options object, not ${JSON.stringify(chunking)}`);
  }
  const o = (chunking === "auto" ? {} : chunking) as ChunkingOptions;
  const r: ResolvedChunking = {
    maxChars: o.maxChars ?? DEFAULT_MAX_CHARS,
    overlapChars: o.overlapChars ?? DEFAULT_OVERLAP_CHARS,
    splitter: o.splitter ?? null,
    concurrency: o.concurrency ?? 1,
    maxChunks: o.maxChunks ?? null,
    propagate: o.propagate ?? true,
    onChunk: o.onChunk ?? null,
  };
  if (r.maxChars < 2 * MIN_PART_CHARS) throw new Error(`chunking.maxChars must be at least ${2 * MIN_PART_CHARS}`);
  if (r.overlapChars < 0 || r.overlapChars > Math.floor(r.maxChars / 4)) {
    throw new Error("chunking.overlapChars must be between 0 and maxChars / 4");
  }
  if (r.concurrency < 1) throw new Error("chunking.concurrency must be at least 1");
  if (r.maxChunks !== null && r.maxChunks < 1) throw new Error("chunking.maxChunks must be at least 1");
  return r;
}

// ── Where to cut (code points) ─────────────────────────────────────────────

type Range = [number, number];

function inside(protectedRanges: Range[], pos: number): Range | null {
  for (const [start, end] of protectedRanges) {
    if (start < pos && pos < end) return [start, end];
    if (start >= pos) break;
  }
  return null;
}

/** The best cut in `cps[lo:hi]`, as the Python SDK's `_cut`. */
function cutIn(cps: string[], lo: number, hi: number): number {
  for (let i = hi - 2; i >= lo; i--) if (cps[i] === "\n" && cps[i + 1] === "\n") return i + 2;
  for (let i = hi - 1; i >= lo; i--) if (cps[i] === "\n") return i + 1;
  for (let i = hi - 1; i > lo; i--) {
    if ((cps[i] === " " || cps[i] === "\t") && (cps[i - 1] === "." || cps[i - 1] === "!" || cps[i - 1] === "?")) {
      return i + 1;
    }
  }
  for (let i = hi - 1; i >= lo; i--) if (cps[i] === " " || cps[i] === "\t") return i + 1;
  return hi;
}

function splitLong(cps: string[], lo: number, hi: number, maxChars: number, protectedRanges: Range[]): number[] {
  const cuts: number[] = [];
  let pos = lo;
  while (hi - pos > maxChars) {
    let cut = cutIn(cps, pos + Math.floor(maxChars / 2), pos + maxChars);
    const held = inside(protectedRanges, cut);
    if (held) cut = held[0] > pos ? held[0] : held[1];
    cuts.push(cut);
    pos = cut;
  }
  return cuts;
}

function overlapStart(cps: string[], cut: number, lo: number, protectedRanges: Range[]): number {
  if (lo >= cut) return cut;
  let start = lo;
  for (let i = lo; i < cut; i++) {
    if (cps[i] === " " || cps[i] === "\t" || cps[i] === "\n") {
      start = i + 1;
      break;
    }
  }
  const held = inside(protectedRanges, start);
  return held ? held[0] : start;
}

/**
 * The parts to send, as `[start, end]` in code points of `text`, overlapping.
 * `protectedRanges` (the placeholders, in code points, sorted) are never cut.
 * `points` are extra cut positions, in code points.
 * @internal Exported for the conformance cases.
 */
export function plan(
  text: string, protectedRanges: Range[], maxChars: number, overlap: number, points: number[] = [],
): Range[] {
  const cps = [...text];
  const n = cps.length;
  overlap = Math.min(overlap, Math.floor(maxChars / 4));
  const cutsAt = [...new Set(points.filter(p => 0 < p && p < n))].sort((a, b) => a - b)
    .filter(p => inside(protectedRanges, p) === null);
  const bounds = [0, ...cutsAt, n];
  const step = maxChars - overlap;
  const cuts: number[] = [];
  for (let i = 0; i + 1 < bounds.length; i++) {
    cuts.push(...splitLong(cps, bounds[i], bounds[i + 1], step, protectedRanges));
    if (bounds[i + 1] !== n) cuts.push(bounds[i + 1]);
  }
  if (cuts.length === 0) return [[0, n]];
  const parts: Range[] = [];
  let start = 0;
  for (const cut of [...cuts, n]) {
    parts.push([start, cut]);
    if (cut !== n) start = overlapStart(cps, cut, Math.max(start + 1, cut - overlap), protectedRanges);
  }
  return parts;
}

// ── Sending and merging ────────────────────────────────────────────────────

/** Code point <-> UTF-16 unit offsets of one text. */
function offsets(text: string): { toUnit: (cp: number) => number; toCp: (unit: number) => number } {
  const units: number[] = [];
  let u = 0;
  for (const ch of text) {
    units.push(u);
    u += ch.length;
  }
  units.push(u);
  const back = new Map<number, number>();
  units.forEach((unit, cp) => back.set(unit, cp));
  return {
    toUnit: cp => units[Math.min(cp, units.length - 1)],
    toCp: unit => {
      for (let x = unit; x >= 0; x--) {
        const cp = back.get(x);
        if (cp !== undefined) return cp;
      }
      return 0;
    },
  };
}

/** Each part's Idempotency-Key, as the Python SDK's `part_key`. @internal */
export function partKey(key: string | undefined, index: number, part: string): string {
  if (key === undefined) return uuid();
  return `${key}:${index}:${sha256Hex([part]).slice(0, 16)}`;
}

type Answer = Array<[Range, RedactResult]>;  // ranges in UTF-16 units of the masked text

interface Annotated extends Error { chunksCompleted?: number; chunksTotal?: number }

/**
 * Send `text` in parts and merge the answers into one result over `text`
 * (UTF-16 offsets, as `CloudClient.redact` returns them).
 * @internal
 */
export async function runChunked(
  send: (part: string, key: string) => Promise<RedactResult>,
  text: string,
  protectedUnits: Range[],
  options: ResolvedChunking,
  key: string | undefined,
  toOriginal: (start: number, end: number) => Range,
  TooLarge: new (...args: never[]) => Error,
): Promise<RedactResult> {
  const { toUnit, toCp } = offsets(text);
  const protectedCps: Range[] = protectedUnits.map(([s, e]) => [toCp(s), toCp(e)]);
  const n = [...text].length;
  const points = options.splitter ? options.splitter(text).map(p => toCp(p)) : [];
  let cpParts = plan(text, protectedCps, options.maxChars, options.overlapChars, points);
  if (options.maxChunks !== null && cpParts.length > options.maxChunks) {
    throw new Error(`the document needs ${cpParts.length} parts, more than maxChunks=${options.maxChunks}; nothing was sent`);
  }
  if (cpParts.length === 1) {
    // Short enough to go whole: today's request, under the caller's own key.
    try {
      return await send(text, key ?? uuid());
    } catch (err) {
      if (!(err instanceof TooLarge) || n < 2 * MIN_PART_CHARS) throw err;
      cpParts = plan(text, protectedCps, Math.floor((n + 1) / 2) + 1, options.overlapChars);
    }
  }
  const parts: Range[] = cpParts.map(([s, e]) => [toUnit(s), toUnit(e)]);

  const one = async (index: number, cp: Range): Promise<Answer> => {
    const [s, e] = [toUnit(cp[0]), toUnit(cp[1])];
    const piece = text.slice(s, e);
    try {
      return [[[s, e], await send(piece, partKey(key, index, piece))]];
    } catch (err) {
      if (!(err instanceof TooLarge) || cp[1] - cp[0] < 2 * MIN_PART_CHARS) throw err;
      const shifted = protectedCps.filter(([a, b]) => cp[0] <= a && b <= cp[1])
        .map(([a, b]) => [a - cp[0], b - cp[0]] as Range);
      const halves = plan(piece, shifted, Math.floor((cp[1] - cp[0] + 1) / 2) + 1, options.overlapChars);
      const out: Answer = [];
      for (let j = 0; j < halves.length; j++) {
        out.push(...await one(index * 1000 + j + 1, [cp[0] + halves[j][0], cp[0] + halves[j][1]]));
      }
      return out;
    }
  };

  const total = parts.length;
  const answers: Array<Answer | null> = new Array(total).fill(null);
  const done = (index: number, got: Answer): void => {
    answers[index] = got;
    if (options.onChunk) {
      const [s, e] = toOriginal(...parts[index]);
      options.onChunk({ index, total, start: s, end: e,
        jobId: got[0][1].cloud?.jobId ?? null, tokens: tokensOf(got.map(([, r]) => r)) });
    }
  };
  let failure: unknown = null;
  if (options.concurrency === 1 || total === 1) {
    for (let i = 0; i < total; i++) {
      try {
        done(i, await one(i, cpParts[i]));
      } catch (err) {
        failure = err;
        break;
      }
    }
  } else {
    let next = 0;
    const worker = async () => {
      while (next < total && failure === null) {
        const i = next++;
        try {
          done(i, await one(i, cpParts[i]));
        } catch (err) {
          failure ??= err;
        }
      }
    };
    await Promise.all(Array.from({ length: Math.min(options.concurrency, total) }, worker));
  }
  if (failure !== null) {
    const completed = answers.filter(a => a !== null).length;
    if (failure instanceof Error) {
      const f = failure as Annotated;
      f.chunksCompleted = completed;
      f.chunksTotal = total;
      f.message += ` (split into ${total} parts; ${completed} completed and billed, the result discarded)`;
    }
    throw failure;
  }
  return merge(text, answers as Answer[], parts, options, toOriginal);
}

function tokensOf(results: RedactResult[]): number | null {
  const found = results.filter(r => r.cloud?.usage).map(r => r.cloud!.usage!.tokens);
  return found.length ? found.reduce((a, b) => a + b, 0) : null;
}

const shift = (d: Detection, by: number): Detection => ({ ...d, start: d.start + by, end: d.end + by });

function merge(
  text: string, answers: Answer[], parts: Range[], options: ResolvedChunking,
  toOriginal: (start: number, end: number) => Range,
): RedactResult {
  const flat = answers.flat();
  const seen = new Set<string>();
  let detections: Detection[] = [];
  for (const [[start], result] of flat) {
    for (const d of result.detections) {
      const moved = shift(d, start);
      const k = `${moved.start}|${moved.end}|${moved.entityType}`;
      if (seen.has(k)) continue;
      seen.add(k);
      detections.push(moved);
    }
  }
  // A span another part found whole, of the same type, is the same value seen
  // from the overlap: keep the whole one.
  detections = detections.filter(d => !detections.some(o => o !== d && o.entityType === d.entityType
    && o.start <= d.start && d.end <= o.end && (o.end - o.start) > (d.end - d.start)));
  if (options.propagate && parts.length > 1) detections.push(...propagated(text, detections));
  detections.sort((a, b) => a.start - b.start || b.end - a.end);

  const unlocated: Unlocated[] = [];
  for (const [, r] of flat) {
    for (const u of r.cloud?.unlocated ?? []) {
      if (!unlocated.some(x => x.text === u.text && x.entityType === u.entityType)) unlocated.push(u);
    }
  }
  const usages = flat.map(([, r]) => r.cloud?.usage).filter((u): u is Usage => !!u);
  let usage: Usage | undefined;
  if (usages.length) {
    const factors: UsageFactor[] = [];
    for (const u of usages) {
      for (const f of u.factors) {
        if (!factors.some(x => JSON.stringify(x) === JSON.stringify(f))) factors.push(f);
      }
    }
    const tokens = usages.reduce((a, u) => a + u.tokens, 0);
    const credits = usages.reduce((a, u) => a + u.credits, 0);
    usage = { tokens, billingRate: tokens ? credits / tokens : 0, credits, factors };
  }
  const first = flat[0][1].cloud;
  const chunks: ChunkInfo[] = parts.map((range, index) => {
    const mine = answers[index].map(([, r]) => r);
    const [s, e] = toOriginal(...range);
    return { index, total: parts.length, start: s, end: e,
      jobId: mine[0].cloud?.jobId ?? null, tokens: tokensOf(mine) };
  });
  const cloud: CloudInfo = {
    jobId: parts.length > 1 ? null : (first?.jobId ?? null),
    modelVersion: first?.modelVersion ?? null,
    ...(usage ? { usage } : {}),
    unlocated,
    ...(parts.length > 1 ? { chunks } : {}),
  };
  return {
    redactedText: text, detections, source: "cloud", degraded: false,
    inferredCountries: [], evidence: [], detectionMode: "declared", tokens: {}, exempted: [],
    cloud, review: mergeReviews(flat.map(([[s], r]) => [s, r.review ?? null] as [number, Review | null])),
  };
}

const WORDISH = /[\p{L}\p{N}_]/u;

function boundaryBefore(text: string, at: number): boolean {
  if (at <= 0) return true;
  const ch = String.fromCodePoint(text.codePointAt(at - 1 - (at >= 2 && /[\uDC00-\uDFFF]/.test(text[at - 1]) ? 1 : 0))!);
  return !WORDISH.test(ch);
}

function boundaryAfter(text: string, end: number): boolean {
  if (end >= text.length) return true;
  return !WORDISH.test(String.fromCodePoint(text.codePointAt(end)!));
}

/** The other occurrences of each value the model found (`propagate`). */
function propagated(text: string, detections: Detection[]): Detection[] {
  const taken = new Uint8Array(text.length + 1);
  for (const d of detections) taken.fill(1, d.start, d.end);
  const values = new Map<string, Detection>();
  for (const d of detections) {
    if (d.source === DetectionSource.CLOUD && d.text.trim().length >= 3 && !d.text.includes("[")
        && !values.has(d.text)) values.set(d.text, d);
  }
  const out: Detection[] = [];
  for (const [value, model] of values) {
    for (let at = text.indexOf(value); at >= 0; at = text.indexOf(value, at + 1)) {
      const end = at + value.length;
      if (!taken.subarray(at, end).some(x => x === 1) && boundaryBefore(text, at) && boundaryAfter(text, end)) {
        out.push({ ...model, start: at, end });
        taken.fill(1, at, end);
      }
    }
  }
  return out;
}

/** One review for the document, as the Python SDK's `_merge_reviews`. */
function mergeReviews(reviews: Array<[number, Review | null]>): Review | null {
  const present = reviews.filter((x): x is [number, Review] => x[1] !== null);
  if (!present.length) return null;
  const scores = present.map(([, r]) => r.score);
  const score = scores.every(x => x !== null)
    ? 1 - (scores as number[]).reduce((clean, x) => clean * (1 - x), 1) : null;
  const recommending = present.map(([, r]) => r).filter(r => r.recommended);
  const flags: string[] = [];
  const uncertain: Detection[] = [];
  for (const [start, r] of present) {
    for (const f of r.flags) if (!flags.includes(f)) flags.push(f);
    for (const d of r.uncertain) {
      const moved = shift(d, start);
      if (!uncertain.some(u => u.start === moved.start && u.end === moved.end)) uncertain.push(moved);
    }
  }
  return {
    score, recommended: recommending.length > 0,
    basis: (recommending[0] ?? present[0][1]).basis,
    flags, uncertain: uncertain.sort((a, b) => a.start - b.start || a.end - b.end),
  };
}
