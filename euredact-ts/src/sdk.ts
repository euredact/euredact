import { ResultCache } from "./cache.js";
import { normalize, mapOffsetToOriginal } from "./normalizer.js";
import { RuleEngine } from "./rules/engine.js";
import { DocumentContext } from "./rules/context.js";
import { weightsToRanking } from "./rules/evidence.js";
import { EntityType, type Detection, type RedactResult } from "./types.js";

const DATE_TYPES = new Set<EntityType | string>([EntityType.DOB, EntityType.DATE_OF_DEATH]);

/** Entry count at which a one-time warning is emitted. */
const MAPPING_WARN_THRESHOLD = 100_000;

/**
 * Maps real PII values to consistent labels within a session.
 *
 * The mapping is keyed on the **raw PII value** and is never evicted — evicting
 * would hand a previously seen value a second label and quietly break
 * referential integrity. Two consequences worth designing around:
 *
 * - It grows for as long as the process runs. Call `clear()` between workloads;
 *   a warning is emitted once the mapping passes `MAPPING_WARN_THRESHOLD`.
 * - Labels are shared by every caller of the same instance, including every
 *   caller of the module-level `redact()`. A label repeated across two
 *   documents reveals that they contain the same underlying value, so give each
 *   tenant its own `EuRedact` instance rather than sharing the module-level one.
 */
class ReferentialMapper {
  private counters = new Map<EntityType | string, number>();
  private mapping = new Map<string, string>();
  private warned = false;

  getLabel(text: string, entityType: EntityType | string): string {
    if (!this.mapping.has(text)) {
      const count = (this.counters.get(entityType) ?? 0) + 1;
      this.counters.set(entityType, count);
      this.mapping.set(text, `${entityType}_${count}`);
      if (!this.warned && this.mapping.size > MAPPING_WARN_THRESHOLD) {
        this.warned = true;
        console.warn(
          `[euredact] Referential integrity mapping holds ${this.mapping.size} ` +
          `raw PII values and is never evicted. Call clear() between workloads ` +
          `to release them.`,
        );
      }
    }
    return this.mapping.get(text)!;
  }

  clear(): void {
    this.counters.clear();
    this.mapping.clear();
    this.warned = false;
  }
}

export interface RedactOptions {
  /**
   * Scope. Detections attributed elsewhere are flagged `outOfScope`, never
   * dropped, and this also acts as a prior when resolving which national
   * scheme owns an ambiguous value. It does **not** gate what is looked for.
   */
  countries?: string[] | null;
  /**
   * A prior only. Helps resolve ambiguity without narrowing scope or flagging
   * anything out of scope.
   */
  countryHint?: string[] | null;
  /**
   * Shares country evidence across the chunks of one document, so a chunk
   * carrying no country signal of its own is still scored against what the
   * rest of the document showed. Pass the same object for every chunk, with
   * `chunkOffset` set to where the chunk starts in the whole document.
   */
  context?: DocumentContext | null;
  /** Offset of this chunk within the document. Used only to rebase spans
   *  recorded in `context`; returned detections are relative to `text`. */
  chunkOffset?: number;
  mode?: string;
  referentialIntegrity?: boolean;
  detectDates?: boolean;
  cache?: boolean;
}

const DEFAULT_MAX_INPUT_LENGTH = 10_485_760;  // ~10 MB of text

/**
 * Reject a bare string where a list of country codes is expected.
 *
 * `countries: "NL"` is iterable, so it walks into the codes "N" and "L".
 * Neither resolves, so nothing is declared — and every detection that *does*
 * carry a country is then flagged `outOfScope`. A caller following the
 * documented pattern of filtering on that field silently keeps none of them,
 * while `redactedText` still looks perfectly correct. The failure direction is
 * "no PII here", from a one-character typo.
 *
 * This already threw in Node, but by accident and only once something happened
 * to call `.map` on it — deep in the call, with a message naming neither the
 * argument nor the fix.
 *
 * A wrong *code* is data and only warns; raising there would invite callers to
 * wrap redaction in try/catch and skip it. A wrong *type* is a programming
 * error with no correct interpretation to fall back on.
 */
function checkCountryArg(value: unknown, param: string): void {
  if (typeof value === "string") {
    throw new TypeError(
      `${param} must be an array of country codes, not a bare string. ` +
      `Pass ${param}: ["${value}"] rather than ${param}: "${value}" — a string ` +
      `is iterated character by character, which silently declares nothing and ` +
      `flags every detection outOfScope.`
    );
  }
}

export class EuRedact {
  private engine = new RuleEngine();
  private cache = new ResultCache();
  private referentialMapper = new ReferentialMapper();
  private maxInputLength: number;

  constructor(options?: { maxInputLength?: number }) {
    this.maxInputLength = options?.maxInputLength ?? DEFAULT_MAX_INPUT_LENGTH;
  }

  addCustomPattern(name: string, pattern: string): void {
    this.engine.addCustomPattern(name, pattern);
    this.cache.clear();
  }

  /** Clear the result cache and referential integrity mappings.
   *  Call this in long-running processes to free PII from memory. */
  clear(): void {
    this.cache.clear();
    this.referentialMapper.clear();
  }

  redact(text: string, options: RedactOptions = {}): RedactResult {
    checkCountryArg(options.countries, "countries");
    checkCountryArg(options.countryHint, "countryHint");

    if (text.length > this.maxInputLength) {
      throw new Error(
        `Input text length (${text.length.toLocaleString()} chars) exceeds the maximum ` +
        `(${this.maxInputLength.toLocaleString()} chars). Split the input or ` +
        `increase maxInputLength when constructing EuRedact.`
      );
    }

    const {
      countries = null,
      countryHint = null,
      context = null,
      chunkOffset = 0,
      mode = "rules",
      referentialIntegrity = false,
      detectDates = false,
    } = options;
    // A context makes the result depend on evidence from other chunks, so the
    // text no longer identifies the result. Caching is disabled rather than
    // keyed on the context, whose contents change as chunks arrive.
    const cache = context !== null ? false : (options.cache ?? true);

    const [normalizedText, offsetMapping] = normalize(text);

    const countriesTuple = countries
      ? countries.map(c => c.toUpperCase()).sort()
      : ["ALL"];
    // countryHint changes attribution, so it must key the cache too.
    const hintKey = countryHint ? countryHint.map(c => c.toUpperCase()).sort().join(",") : "";
    const cacheMode = `${mode}|dates=${detectDates}|hint=${hintKey}`;

    let cacheKey: string | undefined;
    if (cache) {
      cacheKey = this.cache.key(normalizedText, countriesTuple, cacheMode);
      const cached = this.cache.get(cacheKey);
      if (cached !== null) return cached;
    }

    const {
      detections: rawDetections,
      evidence,
      scores,
    } = this.engine.detectWithEvidence(
      normalizedText, countries, countryHint,
      context !== null ? context.evidence : null,
    );
    if (context !== null) context.add(evidence, chunkOffset);
    let detections = rawDetections;

    if (offsetMapping !== null) {
      detections = detections.map(d => ({
        ...d,
        start: mapOffsetToOriginal(d.start, offsetMapping),
        end: mapOffsetToOriginal(d.end, offsetMapping),
      }));
    }

    if (!detectDates) {
      detections = detections.filter(d => !DATE_TYPES.has(d.entityType));
    }

    detections.sort((a, b) => a.start - b.start || b.end - a.end);

    // Labels are resolved right-to-left because the referential mapper numbers
    // each entity type in call order, and that order is part of the output
    // contract. The string itself is then assembled in a single forward pass:
    // rebuilding it per detection copied the whole document each time, which is
    // O(document x detections) — 1.68 s of pure copying on a 1 MB document with
    // 15,000 detections, versus 2 ms here.
    const replacements: string[] = new Array(detections.length);
    for (let i = detections.length - 1; i >= 0; i--) {
      const det = detections[i];
      replacements[i] = referentialIntegrity
        ? this.referentialMapper.getLabel(det.text, det.entityType)
        : `[${det.entityType}]`;
    }

    const parts: string[] = [];
    let pos = 0;
    for (let i = 0; i < detections.length; i++) {
      const det = detections[i];
      // Spans reach here deduplicated and non-overlapping; one starting behind
      // the cursor would splice into the middle of a label, so drop it.
      if (det.start < pos) continue;
      parts.push(text.slice(pos, det.start), replacements[i]);
      pos = det.end;
    }
    parts.push(text.slice(pos));
    const redacted = parts.join("");

    // Report the inference so it can be audited. Spans in `evidence` are
    // offsets into the normalised text, matching `detections`.
    const inferredCountries = [...weightsToRanking(scores).entries()]
      .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));

    const result: RedactResult = {
      redactedText: redacted,
      detections,
      source: "rules",
      degraded: false,
      inferredCountries,
      evidence,
      detectionMode: countries && countries.length ? "declared" : "inferred",
    };

    if (cache && cacheKey) {
      this.cache.put(cacheKey, result);
    }

    return result;
  }

  redactBatch(texts: string[], options: RedactOptions = {}): RedactResult[] {
    // Generation is country-blind, so every country's patterns are loaded
    // regardless of what the caller declared.
    this.engine.loadCountries(null);
    return texts.map(text => this.redact(text, options));
  }
}
