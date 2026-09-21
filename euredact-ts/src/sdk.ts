import { randomInt } from "node:crypto";

import { ResultCache } from "./cache.js";
import { normalize, mapOffsetToOriginal } from "./normalizer.js";
import { RuleEngine } from "./rules/engine.js";
import { DocumentContext } from "./rules/context.js";
import { weightsToRanking } from "./rules/evidence.js";
import { EntityType, type Detection, type RedactResult } from "./types.js";

const DATE_TYPES = new Set<EntityType | string>([EntityType.DOB, EntityType.DATE_OF_DEATH]);

/** Returns the label that replaces `det`; `slice` is the exact text it covers. */
type LabelFor = (det: Detection, slice: string) => string;

/**
 * Splice a label over every detection and return the masked text.
 *
 * `detections` must be sorted by `(start, -end)`.
 *
 * Labels are resolved right-to-left because the referential mapper numbers
 * each entity type in call order, and that order is part of the output
 * contract. The string itself is then assembled in a single forward pass:
 * rebuilding it per detection copied the whole document each time, which is
 * O(document x detections) — 1.68 s of pure copying on a 1 MB document with
 * 15,000 detections, versus 2 ms here.
 *
 * Spans from the rule engine are deduplicated and non-overlapping. Spans from
 * elsewhere (the cloud service) are only sorted, so a span may start behind
 * the cursor. Its uncovered tail is still masked rather than dropped: dropping
 * the span would leave those characters in the clear, and splicing it whole
 * would corrupt the label already emitted over its head.
 */
export function applyReplacements(text: string, detections: Detection[], labelFor: LabelFor): string {
  const kept: Array<[Detection, number, number]> = [];
  let pos = 0;
  for (const det of detections) {
    const start = Math.max(det.start, pos);
    if (det.end <= start) continue;
    kept.push([det, start, det.end]);
    pos = det.end;
  }

  const labels: string[] = new Array(kept.length);
  for (let i = kept.length - 1; i >= 0; i--) {
    const [det, start, end] = kept[i];
    labels[i] = labelFor(det, text.slice(start, end));
  }

  const parts: string[] = [];
  pos = 0;
  for (let i = 0; i < kept.length; i++) {
    const [, start, end] = kept[i];
    parts.push(text.slice(pos, start), labels[i]);
    pos = end;
  }
  parts.push(text.slice(pos));
  return parts.join("");
}

/**
 * Characters a token suffix is drawn from. No vowels, so a suffix never spells
 * a word; no 0/1/I/O, so it survives being read back by a person; no
 * underscore, so the type prefix stays unambiguous.
 */
export const TOKEN_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
export const TOKEN_SUFFIX_LENGTH = 4;
const TOKEN_MAX_DRAWS = 100;

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/**
 * Maps each distinct PII value in one call to a reversible token.
 *
 * A token is `TYPE_XXXX`: the entity type, then `TOKEN_SUFFIX_LENGTH` random
 * characters from `TOKEN_ALPHABET`. The same value gets the same token within
 * the call, so relationships survive; across calls it gets a different one, so
 * two tokenized documents never reveal a shared value.
 *
 * Nothing is kept beyond the call. The mapping goes to the caller in
 * `RedactResult.tokens`, and only the caller can turn it back into text with
 * `restore()`.
 *
 * Tokens are also kept clear of any token-shaped string already in the
 * document. A caller that redacts an LLM's reply to a tokenized prompt has
 * exactly such a document, and a fresh token colliding with an old one would
 * make `restore()` put the wrong value back.
 */
export class TokenMapper {
  private byValue = new Map<string, string>();
  private taken = new Set<string>();
  /** Token -> original value, for `RedactResult.tokens`. */
  readonly tokens: Record<string, string> = {};

  constructor(text: string, detections: Detection[]) {
    const types = [...new Set(detections.map(d => String(d.entityType)))].sort();
    if (types.length === 0) return;
    const shaped = new RegExp(
      `(?:${types.map(escapeRegExp).join("|")})_[${TOKEN_ALPHABET}]{${TOKEN_SUFFIX_LENGTH}}`,
      "g",
    );
    for (const m of text.matchAll(shaped)) this.taken.add(m[0]);
  }

  /** Return the token for `value`, minting one on first sight. */
  getToken = (det: Detection, value: string): string => {
    let token = this.byValue.get(value);
    if (token === undefined) {
      const prefix = `${det.entityType}_`;
      let draws = 0;
      do {
        if (draws++ >= TOKEN_MAX_DRAWS) {
          throw new Error(
            `could not mint a unique token with prefix ${JSON.stringify(prefix)} after ${TOKEN_MAX_DRAWS} draws`,
          );
        }
        let suffix = "";
        for (let i = 0; i < TOKEN_SUFFIX_LENGTH; i++) {
          suffix += TOKEN_ALPHABET[randomInt(TOKEN_ALPHABET.length)];
        }
        token = prefix + suffix;
      } while (this.taken.has(token));
      this.taken.add(token);
      this.byValue.set(value, token);
      this.tokens[token] = value;
    }
    return token;
  };
}

/**
 * Put the original values back into `text`.
 *
 * `tokens` is `RedactResult.tokens` from the `redact(text, { tokenize: true })`
 * call that produced the text this one derives from — typically the reply an
 * LLM wrote to the tokenized prompt. Every occurrence of every token is
 * replaced; a token an LLM glued to other characters (`EMAIL_K7Q2s`) is still
 * restored, since leaving a token behind is the worse failure.
 */
export function restore(text: string, tokens: Record<string, string>): string {
  const keys = Object.keys(tokens);
  if (keys.length === 0) return text;
  // Longest first so a token that is a prefix of another (custom pattern names
  // allow it) cannot be matched short. The replacement is a function so `$&`
  // and friends in the original values are literal.
  keys.sort((a, b) => b.length - a.length);
  const pattern = new RegExp(keys.map(escapeRegExp).join("|"), "g");
  return text.replace(pattern, m => tokens[m]);
}

/** Two label schemes for the same spans cannot both apply. */
function checkLabelOptions(options: RedactOptions): void {
  if (options.tokenize && options.referentialIntegrity) {
    throw new Error(
      "tokenize and referentialIntegrity are two label schemes for the same spans; pass one of them",
    );
  }
}

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
  /**
   * Replace each value with a reversible token (`EMAIL_K7Q2`) and return the
   * token -> value mapping in `RedactResult.tokens`; see `restore()`. Tokens
   * are unique to the call. Cannot be combined with `referentialIntegrity`.
   */
  tokenize?: boolean;
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

  /** The label function for one call, given its output options. */
  private labelFor(referentialIntegrity: boolean, tokenMapper: TokenMapper | null): LabelFor {
    if (tokenMapper !== null) return tokenMapper.getToken;
    if (referentialIntegrity) {
      const mapper = this.referentialMapper;
      return (det) => mapper.getLabel(det.text, det.entityType);
    }
    return (det) => `[${det.entityType}]`;
  }

  /**
   * Send a document to the cloud tier.
   *
   * Options the service cannot honour throw rather than being ignored. Silently
   * dropping one would mean returning a result that does not match what was
   * asked for — which, for anything that changes which spans come back, is
   * under-redaction wearing a plausible face.
   */
  private async redactViaCloud(text: string, options: RedactOptions): Promise<RedactResult> {
    const { CloudClient } = await import("./cloud/client.js");
    const countries = options.countries ?? null;

    if (!countries || countries.length !== 1) {
      throw new Error(
        'cloud mode needs exactly one country, e.g. { countries: ["BE"] }. The ' +
        "model is trained and evaluated per country, so a multi-country request " +
        "has no defined behaviour.",
      );
    }
    if (options.countryHint) {
      throw new Error("countryHint is not supported in cloud mode");
    }
    if (options.context || options.chunkOffset) {
      throw new Error(
        "context/chunkOffset are not supported in cloud mode: the model has never " +
        "seen a chunk boundary, so the service rejects oversized input rather " +
        "than splitting it",
      );
    }
    if (options.referentialIntegrity) {
      throw new Error("referentialIntegrity is not supported in cloud mode");
    }

    // detectDates is deliberately NOT forwarded. The service always runs its
    // rules engine with dates on, because that is what the model was trained
    // against; the caller's value cannot change that. It is the one ignored
    // option that is safe to ignore — it can only cause MORE to be detected,
    // never less, so it cannot produce under-redaction.
    const result = await new CloudClient().redact(text, { country: countries[0] });
    if (options.tokenize) {
      await this.remaskCloudResult(result, text, { tokenize: true });
    }
    return result;
  }

  /**
   * Rebuild the masked text from the service's spans, in place.
   *
   * The service masks with bracketed labels only. Any other output option is
   * applied here, from its spans: the service builds its `redacted_text` from
   * exactly the spans it returns (entities it reports but cannot place are
   * listed separately and never applied), so nothing it masked is lost by
   * masking again from the same spans.
   *
   * The service reports offsets in code points and this SDK slices UTF-16
   * units, so the slice check is what stands between an emoji in the document
   * and a rebuilt text with the wrong characters masked.
   */
  private async remaskCloudResult(
    result: RedactResult,
    text: string,
    opts: { tokenize: boolean },
  ): Promise<void> {
    const { CloudError } = await import("./cloud/errors.js");
    for (const det of result.detections) {
      if (text.slice(det.start, det.end) !== det.text) {
        throw new CloudError("span offsets do not match the document; cannot apply tokenize locally");
      }
    }
    const tokenMapper = opts.tokenize ? new TokenMapper(text, result.detections) : null;
    result.redactedText = applyReplacements(text, result.detections, this.labelFor(false, tokenMapper));
    result.tokens = tokenMapper ? tokenMapper.tokens : {};
  }

  redact(text: string, options: RedactOptions = {}): RedactResult {
    checkCountryArg(options.countries, "countries");
    checkCountryArg(options.countryHint, "countryHint");
    checkLabelOptions(options);

    const requestedMode = options.mode ?? "rules";
    if (requestedMode === "cloud") {
      // Cannot be served synchronously: the cloud tier is a network call, and
      // returning rules-only output instead would be the silent under-redaction
      // this guard exists to prevent. Point at the async entry point rather
      // than inventing a Promise-or-value union return type.
      throw new Error(
        'mode: "cloud" is asynchronous — use redactAsync(text, { mode: "cloud" }) ' +
        "(or EuRedact#redactAsync). redact() is synchronous and can only serve " +
        'mode: "rules".',
      );
    }
    if (requestedMode !== "rules") {
      throw new Error(
        `unknown mode ${JSON.stringify(requestedMode)}: expected "rules" or "cloud"`,
      );
    }

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
      tokenize = false,
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
    // referentialIntegrity changes the labels, not the spans, so a cached
    // bracketed result is the wrong answer for a labelled call on the same
    // text — it has to key the cache too.
    const cacheMode = `${mode}|dates=${detectDates}|hint=${hintKey}|ri=${referentialIntegrity}|tok=${tokenize}`;

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

    const tokenMapper = tokenize ? new TokenMapper(text, detections) : null;
    const redacted = applyReplacements(text, detections, this.labelFor(referentialIntegrity, tokenMapper));

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
      tokens: tokenMapper ? tokenMapper.tokens : {},
    };

    if (cache && cacheKey) {
      this.cache.put(cacheKey, result);
    }

    return result;
  }

  /**
   * Redact, awaiting the cloud tier when `mode: "cloud"` is asked for.
   *
   * `mode: "rules"` resolves immediately with exactly what `redact()` returns,
   * so callers that may or may not use the cloud tier can hold one code path.
   */
  async redactAsync(text: string, options: RedactOptions = {}): Promise<RedactResult> {
    const mode = options.mode ?? "rules";
    if (mode !== "cloud") return this.redact(text, options);
    checkLabelOptions(options);
    return this.redactViaCloud(text, options);
  }

  redactBatch(texts: string[], options: RedactOptions = {}): RedactResult[] {
    // Generation is country-blind, so every country's patterns are loaded
    // regardless of what the caller declared.
    this.engine.loadCountries(null);
    return texts.map(text => this.redact(text, options));
  }
}
