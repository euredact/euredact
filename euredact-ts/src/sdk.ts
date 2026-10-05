import { randomIndex } from "./platform.js";

import { ResultCache } from "./cache.js";
import { normalize, mapOffsetToOriginal } from "./normalizer.js";
import { RuleEngine } from "./rules/engine.js";
import { DocumentContext } from "./rules/context.js";
import { weightsToRanking } from "./rules/evidence.js";
import { EntityType, type Detection, type Exemption, type RedactResult } from "./types.js";

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
 * One label in the text sent to the cloud tier: where it sits in the masked
 * text, and the extent of the original it replaced —
 * `[maskedStart, maskedEnd, start, end]`.
 */
type WireLabel = [number, number, number, number];

/**
 * Bracket-mask `text` and record where each label landed.
 *
 * Returns what is sent to the cloud tier, plus one `WireLabel` per label.
 * Everything between labels is copied unchanged, so the labels are all it
 * takes to carry an offset from the masked text back to the original.
 *
 * Always `[TYPE]`, whatever label scheme the caller asked for. That is the
 * syntax the model was trained on, where a placeholder means "already handled,
 * do not list it". A token or a numbered label would be read as ordinary text,
 * so the format on the wire is a model contract and not an output option.
 */
function maskForCloud(text: string, detections: Detection[]): [string, WireLabel[]] {
  const parts: string[] = [];
  const labels: WireLabel[] = [];
  let pos = 0;
  let out = 0;
  for (const det of detections) {
    const start = Math.max(det.start, pos);
    if (det.end <= start) continue;
    const label = `[${det.entityType}]`;
    out += start - pos;
    parts.push(text.slice(pos, start), label);
    labels.push([out, out + label.length, start, det.end]);
    out += label.length;
    pos = det.end;
  }
  parts.push(text.slice(pos));
  return [parts.join(""), labels];
}

/** Index of the last label starting at or before `offset` — strictly before
 *  when `strict` — or -1. */
function labelBefore(labels: WireLabel[], offset: number, strict: boolean): number {
  let lo = 0;
  let hi = labels.length;
  while (lo < hi) {
    const mid = (lo + hi) >>> 1;
    if (strict ? labels[mid][0] < offset : labels[mid][0] <= offset) lo = mid + 1;
    else hi = mid;
  }
  return lo - 1;
}

/**
 * Carry the service's spans from the masked text onto the original.
 *
 * The service only ever saw `masked`, so its offsets index that. An offset in
 * copied text shifts by whatever the labels before it added or removed. An
 * offset inside a label has no counterpart in the original, so it snaps
 * outward to the edge of the value the label replaced: an address the model
 * reports around `[POSTAL_CODE]` covers the postal code, never half of it.
 * Over-masking is the safe direction.
 *
 * A span lying wholly inside one label describes the label, not the document.
 * It is dropped; the local detection behind the label stands.
 *
 * Throws `Unplaceable` when a span does not match the text that was sent. Such
 * a span cannot be placed, and masking where it points would cover the wrong
 * characters and leave the right ones in the clear.
 */
function ontoOriginal(
  spans: Detection[],
  masked: string,
  text: string,
  labels: WireLabel[],
  Unplaceable: new (message: string) => Error,
): Detection[] {
  const placed: Detection[] = [];
  for (const span of spans) {
    if (
      !(0 <= span.start && span.start <= span.end && span.end <= masked.length) ||
      masked.slice(span.start, span.end) !== span.text
    ) {
      throw new Unplaceable(
        "span offsets do not match the text that was sent; cannot place the " +
        "service's detections in the document",
      );
    }
    if (span.start === span.end) continue;

    let start = span.start;
    let at = labelBefore(labels, span.start, false);
    if (at >= 0) {
      const [, maskedEnd, origStart, origEnd] = labels[at];
      if (span.end <= maskedEnd) continue;
      start = span.start < maskedEnd ? origStart : origEnd + span.start - maskedEnd;
    }

    let end = span.end;
    at = labelBefore(labels, span.end, true);
    if (at >= 0) {
      const [, maskedEnd, , origEnd] = labels[at];
      end = origEnd + Math.max(0, span.end - maskedEnd);
    }

    placed.push({ ...span, start, end, text: text.slice(start, end) });
  }
  return placed;
}

/**
 * Characters a token suffix is drawn from. No vowels (and no Y), so a suffix
 * never spells a word; no 0/1/I/O, so it survives being read back by a person;
 * no underscore, so the type prefix stays unambiguous. A, E, U and Y were in it
 * until rules-engine#55, against this comment.
 */
export const TOKEN_ALPHABET = "BCDFGHJKLMNPQRSTVWXZ23456789";
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
          suffix += TOKEN_ALPHABET[randomIndex(TOKEN_ALPHABET.length)];
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

/**
 * Types whose separators are presentational: the same identifier stays the
 * same value however it is spaced, hyphenated or dotted, so an allowlisted
 * IBAN is exempted whether the document writes NL91ABNA0417164300 or
 * NL91 ABNA 0417 1643 00 (issue rules-engine#15).
 *
 * Free-text types are deliberately absent: folding separators in an address
 * would make `jan.devries@acme.be` exempt `jandevries@acme.be`, a different
 * mailbox at most providers.
 */
const SEPARATOR_INSENSITIVE = new Set<EntityType | string>([
  EntityType.BANK_ACCOUNT, EntityType.BIC, EntityType.CREDIT_CARD,
  EntityType.PHONE, EntityType.VAT, EntityType.NATIONAL_ID, EntityType.SSN,
  EntityType.TAX_ID, EntityType.PASSPORT, EntityType.DRIVERS_LICENSE,
  EntityType.RESIDENCE_PERMIT, EntityType.HEALTH_INSURANCE,
  EntityType.CHAMBER_OF_COMMERCE, EntityType.IMEI, EntityType.VIN,
]);

/** Types carrying a domain an owner may want exempted wholesale. */
const DOMAIN_BEARING = new Set<EntityType | string>([EntityType.EMAIL, EntityType.URL]);

const SEPARATORS = /[\s.\-/()]+/g;

/**
 * Reject a bare string where a list of allowlisted values is expected.
 *
 * A string is iterable, so `allowlist: "ACME NV"` would become the
 * one-character entries "A", "C", ... — none of which is a whole detection, so
 * nothing is exempted and the caller's own name is redacted after all.
 */
function checkAllowlistArg(value: unknown, param = "allowlist"): void {
  if (typeof value === "string") {
    throw new TypeError(
      `${param} must be an array of values, not a bare string. ` +
      `Pass ${param}: ["${value}"] rather than ${param}: "${value}".`,
    );
  }
}

/**
 * The form an allowlist entry and a detected value are compared in. NFC
 * because the rule engine matches on NFC-normalised text while the document
 * may be NFD; lower-cased because an org name in a heading is the same org.
 */
function allowlistKey(value: string): string {
  return value.normalize("NFC").trim().toLowerCase();
}

/** `allowlistKey` with presentational separators removed. */
function foldedKey(value: string): string {
  return allowlistKey(value).replace(SEPARATORS, "");
}

/** Comparison key -> the entry as the caller wrote it (for reporting). */
function normalizeAllowlist(values: string[] | null | undefined): Map<string, string> {
  checkAllowlistArg(values);
  const out = new Map<string, string>();
  for (const v of values ?? []) {
    if (!v || !v.trim()) continue;
    if (!out.has(allowlistKey(v))) out.set(allowlistKey(v), v);
    if (!out.has(foldedKey(v))) out.set(foldedKey(v), v);
  }
  return out;
}

/** Domain key -> the entry as written. A leading `@` or `.` is ignored. */
function normalizeDomains(values: string[] | null | undefined): Map<string, string> {
  checkAllowlistArg(values, "allowlistDomains");
  const out = new Map<string, string>();
  for (const v of values ?? []) {
    if (!v || !v.trim()) continue;
    const k = allowlistKey(v).replace(/^[@.]+/, "");
    if (k && !out.has(k)) out.set(k, v);
  }
  return out;
}

/** The domain an exemption rule would apply to, or null. */
function domainOf(entityType: EntityType | string, value: string): string | null {
  if (!DOMAIN_BEARING.has(entityType)) return null;
  let v = allowlistKey(value);
  if (v.includes("@")) return v.slice(v.lastIndexOf("@") + 1).replace(/^[<[(]+|[>\])(),;:"']+$/g, "") || null;
  v = v.replace(/^[a-z][a-z0-9+.-]*:\/\//, "");
  return v.split("/")[0].split(":")[0].replace(/^[<[(]+|[>\])(),;:"']+$/g, "") || null;
}

/** The [rule, kind] exempting this detection, or null. */
function matchingRule(
  det: Detection,
  slice: string,
  allowed: Map<string, string>,
  domains: Map<string, string>,
): [string, "value" | "domain"] | null {
  for (const candidate of [slice, det.text]) {
    if (!candidate) continue;
    const exact = allowed.get(allowlistKey(candidate));
    if (exact !== undefined) return [exact, "value"];
    if (SEPARATOR_INSENSITIVE.has(det.entityType)) {
      const folded = allowed.get(foldedKey(candidate));
      if (folded !== undefined) return [folded, "value"];
    }
    const host = domainOf(det.entityType, candidate);
    if (host) {
      for (const [owned, entry] of domains) {
        if (host === owned || host.endsWith("." + owned)) return [entry, "domain"];
      }
    }
  }
  return null;
}

/**
 * Split detections into those to redact and those the caller exempted.
 *
 * Whole span only: `euredact.be` as a *value* does not exempt
 * `joren@euredact.be`; that is what `allowlistDomains` is for.
 */
function applyAllowlist(
  text: string,
  detections: Detection[],
  allowed: Map<string, string>,
  domains: Map<string, string>,
): [Detection[], Exemption[]] {
  if (allowed.size === 0 && domains.size === 0) return [detections, []];
  const kept: Detection[] = [];
  const exempted: Exemption[] = [];
  for (const d of detections) {
    const hit = matchingRule(d, text.slice(d.start, d.end), allowed, domains);
    if (hit === null) kept.push(d);
    else exempted.push({
      entityType: d.entityType, start: d.start, end: d.end,
      text: text.slice(d.start, d.end), rule: hit[0], ruleKind: hit[1],
    });
  }
  return [kept, exempted];
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
  /**
   * Values never to redact, matched whole and case-insensitively against each
   * detection. Merged with the instance's allowlist.
   */
  allowlist?: string[] | null;
  /**
   * Domains whose addresses are never redacted, e.g. `["acme.be"]`. Applies to
   * EMAIL and URL only, and covers subdomains. Merged with the instance list.
   */
  allowlistDomains?: string[] | null;
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
  private allowlist: Map<string, string>;
  private allowlistDomains: Map<string, string>;

  /**
   * @param options.maxInputLength Longest document `redact` accepts, in characters.
   * @param options.allowlist Values never to redact, for every call on this
   *   instance — an organisation's own name, its own addresses. Merged with
   *   the per-call `allowlist`. Matched whole, case-insensitively.
   */
  constructor(options?: {
    maxInputLength?: number;
    allowlist?: string[] | null;
    allowlistDomains?: string[] | null;
  }) {
    this.maxInputLength = options?.maxInputLength ?? DEFAULT_MAX_INPUT_LENGTH;
    this.allowlist = normalizeAllowlist(options?.allowlist);
    this.allowlistDomains = normalizeDomains(options?.allowlistDomains);
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

  /** The instance allowlist merged with a call's, in comparison form. */
  private allowedFor(options: RedactOptions): Map<string, string> {
    const allowed = new Map(this.allowlist);
    for (const [k, v] of normalizeAllowlist(options.allowlist)) allowed.set(k, v);
    return allowed;
  }

  /** The instance domain list merged with a call's. */
  private domainsFor(options: RedactOptions): Map<string, string> {
    const domains = new Map(this.allowlistDomains);
    for (const [k, v] of normalizeDomains(options.allowlistDomains)) domains.set(k, v);
    return domains;
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
   * Run the rules here, then send what they left to the cloud tier.
   *
   * Local-first: the rules engine masks everything it can find on the caller's
   * machine, and only that masked text is sent. The service looks for what has
   * no shape to match on — names, employers, diagnoses — and answers with
   * spans relative to the text it received, which are mapped back onto the
   * original here.
   *
   * This is minimisation, not an exemption: what the rules miss, and the names
   * and diagnoses the model is there to find, still travel.
   *
   * Options the service cannot honour throw rather than being ignored. Silently
   * dropping one would mean returning a result that does not match what was
   * asked for — which, for anything that changes which spans come back, is
   * under-redaction wearing a plausible face.
   */
  private async redactViaCloud(text: string, options: RedactOptions): Promise<RedactResult> {
    const { CloudClient } = await import("./cloud/client.js");
    const { CloudError } = await import("./cloud/errors.js");
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

    const allowed = this.allowedFor(options);
    const domains = this.domainsFor(options);
    const client = new CloudClient();

    // Dates are always on, whatever detectDates says: that is the rules output
    // the model was trained against, and a date of birth the rules can place
    // has no reason to travel. It is the one ignored option that is safe to
    // ignore — it can only cause MORE to be detected, never less.
    //
    // No allowlist and no tokens on this pass. An exemption says what the
    // caller wants back, not what may leave; both are applied below, after the
    // response, to the merged spans.
    const local = this.redactRules(
      text, { countries, detectDates: true, cache: options.cache }, new Map(), new Map(),
    );
    const [masked, labels] = maskForCloud(text, local.detections);
    // The client converts the service's code-point offsets to UTF-16 units of
    // the text it sent, so everything from here on is in one unit.
    const remote = await client.redact(masked, { country: countries[0] });

    // A new array throughout: `local` may be the cached rules result.
    const [detections, exempted] = applyAllowlist(
      text,
      [...local.detections, ...ontoOriginal(remote.detections, masked, text, labels, CloudError)],
      allowed, domains,
    );
    detections.sort((a, b) => a.start - b.start || b.end - a.end);
    const tokenMapper = options.tokenize ? new TokenMapper(text, detections) : null;
    return {
      ...local,
      redactedText: applyReplacements(text, detections, this.labelFor(false, tokenMapper)),
      detections,
      source: "cloud",
      tokens: tokenMapper ? tokenMapper.tokens : {},
      exempted,
    };
  }

  redact(text: string, options: RedactOptions = {}): RedactResult {
    checkCountryArg(options.countries, "countries");
    checkCountryArg(options.countryHint, "countryHint");
    checkLabelOptions(options);
    const allowed = this.allowedFor(options);
    const domains = this.domainsFor(options);

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

    return this.redactRules(text, options, allowed, domains);
  }

  /** The local pipeline: normalise, detect, exempt, mask. */
  private redactRules(
    text: string,
    options: RedactOptions,
    allowed: Map<string, string>,
    domains: Map<string, string>,
  ): RedactResult {
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
    // JSON rather than a joined string: an entry may itself contain the
    // separator, and two different lists must never share a key.
    const allowKey = (allowed.size ? JSON.stringify([...allowed.keys()].sort()) : "")
      + (domains.size ? "|dom=" + JSON.stringify([...domains.keys()].sort()) : "");
    const cacheMode = `rules|dates=${detectDates}|hint=${hintKey}|ri=${referentialIntegrity}|tok=${tokenize}|allow=${allowKey}`;

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
    let exempted: Exemption[];
    [detections, exempted] = applyAllowlist(text, detections, allowed, domains);

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
      exempted,
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
