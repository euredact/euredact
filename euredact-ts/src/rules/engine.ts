import { DetectionSource, EntityType, type CountryConfig, type CountryEvidence, type Detection, type PatternDef } from "../types.js";
import { MultiPatternMatcher, type RawMatch } from "./matchers.js";
import { shouldSuppress } from "./suppressors.js";
import { detectStructuralDob } from "./structural.js";
import { COUNTRY_CONFIGS } from "./countries/index.js";
import * as evidenceMod from "./evidence.js";

/**
 * Heuristic to detect nested quantifiers that cause catastrophic backtracking.
 * After stripping escaped chars and character classes, look for an unbounded
 * quantifier (+/*) closing a group that is itself quantified (+/*).
 */
const NESTED_QUANTIFIER_RE = /[+*]\)[+*]/;

function validateCustomPattern(pattern: string): void {
  try {
    new RegExp(pattern, "gu");
  } catch (e) {
    throw new Error(`Invalid regex pattern: ${e instanceof Error ? e.message : e}`);
  }
  const stripped = pattern
    .replace(/\\./g, "X")
    .replace(/\[(?:[^\]\\]|\\.)*\]/g, "X");
  if (NESTED_QUANTIFIER_RE.test(stripped)) {
    throw new Error(
      "Pattern contains nested quantifiers (e.g. (a+)+) which can cause " +
      "catastrophic backtracking (ReDoS). Restructure the pattern to " +
      "avoid quantifiers inside quantified groups."
    );
  }
}

/**
 * The country modules use the EU/VAT convention (UK, EL) while the public
 * contract is ISO 3166-1 alpha-2 (GB, GR). Accept both spellings so a caller
 * passing correct ISO codes is not punished for it.
 */
export const COUNTRY_CODE_ALIASES: Record<string, string> = {
  GB: "UK",
  GR: "EL",
  UK: "UK",
  EL: "EL",
};

/** Map a caller-supplied code to a registered one, or null if unknown. */
export function resolveCountryCode(countryCode: string): string | null {
  let code = countryCode.trim().toUpperCase();
  code = COUNTRY_CODE_ALIASES[code] ?? code;
  return code in COUNTRY_CONFIGS && code !== "SHARED" ? code : null;
}

const warnedCountries = new Set<string>();

function warnUnknownCountry(code: string): void {
  if (warnedCountries.has(code)) return;
  warnedCountries.add(code);
  const available = Object.keys(COUNTRY_CONFIGS).filter(c => c !== "SHARED").sort();
  console.warn(
    `[euredact] Unknown country code: ${JSON.stringify(code)}. Continuing with ` +
    `shared country-independent patterns only (email, IBAN, international ` +
    `phone, credit card, ...). Available: ${available.join(", ")}`
  );
}

export class RuleEngine {
  private matcher = new MultiPatternMatcher();
  private loadedCountries = new Set<string>();

  addCustomPattern(name: string, pattern: string): void {
    validateCustomPattern(pattern);
    const pdef: PatternDef = {
      entityType: name, pattern, validator: null,
      description: "", contextKeywords: [], requiresContext: false,
    };
    this.matcher.addPattern(pdef, "CUSTOM");
    this.matcher.compile();
  }

  loadCountries(countryCodes: string[] | null): void {
    let configs: CountryConfig[];
    if (countryCodes === null) {
      configs = Object.values(COUNTRY_CONFIGS);
    } else {
      configs = [];
      for (const c of countryCodes) {
        const code = resolveCountryCode(c);
        if (code === null) {
          // Detection continues with the shared, country-independent
          // patterns. Throwing on an unknown locale invites callers to wrap
          // the call in try/catch and skip redaction — failing open, with
          // unredacted PII in the output.
          warnUnknownCountry(c);
          continue;
        }
        const config = COUNTRY_CONFIGS[code];
        if (config) configs.push(config);
      }
      const shared = COUNTRY_CONFIGS["SHARED"];
      if (shared) configs.push(shared);
    }

    let newCountries = false;
    for (const config of configs) {
      if (!this.loadedCountries.has(config.code)) {
        this.matcher.addCountry(config);
        this.loadedCountries.add(config.code);
        newCountries = true;
      }
    }
    if (newCountries) this.matcher.compile();
  }

  /**
   * Generate candidate matches. Country-blind, by contract.
   *
   * This is the only caller of {@link MultiPatternMatcher.scan}, and it takes
   * no country argument. Which country the caller declared may influence how a
   * match is *scored*; it may never influence whether the match is *found*.
   * Before this held, `countries: ["BE"]` made a valid Dutch BSN vanish
   * entirely because the Dutch patterns were never run.
   */
  generateCandidates(text: string): RawMatch[] {
    this.loadCountries(null);
    return this.matcher.scan(text, null);
  }

  detect(text: string, countryCodes: string[] | null, countryHint?: string[] | null): Detection[] {
    return this.detectWithEvidence(text, countryCodes, countryHint).detections;
  }

  /**
   * {@link RuleEngine.detect}, plus the country evidence it reasoned from.
   *
   * `countryCodes` is **scope**: it flags detections from elsewhere as
   * `outOfScope` and, like `countryHint`, contributes a prior. `countryHint` is
   * **only** a prior — it helps resolve ambiguity without marking anything out
   * of scope. Neither gates what is looked for.
   */
  detectWithEvidence(
    text: string,
    countryCodes: string[] | null,
    countryHint?: string[] | null,
    priorEvidence?: CountryEvidence[] | null,
  ): { detections: Detection[]; evidence: CountryEvidence[]; scores: Map<string, number> } {
    const rawMatches = this.generateCandidates(text);

    // The declared countries are a scoring signal from here on: they rank
    // candidates and flag out-of-scope detections. They do not gate.
    let declared: Set<string> | null = null;
    if (countryCodes !== null) {
      declared = new Set<string>();
      for (const c of countryCodes) {
        const code = resolveCountryCode(c);
        if (code === null) warnUnknownCountry(c);
        else declared.add(code);
      }
      declared.add("SHARED");
      declared.add("CUSTOM");
    }

    // The prior fed to the evidence bus. Declared countries count too — a
    // caller naming a country is asserting context, which is exactly what a
    // prior is — but a hint never narrows scope, so it is kept out of
    // `declared` and cannot flag anything out of scope.
    const prior = new Set<string>(declared ?? []);
    for (const c of countryHint ?? []) {
      const code = resolveCountryCode(c);
      if (code === null) warnUnknownCountry(c);
      else prior.add(code);
    }

    // Pass 1: checksum validation. A span that matched a checksummed pattern
    // but failed the checksum is recorded with its country and entity type;
    // what it is allowed to demote is decided below, once the document's
    // countries are known.
    const validated: Array<{ match: RawMatch; hasValidValidator: boolean }> = [];
    const failedSpans: Array<{ start: number; end: number; code: string; etype: string }> = [];
    for (const m of rawMatches) {
      if (this.matcher.validate(m)) {
        validated.push({ match: m, hasValidValidator: m.patternDef.validator !== null });
      } else if (m.patternDef.validator !== null && !m.patternDef.requiresContext) {
        failedSpans.push({ start: m.start, end: m.end, code: m.countryCode,
                           etype: String(m.patternDef.entityType) });
      }
    }

    // Evidence pass: work out which countries this document belongs to, from
    // the entities that carry their country in the string.
    //
    // Every surviving candidate is eligible, not only checksum-backed ones. An
    // earlier version required a validator here, which silently dropped the
    // email ccTLD — the second-strongest signal at 4.50 log-odds and present in
    // 98,949 of 152,300 corpus documents — because EMAIL has nothing to
    // checksum. Candidates that failed a validator never reach `validated`, so
    // this admits the unvalidatable, not the invalid.
    const evidenceDets: Detection[] = [];
    for (const { match } of validated) {
      if (!evidenceMod.EVIDENCE_TYPES.has(String(match.patternDef.entityType))) continue;
      evidenceDets.push({
        entityType: match.patternDef.entityType,
        start: match.start, end: match.end, text: match.text,
        source: DetectionSource.RULES,
        country: (match.countryCode !== "SHARED" && match.countryCode !== "CUSTOM")
          ? match.countryCode : null,
        confidence: "high",
      });
    }
    const countryEvidence = evidenceMod.collect(evidenceDets);
    const countryScores = evidenceMod.accumulate(
      priorEvidence && priorEvidence.length ? [...countryEvidence, ...priorEvidence] : countryEvidence,
      prior,
    );
    const hasScores = countryScores.size > 0;
    const corroborated = (code: string): boolean =>
      !hasScores || code === "SHARED" || code === "CUSTOM" || countryScores.has(code);

    // Now that the document's countries are known, decide which failed
    // validators are entitled to demote anything. A checksum failure only means
    // "not a valid X"; it says nothing about the span unless X was plausible
    // here in the first place. A Belgian national-ID pattern failing on
    // 0612345678 is not evidence against that span being a Dutch phone number.
    //
    // Zones are also per entity type. A failed checksum is evidence against
    // *that type*, not against the span: Sweden's own personnummer checksum
    // failing on 0708787668 used to demote the Swedish *phone* candidate for
    // the same digits, handing the span to a Danish CPR that happened to
    // validate. Worth 878 mistyped phone numbers per 30,000 documents.
    const zonesByType = new Map<string, Array<[number, number]>>();
    for (const f of failedSpans) {
      if (!corroborated(f.code)) continue;
      const list = zonesByType.get(f.etype);
      if (list) list.push([f.start, f.end]);
      else zonesByType.set(f.etype, [[f.start, f.end]]);
    }
    const mergedZones = new Map<string, { starts: number[]; ends: number[] }>();
    for (const [etype, spans] of zonesByType) {
      spans.sort((a, b) => a[0] - b[0] || a[1] - b[1]);
      const starts: number[] = [];
      const ends: number[] = [];
      let [ms, me] = spans[0];
      for (let i = 1; i < spans.length; i++) {
        const [zs, ze] = spans[i];
        if (zs <= me) me = Math.max(me, ze);
        else { starts.push(ms); ends.push(me); ms = zs; me = ze; }
      }
      starts.push(ms); ends.push(me);
      mergedZones.set(etype, { starts, ends });
    }

    interface Candidate {
      priority: number;
      length: number;
      countryScore: number;
      inScope: number;
      det: Detection;
    }
    const candidates: Candidate[] = [];

    for (const { match, hasValidValidator } of validated) {
      if (shouldSuppress(text, match)) continue;

      // A validator-less match inside a failed-validation span of its own type
      // is demoted below every other candidate rather than deleted. Demotion
      // cannot silence a detection, which is the property deletion lacked:
      // measured across the corpus, deletion removed 454 detections of which
      // 454 overlapped real labelled PII.
      let demoted = false;
      if (match.patternDef.validator === null) {
        const zone = mergedZones.get(String(match.patternDef.entityType));
        if (zone) {
          let lo = 0, hi = zone.starts.length;
          while (lo < hi) {
            const mid = (lo + hi) >>> 1;
            if (zone.starts[mid] <= match.start) lo = mid + 1; else hi = mid;
          }
          const idx = lo - 1;
          demoted = idx >= 0 && zone.ends[idx] >= match.end;
        }
      }

      let priority: number;
      if (demoted) {
        priority = -1;
      } else if (hasValidValidator) {
        // A passing checksum normally outranks everything. But a checksum only
        // says the digits fit *some* national scheme, and weak ones fit by luck
        // — a mod-11 scheme accepts a random number about one time in eleven.
        // So a validated candidate from a country the document shows no trace
        // of is treated as coincidence, not evidence.
        //
        // Concretely: the Dutch phone number 0612345678 also passes the Danish
        // CPR checksum. Entities that carry their own country vouch for
        // themselves — an IBAN emits evidence for its own country — so a
        // foreign IBAN in a domestic invoice keeps its rank.
        priority = corroborated(match.countryCode) ? 3 : 1;
      } else if (match.countryCode === "CUSTOM") {
        priority = 2;
      } else if (match.patternDef.entityType === EntityType.POSTAL_CODE) {
        // A bare digit run is the weakest evidence in the engine and must never
        // re-cut a span a structured detector claims (PHONE, SSN, NATIONAL_ID,
        // BANK_ACCOUNT, VAT...). Postal codes take unclaimed spans only,
        // whatever the span lengths.
        priority = 0;
      } else {
        priority = 1;
      }

      const country = (match.countryCode !== "SHARED" && match.countryCode !== "CUSTOM")
        ? match.countryCode : null;
      candidates.push({
        priority,
        length: match.end - match.start,
        countryScore: countryScores.get(match.countryCode) ?? 0,
        inScope: declared === null || declared.has(match.countryCode) ? 1 : 0,
        det: {
          entityType: match.patternDef.entityType,
          start: match.start,
          end: match.end,
          text: match.text,
          source: DetectionSource.RULES,
          country,
          confidence: "high",
          outOfScope: declared !== null && country !== null && !declared.has(match.countryCode),
        },
      });
    }

    for (const d of detectStructuralDob(text)) {
      candidates.push({ priority: 1, length: d.end - d.start, countryScore: 0, inScope: 1, det: d });
    }

    const detections = this.deduplicate(candidates);
    detections.sort((a, b) => a.start - b.start || b.end - a.end);

    // Attach the confidence behind each country attribution, so a caller can
    // tell "Danish, and the document is plainly Danish" from "Danish, on a
    // checksum alone".
    const ranking = evidenceMod.weightsToRanking(countryScores);
    for (const d of detections) {
      d.countryConfidence = (d.country !== null ? ranking.get(d.country) : undefined) ?? 0;
    }

    return { detections, evidence: countryEvidence, scores: countryScores };
  }

  /**
   * Remove overlapping detections with priority-aware resolution.
   * Priority: validated (3) > custom (2) > regex-only (1) > postal (0) >
   * demoted (-1). Within a tier, longer span wins, then country evidence.
   */
  private deduplicate(
    candidates: Array<{ priority: number; length: number; countryScore: number; inScope: number; det: Detection }>,
  ): Detection[] {
    if (candidates.length === 0) return [];
    // Span length outranks scope: preferring the declared country over the
    // longest match can truncate an entity. Measured: with countries ["BE"],
    // the Belgian phone pattern claims 11 of the 14 characters of
    // "06 12 34 56 78" and leaves three digits exposed. Scope only breaks ties
    // between candidates of equal length, so it can change WHICH country is
    // attributed, never WHAT is masked.
    const sorted = [...candidates].sort((a, b) =>
      b.priority - a.priority ||
      b.length - a.length ||
      b.countryScore - a.countryScore ||
      b.inScope - a.inScope);
    const result: Detection[] = [];
    const occupied = new Set<number>();
    for (const { det } of sorted) {
      let overlaps = false;
      for (let p = det.start; p < det.end; p++) {
        if (occupied.has(p)) { overlaps = true; break; }
      }
      if (!overlaps) {
        for (let p = det.start; p < det.end; p++) occupied.add(p);
        result.push(det);
      }
    }
    return result;
  }

  getLoadedCountries(): Set<string> {
    return new Set(this.loadedCountries);
  }
}
