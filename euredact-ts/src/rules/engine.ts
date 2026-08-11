import { DetectionSource, EntityType, type CountryConfig, type CountryEvidence, type Detection, type PatternDef } from "../types.js";
import { MultiPatternMatcher, type RawMatch } from "./matchers.js";
import { shouldSuppress, SuppressionScratch } from "./suppressors.js";
import { CUE_TARGETS, CUE_WINDOW, cuedType, retypedBy } from "./cues.js";
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

// ── Local cues: what the document calls the value next to it ────────────
//
// Country evidence resolves which *national scheme* owns an ambiguous value, but
// it never looks at the label sitting immediately in front of it. So
// "Phone: 0705237535" was reported as a Swedish national ID: the digits pass
// that checksum, the document is Swedish, and nothing consulted the word
// "Phone".
//
// A cue touching the span is the strongest statement the document makes about
// what the value *is*, so it outranks the checksum — but only among candidates
// covering the **same span**, so it decides the label and can never change which
// characters are masked. That is what keeps invariant I1 intact.
//
// Measured: 263 phone numbers and 18 French SIREN were reported as national IDs,
// each with an explicit cue in front of it.
//
// The table itself lives in `cues.ts`, because two other steps read it: the
// rescue of a declined identifier below, and the re-typing in deduplicate.
// `CUE_WINDOW` is re-exported from there.

/** 1 when a cue naming `entityType` sits immediately before the span. */
function localCueBonus(text: string, start: number, entityType: EntityType | string): number {
  return cuedType(text, start) === entityType ? 1 : 0;
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
    //
    // One kind of failure is rescued rather than recorded: a span the document
    // itself labels as the very type whose checksum just failed.
    // "Rijksregisternummer: 85.03.19-284.73" is a Belgian national number with a
    // bad check digit — mistyped, OCR'd, or invented — and it is still a
    // national number. Before this, the pattern declined, the generic phone rule
    // was denied the span as a fragment, and the value was left in the clear: a
    // redaction library printing an identifier it had recognised and rejected.
    //
    // Rescued candidates are still recorded as failed spans, so the demotion
    // zones and the fragment rule below are unchanged.
    const validated: Array<{ match: RawMatch; hasValidValidator: boolean }> = [];
    const rescued: RawMatch[] = [];
    const failedSpans: Array<{ start: number; end: number; code: string; etype: string }> = [];
    for (const m of rawMatches) {
      if (this.matcher.validate(m)) {
        validated.push({ match: m, hasValidValidator: m.patternDef.validator !== null });
      } else if (m.patternDef.validator !== null && !m.patternDef.requiresContext) {
        failedSpans.push({ start: m.start, end: m.end, code: m.countryCode,
                           etype: String(m.patternDef.entityType) });
        if (CUE_TARGETS.has(String(m.patternDef.entityType))
            && cuedType(text, m.start) === m.patternDef.entityType) rescued.push(m);
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

    // Any type, strict subset: a candidate covering only *part* of a rejected
    // identifier is a fragment of it, not a different entity. The generic
    // separator-tolerant phone pattern claimed characters 3-14 of the rejected
    // Belgian national number in "Rijksregisternummer: 85.03.19-284.73" and
    // reported it as a PHONE. An equal span is two schemes competing for the
    // whole value; a strict subset is one picking over another's wreckage.
    //
    // Deliberately ignores corroboration and uses every failed span, because it
    // *removes* candidates and must therefore be country-blind — gating it on
    // the document's countries would make the set of spans found depend on
    // `countries`, which is invariant I1.
    //
    // Kept unmerged: merging adjacent spans would invent strict-subset
    // relationships that neither original span had.
    const allFailed = failedSpans
      .map(f => [f.start, f.end] as [number, number])
      .sort((a, b) => a[0] - b[0] || a[1] - b[1]);
    // Running maximum of the end offsets, so the fragment test below can ask
    // "does any span starting at or before me reach past my end?" in O(1)
    // instead of walking the prefix per candidate.
    const failedStarts = allFailed.map(f => f[0]);
    const failedPrefixMax = new Array<number>(allFailed.length + 1).fill(0);
    for (let i = 0; i < allFailed.length; i++) {
      failedPrefixMax[i + 1] = Math.max(failedPrefixMax[i], allFailed[i][1]);
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
      blindPriority: number;
      cue: number;
      priority: number;
      length: number;
      countryScore: number;
      inScope: number;
      det: Detection;
      // Filled in below, once every candidate for the span is known.
      tier: number;
    }
    const candidates: Candidate[] = [];

    // Whole-document facts a suppressor may need, derived at most once per call
    // and discarded with it.
    const scratch = new SuppressionScratch(text);

    for (const { match, hasValidValidator } of validated) {
      if (shouldSuppress(text, match, scratch)) continue;

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

      // Dropped rather than demoted. Demotion cannot help here: nothing else
      // wants a fragment, so a demoted candidate still wins its span by
      // default — the generic phone pattern kept claiming the tail of the
      // rejected national number.
      if (match.patternDef.validator === null && !demoted) {
        // Upper bound of the spans starting at or before match.start.
        let lo = 0, hi = failedStarts.length;
        while (lo < hi) {
          const mid = (lo + hi) >>> 1;
          if (failedStarts[mid] <= match.start) lo = mid + 1; else hi = mid;
        }
        let fragment = false;
        const reach = failedPrefixMax[lo];
        if (reach > match.end) {
          // Something starting no later than us ends strictly later: we are a
          // proper subset of it.
          fragment = true;
        } else if (reach === match.end) {
          // Same end offset — a proper subset only if some span with that end
          // starts strictly earlier. Scanning backwards finds the enclosing
          // span first, and the equal case is rare.
          for (let i = lo - 1; i >= 0; i--) {
            if (allFailed[i][1] === match.end && allFailed[i][0] < match.start) {
              fragment = true;
              break;
            }
          }
        }
        if (fragment) continue;
      }

      let priority: number;
      let blindPriority: number;
      if (demoted) {
        priority = -1;
        blindPriority = -1;
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
        blindPriority = 3;
      } else if (match.countryCode === "CUSTOM") {
        priority = 2;
        blindPriority = 2;
      } else if (match.patternDef.entityType === EntityType.POSTAL_CODE) {
        // A bare digit run is the weakest evidence in the engine and must never
        // re-cut a span a structured detector claims (PHONE, SSN, NATIONAL_ID,
        // BANK_ACCOUNT, VAT...). Postal codes take unclaimed spans only,
        // whatever the span lengths.
        priority = 0;
        blindPriority = 0;
      } else {
        priority = 1;
        blindPriority = 1;
      }

      let entityType: EntityType | string = match.patternDef.entityType;
      let country = (match.countryCode !== "SHARED" && match.countryCode !== "CUSTOM")
        ? match.countryCode : null;
      let outOfScope = declared !== null && country !== null && !declared.has(match.countryCode);
      let confidence = "high";

      // The document labels this span as something else. Relabelling, not
      // suppression: the span is found either way, so removing the claim would
      // decide only whether the value is masked — and the answer was "no".
      // "Rijksregisternummer: 85.03.19-284.73" produced no detection at all.
      //
      // The country came from the pattern that matched, and that pattern was
      // just overruled: a Finnish phone rule saying "Finland" is worthless once
      // the value is filed as a Cypriot identity number. Dropping it also clears
      // outOfScope, which would otherwise claim the detection belongs to a
      // country the caller did not declare while naming no country at all.
      const retyped = retypedBy(text, match.start, entityType);
      if (retyped !== null) {
        entityType = retyped;
        country = null;
        outOfScope = false;
        confidence = "medium";
      }

      candidates.push({
        blindPriority,
        cue: localCueBonus(text, match.start, match.patternDef.entityType),
        priority,
        length: match.end - match.start,
        countryScore: countryScores.get(match.countryCode) ?? 0,
        inScope: declared === null || declared.has(match.countryCode) ? 1 : 0,
        tier: 0,
        det: {
          entityType,
          start: match.start,
          end: match.end,
          text: match.text,
          source: DetectionSource.RULES,
          country,
          confidence,
          outOfScope,
        },
      });
    }

    // A declined identifier the document itself labels. Cue-backed by
    // construction, so `cue` is 1 — that is what lets it take a span from a
    // foreign pattern whose checksum happened to pass, which is how
    // "ΑΦΜ: 147382965" was reported as a Czech national ID.
    //
    // `priority` is 0: below every regex-only claim, so it wins only what
    // nothing better wants. `blindPriority` is 1 so that span selection — the
    // country-blind half of the sort — treats it like any other regex-strength
    // claim and invariant I1 is untouched.
    //
    // Emitted as "low", which is the honest description: the shape and the label
    // agree, the check digit does not. A caller wanting only checksum-backed
    // detections filters on it.
    for (const match of rescued) {
      if (shouldSuppress(text, match, scratch)) continue;
      const country = (match.countryCode !== "SHARED" && match.countryCode !== "CUSTOM")
        ? match.countryCode : null;
      candidates.push({
        blindPriority: 1,
        cue: 1,
        priority: 0,
        length: match.end - match.start,
        countryScore: countryScores.get(match.countryCode) ?? 0,
        inScope: declared === null || declared.has(match.countryCode) ? 1 : 0,
        tier: 0,
        det: {
          entityType: match.patternDef.entityType,
          start: match.start,
          end: match.end,
          text: match.text,
          source: DetectionSource.RULES,
          country,
          confidence: "low",
          outOfScope: declared !== null && country !== null && !declared.has(match.countryCode),
        },
      });
    }

    for (const d of detectStructuralDob(text)) {
      candidates.push({ blindPriority: 1, cue: 0, priority: 1, length: d.end - d.start,
                        countryScore: 0, inScope: 1, tier: 0, det: d });
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
    candidates: Array<{ blindPriority: number; cue: number; priority: number;
                        length: number; countryScore: number; inScope: number;
                        tier: number; det: Detection }>,
  ): Detection[] {
    if (candidates.length === 0) return [];

    // The structural tier is a property of the *span*, not of the candidate:
    // the best tier anything claiming those exact characters can offer. Used
    // per candidate it would also discriminate *within* a span, where the
    // country-aware tier must have the final word — that silently disabled
    // country inference entirely in the Python SDK, handing every ambiguous
    // value to whichever foreign scheme happened to validate.
    const spanTier = new Map<string, number>();
    for (const c of candidates) {
      const key = `${c.det.start}:${c.det.end}`;
      const seen = spanTier.get(key);
      if (seen === undefined || c.blindPriority > seen) spanTier.set(key, c.blindPriority);
    }
    // Resolved once per candidate rather than inside the comparator, which ran
    // it O(n log n) times and rebuilt the key string on every comparison.
    for (const c of candidates) c.tier = spanTier.get(`${c.det.start}:${c.det.end}`)!;
    // Span length outranks *everything*, including validation.
    //
    // A shorter candidate winning re-cuts a longer one and leaves the
    // remainder in the clear, which is a leak. Two measured cases:
    //
    //   "06 12 34 56 78"   the Belgian phone pattern claimed 11 of 14
    //                      characters and exposed three digits
    //   "194.232.104.77"   the Dutch national-ID pattern validates on
    //                      "194.232.104" and outranked the IP address,
    //                      leaving ".77" in the output
    //
    // The second also broke invariant I1 in the Python SDK, where promotion
    // depends on whether the document corroborates the country, so `countries`
    // decided which span won. Ranking length first removes both — a redaction
    // tool masking more than it must is recoverable; masking less is not.
    //
    // Priority still decides between candidates of *equal* length, which is
    // where it matters: a valid IBAN beats a coincidental phone match on the
    // same characters.
    // Ordering between *different* spans is country-blind; the country only
    // ever picks the winner among candidates covering the *same* span. That
    // split makes invariant I1 structural rather than merely tested: the key is
    // country-blind up to and including `start`, and (length, start) already
    // identifies a span uniquely.
    const sorted = [...candidates].sort((a, b) =>
      b.length - a.length ||               // longest first     } country-blind
      b.tier - a.tier ||                   // best tier here    } — decides
      a.det.start - b.det.start ||         // leftmost          } WHICH span
      b.cue - a.cue ||                     // local cue         } country-aware
      b.priority - a.priority ||           // country priority  } — decides the
      b.countryScore - a.countryScore ||   // country evidence  } LABEL only
      b.inScope - a.inScope);              // declared scope    }
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
