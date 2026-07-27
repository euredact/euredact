import { DetectionSource, EntityType, type CountryConfig, type Detection, type PatternDef } from "../types.js";
import { MultiPatternMatcher } from "./matchers.js";
import { shouldSuppress } from "./suppressors.js";
import { detectStructuralDob } from "./structural.js";
import { COUNTRY_CONFIGS } from "./countries/index.js";

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

  detect(text: string, countryCodes: string[] | null): Detection[] {
    this.loadCountries(countryCodes);

    // Scope the scan to requested countries for efficiency
    // Resolve through the alias table so `countries: ["GB"]` actually scans
    // the patterns registered under "UK".
    let scanCodes: Set<string> | null = null;
    if (countryCodes !== null) {
      scanCodes = new Set<string>();
      for (const c of countryCodes) {
        const code = resolveCountryCode(c);
        if (code !== null) scanCodes.add(code);
      }
      scanCodes.add("SHARED");
      scanCodes.add("CUSTOM");
    }
    let rawMatches = this.matcher.scan(text, scanCodes);

    // Matches that have a validator but fail it create suppression zones:
    // the span is recognisably a specific entity (e.g. IBAN-shaped) so
    // overlapping regex-only matches (license plate, phone) are false
    // positives and must be suppressed.
    const validated: Array<{ match: typeof rawMatches[0]; hasValidValidator: boolean }> = [];
    const rawZones: Array<[number, number]> = [];
    for (const m of rawMatches) {
      const isValid = this.matcher.validate(m);
      if (isValid) {
        validated.push({ match: m, hasValidValidator: m.patternDef.validator !== null });
      } else if (m.patternDef.validator !== null && !m.patternDef.requiresContext) {
        rawZones.push([m.start, m.end]);
      }
    }

    // Merge overlapping suppression zones for O(log n) containment checks
    let zoneStarts: number[] = [];
    let zoneEnds: number[] = [];
    if (rawZones.length > 0) {
      rawZones.sort((a, b) => a[0] - b[0] || a[1] - b[1]);
      let [ms, me] = rawZones[0];
      for (let i = 1; i < rawZones.length; i++) {
        const [zs, ze] = rawZones[i];
        if (zs <= me) { me = Math.max(me, ze); }
        else { zoneStarts.push(ms); zoneEnds.push(me); ms = zs; me = ze; }
      }
      zoneStarts.push(ms);
      zoneEnds.push(me);
    }

    // Build candidates with priority: validated (3) > custom (2) > regex-only (1)
    const candidates: Array<{ det: Detection; score: number }> = [];
    for (const { match, hasValidValidator } of validated) {
      if (shouldSuppress(text, match)) continue;
      // O(log n) binary-search containment check on merged zones
      if (match.patternDef.validator === null && zoneStarts.length > 0) {
        let lo = 0, hi = zoneStarts.length;
        while (lo < hi) { const mid = (lo + hi) >>> 1; if (zoneStarts[mid] <= match.start) lo = mid + 1; else hi = mid; }
        const idx = lo - 1;
        if (idx >= 0 && zoneEnds[idx] >= match.end) continue;
      }

      // A bare digit run is the weakest evidence in the engine and must never
      // re-cut a span a structured detector claims (PHONE, SSN, NATIONAL_ID,
      // BANK_ACCOUNT, VAT...). Postal codes take unclaimed spans only,
      // whatever the span lengths.
      const priority = hasValidValidator
        ? 3
        : match.countryCode === "CUSTOM"
          ? 2
          : match.patternDef.entityType === EntityType.POSTAL_CODE
            ? 0
            : 1;
      const spanLength = match.end - match.start;
      const score = priority * 1_000_000 + spanLength;

      candidates.push({
        det: {
          entityType: match.patternDef.entityType,
          start: match.start,
          end: match.end,
          text: match.text,
          source: DetectionSource.RULES,
          country: (match.countryCode !== "SHARED" && match.countryCode !== "CUSTOM") ? match.countryCode : null,
          confidence: "high",
        },
        score,
      });
    }

    for (const d of detectStructuralDob(text)) {
      candidates.push({ det: d, score: 1_000_000 + (d.end - d.start) });
    }

    return this.deduplicate(candidates);
  }

  /**
   * Remove overlapping detections with priority-aware resolution.
   * Priority: validated (3) > custom (2) > regex-only (1).
   * Within the same tier, longer span wins.
   */
  private deduplicate(candidates: Array<{ det: Detection; score: number }>): Detection[] {
    if (candidates.length === 0) return [];
    const sorted = [...candidates].sort((a, b) => b.score - a.score);
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
