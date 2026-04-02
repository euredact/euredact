import { DetectionSource, type CountryConfig, type Detection, type PatternDef } from "../types.js";
import { MultiPatternMatcher } from "./matchers.js";
import { shouldSuppress } from "./suppressors.js";
import { detectStructuralDob } from "./structural.js";
import { COUNTRY_CONFIGS } from "./countries/index.js";

export class RuleEngine {
  private matcher = new MultiPatternMatcher();
  private loadedCountries = new Set<string>();

  addCustomPattern(name: string, pattern: string): void {
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
        const code = c.toUpperCase();
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

    let rawMatches = this.matcher.scan(text);

    if (countryCodes !== null) {
      const codesUpper = new Set(countryCodes.map(c => c.toUpperCase()));
      rawMatches = rawMatches.filter(
        m => codesUpper.has(m.countryCode) || m.countryCode === "SHARED" || m.countryCode === "CUSTOM",
      );
    }

    // Matches that have a validator but fail it create suppression zones:
    // the span is recognisably a specific entity (e.g. IBAN-shaped) so
    // overlapping regex-only matches (license plate, phone) are false
    // positives and must be suppressed.
    const validated: typeof rawMatches = [];
    const suppressionZones: Array<[number, number]> = [];
    for (const m of rawMatches) {
      if (this.matcher.validate(m)) {
        validated.push(m);
      } else if (m.patternDef.validator !== null && !m.patternDef.requiresContext) {
        suppressionZones.push([m.start, m.end]);
      }
    }

    // Build candidates with priority: validated (3) > custom (2) > regex-only (1)
    const candidates: Array<{ det: Detection; score: number }> = [];
    for (const match of validated) {
      if (shouldSuppress(text, match)) continue;
      if (match.patternDef.validator === null && suppressionZones.length > 0) {
        if (suppressionZones.some(([zStart, zEnd]) => match.start >= zStart && match.end <= zEnd)) {
          continue;
        }
      }

      const hasValidator = match.patternDef.validator !== null;
      const isValid = this.matcher.validate(match);
      const priority = (hasValidator && isValid) ? 3 : match.countryCode === "CUSTOM" ? 2 : 1;
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
    for (const { det } of sorted) {
      let overlaps = false;
      for (const kept of result) {
        if (det.start < kept.end && det.end > kept.start) { overlaps = true; break; }
      }
      if (!overlaps) result.push(det);
    }
    return result;
  }

  getLoadedCountries(): Set<string> {
    return new Set(this.loadedCountries);
  }
}
