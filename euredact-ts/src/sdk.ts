import { ResultCache } from "./cache.js";
import { normalize, mapOffsetToOriginal } from "./normalizer.js";
import { RuleEngine } from "./rules/engine.js";
import { EntityType, type Detection, type RedactResult } from "./types.js";

const DATE_TYPES = new Set([EntityType.DOB, EntityType.DATE_OF_DEATH]);

class PseudonymMapper {
  private counters = new Map<EntityType, number>();
  private mapping = new Map<string, string>();

  getPseudonym(text: string, entityType: EntityType): string {
    if (!this.mapping.has(text)) {
      const count = (this.counters.get(entityType) ?? 0) + 1;
      this.counters.set(entityType, count);
      this.mapping.set(text, `${entityType}_${count}`);
    }
    return this.mapping.get(text)!;
  }
}

export interface RedactOptions {
  countries?: string[] | null;
  mode?: string;
  pseudonymize?: boolean;
  detectDates?: boolean;
  cache?: boolean;
}

export class EuRedact {
  private engine = new RuleEngine();
  private cache = new ResultCache();
  private pseudonymMapper = new PseudonymMapper();

  addCustomPattern(name: string, pattern: string): void {
    this.engine.addCustomPattern(name, pattern);
    this.cache.clear();
  }

  redact(text: string, options: RedactOptions = {}): RedactResult {
    const {
      countries = null,
      mode = "rules",
      pseudonymize = false,
      detectDates = false,
      cache = true,
    } = options;

    const [normalizedText, offsetMapping] = normalize(text);

    const countriesTuple = countries
      ? countries.map(c => c.toUpperCase()).sort()
      : ["ALL"];
    const cacheMode = `${mode}|dates=${detectDates}`;

    let cacheKey: string | undefined;
    if (cache) {
      cacheKey = this.cache.key(normalizedText, countriesTuple, cacheMode);
      const cached = this.cache.get(cacheKey);
      if (cached !== null) return cached;
    }

    let detections = this.engine.detect(normalizedText, countries);

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

    let redacted = text;
    for (let i = detections.length - 1; i >= 0; i--) {
      const det = detections[i];
      const replacement = pseudonymize
        ? this.pseudonymMapper.getPseudonym(det.text, det.entityType)
        : `[${det.entityType}]`;
      redacted = redacted.slice(0, det.start) + replacement + redacted.slice(det.end);
    }

    const result: RedactResult = {
      redactedText: redacted,
      detections,
      source: "rules",
      degraded: false,
    };

    if (cache && cacheKey) {
      this.cache.put(cacheKey, result);
    }

    return result;
  }

  redactBatch(texts: string[], options: RedactOptions = {}): RedactResult[] {
    const countries = options.countries ?? null;
    this.engine.loadCountries(
      countries ? countries.map(c => c.toUpperCase()) : null
    );
    return texts.map(text => this.redact(text, options));
  }
}
