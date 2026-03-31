import type { CountryConfig, PatternDef } from "../types.js";
import { VALIDATORS } from "./validators.js";
import type { RawMatch } from "./suppressors.js";

export type { RawMatch };

interface CompiledPattern {
  regex: RegExp;
  patternDef: PatternDef;
  countryCode: string;
}

export class MultiPatternMatcher {
  private patterns: CompiledPattern[] = [];
  private compiled = false;

  addPattern(patternDef: PatternDef, countryCode: string): void {
    const regex = new RegExp(patternDef.pattern, "gu");
    this.patterns.push({ regex, patternDef, countryCode });
    this.compiled = false;
  }

  addCountry(config: CountryConfig): void {
    for (const pdef of config.patterns) {
      // Convert Python-style \b word boundaries — JS handles them natively
      // But we need the 'u' flag for Unicode support
      const regex = new RegExp(pdef.pattern, "gu");
      this.patterns.push({ regex, patternDef: pdef, countryCode: config.code });
    }
    this.compiled = false;
  }

  compile(): void {
    this.compiled = true;
  }

  scan(text: string): RawMatch[] {
    if (!this.compiled) this.compile();
    const matches: RawMatch[] = [];
    for (const { regex, patternDef, countryCode } of this.patterns) {
      regex.lastIndex = 0;
      let m: RegExpExecArray | null;
      while ((m = regex.exec(text)) !== null) {
        matches.push({
          start: m.index,
          end: m.index + m[0].length,
          text: m[0],
          patternDef,
          countryCode,
        });
        // Prevent infinite loops on zero-length matches
        if (m[0].length === 0) regex.lastIndex++;
      }
    }
    return matches;
  }

  validate(match: RawMatch): boolean {
    if (match.patternDef.validator === null) return true;
    const validator = VALIDATORS[match.patternDef.validator];
    if (!validator) return true;
    return validator(match.text);
  }
}
