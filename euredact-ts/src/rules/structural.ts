import { EntityType, DetectionSource, type Detection } from "../types.js";

const DATE_RE = /(?:0[1-9]|[12]\d|3[01])[/.\-](?:0[1-9]|1[0-2])[/.\-](?:19|20)\d{2}|(?:19|20)\d{2}[/.\-](?:0[1-9]|1[0-2])[/.\-](?:0[1-9]|[12]\d|3[01])/g;

const DOB_FIELD_NAMES = [
  "geboortedatum", "date_naissance", "date de naissance", "geburtsdatum",
  "dob", "birth_date", "birthdate", "date_of_birth",
  "fecha_nacimiento", "data_nascita", "born",
  "naissance", "geboren",
];

const JSON_KV = /"([^"]+?)"\s*:\s*"([^"]*?)"/g;

function detectJsonDob(text: string): Detection[] {
  const detections: Detection[] = [];
  JSON_KV.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = JSON_KV.exec(text)) !== null) {
    const key = m[1].toLowerCase().trim();
    const value = m[2];
    if (!DOB_FIELD_NAMES.some(kw => key.includes(kw))) continue;
    DATE_RE.lastIndex = 0;
    const dm = DATE_RE.exec(value);
    if (dm) {
      const valStart = m.index + m[0].indexOf(m[2]);
      const absStart = valStart + dm.index;
      const absEnd = absStart + dm[0].length;
      detections.push({
        entityType: EntityType.DOB,
        start: absStart,
        end: absEnd,
        text: text.slice(absStart, absEnd),
        source: DetectionSource.RULES,
        country: null,
        confidence: "high",
      });
    }
  }
  return detections;
}

function detectDelimiter(header: string): string | null {
  for (const delim of ["|", ";", "\t", ","]) {
    if ((header.match(new RegExp(delim.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "g")) || []).length >= 2) return delim;
  }
  return null;
}

function detectCsvDob(text: string): Detection[] {
  const detections: Detection[] = [];
  const lines = text.split("\n");
  if (lines.length < 2) return detections;
  const headerLine = lines[0];
  const delimiter = detectDelimiter(headerLine);
  if (!delimiter) return detections;
  const headers = headerLine.split(delimiter).map(h => h.trim().toLowerCase());
  if (headers.length < 2) return detections;
  const dobColumns: number[] = [];
  for (let i = 0; i < headers.length; i++) {
    if (DOB_FIELD_NAMES.some(kw => headers[i].includes(kw))) dobColumns.push(i);
  }
  if (dobColumns.length === 0) return detections;
  let offset = lines[0].length + 1;
  for (let li = 1; li < lines.length; li++) {
    const line = lines[li];
    if (!line.trim()) { offset += line.length + 1; continue; }
    const fields = line.split(delimiter);
    for (const colIdx of dobColumns) {
      if (colIdx >= fields.length) continue;
      const field = fields[colIdx];
      DATE_RE.lastIndex = 0;
      const dm = DATE_RE.exec(field);
      if (dm) {
        let fieldOffset = 0;
        for (let fi = 0; fi < colIdx; fi++) fieldOffset += fields[fi].length + delimiter.length;
        const absStart = offset + fieldOffset + dm.index;
        const absEnd = absStart + dm[0].length;
        detections.push({
          entityType: EntityType.DOB,
          start: absStart,
          end: absEnd,
          text: text.slice(absStart, absEnd),
          source: DetectionSource.RULES,
          country: null,
          confidence: "high",
        });
      }
    }
    offset += line.length + 1;
  }
  return detections;
}

export function detectStructuralDob(text: string): Detection[] {
  return [...detectJsonDob(text), ...detectCsvDob(text)];
}
