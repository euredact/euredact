"""Combined evaluation — HTML report with recall + precision per PII type and country.

DOB is reported separately as an optional category (handled by the LLM tier).
"""

import json
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path
from html import escape

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
import euredact
from euredact.types import EntityType

DATA_DIR = Path("/Users/jorenjanssens/Library/Mobile Documents/com~apple~CloudDocs/Werken/JNJS/Apps/PII-EuroMask/Data-Generation")
DATASETS = sorted(DATA_DIR.glob("*.json"))
REPORT_PATH = Path(__file__).resolve().parents[1] / "evaluation_report.html"

CATEGORY_MAP: dict[str, set[str]] = {
    "NATIONAL_ID": {EntityType.NATIONAL_ID.value, EntityType.SSN.value, EntityType.TAX_ID.value},
    "NATIONAL_ID_CARD": {EntityType.NATIONAL_ID.value},
    "SOCIAL_SECURITY": {EntityType.NATIONAL_ID.value, EntityType.SSN.value},
    "TAX_ID": {EntityType.TAX_ID.value},
    "TAX_ID_PERSONAL": {EntityType.TAX_ID.value},
    "TAX_ID_BUSINESS": {EntityType.VAT.value, EntityType.TAX_ID.value},
    "IBAN": {EntityType.IBAN.value},
    "CREDIT_CARD": {EntityType.CREDIT_CARD.value},
    "VAT_NUMBER": {EntityType.VAT.value, EntityType.CHAMBER_OF_COMMERCE.value},
    "PHONE": {EntityType.PHONE.value},
    "EMAIL": {EntityType.EMAIL.value},
    "DOB": {EntityType.DOB.value},
    "POSTAL_CODE": {EntityType.POSTAL_CODE.value},
    "LICENSE_PLATE": {EntityType.LICENSE_PLATE.value},
    "VIN": {EntityType.VIN.value},
    "PASSPORT": {EntityType.PASSPORT.value},
    "HEALTH_INSURANCE": {EntityType.HEALTH_INSURANCE.value, EntityType.NATIONAL_ID.value},
    "CHAMBER_OF_COMMERCE": {EntityType.CHAMBER_OF_COMMERCE.value, EntityType.VAT.value},
    "IP_ADDRESS": {EntityType.IP_ADDRESS.value},
    "IPV6_ADDRESS": {EntityType.IPV6_ADDRESS.value},
    "MAC_ADDRESS": {EntityType.MAC_ADDRESS.value},
    "BIC": {EntityType.BIC.value},
    "IMEI": {EntityType.IMEI.value},
    "GPS_COORDINATES": {EntityType.GPS_COORDINATES.value},
    "SWIFT_BIC": {EntityType.BIC.value},
    "IP_ADDRESS_V6": {EntityType.IPV6_ADDRESS.value},
    "UUID": {EntityType.UUID.value},
    "SOCIAL_HANDLE": {EntityType.SOCIAL_HANDLE.value},
}

# Categories to exclude from evaluation entirely (not in scope)
EXCLUDED_CATEGORIES = {"CRYPTO_ADDRESS_BTC", "CRYPTO_ADDRESS_ETH"}

# DOB is optional — handled by LLM tier, excluded from main stats
DOB_CATEGORIES = {"DOB"}

REVERSE_MAP: dict[str, set[str]] = defaultdict(set)
for _tc, _evs in CATEGORY_MAP.items():
    for _ev in _evs:
        REVERSE_MAP[_ev].add(_tc)


def pct(n, d):
    return n / d * 100 if d else 0.0


def f1(recall, precision):
    return 2 * recall * precision / (recall + precision) if (recall + precision) > 0 else 0.0


def _detection_matches_any(det, expected_spans):
    for es, ee, ecat in expected_spans:
        if det.start < ee and det.end > es:
            acceptable = CATEGORY_MAP.get(ecat, {ecat})
            if det.entity_type.value in acceptable:
                return True
            if ecat in REVERSE_MAP.get(det.entity_type.value, set()):
                return True
    return False


def evaluate(data, use_country_hints: bool):
    cat_tp = Counter(); cat_total = Counter()
    country_tp = Counter(); country_total = Counter()
    cc_tp = Counter(); cc_total = Counter()
    combo_tp = Counter(); combo_total = Counter()
    multi_tp = 0; multi_total = 0
    single_tp = 0; single_total = 0
    det_tp_by_type = Counter(); det_fp_by_type = Counter()
    det_tp_by_country = Counter(); det_fp_by_country = Counter()
    det_tp_by_tc = Counter(); det_fp_by_tc = Counter()
    fp_examples: list[dict] = []  # Sample for HTML report
    all_fps: list[dict] = []      # Complete list for JSON export

    euredact._instance = None
    t0 = time.perf_counter()

    for item in data:
        text = item["source_text"]
        expected = item["PII"]
        if not expected:
            continue

        item_countries = list({p["PII_country"] for p in expected})
        is_multi = len(item_countries) > 1
        combo = " + ".join(sorted(item_countries))
        # Filter to known countries; unknown ones (e.g. INTL) fall back to all-countries
        from euredact.rules.registry import CountryRegistry
        known = set(CountryRegistry().available_countries)
        valid_countries = [c for c in item_countries if c in known]
        countries_arg = valid_countries if (use_country_hints and valid_countries) else None
        result = euredact.redact(text, countries=countries_arg, detect_dates=True, cache=False)

        for pii in expected:
            pii_cat = pii["PII_category"]
            if pii_cat in EXCLUDED_CATEGORIES:
                continue
            pii_text = pii["PII_identifier"]
            pii_country = pii["PII_country"]
            acceptable = CATEGORY_MAP.get(pii_cat, {pii_cat})

            cat_total[pii_cat] += 1
            country_total[pii_country] += 1
            cc_total[(pii_cat, pii_country)] += 1
            if is_multi:
                multi_total += 1
                combo_total[combo] += 1
            else:
                single_total += 1

            found = pii_text not in result.redacted_text
            if not found:
                idx = text.find(pii_text)
                if idx >= 0:
                    end = idx + len(pii_text)
                    for det in result.detections:
                        if det.start < end and det.end > idx and det.entity_type.value in acceptable:
                            found = True
                            break

            if found:
                cat_tp[pii_cat] += 1
                country_tp[pii_country] += 1
                cc_tp[(pii_cat, pii_country)] += 1
                if is_multi:
                    multi_tp += 1
                    combo_tp[combo] += 1
                else:
                    single_tp += 1

        expected_spans = []
        for pii in expected:
            if pii["PII_category"] in EXCLUDED_CATEGORIES:
                continue
            idx = text.find(pii["PII_identifier"])
            if idx >= 0:
                expected_spans.append((idx, idx + len(pii["PII_identifier"]), pii["PII_category"]))

        for det in result.detections:
            etype = det.entity_type.value
            det_countries = item_countries
            if _detection_matches_any(det, expected_spans):
                det_tp_by_type[etype] += 1
                for c in det_countries:
                    det_tp_by_country[c] += 1
                    det_tp_by_tc[(etype, c)] += 1
            else:
                det_fp_by_type[etype] += 1
                for c in det_countries:
                    det_fp_by_country[c] += 1
                    det_fp_by_tc[(etype, c)] += 1
                all_fps.append({
                    "pii_type": etype,
                    "pii_text": det.text,
                    "pii_country": det.country,
                    "countries_in_record": sorted(set(item_countries)),
                    "source_text": text,
                })
                if len(fp_examples) < 60:
                    fp_examples.append({
                        "type": etype, "text": det.text, "countries": combo,
                        "context": text[max(0, det.start - 40):det.end + 40],
                    })

    elapsed = time.perf_counter() - t0
    total_det = sum(det_tp_by_type.values()) + sum(det_fp_by_type.values())
    total_tp_det = sum(det_tp_by_type.values())
    total_fp_det = sum(det_fp_by_type.values())

    return dict(
        elapsed=elapsed, num_records=len(data),
        cat_tp=cat_tp, cat_total=cat_total,
        country_tp=country_tp, country_total=country_total,
        cc_tp=cc_tp, cc_total=cc_total,
        combo_tp=combo_tp, combo_total=combo_total,
        multi_tp=multi_tp, multi_total=multi_total,
        single_tp=single_tp, single_total=single_total,
        det_tp_by_type=det_tp_by_type, det_fp_by_type=det_fp_by_type,
        det_tp_by_country=det_tp_by_country, det_fp_by_country=det_fp_by_country,
        det_tp_by_tc=det_tp_by_tc, det_fp_by_tc=det_fp_by_tc,
        total_det=total_det, total_tp_det=total_tp_det, total_fp_det=total_fp_det,
        fp_examples=fp_examples, all_fps=all_fps,
    )


# ── Helpers ─────────────────────────────────────────────────────────────

def _cls(r):
    if r >= 99: return "perfect"
    if r >= 95: return "good"
    if r >= 80: return "warn"
    return "bad"


def _sum_excl_dob(counter, key_fn=None):
    """Sum counter values excluding DOB categories."""
    return sum(v for k, v in counter.items() if (key_fn(k) if key_fn else k) not in DOB_CATEGORIES)


def _core_cats(s):
    """Return category names excluding DOB, sorted by total descending."""
    return [c for c in sorted(s["cat_total"], key=lambda c: -s["cat_total"][c]) if c not in DOB_CATEGORIES]


def _dob_cats(s):
    return [c for c in s["cat_total"] if c in DOB_CATEGORIES]


def _core_recall(s):
    tp = sum(s["cat_tp"].get(c, 0) for c in _core_cats(s))
    tot = sum(s["cat_total"].get(c, 0) for c in _core_cats(s))
    return tp, tot


def _core_precision(s):
    """Precision excluding DOB detections."""
    dob_etypes = set()
    for dc in DOB_CATEGORIES:
        dob_etypes |= CATEGORY_MAP.get(dc, {dc})
    tp = sum(v for k, v in s["det_tp_by_type"].items() if k not in dob_etypes)
    fp = sum(v for k, v in s["det_fp_by_type"].items() if k not in dob_etypes)
    return tp, tp + fp


# ── HTML rendering ──────────────────────────────────────────────────────

def render_summary(s):
    rec_n, rec_d = _core_recall(s)
    rec = pct(rec_n, rec_d)
    prec_tp, prec_tot = _core_precision(s)
    prec = pct(prec_tp, prec_tot)
    f1v = f1(rec / 100, prec / 100)
    fp = prec_tot - prec_tp

    # DOB stats
    dob_n = sum(s["cat_tp"].get(c, 0) for c in _dob_cats(s))
    dob_d = sum(s["cat_total"].get(c, 0) for c in _dob_cats(s))
    dob_rec = pct(dob_n, dob_d)

    return f"""
    <div class="summary">
      <div class="card">
        <div class="card-title">Records</div>
        <div class="big-number">{s['num_records']:,}</div>
        <div class="card-detail">Expected PII: {rec_d:,} (excl. DOB) &middot; Detections: {prec_tot:,}</div>
        <div class="card-detail">Processing time: {s['elapsed']:.1f}s</div>
      </div>
      <div class="card">
        <div class="card-title">Recall</div>
        <div class="big-number {_cls(rec)}">{rec:.1f}%</div>
        <div class="card-detail">{rec_n:,} / {rec_d:,} PII detected (excl. DOB)</div>
      </div>
      <div class="card">
        <div class="card-title">Precision</div>
        <div class="big-number {_cls(prec)}">{prec:.1f}%</div>
        <div class="card-detail">{prec_tp:,} TP &middot; {fp:,} FP (excl. DOB)</div>
      </div>
      <div class="card">
        <div class="card-title">F1 Score</div>
        <div class="big-number">{f1v:.3f}</div>
      </div>
      <div class="card dob-card">
        <div class="card-title">DOB (optional, LLM tier)</div>
        <div class="big-number dob-number">{dob_rec:.1f}%</div>
        <div class="card-detail">{dob_n:,} / {dob_d:,} &middot; dates without keyword context deferred to LLM</div>
      </div>
    </div>"""


def _cat_row(s, cat):
    t = s["cat_total"][cat]
    tp = s["cat_tp"][cat]
    miss = t - tp
    rec = pct(tp, t)
    etypes = CATEGORY_MAP.get(cat, {cat})
    det_tp = sum(s["det_tp_by_type"].get(et, 0) for et in etypes)
    det_fp = sum(s["det_fp_by_type"].get(et, 0) for et in etypes)
    det_total = det_tp + det_fp
    prec = pct(det_tp, det_total)
    f1v = f1(rec / 100, prec / 100)
    rc = _cls(rec)
    pc = _cls(prec)
    return f"""<tr>
      <td class="label">{escape(cat)}</td>
      <td class="num">{t:,}</td><td class="num">{tp:,}</td><td class="num">{miss}</td>
      <td class="{rc}">{rec:.1f}%</td>
      <td class="num">{det_total:,}</td><td class="num">{det_tp:,}</td><td class="num fp-num">{det_fp}</td>
      <td class="{pc}">{prec:.1f}%</td>
      <td>{f1v:.3f}</td>
    </tr>"""


def render_category_table(s):
    core_rows = "".join(_cat_row(s, cat) for cat in _core_cats(s))
    dob_rows = ""
    for cat in _dob_cats(s):
        dob_rows += _cat_row(s, cat).replace("<tr>", '<tr class="dob-row">')

    thead = """<thead><tr>
        <th rowspan=2>PII Category</th>
        <th colspan=4 class="group-recall">Recall</th>
        <th colspan=4 class="group-precision">Precision</th>
        <th rowspan=2>F1</th>
      </tr><tr>
        <th class="group-recall">Expected</th><th class="group-recall">Hit</th><th class="group-recall">Miss</th><th class="group-recall">Rate</th>
        <th class="group-precision">Detected</th><th class="group-precision">TP</th><th class="group-precision">FP</th><th class="group-precision">Rate</th>
      </tr></thead>"""

    return f"""
    <table>{thead}<tbody>{core_rows}</tbody>
    <tbody class="dob-section"><tr><td colspan=10 class="dob-separator">Optional — deferred to LLM cloud tier</td></tr>{dob_rows}</tbody>
    </table>"""


def render_country_table(s):
    """Country table excluding DOB from recall totals."""
    rows = ""
    for c in sorted(s["country_total"], key=lambda x: -s["country_total"][x]):
        # Recall excl DOB
        t = sum(s["cc_total"].get((cat, c), 0) for cat in _core_cats(s))
        tp = sum(s["cc_tp"].get((cat, c), 0) for cat in _core_cats(s))
        rec = pct(tp, t)
        # Precision excl DOB detections
        dob_etypes = set()
        for dc in DOB_CATEGORIES:
            dob_etypes |= CATEGORY_MAP.get(dc, {dc})
        dtp = sum(v for (et, cc), v in s["det_tp_by_tc"].items() if cc == c and et not in dob_etypes)
        dfp = sum(v for (et, cc), v in s["det_fp_by_tc"].items() if cc == c and et not in dob_etypes)
        dtot = dtp + dfp
        prec = pct(dtp, dtot)
        f1v = f1(rec / 100, prec / 100)
        rc = _cls(rec)
        pc = _cls(prec)
        rows += f"""<tr>
          <td class="label">{escape(c)}</td>
          <td class="num">{t:,}</td><td class="num">{tp:,}</td><td class="num">{t-tp}</td>
          <td class="{rc}">{rec:.1f}%</td>
          <td class="num">{dtot:,}</td><td class="num">{dtp:,}</td><td class="num fp-num">{dfp}</td>
          <td class="{pc}">{prec:.1f}%</td>
          <td>{f1v:.3f}</td>
        </tr>"""
    return f"""
    <table><thead><tr>
        <th rowspan=2>Country</th>
        <th colspan=4 class="group-recall">Recall (excl. DOB)</th>
        <th colspan=4 class="group-precision">Precision (excl. DOB)</th>
        <th rowspan=2>F1</th>
      </tr><tr>
        <th class="group-recall">Expected</th><th class="group-recall">Hit</th><th class="group-recall">Miss</th><th class="group-recall">Rate</th>
        <th class="group-precision">Detected</th><th class="group-precision">TP</th><th class="group-precision">FP</th><th class="group-precision">Rate</th>
      </tr></thead><tbody>{rows}</tbody></table>"""


def render_recall_matrix(s):
    countries = sorted(s["country_total"], key=lambda x: -s["country_total"][x])
    core = _core_cats(s)
    dob = _dob_cats(s)
    hdr = "".join(f"<th>{c}</th>" for c in countries)

    def _matrix_rows(cats, cls_extra=""):
        rows = ""
        for cat in cats:
            cells = ""
            for c in countries:
                t = s["cc_total"].get((cat, c), 0)
                d = s["cc_tp"].get((cat, c), 0)
                if t == 0:
                    cells += '<td class="na">&mdash;</td>'
                else:
                    r = pct(d, t)
                    cells += f'<td class="{_cls(r)}" title="{d}/{t}">{r:.0f}%</td>'
            tr_cls = f' class="{cls_extra}"' if cls_extra else ""
            rows += f"<tr{tr_cls}><td class='label'>{escape(cat)}</td>{cells}</tr>"
        return rows

    core_rows = _matrix_rows(core)
    dob_rows = _matrix_rows(dob, "dob-row")
    dob_sep = f'<tr><td colspan="{1+len(countries)}" class="dob-separator">Optional — deferred to LLM</td></tr>' if dob else ""

    return f"""
    <table class="matrix">
      <thead><tr><th>Category \\ Country</th>{hdr}</tr></thead>
      <tbody>{core_rows}</tbody>
      <tbody class="dob-section">{dob_sep}{dob_rows}</tbody>
    </table>"""


def render_fp_matrix(s):
    countries = sorted(s["country_total"], key=lambda x: -s["country_total"][x])
    # Exclude DOB entity types from FP matrix
    dob_etypes = set()
    for dc in DOB_CATEGORIES:
        dob_etypes |= CATEGORY_MAP.get(dc, {dc})
    etypes = [et for et in sorted(s["det_fp_by_type"], key=lambda e: -s["det_fp_by_type"][e]) if et not in dob_etypes]
    if not etypes:
        return "<p>No false positives (excl. DOB).</p>"
    hdr = "".join(f"<th>{c}</th>" for c in countries)
    rows = ""
    for et in etypes:
        total_fp = s["det_fp_by_type"][et]
        cells = ""
        for c in countries:
            fp = s["det_fp_by_tc"].get((et, c), 0)
            cells += f'<td class="fp-num">{fp}</td>' if fp else '<td class="na">0</td>'
        rows += f"<tr><td class='label'>{escape(et)}</td><td class='num fp-num'>{total_fp}</td>{cells}</tr>"
    return f"""
    <table class="matrix">
      <thead><tr><th>Entity Type</th><th>Total FP</th>{hdr}</tr></thead>
      <tbody>{rows}</tbody>
    </table>"""


def render_multi_country(s):
    # Exclude DOB from multi-country stats
    # Recompute from cc counters
    def _scope_stats(is_multi_filter):
        tot = 0; hit = 0
        for item_key in s["combo_total"] if is_multi_filter else []:
            pass  # Can't easily recompute per-record scope without DOB
        return tot, hit

    # Use the stored counters but subtract DOB
    dob_in_multi = sum(s["cc_total"].get((cat, c), 0) for cat in DOB_CATEGORIES for c in s["country_total"] if s["combo_total"])
    # Simpler: just subtract DOB from totals
    dob_total = sum(s["cat_total"].get(c, 0) for c in DOB_CATEGORIES)
    dob_tp = sum(s["cat_tp"].get(c, 0) for c in DOB_CATEGORIES)

    mt = s["multi_total"]
    md = s["multi_tp"]
    st = s["single_total"]
    sd = s["single_tp"]
    # We can't perfectly subtract DOB per scope, so just show raw (DOB is small fraction of multi)
    # Actually let's just show these as-is with a note
    rows = ""
    for label, t, d in [("Single-country", st, sd), ("Multi-country", mt, md)]:
        r = pct(d, t)
        rows += f'<tr><td class="label">{label}</td><td class="num">{t:,}</td><td class="num">{d:,}</td><td class="num">{t-d}</td><td class="{_cls(r)}">{r:.1f}%</td></tr>'

    combo_rows = ""
    for combo in sorted(s["combo_total"], key=lambda x: -s["combo_total"][x]):
        t = s["combo_total"][combo]
        d = s["combo_tp"][combo]
        r = pct(d, t)
        combo_rows += f'<tr><td class="label">{escape(combo)}</td><td class="num">{t:,}</td><td class="num">{d:,}</td><td class="num">{t-d}</td><td class="{_cls(r)}">{r:.1f}%</td></tr>'

    html = f"""
    <p class="note">Note: multi-country stats include DOB for completeness.</p>
    <table><thead><tr><th>Scope</th><th>Total</th><th>Hit</th><th>Miss</th><th>Recall</th></tr></thead>
    <tbody>{rows}</tbody></table>"""
    if combo_rows:
        html += f"""
        <h4>By Country Combination</h4>
        <table><thead><tr><th>Combination</th><th>Total</th><th>Hit</th><th>Miss</th><th>Recall</th></tr></thead>
        <tbody>{combo_rows}</tbody></table>"""
    return html


def render_fp_examples(s):
    # Exclude DOB FPs
    dob_etypes = set()
    for dc in DOB_CATEGORIES:
        dob_etypes |= CATEGORY_MAP.get(dc, {dc})
    examples = [ex for ex in s["fp_examples"] if ex["type"] not in dob_etypes]
    if not examples:
        return ""
    rows = ""
    for ex in examples[:40]:
        ctx = escape(ex["context"]).replace(escape(ex["text"]), f'<mark>{escape(ex["text"])}</mark>')
        rows += f'<tr><td class="label">{escape(ex["type"])}</td><td><code>{escape(ex["text"])}</code></td><td>{escape(ex["countries"])}</td><td class="ctx">&hellip;{ctx}&hellip;</td></tr>'
    return f"""
    <h3>False Positive Examples (sample)</h3>
    <table class="fp-table">
      <thead><tr><th>Type</th><th>Detected Text</th><th>Countries</th><th>Context</th></tr></thead>
      <tbody>{rows}</tbody>
    </table>"""


CSS = """
:root { --green: #16a34a; --lime: #65a30d; --amber: #d97706; --red: #dc2626; --blue: #2563eb; --bg: #f8fafc; --fg: #0f172a; }
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: 'Inter', system-ui, -apple-system, sans-serif; background: var(--bg); color: var(--fg); line-height: 1.5; padding: 2rem; max-width: 1280px; margin: 0 auto; }
h1 { font-size: 1.5rem; margin-bottom: .25rem; }
h1 small { font-weight: 400; color: #64748b; font-size: .85rem; }
h2 { font-size: 1.2rem; margin: 2rem 0 .75rem; border-bottom: 2px solid #e2e8f0; padding-bottom: .4rem; }
h3 { font-size: 1rem; margin: 1.5rem 0 .5rem; color: #475569; }
h4 { font-size: .9rem; margin: 1rem 0 .4rem; color: #64748b; }
.summary { display: flex; gap: 1rem; flex-wrap: wrap; margin: 1.25rem 0; }
.card { background: white; border: 1px solid #e2e8f0; border-radius: .5rem; padding: 1rem 1.25rem; min-width: 170px; flex: 1; }
.card-title { font-size: .75rem; text-transform: uppercase; letter-spacing: .05em; color: #64748b; margin-bottom: .15rem; }
.big-number { font-size: 2rem; font-weight: 700; line-height: 1.2; }
.card-detail { font-size: .78rem; color: #94a3b8; }
.dob-card { background: #f8fafc; border: 1px dashed #94a3b8; }
.dob-card .card-title { color: #94a3b8; }
.dob-number { color: #64748b !important; font-size: 1.5rem; }
table { width: 100%; border-collapse: collapse; margin-bottom: 1rem; font-size: .82rem; }
th, td { padding: .35rem .55rem; text-align: left; border-bottom: 1px solid #e2e8f0; }
th { background: #f1f5f9; font-weight: 600; font-size: .72rem; text-transform: uppercase; letter-spacing: .04em; color: #475569; }
.group-recall { background: #f0fdf4; }
.group-precision { background: #fef2f2; }
.num { text-align: right; font-variant-numeric: tabular-nums; }
.fp-num { color: var(--red); font-weight: 500; }
.label { font-weight: 500; white-space: nowrap; }
.matrix td, .matrix th { text-align: center; padding: .25rem .45rem; font-size: .78rem; }
.matrix td.label { text-align: left; }
.fill { height: 100%; border-radius: 4px; }
.perfect { color: var(--green); } .fill.perfect { background: var(--green); }
.good { color: var(--lime); } .fill.good { background: var(--lime); }
.warn { color: var(--amber); } .fill.warn { background: var(--amber); }
.bad { color: var(--red); } .fill.bad { background: var(--red); }
.na { color: #cbd5e1; }
.dob-row td { color: #94a3b8; font-style: italic; }
.dob-row td.label::after { content: " *"; color: #94a3b8; }
.dob-separator { text-align: center; color: #94a3b8; font-style: italic; font-size: .75rem; padding: .5rem; border-top: 1px dashed #cbd5e1; border-bottom: none; }
.dob-section { border-top: 1px dashed #cbd5e1; }
.note { font-size: .78rem; color: #94a3b8; font-style: italic; margin-bottom: .5rem; }
.mode-header { background: #1e293b; color: white; padding: .6rem 1rem; border-radius: .5rem; margin: 2.5rem 0 1rem; font-size: 1.05rem; font-weight: 600; }
hr { border: none; border-top: 3px solid #1e293b; margin: 3rem 0; }
.fp-table td.ctx { font-size: .72rem; color: #64748b; max-width: 450px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.fp-table code { background: #fef2f2; color: var(--red); padding: .1rem .3rem; border-radius: 3px; font-size: .78rem; }
.fp-table mark { background: #fecaca; color: var(--red); padding: 0 .15rem; border-radius: 2px; }
"""


def main():
    all_data = []
    for ds_path in DATASETS:
        if not ds_path.exists():
            print(f"WARNING: {ds_path} not found, skipping.")
            continue
        with open(ds_path) as f:
            records = json.load(f)
        all_data.extend(records)
        print(f"Loaded {ds_path.name}: {len(records)} records")
    print(f"Combined: {len(all_data)} records")

    html = [f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>EuRedact Evaluation Report</title>
<style>{CSS}</style></head><body>
<h1>EuRedact Rule Engine &mdash; Evaluation Report <small>{time.strftime('%Y-%m-%d %H:%M')} &middot; {len(all_data):,} records &middot; 10 countries</small></h1>
"""]

    for mode_label, use_hints in [
        ("With Country Hints", True),
        ("Without Country Hints (blind detection)", False),
    ]:
        print(f"\n  Running [{mode_label}] ...", end=" ", flush=True)
        s = evaluate(all_data, use_hints)
        rec_n, rec_d = _core_recall(s)
        rec = pct(rec_n, rec_d)
        prec_tp, prec_tot = _core_precision(s)
        prec = pct(prec_tp, prec_tot)
        dob_n = sum(s["cat_tp"].get(c, 0) for c in DOB_CATEGORIES)
        dob_d = sum(s["cat_total"].get(c, 0) for c in DOB_CATEGORIES)
        print(f"done in {s['elapsed']:.1f}s — recall {rec:.1f}% (excl DOB), precision {prec:.1f}%, DOB {pct(dob_n,dob_d):.1f}%")

        # Export all false positives to JSON
        fp_tag = "with_hints" if use_hints else "blind"
        fp_path = REPORT_PATH.parent / f"false_positives_{fp_tag}.json"
        # Exclude DOB from FP export
        dob_etypes = set()
        for dc in DOB_CATEGORIES:
            dob_etypes |= CATEGORY_MAP.get(dc, {dc})
        fps_to_export = [fp for fp in s["all_fps"] if fp["pii_type"] not in dob_etypes]
        with open(fp_path, "w", encoding="utf-8") as fp_f:
            json.dump(fps_to_export, fp_f, indent=2, ensure_ascii=False)
        print(f"  False positives: {len(fps_to_export)} written to {fp_path.name}")

        html.append(f'<div class="mode-header">Mode: {escape(mode_label)}</div>')
        html.append(render_summary(s))
        html.append("<h2>Performance by PII Category</h2>")
        html.append(render_category_table(s))
        html.append("<h2>Performance by Country (excl. DOB)</h2>")
        html.append(render_country_table(s))
        html.append("<h2>Recall Matrix: Category &times; Country</h2>")
        html.append(render_recall_matrix(s))
        html.append("<h2>False Positives Matrix: Entity Type &times; Country (excl. DOB)</h2>")
        html.append(render_fp_matrix(s))
        html.append("<h2>Single vs Multi-Country</h2>")
        html.append(render_multi_country(s))
        html.append(render_fp_examples(s))
        html.append("<hr>")

    html.append("</body></html>")
    REPORT_PATH.write_text("\n".join(html), encoding="utf-8")
    print(f"\nReport written to {REPORT_PATH}")


if __name__ == "__main__":
    main()
