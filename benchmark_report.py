#!/usr/bin/env python3
"""Generate a combined Python & TypeScript benchmark HTML report.

Usage:
    python benchmark_report.py
    python benchmark_report.py --sample-size 999999
    python benchmark_report.py --output my_report.html
"""

import argparse
import json
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from html import escape
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def run_python_benchmark(sample_size: int) -> dict:
    out = tempfile.NamedTemporaryFile(suffix=".json", delete=False)
    out.close()
    proc = subprocess.run(
        [
            sys.executable,
            str(ROOT / "euredact-python" / "tests" / "benchmark.py"),
            "--json",
            "--sample-size", str(sample_size),
            "--output", out.name,
        ],
        capture_output=True, text=True,
    )
    if proc.returncode != 0:
        print(f"Python benchmark failed:\n{proc.stderr}", file=sys.stderr)
        sys.exit(1)
    return json.loads(Path(out.name).read_text())


def run_ts_benchmark(sample_size: int) -> dict:
    out = tempfile.NamedTemporaryFile(suffix=".json", delete=False)
    out.close()
    proc = subprocess.run(
        [
            "node", "--import", "tsx",
            "src/__tests__/benchmark.ts",
            "--json",
            "--sample-size", str(sample_size),
            "--output", out.name,
        ],
        capture_output=True, text=True,
        cwd=str(ROOT / "euredact-ts"),
    )
    if proc.returncode != 0:
        print(f"TypeScript benchmark failed:\n{proc.stderr}", file=sys.stderr)
        sys.exit(1)
    return json.loads(Path(out.name).read_text())


# ---------------------------------------------------------------------------
# HTML helpers
# ---------------------------------------------------------------------------

def _cls(pct: float | None) -> str:
    if pct is None:
        return "na"
    if pct >= 99:
        return "perfect"
    if pct >= 95:
        return "good"
    if pct >= 85:
        return "warn"
    return "bad"


def _pct(tp: int, total: int) -> str:
    if total == 0:
        return '<span class="na">N/A</span>'
    v = tp / total * 100
    return f'<span class="{_cls(v)}">{v:.1f}%</span>'


def _f1(tp: int, expected: int, detected: int) -> str:
    if expected == 0 or detected == 0:
        return '<span class="na">N/A</span>'
    v = 2 * tp / (expected + detected)
    pct = v * 100
    return f'<span class="{_cls(pct)}">{v:.3f}</span>'


def _num(n: int) -> str:
    return f'{n:,}'


def _delta(py_val: float | None, ts_val: float | None) -> str:
    if py_val is None or ts_val is None:
        return ""
    d = ts_val - py_val
    if abs(d) < 0.05:
        return '<span class="delta-same">=</span>'
    sign = "+" if d > 0 else ""
    cls = "delta-better" if d > 0 else "delta-worse"
    return f'<span class="{cls}">{sign}{d:.1f}pp</span>'


# ---------------------------------------------------------------------------
# HTML generation
# ---------------------------------------------------------------------------

CSS = """\
:root { --green: #16a34a; --lime: #65a30d; --amber: #d97706; --red: #dc2626;
        --blue: #2563eb; --purple: #7c3aed; --bg: #f8fafc; --fg: #0f172a; }
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: 'Inter', system-ui, -apple-system, sans-serif;
       background: var(--bg); color: var(--fg); line-height: 1.5;
       padding: 2rem; max-width: 1400px; margin: 0 auto; }
h1 { font-size: 1.5rem; margin-bottom: .25rem; }
h1 small { font-weight: 400; color: #64748b; font-size: .85rem; }
h2 { font-size: 1.2rem; margin: 2rem 0 .75rem;
     border-bottom: 2px solid #e2e8f0; padding-bottom: .4rem; }
.summary { display: flex; gap: 1rem; flex-wrap: wrap; margin: 1.25rem 0; }
.card { background: white; border: 1px solid #e2e8f0; border-radius: .5rem;
        padding: 1rem 1.25rem; min-width: 150px; flex: 1; }
.card-title { font-size: .75rem; text-transform: uppercase;
              letter-spacing: .05em; color: #64748b; margin-bottom: .15rem; }
.big-number { font-size: 2rem; font-weight: 700; line-height: 1.2; }
.card-detail { font-size: .78rem; color: #94a3b8; }
.runtime-py { color: var(--blue); }
.runtime-ts { color: var(--purple); }
.dual-metric { display: flex; gap: 1.5rem; align-items: baseline; }
.dual-metric .metric { text-align: center; }
.dual-metric .metric-label { font-size: .65rem; text-transform: uppercase;
                              letter-spacing: .05em; margin-bottom: .1rem; }
.dual-metric .metric-value { font-size: 1.8rem; font-weight: 700; line-height: 1.2; }
table { width: 100%; border-collapse: collapse; margin-bottom: 1rem; font-size: .82rem; }
th, td { padding: .35rem .55rem; text-align: left; border-bottom: 1px solid #e2e8f0; }
th { background: #f1f5f9; font-weight: 600; font-size: .72rem;
     text-transform: uppercase; letter-spacing: .04em; color: #475569; }
.group-py { background: #eff6ff; }
.group-ts { background: #f5f3ff; }
.group-shared { background: #f0fdf4; }
.num { text-align: right; font-variant-numeric: tabular-nums; }
.label { font-weight: 500; white-space: nowrap; }
.perfect { color: var(--green); }
.good { color: var(--lime); }
.warn { color: var(--amber); }
.bad { color: var(--red); }
.na { color: #cbd5e1; }
.delta-better { color: var(--green); font-size: .75rem; }
.delta-worse { color: var(--red); font-size: .75rem; }
.delta-same { color: #cbd5e1; font-size: .75rem; }
.perf-bar { display: flex; align-items: center; gap: .5rem; }
.perf-fill { height: 18px; border-radius: 3px; min-width: 4px; }
.perf-fill.py { background: var(--blue); }
.perf-fill.ts { background: var(--purple); }
.perf-label { font-size: .78rem; white-space: nowrap; }
.legend { display: flex; gap: 1.5rem; margin: .5rem 0 1rem; font-size: .78rem; color: #64748b; }
.legend-dot { display: inline-block; width: 10px; height: 10px;
              border-radius: 2px; margin-right: .3rem; vertical-align: middle; }
.legend-dot.py { background: var(--blue); }
.legend-dot.ts { background: var(--purple); }
"""


def generate_html(py: dict, ts: dict) -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    py_o = py["overall"]
    ts_o = ts["overall"]

    py_recall = py_o["tp"] / py_o["expected"] * 100 if py_o["expected"] else 0
    ts_recall = ts_o["tp"] / ts_o["expected"] * 100 if ts_o["expected"] else 0
    py_precision = py_o["tp"] / py_o["detected"] * 100 if py_o["detected"] else 0
    ts_precision = ts_o["tp"] / ts_o["detected"] * 100 if ts_o["detected"] else 0
    py_f1 = 2 * py_o["tp"] / (py_o["expected"] + py_o["detected"]) if py_o["expected"] and py_o["detected"] else 0
    ts_f1 = 2 * ts_o["tp"] / (ts_o["expected"] + ts_o["detected"]) if ts_o["expected"] and ts_o["detected"] else 0
    py_ms = py_o["total_time_s"] / py_o["samples"] * 1000 if py_o["samples"] else 0
    ts_ms = ts_o["total_time_s"] / ts_o["samples"] * 1000 if ts_o["samples"] else 0

    parts = []
    parts.append(f"""\
<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>EuRedact Benchmark Report</title>
<style>{CSS}</style></head><body>
<h1>EuRedact Benchmark Report <small>{now} &middot; {_num(py_o['samples'])} records &middot; {len(py['countries'])} countries &middot; v{py['library_version']}</small></h1>

<div class="legend">
  <span><span class="legend-dot py"></span>Python {py['runtime_version']}</span>
  <span><span class="legend-dot ts"></span>TypeScript {ts['runtime_version']}</span>
</div>
""")

    # --- Summary cards ---
    parts.append(f"""\
<div class="summary">
  <div class="card">
    <div class="card-title">Records</div>
    <div class="big-number">{_num(py_o['samples'])}</div>
    <div class="card-detail">Expected PII: {_num(py_o['expected'])} (excl. DOB)</div>
  </div>
  <div class="card">
    <div class="card-title">Recall</div>
    <div class="dual-metric">
      <div class="metric"><div class="metric-label runtime-py">Python</div><div class="metric-value {_cls(py_recall)}">{py_recall:.1f}%</div></div>
      <div class="metric"><div class="metric-label runtime-ts">TypeScript</div><div class="metric-value {_cls(ts_recall)}">{ts_recall:.1f}%</div></div>
    </div>
  </div>
  <div class="card">
    <div class="card-title">Precision</div>
    <div class="dual-metric">
      <div class="metric"><div class="metric-label runtime-py">Python</div><div class="metric-value {_cls(py_precision)}">{py_precision:.1f}%</div></div>
      <div class="metric"><div class="metric-label runtime-ts">TypeScript</div><div class="metric-value {_cls(ts_precision)}">{ts_precision:.1f}%</div></div>
    </div>
  </div>
  <div class="card">
    <div class="card-title">F1 Score</div>
    <div class="dual-metric">
      <div class="metric"><div class="metric-label runtime-py">Python</div><div class="metric-value">{py_f1:.3f}</div></div>
      <div class="metric"><div class="metric-label runtime-ts">TypeScript</div><div class="metric-value">{ts_f1:.3f}</div></div>
    </div>
  </div>
  <div class="card">
    <div class="card-title">Performance</div>
    <div class="dual-metric">
      <div class="metric"><div class="metric-label runtime-py">Python</div><div class="metric-value">{py_ms:.2f}<small style="font-size:.5em;font-weight:400"> ms</small></div></div>
      <div class="metric"><div class="metric-label runtime-ts">TypeScript</div><div class="metric-value">{ts_ms:.2f}<small style="font-size:.5em;font-weight:400"> ms</small></div></div>
    </div>
    <div class="card-detail">Per sample &middot; TS is {py_ms / ts_ms:.0f}x faster</div>
  </div>
</div>
""")

    # --- Per-dataset table ---
    parts.append('<h2>Performance by Dataset</h2>\n<table><thead><tr>')
    parts.append('<th rowspan=2>Dataset</th><th rowspan=2 class="num">Records</th>')
    parts.append('<th colspan=3 class="group-py">Python</th>')
    parts.append('<th colspan=3 class="group-ts">TypeScript</th>')
    parts.append('<th rowspan=2>Delta</th>')
    parts.append('</tr><tr>')
    parts.append('<th class="group-py">Recall</th><th class="group-py">Precision</th><th class="group-py num">ms/rec</th>')
    parts.append('<th class="group-ts">Recall</th><th class="group-ts">Precision</th><th class="group-ts num">ms/rec</th>')
    parts.append('</tr></thead><tbody>\n')

    ts_files = {f["filename"]: f for f in ts["files"]}

    for pf in py["files"]:
        tf = ts_files.get(pf["filename"], {})
        fn = pf["filename"].replace("euromask_", "").replace(".json", "")

        py_r = pf["tp"] / pf["expected"] * 100 if pf["expected"] else None
        py_p = pf["tp"] / pf["detected"] * 100 if pf["detected"] else None
        py_speed = pf["elapsed_s"] / pf["n"] * 1000 if pf["n"] else 0

        ts_r = tf["tp"] / tf["expected"] * 100 if tf.get("expected") else None
        ts_p = tf["tp"] / tf["detected"] * 100 if tf.get("detected") else None
        ts_speed = tf["elapsed_s"] / tf["n"] * 1000 if tf.get("n") else 0

        parts.append(f'<tr><td class="label">{escape(fn)}</td>')
        parts.append(f'<td class="num">{_num(pf["n"])}</td>')
        parts.append(f'<td>{_pct(pf["tp"], pf["expected"])}</td>')
        parts.append(f'<td>{_pct(pf["tp"], pf["detected"])}</td>')
        parts.append(f'<td class="num">{py_speed:.2f}</td>')
        parts.append(f'<td>{_pct(tf.get("tp", 0), tf.get("expected", 0))}</td>')
        parts.append(f'<td>{_pct(tf.get("tp", 0), tf.get("detected", 0))}</td>')
        parts.append(f'<td class="num">{ts_speed:.2f}</td>')
        parts.append(f'<td class="num">{_delta(py_r, ts_r)}</td>')
        parts.append('</tr>\n')

    # Overall row
    parts.append(f'<tr style="font-weight:600;border-top:2px solid #cbd5e1"><td class="label">TOTAL</td>')
    parts.append(f'<td class="num">{_num(py_o["samples"])}</td>')
    parts.append(f'<td>{_pct(py_o["tp"], py_o["expected"])}</td>')
    parts.append(f'<td>{_pct(py_o["tp"], py_o["detected"])}</td>')
    parts.append(f'<td class="num">{py_ms:.2f}</td>')
    parts.append(f'<td>{_pct(ts_o["tp"], ts_o["expected"])}</td>')
    parts.append(f'<td>{_pct(ts_o["tp"], ts_o["detected"])}</td>')
    parts.append(f'<td class="num">{ts_ms:.2f}</td>')
    parts.append(f'<td class="num">{_delta(py_recall, ts_recall)}</td>')
    parts.append('</tr>\n')

    parts.append('</tbody></table>\n')

    # --- Per-category table ---
    parts.append('<h2>Performance by PII Category</h2>\n<table><thead><tr>')
    parts.append('<th rowspan=2>Category</th>')
    parts.append('<th rowspan=2 class="num">Expected</th>')
    parts.append('<th colspan=3 class="group-py">Python</th>')
    parts.append('<th colspan=3 class="group-ts">TypeScript</th>')
    parts.append('<th rowspan=2>Delta</th>')
    parts.append('</tr><tr>')
    parts.append('<th class="group-py num">Detected</th><th class="group-py">Recall</th><th class="group-py">Precision</th>')
    parts.append('<th class="group-ts num">Detected</th><th class="group-ts">Recall</th><th class="group-ts">Precision</th>')
    parts.append('</tr></thead><tbody>\n')

    all_cats = sorted(
        set(py["categories"].keys()) | set(ts["categories"].keys()),
        key=lambda c: -(py["categories"].get(c, {}).get("expected", 0) + ts["categories"].get(c, {}).get("expected", 0)),
    )

    for cat in all_cats:
        ps = py["categories"].get(cat, {"expected": 0, "detected": 0, "tp": 0})
        tss = ts["categories"].get(cat, {"expected": 0, "detected": 0, "tp": 0})
        expected = max(ps["expected"], tss["expected"])

        py_r = ps["tp"] / ps["expected"] * 100 if ps["expected"] else None
        ts_r = tss["tp"] / tss["expected"] * 100 if tss["expected"] else None

        parts.append(f'<tr><td class="label">{escape(cat)}</td>')
        parts.append(f'<td class="num">{_num(expected)}</td>')
        parts.append(f'<td class="num">{_num(ps["detected"])}</td>')
        parts.append(f'<td>{_pct(ps["tp"], ps["expected"])}</td>')
        parts.append(f'<td>{_pct(ps["tp"], ps["detected"])}</td>')
        parts.append(f'<td class="num">{_num(tss["detected"])}</td>')
        parts.append(f'<td>{_pct(tss["tp"], tss["expected"])}</td>')
        parts.append(f'<td>{_pct(tss["tp"], tss["detected"])}</td>')
        parts.append(f'<td class="num">{_delta(py_r, ts_r)}</td>')
        parts.append('</tr>\n')

    parts.append('</tbody></table>\n')

    # --- Performance comparison ---
    parts.append('<h2>Processing Speed by Dataset</h2>\n')
    max_ms = 0
    for pf in py["files"]:
        ms = pf["elapsed_s"] / pf["n"] * 1000 if pf["n"] else 0
        if ms > max_ms:
            max_ms = ms
    if max_ms == 0:
        max_ms = 1

    parts.append('<table><thead><tr><th>Dataset</th><th>Python</th><th>TypeScript</th></tr></thead><tbody>\n')

    for pf in py["files"]:
        tf = ts_files.get(pf["filename"], {})
        fn = pf["filename"].replace("euromask_", "").replace(".json", "")
        py_speed = pf["elapsed_s"] / pf["n"] * 1000 if pf["n"] else 0
        ts_speed = tf["elapsed_s"] / tf["n"] * 1000 if tf.get("n") else 0
        py_w = py_speed / max_ms * 100
        ts_w = ts_speed / max_ms * 100

        parts.append(f'<tr><td class="label">{escape(fn)}</td>')
        parts.append(f'<td><div class="perf-bar"><div class="perf-fill py" style="width:{py_w:.1f}%"></div><span class="perf-label">{py_speed:.2f} ms</span></div></td>')
        parts.append(f'<td><div class="perf-bar"><div class="perf-fill ts" style="width:{ts_w:.1f}%"></div><span class="perf-label">{ts_speed:.2f} ms</span></div></td>')
        parts.append('</tr>\n')

    parts.append(f'<tr style="font-weight:600;border-top:2px solid #cbd5e1"><td class="label">Average</td>')
    parts.append(f'<td><div class="perf-bar"><div class="perf-fill py" style="width:{py_ms / max_ms * 100:.1f}%"></div><span class="perf-label">{py_ms:.2f} ms ({py_o["total_time_s"]:.1f}s total)</span></div></td>')
    parts.append(f'<td><div class="perf-bar"><div class="perf-fill ts" style="width:{ts_ms / max_ms * 100:.1f}%"></div><span class="perf-label">{ts_ms:.2f} ms ({ts_o["total_time_s"]:.1f}s total)</span></div></td>')
    parts.append('</tr>\n')

    parts.append('</tbody></table>\n')

    parts.append('</body></html>')

    return "".join(parts)


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate combined euredact benchmark report")
    parser.add_argument("--sample-size", type=int, default=500, help="Max samples per file (default: 500)")
    parser.add_argument("--output", type=str, default="benchmark_report.html", help="Output HTML file")
    args = parser.parse_args()

    print(f"Running benchmarks with sample_size={args.sample_size}...")

    print("  Running Python benchmark...")
    py = run_python_benchmark(args.sample_size)
    print(f"  Python done: {py['overall']['total_time_s']:.1f}s")

    print("  Running TypeScript benchmark...")
    ts = run_ts_benchmark(args.sample_size)
    print(f"  TypeScript done: {ts['overall']['total_time_s']:.1f}s")

    html = generate_html(py, ts)
    out_path = Path(args.output)
    out_path.write_text(html)
    print(f"\nReport written to {out_path.resolve()}")


if __name__ == "__main__":
    main()
