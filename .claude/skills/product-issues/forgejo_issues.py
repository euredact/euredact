#!/usr/bin/env python3
"""Forgejo issues for euRedact, routed to the repo that owns the component.

Stdlib only. Token: FORGEJO_TOKEN in the environment, else ~/.config/euredact/forgejo_token
(a personal access token with issue write scope, created in Forgejo > Settings > Applications).
Server: FORGEJO_URL (default https://git.euredact.dev).

Repos (alias -> repo) and the component labels that route to them:
  rules      euredact/rules-engine              rules-engine
  pipeline   euredact/euredact-training-pipeline llm-tier, training-data, bundle
  inference  euredact/euredact-inference        gateway, dashboard, gpu, billing
  site       euredact/public-site               website
`create` derives the repo from the component label; the other commands take --repo <alias>
(list without --repo searches every repo). FORGEJO_REPO=<owner/name> overrides everything.

  forgejo_issues.py labels [--repo A]                        ensure the label set exists, print it
  forgejo_issues.py list [--repo A] [--state open|closed|all] [--label L ...] [--q text]
  forgejo_issues.py get --repo A N                            issue + comments
  forgejo_issues.py create --title T --body-file F --label <component> [--label L ...]
  forgejo_issues.py comment --repo A N --body-file F
  forgejo_issues.py update --repo A N [--state open|closed] [--title T] [--body-file F] [--label L ...]
Output is JSON on stdout; errors on stderr with a non-zero exit.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

BASE = os.environ.get("FORGEJO_URL", "https://git.euredact.dev").rstrip("/")
REPOS = {
    "rules": "euredact/rules-engine",
    "pipeline": "euredact/euredact-training-pipeline",
    "inference": "euredact/euredact-inference",
    "site": "euredact/public-site",
}
# component label -> repo alias. One component per issue; it decides where the issue lives.
COMPONENTS = {
    "rules-engine": "rules",
    "llm-tier": "pipeline", "training-data": "pipeline", "bundle": "pipeline",
    "gateway": "inference", "dashboard": "inference", "gpu": "inference", "billing": "inference",
    "website": "site",
}
# name -> (colour, description). Component labels say WHERE, sev labels say WHAT KIND of failure.
LABELS = {
    "product": ("#0e8a16", "a defect customers can meet, as opposed to internal tooling"),
    "rules-engine": ("#1d76db", "euredact rules engine (regex/suppressor layer, engine versions)"),
    "llm-tier": ("#5319e7", "the fine-tuned model's behaviour (cloud tier)"),
    "training-data": ("#bfd4f2", "corpus, gold labels, canon, rulings"),
    "bundle": ("#c2e0c6", "a published model bundle (euredact_model.json, weights, template)"),
    "gateway": ("#fbca04", "inference gateway: admission, serving, post-processing, throughput"),
    "dashboard": ("#fef2c0", "admin and customer dashboards / console"),
    "gpu": ("#f7e0a0", "GPU rental, boxes, deploy and worker code"),
    "billing": ("#e4c9ff", "billing, plans, Mollie"),
    "website": ("#bfe5bf", "euredact.dev public site"),
    "sev:leak": ("#b60205", "PII reaches the output unredacted"),
    "sev:mislabel": ("#e99695", "PII is redacted but under the wrong type"),
    "sev:over-redaction": ("#f9d0c4", "non-PII is redacted"),
    "sev:availability": ("#d93f0b", "errors, truncations, timeouts, throughput, outages"),
    "sev:ux": ("#ededed", "wrong or confusing behaviour with no data impact"),
}


def repo_for(alias: str | None, labels: list[str] | None = None) -> str:
    if os.environ.get("FORGEJO_REPO"):
        return os.environ["FORGEJO_REPO"]
    if alias:
        if alias not in REPOS:
            sys.exit(f"unknown repo alias {alias!r}; known: {sorted(REPOS)}")
        return REPOS[alias]
    comps = [l for l in (labels or []) if l in COMPONENTS]
    if len(comps) != 1:
        sys.exit(f"exactly one component label decides the repo; got {comps or 'none'} (known: {sorted(COMPONENTS)})")
    return REPOS[COMPONENTS[comps[0]]]


def token() -> str:
    t = os.environ.get("FORGEJO_TOKEN", "").strip()
    if not t:
        p = Path.home() / ".config" / "euredact" / "forgejo_token"
        if p.exists():
            t = p.read_text().strip()
    if not t:
        sys.exit("no token: set FORGEJO_TOKEN or write ~/.config/euredact/forgejo_token")
    return t


def api(method: str, path: str, data=None, params=None, tolerate=()):
    url = f"{BASE}/api/v1{path}"
    if params:
        url += "?" + urllib.parse.urlencode({k: v for k, v in params.items() if v not in (None, "", [])}, doseq=True)
    body = json.dumps(data).encode() if data is not None else None
    req = urllib.request.Request(url, data=body, method=method, headers={
        "Authorization": f"token {token()}", "Content-Type": "application/json", "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            raw = r.read()
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as e:
        if e.code in tolerate:
            print(f"{method} {path} -> {e.code} (skipped)", file=sys.stderr)
            return None
        sys.exit(f"{method} {path} -> {e.code}: {e.read().decode()[:400]}")


def repo_labels(repo: str) -> dict[str, int]:
    out = {}
    page = 1
    while True:
        rows = api("GET", f"/repos/{repo}/labels", params={"page": page, "limit": 50})
        if not rows:
            break
        out.update({r["name"]: r["id"] for r in rows})
        page += 1
    return out


def ensure_labels(repo: str) -> dict[str, int]:
    have = repo_labels(repo)
    for name, (colour, desc) in LABELS.items():
        if name not in have:
            r = api("POST", f"/repos/{repo}/labels", {"name": name, "color": colour, "description": desc})
            have[name] = r["id"]
    return have


def label_ids(repo: str, names: list[str]) -> list[int]:
    have = ensure_labels(repo)
    unknown = [n for n in names if n not in have]
    if unknown:
        sys.exit(f"unknown label(s) {unknown}; known: {sorted(have)}")
    return [have[n] for n in names]


def slim(i: dict) -> dict:
    return {"repo": i.get("repository", {}).get("full_name"), "number": i["number"], "title": i["title"], "state": i["state"],
            "labels": [l["name"] for l in i.get("labels", [])], "updated_at": i.get("updated_at"),
            "url": i.get("html_url"), "comments": i.get("comments")}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("labels"); p.add_argument("--repo", choices=sorted(REPOS))
    p = sub.add_parser("list"); p.add_argument("--repo", choices=sorted(REPOS))
    p.add_argument("--state", default="open", choices=["open", "closed", "all"])
    p.add_argument("--label", action="append", default=[]); p.add_argument("--q", default="")
    p = sub.add_parser("get"); p.add_argument("--repo", required=True, choices=sorted(REPOS)); p.add_argument("number", type=int)
    p = sub.add_parser("create"); p.add_argument("--title", required=True); p.add_argument("--body-file", required=True)
    p.add_argument("--label", action="append", default=[])
    p = sub.add_parser("comment"); p.add_argument("--repo", required=True, choices=sorted(REPOS)); p.add_argument("number", type=int)
    p.add_argument("--body-file", required=True)
    p = sub.add_parser("update"); p.add_argument("--repo", required=True, choices=sorted(REPOS)); p.add_argument("number", type=int)
    p.add_argument("--state", choices=["open", "closed"]); p.add_argument("--title"); p.add_argument("--body-file")
    p.add_argument("--label", action="append", default=[])
    a = ap.parse_args(argv)

    if a.cmd == "labels":
        repos = [repo_for(a.repo)] if (a.repo or os.environ.get("FORGEJO_REPO")) else list(REPOS.values())
        print(json.dumps({r: ensure_labels(r) for r in repos}, indent=1))
    elif a.cmd == "list":
        repos = [repo_for(a.repo)] if (a.repo or os.environ.get("FORGEJO_REPO")) else list(REPOS.values())
        out = []
        for r in repos:
            rows = api("GET", f"/repos/{r}/issues", params={"state": a.state, "labels": ",".join(a.label), "q": a.q,
                                                            "type": "issues", "limit": 50}, tolerate=(404,))
            out += [slim(i) for i in (rows or [])]
        print(json.dumps(out, indent=1, ensure_ascii=False))
    elif a.cmd == "get":
        r = repo_for(a.repo)
        i = api("GET", f"/repos/{r}/issues/{a.number}")
        c = api("GET", f"/repos/{r}/issues/{a.number}/comments")
        print(json.dumps({**slim(i), "body": i.get("body"),
                          "comments_list": [{"created_at": x["created_at"], "user": x["user"]["login"], "body": x["body"]} for x in c]},
                         indent=1, ensure_ascii=False))
    elif a.cmd == "create":
        labels = list(a.label)
        if "product" not in labels:
            labels = ["product"] + labels
        r = repo_for(None, labels)
        body = Path(a.body_file).read_text(encoding="utf-8")
        i = api("POST", f"/repos/{r}/issues", {"title": a.title, "body": body, "labels": label_ids(r, labels)})
        print(json.dumps(slim(i), indent=1, ensure_ascii=False))
    elif a.cmd == "comment":
        r = repo_for(a.repo)
        c = api("POST", f"/repos/{r}/issues/{a.number}/comments", {"body": Path(a.body_file).read_text(encoding="utf-8")})
        print(json.dumps({"id": c["id"], "url": c.get("html_url")}, indent=1))
    elif a.cmd == "update":
        r = repo_for(a.repo)
        patch = {}
        if a.state: patch["state"] = a.state
        if a.title: patch["title"] = a.title
        if a.body_file: patch["body"] = Path(a.body_file).read_text(encoding="utf-8")
        if patch:
            api("PATCH", f"/repos/{r}/issues/{a.number}", patch)
        if a.label:
            api("PUT", f"/repos/{r}/issues/{a.number}/labels", {"labels": label_ids(r, a.label)})
        print(json.dumps(slim(api("GET", f"/repos/{r}/issues/{a.number}")), indent=1, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
