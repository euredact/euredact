#!/usr/bin/env python3
"""Forgejo issues for euRedact, routed to the repo that owns the component.

Stdlib only (Python 3.10+). Token: FORGEJO_TOKEN in the environment, else
~/.config/euredact/forgejo_token — a personal access token with write:issue, and write:repository
for `pr` (Forgejo > Settings > Applications). Server: FORGEJO_URL (default https://git.euredact.dev).

Repos (alias -> repo) and the component labels that route to them:
  rules      euredact/rules-engine              rules-engine
  pipeline   euredact/euredact-training-pipeline llm-tier, training-data, bundle
  inference  euredact/euredact-inference        gateway, dashboard, gpu, billing
  site       euredact/public-site               website
`create` derives the repo from the component label. Every other command takes --repo <alias>; when
it is omitted the alias is read from `git remote get-url origin` of the current checkout (list and
board without --repo cover every repo). FORGEJO_REPO=<owner/name> overrides everything.

Filing and reading:
  labels [--repo A]                                  ensure the label set exists, print it
  list [--repo A] [--state open|closed|all] [--label L ...] [--q text]
  get [--repo A] N                                   issue + comments
  create --title T --body-file F --label <component> [--label sev:...]
  comment [--repo A] N --body-file F
  update [--repo A] N [--state open|closed] [--title T] [--body-file F] [--label L ...]
Working the queue (the issue-queue skill):
  next [--repo A] [--json]                           open issues nobody is working, severity then age
  claim [--repo A] N [--steal]                       status:in-progress + claim marker comment
  release [--repo A] N --status triaged|blocked|needs-human|proposed [--body-file F]
  pr [--repo A] --head issue/N-slug --base main --title T --body-file F [--issue N]
  board [--state open|all] [--json]                  every repo: sev, status, age, claimant, PR
Global: --dry-run (or FORGEJO_DRY_RUN=1) prints every non-GET call instead of sending it.
Output is JSON on stdout (tables for next/board unless --json); errors on stderr, non-zero exit.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import socket
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
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
SEV_RANK = {"sev:leak": 0, "sev:mislabel": 1, "sev:over-redaction": 2, "sev:availability": 3, "sev:ux": 4}
STATUSES = ("triaged", "in-progress", "proposed", "blocked", "needs-human")
WAITING = {"status:in-progress", "status:proposed", "status:blocked", "status:needs-human"}
STALE_AFTER = timedelta(hours=24)
CLAIM_RE = re.compile(r"<!-- euredact-queue claim host=(?P<host>\S+) repo=(?P<repo>\S+) at=(?P<at>\S+) -->")
# name -> (colour, description). Component labels say WHERE, sev labels say WHAT KIND of failure,
# status labels say WHO HAS IT (at most one at a time).
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
    "status:triaged": ("#c5def5", "read; component, severity and evidence confirmed"),
    "status:in-progress": ("#0052cc", "claimed by a worker session (see the claim comment)"),
    "status:proposed": ("#5319e7", "a PR is open and green; waiting for a human to merge"),
    "status:blocked": ("#fbca04", "waiting on another issue or on missing evidence"),
    "status:needs-human": ("#d93f0b", "not reproducible, a judgement call, or a paid step (retrain, deploy)"),
}
DRY_RUN = False


def current_alias() -> str | None:
    """Alias of the checkout we are in, from the origin remote (ssh or https form)."""
    try:
        url = subprocess.run(["git", "remote", "get-url", "origin"], capture_output=True, text=True, timeout=10).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return None
    m = re.search(r"[:/]([^/:]+/[^/:]+?)(?:\.git)?/?$", url)
    if not m:
        return None
    full = m.group(1)
    return next((a for a, r in REPOS.items() if r == full), None)


def repo_for(alias: str | None, labels: list[str] | None = None) -> str:
    if os.environ.get("FORGEJO_REPO"):
        return os.environ["FORGEJO_REPO"]
    if alias:
        if alias not in REPOS:
            sys.exit(f"unknown repo alias {alias!r}; known: {sorted(REPOS)}")
        return REPOS[alias]
    if labels is not None:
        comps = [l for l in labels if l in COMPONENTS]
        if len(comps) != 1:
            sys.exit(f"exactly one component label decides the repo; got {comps or 'none'} (known: {sorted(COMPONENTS)})")
        return REPOS[COMPONENTS[comps[0]]]
    here = current_alias()
    if not here:
        sys.exit("no --repo and the current checkout's origin is not one of the euRedact repos; pass --repo " + "|".join(REPOS))
    return REPOS[here]


def token() -> str:
    t = os.environ.get("FORGEJO_TOKEN", "").strip()
    if not t:
        p = Path.home() / ".config" / "euredact" / "forgejo_token"
        if p.exists():
            t = p.read_text().strip()
    if not t:
        sys.exit("no token: set FORGEJO_TOKEN or write ~/.config/euredact/forgejo_token "
                 "(scopes: write:issue; write:repository for pr)")
    return t


def api(method: str, path: str, data=None, params=None, tolerate=(), quiet=False):
    url = f"{BASE}/api/v1{path}"
    if params:
        url += "?" + urllib.parse.urlencode({k: v for k, v in params.items() if v not in (None, "", [])}, doseq=True)
    if DRY_RUN and method != "GET":
        print(f"dry-run: {method} {path} {json.dumps(data, ensure_ascii=False)[:300] if data is not None else ''}", file=sys.stderr)
        return {"id": 0, "number": 0, "html_url": "dry-run", "labels": [], "title": "", "state": "open"}
    body = json.dumps(data).encode() if data is not None else None
    req = urllib.request.Request(url, data=body, method=method, headers={
        "Authorization": f"token {token()}", "Content-Type": "application/json", "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            raw = r.read()
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as e:
        if e.code in tolerate:
            if not quiet:
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


def names(issue: dict) -> list[str]:
    return [l["name"] for l in issue.get("labels", [])]


def status_of(issue: dict) -> str | None:
    return next((l for l in names(issue) if l.startswith("status:")), None)


def set_status(repo: str, issue: dict, status: str | None) -> list[str]:
    """Replace the single status:* label; every other label stays."""
    keep = [l for l in names(issue) if not l.startswith("status:")]
    new = keep + ([f"status:{status}"] if status else [])
    api("PUT", f"/repos/{repo}/issues/{issue['number']}/labels", {"labels": label_ids(repo, new)})
    return new


def slim(i: dict) -> dict:
    return {"repo": i.get("repository", {}).get("full_name"), "number": i["number"], "title": i["title"], "state": i["state"],
            "labels": names(i), "updated_at": i.get("updated_at"), "url": i.get("html_url"), "comments": i.get("comments")}


def parse_ts(s: str) -> datetime:
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def age(s: str) -> str:
    d = datetime.now(timezone.utc) - parse_ts(s)
    return f"{d.days}d" if d.days else f"{d.seconds // 3600}h"


def claims(comments: list[dict]) -> list[dict]:
    out = []
    for c in comments:
        m = CLAIM_RE.search(c.get("body") or "")
        if m:
            out.append({**m.groupdict(), "user": c["user"]["login"], "created_at": c["created_at"]})
    return out


def claim_state(repo: str, issue: dict, comments: list[dict] | None = None) -> dict:
    """Who holds the issue and whether the claim is stale (in-progress > 24 h with no later word)."""
    if comments is None:
        comments = api("GET", f"/repos/{repo}/issues/{issue['number']}/comments") or []
    cl = claims(comments)
    st = status_of(issue)
    if st != "status:in-progress" or not cl:
        return {"status": st, "claimant": cl[-1]["host"] if cl else None, "stale": False}
    last = cl[-1]
    later = [c for c in comments if c["created_at"] > last["created_at"] and c["user"]["login"] == last["user"]]
    since = parse_ts((later[-1] if later else comments[-1])["created_at"])
    return {"status": st, "claimant": last["host"], "at": last["at"],
            "stale": datetime.now(timezone.utc) - since > STALE_AFTER}


def open_issues(repo: str) -> list[dict]:
    rows = api("GET", f"/repos/{repo}/issues", params={"state": "open", "labels": "product", "type": "issues", "limit": 50},
               tolerate=(404,)) or []
    return sorted(rows, key=lambda i: (min((SEV_RANK.get(l, 9) for l in names(i)), default=9), i["created_at"]))


def sev(issue: dict) -> str:
    return next((l for l in names(issue) if l in SEV_RANK), "-")


def table(rows: list[list[str]], head: list[str]) -> str:
    w = [max(len(str(r[i])) for r in [head] + rows) for i in range(len(head))]
    fmt = lambda r: "  ".join(str(x).ljust(w[i]) for i, x in enumerate(r)).rstrip()
    return "\n".join([fmt(head)] + [fmt(r) for r in rows]) if rows else "(nothing)"


def main(argv=None) -> int:
    global DRY_RUN
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dry-run", action="store_true")
    sub = ap.add_subparsers(dest="cmd", required=True)
    R = dict(choices=sorted(REPOS))
    p = sub.add_parser("labels"); p.add_argument("--repo", **R)
    p = sub.add_parser("list"); p.add_argument("--repo", **R)
    p.add_argument("--state", default="open", choices=["open", "closed", "all"])
    p.add_argument("--label", action="append", default=[]); p.add_argument("--q", default="")
    p = sub.add_parser("get"); p.add_argument("--repo", **R); p.add_argument("number", type=int)
    p = sub.add_parser("create"); p.add_argument("--title", required=True); p.add_argument("--body-file", required=True)
    p.add_argument("--label", action="append", default=[])
    p = sub.add_parser("comment"); p.add_argument("--repo", **R); p.add_argument("number", type=int)
    p.add_argument("--body-file", required=True)
    p = sub.add_parser("update"); p.add_argument("--repo", **R); p.add_argument("number", type=int)
    p.add_argument("--state", choices=["open", "closed"]); p.add_argument("--title"); p.add_argument("--body-file")
    p.add_argument("--label", action="append", default=[])
    p = sub.add_parser("next"); p.add_argument("--repo", **R); p.add_argument("--json", action="store_true")
    p = sub.add_parser("claim"); p.add_argument("--repo", **R); p.add_argument("number", type=int)
    p.add_argument("--steal", action="store_true")
    p = sub.add_parser("release"); p.add_argument("--repo", **R); p.add_argument("number", type=int)
    p.add_argument("--status", required=True, choices=STATUSES); p.add_argument("--body-file")
    p = sub.add_parser("pr"); p.add_argument("--repo", **R); p.add_argument("--head", required=True)
    p.add_argument("--base", default="main"); p.add_argument("--title", required=True); p.add_argument("--body-file", required=True)
    p.add_argument("--issue", type=int)
    p = sub.add_parser("board"); p.add_argument("--state", default="open", choices=["open", "all"]); p.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    DRY_RUN = a.dry_run or os.environ.get("FORGEJO_DRY_RUN") == "1"
    host = socket.gethostname().split(".")[0]

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
        print(json.dumps({**slim(i), "body": i.get("body"), "claim": claim_state(r, i, c),
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
    elif a.cmd == "next":
        r = repo_for(a.repo)
        rows = []
        for i in open_issues(r):
            st = status_of(i)
            if st in WAITING:
                if st != "status:in-progress":
                    continue
                cs = claim_state(r, i)
                if not cs["stale"]:
                    continue
                rows.append({**slim(i), "sev": sev(i), "status": "stale:" + (cs["claimant"] or "?"), "age": age(i["created_at"])})
            else:
                rows.append({**slim(i), "sev": sev(i), "status": st or "-", "age": age(i["created_at"])})
        print(json.dumps(rows, indent=1, ensure_ascii=False) if a.json else
              table([[x["number"], x["sev"], x["status"], x["age"], x["title"][:90]] for x in rows], ["#", "sev", "status", "age", "title"]))
    elif a.cmd == "claim":
        r = repo_for(a.repo)
        i = api("GET", f"/repos/{r}/issues/{a.number}")
        if i.get("state") != "open":
            sys.exit(f"#{a.number} is {i.get('state')}")
        cs = claim_state(r, i)
        if cs["status"] in WAITING and not (cs["status"] == "status:in-progress" and cs["stale"] and a.steal):
            sys.exit(f"#{a.number} is {cs['status']} (claimant {cs.get('claimant')}, stale={cs['stale']}); "
                     + ("use --steal" if cs["status"] == "status:in-progress" and cs["stale"] else "leave it"))
        at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        alias = next(k for k, v in REPOS.items() if v == r) if r in REPOS.values() else r
        set_status(r, i, "in-progress")
        note = (f"<!-- euredact-queue claim host={host} repo={alias} at={at} -->\n"
                f"Claimed by the {alias} worker session on {host}. Reproducing."
                + (f"\n\nTook over a stale claim by {cs.get('claimant')} (from {cs.get('at')})." if a.steal else ""))
        api("POST", f"/repos/{r}/issues/{a.number}/comments", {"body": note})
        # no compare-and-set on Forgejo: if someone else's live claim landed first, yield
        others = [c for c in claims(api("GET", f"/repos/{r}/issues/{a.number}/comments") or [])
                  if c["host"] != host and c["at"] > (cs.get("at") or "") and c["at"] < at]
        if others and not DRY_RUN:
            set_status(r, i, "in-progress")
            api("POST", f"/repos/{r}/issues/{a.number}/comments", {"body": f"Yielded to the claim from {others[-1]['host']} ({others[-1]['at']})."})
            sys.exit(f"#{a.number}: yielded to {others[-1]['host']}; pick the next issue")
        print(json.dumps({"repo": r, "number": a.number, "status": "status:in-progress", "host": host, "at": at}, indent=1))
    elif a.cmd == "release":
        r = repo_for(a.repo)
        i = api("GET", f"/repos/{r}/issues/{a.number}")
        if a.body_file:
            api("POST", f"/repos/{r}/issues/{a.number}/comments", {"body": Path(a.body_file).read_text(encoding="utf-8")})
        new = set_status(r, i, a.status)
        print(json.dumps({"repo": r, "number": a.number, "labels": new}, indent=1))
    elif a.cmd == "pr":
        r = repo_for(a.repo)
        if not re.match(r"^issue/\d+-", a.head):
            sys.exit(f"head must be an issue/<N>-<slug> branch, got {a.head!r}")
        body = Path(a.body_file).read_text(encoding="utf-8")
        if a.issue and not re.search(r"\b(?:Closes|Fixes|Resolves)\b", body):
            body += f"\n\nCloses {r}#{a.issue}"
        pr = api("POST", f"/repos/{r}/pulls", {"head": a.head, "base": a.base, "title": a.title, "body": body}, tolerate=(409,))
        if pr is None:
            existing = api("GET", f"/repos/{r}/pulls", params={"state": "open", "limit": 50}, tolerate=(403,), quiet=True) or []
            hit = next((x for x in existing if x.get("head", {}).get("ref") == a.head), None)
            print(json.dumps({"repo": r, "head": a.head, "existing": hit.get("html_url") if hit else None,
                              "note": "a PR for this head already exists"}, indent=1))
            return 1
        print(json.dumps({"repo": r, "number": pr.get("number"), "url": pr.get("html_url"), "head": a.head}, indent=1))
    elif a.cmd == "board":
        rows = []
        for alias, r in REPOS.items():
            issues = api("GET", f"/repos/{r}/issues", params={"state": a.state, "labels": "product", "type": "issues", "limit": 50},
                         tolerate=(404,)) or []
            pulls = api("GET", f"/repos/{r}/pulls", params={"state": "open", "limit": 50}, tolerate=(403, 404), quiet=True) or []
            by_head = {}
            for pu in pulls:
                m = re.match(r"issue/(\d+)-", pu.get("head", {}).get("ref") or "")
                if m:
                    by_head[int(m.group(1))] = pu.get("html_url")
            for i in sorted(issues, key=lambda i: (min((SEV_RANK.get(l, 9) for l in names(i)), default=9), i["created_at"])):
                comments = api("GET", f"/repos/{r}/issues/{i['number']}/comments") or [] if i.get("comments") else []
                cs = claim_state(r, i, comments)
                pr = by_head.get(i["number"]) or next((m.group(0) for c in reversed(comments)
                                                        for m in [re.search(r"https?://\S+/pulls/\d+", c.get("body") or "")] if m), "")
                rows.append({"repo": alias, "number": i["number"], "state": i["state"], "sev": sev(i),
                             "status": (status_of(i) or "-") + (" (stale)" if cs["stale"] else ""),
                             "age": age(i["created_at"]), "claimant": cs.get("claimant") or "", "pr": pr, "title": i["title"]})
        print(json.dumps(rows, indent=1, ensure_ascii=False) if a.json else
              table([[x["repo"], x["number"], x["state"][:4], x["sev"], x["status"], x["age"], x["claimant"], x["pr"], x["title"][:70]] for x in rows],
                    ["repo", "#", "st", "sev", "status", "age", "claimant", "pr", "title"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
