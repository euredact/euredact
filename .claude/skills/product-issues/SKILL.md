---
name: product-issues
description: File, look up and update Forgejo issues for euRedact defects and problems, routed to the repo that owns the component — rules engine, LLM tier / training data / bundles, inference gateway / dashboards / GPU / billing, public website. Use whenever such a problem is found or discussed, whenever the user asks what issues are open, and whenever a known issue is fixed, confirmed or contradicted by new evidence.
---

# euRedact issues on Forgejo

Tool: `.claude/skills/product-issues/forgejo_issues.py` (stdlib only, Python 3.10+; run with `python3`). The same
skill is checked into every euRedact repo; the copy you run does not decide where an issue goes —
the component does.
Token: `FORGEJO_TOKEN` in the environment or `~/.config/euredact/forgejo_token` — a Forgejo personal
access token with issue write scope. Never print it, never write it into a repo, never pass it on
the command line. If it is missing, say so and stop; do not ask the user to paste it into chat.

## Which repo

| component label | goes to | covers |
|---|---|---|
| `rules-engine` | `euredact/rules-engine` | the `euredact` package: regex patterns, suppressors, type assignment, engine versions and their regressions (`conformance/`) |
| `llm-tier` | `euredact/euredact-training-pipeline` | a shipped or candidate model's behaviour: type confusions, under-labelled genres, runaway generation, prompt/format contract |
| `training-data` | `euredact/euredact-training-pipeline` | corpus, gold labels, canon (`prompts/pii_definitions.md`), rulings, splits |
| `bundle` | `euredact/euredact-training-pipeline` | a published `s3://euredact-models/...` artifact: manifest, template, weights, sums |
| `gateway` | `euredact/euredact-inference` | admission, prompt-hash checks, serving parameters, post-processing, latency, throughput, outages |
| `dashboard` | `euredact/euredact-inference` | admin console and customer dashboard |
| `gpu` | `euredact/euredact-inference` | GPU rental, box bootstrap, deploy and worker code |
| `billing` | `euredact/euredact-inference` | plans, invoices, Mollie |
| `website` | `euredact/public-site` | euredact.dev |

Exactly one component per issue; `create` refuses otherwise. A problem that spans two components is
two issues that link each other (`euredact/rules-engine#4`, `euredact/euredact-inference#12` — Forgejo
cross-references across repos with `owner/repo#N`). Not tracked here: the training dashboard, eval
harness, controllers and scripts of the training pipeline itself — those are commits and docs.

Grey areas, decided:
- A gold error becomes a `llm-tier` issue only once it has demonstrably taught the model something
  wrong (file the behaviour, link the ruling); until then it is `training-data`.
- The rules engine masking something it should not (years as POSTAL_CODE, `CURRICULUM` as
  NATIONAL_ID) is `rules-engine` even when it was found through the corpus.
- Throughput or truncation seen in the eval harness is `llm-tier` if the model does it and
  `gateway` if the serving stack does it (timeouts, admission, wrong `max_tokens`).

## Before filing

1. `list --state all --q "<key words>"` (all repos) and `list --repo <alias> --label <component>`;
   search by the symptom: type names, engine version, the masked token, the endpoint. Read hits with
   `get --repo <alias> N`.
2. If an issue exists: `comment --repo <alias> N --body-file` with the new evidence; `update` labels
   or state if they changed. Do not open a duplicate.
3. Only then create.

## Issue format

Title: `<component>: <symptom in one line>` — `rules-engine: years inside dates masked as POSTAL_CODE (0.3.2+)`,
`gateway: 413 admission counts the system prompt twice`, `website: pricing page 404 on /nl`.

Body (markdown, written to a temp file under `$CLAUDE_JOB_DIR/tmp` or the OS temp dir, then `--body-file`):

```
## Symptom
What happens, one paragraph, with a verbatim minimal example (synthetic values only).

## Expected
What the canon / spec / contract says (quote it: pii_definitions.md section, API contract, design doc).

## Evidence
- versions: euredact x.y.z / adapter name / bundle version / commit / browser
- where measured: eval run id, split + row indices, log excerpt, request id, counts (n of N)
- links: doc or ruling in the repo, S3 prefix, run id, cross-referenced issues

## Impact
sev and who is affected (GDPR tier and types for data issues; customers/plans for gateway, dashboard, billing).

## Suspected cause
Only if verified or strongly indicated; otherwise "unknown".

## Workaround / status
```

Labels: `product` is added automatically; pass one component and one severity — `sev:leak` (PII
unredacted in the output), `sev:mislabel` (redacted under the wrong type), `sev:over-redaction`
(non-PII redacted), `sev:availability` (errors, truncations, timeouts, outages), `sev:ux` (wrong or
confusing, no data impact). `labels` creates the set in a repo on first use.

Rules: synthetic corpus values only — never customer data, never secrets, never live hostnames or
tokens. Numbers come from a run, a log or a count, not from memory. One defect per issue; a pattern
with several examples is one issue with a list.

## Updating

- New evidence, a retrain, a bundle, a deploy: `comment` with the version and the number.
- Fixed and verified (a run, a conformance test, a deploy): closing comment naming the fix (engine
  version, adapter, bundle prefix, commit), then `update --state closed`.
- Wrong severity/component: `update --label product --label <component> --label <sev>` — the label
  set is replaced, list all of them. Changing the component does not move the issue; close it with a
  pointer and file it in the right repo.
- Reopen with `--state open` plus a comment when a fixed issue comes back.

## Commands

```bash
P=python3; S=.claude/skills/product-issues/forgejo_issues.py
$P $S labels                              # every repo
$P $S list --state all --q "POSTAL_CODE"  # every repo
$P $S list --repo inference --label gateway
$P $S get --repo pipeline 1
$P $S create --title "gateway: ..." --body-file /tmp/issue.md --label gateway --label sev:availability
$P $S comment --repo rules 4 --body-file /tmp/note.md
$P $S update --repo rules 4 --state closed
```

Report back with repo, issue number, URL and the one-line title; do not paste the body back.
