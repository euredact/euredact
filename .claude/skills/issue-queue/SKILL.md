---
name: issue-queue
description: Work the Forgejo issue queue from the repo this session is in — take the next open euRedact issue routed to this repo, triage it, reproduce it, and propose a fix as an issue/<N>-<slug> branch with a regression test and a PR; a human merges and closes. Use when asked to "work the queue", "take the next issue", "pick up #N", or to report the board. Never merges, never pushes main, never launches training or a deploy.
---

# Working the issue queue

One queue (the Forgejo tracker, routed by component label), one worker per repo: this skill acts only
on the repo whose checkout it runs in, detected from `git remote get-url origin`. The script:
`.claude/skills/product-issues/forgejo_issues.py` (`python3`, stdlib). Token: `FORGEJO_TOKEN` or
`~/.config/euredact/forgejo_token` — the **bot account's** token (`write:issue`, `write:repository`,
`read:user`); everything the worker files, comments, claims (it becomes assignee), pushes and opens
is attributed to the bot, not to the person running the session. If the token is missing, stop and
say so.
Filing and format rules live in the `product-issues` skill; this skill is about working what is filed.

```bash
S=.claude/skills/product-issues/forgejo_issues.py
python3 $S board                     # every repo: sev, status, age, claimant, PR
python3 $S next                      # this repo's unclaimed issues, severity then age
python3 $S get N                     # body, comments, claim state
python3 $S claim N [--steal]         # status:in-progress + claim comment; --steal only for a stale claim
python3 $S release N --status triaged|blocked|needs-human|proposed [--body-file F]
python3 $S pr --head issue/N-slug --title "..." --body-file F --issue N
```
`--dry-run` before any of the writing commands prints the API calls instead of sending them.

## Status labels (one at a time)

| label | means | `next` shows it? |
|---|---|---|
| *(none)* / `status:triaged` | open, nobody on it | yes |
| `status:in-progress` | a worker holds it (claim comment says who, since when) | only when stale (>24 h without a word from the claimant) |
| `status:proposed` | PR open and green; waiting for a human | no |
| `status:blocked` | waiting on another issue or on evidence | no |
| `status:needs-human` | not reproducible, judgement call, or a paid step | no |

## Procedure

1. `next`; take the top row (or the issue the user named). `get` it; read the docs, rulings or code it
   links in this repo. If the component does not belong here, do not claim — comment and stop.
2. **Triage.** Evidence must name a version (engine / adapter / bundle / commit), a minimal example
   with synthetic values, and counts. Missing → comment listing exactly what is missing,
   `release N --status blocked`, next issue. Sufficient → `release N --status triaged` is implicit in
   the claim; go on.
3. `claim N`. If it yields (someone else's claim landed first), take the next issue.
4. Worktree **outside iCloud**:
   `git fetch origin && git worktree add "$HOME/.cache/euredact/worktrees/<alias>/issue-<N>-<slug>" -b issue/<N>-<slug> origin/main`
   (if `origin/issue/<N>-<slug>` exists from an earlier attempt, check that out instead). Slug: 3–5
   kebab words from the title. All work happens in the worktree; the main checkout is not touched.
5. **Reproduce first.** The reproduction becomes the regression test (per repo, below) and must
   fail before the fix. Not reproducible → comment with what was tried (commands, versions, output),
   `release N --status needs-human`, remove the worktree, nothing pushed.
6. **Minimal fix.** Docs, changelog and canon in the same change when behaviour changes. Never weaken
   or skip a test.
7. **Repo check** (below) must be green. Red → nothing pushed; comment with the failing tests and
   what the diff does, `release N --status needs-human`.
8. Commit only the intended files, **as the bot account** — `python3 $S whoami` gives its login and
   mail; commit with `git -c user.name=<login> -c user.email=<mail> commit ...` so branch history says
   the bot proposed and a human merged. Subject `issue-<N>: <symptom>`, body with the cause and the
   check run, the usual `Co-Authored-By` trailer, last line `Closes euredact/<repo>#<N>`.
   `git push -u origin issue/<N>-<slug>` — only that branch, never `main`.
9. `pr --head issue/<N>-<slug> --title "issue-<N>: ..." --body-file <f> --issue N`. Body: reproduction,
   what changed, the check output summary, what was **not** run (deploys, retrains), and the closing
   line. A 403 here means the token lacks `write:repository`: comment with the branch name and
   `release N --status needs-human` so a human opens the PR.
10. **Write the issue comment** (below), `release N --status proposed`, `git worktree remove` (the
    branch stays on origin). Report: repo, issue, PR URL, one line.

## The issue comment is the record

The issue is what a reader opens first; the PR is where the diff lives. Every worked issue gets one
comment, written for someone who has not seen the PR, with these headings, each a short paragraph
with the actual numbers, file paths, commands and versions — never a one-liner pointing at the PR:

```
## Root cause
What produces the symptom, traced to the file / pattern / ruling / data, and why it does so. Quote the
offending line or rule. Say what was ruled out if that mattered.

## Reproduction
The exact command or test that shows it, with its output before the fix, and the count (n of N).

## What was done
Each change and the reason for it: file, what moved, why that and not the alternative. Regression
test or conformance vector by name. Anything deliberately left unchanged, and why.

## Verification
The check commands and their results (numbers), what the regression test asserts, what was not run.

## Left for a human
Merge, release, retrain, deploy, decisions — with the cost or risk of each.

PR: <url>
```

The same structure, with "What was tried" instead of "What was done", is the comment for
`needs-human` and not-reproducible outcomes. A `blocked` comment names exactly what is missing.

Work one issue at a time. Do not close issues; do not merge; do not deploy; do not start training or
publish a bundle — those are the human's steps and they cost money or reach customers.

## Per repo: reproduce, regression, fix, check

**rules** (`Codebase`, package `euredact-python/`, mirror `euredact-ts/`)
- Reproduce: `cd euredact-python && PYTHONPATH=src .venv/bin/python -c 'from euredact import redact; print(redact(TEXT, countries=[C]).redacted_text)'`
  with the issue's example; also on the installed release if the issue names a version.
- Regression: a case in `conformance/vectors.json` (both SDKs run it); a focused pytest in
  `euredact-python/tests/` only when a vector cannot express it (e.g. out-of-scope detections masking).
- Fix in `euredact-python/src/euredact/` **and** the TypeScript mirror in `euredact-ts/src/` (parity is tested).
- Check: `make check && make conformance`; `make sweep` too if ranking or suppression changed.
- `## Unreleased` entry in both `CHANGELOG.md`s. Never run the `release` skill from here; the PR body
  says "release via the release skill after merge".

**pipeline** (`euredact-training-pipeline`)
- `training-data` / `bundle`: reproduce by querying `output/v6/*.jsonl` for the rows the issue names
  (counts must match); for a bundle, `scripts/fetch_bundle.py` + the manifest. Proposal = a
  `scripts/apply_<slug>.py` with `--dry-run/--apply`, a `output/v6/ruling-<date>-<slug>.json` in the
  existing ruling format, and the canon edit in `prompts/pii_definitions.md` when the canon is wrong.
- `llm-tier`: reproduce in the eval run the issue names (exported rows under the job tmp dir, or the
  VPS `pipeline.db`), then locate the training-data cause. Proposal = the corpus/canon change above
  **plus** a `## Retrain recommendation` in the PR (adapter, recipe, estimated cost, which split proves
  it). The worker never launches training. A model-side availability problem may instead become a
  linked `gateway` issue.
- Check: `.venv/bin/python -m pytest -q`, `.venv/bin/python scripts/validate_canon.py`,
  `.venv/bin/python scripts/verify_rulings_applied.py output/v6`, and `scripts/validate_corpus.py` on
  every split the ruling touched.

**inference** (`Inference Stack`)
- Reproduce with a pytest through the existing fixtures (`tests/conftest.py`, `tests/fixtures/`);
  prompt-contract cases in `conformance/prompt_render_cases.json`.
- The `.venv` is an editable install of the main checkout: in the worktree run
  `PYTHONPATH="$PWD" ... python -c "import euredact_inference; print(euredact_inference.__file__)"` and
  confirm the worktree path before trusting any test.
- Check: `createdb euredact_issue_<N>`; `PYTHONPATH="$PWD" EUREDACT_REQUIRE_DB=1 EUREDACT_TEST_DSN=postgresql:///euredact_issue_<N> <main>/.venv/bin/python -m pytest tests/ -q`; `dropdb euredact_issue_<N>`.
- Pushing the branch runs `test.yml`; `deploy.yml` is dispatch-only and the PR body says it was not run.

**site** (`Euredact-website`, app in `site/`)
- Reproduce: `cd site && npm ci && npm run build`, plus a `node --test` case in `site/tests/` (pattern
  `claims.test.mjs`) or a grep of `site/out/` for rendering issues.
- Check: `cd site && npm test && npm run build`. Deploy runs only on `main`; a branch is safe.

## Cross-repo and other cases

- Needs a change in another repo: file the linked issue there with `product-issues` (`create` routes
  by component), comment `euredact/<repo>#M` on this one, `release N --status blocked`. Do not switch
  repos.
- Wrong component for this repo: comment and stop; do not relabel across repos (close-and-refile is
  the human's call).
- Retry after a previous session: reuse `origin/issue/<N>-<slug>`; `pr` reports an existing PR instead
  of opening a second one.
- The claim went stale (a session died): `next` flags it; `claim N --steal` records the takeover.

When reporting to the user: repo, issue number, what was reproduced, the PR URL or the status set, in
a few lines. Do not paste issue bodies back.
