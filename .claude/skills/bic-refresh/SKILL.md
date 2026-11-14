---
name: bic-refresh
description: Refresh the bundled GLEIF BIC list (bic_gleif.py / bicGleif.ts and the SWIFT notice) to the latest BIC-to-LEI mapping, with a diff report of additions, removals, renames and flapping prefixes, regression vectors and the corpus checks, as an issue/<N> branch and PR. Run it before every quarterly 1.x.0 release (February, May, August, November), and whenever asked to update, check or refresh the BIC list.
---

# Refreshing the bundled BIC list

Both SDKs bundle about 10,400 BIC6 prefixes (institution + country) for the
engine's 31 countries, generated from GLEIF's BIC-to-LEI mapping. GLEIF
publishes it monthly, near the end of the month. We refresh **once a quarter, before every
`1.x.0`** (see the release skill's *1.x rhythm*), so each minor release ships a
list at most a month old. Patch releases do not refresh, unless the owner asks.

The refresh is its own issue and PR, merged **before** the release commit, so
the release's `make verify` measures the list it ships.

## What the list decides, and why removals are not alarming

The list is consulted in one place: `is_known_institution` (rules-engine#57).
A **letters-only** code beside an IBAN, with no `BIC:`/`SWIFT` label
(`OPENDEFF`, `REVOATWW`), is masked only when the list knows the institution.
Everything else ignores the list:
- a labelled code;
- a code with a digit (`SWEDGB21`);
- an 11-character code ending in `XXX`;
- the hand-kept seed list that licenses a code in bare prose (`SEED_BIC6_PREFIXES`).

So a prefix matters only if one of its BICs is letters-only in its first
eight characters, and a removal can only stop that one bare case. The report
marks those prefixes.

**We follow GLEIF exactly, removals included** (decided 2026-11-14, #161). The
SWIFT notice must name the one mapping version the list was built from, and a
union across months would make it untrue. Do not keep removed prefixes, or add
prefixes by hand, without the owner's say-so.

## 1. Issue and worktree

File and claim the issue with the `product-issues` / `issue-queue` scripts:

```bash
I=.claude/skills/product-issues/forgejo_issues.py
python3 $I create --label rules-engine --body-file F \
  --title "rules-engine: refresh the bundled GLEIF BIC list to the <Month YYYY> mapping"
python3 $I claim N
git fetch origin && git worktree add "$HOME/.cache/euredact/worktrees/rules/issue-N-refresh-bic-list" \
  -b issue/N-refresh-bic-list origin/main
```

The body follows the product-issues format. Its Evidence section is the
report of step 2.

## 2. The report

```bash
D=<scratchpad>/gleif-$(date +%Y%m%d)       # its own, empty directory
python3 -I scripts/bic_mapping_diff.py --dir "$D"
```

It downloads, into `$D` only, the file the bundled list was built from and every
file published since. It prints a Markdown report and saves it as
`$D/report.md`. Downloads are data: keep them out of the repository, and run
the scripts with `-I`. If it says the bundled list is the latest file, comment
that on the issue, release it as `needs-human` so a human closes it, and stop.

Read the report before changing anything. **Stop and ask the owner** (issue to
`needs-human`, the report in the comment) if:
- it opens with *"The bundled list is not …'s file"*: someone edited the
  generated module, or it was built from another file;
- the prefix total moves by more than 2% (about 200), or one country loses
  more than a tenth of its prefixes. That is a GLEIF format or scope change,
  not churn;
- a well-known bank's letters-only code is removed **and** its LEI did not
  move to another BIC (column *its LEI now under* is `—`).

Normal churn, for comparison: September → October 2026 added 35 prefixes and
removed 37, of which 13 and 4 were letters-only. Several removals were renames:
`SCFBES` → `OPENES`/`OPENDE`, `UIREDE` → `DIFODE`. `ABGRDE` and `PIRBGR` were out
for one month and back, which the report shows as *In and out between the two*.

## 3. Regenerate

```bash
python3 -I scripts/refresh_bic_registry.py "$D/LEI-BIC-<latest>.zip"
```

This rewrites `euredact-python/src/euredact/rules/bic_gleif.py`,
`euredact-ts/src/rules/bicGleif.ts` and both `NOTICE` files, with the notice
dated from the file. Never edit them by hand. Check:

```bash
git diff --stat      # exactly those four files
grep -m1 'database rights' euredact-python/NOTICE euredact-ts/NOTICE
```

Both SDKs must load the same set: compare `bic6_prefixes()` from Python with
`bic6Prefixes()` from TypeScript. #161 found them identical; anything else is
a generator bug.

## 4. Vectors

Add two or three conformance vectors, `bic-gleif-<month>-<slug>`, for
letters-only **additions** the report marks. Each places the code bare beside
an IBAN, in the country's language, and expects it under `BIC`:

```json
{"id": "bic-gleif-october-openbank-letters-only",
 "text": "Überweisung an DE89 3704 0044 0532 0130 00, OPENDEFF, Verwendungszweck Miete",
 "countries": ["DE"], "mustDetect": {"BIC": ["OPENDEFF"]},
 "notes": "rules-engine#N: an institution the <Month YYYY> GLEIF mapping added. ..."}
```

Use the standard documentation IBANs (`DE89 3704 0044 0532 0130 00`,
`AT61 1904 3002 3457 3201`, `ES91 2100 0418 4502 0005 1332`), never one from
the corpus. Each vector must **fail on `origin/main` in both SDKs** and pass on
the branch. Check both before committing.

An older `bic-gleif-*` vector that now fails means GLEIF dropped that
institution. Confirm it in the report:
- if its LEI moved, point the vector at the successor code;
- otherwise use another letters-only addition.

Say which in the PR. Never weaken the vector to expect nothing.

## 5. Docs and changelogs

- **Prefix count:** the docs say "about 10,400". Grep for it in both READMEs,
  `bic_registry.py`, `bicRegistry.ts` and `suppressors.py`, and change it only
  when the figure rounded to the nearest hundred changes. Released changelog
  entries keep their numbers.
- **Package changelogs:** a `### Changed` entry under `## Unreleased` in both:
  - old → new prefix totals, with the counts added and removed;
  - how many of each are letters-only;
  - two or three codes now masked;
  - the letters-only removals, and that they behave like any unlisted bank;
  - the notice month.
- **Root changelog:** one line under `## [Unreleased]`, `### Changed`.

## 6. Checks

```bash
make check && make conformance
make sweep && make parity && make eval    # the list feeds a suppressor
```

Compare the eval with `origin/main`'s, measured the same way. It is usually
identical, because the corpus has few bare letters-only codes. Any change in
`BIC` precision or recall goes in the PR, by type.

## 7. Commit, PR, issue

Do this as the issue-queue skill says:
- **Commit:** as the bot, with the subject
  `issue-N: refresh the bundled GLEIF BIC list to the <Month YYYY> mapping`.
- **Push:** `issue/N-refresh-bic-list`.
- **PR:** the body carries the report's count table, the letters-only
  additions and removals, the renames, the vectors and the check results.
- **Issue comment:** in the issue-queue format, then status `proposed`.
- **Worktree:** remove it.

Tell the owner the PR must merge before the release commit. If other open
PRs add `### Changed` to the Unreleased changelogs, whichever merges second
has a small changelog conflict.
