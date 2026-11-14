---
name: release
description: Cut a euRedact release — version bump, changelogs, verification, tag, publish to PyPI and npm, then tell the inference, pipeline and website streams by issue. Use whenever releasing, bumping a version, tagging, or fixing a failed publish run. The step order matters; releasing out of order is the cause of every publish failure this repo has had.
---

# Releasing euRedact

Two packages ship from this repo — `euredact-python` (PyPI) and `euredact-ts`
(npm) — from a single tag and a single GitHub Release. They must always carry
the same version number.

**The order below is not stylistic.** Every publish failure this repo has had
came from doing these steps out of order. Reasons are given inline so the
order survives contact with a hurry.

## Which version: the 1.x rhythm

From 1.0.0 (decided 2026-11-14) releases follow the README's
[Versioning](../../../README.md#versioning) section:

- **`1.x.0`, quarterly**, at the start of February, May, August and November:
  everything merged since the last minor release — new identifiers, countries,
  options, cloud features. A minor release always re-measures the accuracy
  figures on the release commit (step 3) and regenerates
  `docs/corpus-results.{json,md}`. Before it, refresh the bundled BIC list
  with the `bic-refresh` skill: its own issue and PR, merged before the
  release commit, so the release measures the list it ships.
- **`1.x.y`, whenever needed**: a fix for a value left unredacted
  (`sev:leak`) or for a broken release, as soon as it is merged and verified.
  Do not hold a leak fix for the quarter. A patch release carries only fixes:
  a new option or API waits for the next `1.x.0`. Its notes say whether the
  figures moved; re-measure if the fix touched ranking, suppression or
  validation.
- **API stability**: within 1.x nothing public is removed or renamed
  (functions, options, result fields, `EntityType` names, error classes). A
  deprecation warns from a minor release and is removed no earlier than 2.0.
  Detection changes are never breaking, but every one is in the changelog.
- **When unsure** whether a change is a fix or a feature, it is a feature,
  and waits for the quarter, unless it closes a leak.

## 0. Land any workflow changes on `main` first

If `.github/workflows/publish.yml` needs a change, push it **before** tagging.

A `release` event replays the workflow file from the commit the tag points at.
A fix pushed after the release is cut is invisible to that release, and
re-running the failed job will faithfully re-execute the *old* definition —
producing an identical failure that looks like the fix did not work.

## 1. Bump the version in all three places

```
euredact-python/pyproject.toml            version = "X.Y.Z"
euredact-python/src/euredact/__init__.py  __version__ = "X.Y.Z"
euredact-ts/package.json                  "version": "X.Y.Z"
```

Then let npm carry it into the lockfile, which otherwise keeps the old version:
`(cd euredact-ts && npm install --package-lock-only --ignore-scripts)`.

Verify none was missed:

```bash
grep -m1 '^version' euredact-python/pyproject.toml
grep -m1 '__version__' euredact-python/src/euredact/__init__.py
python3 -c "import json;print(json.load(open('euredact-ts/package.json'))['version'])"
python3 -c "import json;print(json.load(open('euredact-ts/package-lock.json'))['version'])"
```

## 2. Date the changelogs

Turn `## Unreleased` into `## X.Y.Z (YYYY-MM-DD)` in **both**
`euredact-python/CHANGELOG.md` and `euredact-ts/CHANGELOG.md`.

The root `CHANGELOG.md` is different (Keep a Changelog, held by
`tests/test_changelog.py`):
- keep `## [Unreleased]`, now empty, and add `## [X.Y.Z] - YYYY-MM-DD` beneath
  it with the entries;
- point the `[Unreleased]` link at `compare/vX.Y.Z...main`;
- add an `[X.Y.Z]` link to `compare/vPREV...vX.Y.Z`.

Quote only figures that reproduce. If accuracy numbers are cited, re-measure
them on the current ground truth rather than carrying forward an older run —
comparing a new engine against numbers measured on different labels is not a
comparison.

## 3. Run the checks locally before pushing

```bash
make verify RESULTS=docs/corpus-results
```

`make check` alone is only what CI runs — lint, both suites, conformance. It
does **not** cover the corpus, because the corpus lives outside the repository.
`make verify` adds the three that need it:

- **`make sweep`** — structural properties over 20,000 documents sampled
  evenly from both corpora (`SWEEP_LIMIT`; `make sweep-full` walks all
  ~187,000). This is where the ranking bugs live. `countries=["NL"]` turning
  the IP address `194.232.104.77` into a national ID and leaving `.77` in the
  output was found here; the twenty-document version in CI said nothing.
- **`make parity`** — do both SDKs mask the same characters? Conformance
  vectors pin named cases; this compares whole corpora. TypeScript was once
  leaving 19,014 characters unmasked that Python caught, and no vector showed it.
- **`make eval RESULTS=docs/corpus-results`** — recall and precision, and the
  per-type results file (`docs/corpus-results.json` and `.md`) that the
  Instructions for use on euredact.dev read. Commit both with the release, so
  the published figures are the released engine's (rules-engine#109), and a
  number quoted in the changelog is one that was just measured rather than
  carried forward.

If the corpus is not on this machine, the three corpus checks cannot run, and
`make check` is not a substitute. Say so before going further. Release only if
the owner says to, and record in the release commit that they were skipped.
Any figure quoted in the changelog then has not been re-measured, so say that
too. 0.6.0 went out this way.

Run `make verify` after any change to ranking, suppression or validation, not
just before a release. `ruff` alone has caught a real import-format error that
would otherwise have failed the release, so do not skip the fast half either.

## 4. Commit, push `main` to both remotes, check, *then* tag

There are two remotes and only one of them publishes. In this checkout `origin`
is **Forgejo**. `publish.yml`, the GitHub Release and both publish jobs run on
**GitHub**, and `git push origin` reaches nothing there.

```bash
GH=git@github.com:euredact/euredact.git   # the GitHub repo publish.yml runs in

git add -A && git commit                  # "Release X.Y.Z"
git push origin main
git push "$GH" HEAD:refs/heads/main

scripts/release_refs.sh vX.Y.Z            # GATE: must print "ok" before you tag

git tag -a vX.Y.Z -m "..."                # AFTER the commit and the gate, never before
git push origin vX.Y.Z
git push "$GH" refs/tags/vX.Y.Z

scripts/release_refs.sh vX.Y.Z --tagged   # GATE: must print "ok" before step 5
```

`scripts/release_refs.sh` is read-only. It refuses unless:
- the working tree is clean;
- `HEAD`, Forgejo `main` and GitHub `main` are the same commit;
- neither remote already has `vX.Y.Z` on another commit.

With `--tagged`, it also requires the tag on both remotes, on `HEAD`.
`GITHUB_REMOTE` / `FORGEJO_REMOTE` override the URLs, and
`tests/test_release_refs.py` replays the 0.6.0 failure against it.

**If it fails, stop.** Fix the remote it names and run it again. Do not tag
around it, and do not create the Release. It reads over anonymous HTTPS, so it
runs anywhere. Pushing to GitHub needs credentials: if this machine has none,
the pushes go from a machine that has them, such as the Forgejo box (see the
`release-github-remote` memory). The gate is then run again here.

Why both remotes and why this order:

- **0.6.0 was pushed to Forgejo only.** GitHub `main` was still on the 0.5.1
  commit. The GitHub Release then created its own `v0.6.0` there, and publish
  rebuilt 0.5.1. Both registries skipped it as already published, and the run
  reported **success**. Only step 6 showed nothing had shipped.
- **Tagging before the bump commit** produces a tag whose code still declares
  the previous version. The workflow builds the old version, and npm rejects it
  with `You cannot publish over the previously published versions`. That error
  reads as a workflow problem but is a tag-ordering problem.

If GitHub already has a wrong `vX.Y.Z`, for example one a Release created,
move it with `git push --force "$GH" refs/tags/vX.Y.Z`. Do that only when
nothing published from it, and ask first: it rewrites a published ref. Then
publish with `workflow_dispatch` on `main` (see *Recovering a failed publish*).

The publish workflow runs on GitHub, which receives `main` through Forgejo's
push mirror. Before tagging, check that GitHub's `main` is the release commit
(`git ls-remote https://github.com/euredact/euredact.git refs/heads/main`). If
it lags, look at the push mirror's last error in Forgejo (Settings →
Repository → Mirror settings) before anything else. For 0.7.1 it was GitHub
push protection (`GH013`) rejecting a checksum-valid GitHub token in a test
vector, and every push since had failed; the fix was a history rewrite
(rules-engine#132). `make check` now refuses such a token.

## 5. Create a GitHub Release, set as latest

`publish.yml` triggers on `release: [published]` — **a tag push alone publishes
nothing.** Create the Release only after `scripts/release_refs.sh vX.Y.Z --tagged`
printed `ok`. Create it from the existing tag and mark it latest. If the Release
form offers to *create* the tag, GitHub does not have it, and the new tag would
land on whatever GitHub `main` is. Stop and go back to step 4.

The release is not done when the Release exists, or when the run is green.
It is done when step 6 passes.

**Always hand over the release body as text in the reply, inside a fenced block
they can copy.** Not as an attachment, and not as "the changelog drops in" —
neither works:

- Attachments have silently failed to render more than once. The reply is the
  only delivery that is guaranteed to arrive.
- The changelogs are per package. There are two of them, they diverge, and
  neither is written as release notes for a repo that ships both SDKs. Pasting
  either one omits the other SDK's entries or credits a single-SDK change to
  both.

So: merge both changelogs into one body, mark any entry that applies to only one
SDK, drop the sections that belong in a changelog but not in release notes, and
paste it in the reply. Write it to `~/Desktop/` as well, as a convenience — but
the reply is the deliverable.

**Verify every claim in the body against the tagged commit before writing it.**
Run the assertions; do not transcribe prose forward from a previous release. A
known issue that no longer reproduces, or a figure measured on a different
sample, is exactly the kind of thing that survives a copy-paste.

## 6. Verify both registries actually served it

Metadata is not proof; install and exercise it.

```bash
curl -s https://registry.npmjs.org/euredact | python3 -c "import json,sys;print(json.load(sys.stdin)['dist-tags']['latest'])"
curl -s https://pypi.org/pypi/euredact/json | python3 -c "import json,sys;print(json.load(sys.stdin)['info']['version'])"
```

Both registries have a lagging surface, and both have caused a false alarm:

- npmjs.com's **web page** lags the registry by minutes. The registry API and
  `npm view` are authoritative.
- PyPI's **JSON API** (`/pypi/euredact/json`) is cached and has reported the
  *previous* version for minutes after a successful upload. The **simple
  index** is fresher:

  ```bash
  curl -s https://pypi.org/simple/euredact/ | grep -o 'euredact-X\.Y\.Z[^"#]*'
  ```

A stale version on either surface is not a failed publish. Confirm against the
publish run's job list before reacting: if `publish-python` succeeded, the
upload happened. `skip-existing: true` means a *genuinely* stale build also
reports success, so the version at the tag (step 4) is what rules that out.

The package size in the TypeScript README (*Package* table) is measured from
a clean build. Check it against what npm serves:
`npm view euredact@X.Y.Z dist.unpackedSize` and the tarball's byte count. If
they differ by more than rounding, file an issue (rules-engine#148).

Metadata of any kind is still not the final word — install and exercise the new
release's actual features, not just its version string. A correct
`__version__` on code that predates the feature would pass a version check and
fail a user.

## 7. Tell the other streams: one issue each

A release reaches customers through more than the registries. The gateway pins
the engine for its own rules pass, the training pipeline measures end to end
against it, and the website quotes its figures and documents its API. None of
them watches this repo, so **once step 6 passes**, file one issue per stream
with the `product-issues` skill. The release is not done until all three exist.

| stream | component label | `--repo` | what the issue asks for |
|---|---|---|---|
| inference stack | `gateway` | `inference` | bump `euredact[fast]==X.Y.Z` in `euredact-inference/pyproject.toml`, in a deploy of its own (the bundle's `euredact_version` is reported, not enforced); name every change its own code may see: types it keys on, what the rules pass now masks before the model, wire or error changes |
| training pipeline | `training-data` | `pipeline` | evaluation and type mapping follow the release; any end-to-end re-run waits for the gateway upgrade, or it measures the old engine; gold or generator gaps that rules-engine issues found |
| website | `website` | `site` | the figures from `docs/corpus-results.{json,md}` and the README's Accuracy section, as measured in step 3, with their conditions; type changes; upgrade notes; new API docs; version strings |

For each:

1. **Search first** (`list --repo <alias> --state open`). Link the stream's
   related issues instead of duplicating them; comment on one that already
   covers the release.
2. **Write it from the tagged commit**, in the `product-issues` format:
   - the version, the tag and the commit;
   - the changelog entries that touch that stream;
   - the figures from step 3, never carried forward;
   - for the gateway, the exact files and lines its code keys on.

   Mark what is a decision for that stream rather than a task. In 0.7.0 that
   was whether the HTTP API returns `CREDENTIAL` or `SECRET`.
3. **Order the dependencies.** The pipeline's re-run waits for the gateway
   upgrade; the website waits for the registries.
4. **Cross-link** the issues to each other, and comment them onto the
   rules-engine issues whose follow-ups wait on them.

The issues use synthetic values only, like every issue.

Why: after 0.6.0 the gateway stayed on its old pin while the fixes shipped,
and a v15 end-to-end run measured an engine the fixes never reached
(rules-engine#111: all 100 gateway-layer `DOB` mistypes reproduced on 0.6.0
and none on 0.7.0). For 0.7.0 the issues were filed by hand and serve as the
example: euredact/euredact-inference#120, euredact/euredact-training-pipeline#41,
euredact/public-site#25 (rules-engine#122).

## Recovering a failed publish

**Do not re-cut a release to pick up a fix.** Re-running a release run replays
the workflow from the tag's commit (see step 0).

- **Fix on `main`, then Actions → Publish → Run workflow → `main`.**
  `workflow_dispatch` uses the selected branch, so it picks up fixes and
  publishes whatever version that branch declares.
- **Use "Re-run failed jobs", never "Re-run all jobs"** — the latter re-runs
  the PyPI upload. `skip-existing: true` covers that now, but the narrower
  option is still correct.
- If the tag points at the wrong commit, moving it is reasonable *provided
  nothing published from it* — but it rewrites a published ref, so ask first.

### Reading npm publish errors

npm returns `E404` for anything credential-shaped, so the message is not
diagnostic on its own. Check in this order:

1. **Does the package exist and do we own it?**
   `curl -s https://registry.npmjs.org/euredact` — a 200 with our maintainer
   means the name is fine and it is an auth problem.
2. **Is the workflow the current one?** See step 0.
3. **Any other error text** — `cannot publish over the previously published
   versions` means auth *succeeded* and the version is stale. That is progress,
   not a regression.

Publishing uses **OIDC trusted publishing**, not `NPM_TOKEN`. It requires a
trusted publisher on npmjs.com (org `euredact`, repo `euredact`, workflow
`publish.yml`, environment `release`) and npm 11+, which is why the job
installs a pinned npm over the Node 20 default.

### Both publish jobs run in the `release` environment

They declare `environment: release` so a publish waits on that environment's
required reviewers — otherwise anyone with repo write could ship to both
registries unreviewed, including via `workflow_dispatch` from any branch.

This only works if all three sides agree, and a publish **fails closed** until
they do:

1. A repository environment named `release` exists (Settings → Environments)
   with reviewers configured.
2. The PyPI trusted publisher for this project names environment `release`.
3. The npm trusted publisher for this package names environment `release`.

If a release fails to authenticate against either registry, check this first:
an environment mismatch is indistinguishable from an ordinary auth failure in
the error text.

## Cross-SDK parity

The engines share `conformance/vectors.json`, run by both test suites. Any
behavioural fix belongs in **both** engines and usually earns a vector there —
adding one covers both languages automatically. A release where the two SDKs
disagree is a release that will be reported as a bug.
