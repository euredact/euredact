---
name: release
description: Cut a euRedact release — version bump, changelogs, verification, tag, publish to PyPI and npm. Use whenever releasing, bumping a version, tagging, or fixing a failed publish run. The step order matters; releasing out of order is the cause of every publish failure this repo has had.
---

# Releasing euRedact

Two packages ship from this repo — `euredact-python` (PyPI) and `euredact-ts`
(npm) — from a single tag and a single GitHub Release. They must always carry
the same version number.

**The order below is not stylistic.** Every publish failure this repo has had
came from doing these steps out of order. Reasons are given inline so the
order survives contact with a hurry.

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

Verify none was missed:

```bash
grep -m1 '^version' euredact-python/pyproject.toml
grep -m1 '__version__' euredact-python/src/euredact/__init__.py
python3 -c "import json;print(json.load(open('euredact-ts/package.json'))['version'])"
```

## 2. Date the changelogs

Turn `## Unreleased` into `## X.Y.Z (YYYY-MM-DD)` in **both**
`euredact-python/CHANGELOG.md` and `euredact-ts/CHANGELOG.md`.

Quote only figures that reproduce. If accuracy numbers are cited, re-measure
them on the current ground truth rather than carrying forward an older run —
comparing a new engine against numbers measured on different labels is not a
comparison.

## 3. Run the checks locally before pushing

```bash
make verify
```

`make check` alone is only what CI runs — lint, both suites, conformance. It
does **not** cover the corpus, because the corpus lives outside the repository.
`make verify` adds the three that need it:

- **`make sweep`** — structural properties over every document we have
  (~187,000). This is where the ranking bugs live. `countries=["NL"]` turning
  the IP address `194.232.104.77` into a national ID and leaving `.77` in the
  output was found here; the twenty-document version in CI said nothing.
- **`make parity`** — do both SDKs mask the same characters? Conformance
  vectors pin named cases; this compares whole corpora. TypeScript was once
  leaving 19,014 characters unmasked that Python caught, and no vector showed it.
- **`make eval`** — recall and precision, so a number quoted in the changelog
  is one that was just measured rather than carried forward.

Run `make verify` after any change to ranking, suppression or validation, not
just before a release. `ruff` alone has caught a real import-format error that
would otherwise have failed the release, so do not skip the fast half either.

## 4. Commit, then tag *that* commit

```bash
git add -A && git commit          # "Release X.Y.Z"
git tag -a vX.Y.Z -m "..."        # AFTER the commit, never before
git push origin main
git push origin vX.Y.Z
```

Tagging before the bump commit produces a tag whose code still declares the
previous version. The workflow then builds the old version and npm rejects it
with `You cannot publish over the previously published versions` — an error
that reads as a workflow problem but is a tag-ordering problem.

## 5. Create a GitHub Release, set as latest

`publish.yml` triggers on `release: [published]` — **a tag push alone publishes
nothing.** Create the Release from the tag and mark it latest.

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

Metadata of any kind is still not the final word — install and exercise the new
release's actual features, not just its version string. A correct
`__version__` on code that predates the feature would pass a version check and
fail a user.

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
`publish.yml`, environment blank — the job declares none, so a value there
will not match) and npm 11+, which is why the job upgrades npm from the Node 20
default.

## Cross-SDK parity

The engines share `conformance/vectors.json`, run by both test suites. Any
behavioural fix belongs in **both** engines and usually earns a vector there —
adding one covers both languages automatically. A release where the two SDKs
disagree is a release that will be reported as a bug.
