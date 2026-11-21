#!/usr/bin/env bash
# Are Forgejo and GitHub on the release commit? Run before tagging and again
# before creating the GitHub Release. Read-only: it fetches nothing and pushes
# nothing, it only compares refs.
#
#   scripts/release_refs.sh vX.Y.Z            before tagging
#   scripts/release_refs.sh vX.Y.Z --tagged   after pushing the tag, before the Release
#
# A maintenance release (1.0.1 after 1.1.0) is tagged on its line's branch,
# not on main; name the branch (rules-engine#204):
#
#   scripts/release_refs.sh v1.0.1 --branch release/1.0.x [--tagged]
#
# Why it exists: `origin` is Forgejo, but publish.yml runs on GitHub. 0.6.0 was
# pushed to Forgejo only; GitHub's main was still on 0.5.1, the Release created
# its own v0.6.0 there, and publish rebuilt 0.5.1 — reported as success because
# both registries skipped it as already published.
set -euo pipefail

FORGEJO="${FORGEJO_REMOTE:-$(git remote get-url origin)}"
GITHUB="${GITHUB_REMOTE:-https://github.com/euredact/euredact.git}"

usage() { echo "usage: $0 vX.Y.Z [--tagged] [--branch BRANCH]" >&2; exit 2; }
tag="" tagged="" branch="main"
while (( $# )); do
  case "$1" in
    --tagged) tagged=1 ;;
    --branch) [[ $# -ge 2 ]] || usage; branch="$2"; shift ;;
    v*) [[ -z "$tag" ]] || usage; tag="$1" ;;
    *) usage ;;
  esac
  shift
done
[[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || usage
# A line's branch carries only its own patches: release/1.0.x tags 1.0.y.
if [[ "$branch" =~ ^release/([0-9]+)\.([0-9]+)\.x$ ]]; then
  [[ "$tag" == "v${BASH_REMATCH[1]}.${BASH_REMATCH[2]}."* ]] \
    || { echo "FAIL: $tag is not a release of $branch" >&2; exit 1; }
elif [[ "$branch" != "main" ]]; then
  echo "FAIL: release from main or a release/X.Y.x branch, not $branch" >&2; exit 1
fi

fail=0
bad() { echo "FAIL: $*" >&2; fail=1; }

if [[ -n "$(git status --porcelain)" ]]; then
  bad "the working tree is not clean; the release commit is not what you would tag"
fi

head=$(git rev-parse HEAD)
echo "HEAD                $head"

# The release branch on each remote, and the commit the tag points at there
# (empty if absent).
remote_branch() { git ls-remote "$1" "refs/heads/$branch" | cut -f1; }
remote_tag() {
  local out
  out=$(git ls-remote --tags "$1" "refs/tags/$tag" "refs/tags/$tag^{}")
  # An annotated tag is listed twice; its ^{} line is the commit. A lightweight
  # tag, like the one a GitHub Release creates, is listed once.
  sort -k2 <<<"$out" | tail -n1 | cut -f1
}

for name in forgejo github; do
  url=$([[ $name == forgejo ]] && echo "$FORGEJO" || echo "$GITHUB")
  at_branch=$(remote_branch "$url") || { bad "$name: cannot reach $url"; continue; }
  echo "$name $branch$( [[ $name == github ]] && echo ' ' )        ${at_branch:-<none>}"
  [[ "$at_branch" == "$head" ]] || bad "$name $branch is not HEAD — push it: git push $url HEAD:refs/heads/$branch"

  at=$(remote_tag "$url")
  echo "$name $tag$( [[ $name == github ]] && echo ' ' )      ${at:-<none>}"
  if [[ -n "$at" && "$at" != "$head" ]]; then
    bad "$name already has $tag on $at, not HEAD. Move it only if nothing published from it."
  elif [[ -z "$at" && -n "$tagged" ]]; then
    bad "$name has no $tag — push it: git push $url refs/tags/$tag"
  fi
done

if local_tag=$(git rev-parse -q --verify "refs/tags/$tag^{commit}"); then
  [[ "$local_tag" == "$head" ]] || bad "local $tag is on $local_tag, not HEAD"
fi

if (( fail )); then
  echo "not safe to $([[ -n $tagged ]] && echo 'create the GitHub Release' || echo 'tag')." >&2
  exit 1
fi
echo "ok: Forgejo and GitHub agree on $branch = $head$([[ -n $tagged ]] && echo " and $tag")."
