# rules-engine (euredact)

Issues live on Forgejo (`git.euredact.dev/euredact/*`): file and update them with the `product-issues` skill,
work them with the `issue-queue` skill. Workers push only `issue/<N>-<slug>` branches; a human merges, releases
(`release` skill) and closes.
Check before declaring work done: `make check && make conformance` (`make sweep` when ranking or suppression changed).
Test values that look like live credentials must be broken on purpose: a GitHub or npm token in a vector or test gets a
wrong checksum character. GitHub push protection blocks the whole mirror on a checksum-valid one, and synthetic corpora
(the benchmark sets) generate valid ones; `tests/test_no_live_shaped_tokens.py` enforces it (rules-engine#132).
