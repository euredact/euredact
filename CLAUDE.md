# rules-engine (euredact)

Issues live on Forgejo (`git.euredact.dev/euredact/*`): file and update them with the `product-issues` skill,
work them with the `issue-queue` skill. Workers push only `issue/<N>-<slug>` branches; a human merges, releases
(`release` skill) and closes.
Check before declaring work done: `make check && make conformance` (`make sweep` when ranking or suppression changed).
