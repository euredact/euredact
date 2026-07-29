# euRedact — one entry point for every check.
#
# Two tiers, split by what they need:
#
#   make check    what CI runs. No corpus, no network. Run before every commit.
#   make verify   everything, including the corpus checks CI cannot run.
#                 Run before every release, and after any change to ranking,
#                 suppression or validation.
#
# The corpus lives outside the repository, so `make check` cannot cover the
# properties that matter most at scale. That gap is exactly where the
# IP-address truncation leak lived: twenty documents in CI said nothing, and
# 4,611 documents found it in one pass. Set EUREDACT_CORPUS if yours is
# somewhere other than ../Data-Generation.

PY      ?= python3
# Sampled by default so the gate stays runnable; the sample is spread evenly
# across both corpora, not a prefix. `make sweep-full` walks all ~187,000.
SWEEP_LIMIT   ?= 20000
PARITY_LIMIT  ?= 2000
PYDIR    = euredact-python
TSDIR    = euredact-ts
PYTHONPATH_ := $(CURDIR)/$(PYDIR)/src

.DEFAULT_GOAL := help
.PHONY: help check verify test-py test-ts lint conformance sweep sweep-full parity eval bench clean

help:
	@echo "euRedact checks"
	@echo
	@echo "  make check     lint + both test suites + conformance   (CI-equivalent, fast)"
	@echo "  make verify    check + sweep + parity + eval           (pre-release, needs corpus)"
	@echo
	@echo "  make lint          ruff over the Python sources"
	@echo "  make test-py       Python suite"
	@echo "  make test-ts       TypeScript typecheck, build and suite"
	@echo "  make conformance   shared vectors, both runtimes"
	@echo "  make sweep         corpus-scale property sweep ($(SWEEP_LIMIT) sampled)"
	@echo "  make sweep-full    the same, over every document (~187,000)"
	@echo "  make parity        do both SDKs mask the same characters?"
	@echo "  make eval          accuracy over the full corpus"
	@echo "  make bench         latency, both runtimes"
	@echo
	@echo "  EUREDACT_CORPUS=<dir>  where the generated datasets live"

# ── CI-equivalent ───────────────────────────────────────────────────────

check: lint test-py test-ts
	@echo
	@echo "check passed — this is what CI runs."
	@echo "Before a release run 'make verify': the corpus checks are not in CI."

lint:
	@echo "==> ruff"
	@cd $(PYDIR) && ruff check src/

test-py:
	@echo "==> python suite"
	@cd $(PYDIR) && PYTHONPATH=src $(PY) -m pytest tests/ -q

test-ts:
	@echo "==> typescript typecheck, build and suite"
	@cd $(TSDIR) && npx tsc --noEmit && npm run --silent build >/dev/null && npm test --silent

conformance:
	@echo "==> shared conformance vectors"
	@cd $(PYDIR) && PYTHONPATH=src $(PY) -m pytest tests/test_conformance.py -q
	@cd $(TSDIR) && npm run --silent test:conformance

# ── Corpus-scale, not runnable in CI ────────────────────────────────────

verify: check sweep parity eval
	@echo
	@echo "verify passed — safe to release."

sweep:
	@echo "==> corpus property sweep ($(SWEEP_LIMIT) documents, evenly sampled)"
	@cd $(PYDIR) && PYTHONPATH=src $(PY) tests/sweep.py --limit $(SWEEP_LIMIT)

sweep-full:
	@echo "==> corpus property sweep (every document)"
	@cd $(PYDIR) && PYTHONPATH=src $(PY) tests/sweep.py

parity:
	@echo "==> cross-SDK masking parity ($(PARITY_LIMIT) documents)"
	@$(PY) scripts/parity.py --limit $(PARITY_LIMIT)

eval:
	@echo "==> accuracy over the full corpus"
	@cd $(PYDIR) && PYTHONPATH=src $(PY) tests/eval_full.py

bench:
	@echo "==> latency"
	@cd $(PYDIR) && PYTHONPATH=src $(PY) tests/benchmark.py
	@cd $(TSDIR) && npm run --silent benchmark

clean:
	@rm -rf $(TSDIR)/dist $(PYDIR)/.pytest_cache $(PYDIR)/.ruff_cache
	@find $(PYDIR) -name __pycache__ -type d -prune -exec rm -rf {} +
