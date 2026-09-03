.PHONY: help install install-dev venv lint test test-offline secrets-scan run-audit run-verify discover clean

PYTHON ?= python3
VENV   ?= .venv
ACT    := . $(VENV)/bin/activate
TAP_API_SRC ?= ../repositories/tap/tap-api/src/main/java

help:
	@echo "tap-authz-check - PenTest-001"
	@echo "Targets:"
	@echo "  make venv           Create .venv"
	@echo "  make install        Install runtime deps"
	@echo "  make install-dev    Install runtime + dev deps (editable)"
	@echo "  make lint           Run ruff"
	@echo "  make secrets-scan   Scan tracked files for JWTs / secret-like content"
	@echo "  make test           Run pytest (offline suite)"
	@echo "  make discover       Regenerate cases/99_discovery_catalog.yaml from TAP API src"
	@echo "  make run-audit      Run audit mode (requires TAP_AUTHZ_TOKEN)"
	@echo "  make run-verify     Run verify mode (requires TAP_AUTHZ_TOKEN)"

venv:
	$(PYTHON) -m venv $(VENV)

install:
	$(ACT) && pip install -r requirements.txt

install-dev:
	$(ACT) && pip install -e ".[dev]"

lint:
	$(ACT) && ruff check src tests tools

secrets-scan:
	$(ACT) && python tools/scan_for_secrets.py --strict

test:
	$(ACT) && pytest

discover:
	$(ACT) && python tools/extract_paths_from_java.py \
		--src $(TAP_API_SRC) --out tools/discovery_catalog.yaml
	$(ACT) && python tools/build_discovery_suite.py \
		--catalog tools/discovery_catalog.yaml --out cases/99_discovery_catalog.yaml

run-audit:
	$(ACT) && tap-authz-check --mode audit

run-verify:
	$(ACT) && tap-authz-check --mode verify

clean:
	rm -rf .pytest_cache .ruff_cache reports/*.json reports/*.xml
	find . -type d -name __pycache__ -exec rm -rf {} +
