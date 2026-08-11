.DEFAULT_GOAL := help
SHELL := /bin/bash

VENV ?= .venv
PY   := $(VENV)/bin/python
PIP  := $(VENV)/bin/pip
BIN  := $(VENV)/bin

.PHONY: help
help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-16s\033[0m %s\n", $$1, $$2}'

# ---------------------------------------------------------------------------
# Environment
# ---------------------------------------------------------------------------

$(VENV):
	python3 -m venv $(VENV)
	$(PIP) install --upgrade pip

.PHONY: install
install: $(VENV) ## Create the virtualenv and install the project in editable mode
	$(PIP) install -e ".[dev]"
	@echo "✅ ready — run '$(BIN)/cloudguard --help'"

.PHONY: clean
clean: ## Remove build, cache and report artefacts
	rm -rf build dist *.egg-info reports .coverage coverage.xml htmlcov
	rm -rf .pytest_cache .mypy_cache .ruff_cache
	find . -type d -name __pycache__ -prune -exec rm -rf {} +

# ---------------------------------------------------------------------------
# Quality gates — the same commands the CI pipeline runs
# ---------------------------------------------------------------------------

.PHONY: lint
lint: ## Lint the Python code, the formatting and the GitHub Actions workflows
	$(BIN)/ruff check .
	$(BIN)/ruff format --check .
	$(BIN)/actionlint

.PHONY: format
format: ## Format the code and fix what can be fixed
	$(BIN)/ruff format .
	$(BIN)/ruff check --fix .

.PHONY: typecheck
typecheck: ## Static type checking (mypy strict)
	$(BIN)/mypy

.PHONY: test
test: ## Run the test suite with coverage
	$(BIN)/pytest --cov=cloudguard --cov-report=term-missing

.PHONY: sast
sast: ## Run the security scanners on our own code and dependencies
	$(BIN)/bandit -c pyproject.toml -r cloudguard
	# --strict would fail on the editable install of the project itself.
	$(BIN)/pip-audit --skip-editable

.PHONY: check
check: lint typecheck test sast docs-check selfscan ## Everything the CI pipeline checks
	@echo "✅ all checks passed"

# ---------------------------------------------------------------------------
# Dogfooding
# ---------------------------------------------------------------------------

.PHONY: selfscan
selfscan: ## Scan this repository with CloudGuard (must pass)
	$(BIN)/cloudguard full-scan . --exclude 'examples/vulnerable'

.PHONY: demo
demo: ## Scan the vulnerable corpus — expected to fail with exit code 1
	-$(BIN)/cloudguard full-scan examples/vulnerable --details

.PHONY: reports
reports: ## Generate the HTML, Markdown and SARIF reports of the demo corpus
	$(BIN)/cloudguard full-scan examples/vulnerable -F json -o reports/results.json --fail-on never
	$(BIN)/cloudguard generate-report -I reports/results.json -F html     -o reports/report.html  --fail-on never
	$(BIN)/cloudguard generate-report -I reports/results.json -F markdown -o reports/report.md    --fail-on never
	$(BIN)/cloudguard generate-report -I reports/results.json -F sarif    -o reports/report.sarif --fail-on never
	@echo "📄 open reports/report.html"

# ---------------------------------------------------------------------------
# Documentation & packaging
# ---------------------------------------------------------------------------

.PHONY: docs
docs: ## Regenerate the rules table in the README from the registry
	$(PY) scripts/sync_rules_table.py

.PHONY: docs-check
docs-check: ## Fail when the README rules table is out of date
	$(PY) scripts/sync_rules_table.py --check

.PHONY: build
build: ## Build the wheel and the sdist
	$(PIP) install --quiet build twine
	$(PY) -m build
	$(BIN)/twine check dist/*

.PHONY: docker
docker: ## Build the container image and scan it with CloudGuard
	docker build -t cloudguard-iac:local .
	$(BIN)/cloudguard scan-docker Dockerfile
