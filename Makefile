.DEFAULT_GOAL := all

SOURCES = src tests

# ── Install ─────────────────────────────────────────────────
.PHONY: install
install:  ## Install project with all dev dependencies
	uv sync --locked --dev --no-group train --all-extras
	uv run pre-commit install --install-hooks

# ── Format ──────────────────────────────────────────────────
.PHONY: format
format:  ## Auto-format code
	uv run ruff check --fix --fix-only $(SOURCES)
	uv run ruff format $(SOURCES)

# ── Lint ────────────────────────────────────────────────────
.PHONY: lint
lint:  ## Check code style (no auto-fix)
	uv run ruff check $(SOURCES)
	uv run ruff format --check $(SOURCES)

# ── Type check ──────────────────────────────────────────────
.PHONY: typecheck
typecheck:  ## Run mypy strict type checking
	uv run mypy src/munio/

# ── Test ────────────────────────────────────────────────────
.PHONY: test
test:  ## Run tests
	uv run pytest

.PHONY: test-fast
test-fast:  ## Run tests excluding slow/z3/benchmark
	uv run pytest -m "not slow and not z3 and not benchmark"

# ── Coverage ────────────────────────────────────────────────
.PHONY: testcov
testcov:  ## Run tests with coverage report
	uv run coverage run -m pytest
	@uv run coverage report --show-missing --fail-under=70
	@uv run coverage html
	@echo "HTML report: htmlcov/index.html"

# ── All ─────────────────────────────────────────────────────
.PHONY: all
all: format lint typecheck testcov  ## Run everything

# ── Smoke test CLI ────────────────────────────────────────
.PHONY: smoke-cli
smoke-cli:  ## Smoke test CLI commands
	uv run munio version
	uv run munio check '{"tool": "http_request", "args": {"url": "https://example.com"}}' -c generic || true
	uv run munio audit

# ── Smoke test server ────────────────────────────────────
.PHONY: smoke-server
smoke-server:  ## Smoke test server creation
	uv run python -c "from munio.server import create_server; print('Server OK')"

# ── CI (non-mutating) ──────────────────────────────────────
.PHONY: ci
ci: lint typecheck testcov smoke-cli smoke-server  ## CI pipeline (no auto-format)

# ── Docs ─────────────────────────────────────────────────────
.PHONY: docs
docs:  ## Generate API reference docs from source code
	uv run python scripts/generate_api_docs.py

.PHONY: docs-sync
docs-sync: docs  ## Generate API docs + sync to munio.dev (local dev)
	@SITE="../munio.dev"; \
	if [ -d "$$SITE" ]; then \
		$$SITE/scripts/sync-docs.sh "$(CURDIR)"; \
	else \
		echo "munio.dev repo not found at $$SITE — skipping sync"; \
	fi

# ── Clean ───────────────────────────────────────────────────
.PHONY: clean
clean:  ## Remove build/cache artifacts
	rm -rf build/ dist/ .eggs/ *.egg-info
	rm -rf .mypy_cache/ .pytest_cache/ .ruff_cache/
	rm -rf htmlcov/ .coverage .coverage.* site/
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true

# ── Help ────────────────────────────────────────────────────
.PHONY: help
help:  ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-15s\033[0m %s\n", $$1, $$2}'
