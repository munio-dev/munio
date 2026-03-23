# Contributing

## Prerequisites

- Python 3.10+
- [uv](https://docs.astral.sh/uv/) package manager

## Setup

```bash
git clone https://github.com/munio-dev/munio.git
cd munio
make install    # uv sync --all-extras + pre-commit hooks
```

## Development Commands

| Command | Purpose |
|---------|---------|
| `make install` | Install project with all dev dependencies |
| `make test` | Run all tests (3500+) |
| `make test-fast` | Skip slow/z3/benchmark tests |
| `make format` | Auto-format code (ruff check --fix + ruff format) |
| `make lint` | Check code style (ruff check + ruff format --check) |
| `make typecheck` | mypy strict type checking |
| `make testcov` | Run tests with coverage report |
| `make ci` | lint + typecheck + tests with coverage (CI pipeline) |

## Running Tests

The project has 3500+ tests across core, scan, and gate modules.

```bash
# All tests
make test

# Fast subset (skip Z3, benchmarks)
make test-fast

# With coverage
make testcov

# Specific file
uv run pytest tests/core/test_models.py -v
```

Test markers: `slow`, `z3`, `benchmark`, `server`.

## Code Quality

All code must pass:

- **ruff** -- linting (strict, 19 rule sets) and formatting
- **mypy** -- strict type checking
- **pytest** -- 3500+ tests with minimum 70% branch coverage

```bash
make ci   # runs all checks (lint + typecheck + tests with coverage)
```

Auto-format before committing:

```bash
make format
```

## Adding Constraints

1. Create a YAML file under `constraints/<pack-name>/`
2. Follow the format in [Constraint Authoring](guides/constraint-authoring.md)
3. Add tests in `tests/core/`
4. Run `make ci`

## Project Structure

This is a single-package project:

```
munio/
├── src/munio/               # All source code
│   ├── __init__.py          # Public API (lazy imports)
│   ├── models.py            # Pydantic models, enums, config
│   ├── constraints.py       # YAML loader, registry
│   ├── solver.py            # Tier 1 Python + Z3 subprocess
│   ├── verifier.py          # Async verification pipeline
│   ├── guard.py             # Guard class + decorators
│   ├── server.py            # HTTP API server (FastAPI)
│   ├── scan/                # MCP security scanner (8-layer analysis)
│   ├── gate/                # MCP stdio proxy (runtime constraint verification)
│   └── cli.py               # CLI interface
├── constraints/             # Built-in constraint packs (generic, openclaw)
├── docs/                    # Documentation
├── tests/
│   ├── core/
│   ├── scan/
│   └── gate/
└── pyproject.toml           # Single package config
```

## Pull Request Guidelines

- Run `make ci` before opening a PR. All checks must pass.
- Keep PRs focused -- one feature or fix per PR.
- Add tests for new functionality. Use `@pytest.mark.parametrize` when multiple test cases differ only by input data.
- Update constraint YAML files if adding new check types.
- Security-sensitive changes require review of `tests/test_security_invariants.py` to confirm no invariant is broken.

## License

Apache 2.0 — see [LICENSE](https://github.com/munio-dev/munio/blob/main/LICENSE).
