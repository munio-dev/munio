# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in munio, please report it responsibly.

**Email:** security@munio.dev

Please include:
- Description of the vulnerability
- Steps to reproduce
- Impact assessment
- Suggested fix (if any)

We will acknowledge receipt within 48 hours and provide a timeline for the fix.

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |

## Security Design

munio is a security tool. We hold ourselves to a higher standard:

- **Fail-closed**: All error paths block by default, never fail-open
- **No information leaks**: Error messages never expose internal state, constraint names, or raw values
- **Input validation**: All external inputs validated with Pydantic strict models
- **No eval/exec**: Expression evaluation uses AST whitelist, never `eval()`
- **Z3 isolation**: Z3 runs in subprocess with memory limits and timeouts
- **Dependency minimization**: Core requires only pydantic + pyyaml + typer + rich

## Security Testing

- 13 AST-based security invariant tests run in CI
- 7 property-based tests (Hypothesis)
- 12 security review rounds with adversarial testing
- 3500+ total tests
