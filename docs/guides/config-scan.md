# Config Scan

`munio config-scan` scans MCP configuration files for supply chain security issues. It performs pure static analysis of JSON config files -- no server connections are needed.

## What It Does

MCP IDE integrations store server definitions in JSON config files. These configs specify commands to execute, environment variables, Docker images, and URLs. A compromised or carelessly written config can introduce supply chain risks before any tool call is made.

`munio config-scan` inspects these configs for 10 categories of supply chain issues, from unpinned dependencies to hardcoded credentials.

## Supported IDEs

Config-scan auto-discovers configuration files for the following IDEs:

- Claude Desktop (`claude_desktop_config.json`)
- Cursor (`.cursor/mcp.json`)
- VS Code (`.vscode/mcp.json`)
- Windsurf (`windsurf/mcp.json`)
- Cline (`cline_mcp_settings.json`)
- JetBrains Junie (`junie/mcp.json`)
- Claude Code (`.claude/settings.json`)

Project-level configs (`.vscode/mcp.json`, `.claude/settings.json` in the working directory) are excluded by default. Use `--trust-project` to include them.

## Checks

| ID | Severity | Description |
|----|----------|-------------|
| SC_001 | HIGH | Unpinned npm version -- `npx @scope/pkg` without `@version` suffix is vulnerable to supply chain attacks via tag mutation |
| SC_002 | CRITICAL | Dangerous environment variables -- `LD_PRELOAD`, `NODE_OPTIONS`, `DYLD_INSERT_LIBRARIES`, `PYTHONPATH`, and others that can hijack process execution |
| SC_003 | CRITICAL | Typosquatting -- package name within Levenshtein distance 2 of a known MCP package (e.g., `@modelcontextprotcol/server-filesystem`) |
| SC_004 | HIGH | Unscoped npm package -- packages without `@scope/` prefix have higher risk of name hijacking |
| SC_005 | MEDIUM | Shell metacharacters in args -- `;`, `|`, `&`, backticks, `$(`, `>>` in command arguments indicate potential command injection |
| SC_006 | MEDIUM | Absolute path binary -- `/usr/local/bin/server` may break portability and bypass PATH controls |
| SC_007 | MEDIUM | HTTP (not HTTPS) URL -- server URL or argument URL uses unencrypted HTTP (localhost URLs are excluded) |
| SC_008 | HIGH | Docker image without digest -- `docker run image:latest` is vulnerable to tag mutation; pin with `image@sha256:...` |
| SC_009 | CRITICAL | Hardcoded credentials -- two-tier detection: (1) env var name matches sensitive patterns (`TOKEN`, `SECRET`, `API_KEY`, etc.), (2) value matches known credential formats (GitHub PAT, AWS access key, Slack token, etc.) |
| SC_010 | HIGH/MEDIUM | World-readable/writable config file -- file permissions allow other users to read credentials (MEDIUM) or modify server definitions (HIGH). Unix only. |

Credentials are NEVER included in findings. All sensitive values are replaced with "(value redacted)".

## Credential Detection Details

SC_009 uses two-tier detection to minimize false positives:

**Tier 1 -- Name-based**: env var names containing words like `token`, `key`, `secret`, `password`, `credential`, `api_key`, `auth`, `private_key`, `access_key`. Confidence: 0.8.

**Tier 2 -- Pattern-based**: env var values matching known credential formats:

- GitHub PAT (`ghp_...`, `github_pat_...`), GitHub OAuth (`gho_...`)
- OpenAI/Anthropic keys (`sk-...`, `sk-ant-...`)
- AWS access keys (`AKIA...`)
- Slack tokens (`xoxb-...`, `xoxp-...`)
- npm tokens (`npm_...`)
- GitLab PAT (`glpat-...`)
- Google OAuth (`ya29....`)

Pattern matching is capped at 1024 characters per value to prevent regex denial-of-service.

## CI Integration

Config-scan exits with code 1 when CRITICAL or HIGH findings are detected. Use in CI pipelines:

```bash
# Fail CI build if supply chain issues found
munio config-scan --format sarif -O config-scan.sarif
# Upload SARIF to GitHub Code Scanning (optional)
```

## CLI Usage

```bash
# Auto-discover and scan all IDE config files
munio config-scan

# Scan a specific config file
munio config-scan --config ~/.config/claude/claude_desktop_config.json

# Show affected servers and fix suggestions
munio config-scan --details

# Include project-level configs (use with caution)
munio config-scan --trust-project

# Machine-readable output
munio config-scan --format json
munio config-scan --format sarif -O results.sarif
```

## Output Example

```
munio config-scan v0.1.0 -- 2 config files, 5 servers

  + claude_desktop_config.json (claude-desktop, 3 servers)
  o mcp.json (cursor, 2 servers)

+----------+------------------------------------------------------+----------+---------+
| Severity | Finding                                              | CWE      | Servers |
+----------+------------------------------------------------------+----------+---------+
| CRITICAL | Dangerous environment variable 'NODE_OPTIONS' can... | CWE-426  |       1 |
| HIGH     | Unpinned npm package '@scope/server' -- vulnerable...| CWE-1104 |       2 |
+----------+------------------------------------------------------+----------+---------+

2 issues across 5 servers  CRITICAL: 1  HIGH: 1

Run munio scan for schema analysis, munio compose for composition analysis
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | No CRITICAL or HIGH findings |
| 1 | CRITICAL or HIGH findings detected |
| 2 | Error (file not found, parse failure) |

## See Also

- [CLI Reference](../reference/cli.md) -- full option listing
- [Scanner](../reference/scanner.md) -- schema analysis (`munio scan`)
- [Compose](compose.md) -- composition analysis (`munio compose`)
