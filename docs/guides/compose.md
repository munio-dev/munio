# Compose

`munio compose` analyzes multi-server MCP configurations for cross-server attack chains. When multiple MCP servers are active, tools from one server can feed data to another, creating compound vulnerabilities that no single-server scan can detect.

## How It Works

1. **Classify tools** -- each tool is assigned capabilities using the P/U/S (Provide/Use/Store) taxonomy across 16 capability categories (FILE_READ, HTTP_SEND, CODE_EXEC, DB_WRITE, etc.) using a 50-tool taxonomy with keyword and verb-noun inference.

2. **Build capability graph** -- tools are connected by data flow edges: a tool that provides data (P) connects to a tool that uses or stores data (U/S) in a compatible category.

3. **Detect chains** -- BFS traversal finds paths from sensitive sources (FILE_READ, CRED_READ, DB_READ) to exfiltration sinks (HTTP_SEND, MSG_SEND, CODE_EXEC). Cross-server chains are flagged with higher severity.

4. **Score and grade** -- each chain receives a danger score; the overall configuration gets a letter grade (A-F).

## Signal Quality

Each detected chain is assigned a signal quality level:

| Signal | Meaning | Basis |
|--------|---------|-------|
| **high** | Known dangerous combination | Both endpoints match known taxonomy entries AND the combination is in the 26 known dangerous combos list |
| **medium** | One known endpoint | One endpoint matches known taxonomy; the other is inferred |
| **low** | Heuristic only | Both endpoints are inferred from tool/parameter names |

Higher signal chains are more likely to represent real vulnerabilities. CVE drafts are only generated for high and medium signal CRITICAL/HIGH chains.

## Danger Score

The danger score (0-100) uses a max-dominant formula:

- Base score: highest individual chain score
- Cross-server amplification: chains spanning multiple servers receive a multiplier
- Chain count factor: more chains increase the score marginally

The letter grade maps: A (0-19), B (20-39), C (40-59), D (60-79), F (80-100).

## CVE Draft Generation

For high and medium signal chains at CRITICAL or HIGH risk, `munio compose` generates CVE filing drafts including:

- Title and description
- Affected servers
- CVSS score estimate and vector string
- Proof-of-concept narrative

CVSS scores are estimated based on chain properties (cross-server, capability types, data sensitivity). Always verify the score independently before filing.

## CLI Usage

```bash
# Auto-discover servers from IDE configs and analyze
munio compose

# Analyze from a specific config file
munio compose --config ~/.config/claude/claude_desktop_config.json

# Analyze from pre-fetched schema JSON files
munio compose --schemas-dir ./schemas/

# Show chain details and capabilities
munio compose --details

# Output formats
munio compose --format text       # Rich table (default)
munio compose --format json       # Full CompositionReport
munio compose --format markdown   # CVE filing drafts with CVSS and PoC
munio compose --format json -O report.json
```

## Output Formats

### Text (default)

Rich terminal table with signal indicators, chain descriptions, and danger grade.

### JSON

Full `CompositionReport` model serialized as JSON. Includes all chains, nodes, capabilities, danger score, and CVE drafts.

### Markdown

CVE-ready markdown output with:

- Danger score summary
- CVE candidate sections with title, affected servers, description, CVSS estimate, and PoC narrative
- Suitable for pasting into GitHub issues or CVE submission forms

## Output Example (text)

```
munio compose -- 3 servers, 18 tools

Danger: D (72/100) (4 chains, 1.8x amplification)

+----------+-----------------------------------------------+-------+
| Risk     | Chain                                         | Score |
+----------+-----------------------------------------------+-------+
| CRITICAL | read_file@filesystem -> send_http@fetch       |    85 |
|          | Data from filesystem can be exfiltrated       |       |
| HIGH     | query_db@postgres -> send_email@slack          |    68 |
|          | Database records routed to messaging           |       |
+----------+-----------------------------------------------+-------+

Signal: 2 high  1 medium  1 low

2 CVE candidates
  - Filesystem data exfiltration via HTTP (CVSS 8.1, ...)
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | No CRITICAL or HIGH chains |
| 1 | CRITICAL or HIGH chains detected |
| 2 | Error (no servers found, parse failure) |

## See Also

- [CLI Reference](../reference/cli.md) -- full option listing
- [Scan Layers](../reference/scan-layers.md) -- L5 compositional analysis details
- [Config Scan](config-scan.md) -- supply chain checks (`munio config-scan`)
