# Config Scanner

Supply chain security scanner for MCP config files.

**Module:** `munio.scan.config_scanner`

---

### `ConfigScanner`

Scan MCP config files for supply chain security issues.

**Methods:**

- `scan_server(server, config_path) -> list[Finding]`
  Run all checks against a single server config entry.
- `scan_file(path, ide) -> ConfigFileResult`
  Scan a single config file for all supply chain issues.
- `scan_all(include_project_level) -> ConfigScanResult`
  Scan all discoverable MCP config files.

---

*Auto-generated from source code. Do not edit manually.*
