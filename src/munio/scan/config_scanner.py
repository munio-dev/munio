"""Config file scanner for MCP supply chain security issues.

Analyzes MCP config files (claude_desktop_config.json, .cursor/mcp.json, etc.)
for supply chain risks: unpinned deps, dangerous env vars, typosquatting,
credential exposure. Pure static analysis -- no server connections needed.
"""

from __future__ import annotations

import logging
import re
import stat
import sys
import time
import unicodedata
import uuid
from pathlib import Path  # noqa: TC003 -- used in runtime signatures

from munio.scan._config_utils import get_config_candidates, parse_servers, read_config_file
from munio.scan.models import (
    AttackType,
    ConfigFileResult,
    ConfigPermissions,
    ConfigScanResult,
    Finding,
    FindingSeverity,
    Layer,
    ServerConfig,
)

__all__ = ["ConfigScanner"]

logger = logging.getLogger(__name__)

_MAX_PKG_NAME_LEN = 256

# -- Known MCP packages (for typosquatting detection) -------------------

_KNOWN_MCP_PACKAGES: frozenset[str] = frozenset(
    {
        "@anthropic-ai/mcp-server-memory",
        "@anthropic-ai/mcp-server-sequential-thinking",
        "@anthropic-ai/mcp-server-filesystem",
        "@anthropic-ai/mcp-server-puppeteer",
        "@anthropic-ai/mcp-server-fetch",
        "@anthropic-ai/mcp-server-github",
        "@anthropic-ai/mcp-server-brave-search",
        "@anthropic-ai/mcp-server-google-maps",
        "@anthropic-ai/mcp-server-slack",
        "@anthropic-ai/mcp-server-postgres",
        "@anthropic-ai/mcp-server-gdrive",
        "@anthropic-ai/mcp-server-sentry",
        "@anthropic-ai/mcp-server-linear",
        "@anthropic-ai/mcp-server-notion",
        "@anthropic-ai/mcp-server-everything",
        "@anthropic-ai/mcp-server-git",
        "@modelcontextprotocol/server-filesystem",
        "@modelcontextprotocol/server-puppeteer",
        "@modelcontextprotocol/server-fetch",
        "@modelcontextprotocol/server-github",
        "@modelcontextprotocol/server-brave-search",
        "@modelcontextprotocol/server-google-maps",
        "@modelcontextprotocol/server-slack",
        "@modelcontextprotocol/server-postgres",
        "@modelcontextprotocol/server-gdrive",
        "@modelcontextprotocol/server-everything",
        "@modelcontextprotocol/server-memory",
        "@modelcontextprotocol/server-sequential-thinking",
        "@modelcontextprotocol/server-git",
    }
)

# -- Dangerous environment variables ------------------------------------

_DANGEROUS_ENV_VARS: frozenset[str] = frozenset(
    {
        "LD_PRELOAD",
        "LD_LIBRARY_PATH",
        "DYLD_INSERT_LIBRARIES",
        "DYLD_LIBRARY_PATH",
        "DYLD_FRAMEWORK_PATH",
        "DYLD_FALLBACK_LIBRARY_PATH",
        "NODE_OPTIONS",
        "NODE_EXTRA_CA_CERTS",
        "PYTHONPATH",
        "PYTHONSTARTUP",
        "PYTHONHOME",
        "RUBYOPT",
        "RUBYLIB",
        "PERL5OPT",
        "PERL5LIB",
        "JAVA_TOOL_OPTIONS",
        "_JAVA_OPTIONS",
        "JAVA_OPTS",
        "CLASSPATH",
        "BASH_ENV",
        "ENV",
        "ZDOTDIR",
    }
)

# -- Sensitive env var name patterns ------------------------------------

_SENSITIVE_NAME_WORDS: frozenset[str] = frozenset(
    {
        "token",
        "key",
        "secret",
        "password",
        "passwd",
        "credential",
        "api_key",
        "apikey",
        "auth",
        "private_key",
        "access_key",
        "secret_key",
    }
)

# -- Known credential value patterns ------------------------------------

_CREDENTIAL_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"^ghp_[A-Za-z0-9]{36,}$"),  # GitHub PAT
    re.compile(r"^github_pat_[A-Za-z0-9_]{20,}$"),  # GitHub fine-grained PAT
    re.compile(r"^gho_[A-Za-z0-9]{36,}$"),  # GitHub OAuth
    re.compile(r"^sk-[A-Za-z0-9]{20,}$"),  # OpenAI / Anthropic
    re.compile(r"^sk-ant-[A-Za-z0-9-]{20,}$"),  # Anthropic
    re.compile(r"^AKIA[A-Z0-9]{16}$"),  # AWS access key
    re.compile(r"^xoxb-[0-9]+-[A-Za-z0-9-]+$"),  # Slack bot token
    re.compile(r"^xoxp-[0-9]+-[A-Za-z0-9-]+$"),  # Slack user token
    re.compile(r"^npm_[A-Za-z0-9]{36,}$"),  # npm token
    re.compile(r"^glpat-[A-Za-z0-9_-]{20,}$"),  # GitLab PAT
    re.compile(r"^ya29\.[A-Za-z0-9_-]+$"),  # Google OAuth
)

# -- Shell metacharacters -----------------------------------------------

_SHELL_META_RE = re.compile(r"[;|&`]|\$[({]|>>|<<")

# -- Levenshtein distance -----------------------------------------------


def _levenshtein(s1: str, s2: str) -> int:
    """Compute Levenshtein edit distance between two strings."""
    if len(s1) < len(s2):
        return _levenshtein(s2, s1)
    if len(s2) == 0:
        return len(s1)

    prev_row = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        curr_row = [i + 1]
        for j, c2 in enumerate(s2):
            cost = 0 if c1 == c2 else 1
            curr_row.append(min(curr_row[j] + 1, prev_row[j + 1] + 1, prev_row[j] + cost))
        prev_row = curr_row

    return prev_row[-1]


def _normalize_pkg_name(name: str) -> str:
    """Normalize package name for comparison: NFKC + casefold."""
    return unicodedata.normalize("NFKC", name).casefold()


# -- Check functions ----------------------------------------------------


def _check_unpinned_version(server: ServerConfig) -> list[Finding]:
    """SC_001: Detect npx/bunx packages without pinned version."""
    findings: list[Finding] = []

    if server.command not in ("npx", "bunx", "pnpx"):
        return findings

    for arg in server.args:
        if arg.startswith("-"):
            continue
        if not arg.startswith("@"):
            continue
        # @scope/pkg@version or @scope/pkg#tag (git-pinned)
        if "@" in arg[1:] or "#" in arg:
            continue
        findings.append(
            Finding(
                id="SC_001",
                layer=Layer.L0_CONFIG,
                severity=FindingSeverity.HIGH,
                tool_name=server.name,
                message=f"Unpinned npm package '{arg}' -- vulnerable to supply chain attacks",
                attack_type=AttackType.SUPPLY_CHAIN,
                cwe="CWE-1104",
                location=f"server:{server.name}",
                confidence=0.95,
            )
        )

    return findings


def _check_dangerous_env(server: ServerConfig) -> list[Finding]:
    """SC_002: Detect dangerous environment variables."""
    findings: list[Finding] = []

    if not server.env:
        return findings

    for var_name in server.env:
        upper = var_name.strip().upper()
        if upper in _DANGEROUS_ENV_VARS:
            findings.append(
                Finding(
                    id="SC_002",
                    layer=Layer.L0_CONFIG,
                    severity=FindingSeverity.CRITICAL,
                    tool_name=server.name,
                    message=(
                        f"Dangerous environment variable '{var_name}' can hijack process execution"
                    ),
                    attack_type=AttackType.CONFIG_INJECTION,
                    cwe="CWE-426",
                    location=f"server:{server.name}",
                    confidence=0.95,
                )
            )

    return findings


def _check_typosquatting(server: ServerConfig) -> list[Finding]:
    """SC_003: Detect potential typosquatting of known MCP packages."""
    findings: list[Finding] = []

    if server.command not in ("npx", "bunx", "pnpx", "node"):
        return findings

    known_normalized = {_normalize_pkg_name(p) for p in _KNOWN_MCP_PACKAGES}

    for arg in server.args:
        if arg.startswith("-"):
            continue
        if len(arg) > _MAX_PKG_NAME_LEN:
            continue

        normalized = _normalize_pkg_name(arg)

        # Skip exact matches
        if normalized in known_normalized:
            continue

        for known in _KNOWN_MCP_PACKAGES:
            known_norm = _normalize_pkg_name(known)
            dist = _levenshtein(normalized, known_norm)
            if 0 < dist <= 2:
                findings.append(
                    Finding(
                        id="SC_003",
                        layer=Layer.L0_CONFIG,
                        severity=FindingSeverity.CRITICAL,
                        tool_name=server.name,
                        message=(
                            f"Package '{arg}' is suspiciously similar to"
                            f" known '{known}' (edit distance {dist})"
                        ),
                        attack_type=AttackType.SUPPLY_CHAIN,
                        cwe="CWE-1104",
                        location=f"server:{server.name}",
                        confidence=0.85,
                    )
                )
                break  # one match per arg is enough

    return findings


def _check_unscoped_npm(server: ServerConfig) -> list[Finding]:
    """SC_004: Detect unscoped npm packages (higher hijack risk)."""
    findings: list[Finding] = []

    if server.command not in ("npx", "bunx", "pnpx"):
        return findings

    for arg in server.args:
        if arg.startswith("-"):
            continue
        if arg.startswith("@"):
            continue  # scoped
        # Check if it looks like a package name (not a path, not a flag)
        if "/" in arg or arg.startswith("."):
            continue
        if not re.match(r"^[a-z0-9][a-z0-9._-]*$", arg, re.IGNORECASE):
            continue
        findings.append(
            Finding(
                id="SC_004",
                layer=Layer.L0_CONFIG,
                severity=FindingSeverity.HIGH,
                tool_name=server.name,
                message=f"Unscoped npm package '{arg}' -- higher risk of name hijacking",
                attack_type=AttackType.SUPPLY_CHAIN,
                cwe="CWE-1104",
                location=f"server:{server.name}",
                confidence=0.8,
            )
        )

    return findings


def _check_shell_metacharacters(server: ServerConfig) -> list[Finding]:
    """SC_005: Detect shell metacharacters in command arguments."""
    findings: list[Finding] = []

    for arg in server.args:
        if _SHELL_META_RE.search(arg):
            findings.append(
                Finding(
                    id="SC_005",
                    layer=Layer.L0_CONFIG,
                    severity=FindingSeverity.MEDIUM,
                    tool_name=server.name,
                    message=(
                        "Shell metacharacters in server arguments -- potential command injection"
                    ),
                    attack_type=AttackType.COMMAND_INJECTION,
                    cwe="CWE-78",
                    location=f"server:{server.name}",
                    confidence=0.75,
                )
            )
            break  # one finding per server

    return findings


def _check_absolute_path_binary(server: ServerConfig) -> list[Finding]:
    """SC_006: Detect absolute path binaries in command."""
    findings: list[Finding] = []

    if server.command.startswith("/") or server.command.startswith("\\"):
        findings.append(
            Finding(
                id="SC_006",
                layer=Layer.L0_CONFIG,
                severity=FindingSeverity.MEDIUM,
                tool_name=server.name,
                message=(
                    f"Absolute path binary '{server.command}'"
                    " -- may break portability and bypass PATH controls"
                ),
                attack_type=AttackType.CONFIG_INJECTION,
                cwe="CWE-426",
                location=f"server:{server.name}",
                confidence=0.7,
            )
        )

    return findings


def _check_http_url(server: ServerConfig) -> list[Finding]:
    """SC_007: Detect unencrypted HTTP URLs."""
    findings: list[Finding] = []

    url = server.url or ""
    if url.startswith("http://"):
        findings.append(
            Finding(
                id="SC_007",
                layer=Layer.L0_CONFIG,
                severity=FindingSeverity.MEDIUM,
                tool_name=server.name,
                message="Server URL uses HTTP (not HTTPS) -- traffic is unencrypted",
                attack_type=AttackType.CREDENTIAL_EXPOSURE,
                cwe="CWE-319",
                location=f"server:{server.name}",
                confidence=0.9,
            )
        )

    # Also check args for HTTP URLs
    for arg in server.args:
        if not arg.startswith("http://"):
            continue
        # Allow localhost variants (IPv4, IPv6, hostname) with port/path only
        rest = arg[7:]  # after "http://"
        if rest.startswith("localhost") and (len(rest) == 9 or rest[9:10] in (":", "/")):
            continue
        if rest.startswith("127.0.0.1") and (len(rest) == 9 or rest[9:10] in (":", "/")):
            continue
        if rest.startswith("[::1]"):
            continue
        findings.append(
            Finding(
                id="SC_007",
                layer=Layer.L0_CONFIG,
                severity=FindingSeverity.MEDIUM,
                tool_name=server.name,
                message="HTTP URL in arguments -- traffic is unencrypted",
                attack_type=AttackType.CREDENTIAL_EXPOSURE,
                cwe="CWE-319",
                location=f"server:{server.name}",
                confidence=0.9,
            )
        )
        break  # one per server

    return findings


def _check_docker_no_digest(server: ServerConfig) -> list[Finding]:
    """SC_008: Detect Docker images without digest pinning."""
    findings: list[Finding] = []

    if server.command != "docker":
        return findings

    # Look for "run" subcommand and image argument
    args = server.args
    if "run" not in args:
        return findings

    run_idx = args.index("run")
    # Find the image arg (first non-flag arg after "run"),
    # skipping flag values (e.g. -v /path:/path, --name myname)
    skip_next = False
    for arg in args[run_idx + 1 :]:
        if skip_next:
            skip_next = False
            continue
        if arg.startswith("--") and "=" not in arg:
            skip_next = True  # next arg is the flag's value
            continue
        if arg.startswith("-") and not arg.startswith("--"):
            # Short flags like -v, -e -- next arg is value
            skip_next = True
            continue
        # This is the image argument
        if "@sha256:" in arg:
            break
        # `:latest` or no tag at all
        if ":" not in arg or arg.endswith(":latest"):
            findings.append(
                Finding(
                    id="SC_008",
                    layer=Layer.L0_CONFIG,
                    severity=FindingSeverity.HIGH,
                    tool_name=server.name,
                    message=(
                        f"Docker image '{arg}' not pinned by digest -- vulnerable to tag mutation"
                    ),
                    attack_type=AttackType.SUPPLY_CHAIN,
                    cwe="CWE-1104",
                    location=f"server:{server.name}",
                    confidence=0.9,
                )
            )
        break  # only check first image

    return findings


def _check_sensitive_data(server: ServerConfig) -> list[Finding]:
    """SC_009: Detect sensitive data (API keys, tokens, passwords) in env values."""
    findings: list[Finding] = []

    if not server.env:
        return findings

    for var_name, var_value in server.env.items():
        if not var_value or len(var_value) < 8:
            continue

        # Tier 1: name-based detection (no length concern)
        name_lower = var_name.lower()
        name_match = any(word in name_lower for word in _SENSITIVE_NAME_WORDS)

        # Tier 2: pattern-based detection -- cap length to prevent regex DoS
        pattern_match = False
        if len(var_value) <= 1024:
            pattern_match = any(p.match(var_value) for p in _CREDENTIAL_PATTERNS)

        if name_match or pattern_match:
            findings.append(
                Finding(
                    id="SC_009",
                    layer=Layer.L0_CONFIG,
                    severity=FindingSeverity.CRITICAL,
                    tool_name=server.name,
                    message=f"Sensitive credential in env var '{var_name}' (value redacted)",
                    attack_type=AttackType.CREDENTIAL_EXPOSURE,
                    cwe="CWE-798",
                    location=f"server:{server.name}",
                    confidence=0.9 if pattern_match else 0.8,
                )
            )

    return findings


def _check_file_permissions(config_path: Path) -> ConfigPermissions | None:
    """SC_010: Check file permissions (Unix only)."""
    if sys.platform == "win32":
        return None

    try:
        st = config_path.stat()
    except OSError:
        return None

    mode = st.st_mode
    world_readable = bool(mode & stat.S_IROTH)
    world_writable = bool(mode & stat.S_IWOTH)

    return ConfigPermissions(
        mode=mode & 0o777,
        world_readable=world_readable,
        world_writable=world_writable,
    )


def _permissions_findings(
    server_name: str,
    permissions: ConfigPermissions | None,
) -> list[Finding]:
    """Generate findings from file permissions."""
    if permissions is None:
        return []

    findings: list[Finding] = []
    if permissions.world_writable:
        findings.append(
            Finding(
                id="SC_010",
                layer=Layer.L0_CONFIG,
                severity=FindingSeverity.HIGH,
                tool_name=server_name,
                message=("Config file is world-writable -- any user can modify server definitions"),
                attack_type=AttackType.CONFIG_INJECTION,
                cwe="CWE-732",
                location="file-permissions",
                confidence=0.95,
            )
        )
    elif permissions.world_readable:
        findings.append(
            Finding(
                id="SC_010",
                layer=Layer.L0_CONFIG,
                severity=FindingSeverity.MEDIUM,
                tool_name=server_name,
                message="Config file is world-readable -- credentials may be exposed",
                attack_type=AttackType.CREDENTIAL_EXPOSURE,
                cwe="CWE-732",
                location="file-permissions",
                confidence=0.85,
            )
        )

    return findings


# -- All check functions ------------------------------------------------

_SERVER_CHECKS = [
    _check_unpinned_version,
    _check_dangerous_env,
    _check_typosquatting,
    _check_unscoped_npm,
    _check_shell_metacharacters,
    _check_absolute_path_binary,
    _check_http_url,
    _check_docker_no_digest,
    _check_sensitive_data,
]


# -- ConfigScanner class ------------------------------------------------


class ConfigScanner:
    """Scan MCP config files for supply chain security issues."""

    def scan_server(self, server: ServerConfig, config_path: str = "") -> list[Finding]:
        """Run all checks against a single server config entry."""
        findings: list[Finding] = []
        for check_fn in _SERVER_CHECKS:
            findings.extend(check_fn(server))
        return findings

    def scan_file(self, path: Path, ide: str = "unknown") -> ConfigFileResult:
        """Scan a single config file for all supply chain issues."""
        data = read_config_file(path)
        if data is None:
            return ConfigFileResult(path=str(path), ide=ide)

        # Try all known config keys
        servers: list[ServerConfig] = []
        for key in ("mcpServers", "servers"):
            parsed = parse_servers(data, ide, key)
            if parsed:
                servers = parsed
                break

        findings: list[Finding] = []
        for server in servers:
            findings.extend(self.scan_server(server, config_path=str(path)))

        # File-level permission check
        permissions = _check_file_permissions(path)
        if permissions is not None:
            perm_findings = _permissions_findings("(config-file)", permissions)
            findings.extend(perm_findings)

        return ConfigFileResult(
            path=str(path),
            ide=ide,
            servers_count=len(servers),
            findings=findings,
            permissions=permissions,
        )

    def scan_all(self, *, include_project_level: bool = False) -> ConfigScanResult:
        """Scan all discoverable MCP config files."""
        from munio.scan._config_utils import _PROJECT_LEVEL_SOURCES

        start = time.monotonic()
        scan_id = str(uuid.uuid4())
        files: list[ConfigFileResult] = []

        for source, path, _key in get_config_candidates():
            if not include_project_level and source in _PROJECT_LEVEL_SOURCES:
                continue
            if not path.is_file():
                continue
            file_result = self.scan_file(path, ide=source)
            files.append(file_result)

        elapsed = (time.monotonic() - start) * 1000

        return ConfigScanResult(
            scan_id=scan_id,
            files=files,
            elapsed_ms=elapsed,
        )
