"""Shared config file reading and parsing utilities.

Extracted from discovery.py to be reused by config_scanner.py
without circular imports.
"""

from __future__ import annotations

import json
import logging
import os
import sys
from pathlib import Path
from typing import Any

from munio.scan.models import ServerConfig

__all__ = [
    "get_config_candidates",
    "parse_servers",
    "read_config_file",
]

logger = logging.getLogger(__name__)

_MAX_CONFIG_SIZE = 1_048_576  # 1 MB

# Sources that use Path.cwd() -- untrusted in cloned repos.
# A malicious .vscode/mcp.json can execute arbitrary commands.
_PROJECT_LEVEL_SOURCES: frozenset[str] = frozenset({"vscode", "claude-code"})


def _expand(path_str: str) -> Path:
    """Expand ~ and environment variables in a path string."""
    return Path(os.path.expandvars(path_str)).expanduser()


def read_config_file(path: Path) -> dict[str, Any] | None:
    """Read and parse a JSON config file with size limit."""
    if not path.is_file():
        return None

    try:
        size = path.stat().st_size
    except OSError:
        logger.warning("Cannot read config file: %s", path)
        return None

    if size > _MAX_CONFIG_SIZE:
        logger.warning("Config file too large (>1MB), skipping: %s", path)
        return None

    try:
        raw = path.read_text(encoding="utf-8")
    except OSError:
        logger.warning("Cannot read config file: %s", path)
        return None

    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        logger.warning("Invalid JSON in config file: %s", path)
        return None

    if not isinstance(data, dict):
        logger.warning("Config file is not a JSON object: %s", path)
        return None

    return data


def parse_servers(data: dict[str, Any], source: str, key: str) -> list[ServerConfig]:
    """Extract server configs from a parsed JSON config."""
    servers_dict = data.get(key, {})
    if not isinstance(servers_dict, dict):
        return []

    results: list[ServerConfig] = []
    for name, config in servers_dict.items():
        if not isinstance(config, dict):
            logger.warning("Skipping non-dict server config %s::%s", source, name)
            continue

        # Skip disabled servers
        if config.get("disabled") is True:
            logger.debug("Skipping disabled server %s::%s", source, name)
            continue

        command = config.get("command", "")
        args_raw = config.get("args", [])
        env_raw = config.get("env")
        url = config.get("url")

        # Validate command is a string
        if not isinstance(command, str):
            logger.warning("Skipping server %s::%s -- command is not a string", source, name)
            continue

        # Validate args is list of strings (skip non-string items)
        if not isinstance(args_raw, list):
            args_raw = []
        args = [a for a in args_raw if isinstance(a, str)]

        # Validate env is dict of strings (skip non-string values)
        env: dict[str, str] | None = None
        if isinstance(env_raw, dict):
            env = {
                str(k): str(v)
                for k, v in env_raw.items()
                if isinstance(v, (str, int, float)) and not isinstance(v, bool)
            }

        results.append(
            ServerConfig(
                name=name,
                source=source,
                command=command,
                args=args,
                env=env,
                url=str(url) if isinstance(url, str) else None,
            )
        )

    return results


def get_config_candidates() -> list[tuple[str, Path, str]]:
    """Build list of (source, path, config_key) candidates for the current platform."""
    candidates: list[tuple[str, Path, str]] = []

    # Claude Desktop
    if sys.platform == "darwin":
        candidates.append(
            (
                "claude-desktop",
                _expand("~/Library/Application Support/Claude/claude_desktop_config.json"),
                "mcpServers",
            )
        )
    elif sys.platform == "linux":  # pragma: no cover
        candidates.append(
            (
                "claude-desktop",
                _expand("~/.config/Claude/claude_desktop_config.json"),
                "mcpServers",
            )
        )
    elif sys.platform == "win32":  # pragma: no cover
        candidates.append(
            (
                "claude-desktop",
                _expand("%APPDATA%/Claude/claude_desktop_config.json"),
                "mcpServers",
            )
        )

    # Cursor (global)
    candidates.append(
        (
            "cursor",
            _expand("~/.cursor/mcp.json"),
            "mcpServers",
        )
    )

    # VS Code (project-level) -- key is "servers", NOT "mcpServers"
    candidates.append(
        (
            "vscode",
            Path.cwd() / ".vscode" / "mcp.json",
            "servers",
        )
    )

    # Windsurf
    if sys.platform == "darwin":
        candidates.append(
            (
                "windsurf",
                _expand("~/.codeium/windsurf/mcp_config.json"),
                "mcpServers",
            )
        )
    elif sys.platform == "win32":  # pragma: no cover
        candidates.append(
            (
                "windsurf",
                _expand("%USERPROFILE%/.codeium/windsurf/mcp_config.json"),
                "mcpServers",
            )
        )

    # Cline
    if sys.platform == "darwin":
        cline_base = "~/Library/Application Support/Code/User/globalStorage"
    elif sys.platform == "win32":  # pragma: no cover
        cline_base = "%APPDATA%/Code/User/globalStorage"
    else:  # pragma: no cover
        cline_base = "~/.config/Code/User/globalStorage"
    candidates.append(
        (
            "cline",
            _expand(f"{cline_base}/saoudrizwan.claude-dev/settings/cline_mcp_settings.json"),
            "mcpServers",
        )
    )

    # JetBrains Junie
    candidates.append(
        (
            "junie",
            _expand("~/.junie/mcp/mcp.json"),
            "mcpServers",
        )
    )

    # Claude Code (project-level)
    candidates.append(
        (
            "claude-code",
            Path.cwd() / ".claude" / "settings.json",
            "mcpServers",
        )
    )

    return candidates
