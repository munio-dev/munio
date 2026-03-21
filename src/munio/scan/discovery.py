"""Auto-discover MCP server configurations from IDE settings files.

Supported IDEs:
  - Claude Desktop (macOS/Linux/Windows)
  - Cursor
  - VS Code (project-level)
  - Windsurf
  - Cline
  - JetBrains Junie
  - Claude Code (project-level)
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from munio.scan._config_utils import (
    _PROJECT_LEVEL_SOURCES,
    _expand,  # noqa: F401 — re-exported for backward compat (used by tests)
    get_config_candidates,
    parse_servers,
    read_config_file,
)

if TYPE_CHECKING:
    from pathlib import Path

    from munio.scan.models import ServerConfig

__all__ = ["discover_from_file", "discover_servers"]

logger = logging.getLogger(__name__)

# Keep private aliases for backward compat within this module
_read_config_file = read_config_file
_parse_servers = parse_servers
_get_candidates = get_config_candidates


def discover_servers(*, include_project_level: bool = False) -> list[ServerConfig]:
    """Auto-discover MCP server configs from all supported IDE settings.

    Args:
        include_project_level: If False (default), skip project-level configs
            (.vscode/mcp.json, .claude/settings.json) because they may contain
            untrusted commands from cloned repositories.

    Returns:
        List of discovered server configs, sorted by source name.
        Silently skips missing files and malformed configs.
    """
    results: list[ServerConfig] = []

    for source, path, key in _get_candidates():
        if not include_project_level and source in _PROJECT_LEVEL_SOURCES:
            logger.debug("Skipping project-level config %s (%s)", source, path)
            continue
        data = _read_config_file(path)
        if data is None:
            continue
        servers = _parse_servers(data, source, key)
        results.extend(servers)
        if servers:
            logger.info("Discovered %d server(s) from %s (%s)", len(servers), source, path)

    results.sort(key=lambda s: (s.source, s.name))
    return results


def discover_from_file(path: Path) -> list[ServerConfig]:
    """Parse a single IDE config file for MCP server definitions.

    Tries all known config keys (mcpServers, servers) to auto-detect format.

    Args:
        path: Path to the config file.

    Returns:
        List of server configs found in the file.

    Raises:
        DiscoveryError: If the file cannot be read or parsed.
    """
    from munio.scan.models import DiscoveryError

    data = _read_config_file(path)
    if data is None:
        msg = f"Cannot read or parse config file: {path}"
        raise DiscoveryError(msg)

    # Try all known keys
    for key in ("mcpServers", "servers"):
        servers = _parse_servers(data, path.stem, key)
        if servers:
            return servers

    return []
