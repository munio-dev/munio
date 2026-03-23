"""MCP config discovery and rewriting for munio gate init.

Discovers MCP server configurations across IDEs and rewrites them
to route through munio gate.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any

__all__ = ["ConfigEntry", "discover_configs", "restore_config", "rewrite_config"]

logger = logging.getLogger(__name__)

_MAX_CONFIG_SIZE = 1_048_576  # 1 MB
_GATE_CMD = "munio"
_BACKUP_SUFFIX = ".munio-backup.json"


def _is_venv_path(path: Path) -> bool:
    """Check if a path is inside a virtual environment."""
    parts = path.parts
    return ".venv" in parts or "venv" in parts


def _resolve_gate_cmd() -> str:
    """Resolve the absolute path to the munio binary for config rewriting.

    IDE processes (Cursor, Windsurf, Claude Desktop) don't inherit venv PATH,
    so we always write the absolute path to the munio binary.

    Priority: global install (pipx/stable) > venv install (with warning) > bare name.
    """
    # 1. Prefer global/pipx install (stable, survives venv deletion)
    found = shutil.which("munio")
    if found and not _is_venv_path(Path(found)):
        return found

    # 2. Venv binary (next to sys.executable)
    venv_bin = Path(sys.executable).parent / "munio"
    if venv_bin.exists():
        return str(venv_bin)

    # 3. Any munio in PATH (even venv — better than nothing)
    if found:
        return found

    # 4. Last resort
    logger.warning(
        "munio binary not found. Servers may fail to start. Install globally: pipx install munio"
    )
    return "munio"


class ConfigEntry:
    """A discovered MCP config file with its servers."""

    __slots__ = ("key", "path", "servers", "source")

    def __init__(
        self,
        source: str,
        path: Path,
        key: str,
        servers: dict[str, dict[str, Any]],
    ) -> None:
        self.source = source
        self.path = path
        self.key = key
        self.servers = servers

    def __repr__(self) -> str:
        return f"ConfigEntry({self.source!r}, {self.path}, servers={len(self.servers)})"


def _expand(path_str: str) -> Path:
    """Expand ~ and environment variables in a path string."""
    return Path(os.path.expandvars(path_str)).expanduser()


def _get_candidates() -> list[tuple[str, Path, str]]:
    """Build (source, path, config_key) for all known IDE configs."""
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
    elif sys.platform == "linux":
        candidates.append(
            (
                "claude-desktop",
                _expand("~/.config/Claude/claude_desktop_config.json"),
                "mcpServers",
            )
        )
    elif sys.platform == "win32":
        candidates.append(
            (
                "claude-desktop",
                _expand("%APPDATA%/Claude/claude_desktop_config.json"),
                "mcpServers",
            )
        )

    # Cursor
    candidates.append(("cursor", _expand("~/.cursor/mcp.json"), "mcpServers"))

    # VS Code — key is "servers", NOT "mcpServers"
    candidates.append(("vscode", Path.cwd() / ".vscode" / "mcp.json", "servers"))

    # Windsurf
    if sys.platform == "darwin":
        candidates.append(
            (
                "windsurf",
                _expand("~/.codeium/windsurf/mcp_config.json"),
                "mcpServers",
            )
        )

    # Cline
    if sys.platform == "darwin":
        cline_base = "~/Library/Application Support/Code/User/globalStorage"
    elif sys.platform == "win32":
        cline_base = "%APPDATA%/Code/User/globalStorage"
    else:
        cline_base = "~/.config/Code/User/globalStorage"
    candidates.append(
        (
            "cline",
            _expand(f"{cline_base}/saoudrizwan.claude-dev/settings/cline_mcp_settings.json"),
            "mcpServers",
        )
    )

    # JetBrains Junie
    candidates.append(("junie", _expand("~/.junie/mcp/mcp.json"), "mcpServers"))

    # Claude Code
    candidates.append(("claude-code", Path.cwd() / ".claude" / "settings.json", "mcpServers"))

    return candidates


def _read_config_raw(path: Path) -> bytes | None:
    """Read a config file as raw bytes, with size and existence checks."""
    if not path.is_file():
        return None
    try:
        if path.stat().st_size > _MAX_CONFIG_SIZE:
            return None
    except OSError:
        return None
    try:
        return path.read_bytes()
    except OSError:
        return None


def _parse_config(raw: bytes) -> dict[str, Any] | None:
    """Parse raw bytes as JSON and return a dict, or None."""
    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None
    if not isinstance(data, dict):
        return None
    return data


def _read_config(path: Path) -> dict[str, Any] | None:
    """Read and parse a JSON config file."""
    raw = _read_config_raw(path)
    if raw is None:
        return None
    return _parse_config(raw)


def _read_config_with_hash(path: Path) -> tuple[dict[str, Any], str] | None:
    """Read config file and return (data, sha256_hex) for TOCTOU detection."""
    raw = _read_config_raw(path)
    if raw is None:
        return None
    data = _parse_config(raw)
    if data is None:
        return None
    return data, hashlib.sha256(raw).hexdigest()


def _is_already_wrapped(server_config: dict[str, Any]) -> bool:
    """Check if a server is already routed through munio."""
    command = server_config.get("command", "")
    if not isinstance(command, str):
        return False
    # L2 fix: Use basename to avoid false positives on arbitrary paths
    return Path(command).name == _GATE_CMD


def discover_configs() -> list[ConfigEntry]:
    """Discover all MCP config files with their server definitions."""
    results: list[ConfigEntry] = []
    for source, path, key in _get_candidates():
        data = _read_config(path)
        if data is None:
            continue
        servers = data.get(key, {})
        if not isinstance(servers, dict) or not servers:
            continue
        # Filter to stdio servers (have "command" field)
        stdio_servers = {
            name: cfg
            for name, cfg in servers.items()
            if isinstance(cfg, dict) and isinstance(cfg.get("command"), str)
        }
        if stdio_servers:
            results.append(ConfigEntry(source, path, key, stdio_servers))
    return results


def rewrite_config(
    entry: ConfigEntry,
    *,
    dry_run: bool = False,
    gate_args: list[str] | None = None,
) -> dict[str, str]:
    """Rewrite a config file to route servers through munio gate.

    Args:
        entry: The config entry to rewrite.
        dry_run: If True, don't write changes -- just report what would change.
        gate_args: Extra args to pass to munio gate run (e.g. --constraints).

    Returns:
        Dict of server_name -> "wrapped" | "already_wrapped" | "skipped".
    """
    # Refuse to modify symlinked config files (write-through-symlink attack)
    if entry.path.is_symlink():
        logger.error("Config path is a symlink (refusing): %s", entry.path)
        return {}

    # M5 fix: Read with hash for TOCTOU detection
    read_result = _read_config_with_hash(entry.path)
    if read_result is None:
        return {}
    data, original_hash = read_result

    servers = data.get(entry.key, {})
    if not isinstance(servers, dict):
        return {}

    results: dict[str, str] = {}
    modified = False

    for name, cfg in servers.items():
        if not isinstance(cfg, dict):
            results[name] = "skipped"
            continue

        if _is_already_wrapped(cfg):
            results[name] = "already_wrapped"
            continue

        command = cfg.get("command")
        if not isinstance(command, str) or not command:
            results[name] = "skipped"
            continue

        # Build new command: munio run [gate_args] -- original_command original_args
        original_args = cfg.get("args", [])
        if not isinstance(original_args, list):
            original_args = []

        new_args = ["run"]
        if gate_args:
            new_args.extend(gate_args)
        new_args.append("--")
        new_args.append(command)
        new_args.extend(str(a) for a in original_args)

        cfg["command"] = _resolve_gate_cmd()
        cfg["args"] = new_args
        results[name] = "wrapped"
        modified = True

    if not modified or dry_run:
        return results

    # M5 fix: TOCTOU detection — verify file hasn't changed since first read
    try:
        current_raw = entry.path.read_bytes()
        current_hash = hashlib.sha256(current_raw).hexdigest()
    except OSError:
        logger.error("Cannot re-read config for TOCTOU check: %s", entry.path)
        return {}
    if current_hash != original_hash:
        logger.error("Config file changed between reads (TOCTOU): %s — aborting", entry.path)
        return {}

    # M5 fix: Backup creation must succeed before rewriting
    backup_path = entry.path.with_suffix(_BACKUP_SUFFIX)
    # M6 fix: Validate existing backup — don't trust pre-created garbage
    should_backup = True
    if backup_path.exists():
        try:
            backup_data = json.loads(backup_path.read_text(encoding="utf-8"))
            if isinstance(backup_data, dict) and entry.key in backup_data:
                should_backup = False  # Existing backup looks valid
            else:
                logger.warning(
                    "Existing backup appears corrupt: %s — creating new backup", backup_path
                )
        except (OSError, json.JSONDecodeError):
            logger.warning("Existing backup unreadable: %s — creating new backup", backup_path)
    if should_backup:
        # M6 fix: Refuse to create backup through symlinks
        if backup_path.is_symlink():
            logger.error("Backup path is a symlink (refusing): %s", backup_path)
            return {}
        try:
            shutil.copy2(entry.path, backup_path)
            logger.info("Backup: %s", backup_path)
        except OSError:
            logger.error("Failed to create backup: %s — aborting rewrite", backup_path)
            return {}

    # M8 fix: Atomic write via temp file + os.replace
    content = json.dumps(data, indent=2, ensure_ascii=False) + "\n"
    tmp_path = None
    try:
        fd, tmp_path = tempfile.mkstemp(
            dir=entry.path.parent,
            prefix=".munio-gate-",
            suffix=".tmp",
        )
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(content)
        Path(tmp_path).replace(entry.path)
        tmp_path = None  # Replaced successfully, no cleanup needed
    except OSError:
        logger.error("Failed to write config: %s", entry.path)
        return {}  # Write failed — don't report "wrapped" to user
    finally:
        if tmp_path is not None:
            Path(tmp_path).unlink(missing_ok=True)

    return results


def _unwrap_server(cfg: dict[str, Any]) -> tuple[str, list[str]] | None:
    """Extract original command and args from a munio wrapped server.

    Returns (command, args) or None if the config is not a valid wrapper.
    Expected format: command="munio", args=["run", ...gate_flags..., "--", cmd, ...args...]
    """
    args = cfg.get("args", [])
    if not isinstance(args, list):
        return None
    try:
        sep_idx = args.index("--")
    except ValueError:
        return None
    if sep_idx + 1 >= len(args):
        return None
    original_cmd = args[sep_idx + 1]
    if not isinstance(original_cmd, str) or not original_cmd:
        return None
    original_args = [str(a) for a in args[sep_idx + 2 :]]
    return original_cmd, original_args


def restore_config(
    entry: ConfigEntry,
    *,
    dry_run: bool = False,
) -> dict[str, str]:
    """Restore a config file by unwrapping munio from all servers.

    Returns dict of server_name -> "restored" | "not_wrapped" | "invalid_wrapper" | "skipped".
    """
    if entry.path.is_symlink():
        logger.error("Config path is a symlink (refusing): %s", entry.path)
        return {}

    read_result = _read_config_with_hash(entry.path)
    if read_result is None:
        return {}
    data, original_hash = read_result

    servers = data.get(entry.key, {})
    if not isinstance(servers, dict):
        return {}

    results: dict[str, str] = {}
    modified = False

    for name, cfg in servers.items():
        if not isinstance(cfg, dict):
            results[name] = "skipped"
            continue

        if not _is_already_wrapped(cfg):
            results[name] = "not_wrapped"
            continue

        unwrapped = _unwrap_server(cfg)
        if unwrapped is None:
            results[name] = "invalid_wrapper"
            continue

        original_cmd, original_args = unwrapped
        cfg["command"] = original_cmd
        cfg["args"] = original_args
        results[name] = "restored"
        modified = True

    if not modified or dry_run:
        return results

    # TOCTOU detection
    try:
        current_raw = entry.path.read_bytes()
        current_hash = hashlib.sha256(current_raw).hexdigest()
    except OSError:
        logger.error("Cannot re-read config for TOCTOU check: %s", entry.path)
        return {}
    if current_hash != original_hash:
        logger.error("Config file changed between reads (TOCTOU): %s — aborting", entry.path)
        return {}

    # Backup before restore (same safety as rewrite_config)
    backup_path = entry.path.with_suffix(_BACKUP_SUFFIX)
    if backup_path.is_symlink():
        logger.error("Backup path is a symlink (refusing): %s", backup_path)
        return {}
    try:
        shutil.copy2(entry.path, backup_path)
    except OSError:
        logger.error("Failed to create backup: %s — aborting restore", backup_path)
        return {}

    # Atomic write
    content = json.dumps(data, indent=2, ensure_ascii=False) + "\n"
    tmp_path_str = None
    try:
        fd, tmp_path_str = tempfile.mkstemp(
            dir=entry.path.parent,
            prefix=".munio-gate-",
            suffix=".tmp",
        )
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(content)
        Path(tmp_path_str).replace(entry.path)
        tmp_path_str = None
    except OSError:
        logger.error("Failed to write config: %s", entry.path)
        return {}
    finally:
        if tmp_path_str is not None:
            Path(tmp_path_str).unlink(missing_ok=True)

    return results
