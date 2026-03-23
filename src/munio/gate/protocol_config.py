"""L6 Protocol Configuration loader.

Loads ProtocolConfig from:
1. Standalone ``protocol.yaml`` file in constraints directory
2. ``protocol:`` section in a gate config JSON/YAML file
3. Programmatic construction via ProtocolConfig model

Example protocol.yaml:

    protocol:
      enabled: true
      session:
        require_initialization: true
        max_init_timeout_ms: 5000
        block_capability_escalation: true
      notifications:
        max_list_changed_per_minute: 10
        max_progress_per_request: 100
        progress_timeout_ms: 120000
      sampling:
        max_depth: 3
        max_cost_budget_usd: 1.0
      elicitation:
        allowed_domains:
          - github.com
          - login.microsoftonline.com
        require_approval_for_url_mode: true
      tool_registry:
        detect_mutations: true
        allow_additions: false
        allow_removals: false
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from pathlib import Path

import yaml

from munio.gate.protocol_models import ProtocolConfig

__all__ = ["load_protocol_config"]

logger = logging.getLogger(__name__)

# Max config file size to prevent DoS via huge YAML
_MAX_CONFIG_SIZE = 1_048_576  # 1 MB


def load_protocol_config(
    constraints_dir: Path | None = None,
    *,
    config_data: dict[str, Any] | None = None,
) -> ProtocolConfig:
    """Load L6 protocol configuration.

    Priority:
    1. ``config_data`` dict (programmatic override)
    2. ``protocol.yaml`` in ``constraints_dir``
    3. Default ProtocolConfig()

    Args:
        constraints_dir: Path to constraints directory containing protocol.yaml.
        config_data: Pre-parsed config dict (e.g., from gate config file).

    Returns:
        Validated ProtocolConfig. Never raises on missing config -- returns defaults.
    """
    if config_data is not None:
        return _parse_config(config_data)

    if constraints_dir is not None:
        yaml_path = constraints_dir / "protocol.yaml"
        if yaml_path.is_file():
            return _load_yaml(yaml_path)

        # Also check parent directory (constraints_dir might be a pack subdir)
        parent_yaml = constraints_dir.parent / "protocol.yaml"
        if parent_yaml.is_file():
            return _load_yaml(parent_yaml)

    # Default config
    logger.debug("No protocol.yaml found, using default L6 configuration")
    return ProtocolConfig()


def _load_yaml(path: Path) -> ProtocolConfig:
    """Load and parse protocol.yaml file."""
    try:
        size = path.stat().st_size
        if size > _MAX_CONFIG_SIZE:
            logger.warning("protocol.yaml too large (%d bytes), using defaults", size)
            return ProtocolConfig()

        raw = path.read_text(encoding="utf-8")
        data = yaml.safe_load(raw)

        if not isinstance(data, dict):
            logger.warning("protocol.yaml is not a YAML mapping, using defaults")
            return ProtocolConfig()

        return _parse_config(data)

    except yaml.YAMLError:
        logger.warning("Failed to parse protocol.yaml, using defaults", exc_info=True)
        return ProtocolConfig()
    except OSError:
        logger.warning("Failed to read protocol.yaml, using defaults", exc_info=True)
        return ProtocolConfig()


def _parse_config(data: dict[str, Any]) -> ProtocolConfig:
    """Parse a config dict into ProtocolConfig.

    Accepts either top-level keys or nested under ``protocol:`` key.
    """
    # If there's a "protocol" key, use that subtree
    if "protocol" in data and isinstance(data["protocol"], dict):
        data = data["protocol"]

    try:
        return ProtocolConfig(**data)
    except Exception:
        logger.warning("Invalid protocol config, using defaults", exc_info=True)
        return ProtocolConfig()
