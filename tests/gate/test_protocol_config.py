"""Tests for L6 protocol configuration loader."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import yaml

from munio.gate.protocol_config import load_protocol_config
from munio.gate.protocol_models import ProtocolConfig


class TestLoadProtocolConfig:
    def test_default_when_no_config(self) -> None:
        """Returns default ProtocolConfig when no config source is available."""
        config = load_protocol_config(constraints_dir=None)
        assert isinstance(config, ProtocolConfig)
        assert config.enabled is True
        assert config.session.require_initialization is True

    def test_from_config_data(self) -> None:
        """Programmatic config via dict."""
        data: dict[str, Any] = {
            "enabled": True,
            "session": {"max_init_timeout_ms": 10000},
            "sampling": {"max_depth": 5},
        }
        config = load_protocol_config(config_data=data)
        assert config.session.max_init_timeout_ms == 10000
        assert config.sampling.max_depth == 5

    def test_from_config_data_nested(self) -> None:
        """Config data with protocol: wrapper key."""
        data: dict[str, Any] = {
            "protocol": {
                "enabled": False,
                "notifications": {"max_list_changed_per_minute": 20},
            }
        }
        config = load_protocol_config(config_data=data)
        assert config.enabled is False
        assert config.notifications.max_list_changed_per_minute == 20

    def test_from_yaml_file(self, tmp_path: Path) -> None:
        """Load from protocol.yaml file in constraints directory."""
        yaml_content = {
            "protocol": {
                "enabled": True,
                "session": {
                    "require_initialization": True,
                    "max_init_timeout_ms": 8000,
                },
                "sampling": {"max_depth": 4},
                "elicitation": {
                    "allowed_domains": ["github.com", "example.com"],
                    "require_approval_for_url_mode": True,
                },
            }
        }
        yaml_path = tmp_path / "protocol.yaml"
        yaml_path.write_text(yaml.dump(yaml_content), encoding="utf-8")

        config = load_protocol_config(constraints_dir=tmp_path)
        assert config.session.max_init_timeout_ms == 8000
        assert config.sampling.max_depth == 4
        assert "github.com" in config.elicitation.allowed_domains

    def test_from_yaml_file_in_parent(self, tmp_path: Path) -> None:
        """Load from protocol.yaml in parent of constraints subdir."""
        yaml_content = {"protocol": {"enabled": True}}
        yaml_path = tmp_path / "protocol.yaml"
        yaml_path.write_text(yaml.dump(yaml_content), encoding="utf-8")

        subdir = tmp_path / "generic"
        subdir.mkdir()

        config = load_protocol_config(constraints_dir=subdir)
        assert config.enabled is True

    def test_invalid_yaml_returns_defaults(self, tmp_path: Path) -> None:
        """Invalid YAML falls back to defaults."""
        yaml_path = tmp_path / "protocol.yaml"
        yaml_path.write_text("{{invalid yaml::", encoding="utf-8")

        config = load_protocol_config(constraints_dir=tmp_path)
        assert isinstance(config, ProtocolConfig)
        assert config.enabled is True  # Default

    def test_non_dict_yaml_returns_defaults(self, tmp_path: Path) -> None:
        """YAML that parses to non-dict falls back to defaults."""
        yaml_path = tmp_path / "protocol.yaml"
        yaml_path.write_text("- item1\n- item2", encoding="utf-8")

        config = load_protocol_config(constraints_dir=tmp_path)
        assert isinstance(config, ProtocolConfig)

    def test_invalid_field_values_returns_defaults(self, tmp_path: Path) -> None:
        """Invalid field values fall back to defaults."""
        yaml_content = {
            "protocol": {
                "session": {"max_init_timeout_ms": -1},  # Invalid: below min
            }
        }
        yaml_path = tmp_path / "protocol.yaml"
        yaml_path.write_text(yaml.dump(yaml_content), encoding="utf-8")

        config = load_protocol_config(constraints_dir=tmp_path)
        # Should fallback to defaults since validation fails
        assert isinstance(config, ProtocolConfig)

    def test_oversized_yaml_returns_defaults(self, tmp_path: Path) -> None:
        """YAML file >1MB falls back to defaults."""
        yaml_path = tmp_path / "protocol.yaml"
        yaml_path.write_text("x" * (1_048_577), encoding="utf-8")

        config = load_protocol_config(constraints_dir=tmp_path)
        assert isinstance(config, ProtocolConfig)

    def test_config_data_takes_priority_over_file(self, tmp_path: Path) -> None:
        """config_data overrides yaml file."""
        yaml_content = {"protocol": {"sampling": {"max_depth": 2}}}
        yaml_path = tmp_path / "protocol.yaml"
        yaml_path.write_text(yaml.dump(yaml_content), encoding="utf-8")

        config = load_protocol_config(
            constraints_dir=tmp_path,
            config_data={"sampling": {"max_depth": 7}},
        )
        assert config.sampling.max_depth == 7  # config_data wins

    def test_missing_constraints_dir(self) -> None:
        """Non-existent constraints dir returns defaults."""
        config = load_protocol_config(constraints_dir=Path("/nonexistent/path"))
        assert isinstance(config, ProtocolConfig)
