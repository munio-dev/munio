"""Tests for munio.constraints — YAML loading, registry, and lookup."""

import logging
from pathlib import Path

import pytest

from munio.constraints import (
    ConstraintLoadError,
    ConstraintRegistry,
    load_constraints,
    load_constraints_dir,
)
from munio.models import CheckType, Constraint, ConstraintCheck, Tier

# Path to built-in constraint YAMLs
CONSTRAINTS_DIR = Path(__file__).parent.parent.parent / "constraints"
GENERIC_DIR = CONSTRAINTS_DIR / "generic"


# ── TestLoadConstraints ──────────────────────────────────────────────────


class TestLoadConstraints:
    """Tests for load_constraints() single-file loading."""

    def test_load_single_yaml(self):
        path = GENERIC_DIR / "asi02-tool-misuse" / "url-denylist.yaml"
        result = load_constraints(path)
        assert len(result) == 1
        c = result[0]
        assert c.name == "block-dangerous-urls"
        assert c.check is not None
        assert c.check.type == CheckType.DENYLIST
        assert c.check.field == "url"
        assert len(c.check.values) > 0

    def test_load_returns_list_for_single_dict(self, tmp_path: Path):
        yaml_file = tmp_path / "single.yaml"
        yaml_file.write_text(
            "name: test\ncheck:\n  type: denylist\n  field: url\n  values: ['x']\n"
        )
        result = load_constraints(yaml_file)
        assert isinstance(result, list)
        assert len(result) == 1

    def test_load_multi_constraint_yaml(self, tmp_path: Path):
        yaml_file = tmp_path / "multi.yaml"
        yaml_file.write_text(
            "- name: rule1\n"
            "  check:\n"
            "    type: denylist\n"
            "    field: url\n"
            "    values: ['a']\n"
            "- name: rule2\n"
            "  check:\n"
            "    type: denylist\n"
            "    field: url\n"
            "    values: ['b']\n"
        )
        result = load_constraints(yaml_file)
        assert len(result) == 2
        assert result[0].name == "rule1"
        assert result[1].name == "rule2"

    def test_empty_yaml_returns_empty_list(self, tmp_path: Path):
        yaml_file = tmp_path / "empty.yaml"
        yaml_file.write_text("")
        result = load_constraints(yaml_file)
        assert result == []

    def test_comments_only_yaml_returns_empty_list(self, tmp_path: Path):
        yaml_file = tmp_path / "comments.yaml"
        yaml_file.write_text("# This is a comment\n# Another comment\n")
        result = load_constraints(yaml_file)
        assert result == []

    def test_file_not_found_raises(self):
        with pytest.raises(ConstraintLoadError, match="not found"):
            load_constraints("/nonexistent/path.yaml")

    def test_invalid_yaml_raises(self, tmp_path: Path):
        yaml_file = tmp_path / "bad.yaml"
        yaml_file.write_text(":\n  - :\n    bad: [unclosed")
        with pytest.raises(ConstraintLoadError, match="Invalid YAML"):
            load_constraints(yaml_file)

    def test_invalid_schema_raises(self, tmp_path: Path):
        yaml_file = tmp_path / "bad_schema.yaml"
        yaml_file.write_text(
            "name: test\ncheck:\n  type: denylist\n  field: url\n  # missing values\n"
        )
        with pytest.raises(ConstraintLoadError, match="validation failed"):
            load_constraints(yaml_file)

    def test_scalar_yaml_raises(self, tmp_path: Path):
        yaml_file = tmp_path / "scalar.yaml"
        yaml_file.write_text("hello\n")
        with pytest.raises(ConstraintLoadError, match="Expected dict or list"):
            load_constraints(yaml_file)

    def test_oversized_file_raises(self, tmp_path: Path):
        yaml_file = tmp_path / "big.yaml"
        yaml_file.write_text("x" * (1_048_577))  # 1MB + 1
        with pytest.raises(ConstraintLoadError, match="too large"):
            load_constraints(yaml_file)

    def test_extra_field_rejected(self, tmp_path: Path):
        """extra='forbid' catches YAML typos."""
        yaml_file = tmp_path / "typo.yaml"
        yaml_file.write_text(
            "name: test\n"
            "check:\n"
            "  type: denylist\n"
            "  field: url\n"
            "  values: ['x']\n"
            "severtiy: critical\n"  # typo
        )
        with pytest.raises(ConstraintLoadError, match="validation failed"):
            load_constraints(yaml_file)

    def test_unreadable_file_raises(self, tmp_path: Path):
        """File exists but cannot be read (e.g. permission denied)."""
        yaml_file = tmp_path / "unreadable.yaml"
        yaml_file.write_text("name: test\n")
        yaml_file.chmod(0o000)
        try:
            with pytest.raises(ConstraintLoadError, match="Cannot read"):
                load_constraints(yaml_file)
        finally:
            yaml_file.chmod(0o644)

    def test_too_many_constraints_raises(self, tmp_path: Path):
        """YAML with >10,000 top-level items triggers count guard."""
        yaml_file = tmp_path / "huge.yaml"
        # Write a YAML list with 10,001 items (minimal valid constraint dicts)
        lines = [
            f"- name: rule-{i}\n  check:\n    type: denylist\n    field: url\n    values: ['x']\n"
            for i in range(10_001)
        ]
        yaml_file.write_text("".join(lines))
        with pytest.raises(ConstraintLoadError, match="10000"):
            load_constraints(yaml_file)

    def test_error_message_contains_file_path(self, tmp_path: Path):
        yaml_file = tmp_path / "bad_path_test.yaml"
        yaml_file.write_text("just a string\n")
        with pytest.raises(ConstraintLoadError) as exc_info:
            load_constraints(yaml_file)
        assert "bad_path_test.yaml" in str(exc_info.value)

    @pytest.mark.parametrize(
        "subdir",
        [
            "asi01-goal-hijack",
            "asi02-tool-misuse",
            "asi05-code-execution",
        ],
    )
    def test_load_existing_yaml_files(self, subdir: str):
        """All shipped YAML files must load successfully."""
        pack_dir = GENERIC_DIR / subdir
        if not pack_dir.is_dir():
            pytest.skip(f"{pack_dir} not found")
        for yaml_file in sorted(pack_dir.glob("*.yaml")):
            constraints = load_constraints(yaml_file)
            assert len(constraints) >= 1, f"No constraints in {yaml_file}"


# ── TestLoadConstraintsDir ───────────────────────────────────────────────


class TestLoadConstraintsDir:
    """Tests for load_constraints_dir() directory loading."""

    def test_load_all_packs(self):
        registry = load_constraints_dir(CONSTRAINTS_DIR)
        assert len(registry) > 0

    def test_load_specific_pack(self):
        registry = load_constraints_dir(CONSTRAINTS_DIR, packs=["generic"])
        assert len(registry) == 30

    def test_nonexistent_pack_returns_empty(self):
        registry = load_constraints_dir(CONSTRAINTS_DIR, packs=["nonexistent"])
        assert len(registry) == 0

    @pytest.mark.parametrize(
        "bad_pack",
        ["../../etc", "../secrets", "has space", ".hidden", "a/b"],
        ids=["traversal-up", "traversal-parent", "space", "hidden", "slash"],
    )
    def test_invalid_pack_name_raises(self, bad_pack: str):
        with pytest.raises(ConstraintLoadError, match="Invalid pack name"):
            load_constraints_dir(CONSTRAINTS_DIR, packs=[bad_pack])

    def test_nonexistent_directory_returns_empty(self):
        registry = load_constraints_dir("/nonexistent/path")
        assert len(registry) == 0

    def test_symlink_outside_base_skipped(self, tmp_path: Path, caplog):
        """Symlinks pointing outside the base directory are skipped (security check)."""
        # Create an external file with valid constraint
        external = tmp_path / "external"
        external.mkdir()
        ext_file = external / "evil.yaml"
        ext_file.write_text("name: evil\ncheck:\n  type: denylist\n  field: url\n  values: ['x']\n")

        # Create base dir with a pack containing a symlink to external
        base = tmp_path / "constraints"
        pack = base / "pack1"
        pack.mkdir(parents=True)
        symlink = pack / "evil.yaml"
        symlink.symlink_to(ext_file)

        # Also add a real file to prove loading works when not symlinked
        real_file = pack / "real.yaml"
        real_file.write_text(
            "name: real\ncheck:\n  type: denylist\n  field: url\n  values: ['y']\n"
        )

        with caplog.at_level(logging.WARNING):
            registry = load_constraints_dir(base)
        # Only real file loaded; symlink skipped
        assert len(registry) == 1
        assert "real" in registry

    def test_yml_extension_loaded(self, tmp_path: Path):
        """Files with .yml extension are loaded (not just .yaml)."""
        base = tmp_path / "constraints"
        pack = base / "pack1"
        pack.mkdir(parents=True)
        (pack / "rule.yml").write_text(
            "name: yml-rule\ncheck:\n  type: denylist\n  field: url\n  values: ['x']\n"
        )
        registry = load_constraints_dir(base)
        assert len(registry) == 1
        assert "yml-rule" in registry

    def test_empty_pack_directory_returns_zero(self, tmp_path: Path):
        """Pack directory with no YAML files returns empty registry."""
        base = tmp_path / "constraints"
        pack = base / "empty-pack"
        pack.mkdir(parents=True)
        registry = load_constraints_dir(base)
        assert len(registry) == 0

    def test_duplicate_name_raises_with_file_paths(self, tmp_path: Path):
        """Duplicate constraint names detected with both file paths in error."""
        base = tmp_path / "constraints"
        pack1 = base / "pack1"
        pack2 = base / "pack2"
        pack1.mkdir(parents=True)
        pack2.mkdir(parents=True)

        yaml_content = (
            "name: duplicate-name\ncheck:\n  type: denylist\n  field: url\n  values: ['x']\n"
        )
        (pack1 / "rule.yaml").write_text(yaml_content)
        (pack2 / "rule.yaml").write_text(yaml_content)

        with pytest.raises(ConstraintLoadError, match="Duplicate constraint name"):
            load_constraints_dir(base)


# ── TestConstraintRegistry ───────────────────────────────────────────────


def _make_constraint(name: str, action: str = "*", enabled: bool = True) -> Constraint:
    """Helper to create a minimal Constraint for testing."""
    return Constraint(
        name=name,
        action=action,
        enabled=enabled,
        check=ConstraintCheck(type=CheckType.DENYLIST, field="url", values=["x"]),
    )


class TestConstraintRegistry:
    """Tests for ConstraintRegistry methods."""

    def test_contains_by_name(self):
        registry = ConstraintRegistry([_make_constraint("test-rule")])
        assert "test-rule" in registry
        assert "nonexistent" not in registry

    def test_contains_by_constraint_object(self):
        c = _make_constraint("test-rule")
        registry = ConstraintRegistry([c])
        assert c in registry

    def test_getitem_found(self):
        registry = ConstraintRegistry([_make_constraint("my-rule")])
        result = registry["my-rule"]
        assert result.name == "my-rule"

    def test_getitem_not_found(self):
        registry = ConstraintRegistry([_make_constraint("my-rule")])
        with pytest.raises(KeyError, match="nonexistent"):
            registry["nonexistent"]

    def test_get_found(self):
        registry = ConstraintRegistry([_make_constraint("my-rule")])
        result = registry.get("my-rule")
        assert result is not None
        assert result.name == "my-rule"

    def test_get_not_found_returns_none(self):
        registry = ConstraintRegistry([_make_constraint("my-rule")])
        assert registry.get("nonexistent") is None

    def test_constraints_for_exact_match(self):
        c = _make_constraint("rule1", action="http_request")
        registry = ConstraintRegistry([c])
        assert registry.constraints_for("http_request") == [c]
        assert registry.constraints_for("other_tool") == []

    def test_constraints_for_wildcard(self):
        c = _make_constraint("rule1", action="*")
        registry = ConstraintRegistry([c])
        assert registry.constraints_for("anything") == [c]

    def test_constraints_for_glob_pattern(self):
        c = _make_constraint("rule1", action="http_*")
        registry = ConstraintRegistry([c])
        assert registry.constraints_for("http_request") == [c]
        assert registry.constraints_for("http_get") == [c]
        assert registry.constraints_for("db_query") == []

    def test_constraints_for_excludes_disabled(self):
        c = _make_constraint("rule1", action="*", enabled=False)
        registry = ConstraintRegistry([c])
        assert registry.constraints_for("anything") == []

    def test_constraints_for_case_insensitive(self):
        """Tool name matching is case-insensitive (prevents bypass via case variants)."""
        c = _make_constraint("rule1", action="HTTP_request")
        registry = ConstraintRegistry([c])
        assert registry.constraints_for("HTTP_request") == [c]
        assert registry.constraints_for("http_request") == [c]
        assert registry.constraints_for("Http_Request") == [c]

    def test_get_by_tier(self):
        c1 = _make_constraint("rule1")
        registry = ConstraintRegistry([c1])
        assert registry.get_by_tier(Tier.TIER_1) == [c1]
        assert registry.get_by_tier(Tier.TIER_2) == []

    def test_duplicate_name_raises(self):
        with pytest.raises(ConstraintLoadError, match="Duplicate"):
            ConstraintRegistry([_make_constraint("same"), _make_constraint("same")])

    def test_by_name_is_read_only(self):
        registry = ConstraintRegistry([_make_constraint("test")])
        # _by_name is MappingProxyType — assignment should raise
        with pytest.raises(TypeError):
            registry._by_name["new"] = _make_constraint("new")  # type: ignore[index]
