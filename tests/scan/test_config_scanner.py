"""Tests for munio.scan.config_scanner."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import patch

import pytest
from pydantic import ValidationError

from munio.scan.config_scanner import (
    ConfigScanner,
    _check_absolute_path_binary,
    _check_dangerous_env,
    _check_docker_no_digest,
    _check_file_permissions,
    _check_http_url,
    _check_sensitive_data,
    _check_shell_metacharacters,
    _check_typosquatting,
    _check_unpinned_version,
    _check_unscoped_npm,
    _levenshtein,
    _permissions_findings,
)
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

# ── Levenshtein distance ──────────────────────────────────────────────


class TestLevenshtein:
    @pytest.mark.parametrize(
        ("s1", "s2", "expected"),
        [
            ("", "", 0),
            ("abc", "abc", 0),
            ("abc", "abd", 1),
            ("abc", "ab", 1),
            ("abc", "abcd", 1),
            ("kitten", "sitting", 3),
            ("a", "", 1),
            ("", "xyz", 3),
            ("flaw", "lawn", 2),
        ],
    )
    def test_distance(self, s1: str, s2: str, expected: int) -> None:
        assert _levenshtein(s1, s2) == expected

    def test_symmetric(self) -> None:
        assert _levenshtein("abc", "xyz") == _levenshtein("xyz", "abc")


# ── SC_001: Unpinned version ──────────────────────────────────────────


class TestSC001UnpinnedVersion:
    @pytest.mark.parametrize(
        ("command", "args", "expected_count", "desc"),
        [
            ("npx", ["@scope/pkg"], 1, "unpinned scoped package"),
            ("bunx", ["@scope/pkg"], 1, "bunx unpinned"),
            ("pnpx", ["@scope/pkg"], 1, "pnpx unpinned"),
            ("npx", ["@scope/pkg@1.2.3"], 0, "pinned version"),
            ("npx", ["@scope/pkg@latest"], 0, "pinned to latest tag"),
            ("npx", ["-y", "@scope/pkg"], 1, "flag before unpinned"),
            ("npx", ["--flag", "@scope/pkg@1.0.0"], 0, "flag before pinned"),
            ("node", ["@scope/pkg"], 0, "node command not checked"),
            ("python", ["@scope/pkg"], 0, "unrelated command"),
            ("npx", [], 0, "no args"),
            ("npx", ["-y"], 0, "only flags"),
        ],
    )
    def test_unpinned_detection(
        self, command: str, args: list[str], expected_count: int, desc: str
    ) -> None:
        server = ServerConfig(name="test", source="test", command=command, args=args)
        findings = _check_unpinned_version(server)
        assert len(findings) == expected_count, desc
        if findings:
            assert findings[0].id == "SC_001"
            assert findings[0].layer == Layer.L0_CONFIG
            assert findings[0].severity == FindingSeverity.HIGH


# ── SC_002: Dangerous env vars ────────────────────────────────────────


class TestSC002DangerousEnv:
    @pytest.mark.parametrize(
        ("env", "expected_count", "desc"),
        [
            ({"LD_PRELOAD": "/lib/evil.so"}, 1, "LD_PRELOAD"),
            ({"NODE_OPTIONS": "--require=/evil.js"}, 1, "NODE_OPTIONS"),
            ({"PYTHONPATH": "/evil"}, 1, "PYTHONPATH"),
            ({"DYLD_INSERT_LIBRARIES": "/evil"}, 1, "DYLD_INSERT_LIBRARIES"),
            ({"BASH_ENV": "/evil"}, 1, "BASH_ENV"),
            ({"SAFE_VAR": "value"}, 0, "safe variable"),
            ({"PATH": "/usr/bin"}, 0, "PATH is not dangerous"),
            ({"ld_preload": "/lib/evil.so"}, 1, "case insensitive"),
        ],
    )
    def test_dangerous_env_detection(
        self, env: dict[str, str], expected_count: int, desc: str
    ) -> None:
        server = ServerConfig(name="test", source="test", command="npx", env=env)
        findings = _check_dangerous_env(server)
        assert len(findings) == expected_count, desc
        if findings:
            assert findings[0].id == "SC_002"
            assert findings[0].severity == FindingSeverity.CRITICAL

    def test_no_env(self) -> None:
        server = ServerConfig(name="test", source="test", command="npx")
        assert _check_dangerous_env(server) == []


# ── SC_003: Typosquatting ─────────────────────────────────────────────


class TestSC003Typosquatting:
    @pytest.mark.parametrize(
        ("command", "args", "should_find", "desc"),
        [
            (
                "npx",
                ["@modelcontextprotocol/server-filesysem"],
                True,
                "1 char deletion from server-filesystem",
            ),
            (
                "npx",
                ["@modelcontextprotocol/server-filesystem"],
                False,
                "exact match",
            ),
            ("npx", ["totally-different-name"], False, "completely different name"),
            ("python", ["@modelcontextprotocol/server-filesysem"], False, "wrong command"),
            ("npx", ["-y"], False, "flag only"),
        ],
    )
    def test_typosquatting_detection(
        self, command: str, args: list[str], should_find: bool, desc: str
    ) -> None:
        server = ServerConfig(name="test", source="test", command=command, args=args)
        findings = _check_typosquatting(server)
        if should_find:
            assert len(findings) >= 1, desc
            assert findings[0].id == "SC_003"
            assert findings[0].severity == FindingSeverity.CRITICAL
        else:
            assert len(findings) == 0, desc

    def test_long_name_skipped(self) -> None:
        server = ServerConfig(
            name="test",
            source="test",
            command="npx",
            args=["@scope/" + "x" * 300],
        )
        findings = _check_typosquatting(server)
        assert len(findings) == 0


# ── SC_004: Unscoped npm ──────────────────────────────────────────────


class TestSC004UnscopedNpm:
    @pytest.mark.parametrize(
        ("command", "args", "expected_count", "desc"),
        [
            ("npx", ["mcp-server-test"], 1, "unscoped package"),
            ("bunx", ["some-package"], 1, "bunx unscoped"),
            ("npx", ["@scope/pkg"], 0, "scoped package"),
            ("npx", ["-y", "some-package"], 1, "flag then unscoped"),
            ("npx", ["./local-script.js"], 0, "local path"),
            ("npx", ["/absolute/path"], 0, "absolute path with slash"),
            ("node", ["some-package"], 0, "node command not checked"),
            ("npx", [], 0, "no args"),
            ("npx", ["--flag"], 0, "only flags"),
        ],
    )
    def test_unscoped_detection(
        self, command: str, args: list[str], expected_count: int, desc: str
    ) -> None:
        server = ServerConfig(name="test", source="test", command=command, args=args)
        findings = _check_unscoped_npm(server)
        assert len(findings) == expected_count, desc
        if findings:
            assert findings[0].id == "SC_004"
            assert findings[0].severity == FindingSeverity.HIGH


# ── SC_005: Shell metacharacters ──────────────────────────────────────


class TestSC005ShellMeta:
    @pytest.mark.parametrize(
        ("args", "expected_count", "desc"),
        [
            (["safe-arg"], 0, "safe arg"),
            (["arg; evil"], 1, "semicolon"),
            (["arg | evil"], 1, "pipe"),
            (["arg & evil"], 1, "ampersand"),
            (["arg `evil`"], 1, "backtick"),
            (["$(evil)"], 1, "command substitution"),
            (["safe", "also-safe"], 0, "multiple safe args"),
        ],
    )
    def test_shell_meta_detection(self, args: list[str], expected_count: int, desc: str) -> None:
        server = ServerConfig(name="test", source="test", command="npx", args=args)
        findings = _check_shell_metacharacters(server)
        assert len(findings) == expected_count, desc
        if findings:
            assert findings[0].id == "SC_005"
            assert findings[0].attack_type == AttackType.COMMAND_INJECTION


# ── SC_006: Absolute path binary ──────────────────────────────────────


class TestSC006AbsolutePath:
    @pytest.mark.parametrize(
        ("command", "expected_count", "desc"),
        [
            ("/usr/bin/node", 1, "Unix absolute path"),
            ("\\\\server\\share\\node.exe", 1, "Windows UNC path"),
            ("npx", 0, "relative command"),
            ("node", 0, "bare command"),
        ],
    )
    def test_absolute_path_detection(self, command: str, expected_count: int, desc: str) -> None:
        server = ServerConfig(name="test", source="test", command=command)
        findings = _check_absolute_path_binary(server)
        assert len(findings) == expected_count, desc
        if findings:
            assert findings[0].id == "SC_006"


# ── SC_007: HTTP URL ──────────────────────────────────────────────────


class TestSC007HttpUrl:
    @pytest.mark.parametrize(
        ("url", "args", "expected_count", "desc"),
        [
            ("http://example.com/sse", [], 1, "HTTP URL in url field"),
            ("https://example.com/sse", [], 0, "HTTPS URL is safe"),
            (None, [], 0, "no URL"),
            (None, ["http://evil.com/api"], 1, "HTTP URL in args"),
            (None, ["http://localhost:3000"], 0, "localhost is safe"),
            (None, ["http://127.0.0.1:3000"], 0, "loopback is safe"),
            ("http://evil.com", ["http://also-evil.com"], 2, "both url and args"),
        ],
    )
    def test_http_url_detection(
        self,
        url: str | None,
        args: list[str],
        expected_count: int,
        desc: str,
    ) -> None:
        server = ServerConfig(name="test", source="test", command="node", url=url, args=args)
        findings = _check_http_url(server)
        assert len(findings) == expected_count, desc
        if findings:
            assert findings[0].id == "SC_007"
            assert findings[0].cwe == "CWE-319"


# ── SC_008: Docker no digest ─────────────────────────────────────────


class TestSC008DockerNoDigest:
    @pytest.mark.parametrize(
        ("command", "args", "expected_count", "desc"),
        [
            ("docker", ["run", "myimage"], 1, "no tag"),
            ("docker", ["run", "myimage:latest"], 1, "latest tag"),
            (
                "docker",
                ["run", "myimage@sha256:abc123"],
                0,
                "pinned by digest",
            ),
            ("docker", ["run", "myimage:v1.0"], 0, "specific tag"),
            ("docker", ["run", "--rm", "-it", "myimage"], 1, "flags before image"),
            ("docker", ["build", "."], 0, "no run subcommand"),
            ("npx", ["run", "myimage"], 0, "not docker"),
        ],
    )
    def test_docker_digest_detection(
        self, command: str, args: list[str], expected_count: int, desc: str
    ) -> None:
        server = ServerConfig(name="test", source="test", command=command, args=args)
        findings = _check_docker_no_digest(server)
        assert len(findings) == expected_count, desc
        if findings:
            assert findings[0].id == "SC_008"
            assert findings[0].attack_type == AttackType.SUPPLY_CHAIN


# ── SC_009: Sensitive data ────────────────────────────────────────────


class TestSC009SensitiveData:
    @pytest.mark.parametrize(
        ("env", "expected_count", "desc"),
        [
            (
                {"API_KEY": "sk-abcdefghijklmnopqrstuvwxyz1234567890"},
                1,
                "OpenAI key by name+pattern",
            ),
            ({"GITHUB_TOKEN": "ghp_abcdefghijklmnopqrstuvwxyz1234567890"}, 1, "GitHub PAT"),
            ({"MY_SECRET": "some-long-secret-value"}, 1, "name-based: secret"),
            ({"MY_PASSWORD": "verylongpassword"}, 1, "name-based: password"),
            ({"SAFE_VAR": "safe-value-here"}, 0, "safe variable"),
            ({"SHORT": "abc"}, 0, "value too short"),
            ({"API_KEY": ""}, 0, "empty value"),
            (None, 0, "no env"),
        ],
    )
    def test_sensitive_data_detection(
        self,
        env: dict[str, str] | None,
        expected_count: int,
        desc: str,
    ) -> None:
        server = ServerConfig(name="test", source="test", command="npx", env=env)
        findings = _check_sensitive_data(server)
        assert len(findings) == expected_count, desc
        if findings:
            assert findings[0].id == "SC_009"
            assert findings[0].severity == FindingSeverity.CRITICAL
            # Must not leak the actual value
            assert "redacted" in findings[0].message.lower()

    def test_pattern_match_higher_confidence(self) -> None:
        """Pattern-matched credentials have higher confidence than name-only."""
        server = ServerConfig(
            name="test",
            source="test",
            command="npx",
            env={"MY_TOKEN": "ghp_abcdefghijklmnopqrstuvwxyz1234567890"},
        )
        findings = _check_sensitive_data(server)
        assert len(findings) == 1
        assert findings[0].confidence == 0.9  # pattern match


# ── SC_010: File permissions ──────────────────────────────────────────


class TestSC010FilePermissions:
    @pytest.mark.skipif(sys.platform == "win32", reason="Unix-only test")
    def test_world_writable(self, tmp_path: Path) -> None:
        config = tmp_path / "config.json"
        config.write_text("{}")
        config.chmod(0o666)
        perms = _check_file_permissions(config)
        assert perms is not None
        assert perms.world_writable is True
        findings = _permissions_findings("test", perms)
        assert len(findings) == 1
        assert findings[0].id == "SC_010"
        assert findings[0].severity == FindingSeverity.HIGH

    @pytest.mark.skipif(sys.platform == "win32", reason="Unix-only test")
    def test_world_readable(self, tmp_path: Path) -> None:
        config = tmp_path / "config.json"
        config.write_text("{}")
        config.chmod(0o644)
        perms = _check_file_permissions(config)
        assert perms is not None
        assert perms.world_readable is True
        assert perms.world_writable is False
        findings = _permissions_findings("test", perms)
        assert len(findings) == 1
        assert findings[0].severity == FindingSeverity.MEDIUM

    @pytest.mark.skipif(sys.platform == "win32", reason="Unix-only test")
    def test_restricted_permissions(self, tmp_path: Path) -> None:
        config = tmp_path / "config.json"
        config.write_text("{}")
        config.chmod(0o600)
        perms = _check_file_permissions(config)
        assert perms is not None
        assert perms.world_readable is False
        assert perms.world_writable is False
        findings = _permissions_findings("test", perms)
        assert len(findings) == 0

    def test_none_permissions(self) -> None:
        findings = _permissions_findings("test", None)
        assert findings == []

    def test_nonexistent_file(self, tmp_path: Path) -> None:
        perms = _check_file_permissions(tmp_path / "nonexistent")
        assert perms is None

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows-only test")
    def test_win32_returns_none(self, tmp_path: Path) -> None:  # pragma: no cover
        config = tmp_path / "config.json"
        config.write_text("{}")
        perms = _check_file_permissions(config)
        assert perms is None


# ── ConfigScanner.scan_server ─────────────────────────────────────────


class TestConfigScannerScanServer:
    def test_collects_findings_from_all_checks(self) -> None:
        scanner = ConfigScanner()
        server = ServerConfig(
            name="test",
            source="test",
            command="npx",
            args=["mcp-server-test"],  # unscoped
        )
        findings = scanner.scan_server(server)
        # Should have at least SC_004 (unscoped)
        assert any(f.id == "SC_004" for f in findings)

    def test_multiple_checks_fire(self) -> None:
        scanner = ConfigScanner()
        server = ServerConfig(
            name="test",
            source="test",
            command="npx",
            args=["mcp-server-test"],
            env={"LD_PRELOAD": "/evil.so", "API_KEY": "sk-abcdefghijklmnopqrstuvwxyz"},
        )
        findings = scanner.scan_server(server)
        check_ids = {f.id for f in findings}
        assert "SC_002" in check_ids  # dangerous env
        assert "SC_004" in check_ids  # unscoped
        assert "SC_009" in check_ids  # sensitive data

    def test_clean_server_no_findings(self) -> None:
        scanner = ConfigScanner()
        server = ServerConfig(
            name="test",
            source="test",
            command="node",
            args=["server.js"],
        )
        findings = scanner.scan_server(server)
        assert len(findings) == 0

    def test_all_findings_have_l0_layer(self) -> None:
        scanner = ConfigScanner()
        server = ServerConfig(
            name="test",
            source="test",
            command="npx",
            args=["mcp-server-test"],
            env={"NODE_OPTIONS": "--require=/evil.js"},
        )
        findings = scanner.scan_server(server)
        assert all(f.layer == Layer.L0_CONFIG for f in findings)


# ── ConfigScanner.scan_file ───────────────────────────────────────────


class TestConfigScannerScanFile:
    def test_scan_valid_config(self, tmp_path: Path) -> None:
        config = {
            "mcpServers": {
                "test": {
                    "command": "npx",
                    "args": ["mcp-server-test"],
                }
            }
        }
        p = tmp_path / "config.json"
        p.write_text(json.dumps(config))
        scanner = ConfigScanner()
        result = scanner.scan_file(p, ide="test")
        assert result.servers_count == 1
        assert result.path == str(p)
        assert result.ide == "test"

    def test_scan_missing_file(self, tmp_path: Path) -> None:
        scanner = ConfigScanner()
        result = scanner.scan_file(tmp_path / "nonexistent.json")
        assert result.servers_count == 0
        assert len(result.findings) == 0

    def test_scan_servers_key(self, tmp_path: Path) -> None:
        """Falls back to 'servers' key if 'mcpServers' is missing."""
        config = {
            "servers": {
                "test": {"command": "npx", "args": ["mcp-server-test"]},
            }
        }
        p = tmp_path / "config.json"
        p.write_text(json.dumps(config))
        scanner = ConfigScanner()
        result = scanner.scan_file(p, ide="vscode")
        assert result.servers_count == 1

    def test_scan_empty_config(self, tmp_path: Path) -> None:
        p = tmp_path / "config.json"
        p.write_text("{}")
        if sys.platform != "win32":
            p.chmod(0o600)  # restrict permissions so SC_010 doesn't fire
        scanner = ConfigScanner()
        result = scanner.scan_file(p)
        assert result.servers_count == 0
        assert len(result.findings) == 0

    def test_scan_disabled_server_skipped(self, tmp_path: Path) -> None:
        config = {
            "mcpServers": {
                "test": {"command": "npx", "args": ["evil-pkg"], "disabled": True},
            }
        }
        p = tmp_path / "config.json"
        p.write_text(json.dumps(config))
        scanner = ConfigScanner()
        result = scanner.scan_file(p)
        assert result.servers_count == 0

    @pytest.mark.skipif(sys.platform == "win32", reason="Unix-only test")
    def test_scan_includes_permission_check(self, tmp_path: Path) -> None:
        config = {"mcpServers": {"test": {"command": "echo"}}}
        p = tmp_path / "config.json"
        p.write_text(json.dumps(config))
        p.chmod(0o666)
        scanner = ConfigScanner()
        result = scanner.scan_file(p)
        assert result.permissions is not None
        # World-writable should generate SC_010 finding
        assert any(f.id == "SC_010" for f in result.findings)

    def test_scan_collects_findings_from_multiple_servers(self, tmp_path: Path) -> None:
        config = {
            "mcpServers": {
                "server1": {
                    "command": "npx",
                    "args": ["unscoped-pkg1"],
                },
                "server2": {
                    "command": "npx",
                    "args": ["unscoped-pkg2"],
                },
            }
        }
        p = tmp_path / "config.json"
        p.write_text(json.dumps(config))
        scanner = ConfigScanner()
        result = scanner.scan_file(p)
        assert result.servers_count == 2
        # Both servers should generate SC_004
        sc004 = [f for f in result.findings if f.id == "SC_004"]
        assert len(sc004) == 2


# ── ConfigScanner.scan_all ────────────────────────────────────────────


class TestConfigScannerScanAll:
    def test_scan_all_returns_result(self) -> None:
        with patch("munio.scan.config_scanner.get_config_candidates", return_value=[]):
            scanner = ConfigScanner()
            result = scanner.scan_all()
            assert isinstance(result, ConfigScanResult)
            assert len(result.files) == 0

    def test_scan_all_skips_project_level_by_default(self, tmp_path: Path) -> None:
        config = {"mcpServers": {"test": {"command": "echo"}}}
        p = tmp_path / "config.json"
        p.write_text(json.dumps(config))

        with patch(
            "munio.scan.config_scanner.get_config_candidates",
            return_value=[("vscode", p, "servers")],
        ):
            scanner = ConfigScanner()
            result = scanner.scan_all(include_project_level=False)
            assert len(result.files) == 0

    def test_scan_all_includes_project_level_when_requested(self, tmp_path: Path) -> None:
        config = {"mcpServers": {"test": {"command": "echo"}}}
        p = tmp_path / "config.json"
        p.write_text(json.dumps(config))

        with patch(
            "munio.scan.config_scanner.get_config_candidates",
            return_value=[("vscode", p, "servers")],
        ):
            scanner = ConfigScanner()
            result = scanner.scan_all(include_project_level=True)
            assert len(result.files) == 1

    def test_scan_all_skips_nonexistent_files(self) -> None:
        with patch(
            "munio.scan.config_scanner.get_config_candidates",
            return_value=[
                ("test", Path("/nonexistent/config.json"), "mcpServers"),
            ],
        ):
            scanner = ConfigScanner()
            result = scanner.scan_all()
            assert len(result.files) == 0

    def test_scan_all_has_scan_id_and_elapsed(self, tmp_path: Path) -> None:
        config = {"mcpServers": {"test": {"command": "echo"}}}
        p = tmp_path / "config.json"
        p.write_text(json.dumps(config))

        with patch(
            "munio.scan.config_scanner.get_config_candidates",
            return_value=[("cursor", p, "mcpServers")],
        ):
            scanner = ConfigScanner()
            result = scanner.scan_all()
            assert result.scan_id
            assert result.elapsed_ms >= 0


# ── ConfigScanResult properties ───────────────────────────────────────


class TestConfigScanResultProperties:
    def test_total_findings(self) -> None:
        f1 = Finding(
            id="SC_001",
            layer=Layer.L0_CONFIG,
            severity=FindingSeverity.HIGH,
            tool_name="test",
            message="test",
        )
        f2 = Finding(
            id="SC_002",
            layer=Layer.L0_CONFIG,
            severity=FindingSeverity.CRITICAL,
            tool_name="test",
            message="test",
        )
        result = ConfigScanResult(
            scan_id="test",
            files=[
                ConfigFileResult(path="/a", findings=[f1]),
                ConfigFileResult(path="/b", findings=[f2]),
            ],
        )
        assert result.total_findings == 2

    def test_all_findings(self) -> None:
        f1 = Finding(
            id="SC_001",
            layer=Layer.L0_CONFIG,
            severity=FindingSeverity.HIGH,
            tool_name="test",
            message="test",
        )
        result = ConfigScanResult(
            scan_id="test",
            files=[ConfigFileResult(path="/a", findings=[f1])],
        )
        assert len(result.all_findings) == 1
        assert result.all_findings[0].id == "SC_001"

    def test_by_severity(self) -> None:
        f1 = Finding(
            id="SC_001",
            layer=Layer.L0_CONFIG,
            severity=FindingSeverity.HIGH,
            tool_name="test",
            message="test",
        )
        f2 = Finding(
            id="SC_002",
            layer=Layer.L0_CONFIG,
            severity=FindingSeverity.HIGH,
            tool_name="test",
            message="test",
        )
        f3 = Finding(
            id="SC_003",
            layer=Layer.L0_CONFIG,
            severity=FindingSeverity.CRITICAL,
            tool_name="test",
            message="test",
        )
        result = ConfigScanResult(
            scan_id="test",
            files=[ConfigFileResult(path="/a", findings=[f1, f2, f3])],
        )
        assert result.by_severity == {"HIGH": 2, "CRITICAL": 1}

    def test_empty_result(self) -> None:
        result = ConfigScanResult(scan_id="test")
        assert result.total_findings == 0
        assert result.all_findings == []
        assert result.by_severity == {}


# ── Model validation ──────────────────────────────────────────────────


class TestConfigModels:
    def test_config_permissions_frozen(self) -> None:
        perms = ConfigPermissions(mode=0o644, world_readable=True)
        with pytest.raises(ValidationError):
            perms.mode = 0o600  # type: ignore[misc]

    def test_config_file_result_frozen(self) -> None:
        result = ConfigFileResult(path="/test")
        with pytest.raises(ValidationError):
            result.path = "/other"  # type: ignore[misc]

    def test_config_scan_result_frozen(self) -> None:
        result = ConfigScanResult(scan_id="test")
        with pytest.raises(ValidationError):
            result.scan_id = "other"  # type: ignore[misc]

    def test_config_permissions_extra_forbid(self) -> None:
        with pytest.raises(ValidationError):
            ConfigPermissions(mode=0o644, extra_field="bad")  # type: ignore[call-arg]

    def test_config_file_result_extra_forbid(self) -> None:
        with pytest.raises(ValidationError):
            ConfigFileResult(path="/test", extra_field="bad")  # type: ignore[call-arg]


# ── Recommendations coverage ──────────────────────────────────────────


class TestSCRecommendations:
    @pytest.mark.parametrize(
        "check_id",
        [
            "SC_001",
            "SC_002",
            "SC_003",
            "SC_004",
            "SC_005",
            "SC_006",
            "SC_007",
            "SC_008",
            "SC_009",
            "SC_010",
        ],
    )
    def test_recommendation_exists(self, check_id: str) -> None:
        from munio.scan.recommendations import get_recommendation

        rec = get_recommendation(check_id)
        assert rec is not None, f"Missing recommendation for {check_id}"
        assert rec.short


# ── SC_001 edge cases ───────────────────────────────────────────────


class TestSC001EdgeCases:
    @pytest.mark.parametrize(
        "args,should_find,desc",
        [
            (["@scope/pkg@1.2.3"], False, "version pinned"),
            (["@scope/pkg#v1.0.0"], False, "git tag pinned"),
            (["@scope/pkg@latest"], False, "explicit latest is pinned"),
            (["@scope/pkg"], True, "no version"),
        ],
    )
    def test_pinning_variants(
        self, args: list[str], should_find: bool, desc: str
    ) -> None:
        server = ServerConfig(name="t", source="t", command="npx", args=args)
        findings = ConfigScanner().scan_server(server)
        sc001 = [f for f in findings if f.id == "SC_001"]
        assert bool(sc001) == should_find, desc


# ── SC_007 localhost variants ────────────────────────────────────────


class TestSC007LocalhostVariants:
    @pytest.mark.parametrize(
        "url,should_find,desc",
        [
            ("http://localhost:3000", False, "localhost with port"),
            ("http://127.0.0.1:8080", False, "loopback with port"),
            ("http://[::1]:3000", False, "IPv6 loopback"),
            ("http://example.com", True, "external HTTP"),
            ("http://localhost.evil.com", True, "localhost subdomain trick"),
            ("http://127.0.0.1.evil.com", True, "IP subdomain trick"),
        ],
    )
    def test_http_url_variants(
        self, url: str, should_find: bool, desc: str
    ) -> None:
        server = ServerConfig(name="t", source="t", command="node", args=[url])
        findings = ConfigScanner().scan_server(server)
        sc007 = [f for f in findings if f.id == "SC_007"]
        assert bool(sc007) == should_find, desc


# ── SC_005 shell metacharacter edge cases ────────────────────────────


class TestSC005ShellMetaEdgeCases:
    @pytest.mark.parametrize(
        "arg,should_find,desc",
        [
            ("safe-arg", False, "no metacharacters"),
            ("foo;bar", True, "semicolon"),
            ("foo|bar", True, "pipe"),
            ("foo&bar", True, "ampersand"),
            ("$(evil)", True, "command substitution"),
            ("${PATH}", True, "variable expansion"),
            ("foo>>bar", True, "append redirect"),
            ("foo<<EOF", True, "heredoc"),
        ],
    )
    def test_shell_meta_variants(
        self, arg: str, should_find: bool, desc: str
    ) -> None:
        server = ServerConfig(name="t", source="t", command="node", args=[arg])
        findings = ConfigScanner().scan_server(server)
        sc005 = [f for f in findings if f.id == "SC_005"]
        assert bool(sc005) == should_find, desc


# ── SC_009 credential patterns ──────────────────────────────────────


class TestSC009CredentialPatterns:
    @pytest.mark.parametrize(
        "name,value,should_find,desc",
        [
            ("GITHUB_TOKEN", "ghp_" + "a" * 36, True, "GitHub PAT by name+pattern"),
            ("RANDOM_VAR", "ghp_" + "a" * 36, True, "GitHub PAT by pattern only"),
            ("API_KEY", "some-api-key-value", True, "API key by name"),
            ("SOME_VAR", "some-value", False, "no sensitive name or pattern"),
            ("TOKEN", "short", False, "too short value"),
            ("AWS_KEY", "AKIA" + "A" * 16, True, "AWS access key"),
            ("DATA", "x" * 2000, False, "very long value, no name match"),
        ],
    )
    def test_credential_detection(
        self, name: str, value: str, should_find: bool, desc: str
    ) -> None:
        server = ServerConfig(name="t", source="t", command="node", env={name: value})
        findings = ConfigScanner().scan_server(server)
        sc009 = [f for f in findings if f.id == "SC_009"]
        assert bool(sc009) == should_find, desc


# ── SC_002 env var whitespace ────────────────────────────────────────


class TestSC002EnvVarWhitespace:
    def test_whitespace_stripped(self) -> None:
        """Env var name with whitespace should still be detected."""
        server = ServerConfig(
            name="t", source="t", command="node", env={" LD_PRELOAD ": "/evil.so"}
        )
        findings = ConfigScanner().scan_server(server)
        sc002 = [f for f in findings if f.id == "SC_002"]
        assert len(sc002) == 1
