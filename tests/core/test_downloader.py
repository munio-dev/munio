"""Tests for munio.downloader."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING
from unittest.mock import MagicMock, patch

import pytest

from munio.downloader import (
    MODEL_REGISTRY,
    _compute_sha256,
    download_all,
    download_model,
    get_models_dir,
    list_installed_models,
)

if TYPE_CHECKING:
    from pathlib import Path


# ── TestGetModelsDir ──────────────────────────────────────────────────


class TestGetModelsDir:
    def test_creates_dir(self, tmp_path: Path) -> None:
        d = get_models_dir(tmp_path / "models")
        assert d.exists()
        assert d.is_dir()

    def test_custom_dir(self, tmp_path: Path) -> None:
        custom = tmp_path / "custom" / "models"
        d = get_models_dir(custom)
        assert d == custom
        assert d.exists()

    def test_existing_dir_unchanged(self, tmp_path: Path) -> None:
        marker = tmp_path / "marker.txt"
        marker.write_text("exists")
        d = get_models_dir(tmp_path)
        assert d == tmp_path
        assert marker.read_text() == "exists"


# ── TestComputeSha256 ─────────────────────────────────────────────────


class TestComputeSha256:
    @pytest.mark.parametrize(
        ("content", "expected_hash"),
        [
            (
                b"hello world",
                "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
            ),
            (
                b"",
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            ),
        ],
        ids=["hello-world", "empty-file"],
    )
    def test_known_hashes(self, tmp_path: Path, content: bytes, expected_hash: str) -> None:
        f = tmp_path / "test.bin"
        f.write_bytes(content)
        assert _compute_sha256(f) == expected_hash


# ── TestListInstalledModels ───────────────────────────────────────────


class TestListInstalledModels:
    def test_no_models(self, tmp_path: Path) -> None:
        result = list_installed_models(tmp_path)
        assert result == []

    def test_installed_model(self, tmp_path: Path) -> None:
        name = "multilingual-v1"
        info = MODEL_REGISTRY[name]
        model_dir = tmp_path / name
        model_dir.mkdir()
        (model_dir / info["filename"]).write_bytes(b"fake model data")
        (model_dir / ".metadata").write_text(
            json.dumps(
                {
                    "version": "0.1.0",
                    "sha256_verified": True,
                    "installed_at": "2026-01-01T00:00:00Z",
                }
            )
        )
        result = list_installed_models(tmp_path)
        assert len(result) == 1
        assert result[0]["name"] == name
        assert result[0]["sha256_ok"] is True
        assert result[0]["version"] == "0.1.0"

    def test_corrupt_metadata_skipped(self, tmp_path: Path) -> None:
        name = "multilingual-v1"
        info = MODEL_REGISTRY[name]
        model_dir = tmp_path / name
        model_dir.mkdir()
        (model_dir / info["filename"]).write_bytes(b"data")
        (model_dir / ".metadata").write_text("not valid json {{{")
        result = list_installed_models(tmp_path)
        assert result == []

    def test_missing_model_file_not_listed(self, tmp_path: Path) -> None:
        name = "multilingual-v1"
        model_dir = tmp_path / name
        model_dir.mkdir()
        (model_dir / ".metadata").write_text(json.dumps({"version": "0.1.0"}))
        # No model file
        result = list_installed_models(tmp_path)
        assert result == []


# ── TestDownloadModel ─────────────────────────────────────────────────


class TestDownloadModel:
    def test_unknown_model(self, tmp_path: Path) -> None:
        ok = download_model("nonexistent", models_dir=tmp_path)
        assert ok is False

    def test_already_installed_skip(self, tmp_path: Path) -> None:
        name = "multilingual-v1"
        info = MODEL_REGISTRY[name]
        model_dir = tmp_path / name
        model_dir.mkdir()
        (model_dir / info["filename"]).write_bytes(b"existing")
        ok = download_model(name, models_dir=tmp_path, force=False)
        assert ok is True  # skipped, not re-downloaded

    def test_dry_run(self, tmp_path: Path) -> None:
        ok = download_model("multilingual-v1", models_dir=tmp_path, dry_run=True)
        assert ok is True
        # File should NOT exist
        assert not (tmp_path / "multilingual-v1" / "multilingual-v1.joblib").exists()

    def test_no_httpx_returns_false(self, tmp_path: Path) -> None:
        with patch.dict("sys.modules", {"httpx": None}):
            ok = download_model("multilingual-v1", models_dir=tmp_path, force=True)
            assert ok is False

    def test_http_404_returns_false(self, tmp_path: Path) -> None:
        import httpx

        mock_response = MagicMock()
        mock_response.status_code = 404

        with patch(
            "munio.downloader._download_with_httpx",
            side_effect=httpx.HTTPStatusError(
                "Not Found", request=MagicMock(), response=mock_response
            ),
        ):
            ok = download_model("multilingual-v1", models_dir=tmp_path, force=True)
            assert ok is False

    def test_http_500_retries_and_fails(self, tmp_path: Path) -> None:
        import httpx

        mock_response = MagicMock()
        mock_response.status_code = 500

        with patch(
            "munio.downloader._download_with_httpx",
            side_effect=httpx.HTTPStatusError(
                "Server Error", request=MagicMock(), response=mock_response
            ),
        ):
            ok = download_model("multilingual-v1", models_dir=tmp_path, force=True)
            assert ok is False

    def test_successful_download(self, tmp_path: Path) -> None:
        """Simulate a successful download with mocked _download_with_httpx."""
        name = "multilingual-v1"
        info = MODEL_REGISTRY[name]
        model_data = b"fake-model-binary-content"

        def fake_download(url: str, dest: Path, verbose: bool = False) -> None:
            dest.write_bytes(model_data)

        with patch("munio.downloader._download_with_httpx", side_effect=fake_download):
            ok = download_model(name, models_dir=tmp_path, force=True)

        assert ok is True
        model_file = tmp_path / name / info["filename"]
        assert model_file.exists()
        assert model_file.read_bytes() == model_data

        metadata_file = tmp_path / name / ".metadata"
        assert metadata_file.exists()
        meta = json.loads(metadata_file.read_text())
        assert meta["name"] == name
        assert meta["version"] == "0.1.0"
        assert meta["sha256_verified"] is True

    def test_sha256_mismatch_retries(self, tmp_path: Path) -> None:
        """When SHA256 is set and doesn't match, file is deleted and retried."""
        name = "multilingual-v1"
        model_data = b"bad-data"

        def fake_download(url: str, dest: Path, verbose: bool = False) -> None:
            dest.write_bytes(model_data)

        # Temporarily set a sha256 that won't match
        original_sha = MODEL_REGISTRY[name]["sha256"]
        MODEL_REGISTRY[name]["sha256"] = "0" * 64
        try:
            with patch("munio.downloader._download_with_httpx", side_effect=fake_download):
                ok = download_model(name, models_dir=tmp_path, force=True)

            assert ok is False  # all retries fail due to sha256 mismatch
        finally:
            MODEL_REGISTRY[name]["sha256"] = original_sha

    def test_request_error_retries(self, tmp_path: Path) -> None:
        import httpx

        with patch(
            "munio.downloader._download_with_httpx",
            side_effect=httpx.RequestError("connection failed"),
        ):
            ok = download_model("multilingual-v1", models_dir=tmp_path, force=True)
            assert ok is False


# ── TestDownloadAll ───────────────────────────────────────────────────


class TestDownloadAll:
    def test_dry_run_all(self, tmp_path: Path) -> None:
        results = download_all(models_dir=tmp_path, dry_run=True)
        assert len(results) == len(MODEL_REGISTRY)
        assert all(v is True for v in results.values())

    @pytest.mark.parametrize(
        ("tier", "expected_in", "expected_out"),
        [
            ("l2.6", "multilingual-v1", "e5-hidden-probe-v1"),
            ("l2.5", "e5-hidden-probe-v1", "multilingual-v1"),
        ],
        ids=["filter-l2.6", "filter-l2.5"],
    )
    def test_filter_by_tier(
        self, tmp_path: Path, tier: str, expected_in: str, expected_out: str
    ) -> None:
        results = download_all(tier=tier, models_dir=tmp_path, dry_run=True)
        assert expected_in in results
        assert expected_out not in results

    def test_filter_no_match(self, tmp_path: Path) -> None:
        results = download_all(tier="nonexistent", models_dir=tmp_path, dry_run=True)
        assert len(results) == 0


# ── TestModelRegistry ─────────────────────────────────────────────────


class TestModelRegistry:
    @pytest.mark.parametrize("name", list(MODEL_REGISTRY.keys()))
    def test_registry_entry_has_required_fields(self, name: str) -> None:
        info = MODEL_REGISTRY[name]
        assert "description" in info
        assert "filename" in info
        assert "size_mb" in info
        assert "sha256" in info
        assert "tier" in info
        assert "layer" in info

    @pytest.mark.parametrize("name", list(MODEL_REGISTRY.keys()))
    def test_filename_ends_with_joblib(self, name: str) -> None:
        assert MODEL_REGISTRY[name]["filename"].endswith(".joblib")


# ── TestCLIDownloadModels ─────────────────────────────────────────────


class TestCLIDownloadModels:
    """Integration tests for the download-models CLI command."""

    @pytest.fixture
    def cli_setup(self):
        from typer.testing import CliRunner

        from munio.cli import create_app

        return CliRunner(), create_app()

    def test_help(self, cli_setup: tuple) -> None:
        runner, app = cli_setup
        result = runner.invoke(app, ["download-models", "--help"])
        assert result.exit_code == 0
        assert "Download ML classifier models" in result.output

    def test_dry_run(self, cli_setup: tuple) -> None:
        runner, app = cli_setup
        result = runner.invoke(app, ["download-models", "--dry-run"])
        assert result.exit_code == 0
        assert "Would download" in result.output

    def test_list_empty(self, cli_setup: tuple) -> None:
        runner, app = cli_setup
        result = runner.invoke(app, ["download-models", "--list"])
        assert result.exit_code == 0
        assert "No models installed" in result.output

    def test_unknown_model(self, cli_setup: tuple) -> None:
        runner, app = cli_setup
        result = runner.invoke(app, ["download-models", "--model", "nonexistent"])
        assert result.exit_code == 2
        assert "Unknown model" in result.output

    def test_unknown_tier(self, cli_setup: tuple) -> None:
        runner, app = cli_setup
        result = runner.invoke(app, ["download-models", "--tier", "l99"])
        assert result.exit_code == 2
        assert "No models match" in result.output

    @pytest.mark.parametrize(
        "tier",
        ["l2.5", "l2.6"],
    )
    def test_dry_run_with_tier(self, cli_setup: tuple, tier: str) -> None:
        runner, app = cli_setup
        result = runner.invoke(app, ["download-models", "--tier", tier, "--dry-run"])
        assert result.exit_code == 0
        assert "Would download 1 model(s)" in result.output

    def test_list_installed(self, cli_setup: tuple, tmp_path: Path) -> None:
        """Test --list with an installed model."""
        name = "multilingual-v1"
        info = MODEL_REGISTRY[name]
        model_dir = tmp_path / name
        model_dir.mkdir()
        (model_dir / info["filename"]).write_bytes(b"fake")
        (model_dir / ".metadata").write_text(
            json.dumps({"version": "0.1.0", "sha256_verified": True})
        )
        runner, app = cli_setup
        result = runner.invoke(app, ["download-models", "--list", "--models-dir", str(tmp_path)])
        assert result.exit_code == 0
        assert "multilingual-v1" in result.output
        assert "verified" in result.output
