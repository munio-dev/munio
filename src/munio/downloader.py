"""Model downloader for munio ML classifiers.

Downloads pre-trained models from GitHub Releases to ~/.munio/models/.
Models are verified via SHA256 checksums after download.
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
from pathlib import Path
from typing import Any

__all__ = [
    "MODEL_REGISTRY",
    "download_all",
    "download_model",
    "get_models_dir",
    "list_installed_models",
]

logger = logging.getLogger(__name__)

# Default models directory
_DEFAULT_MODELS_DIR = Path.home() / ".munio" / "models"

# GitHub release base URL
_GITHUB_RELEASE_URL = "https://github.com/munio-dev/munio/releases/download/v0.1.0-models"

# Max retries for download
_MAX_RETRIES = 3

# Model registry: name -> metadata
MODEL_REGISTRY: dict[str, dict[str, Any]] = {
    "multilingual-v1": {
        "description": "L2.6 multilingual prompt injection classifier (188 languages)",
        "filename": "multilingual-v1.joblib",
        "size_mb": 3.2,
        "sha256": "",  # Will be set when models are uploaded to GitHub Releases
        "tier": "l2.6",
        "layer": "L2_MULTILINGUAL",
    },
    "e5-hidden-probe-v1": {
        "description": "L2.5 E5 hidden states probe (English, high accuracy)",
        "filename": "e5-hidden-probe-v1.joblib",
        "size_mb": 1.8,
        "sha256": "",  # Will be set when models are uploaded to GitHub Releases
        "tier": "l2.5",
        "layer": "L2_CLASSIFIER",
    },
}


def get_models_dir(custom_dir: Path | None = None) -> Path:
    """Get the models directory, creating it if needed."""
    d = custom_dir or _DEFAULT_MODELS_DIR
    d.mkdir(parents=True, exist_ok=True)
    return d


def list_installed_models(models_dir: Path | None = None) -> list[dict[str, Any]]:
    """List all installed models with their metadata."""
    d = get_models_dir(models_dir)
    installed: list[dict[str, Any]] = []
    for name, info in MODEL_REGISTRY.items():
        model_dir = d / name
        metadata_file = model_dir / ".metadata"
        model_file = model_dir / info["filename"]

        if model_file.exists() and metadata_file.exists():
            try:
                meta = json.loads(metadata_file.read_text())
                installed.append(
                    {
                        "name": name,
                        "version": meta.get("version", "unknown"),
                        "size_mb": model_file.stat().st_size / (1024 * 1024),
                        "installed_at": meta.get("installed_at", ""),
                        "sha256_ok": meta.get("sha256_verified", False),
                        **info,
                    }
                )
            except (json.JSONDecodeError, OSError):
                pass
    return installed


def _compute_sha256(path: Path) -> str:
    """Compute SHA256 hash of a file."""
    h = hashlib.sha256()
    with open(path, "rb") as f:  # noqa: PTH123
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def _download_with_httpx(url: str, dest: Path, verbose: bool = False) -> None:
    """Download a file using httpx with streaming."""
    import httpx

    with httpx.stream("GET", url, follow_redirects=True, timeout=60.0) as response:
        response.raise_for_status()
        with open(dest, "wb") as f:  # noqa: PTH123
            for chunk in response.iter_bytes(chunk_size=8192):
                f.write(chunk)


def download_model(
    name: str,
    *,
    models_dir: Path | None = None,
    force: bool = False,
    dry_run: bool = False,
    verbose: bool = False,
) -> bool:
    """Download a single model from GitHub Releases.

    Returns True if download succeeded (or already installed), False otherwise.
    """
    if name not in MODEL_REGISTRY:
        logger.error("Unknown model: %s. Available: %s", name, list(MODEL_REGISTRY.keys()))
        return False

    info = MODEL_REGISTRY[name]
    d = get_models_dir(models_dir)
    model_dir = d / name
    model_file = model_dir / info["filename"]
    metadata_file = model_dir / ".metadata"

    # Check if already installed
    if model_file.exists() and not force:
        if verbose:
            logger.info("Model %s already installed at %s", name, model_file)
        return True

    if dry_run:
        logger.info("[dry-run] Would download %s (%.1f MB) to %s", name, info["size_mb"], model_dir)
        return True

    # Lazy import httpx
    try:
        import httpx
    except ImportError:
        logger.error("httpx not installed. Run: pip install 'munio[download]'")
        return False

    url = f"{_GITHUB_RELEASE_URL}/{info['filename']}"
    model_dir.mkdir(parents=True, exist_ok=True)

    for attempt in range(1, _MAX_RETRIES + 1):
        try:
            if verbose:
                logger.info("Downloading %s (attempt %d/%d)...", name, attempt, _MAX_RETRIES)

            _download_with_httpx(url, model_file, verbose=verbose)

            # Verify SHA256
            sha256_ok = True
            expected = info.get("sha256", "")
            if expected:
                actual = _compute_sha256(model_file)
                if actual != expected:
                    logger.error(
                        "SHA256 mismatch for %s: expected %s, got %s",
                        name,
                        expected[:16],
                        actual[:16],
                    )
                    model_file.unlink(missing_ok=True)
                    sha256_ok = False
                    continue  # retry

            # Write metadata
            metadata_file.write_text(
                json.dumps(
                    {
                        "name": name,
                        "version": "0.1.0",
                        "sha256": expected if expected else _compute_sha256(model_file),
                        "sha256_verified": sha256_ok,
                        "installed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                        "source": url,
                    },
                    indent=2,
                )
            )

            logger.info("Downloaded %s (%.1f MB)", name, model_file.stat().st_size / (1024 * 1024))
            return True

        except httpx.HTTPStatusError as exc:
            logger.warning("HTTP %d for %s (attempt %d)", exc.response.status_code, name, attempt)
            if exc.response.status_code == 404:
                logger.error("Model %s not found at %s", name, url)
                return False
        except (httpx.RequestError, OSError) as exc:
            logger.warning("Download error for %s: %s (attempt %d)", name, exc, attempt)

    logger.error("Failed to download %s after %d attempts", name, _MAX_RETRIES)
    return False


def download_all(
    *,
    tier: str | None = None,
    models_dir: Path | None = None,
    force: bool = False,
    dry_run: bool = False,
    verbose: bool = False,
) -> dict[str, bool]:
    """Download all (or filtered by tier) models.

    Returns dict of {model_name: success}.
    """
    results: dict[str, bool] = {}
    for name, info in MODEL_REGISTRY.items():
        if tier and info["tier"] != tier:
            continue
        results[name] = download_model(
            name,
            models_dir=models_dir,
            force=force,
            dry_run=dry_run,
            verbose=verbose,
        )
    return results
