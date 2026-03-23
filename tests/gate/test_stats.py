"""Tests for munio stats module and CLI command."""

from __future__ import annotations

import json
import math
from datetime import datetime, timezone
from pathlib import Path

import pytest
from pydantic import ValidationError
from typer.testing import CliRunner

from munio.gate.cli import app
from munio.gate.models import InterceptionRecord
from munio.gate.stats import LogStats, compute_stats, parse_log

# ── Helpers ──────────────────────────────────────────────────────────────


def _record(
    tool: str = "read_file",
    decision: str = "allowed",
    elapsed_ms: float = 1.0,
    ts: datetime | None = None,
) -> InterceptionRecord:
    return InterceptionRecord(
        timestamp=ts or datetime(2026, 3, 10, 12, 0, 0, tzinfo=timezone.utc),
        tool=tool,
        decision=decision,  # type: ignore[arg-type]
        elapsed_ms=elapsed_ms,
    )


def _write_jsonl(path: Path, records: list[InterceptionRecord]) -> None:
    with path.open("w", encoding="utf-8") as fh:
        for rec in records:
            fh.write(rec.model_dump_json() + "\n")


# ── TestLogStats ─────────────────────────────────────────────────────────


class TestLogStats:
    def test_defaults(self) -> None:
        s = LogStats()
        assert s.total == 0
        assert s.allowed == 0
        assert s.top_blocked_tools == []
        assert s.first_timestamp is None

    def test_frozen(self) -> None:
        s = LogStats()
        with pytest.raises(ValidationError):
            s.total = 5  # type: ignore[misc]


# ── TestComputeStats ─────────────────────────────────────────────────────


class TestComputeStats:
    def test_empty_records(self) -> None:
        result = compute_stats([])
        assert result.total == 0
        assert result.latency_p50_ms == 0.0
        assert result.top_blocked_tools == []
        assert result.first_timestamp is None

    def test_single_record(self) -> None:
        result = compute_stats([_record(elapsed_ms=5.0)])
        assert result.total == 1
        assert result.allowed == 1
        assert result.latency_p50_ms == 5.0
        assert result.latency_max_ms == 5.0

    def test_all_allowed(self) -> None:
        recs = [_record(elapsed_ms=float(i)) for i in range(1, 6)]
        result = compute_stats(recs)
        assert result.allowed == 5
        assert result.blocked == 0
        assert result.errors == 0
        assert result.latency_max_ms == 5.0

    def test_all_blocked(self) -> None:
        recs = [
            _record(tool="exec", decision="blocked"),
            _record(tool="exec", decision="blocked"),
            _record(tool="write_file", decision="blocked"),
        ]
        result = compute_stats(recs)
        assert result.blocked == 3
        assert result.allowed == 0
        assert result.top_blocked_tools[0] == ("exec", 2)
        assert result.top_blocked_tools[1] == ("write_file", 1)

    def test_mixed_decisions(self) -> None:
        recs = [
            _record(decision="allowed"),
            _record(decision="blocked", tool="exec"),
            _record(decision="error"),
        ]
        result = compute_stats(recs)
        assert result.allowed == 1
        assert result.blocked == 1
        assert result.errors == 1
        assert result.total == 3

    def test_latency_percentiles(self) -> None:
        # 100 records with latencies 1.0 to 100.0
        recs = [_record(elapsed_ms=float(i)) for i in range(1, 101)]
        result = compute_stats(recs)
        assert 49.0 <= result.latency_p50_ms <= 51.0
        assert 94.0 <= result.latency_p95_ms <= 96.0
        assert 98.0 <= result.latency_p99_ms <= 100.0
        assert result.latency_max_ms == 100.0

    @pytest.mark.parametrize(
        ("top_n", "expected_len"),
        [
            (5, 5),
            (2, 2),
            (0, 0),
            (100, 10),  # only 10 distinct tools
        ],
    )
    def test_top_n_limit(self, top_n: int, expected_len: int) -> None:
        recs = [_record(tool=f"tool_{i}", decision="blocked") for i in range(10)]
        result = compute_stats(recs, top_n=top_n)
        assert len(result.top_blocked_tools) == expected_len

    def test_timestamps_ordered(self) -> None:
        recs = [
            _record(ts=datetime(2026, 3, 10, 14, 0, tzinfo=timezone.utc)),
            _record(ts=datetime(2026, 3, 10, 12, 0, tzinfo=timezone.utc)),
            _record(ts=datetime(2026, 3, 10, 16, 0, tzinfo=timezone.utc)),
        ]
        result = compute_stats(recs)
        assert result.first_timestamp is not None
        assert result.last_timestamp is not None
        assert result.first_timestamp < result.last_timestamp
        assert result.first_timestamp.hour == 12
        assert result.last_timestamp.hour == 16

    @pytest.mark.parametrize("bad_value", [float("nan"), float("inf"), float("-inf")])
    def test_nan_inf_latencies_excluded(self, bad_value: float) -> None:
        recs = [_record(elapsed_ms=10.0), _record(elapsed_ms=bad_value)]
        result = compute_stats(recs)
        assert result.total == 2
        assert math.isfinite(result.latency_p50_ms)
        assert math.isfinite(result.latency_max_ms)
        assert result.latency_max_ms == 10.0

    def test_all_nan_latencies(self) -> None:
        recs = [_record(elapsed_ms=float("nan")), _record(elapsed_ms=float("inf"))]
        result = compute_stats(recs)
        assert result.total == 2
        assert result.latency_p50_ms == 0.0
        assert result.latency_max_ms == 0.0

    @pytest.mark.parametrize("top_n", [-1, -100])
    def test_negative_top_n_returns_empty(self, top_n: int) -> None:
        recs = [_record(tool="exec", decision="blocked")]
        result = compute_stats(recs, top_n=top_n)
        assert result.top_blocked_tools == []


# ── TestParseLog ─────────────────────────────────────────────────────────


class TestParseLog:
    def test_valid_jsonl(self, tmp_path: Path) -> None:
        recs = [_record(), _record(decision="blocked", tool="exec"), _record()]
        _write_jsonl(tmp_path / "gate.jsonl", recs)
        parsed, errors = parse_log(tmp_path / "gate.jsonl")
        assert len(parsed) == 3
        assert errors == 0

    @pytest.mark.parametrize(
        ("corrupt_lines", "expected_records", "expected_errors"),
        [
            (["NOT VALID JSON\n", "{}\n"], 2, 2),
            (["null\n"], 2, 1),
            (["[]\n", '{"bad": true}\n'], 2, 2),
        ],
        ids=["plain-text-and-empty-obj", "null-literal", "array-and-wrong-schema"],
    )
    def test_corrupt_lines_skipped(
        self,
        tmp_path: Path,
        corrupt_lines: list[str],
        expected_records: int,
        expected_errors: int,
    ) -> None:
        log_file = tmp_path / "gate.jsonl"
        with log_file.open("w") as fh:
            fh.write(_record().model_dump_json() + "\n")
            for line in corrupt_lines:
                fh.write(line)
            fh.write(_record().model_dump_json() + "\n")
        parsed, errors = parse_log(log_file)
        assert len(parsed) == expected_records
        assert errors == expected_errors

    def test_empty_file(self, tmp_path: Path) -> None:
        log_file = tmp_path / "gate.jsonl"
        log_file.write_text("")
        parsed, errors = parse_log(log_file)
        assert len(parsed) == 0
        assert errors == 0

    def test_max_lines_cap(self, tmp_path: Path) -> None:
        recs = [_record() for _ in range(10)]
        _write_jsonl(tmp_path / "gate.jsonl", recs)
        parsed, errors = parse_log(tmp_path / "gate.jsonl", max_lines=5)
        assert len(parsed) == 5
        assert errors == 0

    def test_blank_lines_ignored(self, tmp_path: Path) -> None:
        log_file = tmp_path / "gate.jsonl"
        with log_file.open("w") as fh:
            fh.write("\n")
            fh.write(_record().model_dump_json() + "\n")
            fh.write("\n\n")
            fh.write(_record().model_dump_json() + "\n")
        parsed, errors = parse_log(log_file)
        assert len(parsed) == 2
        assert errors == 0

    def test_nonexistent_file(self) -> None:
        with pytest.raises(FileNotFoundError):
            parse_log(Path("/tmp/nonexistent_munio.gate_log_xyz.jsonl"))


# ── TestStatsCli ─────────────────────────────────────────────────────────


class TestStatsCli:
    @pytest.fixture
    def cli(self) -> tuple[CliRunner, object]:

        return CliRunner(), app

    def test_stats_with_valid_log(self, tmp_path: Path, cli: tuple) -> None:
        runner, app = cli
        recs = [
            _record(decision="allowed"),
            _record(decision="blocked", tool="exec"),
            _record(decision="allowed"),
        ]
        _write_jsonl(tmp_path / "gate.jsonl", recs)
        result = runner.invoke(app, ["stats", str(tmp_path / "gate.jsonl")])
        assert result.exit_code == 0

    def test_stats_json_output(self, tmp_path: Path, cli: tuple) -> None:
        runner, app = cli
        recs = [_record(), _record(decision="blocked", tool="exec")]
        _write_jsonl(tmp_path / "gate.jsonl", recs)
        result = runner.invoke(app, ["stats", str(tmp_path / "gate.jsonl"), "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["total"] == 2
        assert data["allowed"] == 1
        assert data["blocked"] == 1

    def test_stats_empty_log(self, tmp_path: Path, cli: tuple) -> None:
        runner, app = cli
        log_file = tmp_path / "gate.jsonl"
        log_file.write_text("")
        result = runner.invoke(app, ["stats", str(log_file)])
        assert result.exit_code == 0

    def test_stats_nonexistent_file(self, cli: tuple) -> None:
        runner, app = cli
        result = runner.invoke(app, ["stats", "/tmp/nonexistent_xyz.jsonl"])
        assert result.exit_code != 0

    def test_stats_top_flag(self, tmp_path: Path, cli: tuple) -> None:
        runner, app = cli
        recs = [_record(tool=f"tool_{i}", decision="blocked") for i in range(10)]
        _write_jsonl(tmp_path / "gate.jsonl", recs)
        result = runner.invoke(app, ["stats", str(tmp_path / "gate.jsonl"), "--json", "--top", "3"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert len(data["top_blocked_tools"]) == 3

    def test_stats_corrupt_log_warns(self, tmp_path: Path, cli: tuple) -> None:
        runner, app = cli
        log_file = tmp_path / "gate.jsonl"
        with log_file.open("w") as fh:
            fh.write(_record().model_dump_json() + "\n")
            fh.write("BAD LINE\n")
        result = runner.invoke(app, ["stats", str(log_file)])
        assert result.exit_code == 0

    def test_stats_all_corrupt(self, tmp_path: Path, cli: tuple) -> None:
        runner, app = cli
        log_file = tmp_path / "gate.jsonl"
        log_file.write_text("BAD\nALSO BAD\n")
        result = runner.invoke(app, ["stats", str(log_file)])
        assert result.exit_code != 0
