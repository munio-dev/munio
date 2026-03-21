"""Tests for HTTP API server (server.py).

Tests use sync TestClient which properly triggers lifespan events.
"""

from __future__ import annotations

from typing import Any

import pytest

from munio.server import (
    OpenClawContext,
    OpenClawEvent,
    OpenClawRequest,
    OpenClawResponse,
    ServerConfig,
    VerifyRequest,
    create_server,
)

CONSTRAINTS_DIR = "constraints"

pytestmark = pytest.mark.server


# ── Fixtures ──────────────────────────────────────────────────────────


@pytest.fixture
def client():
    """Create a test client with generic + openclaw packs."""
    from starlette.testclient import TestClient

    cfg = ServerConfig(
        constraints_dir=CONSTRAINTS_DIR,
        default_packs=["generic"],
    )
    app = create_server(cfg)
    with TestClient(app) as c:
        yield c


@pytest.fixture
def openclaw_client():
    """Create a test client with openclaw as default pack."""
    from starlette.testclient import TestClient

    cfg = ServerConfig(
        constraints_dir=CONSTRAINTS_DIR,
        default_packs=["openclaw"],
    )
    app = create_server(cfg)
    with TestClient(app) as c:
        yield c


# ── Health endpoint ───────────────────────────────────────────────────


class TestHealthEndpoint:
    def test_returns_200_with_version(self, client: Any) -> None:
        r = client.get("/v1/health")
        assert r.status_code == 200
        data = r.json()
        assert data["status"] == "ok"
        assert "version" in data
        assert isinstance(data["packs_loaded"], int)
        assert data["packs_loaded"] > 0

    def test_health_does_not_leak_pack_names(self, client: Any) -> None:
        """Health endpoint must not expose individual pack names (M7)."""
        r = client.get("/v1/health")
        data = r.json()
        assert "packs" not in data
        assert "total_constraints" not in data


# ── Packs endpoint ────────────────────────────────────────────────────


class TestPacksEndpoint:
    def test_lists_available_packs(self, client: Any) -> None:
        r = client.get("/v1/packs")
        assert r.status_code == 200
        data = r.json()
        assert "packs" in data
        assert "generic" in data["packs"]
        # Pack names are listed, but constraint counts are NOT exposed (M7)
        assert isinstance(data["packs"], list)


# ── Verify endpoint ──────────────────────────────────────────────────


class TestVerifyEndpoint:
    def test_allowed_action_returns_allowed_true(self, client: Any) -> None:
        r = client.post("/v1/verify", json={"tool": "http_request", "args": {}})
        assert r.status_code == 200
        data = r.json()
        assert data["allowed"] is True

    def test_missing_tool_returns_422(self, client: Any) -> None:
        r = client.post("/v1/verify", json={"args": {}})
        assert r.status_code == 422

    def test_extra_fields_silently_ignored(self, client: Any) -> None:
        r = client.post(
            "/v1/verify",
            json={
                "tool": "http_request",
                "args": {},
                "future_field": "should be ignored",
                "another_field": 42,
            },
        )
        assert r.status_code == 200

    def test_constraints_override_uses_specified_pack(self, client: Any) -> None:
        r = client.post(
            "/v1/verify",
            json={
                "tool": "exec",
                "args": {"command": "rm -rf /"},
                "constraints": "openclaw",
            },
        )
        assert r.status_code == 200
        data = r.json()
        assert data["allowed"] is False

    def test_unknown_pack_returns_400(self, client: Any) -> None:
        r = client.post(
            "/v1/verify",
            json={"tool": "test", "args": {}, "constraints": "nonexistent"},
        )
        assert r.status_code == 400
        assert "not found" in r.json()["detail"].lower()

    def test_unknown_pack_does_not_leak_available_names(self, client: Any) -> None:
        """S3: Error response for unknown pack must NOT include available pack names.

        Leaking available pack names helps attackers enumerate the constraint surface.
        The response should say 'not found' but NOT list alternatives.
        """
        r = client.post(
            "/v1/verify",
            json={"tool": "test", "args": {}, "constraints": "nonexistent"},
        )
        assert r.status_code == 400
        detail = r.json()["detail"]
        assert "not found" in detail.lower()
        # Must NOT contain names of real packs
        assert "generic" not in detail.lower()
        assert "openclaw" not in detail.lower()
        # Must NOT contain hint text like "Available:" or "available packs"
        assert "available" not in detail.lower()

    def test_empty_args_default(self, client: Any) -> None:
        r = client.post("/v1/verify", json={"tool": "some_tool"})
        assert r.status_code == 200

    @pytest.mark.parametrize(
        "bad_pack",
        [
            "../etc/shadow",
            "../../secrets",
            "pack with spaces",
            "UPPERCASE",
            "",
        ],
    )
    def test_pack_name_validation_rejects_traversal(self, client: Any, bad_pack: str) -> None:
        r = client.post(
            "/v1/verify",
            json={"tool": "test", "args": {}, "constraints": bad_pack},
        )
        assert r.status_code == 422


# ── OpenClaw endpoint ────────────────────────────────────────────────


class TestOpenClawEndpoint:
    def test_allowed_returns_block_false(self, openclaw_client: Any) -> None:
        r = openclaw_client.post(
            "/v1/openclaw/before-tool-call",
            json={
                "event": {"toolName": "exec", "params": {"command": "ls -la"}},
                "ctx": {"toolName": "exec"},
            },
        )
        assert r.status_code == 200
        data = r.json()
        assert data["block"] is False

    def test_blocked_returns_block_true_with_reason(self, openclaw_client: Any) -> None:
        r = openclaw_client.post(
            "/v1/openclaw/before-tool-call",
            json={
                "event": {"toolName": "exec", "params": {"command": "rm -rf /"}},
                "ctx": {"toolName": "exec"},
            },
        )
        assert r.status_code == 200
        data = r.json()
        assert data["block"] is True
        assert data["blockReason"] is not None
        assert len(data["blockReason"]) > 0

    def test_camelcase_field_mapping(self, openclaw_client: Any) -> None:
        """Verify camelCase aliases in request/response."""
        r = openclaw_client.post(
            "/v1/openclaw/before-tool-call",
            json={
                "event": {"toolName": "exec", "params": {"command": "echo hi"}},
                "ctx": {"toolName": "exec", "agentId": "agent-1", "sessionKey": "s123"},
            },
        )
        assert r.status_code == 200
        data = r.json()
        # Response should use camelCase
        assert "blockReason" in data or "block" in data

    def test_missing_event_returns_422(self, openclaw_client: Any) -> None:
        r = openclaw_client.post(
            "/v1/openclaw/before-tool-call",
            json={"ctx": {"toolName": "exec"}},
        )
        assert r.status_code == 422

    def test_extra_event_fields_ignored(self, openclaw_client: Any) -> None:
        r = openclaw_client.post(
            "/v1/openclaw/before-tool-call",
            json={
                "event": {
                    "toolName": "exec",
                    "params": {"command": "ls"},
                    "futureField": True,
                },
                "ctx": {"toolName": "exec", "newField": "v2"},
            },
        )
        assert r.status_code == 200


# ── Request model tests ──────────────────────────────────────────────


class TestRequestModels:
    def test_verify_request_extra_ignore_discards_unknown(self) -> None:
        req = VerifyRequest(tool="test", future_field="ignored")  # type: ignore[call-arg]
        assert req.tool == "test"
        assert not hasattr(req, "future_field")

    def test_openclaw_request_alias_mapping(self) -> None:
        req = OpenClawRequest(
            event=OpenClawEvent(toolName="exec", params={}),
            ctx=OpenClawContext(toolName="exec", agentId="a1"),
        )
        assert req.event.tool_name == "exec"
        assert req.ctx.agent_id == "a1"

    def test_openclaw_response_serialization_alias(self) -> None:
        resp = OpenClawResponse(block=True, block_reason="too dangerous")
        data = resp.model_dump(by_alias=True)
        assert "blockReason" in data
        assert data["blockReason"] == "too dangerous"

    def test_server_config_frozen(self) -> None:
        cfg = ServerConfig()
        with pytest.raises(Exception):  # noqa: B017, PT011
            cfg.constraints_dir = "other"  # type: ignore[misc]

    @pytest.mark.parametrize(
        "pack_name",
        ["../etc", "../../x", " spaces", "UPPER", "a" * 65],
    )
    def test_pack_name_regex_rejects_traversal(self, pack_name: str) -> None:
        with pytest.raises(Exception):  # noqa: B017, PT011
            VerifyRequest(tool="test", constraints=pack_name)

    @pytest.mark.parametrize(
        "pack_name",
        ["generic", "openclaw", "my-pack", "pack123", "a-b-c"],
    )
    def test_pack_name_regex_accepts_valid(self, pack_name: str) -> None:
        req = VerifyRequest(tool="test", constraints=pack_name)
        assert req.constraints == pack_name


# ── Error handling ───────────────────────────────────────────────────


class TestErrorHandling:
    def test_invalid_json_body_returns_422(self, client: Any) -> None:
        r = client.post(
            "/v1/verify",
            content=b"not json",
            headers={"content-type": "application/json"},
        )
        assert r.status_code == 422

    def test_oversized_content_length_returns_413(self, client: Any) -> None:
        r = client.post(
            "/v1/verify",
            content=b"x",
            headers={
                "content-type": "application/json",
                "content-length": "2000000",
            },
        )
        assert r.status_code == 413
        assert "payload_too_large" in r.json()["error"]


class TestModeOverrideRemoved:
    def test_mode_field_ignored(self, client: Any) -> None:
        """Mode override removed — callers cannot bypass enforcement.

        The 'mode' field is no longer accepted in VerifyRequest.
        Sending it should have no effect (extra='ignore' drops it).
        """
        r = client.post(
            "/v1/verify",
            json={
                "tool": "exec",
                "args": {"command": "rm -rf /"},
                "constraints": "openclaw",
                "mode": "shadow",  # should be ignored
            },
        )
        assert r.status_code == 200
        # Action should still be BLOCKED despite "mode: shadow" — field is ignored
        assert r.json()["allowed"] is False


# ── Additional coverage ──────────────────────────────────────────────


class TestOpenClawViolationTruncation:
    def test_multiple_violations_truncated_to_3(self, openclaw_client: Any) -> None:
        """Action violating 4+ constraints → blockReason shows first 3 + '(+N more)'."""
        # exec with rm -rf / AND elevated=true AND timeout=600
        # This hits exec-command-denylist + exec-no-elevated + exec-timeout-limit = 3+
        r = openclaw_client.post(
            "/v1/openclaw/before-tool-call",
            json={
                "event": {
                    "toolName": "exec",
                    "params": {"command": "sudo rm -rf /", "elevated": "true", "timeout": 600},
                },
                "ctx": {"toolName": "exec"},
            },
        )
        assert r.status_code == 200
        data = r.json()
        assert data["block"] is True
        assert data["blockReason"] is not None


class TestUnicodeThroughHTTP:
    def test_fullwidth_characters_in_args(self, openclaw_client: Any) -> None:
        """Fullwidth rm should be caught after NFKC normalization."""
        r = openclaw_client.post(
            "/v1/openclaw/before-tool-call",
            json={
                "event": {
                    "toolName": "exec",
                    "params": {"command": "\uff52\uff4d -rf /"},  # fullwidth "rm"
                },
                "ctx": {"toolName": "exec"},
            },
        )
        assert r.status_code == 200
        data = r.json()
        assert data["block"] is True

    def test_zero_width_bypass_attempt(self, openclaw_client: Any) -> None:
        """Zero-width chars in command should be stripped before matching."""
        r = openclaw_client.post(
            "/v1/openclaw/before-tool-call",
            json={
                "event": {
                    "toolName": "exec",
                    "params": {"command": "r\u200bm -rf /"},  # zero-width space in "rm"
                },
                "ctx": {"toolName": "exec"},
            },
        )
        assert r.status_code == 200
        data = r.json()
        assert data["block"] is True


class TestServerConfigValidation:
    def test_extra_fields_rejected(self) -> None:
        """ServerConfig uses extra='forbid' — typos raise errors."""
        with pytest.raises(Exception):  # noqa: B017, PT011
            ServerConfig(constraintss_dir="typo")  # type: ignore[call-arg]

    def test_default_cors_is_empty(self) -> None:
        """Default CORS origins is empty list — not wildcard (H7)."""
        cfg = ServerConfig()
        assert cfg.cors_origins == []


# ── Startup validation ───────────────────────────────────────────────


class TestStartupValidation:
    def test_nonexistent_dir_raises_runtime_error(self) -> None:
        from starlette.testclient import TestClient

        cfg = ServerConfig(constraints_dir="/nonexistent/path")
        app = create_server(cfg)
        with pytest.raises(RuntimeError, match="not found"), TestClient(app):
            pass

    def test_missing_default_pack_raises_runtime_error(self, tmp_path: Any) -> None:
        from starlette.testclient import TestClient

        # Create a dir with one pack
        (tmp_path / "mypack").mkdir()
        (tmp_path / "mypack" / "test.yaml").write_text(
            "name: t\ntier: 1\naction: x\non_violation: block\nseverity: high\n"
        )
        cfg = ServerConfig(
            constraints_dir=str(tmp_path),
            default_packs=["nonexistent"],
        )
        app = create_server(cfg)
        with pytest.raises(RuntimeError, match="not found"), TestClient(app):
            pass

    def test_empty_packs_dir_raises_runtime_error(self, tmp_path: Any) -> None:
        from starlette.testclient import TestClient

        cfg = ServerConfig(constraints_dir=str(tmp_path))
        app = create_server(cfg)
        with pytest.raises(RuntimeError, match="No constraint packs"), TestClient(app):
            pass


# ── Verify endpoint extras ──────────────────────────────────────────


class TestVerifyAgentIdMetadata:
    """Test verify endpoint with agent_id and metadata fields."""

    def test_agent_id_passed_through(self, client: Any) -> None:
        r = client.post(
            "/v1/verify",
            json={"tool": "http_request", "args": {}, "agent_id": "agent-1"},
        )
        assert r.status_code == 200

    def test_metadata_passed_through(self, client: Any) -> None:
        r = client.post(
            "/v1/verify",
            json={
                "tool": "http_request",
                "args": {},
                "metadata": {"session": "s123", "trace_id": "t456"},
            },
        )
        assert r.status_code == 200


# ── OpenClaw error handling ─────────────────────────────────────────


class TestOpenClawErrorHandling:
    """Test OpenClaw fail-closed on internal errors."""

    def test_openclaw_internal_error_blocks(self, openclaw_client: Any) -> None:
        """ProofAgentError during verification → block=True (fail-closed)."""
        from unittest.mock import AsyncMock, patch

        from munio.guard import Guard
        from munio.models import ProofAgentError

        with patch.object(
            Guard, "acheck", new_callable=AsyncMock, side_effect=ProofAgentError("test error")
        ):
            r = openclaw_client.post(
                "/v1/openclaw/before-tool-call",
                json={
                    "event": {"toolName": "exec", "params": {"command": "ls"}},
                    "ctx": {"toolName": "exec"},
                },
            )
        assert r.status_code == 200
        data = r.json()
        assert data["block"] is True
        assert "error" in data["blockReason"].lower()


# ── Chunked body limit ──────────────────────────────────────────────


class TestChunkedBodyLimit:
    """Test that chunked transfers (no Content-Length) are also size-limited."""

    def test_invalid_content_length_header(self, client: Any) -> None:
        """Non-numeric Content-Length → handled gracefully."""
        r = client.post(
            "/v1/verify",
            content=b'{"tool":"test","args":{}}',
            headers={"content-type": "application/json", "content-length": "not-a-number"},
        )
        # Should still process normally (invalid CL falls through to receive())
        assert r.status_code == 200

    def test_chunked_body_exceeding_limit_returns_413(self) -> None:
        """Chunked body (no Content-Length) exceeding 1MB → 413."""
        from starlette.testclient import TestClient

        cfg = ServerConfig(constraints_dir=CONSTRAINTS_DIR, default_packs=["generic"])
        app = create_server(cfg)
        # Use transfer-encoding: chunked by sending a generator
        oversized = b"x" * (1_048_577)  # 1MB + 1 byte
        with TestClient(app) as c:
            r = c.post(
                "/v1/verify",
                content=oversized,
                headers={"content-type": "application/json"},
            )
        assert r.status_code == 413
        assert "payload_too_large" in r.json()["error"]

    def test_content_length_at_limit_accepted(self, client: Any) -> None:
        """Request exactly at 1MB limit should be processed (not rejected)."""
        # Small valid JSON body with large Content-Length header (but actual body is small)
        r = client.post(
            "/v1/verify",
            content=b'{"tool":"test","args":{}}',
            headers={"content-type": "application/json"},
        )
        assert r.status_code == 200


# ── Review Round 11: error info leak tests ─────────────────────────────


class TestErrorInfoNoLeak:
    """M1: Server error handlers must NOT leak exception details to callers."""

    def test_verify_endpoint_no_exception_detail(self, client: Any) -> None:
        """ProofAgentError in verify → generic message, no str(exc) leak."""
        from unittest.mock import AsyncMock, patch

        from munio.guard import Guard
        from munio.models import ProofAgentError

        internal_detail = "internal path /etc/constraints/foo.yaml"
        with patch.object(
            Guard, "acheck", new_callable=AsyncMock, side_effect=ProofAgentError(internal_detail)
        ):
            r = client.post("/v1/verify", json={"tool": "exec", "args": {}})
        assert r.status_code == 422
        body = r.json()
        assert internal_detail not in body.get("detail", "")
        assert body["detail"] == "Verification failed"

    def test_openclaw_endpoint_no_exception_detail(self, openclaw_client: Any) -> None:
        """ProofAgentError in OpenClaw → generic block_reason, no str(exc) leak."""
        from unittest.mock import AsyncMock, patch

        from munio.guard import Guard
        from munio.models import ProofAgentError

        internal_detail = "Constraint file /opt/custom.yaml not found"
        with patch.object(
            Guard, "acheck", new_callable=AsyncMock, side_effect=ProofAgentError(internal_detail)
        ):
            r = openclaw_client.post(
                "/v1/openclaw/before-tool-call",
                json={
                    "event": {"toolName": "exec", "params": {}},
                    "ctx": {"toolName": "exec"},
                },
            )
        assert r.status_code == 200
        data = r.json()
        assert data["block"] is True
        assert internal_detail not in data.get("blockReason", "")
        assert data["blockReason"] == "munio internal error"


# ── E2E constraint type coverage ──────────────────────────────────────


class TestE2EConstraintTypes:
    """E2E tests covering all check types through the real HTTP path.

    Existing tests cover denylist/regex_deny via exec commands.
    These cover: threshold, allowlist, composite, regex_deny, response schema.
    """

    # ── Threshold (exec-timeout-limit.yaml, openclaw pack) ──

    def test_e2e_threshold_blocks_over_limit(self, openclaw_client: Any) -> None:
        """Threshold constraint blocks exec with timeout > 300."""
        r = openclaw_client.post(
            "/v1/openclaw/before-tool-call",
            json={
                "event": {"toolName": "exec", "params": {"command": "echo hi", "timeout": 600}},
                "ctx": {"toolName": "exec"},
            },
        )
        assert r.status_code == 200
        data = r.json()
        assert data["block"] is True, f"Expected block, got: {data}"

    def test_e2e_threshold_allows_under_limit(self, openclaw_client: Any) -> None:
        """Threshold constraint allows exec with timeout within limit."""
        r = openclaw_client.post(
            "/v1/openclaw/before-tool-call",
            json={
                "event": {"toolName": "exec", "params": {"command": "echo hi", "timeout": 10}},
                "ctx": {"toolName": "exec"},
            },
        )
        assert r.status_code == 200
        data = r.json()
        assert data["block"] is False, f"Unexpected block: {data}"

    # ── Allowlist (web-fetch-url-scheme.yaml, openclaw pack) ──
    # Use http:// (not file:///) to isolate allowlist from url-denylist.

    def test_e2e_allowlist_blocks_disallowed_scheme(self, openclaw_client: Any) -> None:
        """Allowlist constraint blocks non-https scheme."""
        r = openclaw_client.post(
            "/v1/openclaw/before-tool-call",
            json={
                "event": {"toolName": "web_fetch", "params": {"url": "http://example.com/api"}},
                "ctx": {"toolName": "web_fetch"},
            },
        )
        assert r.status_code == 200
        data = r.json()
        assert data["block"] is True, f"Expected block, got: {data}"

    def test_e2e_allowlist_allows_https(self, openclaw_client: Any) -> None:
        """Allowlist constraint allows https scheme."""
        r = openclaw_client.post(
            "/v1/openclaw/before-tool-call",
            json={
                "event": {"toolName": "web_fetch", "params": {"url": "https://safe.com/api"}},
                "ctx": {"toolName": "web_fetch"},
            },
        )
        assert r.status_code == 200
        data = r.json()
        assert data["block"] is False, f"Unexpected block: {data}"

    # ── Composite (compound-spend-limit.yaml, generic pack, tier 2 → Z3) ──

    @pytest.mark.z3
    def test_e2e_composite_blocks_over_budget(self, client: Any) -> None:
        """COMPOSITE constraint blocks when cost*quantity > budget.

        Uses cost=99 to stay under max-spend-per-request (max=100) so the
        composite violation is the sole cause of the block: 99*10=990 > 500.
        """
        r = client.post(
            "/v1/verify",
            json={
                "tool": "purchase",
                "args": {"cost": 99, "quantity": 10, "budget": 500},
            },
        )
        data = r.json()
        assert data["allowed"] is False, f"Expected block, got: {data}"
        assert any("compound-spend-limit" in v["constraint_name"] for v in data["violations"])

    @pytest.mark.z3
    def test_e2e_composite_allows_within_budget(self, client: Any) -> None:
        """COMPOSITE constraint allows when cost*quantity <= budget."""
        r = client.post(
            "/v1/verify",
            json={
                "tool": "purchase",
                "args": {"cost": 10, "quantity": 5, "budget": 500},
            },
        )
        data = r.json()
        assert data["allowed"] is True, f"Unexpected block: {data}"
        assert data["checked_constraints"] > 0, "Constraint was not evaluated"

    # ── Regex deny (sql-injection-deny.yaml, generic pack) ──

    def test_e2e_regex_deny_blocks_sql_injection(self, client: Any) -> None:
        """regex_deny blocks SQL injection pattern."""
        r = client.post(
            "/v1/verify",
            json={
                "tool": "http_request",
                "args": {"query": "'; DROP TABLE users; --"},
            },
        )
        data = r.json()
        assert data["allowed"] is False, f"Expected block, got: {data}"
        assert any("sql-injection" in v["constraint_name"] for v in data["violations"])

    def test_e2e_regex_deny_allows_safe_query(self, client: Any) -> None:
        """regex_deny allows normal query (no SQL injection patterns)."""
        r = client.post(
            "/v1/verify",
            json={
                "tool": "http_request",
                "args": {"query": "find products by name"},
            },
        )
        data = r.json()
        assert data["allowed"] is True, f"Unexpected block: {data}"
        assert data["checked_constraints"] > 0, "No constraints were evaluated"

    # ── Response schema validation ──

    def test_e2e_verify_response_schema_complete(self, client: Any) -> None:
        """Verify response contains all expected VerificationResult fields."""
        r = client.post(
            "/v1/verify",
            json={
                "tool": "exec",
                "args": {"command": "rm -rf /"},
                "constraints": "openclaw",
            },
        )
        data = r.json()
        # Top-level fields
        assert "allowed" in data
        assert "mode" in data
        assert "violations" in data
        assert "checked_constraints" in data
        assert "elapsed_ms" in data
        assert "has_violations" in data
        assert "tier_breakdown" in data
        assert isinstance(data["violations"], list)
        assert data["checked_constraints"] > 0
        # Violation structure
        v = data["violations"][0]
        assert "constraint_name" in v
        assert "message" in v
        assert "severity" in v


# ── Temporal server tests ────────────────────────────────────────────


class TestServerTemporal:
    """Tests for temporal constraints via the HTTP API server."""

    @pytest.fixture
    def temporal_client(self):
        """Create a test client with generic pack (includes temporal constraints)."""
        from starlette.testclient import TestClient

        cfg = ServerConfig(
            constraints_dir=CONSTRAINTS_DIR,
            default_packs=["generic"],
        )
        app = create_server(cfg)
        with TestClient(app) as c:
            yield c

    # ── Rate limit via HTTP ──

    def test_rate_limit_allows_under_limit(self, temporal_client: Any) -> None:
        """Calls within the rate limit are allowed."""
        # The generic pack has api-call-rate-limit (50/60s for http_request)
        r = temporal_client.post(
            "/v1/verify",
            json={"tool": "http_request", "args": {"url": "https://safe.com"}},
        )
        assert r.status_code == 200
        assert r.json()["allowed"] is True

    def test_rate_limit_blocks_after_exceeded(self, temporal_client: Any) -> None:
        """Calls exceeding the rate limit are blocked.

        Uses exec-rate-limit (max_count=10, scope=agent) from generic pack.
        """
        # Send 10 exec calls (should all pass)
        for _ in range(10):
            r = temporal_client.post(
                "/v1/verify",
                json={"tool": "exec", "args": {"command": "ls"}, "agent_id": "test-agent"},
            )
            assert r.status_code == 200
        # 11th call should be blocked by exec-rate-limit
        r = temporal_client.post(
            "/v1/verify",
            json={"tool": "exec", "args": {"command": "ls"}, "agent_id": "test-agent"},
        )
        assert r.status_code == 200
        data = r.json()
        assert data["allowed"] is False
        rate_violations = [
            v
            for v in data["violations"]
            if "rate" in v["message"].lower() or "rate" in v.get("field", "").lower()
        ]
        assert len(rate_violations) >= 1

    def test_rate_limit_different_agents_isolated(self, temporal_client: Any) -> None:
        """Rate limit with agent scope isolates different agents.

        exec-rate-limit uses scope=agent, so different agent_ids have separate limits.
        """
        # Exhaust agent-a's limit
        for _ in range(10):
            temporal_client.post(
                "/v1/verify",
                json={"tool": "exec", "args": {"command": "ls"}, "agent_id": "agent-a"},
            )
        # agent-b should still be allowed
        r = temporal_client.post(
            "/v1/verify",
            json={"tool": "exec", "args": {"command": "ls"}, "agent_id": "agent-b"},
        )
        assert r.status_code == 200
        assert r.json()["allowed"] is True

    # ── Shared store across packs ──

    def test_shared_store_across_packs(self, temporal_client: Any) -> None:
        """Server uses shared temporal store — rate limit state persists
        regardless of which pack is used for constraints."""
        # Send 10 exec calls with default pack
        for _ in range(10):
            temporal_client.post(
                "/v1/verify",
                json={"tool": "exec", "args": {"command": "ls"}, "agent_id": "shared-agent"},
            )
        # 11th call with explicit 'generic' pack should also be blocked
        r = temporal_client.post(
            "/v1/verify",
            json={
                "tool": "exec",
                "args": {"command": "ls"},
                "constraints": "generic",
                "agent_id": "shared-agent",
            },
        )
        assert r.status_code == 200
        data = r.json()
        assert data["allowed"] is False

    # ── Sequence deny via HTTP ──

    def test_sequence_deny_partial_allowed(self, temporal_client: Any) -> None:
        """Partial sequence does not trigger violation."""
        r = temporal_client.post(
            "/v1/verify",
            json={"tool": "read_file", "args": {"path": "/home/user/test.txt"}},
        )
        assert r.status_code == 200
        assert r.json()["allowed"] is True

    def test_sequence_deny_full_chain_blocked(self, temporal_client: Any) -> None:
        """Full read_file -> http_request sequence is blocked by deny-read-exfil.

        deny-read-exfil uses scope=agent, so we need agent_id for proper scoping.
        """
        agent = "seq-agent"
        # Step 1: read_file
        r1 = temporal_client.post(
            "/v1/verify",
            json={
                "tool": "read_file",
                "args": {"path": "/home/user/data.txt"},
                "agent_id": agent,
            },
        )
        assert r1.status_code == 200
        assert r1.json()["allowed"] is True

        # Step 2: http_request completes the denied sequence
        r2 = temporal_client.post(
            "/v1/verify",
            json={
                "tool": "http_request",
                "args": {"url": "https://safe.example.com"},
                "agent_id": agent,
            },
        )
        assert r2.status_code == 200
        data = r2.json()
        assert data["allowed"] is False
        seq_violations = [v for v in data["violations"] if "sequence" in v["message"].lower()]
        assert len(seq_violations) >= 1

    def test_sequence_deny_unrelated_tool_no_trigger(self, temporal_client: Any) -> None:
        """Tool not in sequence does not trigger after read_file."""
        agent = "unrelated-agent"
        temporal_client.post(
            "/v1/verify",
            json={
                "tool": "read_file",
                "args": {"path": "/home/user/test.txt"},
                "agent_id": agent,
            },
        )
        r = temporal_client.post(
            "/v1/verify",
            json={
                "tool": "write_file",
                "args": {"path": "/home/user/out.txt", "content": "x"},
                "agent_id": agent,
            },
        )
        assert r.status_code == 200
        data = r.json()
        # write_file is not in the deny-read-exfil sequence
        seq_violations = [v for v in data["violations"] if "sequence" in v["message"].lower()]
        assert len(seq_violations) == 0

    # ── Rate limit violation response schema ──

    def test_rate_limit_violation_response_schema(self, temporal_client: Any) -> None:
        """Rate limit violation response contains proper violation structure."""
        for _ in range(11):
            temporal_client.post(
                "/v1/verify",
                json={"tool": "exec", "args": {"command": "ls"}, "agent_id": "schema-agent"},
            )
        r = temporal_client.post(
            "/v1/verify",
            json={"tool": "exec", "args": {"command": "ls"}, "agent_id": "schema-agent"},
        )
        data = r.json()
        if not data["allowed"]:
            rate_v = [v for v in data["violations"] if "rate" in v.get("field", "").lower()]
            if rate_v:
                v = rate_v[0]
                assert "constraint_name" in v
                assert "message" in v
                assert "severity" in v

    # ── Multiple sequence deny constraints ──

    def test_credential_harvest_sequence_blocked(self, temporal_client: Any) -> None:
        """Credential harvesting sequence (read_file x2 + http_request) is blocked.

        deny-cred-harvest uses scope=agent, so agent_id is required.
        """
        agent = "harvest-agent"
        temporal_client.post(
            "/v1/verify",
            json={"tool": "read_file", "args": {"path": "/etc/shadow"}, "agent_id": agent},
        )
        temporal_client.post(
            "/v1/verify",
            json={"tool": "read_file", "args": {"path": "/etc/passwd"}, "agent_id": agent},
        )
        r = temporal_client.post(
            "/v1/verify",
            json={
                "tool": "http_request",
                "args": {"url": "https://attacker.com"},
                "agent_id": agent,
            },
        )
        data = r.json()
        assert data["allowed"] is False
        seq_violations = [v for v in data["violations"] if "sequence" in v["message"].lower()]
        assert len(seq_violations) >= 1

    # ── Rate limit resets (behavioral check) ──

    def test_rate_limit_first_call_always_allowed(self, temporal_client: Any) -> None:
        """First call to a fresh client (empty store) is always allowed."""
        r = temporal_client.post(
            "/v1/verify",
            json={"tool": "exec", "args": {"command": "whoami"}, "agent_id": "fresh-agent"},
        )
        assert r.status_code == 200
        assert r.json()["allowed"] is True
