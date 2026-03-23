"""HTTP API server: language-agnostic verification over HTTP.

Endpoints (all under /v1/ prefix):
  POST /v1/verify                      Universal action verification
  POST /v1/openclaw/before-tool-call   OpenClaw-native hook format
  GET  /v1/health                      Health check (k8s probes)
  GET  /v1/packs                       List available constraint packs

Start via CLI:
  munio serve --pack generic --pack openclaw

Requires: pip install "munio[server]" (fastapi + uvicorn).
"""

from __future__ import annotations

import logging
import re
from contextlib import asynccontextmanager
from pathlib import Path
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, ConfigDict, Field

from munio.guard import Guard
from munio.models import (
    ConstraintConfig,
    MunioError,
    VerificationMode,
)

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

__all__ = [
    "ServerConfig",
    "create_server",
]

logger = logging.getLogger(__name__)

_PACK_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]*$")
_MAX_REQUEST_BODY = 1_048_576  # 1MB, consistent with CLI/constraint limits


# ── Server configuration ──────────────────────────────────────────────


class ServerConfig(BaseModel):
    """Server configuration (frozen after construction)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    constraints_dir: str = "constraints"
    default_packs: list[str] = Field(default_factory=lambda: ["generic"])
    mode: VerificationMode = VerificationMode.ENFORCE
    include_violation_values: bool = True
    cors_origins: list[str] = Field(default_factory=list)


# ── API request/response models (extra="ignore" for forward-compat) ───


class VerifyRequest(BaseModel):
    """Universal verify endpoint request."""

    model_config = ConfigDict(extra="ignore")

    tool: str
    args: dict[str, Any] = Field(default_factory=dict)
    agent_id: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    constraints: str | None = Field(
        default=None,
        min_length=1,
        max_length=64,
        pattern=r"^[a-z0-9][a-z0-9_-]*$",
    )
    # NOTE: mode override removed — allowing callers to set mode=disabled
    # would bypass all security checks. Mode is server-side config only.


class OpenClawEvent(BaseModel):
    """OpenClaw before_tool_call event payload."""

    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    tool_name: str = Field(alias="toolName")
    params: dict[str, Any] = Field(default_factory=dict)


class OpenClawContext(BaseModel):
    """OpenClaw hook context."""

    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    agent_id: str | None = Field(default=None, alias="agentId")
    session_key: str | None = Field(default=None, alias="sessionKey")
    tool_name: str = Field(alias="toolName")


class OpenClawRequest(BaseModel):
    """OpenClaw before_tool_call hook request."""

    model_config = ConfigDict(extra="ignore")

    event: OpenClawEvent
    ctx: OpenClawContext


class OpenClawResponse(BaseModel):
    """OpenClaw before_tool_call hook response."""

    block: bool = False
    block_reason: str | None = Field(default=None, serialization_alias="blockReason")


# ── ASGI middleware: request body size limit ───────────────────────────


class _BodyTooLargeError(Exception):
    """Sentinel raised when chunked body exceeds size limit."""


class _RequestSizeLimitMiddleware:
    """ASGI middleware to reject oversized request bodies (413).

    Enforces the limit for both Content-Length and chunked requests.
    """

    __slots__ = ("_app", "_max_size")

    def __init__(self, app: Any, max_size: int = _MAX_REQUEST_BODY) -> None:
        self._app = app
        self._max_size = max_size

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return

        content_length = _get_content_length(scope)
        if content_length is not None and content_length > self._max_size:
            await _send_413(send)
            return

        # Wrap receive to enforce limit for chunked requests (no Content-Length).
        max_size = self._max_size
        bytes_received = 0

        async def _limited_receive() -> dict[str, Any]:
            nonlocal bytes_received
            message: dict[str, Any] = await receive()
            if message.get("type") == "http.request":
                body = message.get("body", b"")
                bytes_received += len(body)
                if bytes_received > max_size:
                    raise _BodyTooLargeError
            return message

        try:
            await self._app(scope, _limited_receive, send)
        except _BodyTooLargeError:
            await _send_413(send)


def _get_content_length(scope: dict[str, Any]) -> int | None:
    """Extract Content-Length from ASGI scope headers."""
    for name, value in scope.get("headers", []):
        if name == b"content-length":
            try:
                return int(value)
            except (ValueError, TypeError):
                return None
    return None


async def _send_413(send: Any) -> None:
    """Send 413 Payload Too Large response."""
    body = b'{"error":"payload_too_large","detail":"Request body exceeds 1MB limit"}'
    await send(
        {
            "type": "http.response.start",
            "status": 413,
            "headers": [
                [b"content-type", b"application/json"],
                [b"content-length", str(len(body)).encode()],
            ],
        }
    )
    await send({"type": "http.response.body", "body": body})


# ── App factory ────────────────────────────────────────────────────────


def _discover_packs(constraints_dir: Path) -> list[str]:
    """Discover available pack names from constraints directory."""
    if not constraints_dir.is_dir():
        return []
    return sorted(
        p.name for p in constraints_dir.iterdir() if p.is_dir() and _PACK_NAME_RE.match(p.name)
    )


def create_server(config: ServerConfig | None = None) -> Any:
    """Create and configure the FastAPI server.

    Preloads all constraint packs at startup. Fails fatally on
    invalid configuration (missing directory, invalid YAML, etc.).

    Args:
        config: Server configuration. Defaults to ServerConfig().

    Returns:
        FastAPI application instance.

    Raises:
        ImportError: If fastapi is not installed.
        RuntimeError: If constraints directory is missing or empty.
    """
    from fastapi import FastAPI, Request, Response
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.responses import JSONResponse

    cfg = config or ServerConfig()
    dir_path = Path(cfg.constraints_dir)
    if not dir_path.is_absolute():
        dir_path = Path.cwd() / dir_path

    # State populated during lifespan
    guards: dict[str, Guard] = {}
    default_guard: Guard | None = None
    available_packs: set[str] = set()

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        nonlocal guards, default_guard, available_packs

        # 1. Validate constraints directory
        if not dir_path.is_dir():
            msg = f"Constraints directory not found: {dir_path}"
            raise RuntimeError(msg)

        # 2. Discover packs
        pack_names = _discover_packs(dir_path)
        if not pack_names:
            msg = f"No constraint packs found in {dir_path}"
            raise RuntimeError(msg)

        # 3. Validate default packs exist
        for pack in cfg.default_packs:
            if pack not in pack_names:
                msg = f"Default pack {pack!r} not found. Available: {pack_names}"
                raise RuntimeError(msg)

        # 4. Create shared temporal store (one store across all Guards)
        from munio._temporal import InMemoryTemporalStore

        shared_store = InMemoryTemporalStore()

        # 5. Build Guard per pack (validates YAML at startup)
        for pack_name in pack_names:
            pack_cfg = ConstraintConfig(
                mode=cfg.mode,
                constraint_packs=[pack_name],
                include_violation_values=cfg.include_violation_values,
            )
            guards[pack_name] = Guard(
                config=pack_cfg, constraints_dir=dir_path, temporal_store=shared_store
            )

        # 6. Build default Guard (server's default packs)
        default_cfg = ConstraintConfig(
            mode=cfg.mode,
            constraint_packs=list(cfg.default_packs),
            include_violation_values=cfg.include_violation_values,
        )
        default_guard = Guard(
            config=default_cfg, constraints_dir=dir_path, temporal_store=shared_store
        )
        available_packs = set(pack_names)

        logger.info(
            "Server ready: %d pack(s) loaded from %s (default: %s)",
            len(pack_names),
            dir_path,
            cfg.default_packs,
        )
        yield

    from munio import __version__

    app = FastAPI(
        title="munio",
        description="Agent Safety Platform — pre-execution verification for AI agents.",
        version=__version__,
        lifespan=lifespan,
    )

    # Middleware stack (last added = outermost = runs first):
    # 1. Request size limit (outermost — reject before any processing)
    # 2. CORS (must wrap request handlers to add response headers)
    app.add_middleware(_RequestSizeLimitMiddleware, max_size=_MAX_REQUEST_BODY)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=cfg.cors_origins,
        allow_credentials=False,
        allow_methods=["GET", "POST"],
        allow_headers=["*"],
    )

    # ── Endpoints ──

    @app.get("/v1/health")
    async def health() -> dict[str, Any]:
        from munio import __version__

        return {
            "status": "ok",
            "version": __version__,
            "packs_loaded": len(available_packs),
        }

    @app.get("/v1/packs")
    async def packs() -> dict[str, Any]:
        return {"packs": sorted(available_packs)}

    @app.post("/v1/verify")
    async def verify(req: VerifyRequest) -> Response:
        # Select guard
        guard = _resolve_guard(req.constraints, guards, default_guard, available_packs)

        # Build action dict
        action_dict: dict[str, Any] = {
            "tool": req.tool,
            "args": req.args,
        }
        if req.agent_id is not None:
            action_dict["agent_id"] = req.agent_id
        if req.metadata:
            action_dict["metadata"] = req.metadata

        # Verify
        try:
            result = await guard.acheck(action_dict)
        except MunioError as exc:
            logger.error("Verification error: %s", exc)
            return JSONResponse(
                status_code=422,
                content={"error": "verification_error", "detail": "Verification failed"},
            )

        return Response(
            content=result.model_dump_json(indent=2),
            media_type="application/json",
        )

    @app.post("/v1/openclaw/before-tool-call")
    async def openclaw_before_tool_call(req: OpenClawRequest) -> Response:
        if default_guard is None:
            raise RuntimeError("Server not initialized")

        # Map OpenClaw format → Action dict
        action_dict: dict[str, Any] = {
            "tool": req.event.tool_name,
            "args": req.event.params,
        }
        if req.ctx.agent_id is not None:
            action_dict["agent_id"] = req.ctx.agent_id
        metadata: dict[str, Any] = {}
        if req.ctx.session_key is not None:
            metadata["session_key"] = req.ctx.session_key
        if metadata:
            action_dict["metadata"] = metadata

        # Verify using default guard (openclaw pack)
        try:
            result = await default_guard.acheck(action_dict)
        except MunioError as exc:
            logger.error("Verification error for OpenClaw hook: %s", exc)
            # Fail-closed: block on internal errors
            resp = OpenClawResponse(
                block=True,
                block_reason="munio internal error",
            )
            return Response(
                content=resp.model_dump_json(by_alias=True),
                media_type="application/json",
            )

        # Build response
        if result.allowed:
            resp = OpenClawResponse(block=False)
        else:
            reasons = [v.message for v in result.violations[:3]]
            if len(result.violations) > 3:
                reasons.append(f"(+{len(result.violations) - 3} more)")
            resp = OpenClawResponse(
                block=True,
                block_reason="; ".join(reasons),
            )

        return Response(
            content=resp.model_dump_json(by_alias=True),
            media_type="application/json",
        )

    # ── Exception handlers ──

    @app.exception_handler(MunioError)
    async def munio_error_handler(request: Request, exc: MunioError) -> JSONResponse:
        logger.error("Verification error: %s", exc)
        return JSONResponse(
            status_code=422,
            content={"error": "verification_error", "detail": "Verification failed"},
        )

    @app.exception_handler(Exception)
    async def generic_error_handler(request: Request, exc: Exception) -> JSONResponse:
        logger.exception("Unexpected error: %s", exc)
        return JSONResponse(
            status_code=500,
            content={"error": "internal_error", "detail": "Internal server error"},
        )

    return app


def _resolve_guard(
    pack_name: str | None,
    guards: dict[str, Guard],
    default_guard: Guard | None,
    available_packs: set[str],
) -> Guard:
    """Resolve guard for request, raising HTTPException on invalid pack."""
    from fastapi import HTTPException

    if pack_name is None:
        if default_guard is None:
            raise RuntimeError("Server not initialized")
        return default_guard

    if pack_name not in available_packs:
        raise HTTPException(
            status_code=400,
            detail=f"Pack {pack_name!r} not found",
        )

    return guards[pack_name]
