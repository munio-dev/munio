"""Bidirectional MCP stdio proxy with tools/call interception.

Spawns the real MCP server as a subprocess, relays all JSON-RPC messages
bidirectionally, and intercepts ``tools/call`` requests for verification.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import math
import sys
from typing import TYPE_CHECKING, Any

from munio.gate.models import GateDecision, InterceptionRecord

if TYPE_CHECKING:
    from collections.abc import Callable

    from munio.gate.interceptor import Interceptor

__all__ = ["run_proxy"]

logger = logging.getLogger(__name__)

# Max line size for asyncio.StreamReader (10 MB).
# Default 64KB is too small for tool calls with large arguments;
# exceeding the limit raises ValueError which kills the interception loop.
_READER_LIMIT = 10 * 1024 * 1024

# M2 fix: Cap blocked_ids set to prevent unbounded memory growth.
# Blocked requests are never forwarded, so server shouldn't know the ID.
# This is defense against a malicious server guessing sequential IDs.
_MAX_BLOCKED_IDS = 10_000

# Cap batch array size to prevent DoS via thousands of tools/call elements.
_MAX_BATCH_SIZE = 100

# R3-F1 fix: Timeout for Guard.check() via run_in_executor.
# If Guard hangs (e.g. Z3 solver loop, custom constraint bug), the proxy
# would block forever. Fail-closed on timeout.
_CHECK_TIMEOUT_S = 30.0

# Type alias: JSON-RPC ID can be int, float, str, or null.
# R2-L1 fix: Use dict (insertion-ordered in Python 3.7+) as ordered set for FIFO eviction.
_JsonRpcId = int | float | str | None
_BlockedIds = dict[int | float | str, None]  # None excluded at add time


def _make_blocked_response(request_id: int | float | str | None, reason: str) -> bytes:
    """Build a JSON-RPC result with isError=true for a blocked tool call.

    M1 fix: reason is sanitized to avoid leaking constraint policy details.
    """
    # M1 fix: Use generic message — don't expose internal violation details to agent
    safe_reason = "Tool call blocked by policy"
    if reason in ("Malformed tools/call request", "Policy violation"):
        safe_reason = reason
    # R2-N3 fix: Non-finite float IDs crash json.dumps (NaN/Inf not valid JSON).
    safe_id: int | float | str | None = request_id
    if isinstance(request_id, float) and not math.isfinite(request_id):
        safe_id = None
    resp: dict[str, Any] = {
        "jsonrpc": "2.0",
        "id": safe_id,
        "result": {
            "content": [{"type": "text", "text": f"Blocked by munio: {safe_reason}"}],
            "isError": True,
        },
    }
    return json.dumps(resp, ensure_ascii=False).encode("utf-8") + b"\n"


def _extract_tool_call(msg: dict[str, Any]) -> tuple[str, dict[str, Any]] | None:
    """Extract (tool_name, arguments) from a tools/call JSON-RPC request.

    Returns None if this is not a tools/call request.
    """
    if msg.get("method") != "tools/call":
        return None
    params = msg.get("params")
    if not isinstance(params, dict):
        return None
    name = params.get("name")
    if not isinstance(name, str):
        return None
    arguments = params.get("arguments")
    if arguments is None:
        arguments = {}
    if not isinstance(arguments, dict):
        # C1 fix: Non-dict arguments (list, string, number) are malformed per MCP spec.
        # Coercing to {} would create a check-vs-use mismatch: Guard checks empty args
        # but the original line with malicious non-dict args gets forwarded to the server.
        # Returning None triggers the fail-closed block path.
        return None
    return name, arguments


def _is_tools_call(msg: dict[str, Any]) -> bool:
    """Check if a message has method == tools/call regardless of params validity."""
    return msg.get("method") == "tools/call"


def _has_id(msg: dict[str, Any]) -> bool:
    """Check if a JSON-RPC message has an 'id' field (is a request, not notification)."""
    return "id" in msg


def _add_blocked_id(blocked_ids: _BlockedIds, request_id: _JsonRpcId) -> None:
    """Add a blocked request ID to the tracking set.

    H4 fix: Never add None — null is not a unique identifier in JSON-RPC 2.0.
    Adding None would cause ALL future null-id server responses to be dropped.
    M3 fix: Normalize bool→int to prevent True==1 / False==0 cross-type collision.
    """
    if request_id is None:
        return
    # R2-N1 fix: Reject non-hashable IDs (dict/list) that would crash dict operations.
    # JSON-RPC 2.0 only allows string, number, or null for id.
    if not isinstance(request_id, (int, float, str)):
        logger.warning("Rejecting non-scalar JSON-RPC ID type: %s", type(request_id).__name__)
        return
    # M3 fix: Normalize bool IDs to int to match Python equality semantics
    if isinstance(request_id, bool):
        request_id = int(request_id)
    # R2-H1 fix: Reject non-finite floats (NaN != NaN breaks set membership)
    if isinstance(request_id, float) and (math.isnan(request_id) or math.isinf(request_id)):
        logger.warning("Rejecting non-finite float ID: %s", request_id)
        return
    # M2 fix: Prevent unbounded growth. Evict oldest half (FIFO order)
    # R2-L1 fix: dict preserves insertion order → true FIFO eviction.
    if len(blocked_ids) >= _MAX_BLOCKED_IDS:
        evict_count = len(blocked_ids) // 2
        keys = list(blocked_ids)[:evict_count]
        for rid in keys:
            del blocked_ids[rid]
        logger.warning(
            "blocked_ids exceeded %d entries, evicted %d oldest", _MAX_BLOCKED_IDS, evict_count
        )
    blocked_ids[request_id] = None


def _is_jsonrpc_response(msg: dict[str, Any]) -> bool:
    """Check if a JSON-RPC message is a response (has id + result or error)."""
    return "id" in msg and ("result" in msg or "error" in msg)


def _should_drop_response(
    msg: Any,
    blocked_ids: _BlockedIds,
) -> tuple[bool, bytes | None]:
    """Check if a server response should be dropped (spoofed for a blocked request).

    H1 fix: filters both "result" AND "error" responses for blocked IDs.
    M7 fix: inspects elements inside batch array responses, rebuilds without spoofed.
    H4 fix: None is never added to blocked_ids (see _add_blocked_id).

    Returns (should_drop, optional_rebuilt_line).
    If should_drop is True, the entire message is dropped.
    If rebuilt_line is not None, the original line should be replaced with it.
    """
    if isinstance(msg, dict) and _is_jsonrpc_response(msg):
        resp_id = msg["id"]
        if resp_id in blocked_ids:
            blocked_ids.pop(resp_id, None)
            logger.warning("Dropped spoofed response for blocked id=%s", resp_id)
            return True, None
    elif isinstance(msg, list):
        # R2-N5 fix: Cap batch response inspection to prevent CPU DoS
        if len(msg) > _MAX_BATCH_SIZE * 10:
            logger.warning(
                "Server batch response too large (%d), forwarding without inspection", len(msg)
            )
            return False, None
        # M7 fix: Filter spoofed elements from batch response array
        filtered: list[Any] = []
        had_spoofed = False
        for element in msg:
            if isinstance(element, dict) and _is_jsonrpc_response(element):
                resp_id = element["id"]
                if resp_id in blocked_ids:
                    blocked_ids.pop(resp_id, None)
                    logger.warning(
                        "Dropped spoofed response in batch for blocked id=%s",
                        resp_id,
                    )
                    had_spoofed = True
                    continue
            filtered.append(element)
        if had_spoofed:
            if not filtered:
                return True, None  # All elements were spoofed — drop entire batch
            # Rebuild batch without spoofed elements
            rebuilt = json.dumps(filtered, ensure_ascii=False).encode("utf-8") + b"\n"
            return False, rebuilt
    return False, None


async def _forward_server_to_agent(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter | None,
    blocked_ids: _BlockedIds,
    *,
    label: str,
) -> None:
    """Forward server stdout to agent, filtering responses for blocked request IDs."""
    try:
        while True:
            try:
                line = await reader.readline()
            except asyncio.LimitOverrunError:
                # R2-M2 fix: Oversized line — discard instead of killing the loop.
                logger.warning("Oversized line from server (>%d bytes), discarding", _READER_LIMIT)
                with contextlib.suppress(asyncio.IncompleteReadError, asyncio.LimitOverrunError):
                    await reader.readuntil(b"\n")
                continue
            if not line:
                break
            if writer is None:
                continue

            # Check if this is a response for a blocked request ID
            if blocked_ids:
                stripped = line.strip()
                if stripped:
                    try:
                        msg = json.loads(stripped)
                        should_drop, rebuilt = _should_drop_response(msg, blocked_ids)
                        if should_drop:
                            continue
                        if rebuilt is not None:
                            # Batch was rebuilt without spoofed elements
                            line = rebuilt
                    except (json.JSONDecodeError, UnicodeDecodeError):
                        pass  # Not JSON — forward as-is

            writer.write(line)
            await writer.drain()
    except (BrokenPipeError, ConnectionResetError):
        logger.debug("%s: pipe closed", label)
    except Exception:
        logger.warning("%s: forward error", label, exc_info=True)


async def _forward_stream(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter | None,
    *,
    label: str,
) -> None:
    """Forward lines from reader to writer until EOF."""
    try:
        while True:
            line = await reader.readline()
            if not line:
                break
            if writer is not None:
                writer.write(line)
                await writer.drain()
    except (BrokenPipeError, ConnectionResetError):
        logger.debug("%s: pipe closed", label)
    except Exception:
        logger.warning("%s: forward error", label, exc_info=True)


def _intercept_single_msg(
    msg: dict[str, Any],
    interceptor: Interceptor,
) -> tuple[bool, bytes | None, GateDecision | None]:
    """Intercept a single JSON-RPC message dict.

    Returns (should_forward, optional_blocked_response_bytes, decision).
    decision is None for non-tools/call or malformed messages.
    """
    # Not a tools/call → forward
    if not _is_tools_call(msg):
        return True, None, None

    # It IS a tools/call — must intercept or fail-closed
    tool_info = _extract_tool_call(msg)
    if tool_info is None:
        # Malformed tools/call (missing params, non-string name, etc.)
        # Fail-closed: block, do NOT forward to server
        request_id = msg.get("id") if _has_id(msg) else None
        if _has_id(msg):
            return False, _make_blocked_response(request_id, "Malformed tools/call request"), None
        # Notification (no id) → block silently (must not respond per JSON-RPC 2.0)
        return False, None, None

    tool_name, arguments = tool_info
    request_id = msg.get("id") if _has_id(msg) else None
    decision = interceptor.check_tool_call(tool_name, arguments)

    if decision.allowed:
        return True, None, decision

    # Blocked
    reason = decision.violations[0] if decision.violations else "Policy violation"
    if _has_id(msg):
        return False, _make_blocked_response(request_id, reason), decision
    # Notification → block silently
    return False, None, decision


async def _read_agent_forward_to_server(
    agent_reader: asyncio.StreamReader,
    server_stdin: asyncio.StreamWriter,
    agent_stdout: asyncio.StreamWriter,
    interceptor: Interceptor,
    log_callback: Callable[[InterceptionRecord], None] | None,
    blocked_ids: _BlockedIds,
) -> None:
    """Read from agent (our stdin), intercept tools/call, forward rest to server."""
    try:
        while True:
            try:
                line = await agent_reader.readline()
            except asyncio.LimitOverrunError:
                # R2-M2 fix: Oversized line (>_READER_LIMIT) — drain and skip
                # instead of killing the entire interception loop.
                logger.warning("Oversized line from agent (>%d bytes), discarding", _READER_LIMIT)
                with contextlib.suppress(asyncio.IncompleteReadError, asyncio.LimitOverrunError):
                    await agent_reader.readuntil(b"\n")
                continue
            if not line:
                # Agent closed stdin — signal server to stop
                try:
                    server_stdin.close()
                    await server_stdin.wait_closed()
                except Exception:  # noqa: S110
                    pass  # Best-effort close on agent disconnect
                break

            # Try to parse as JSON-RPC
            stripped = line.strip()
            if not stripped:
                # Empty line — forward as-is
                server_stdin.write(line)
                await server_stdin.drain()
                continue

            try:
                msg = json.loads(stripped)
            except (json.JSONDecodeError, UnicodeDecodeError):
                # Not JSON — forward as-is (could be protocol framing)
                server_stdin.write(line)
                await server_stdin.drain()
                continue

            # C1 fix: Handle JSON-RPC batch arrays (fail-closed)
            if isinstance(msg, list):
                await _handle_batch(
                    msg,
                    line,
                    server_stdin,
                    agent_stdout,
                    interceptor,
                    log_callback,
                    blocked_ids,
                )
                await server_stdin.drain()
                await agent_stdout.drain()
                continue

            if not isinstance(msg, dict):
                # JSON but not an object or array — forward
                server_stdin.write(line)
                await server_stdin.drain()
                continue

            # Process single message
            await _process_single_message(
                msg,
                line,
                server_stdin,
                agent_stdout,
                interceptor,
                log_callback,
                blocked_ids,
            )

    except (BrokenPipeError, ConnectionResetError):
        logger.debug("agent->server: pipe closed")
    except Exception:
        logger.warning("agent->server: error", exc_info=True)


async def _handle_batch(
    batch: list[Any],
    original_line: bytes,
    server_stdin: asyncio.StreamWriter,
    agent_stdout: asyncio.StreamWriter,
    interceptor: Interceptor,
    log_callback: Callable[[InterceptionRecord], None] | None,
    blocked_ids: _BlockedIds,
) -> None:
    """Handle a JSON-RPC batch request array.

    Intercept each tools/call element. Forward allowed elements,
    send blocked responses for blocked ones.

    H2 fix: async with run_in_executor for Guard checks (consistent with single-message path).
    H3 fix: per-element try/except — one bad element doesn't kill the pipeline.
    """
    if not batch:
        # Empty batch — forward as-is (server returns JSON-RPC "Invalid Request" per spec)
        server_stdin.write(original_line)
        return

    if len(batch) > _MAX_BATCH_SIZE:
        # R2-M3 fix: Send error responses for each request element instead of silent drop.
        logger.warning("Batch too large (%d > %d), rejecting", len(batch), _MAX_BATCH_SIZE)
        for element in batch:
            if isinstance(element, dict) and _has_id(element):
                agent_stdout.write(
                    _make_blocked_response(element.get("id"), "Malformed tools/call request")
                )
        return

    loop = asyncio.get_running_loop()
    allowed_elements: list[Any] = []
    has_tools_calls = False

    for element in batch:
        if not isinstance(element, dict):
            allowed_elements.append(element)
            continue

        if not _is_tools_call(element):
            allowed_elements.append(element)
            continue

        has_tools_calls = True
        try:
            # H2 fix: Run interception in executor to avoid blocking event loop
            # R3-F1 fix: Timeout prevents batch-level hang on a single element.
            should_forward, blocked_response, decision = await asyncio.wait_for(
                loop.run_in_executor(None, _intercept_single_msg, element, interceptor),
                timeout=_CHECK_TIMEOUT_S,
            )
        except TimeoutError:
            # R3-F1 fix: Fail-closed on timeout — block this element, continue batch
            logger.warning("Guard.check() timeout in batch element", exc_info=False)
            request_id = element.get("id") if _has_id(element) else None
            if _has_id(element):
                agent_stdout.write(
                    _make_blocked_response(request_id, "Malformed tools/call request")
                )
                _add_blocked_id(blocked_ids, request_id)
            continue
        except Exception:
            # H3 fix: Fail-closed per element — don't kill pipeline
            logger.warning("Batch element interception error", exc_info=True)
            request_id = element.get("id") if _has_id(element) else None
            if _has_id(element):
                agent_stdout.write(
                    _make_blocked_response(request_id, "Malformed tools/call request")
                )
                _add_blocked_id(blocked_ids, request_id)
            continue

        if should_forward:
            allowed_elements.append(element)
        else:
            # Send blocked response
            if blocked_response is not None:
                agent_stdout.write(blocked_response)
                request_id = element.get("id") if _has_id(element) else None
                _add_blocked_id(blocked_ids, request_id)

        # Log the interception (decision is None for malformed messages)
        if decision is not None:
            _log_interception(element, decision, log_callback)

    # Forward remaining allowed elements
    if allowed_elements:
        if has_tools_calls and len(allowed_elements) < len(batch):
            # Rebuild batch without blocked elements
            rebuilt = json.dumps(allowed_elements, ensure_ascii=False).encode("utf-8") + b"\n"
            server_stdin.write(rebuilt)
        elif not has_tools_calls or len(allowed_elements) == len(batch):
            # No tools/call in batch, or all allowed — forward original
            server_stdin.write(original_line)


def _log_interception(
    msg: dict[str, Any],
    decision: GateDecision,
    log_callback: Callable[[InterceptionRecord], None] | None,
    *,
    tool_name: str | None = None,
) -> None:
    """Log a tool call interception if callback is provided.

    R2-M4 fix: Accept pre-extracted tool_name to avoid re-parsing the message.
    """
    if log_callback is None:
        return
    if tool_name is None:
        tool_info = _extract_tool_call(msg)
        if tool_info is None:
            return
        tool_name = tool_info[0]
    request_id = msg.get("id") if _has_id(msg) else None
    try:
        record = InterceptionRecord.now(
            tool=tool_name,
            decision="allowed" if decision.allowed else "blocked",
            violations=decision.violations,
            elapsed_ms=decision.elapsed_ms,
            jsonrpc_id=request_id,
        )
        log_callback(record)
    except Exception:
        logger.warning("Log callback error", exc_info=True)


async def _process_single_message(
    msg: dict[str, Any],
    line: bytes,
    server_stdin: asyncio.StreamWriter,
    agent_stdout: asyncio.StreamWriter,
    interceptor: Interceptor,
    log_callback: Callable[[InterceptionRecord], None] | None,
    blocked_ids: _BlockedIds,
) -> None:
    """Process a single JSON-RPC message: intercept or forward."""
    # Not a tools/call → forward transparently
    if not _is_tools_call(msg):
        server_stdin.write(line)
        await server_stdin.drain()
        return

    # It IS a tools/call — intercept
    tool_info = _extract_tool_call(msg)
    request_id = msg.get("id") if _has_id(msg) else None
    is_notification = not _has_id(msg)

    if tool_info is None:
        # C2 fix: Malformed tools/call — fail-closed, do NOT forward
        if not is_notification:
            response = _make_blocked_response(request_id, "Malformed tools/call request")
            agent_stdout.write(response)
            await agent_stdout.drain()
        logger.warning("Blocked malformed tools/call (id=%s)", request_id)
        return

    tool_name, arguments = tool_info

    # H7 fix: Run synchronous Guard check in thread to avoid blocking event loop
    # R3-F1 fix: Timeout prevents indefinite hang if Guard is stuck (fail-closed).
    # R3-F2 fix: Catch exceptions for defense-in-depth (same as _handle_batch).
    loop = asyncio.get_running_loop()
    try:
        decision = await asyncio.wait_for(
            loop.run_in_executor(
                None,
                interceptor.check_tool_call,
                tool_name,
                arguments,
            ),
            timeout=_CHECK_TIMEOUT_S,
        )
    except TimeoutError:
        logger.warning("Guard.check() timeout for %s (>%.0fs)", tool_name, _CHECK_TIMEOUT_S)
        decision = GateDecision(
            allowed=False,
            violations=["Verification timeout"],
            elapsed_ms=_CHECK_TIMEOUT_S * 1000,
        )
    except Exception:
        logger.warning("Guard.check() error for %s", tool_name, exc_info=True)
        decision = GateDecision(
            allowed=False,
            violations=["Internal verification error"],
            elapsed_ms=0.0,
        )

    if decision.allowed:
        # Forward to server
        server_stdin.write(line)
        await server_stdin.drain()
        logger.debug("Allowed: %s (%.2fms)", tool_name, decision.elapsed_ms)
    else:
        # Block — send error response back to agent (only for requests, not notifications)
        reason = decision.violations[0] if decision.violations else "Policy violation"
        if not is_notification:
            response = _make_blocked_response(request_id, reason)
            agent_stdout.write(response)
            await agent_stdout.drain()
            # H3 fix: Track blocked ID to filter spoofed server responses
            _add_blocked_id(blocked_ids, request_id)
        # B4 fix: Show constraint violation to operator (stderr) at INFO level.
        # The sanitized message goes to the agent (stdout); the real reason goes to stderr
        # so the developer can see WHY the call was blocked and tune false positives.
        violations_summary = "; ".join(decision.violations[:3]) if decision.violations else reason
        logger.info("Blocked: %s — %s (%.2fms)", tool_name, violations_summary, decision.elapsed_ms)

    # H4 fix: Wrap log_callback in try/except to prevent killing interception loop
    if log_callback is not None:
        try:
            record = InterceptionRecord.now(
                tool=tool_name,
                decision="allowed" if decision.allowed else "blocked",
                violations=decision.violations,
                elapsed_ms=decision.elapsed_ms,
                jsonrpc_id=request_id,
            )
            log_callback(record)
        except Exception:
            logger.warning("Log callback error", exc_info=True)


async def run_proxy(
    command: str,
    args: list[str],
    interceptor: Interceptor,
    *,
    env: dict[str, str] | None = None,
    log_callback: Callable[[InterceptionRecord], None] | None = None,
) -> int:
    """Run the MCP stdio proxy.

    Spawns ``command args`` as a subprocess, relays stdio bidirectionally,
    intercepts tools/call requests for Guard verification.

    Returns the subprocess exit code.
    """
    # Spawn the real MCP server
    try:
        process = await asyncio.create_subprocess_exec(
            command,
            *args,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            limit=_READER_LIMIT,
            env=env,
        )
    except FileNotFoundError:
        logger.error("Command not found: %s", command)
        return 127
    except OSError:
        logger.error("Failed to start server process")
        return 126

    assert process.stdin is not None  # noqa: S101
    assert process.stdout is not None  # noqa: S101
    assert process.stderr is not None  # noqa: S101

    # H3: Shared set of blocked request IDs for response spoofing prevention
    blocked_ids: _BlockedIds = {}

    # H1 fix: Create async reader with explicit large limit
    loop = asyncio.get_running_loop()
    agent_reader = asyncio.StreamReader(limit=_READER_LIMIT)
    await loop.connect_read_pipe(
        lambda: asyncio.StreamReaderProtocol(agent_reader),
        sys.stdin.buffer,
    )

    # Create async writer for our own stdout
    agent_stdout_transport, agent_stdout_protocol = await loop.connect_write_pipe(
        asyncio.streams.FlowControlMixin,
        sys.stdout.buffer,
    )
    agent_stdout = asyncio.StreamWriter(agent_stdout_transport, agent_stdout_protocol, None, loop)

    # Create async writer for our own stderr (for server stderr forwarding)
    agent_stderr_transport, agent_stderr_protocol = await loop.connect_write_pipe(
        asyncio.streams.FlowControlMixin,
        sys.stderr.buffer,
    )
    agent_stderr = asyncio.StreamWriter(agent_stderr_transport, agent_stderr_protocol, None, loop)

    # Three concurrent tasks:
    # 1. agent stdin → (intercept) → server stdin
    # 2. server stdout → (filter blocked IDs) → agent stdout
    # 3. server stderr → agent stderr
    tasks = [
        asyncio.create_task(
            _read_agent_forward_to_server(
                agent_reader,
                process.stdin,
                agent_stdout,
                interceptor,
                log_callback,
                blocked_ids,
            ),
            name="agent->server",
        ),
        asyncio.create_task(
            _forward_server_to_agent(
                process.stdout,
                agent_stdout,
                blocked_ids,
                label="server->agent",
            ),
            name="server->agent",
        ),
        asyncio.create_task(
            _forward_stream(process.stderr, agent_stderr, label="server-stderr"),
            name="server-stderr",
        ),
    ]

    # Wait for all tasks or server process to exit
    _done, pending = await asyncio.wait(
        [*tasks, asyncio.create_task(process.wait(), name="process-wait")],
        return_when=asyncio.FIRST_COMPLETED,
    )

    # H5 fix: Only suppress CancelledError during teardown, log others
    for task in pending:
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        except Exception:
            logger.debug("Task %s cleanup error", task.get_name(), exc_info=True)

    # Ensure process is terminated
    if process.returncode is None:
        try:
            process.terminate()
            await asyncio.wait_for(process.wait(), timeout=5.0)
        except (TimeoutError, ProcessLookupError):
            process.kill()
            await process.wait()

    rc = process.returncode if process.returncode is not None else 0
    # Negative return code = killed by signal (e.g. SIGTERM during cleanup).
    # This is expected — the proxy terminated the server on agent disconnect.
    return rc if rc >= 0 else 0
