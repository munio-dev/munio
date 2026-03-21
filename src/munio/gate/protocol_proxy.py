"""L6 Protocol proxy integration: hooks protocol monitoring into the gate proxy.

This module provides the integration layer between the ProtocolInterceptor
and the existing proxy.py message forwarding loops. It exports two async
functions that wrap the existing forwarding functions with L6 inspection:

- ``protocol_filter_client_message``: Inspects client->server messages
- ``protocol_filter_server_message``: Inspects server->client messages

Architecture:

    ┌─────────────────────────────────────────────────────────┐
    │                    munio gate proxy                      │
    │                                                          │
    │  agent stdin ──► protocol_filter_client_message() ──►   │
    │                  │                                       │
    │                  ├─ L6 BLOCK? → error response to agent  │
    │                  ├─ L6 ALERT? → log + forward            │
    │                  └─ L6 OK → existing interception flow   │
    │                           │                              │
    │                           ├─ tools/call? → Interceptor   │
    │                           └─ other → forward to server   │
    │                                                          │
    │  server stdout ──► protocol_filter_server_message() ──►  │
    │                    │                                      │
    │                    ├─ L6 BLOCK? → drop message            │
    │                    ├─ L6 ALERT? → log + forward           │
    │                    └─ L6 OK → forward to agent            │
    └─────────────────────────────────────────────────────────┘

Performance budget:
    L6 inspection adds <1ms per message (dict inspection + Lock).
    No I/O, no subprocess, no Z3.

Integration with proxy.py:

    The existing ``_read_agent_forward_to_server`` and ``_forward_server_to_agent``
    functions are extended (not replaced) to call L6 before forwarding.

    Option A (recommended): Modify proxy.py to accept an optional
    ProtocolInterceptor parameter and call it inline.

    Option B: Wrap the proxy with a ProtocolProxy class that
    pre-filters messages before passing to existing functions.

    This file implements Option A's integration points.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    import asyncio

    from munio.gate.protocol_interceptor import ProtocolInterceptor

__all__ = [
    "protocol_filter_client_message",
    "protocol_filter_server_message",
]

logger = logging.getLogger(__name__)


async def protocol_filter_client_message(
    msg: dict[str, Any],
    line: bytes,
    agent_stdout: asyncio.StreamWriter,
    protocol: ProtocolInterceptor,
) -> bool:
    """Run L6 protocol checks on a client->server message.

    Returns True if the message should be forwarded (allowed).
    Returns False if the message was blocked (error response already sent to agent).

    This function is called from ``_read_agent_forward_to_server`` BEFORE
    the existing tools/call interception.
    """
    result = protocol.on_client_message(msg)

    if not result.should_block:
        return True  # Forward

    # L6 blocked this message -- send error response to agent
    request_id = msg.get("id")
    if request_id is not None:
        response = protocol.make_block_response(request_id, result.violations)
        agent_stdout.write(response)
        await agent_stdout.drain()

    return False  # Do not forward


async def protocol_filter_server_message(
    msg: dict[str, Any],
    protocol: ProtocolInterceptor,
) -> bool:
    """Run L6 protocol checks on a server->client message.

    Returns True if the message should be forwarded to the agent.
    Returns False if the message should be dropped (not forwarded).

    This function is called from ``_forward_server_to_agent`` BEFORE
    forwarding the line to the agent.
    """
    result = protocol.on_server_message(msg)

    if not result.should_block:
        return True  # Forward

    # L6 blocked -- drop the message (don't forward to agent)
    logger.warning(
        "L6 dropped server message: %s",
        "; ".join(v.message for v in result.block_violations[:3]),
    )
    return False  # Drop
