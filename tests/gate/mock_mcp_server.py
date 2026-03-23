"""Minimal MCP server mock for integration testing.

Reads newline-delimited JSON-RPC from stdin, responds to:
- initialize → capabilities response
- tools/call → echoes tool name and arguments back
- Any other method → echoes the method name
- Exit on EOF
"""

from __future__ import annotations

import json
import sys


def main() -> None:
    for raw_line in sys.stdin:
        line = raw_line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue

        if not isinstance(msg, dict):
            continue

        request_id = msg.get("id")
        method = msg.get("method", "")

        if method == "initialize":
            resp = {
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "mock-mcp", "version": "0.1.0"},
                },
            }
        elif method == "tools/call":
            params = msg.get("params", {})
            name = params.get("name", "unknown")
            arguments = params.get("arguments", {})
            resp = {
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {
                    "content": [
                        {
                            "type": "text",
                            "text": json.dumps({"tool": name, "args": arguments}),
                        }
                    ]
                },
            }
        else:
            resp = {
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {"echo": method},
            }

        sys.stdout.write(json.dumps(resp) + "\n")
        sys.stdout.flush()


if __name__ == "__main__":
    main()
