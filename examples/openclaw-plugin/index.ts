/**
 * munio OpenClaw Plugin
 *
 * Intercepts tool calls via before_tool_call hook and verifies them
 * against munio's constraint engine over HTTP.
 *
 * IMPORTANT: OpenClaw hooks are FAIL-OPEN — if a handler throws,
 * the tool call proceeds unchecked. This plugin wraps everything in
 * try/catch and returns {block: true} on ANY error (fail-closed).
 *
 * Setup:
 *   1. Start munio: munio serve --pack openclaw
 *   2. Copy this plugin to your OpenClaw plugins directory
 *   3. Configure in openclaw.json (see README.md)
 */

import type { OpenClawPluginApi } from "openclaw"; // OpenClaw plugin types

interface PluginConfig {
  apiUrl: string;
  timeoutMs: number;
  failClosed: boolean;
}

interface MunioResponse {
  block: boolean;
  blockReason: string | null;
}

const DEFAULT_CONFIG: PluginConfig = {
  apiUrl: "http://localhost:8080",
  timeoutMs: 5000,
  failClosed: true,
};

export default function register(api: OpenClawPluginApi): void {
  const config: PluginConfig = { ...DEFAULT_CONFIG, ...api.pluginConfig };

  api.on(
    "before_tool_call",
    async (event, ctx) => {
      // CRITICAL: Never throw from this handler.
      // OpenClaw hooks are FAIL-OPEN: throw → tool proceeds unchecked.
      const controller = new AbortController();
      const timeoutId = setTimeout(
        () => controller.abort(),
        config.timeoutMs,
      );

      try {
        const response = await fetch(
          `${config.apiUrl}/v1/openclaw/before-tool-call`,
          {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ event, ctx }),
            signal: controller.signal,
          },
        );

        if (!response.ok) {
          // HTTP error (500, 502, etc.) — fail-closed
          if (config.failClosed) {
            return {
              block: true,
              blockReason: `munio HTTP ${response.status} (fail-closed)`,
            };
          }
          return {};
        }

        const result: MunioResponse = await response.json();

        if (result.block) {
          return {
            block: true,
            blockReason: result.blockReason ?? "Blocked by munio",
          };
        }

        return {};
      } catch (error: unknown) {
        // Network error, timeout, DNS failure, parse error, etc.
        // FAIL-CLOSED: block rather than allowing unchecked tool calls
        if (config.failClosed) {
          const message =
            error instanceof Error ? error.message : "Unknown error";
          return {
            block: true,
            blockReason: `munio unavailable: ${message} (fail-closed)`,
          };
        }
        return {};
      } finally {
        clearTimeout(timeoutId);
      }
    },
    { priority: 10 },
  );
}
