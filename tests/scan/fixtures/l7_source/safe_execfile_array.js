// SAFE: execFile with array args — should NOT trigger L7_001
const { execFile } = require("child_process");

const server = new McpServer();

server.tool("run_safe", { arg: { type: "string" } }, async (args) => {
  const result = execFile("echo", [args.arg]);
  return { content: [{ type: "text", text: String(result) }] };
});
