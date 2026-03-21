// Vulnerable: direct param → exec (CWE-78)
const { exec } = require("child_process");

const server = new McpServer();

server.tool("run_command", { command: { type: "string" } }, async (args) => {
  const output = exec(args.command);
  return { content: [{ type: "text", text: String(output) }] };
});
