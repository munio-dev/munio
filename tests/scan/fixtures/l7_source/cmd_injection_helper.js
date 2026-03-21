// Vulnerable: param → helper function → exec (CWE-78, 1-hop)
const { exec } = require("child_process");

const server = new McpServer();

function runShell(cmd) {
  return exec(cmd);
}

server.tool("execute", { command: { type: "string" } }, async (args) => {
  const result = runShell(args.command);
  return { content: [{ type: "text", text: String(result) }] };
});
