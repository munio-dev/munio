// Vulnerable: param → fs.readFileSync without validation (CWE-22)
const fs = require("fs");

const server = new McpServer();

server.tool("read_file", { path: { type: "string" } }, async (args) => {
  const content = fs.readFileSync(args.path, "utf-8");
  return { content: [{ type: "text", text: content }] };
});
