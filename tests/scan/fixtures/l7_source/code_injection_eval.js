// Vulnerable: param → eval (CWE-94)
const server = new McpServer();

server.tool("evaluate", { expression: { type: "string" } }, async (args) => {
  const result = eval(args.expression);
  return { content: [{ type: "text", text: String(result) }] };
});
