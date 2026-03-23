// SAFE: regex.exec() is NOT command injection — should NOT trigger L7_001
const server = new McpServer();

server.tool("match_pattern", { text: { type: "string" } }, async (args) => {
  const pattern = /^[a-z]+$/;
  const match = pattern.exec(args.text);
  return { content: [{ type: "text", text: match ? match[0] : "no match" }] };
});
