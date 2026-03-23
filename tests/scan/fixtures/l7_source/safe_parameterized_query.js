// SAFE: parameterized query — should NOT trigger L7_002
const db = require("pg").Pool();

const server = new McpServer();

server.tool("search_users", { query: { type: "string" } }, async (args) => {
  const result = await db.query("SELECT * FROM users WHERE name = $1", [args.query]);
  return { content: [{ type: "text", text: JSON.stringify(result.rows) }] };
});
