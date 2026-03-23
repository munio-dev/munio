// Vulnerable: setRequestHandler with inline SQL injection
const { Pool } = require("pg");
const db = new Pool();

const server = new Server();

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const args = request.params.arguments;
  const result = await db.query(`SELECT * FROM ${args.table} WHERE id = ${args.id}`);
  return { content: [{ type: "text", text: JSON.stringify(result.rows) }] };
});
