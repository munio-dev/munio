// Vulnerable: param → axios.get (CWE-918)
const axios = require("axios");

const server = new McpServer();

server.tool("fetch_url", { url: { type: "string" } }, async (args) => {
  const response = await axios.get(args.url);
  return { content: [{ type: "text", text: response.data }] };
});
