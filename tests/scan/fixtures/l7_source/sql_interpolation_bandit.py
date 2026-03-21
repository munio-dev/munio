# Vulnerable: SQL keywords in f-string (Bandit-style detection)
import sqlite3

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("sql-server")


@mcp.tool()
def run_query(query: str) -> str:
    """Execute a raw SQL query."""
    conn = sqlite3.connect("data.db")
    cursor = conn.cursor()
    result = cursor.execute(f"SELECT * FROM users WHERE name = '{query}'")
    return str(result.fetchall())
