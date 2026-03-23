# Vulnerable: param → f-string → cursor.execute (CWE-89)
import sqlite3

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("db-server")


@mcp.tool()
def search(query: str) -> str:
    """Search the database."""
    conn = sqlite3.connect("data.db")
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE name = '{query}'")
    return str(cursor.fetchall())
