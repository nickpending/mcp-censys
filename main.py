"""
Main entry point for the Censys MCP server.

This script loads the global FastMCP instance from tools.py,
which already has all tools registered, and starts the MCP server.

Usage:
  python main.py  # or via Docker
"""

from mcp.server.fastmcp import FastMCP
from mcp_censys.tools.discovery import mcp

if __name__ == "__main__":
    mcp.run()
