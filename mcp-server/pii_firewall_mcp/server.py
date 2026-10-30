"""PII Firewall MCP server.

Works with any MCP client (Claude Desktop, Claude Code, ChatGPT connectors,
Cursor, VS Code, Gemini CLI). Exposes file and text tools that return data with
personal information already replaced by tokens like [SSN_1].

Configure which folders the AI may read with PII_FIREWALL_ROOTS
(colon-separated on macOS/Linux, semicolon-separated on Windows).
"""

from __future__ import annotations

import argparse

from mcp.server.mcpserver import MCPServer

from .tools import AccessDenied, Tools

INSTRUCTIONS = (
    "Use these tools to read the user's files instead of any raw file tool. "
    "Personal data comes back as tokens such as [PERSON_1] or [SSN_2]; keep the tokens "
    "as they are in your answer. The same value always maps to the same token, so you can "
    "still compare and count records. Do not ask the user to reveal the real values."
)

mcp = MCPServer(name="pii-firewall", instructions=INSTRUCTIONS, version="0.1.0")
tools = Tools()


def _guard(fn, *args):
    try:
        return fn(*args)
    except AccessDenied as e:
        return {"error": str(e)}


@mcp.tool()
def scan_text(text: str) -> dict:
    """Check text for personal data (SSN, card, email, phone, IP, date of birth, address, name).
    Returns counts per type only, never the values."""
    return tools.scan_text(text)


@mcp.tool()
def redact_text(text: str) -> dict:
    """Replace personal data in text with consistent tokens like [EMAIL_1] before you store,
    forward or quote it."""
    return tools.redact_text(text)


@mcp.tool()
def list_files(folder: str = "") -> dict:
    """List files in a shared folder (or the first shared folder when empty)."""
    return _guard(tools.list_files, folder)


@mcp.tool()
def safe_read_file(path: str) -> dict:
    """Read a text, Markdown, JSON or CSV file from a shared folder with personal data
    replaced by tokens. For CSVs, columns like name, ssn, email, phone, address, dob are
    tokenized whole."""
    return _guard(tools.safe_read_file, path)


def main() -> None:
    p = argparse.ArgumentParser(prog="pii-firewall-mcp")
    p.add_argument("--transport", choices=["stdio", "streamable-http"], default="stdio")
    args = p.parse_args()
    mcp.run(args.transport)


if __name__ == "__main__":
    main()
