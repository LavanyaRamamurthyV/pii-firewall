import asyncio
import json
import sys
from pathlib import Path

import pytest
from pii_firewall_mcp.tools import AccessDenied, Tools


@pytest.fixture
def share(tmp_path):
    (tmp_path / "notes.txt").write_text("Customer Maria Garcia, SSN 234-56-7890, email maria.g@example.com")
    (tmp_path / "customers.csv").write_text(
        "customer_name,email,ssn,balance\n"
        "Maria Garcia,maria.g@example.com,234-56-7890,1200\n"
        "Lee Wong,lee@example.org,345-67-8901,90\n"
        "Maria Garcia,maria.g@example.com,234-56-7890,15\n"
    )
    (tmp_path / "photo.png").write_bytes(b"\x89PNG")
    outside = tmp_path.parent / "secret.txt"
    outside.write_text("SSN 123-45-6789")
    return tmp_path


def test_read_text_file_tokenizes(share):
    t = Tools(roots=[str(share)])
    out = t.safe_read_file("notes.txt")
    assert "234-56-7890" not in out["text"] and "maria.g@example.com" not in out["text"]
    assert out["counts"] == {"PERSON": 1, "SSN": 1, "EMAIL": 1}
    assert "Maria" not in out["text"]


def test_csv_column_hints_and_consistent_tokens(share):
    t = Tools(roots=[str(share)])
    out = t.safe_read_file("customers.csv")
    lines = out["text"].strip().split("\n")
    assert lines[1] == "[PERSON_1],[EMAIL_1],[SSN_1],1200"
    assert lines[3] == "[PERSON_1],[EMAIL_1],[SSN_1],15"  # same person -> same tokens
    assert lines[2].startswith("[PERSON_2],[EMAIL_2],[SSN_2]")
    assert "Maria" not in out["text"]


def test_path_escape_blocked(share):
    t = Tools(roots=[str(share)])
    with pytest.raises(AccessDenied):
        t.safe_read_file("../secret.txt")
    with pytest.raises(AccessDenied):
        t.safe_read_file(str(share.parent / "secret.txt"))


def test_binary_and_no_roots_blocked(share):
    with pytest.raises(AccessDenied):
        Tools(roots=[str(share)]).safe_read_file("photo.png")
    with pytest.raises(AccessDenied):
        Tools(roots=[]).safe_read_file("notes.txt")


def test_scan_never_returns_values(share):
    out = Tools(roots=[str(share)]).scan_text("call (214) 555-0182")
    assert out == {"contains_pii": True, "counts": {"PHONE": 1}}


def test_over_stdio_like_a_real_client(share):
    """Spawn the server as a subprocess and talk MCP to it, the way Claude/ChatGPT do."""
    from mcp import Client
    from mcp.client.stdio import StdioServerParameters

    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "pii_firewall_mcp.server"],
        env={"PII_FIREWALL_ROOTS": str(share)},
        cwd=str(Path(__file__).parents[1]),
    )

    async def run():
        async with Client(params) as c:
            names = {t.name for t in (await c.list_tools()).tools}
            res = await c.call_tool("safe_read_file", {"path": "customers.csv"})
            denied = await c.call_tool("safe_read_file", {"path": "../secret.txt"})
            return names, res, denied

    names, res, denied = asyncio.run(run())
    assert names == {"scan_text", "redact_text", "list_files", "safe_read_file"}
    payload = res.structured_content or json.loads(res.content[0].text)
    payload = payload.get("result", payload)
    assert "[SSN_1]" in payload["text"] and "234-56-7890" not in payload["text"]
    denied_payload = denied.structured_content or json.loads(denied.content[0].text)
    denied_payload = denied_payload.get("result", denied_payload)
    assert "outside the shared folders" in denied_payload["error"]
