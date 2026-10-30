"""Tool logic for the MCP server, kept free of MCP imports so it is easy to test.

Design rule: nothing returned to the AI contains raw PII. There is deliberately
no `rehydrate` tool: real values stay with the server and the person running it.
"""

from __future__ import annotations

import csv
import io
import os
import re
from pathlib import Path

from pii_firewall import Firewall

MAX_BYTES = 2_000_000
TEXT_SUFFIXES = {".txt", ".md", ".csv", ".tsv", ".json", ".log", ".yaml", ".yml", ".xml", ".html", ".eml"}

# Column headers that tell us a whole cell is PII even when the value alone doesn't look like it.
COLUMN_HINTS = [
    (re.compile(r"(^|_)(ssn|social)", re.I), "SSN"),
    (re.compile(r"(first|last|full|customer|applicant|card_?holder)?_?name$", re.I), "PERSON"),
    (re.compile(r"(address|street|addr)", re.I), "ADDRESS"),
    (re.compile(r"(dob|birth)", re.I), "DOB"),
    (re.compile(r"(phone|mobile|cell)", re.I), "PHONE"),
    (re.compile(r"e-?mail", re.I), "EMAIL"),
    (re.compile(r"(card|pan|cc)_?(number|num|no)?$", re.I), "CREDIT_CARD"),
]


class AccessDenied(Exception):
    pass


class Tools:
    def __init__(self, roots: list[str] | None = None, policy: dict | None = None):
        env_roots = os.environ.get("PII_FIREWALL_ROOTS", "")
        raw = roots if roots is not None else [r for r in env_roots.split(os.pathsep) if r]
        self.roots = [Path(r).expanduser().resolve() for r in raw]
        self.fw = Firewall(policy=policy) if policy else Firewall()

    # -- path safety ---------------------------------------------------------
    def _resolve(self, path: str) -> Path:
        if not self.roots:
            raise AccessDenied("No folders are shared. Set PII_FIREWALL_ROOTS to the folders the AI may read.")
        p = Path(path).expanduser()
        if not p.is_absolute():
            p = self.roots[0] / p
        p = p.resolve()
        if not any(p == r or r in p.parents for r in self.roots):
            raise AccessDenied(f"{path} is outside the shared folders.")
        return p

    # -- tools ---------------------------------------------------------------
    def scan_text(self, text: str) -> dict:
        found = self.fw.scan(text)
        counts: dict[str, int] = {}
        for e in found:
            counts[e.type] = counts.get(e.type, 0) + 1
        return {"contains_pii": bool(found), "counts": counts}

    def redact_text(self, text: str) -> dict:
        r = self.fw.redact(text)
        return {"text": r.text, "counts": r.counts, "blocked": r.blocked}

    def list_files(self, folder: str = "") -> dict:
        base = self._resolve(folder) if folder else self.roots[0] if self.roots else self._resolve("")
        if not base.is_dir():
            raise AccessDenied(f"{folder} is not a folder.")
        items = sorted(base.iterdir())
        return {
            "folder": str(base),
            "files": [p.name + ("/" if p.is_dir() else "") for p in items if not p.name.startswith(".")],
        }

    def safe_read_file(self, path: str) -> dict:
        p = self._resolve(path)
        if not p.is_file():
            raise AccessDenied(f"{path} is not a file.")
        if p.suffix.lower() not in TEXT_SUFFIXES:
            raise AccessDenied(f"{p.suffix} files are not supported (text formats only).")
        if p.stat().st_size > MAX_BYTES:
            raise AccessDenied("File is larger than 2 MB.")
        text = p.read_text(encoding="utf-8", errors="replace")
        if p.suffix.lower() in (".csv", ".tsv"):
            return self._redact_table(text, "\t" if p.suffix.lower() == ".tsv" else ",")
        r = self.fw.redact(text)
        return {"path": str(p), "text": r.text, "counts": r.counts}

    def _redact_table(self, text: str, delim: str) -> dict:
        rows = list(csv.reader(io.StringIO(text), delimiter=delim))
        if not rows:
            return {"text": "", "counts": {}}
        header, body = rows[0], rows[1:]
        hints = [next((t for rx, t in COLUMN_HINTS if rx.search(h.strip())), None) for h in header]
        counts: dict[str, int] = {}
        out = io.StringIO()
        w = csv.writer(out, delimiter=delim, lineterminator="\n")
        w.writerow(header)
        for row in body:
            new = []
            for i, cell in enumerate(row):
                hint = hints[i] if i < len(hints) else None
                if hint and cell.strip() and self.fw.policy.get(hint, "tokenize") != "allow":
                    counts[hint] = counts.get(hint, 0) + 1
                    new.append(self.fw.redact_value(cell.strip(), hint))
                else:
                    r = self.fw.redact(cell)
                    for k, v in r.counts.items():
                        counts[k] = counts.get(k, 0) + v
                    new.append(r.text)
            w.writerow(new)
        return {"text": out.getvalue(), "counts": counts, "columns_treated_as_pii": {h: t for h, t in zip(header, hints, strict=False) if t}}
