"""Command line: pii-firewall scan|redact [FILE]  (reads stdin when FILE is omitted)."""

from __future__ import annotations

import argparse
import json
import sys

from .firewall import Firewall


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="pii-firewall", description="Detect or redact PII in text.")
    p.add_argument("command", choices=["scan", "redact"])
    p.add_argument("file", nargs="?", help="Input file (default: stdin)")
    args = p.parse_args(argv)

    if args.file:
        with open(args.file, encoding="utf-8") as f:
            text = f.read()
    else:
        text = sys.stdin.read()
    fw = Firewall()
    if args.command == "scan":
        found = [{"type": e.type, "start": e.start, "end": e.end} for e in fw.scan(text)]
        print(json.dumps({"count": len(found), "entities": found}, indent=2))
        return 1 if found else 0
    sys.stdout.write(fw.redact(text).text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
