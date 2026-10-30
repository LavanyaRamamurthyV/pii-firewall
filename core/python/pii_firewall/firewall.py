"""Firewall: applies a policy to detected PII and keeps a reversible token vault."""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field

from .detectors import ENTITY_TYPES, Entity, detect

ACTIONS = ("tokenize", "mask", "block", "allow")
DEFAULT_POLICY = {t: "tokenize" for t in ENTITY_TYPES}
TOKEN_RE = re.compile(r"\[(" + "|".join(ENTITY_TYPES) + r")_(\d+)\]")


def mask(entity: Entity) -> str:
    """Irreversible partial mask, e.g. ***-**-6789 or j***@example.com."""
    v = entity.value
    if entity.type in ("SSN", "CREDIT_CARD", "PHONE"):
        keep = 4
        out, seen = [], 0
        for ch in reversed(v):
            if ch.isdigit():
                out.append(ch if seen < keep else "*")
                seen += 1
            else:
                out.append(ch)
        return "".join(reversed(out))
    if entity.type == "EMAIL":
        user, _, domain = v.partition("@")
        return user[:1] + "***@" + domain
    return f"[{entity.type}]"


@dataclass
class Finding:
    type: str
    action: str
    start: int
    end: int
    replacement: str


@dataclass
class RedactResult:
    text: str
    findings: list[Finding]
    blocked: bool

    @property
    def counts(self) -> dict[str, int]:
        c: dict[str, int] = {}
        for f in self.findings:
            c[f.type] = c.get(f.type, 0) + 1
        return c


@dataclass
class Firewall:
    """Detect, redact and restore PII.

    policy maps entity type -> one of: tokenize (reversible), mask (partial,
    irreversible), block (removed and flagged), allow (left as is).
    """

    policy: dict[str, str] = field(default_factory=lambda: dict(DEFAULT_POLICY))
    _vault: dict[str, str] = field(default_factory=dict, repr=False)  # token -> value
    _index: dict[tuple[str, str], str] = field(default_factory=dict, repr=False)  # (type, value) -> token
    _counters: dict[str, int] = field(default_factory=dict, repr=False)
    audit_log: list[dict] = field(default_factory=list, repr=False)

    def __post_init__(self):
        for t, a in self.policy.items():
            if t not in ENTITY_TYPES:
                raise ValueError(f"Unknown entity type: {t}")
            if a not in ACTIONS:
                raise ValueError(f"Unknown action for {t}: {a}")

    def _token_for(self, e: Entity) -> str:
        key = (e.type, _normalise(e))
        if key not in self._index:
            n = self._counters.get(e.type, 0) + 1
            self._counters[e.type] = n
            tok = f"[{e.type}_{n}]"
            self._index[key] = tok
            self._vault[tok] = e.value
        return self._index[key]

    def scan(self, text: str) -> list[Entity]:
        active = [t for t in ENTITY_TYPES if self.policy.get(t, "tokenize") != "allow"]
        return detect(text, active)

    def redact(self, text: str) -> RedactResult:
        entities = self.scan(text)
        out, pos, findings, blocked = [], 0, [], False
        for e in entities:
            action = self.policy.get(e.type, "tokenize")
            if action == "tokenize":
                rep = self._token_for(e)
            elif action == "mask":
                rep = mask(e)
            else:  # block
                rep, blocked = f"[REDACTED_{e.type}]", True
            out.append(text[pos:e.start])
            out.append(rep)
            pos = e.end
            findings.append(Finding(e.type, action, e.start, e.end, rep))
        out.append(text[pos:])
        result = RedactResult("".join(out), findings, blocked)
        if findings:
            self.audit_log.append({"ts": time.time(), "counts": result.counts, "blocked": blocked})
        return result

    def redact_value(self, value: str, entity_type: str) -> str:
        """Redact a value already known to be PII (e.g. a cell in a "name" column)."""
        e = Entity(entity_type, 0, len(value), value)
        action = self.policy.get(entity_type, "tokenize")
        if action == "allow":
            return value
        if action == "tokenize":
            return self._token_for(e)
        return mask(e) if action == "mask" else f"[REDACTED_{entity_type}]"

    def rehydrate(self, text: str) -> str:
        """Put real values back for tokens this firewall issued. Unknown tokens are left alone."""
        return TOKEN_RE.sub(lambda m: self._vault.get(m.group(0), m.group(0)), text)

    def clear(self) -> None:
        self._vault.clear()
        self._index.clear()
        self._counters.clear()


def _normalise(e: Entity) -> str:
    if e.type in ("SSN", "CREDIT_CARD", "PHONE"):
        d = re.sub(r"\D", "", e.value)
        return d[1:] if e.type == "PHONE" and len(d) == 11 else d
    return e.value.lower() if e.type == "EMAIL" else e.value
