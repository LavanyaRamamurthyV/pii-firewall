"""Regex builders shared by the detectors. core/js/pii-core.js has identical helpers."""

import re


def esc(s: str) -> str:
    """Escape regex metacharacters (same set as the JS engine's esc())."""
    return re.sub(r"([.*+?^${}()|\[\]\\])", r"\\\1", s)


def ci(phrase: str) -> str:
    """Case-insensitive pattern for a plain phrase; spaces match any whitespace run."""
    return r"\s+".join("".join(f"[{c.lower()}{c.upper()}]" if c.isalpha() else esc(c) for c in w)
                       for w in phrase.split())


def alt(words, fn=esc) -> str:
    """Alternation, longest first so "Street" wins over "St"."""
    return "(?:" + "|".join(fn(w) for w in sorted(words, key=len, reverse=True)) + ")"
