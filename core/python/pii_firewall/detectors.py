"""PII detectors: regex candidates + validation (checksums, structural rules, context).

Each detector returns Entity spans. Overlaps are resolved in `detect()` by
priority, then by length. All logic here is mirrored in core/js/pii-core.js;
shared fixtures in core/fixtures/cases.json keep the two in sync.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# Lower number = higher priority when spans overlap.
PRIORITY = {
    "CREDIT_CARD": 1,
    "SSN": 2,
    "EMAIL": 3,
    "IP_ADDRESS": 4,
    "PHONE": 5,
    "DOB": 6,
    "ADDRESS": 7,
    "PERSON": 8,
}

ENTITY_TYPES = tuple(PRIORITY)


@dataclass(frozen=True)
class Entity:
    type: str
    start: int
    end: int
    value: str


# --- patterns ---------------------------------------------------------------

EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}\b")

SSN_RE = re.compile(r"(?<![\d-])(\d{3})([- ]?)(\d{2})\2(\d{4})(?![\d-])")

WORD_DIGITS = {"zero": "0", "oh": "0", "one": "1", "two": "2", "three": "3", "four": "4",
               "five": "5", "six": "6", "seven": "7", "eight": "8", "nine": "9"}
_WD = r"(?:zero|oh|one|two|three|four|five|six|seven|eight|nine)"
# SSN read out loud: nine number words, e.g. "one two three, four five, six seven eight nine".
SSN_WORDS_RE = re.compile(r"(?i)\b" + _WD + r"(?:[\s,-]+" + _WD + r"){8}\b(?![\s,-]+" + _WD + r"\b)")
_WD_BEFORE_RE = re.compile(r"(?i)\b" + _WD + r"[\s,-]+$")

CARD_RE = re.compile(r"(?<![\d-])(?:\d[ -]?){12,18}\d(?![\d-])")

PHONE_RE = re.compile(
    r"(?<![\w+])(?:\+?1[ .-]?)?(?:\(\d{3}\)\s?|\d{3}[ .-])\d{3}[ .-]\d{4}(?!\d)"
)

IP_RE = re.compile(r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?![\d.])")

DATE = r"(?:\d{1,2}[/-]\d{1,2}[/-](?:\d{4}|\d{2})|\d{4}-\d{2}-\d{2}|(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Sept|Oct|Nov|Dec)[a-z]*\.? \d{1,2},? \d{4})"
DOB_RE = re.compile(
    r"(?i)\b(?:dob|d\.o\.b\.?|date of birth|birth ?date|born(?: on)?)\b\s*[:\-]?\s*(" + DATE + r")"
)

STREET_SUFFIX = (
    r"(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Drive|Dr|Lane|Ln|Court|Ct|Way|"
    r"Place|Pl|Terrace|Ter|Circle|Cir|Parkway|Pkwy|Highway|Hwy|Trail|Trl)"
)
ADDRESS_RE = re.compile(
    r"\b\d{1,6}\s+(?:[NSEW]\.?\s+)?(?:[A-Z][a-zA-Z]+\s+){1,3}" + STREET_SUFFIX + r"\b\.?"
    r"(?:,?\s+(?:Apt|Apartment|Unit|Suite|Ste|#)\.?\s*[\w-]+)?"
    r"(?:,\s*[A-Z][a-zA-Z]+(?:\s[A-Z][a-zA-Z]+)*)?"
    r"(?:,\s*[A-Z]{2})?(?:\s+\d{5}(?:-\d{4})?)?"
)

NAME = r"[A-Z][a-z]+(?:[-'][A-Z][a-z]+)?"
FULL_NAME = NAME + r"(?:\s+[A-Z]\.)?(?:\s+" + NAME + r"){0,2}"
# Names are only flagged with a context cue; capitalised words alone are too noisy.
PERSON_RES = [
    re.compile(r"(?i:\b(?:my name is|name is|i am|i'm|this is)\s+)(" + FULL_NAME + r"\s+" + NAME + r")"),
    re.compile(r"(?i:\b(?:full name|name|applicant|cardholder|customer|patient|employee)\s*:\s*)(" + FULL_NAME + r")"),
    re.compile(r"\b(?:Mr|Mrs|Ms|Miss|Dr|Prof)\.?\s+(" + FULL_NAME + r")"),
    re.compile(r"(?i:\b(?:dear|hi|hello|sincerely|regards|thanks),?\s+)(" + NAME + r"\s+" + NAME + r")"),
]
PERSON_STOPWORDS = {"Street", "Avenue", "Road", "Drive", "Lane", "Bank", "Card", "The", "Team", "Customer", "Support"}


# --- validators --------------------------------------------------------------

def luhn_ok(digits: str) -> bool:
    total, alt = 0, False
    for ch in reversed(digits):
        d = int(ch)
        if alt:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        alt = not alt
    return total % 10 == 0


def ssn_ok(area: str, group: str, serial: str) -> bool:
    a = int(area)
    return a != 0 and a != 666 and a < 900 and group != "00" and serial != "0000"


# --- detectors ---------------------------------------------------------------

def _email(text):
    for m in EMAIL_RE.finditer(text):
        yield Entity("EMAIL", m.start(), m.end(), m.group())


def _ssn(text):
    for m in SSN_RE.finditer(text):
        if ssn_ok(m.group(1), m.group(3), m.group(4)):
            yield Entity("SSN", m.start(), m.end(), m.group())
    for m in SSN_WORDS_RE.finditer(text):
        if _WD_BEFORE_RE.search(text[: m.start()]):
            continue  # part of a longer run of number words
        d ="".join(WORD_DIGITS[w.lower()] for w in re.findall(r"[A-Za-z]+", m.group()))
        if ssn_ok(d[:3], d[3:5], d[5:]):
            yield Entity("SSN", m.start(), m.end(), m.group())


def _card(text):
    for m in CARD_RE.finditer(text):
        digits = re.sub(r"\D", "", m.group())
        if 13 <= len(digits) <= 19 and luhn_ok(digits) and len(set(digits)) > 1:
            yield Entity("CREDIT_CARD", m.start(), m.end(), m.group())


def _phone(text):
    for m in PHONE_RE.finditer(text):
        digits = re.sub(r"\D", "", m.group())
        if digits.startswith("1") and len(digits) == 11:
            digits = digits[1:]
        if len(digits) == 10 and digits[0] not in "01" and digits[3] not in "01":
            yield Entity("PHONE", m.start(), m.end(), m.group())


def _ip(text):
    for m in IP_RE.finditer(text):
        yield Entity("IP_ADDRESS", m.start(), m.end(), m.group())


def _dob(text):
    for m in DOB_RE.finditer(text):
        yield Entity("DOB", m.start(1), m.end(1), m.group(1))


def _address(text):
    for m in ADDRESS_RE.finditer(text):
        yield Entity("ADDRESS", m.start(), m.end(), m.group().rstrip(".,"))


def _person(text):
    for rx in PERSON_RES:
        for m in rx.finditer(text):
            words = m.group(1).split()
            if any(w.strip(".") in PERSON_STOPWORDS for w in words):
                continue
            yield Entity("PERSON", m.start(1), m.end(1), m.group(1))


DETECTORS = {
    "EMAIL": _email,
    "SSN": _ssn,
    "CREDIT_CARD": _card,
    "PHONE": _phone,
    "IP_ADDRESS": _ip,
    "DOB": _dob,
    "ADDRESS": _address,
    "PERSON": _person,
}


def detect(text: str, types=None) -> list[Entity]:
    """Return non-overlapping PII entities in `text`, sorted by position."""
    wanted = set(types) if types else set(ENTITY_TYPES)
    found = [e for t, fn in DETECTORS.items() if t in wanted for e in fn(text)]
    found.sort(key=lambda e: (PRIORITY[e.type], -(e.end - e.start), e.start))
    kept: list[Entity] = []
    for e in found:
        if all(e.end <= k.start or e.start >= k.end for k in kept):
            kept.append(e)
    return sorted(kept, key=lambda e: e.start)
