"""Person name detection. Mirrored in core/js/pii-core.js (section "names").

Two complementary methods:

1. Dictionary: a known first name followed by a surname (with optional middle
   initial, particles like "de la", and suffixes like "Jr.").
   - Capitalised ("Maria Garcia"): the last word must be a known surname or a
     capitalised word that isn't an everyday English word.
   - Lowercase or ALL CAPS ("priya sharma"): both words must be known names and
     not everyday words.
   - First names that are everyday words (Will, Mark, Grace, Chase) need a known
     surname after them.
   - Place and organisation words (Park, Bank, Station, Airport) next to the
     name cancel the match.
2. Cues: words after "my name is", "Applicant:", "Dr.", "Dear", "Hi" ... even
   when the name isn't in the dictionary ("co-applicant: Kwame Mensah").
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from ._rx import alt, ci

_DATA = json.loads((Path(__file__).parent / "data" / "names.json").read_text())
FIRST = frozenset(_DATA["first"])
LAST = frozenset(_DATA["last"])
AMBIGUOUS_FIRST = frozenset(_DATA["ambiguous_first"])
AMBIGUOUS_LAST = frozenset(_DATA["ambiguous_last"])
COMMON = frozenset(_DATA["common"])

# Capitalised words that are never part of a person's name when next to one.
PLACE_ORG = frozenset("""
street st avenue ave road rd drive dr lane ln boulevard blvd court ct way place pl terrace circle parkway highway
park heights hills valley river lake bay beach station airport center centre county city town village square
plaza mall bank group inc llc ltd corp corporation company co university college school academy hospital clinic
church building tower bridge island mountain mountains falls springs creek point harbor port fund capital
partners foundation institute association society club team support service services department office card
account airlines airways motors foods pharmacy market stadium arena theater theatre museum library
gmbh ag plc llp lp sa srl bv nv pty limited holdings
residency residences apartments towers enclave nagar colony layout complex villas
january february march april may june july august september october november december
monday tuesday wednesday thursday friday saturday sunday
texas california florida georgia virginia washington carolina dakota york jersey india china america england
""".split())
# Words before a name that make it a place ("St. John Hospital", "Fort Worth", "Lake Victoria").
PLACE_PREFIX = frozenset("saint st mount mt fort ft lake port san santa los las new north south east west "
                         "university college bank".split())
STOP_TOKENS = frozenset("jan feb mar apr jun jul aug sep sept oct nov dec mon tue tues wed thu thur thurs fri sat sun".split())
PARTICLES = frozenset("de da del della di dos du la le van von der den bin ibn al el ter".split())
SUFFIXES = frozenset("jr sr ii iii iv".split())
GREETING_CUES = ["hi", "hello", "hey", "dear", "thanks", "thank you", "thx", "cc", "attn", "attention"]
SELF_CUES = ["my name is", "my name's", "name is", "i am", "i'm", "this is", "call me", "i go by"]
SIGNOFF_CUES = ["dear", "hi", "hello", "hey", "sincerely", "regards", "best", "thanks", "cheers"]
LABELS = ["full name", "name", "applicant", "co-applicant", "borrower", "co-borrower", "cardholder", "card holder",
          "account holder", "customer", "client", "patient", "employee", "member", "beneficiary", "insured",
          "policyholder", "tenant", "guarantor", "spouse", "student", "guest", "passenger", "owner", "contact",
          "signed", "signature", "from", "to", "attn", "recipient", "sender", "payee"]

# Context that says the next/previous words are a person, for names the dictionary doesn't know.
BEFORE_CUES = ["email", "e-mail", "call", "ask", "tell", "cc", "contact", "meet", "pay", "text", "message",
               "send it to", "send this to", "send to", "forward to", "forward it to", "introduce", "named"]
AFTER_CUES = ["called", "said", "says", "emailed", "wrote", "asked", "told", "replied", "mentioned", "signed",
              "paid", "texted", "phoned"]
RELATIONS = ["friend", "wife", "husband", "son", "daughter", "mother", "mom", "father", "dad", "brother", "sister",
             "colleague", "coworker", "boss", "manager", "neighbor", "neighbour", "partner", "cousin", "uncle", "aunt",
             "grandma", "grandpa", "grandmother", "grandfather", "client", "doctor", "lawyer", "landlord", "tenant"]

TOKEN_RE = re.compile(r"[A-Za-z]+(?:['’-][A-Za-z]+)*\.?")

NAME = r"[A-Z][a-z]+(?:[-'’][A-Z]?[a-z]+)?"
FULL_NAME = NAME + r"(?:[ \t]+[A-Z]\.)?(?:[ \t]+" + NAME + r"){0,2}"
CUE_RES = [
    re.compile(r"\b" + alt(SELF_CUES, ci) + r"[ \t]+(" + FULL_NAME + r"[ \t]+" + NAME + r")"),
    re.compile(r"\b" + alt(LABELS, ci) + r"(?:[ \t]*:\s*|[ \t]+[-–][ \t]+)(" + FULL_NAME + r")"),
    re.compile(r"\b(?:Mr|Mrs|Ms|Miss|Mx|Dr|Prof)\.?[ \t]+(" + FULL_NAME + r")"),
    re.compile(r"\b" + alt(SIGNOFF_CUES, ci) + r",?\s+(" + NAME + r"(?:[ \t]+" + NAME + r"){1,2})"),
]
CTX_BEFORE_RE = re.compile(r"\b" + alt(BEFORE_CUES, ci) + r"[ \t]+(" + NAME + r"[ \t]+" + NAME + r"|[a-z]+[ \t]+[a-z]+)\b")
CTX_AFTER_RE = re.compile(r"\b(" + NAME + r"[ \t]+" + NAME + r")[ \t]+" + alt(AFTER_CUES, ci) + r"\b")
RELATION_RE = re.compile(r"\b" + alt(["my", "our", "your", "his", "her", "their"], ci) + r"[ \t]+" + alt(RELATIONS, ci)
                         + r"[ \t]*,?[ \t]+([A-Za-z][A-Za-z'’-]*(?:[ \t]+[A-Za-z][A-Za-z'’-]*){0,2})")
# More names joined to a found one: "Mats Brandt and Belo Durka", "A, B and C"
JOINED_RE = re.compile(r"[ \t]*(?:,[ \t]*(?:and|or|&)?|and|or|&)[ \t]+(" + NAME + r"(?:[ \t]+" + NAME + r"){1,2})\b")
# Single known first name after a greeting: "Hi Priya," / "Thanks, Rahul!"
GREETING_RE = re.compile(r"\b" + alt(GREETING_CUES, ci) + r"[ \t]*,?[ \t]+(" + NAME + r")\b(?![ \t]+[A-Z])")
# Lowercase self-introduction: "my name is rahul", "i'm priya sharma"
SELF_LOWER_RE = re.compile(r"\b" + alt(SELF_CUES, ci) + r"[ \t]+([a-z]+(?:[ \t]+[a-z]+){0,2})\b")


def _style(tok: str) -> str:
    core = tok.rstrip(".")
    if len(core) == 1 and core.isupper():
        return "initial"
    if core.islower():
        return "lower"
    if core.isupper():
        return "upper"
    if core[0].isupper():
        return "cap"
    return "other"


def _key(tok: str) -> str:
    return re.sub(r"['’]s$", "", tok.rstrip(".")).lower()


def _valid_last(tok: str, strict: bool) -> bool:
    k = _key(tok)
    if k in PLACE_ORG or len(k) < 2:
        return False
    parts = k.replace("’", "'").split("-")
    if strict:  # lowercase / all caps: must be a known surname that isn't an everyday word
        return all(p in LAST and p not in AMBIGUOUS_LAST and len(p) >= 3 for p in parts)
    # Capitalised: a known surname, or any word that isn't everyday English ("Venkatasubramanian").
    return all(p in LAST or p not in COMMON for p in parts)


def _dictionary(text: str):
    toks = [(m.start(), m.end(), m.group()) for m in TOKEN_RE.finditer(text)]

    def joined(a, b):  # tokens a and b separated only by spaces/tabs
        return re.fullmatch(r"[ \t]+", text[toks[a][1]:toks[b][0]]) is not None

    i = 0
    while i < len(toks):
        s, _, t = toks[i]
        style, k = _style(t), _key(t)
        if style not in ("cap", "lower", "upper") or k not in FIRST or t.endswith("."):
            i += 1
            continue
        # A place word right before ("Lake Victoria", "St. John") makes this a place.
        if i > 0 and joined(i - 1, i) and _key(toks[i - 1][2]) in PLACE_PREFIX and _style(toks[i - 1][2]) != "lower":
            i += 1
            continue
        strict = style != "cap"
        if strict and k in AMBIGUOUS_FIRST:
            i += 1
            continue
        best, j = None, i
        while j + 1 < len(toks) and j - i < 4 and joined(j, j + 1):
            nt = toks[j + 1][2]
            ns, nk = _style(nt), _key(nt)
            if not strict and ns == "initial":  # "Robert J. Smith"
                j += 1
                continue
            if not strict and ns == "lower" and nk in PARTICLES:  # "Maria de la Cruz"
                j += 1
                continue
            if (ns != style) if strict else (ns != "cap"):
                break
            if nk in PLACE_ORG:  # "Grant Park", "Charlotte Douglas Airport"
                best = None
                break
            if nk in STOP_TOKENS:  # "Briggs Mar" (month abbreviation)
                break
            if nk in SUFFIXES:  # "Smith Jr."
                if best is not None:
                    best = j + 1
                break
            if _valid_last(nt, strict) and (k not in AMBIGUOUS_FIRST or nk in LAST):
                best = j + 1
            elif strict or nk in COMMON:
                break
            if nt.endswith(".") or re.search(r"['’]s$", nt):  # "Gamma's JUnit": possessive ends the name
                break
            j += 1
        if best is None:
            i += 1
            continue
        # Optional suffix after a comma: "Robert Smith, Sr."
        end = toks[best][1]
        nxt = best + 1
        if nxt < len(toks) and _key(toks[nxt][2]) in SUFFIXES and re.fullmatch(r",[ \t]*", text[end:toks[nxt][0]]):
            best, end = nxt, toks[nxt][1]
        if _key(toks[best][2]) not in SUFFIXES:  # sentence period isn't part of the name
            end = s + len(text[s:end].rstrip("."))
        end -= len(re.search(r"(?:['’]s)?$", text[s:end]).group())  # "Brown's" -> "Brown"
        yield s, end
        i = best + 1


def _cues(text: str):
    for idx, rx in enumerate(CUE_RES):
        for m in rx.finditer(text):
            words = [_key(w) for w in m.group(1).split()]
            if any(w in PLACE_ORG or w in STOP_TOKENS for w in words):
                continue
            known = [w in FIRST or w in LAST for w in words]
            if len(words) == 1:
                # One word after a label must be a known name; after Mr./Dr. any non-everyday word will do.
                if not known[0] and not (idx == 2 and words[0] not in COMMON):
                    continue
            elif not any(known) and all(w in COMMON for w in words):  # "Noise Ratio"
                continue
            yield m.start(1), m.end(1)
    for m in GREETING_RE.finditer(text):
        k = m.group(1).lower()
        # After a greeting even word-names are names ("Hi Grace,") when punctuation follows.
        if k in FIRST and (k not in AMBIGUOUS_FIRST or re.match(r"[ \t]*[,.!:]", text[m.end(1):])):
            yield m.start(1), m.end(1)
    for m in SELF_LOWER_RE.finditer(text):
        words = m.group(1).split()
        if words[0] not in FIRST or words[0] in AMBIGUOUS_FIRST:
            continue
        keep = 1
        for w in words[1:]:
            if (w in LAST or w in FIRST) and w not in COMMON and w not in AMBIGUOUS_LAST:
                keep += 1
            else:
                break
        span = re.match(r"[a-z]+(?:[ \t]+[a-z]+){" + str(keep - 1) + "}", text[m.start(1):])
        yield m.start(1), m.start(1) + span.end()


def _namelike(w: str) -> bool:
    """A word that can be part of an unknown name: a known name or not an everyday word."""
    return w not in PLACE_ORG and w not in STOP_TOKENS and (
        ((w in FIRST or w in LAST) and w not in AMBIGUOUS_FIRST) or w not in COMMON)


def _context(text: str):
    for rx in (CTX_BEFORE_RE, CTX_AFTER_RE):
        for m in rx.finditer(text):
            ws = [_key(w) for w in m.group(1).split()]
            if m.group(1).islower():  # "email lisa white": both must be known names
                ok = ws[0] in FIRST and ws[0] not in AMBIGUOUS_FIRST and ws[1] in LAST
            else:
                ok = all(_namelike(w) for w in ws)
            if ok:
                yield m.start(1), m.end(1)
    for m in RELATION_RE.finditer(text):  # "my friend nevenka dretvic"
        toks = list(re.finditer(r"[A-Za-z][A-Za-z'’-]*", m.group(1)))
        keep = 0
        for t in toks:
            if _namelike(_key(t.group())):
                keep += 1
            else:
                break
        if keep:
            yield m.start(1), m.start(1) + toks[keep - 1].end()


def find(text: str):
    """Return (start, end) spans of person names."""
    spans = [*_dictionary(text), *_cues(text), *_context(text)]
    todo = list(spans)
    while todo:  # follow lists of names: "A and B", "A, B and C"
        _, end = todo.pop()
        m = JOINED_RE.match(text, end)
        if m and all(_namelike(_key(w)) for w in m.group(1).split()) and (m.start(1), m.end(1)) not in spans:
            spans.append((m.start(1), m.end(1)))
            todo.append((m.start(1), m.end(1)))
    return spans
