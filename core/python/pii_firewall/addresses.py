"""US street address detection. Mirrored in core/js/pii-core.js (section "addresses").

Four independent patterns; overlaps are resolved by detect(), which keeps the
longest span, then merge_adjacent() joins a street line to a city line that
follows it.

1. STREET: house number + street name + suffix (St, Ave, Hollow, ...) or a
   numbered road (FM 1709, US 75), optional unit and city/state/ZIP tail.
   Street name words must be capitalised or ordinal (34th), which keeps
   "3 dogs on the farm" out.
2. LOOSE: any wording after a cue such as "I live at", "ship to", "address:".
   Lowercase and suffix-less ("9 oak hollow") are fine here.
3. STATE_ZIP: house number ... state ... ZIP in any case
   ("2210 mesquite lane grand prairie tx 75050").
4. PO_BOX and CITY_ZIP ("Dallas, TX 75201").
"""

from __future__ import annotations

import re

from ._rx import alt, ci

SUFFIXES = """Street St Avenue Ave Av Road Rd Boulevard Blvd Drive Dr Lane Ln Court Ct Way Place Pl Terrace Ter
Circle Cir Parkway Pkwy Highway Hwy Trail Trl Square Sq Loop Path Pike Row Alley Aly Crossing Xing Point Pt Ridge Rdg
Cove Cv Bend Hollow Holw Commons Plaza Plz Expressway Expy Freeway Fwy Turnpike Tpke Walk Mews Close Crescent Cres
Gardens Gdns Grove Grv Heights Hts Meadow Meadows Mdw Park Pass Glen Creek Crk Landing Lndg Manor Mnr Estates View
Vw Vista Center Ctr Junction Jct Run Trace Hill Hills""".split()
STATE_ABBR = """AL AK AZ AR CA CO CT DE DC FL GA HI ID IL IN IA KS KY LA ME MD MA MI MN MS MO MT NE NV NH NJ NM NY
NC ND OH OK OR PA RI SC SD TN TX UT VT VA WA WV WI WY PR VI GU AS MP FM MH PW AA AE AP""".split()
STATE_NAMES = ["Alabama", "Alaska", "Arizona", "Arkansas", "California", "Colorado", "Connecticut", "Delaware",
               "District of Columbia", "Florida", "Georgia", "Hawaii", "Idaho", "Illinois", "Indiana", "Iowa",
               "Kansas", "Kentucky", "Louisiana", "Maine", "Maryland", "Massachusetts", "Michigan", "Minnesota",
               "Mississippi", "Missouri", "Montana", "Nebraska", "Nevada", "New Hampshire", "New Jersey",
               "New Mexico", "New York", "North Carolina", "North Dakota", "Ohio", "Oklahoma", "Oregon",
               "Pennsylvania", "Rhode Island", "South Carolina", "South Dakota", "Tennessee", "Texas", "Utah",
               "Vermont", "Virginia", "Washington", "West Virginia", "Wisconsin", "Wyoming", "Puerto Rico", "Guam",
               "American Samoa", "U.S. Virgin Islands", "Northern Mariana Islands"]
CUES = ["address is", "address", "addr", "live at", "lives at", "living at", "reside at", "resides at",
        "residing at", "located at", "staying at", "stay at", "moved to", "move to", "ship to", "ship it to",
        "ship this to", "deliver to", "deliver it to", "mail to", "mail it to", "send to", "send it to",
        "send this to", "house is at", "home is at"]

NUM = r"\d{1,6}[A-Za-z]?(?:-\d{1,5})?"
DIR = r"(?:(?:N|S|E|W|NE|NW|SE|SW)\.?|" + alt(["North", "South", "East", "West", "Northeast", "Northwest",
                                              "Southeast", "Southwest"], ci) + r")"
CAP_WORD = r"(?:[A-Z][a-zA-Z'-]*|\d{1,3}(?:st|nd|rd|th))"
ANY_WORD = r"(?:[A-Za-z][A-Za-z'-]*|\d{1,3}(?:st|nd|rd|th))"
SUFFIX = alt(SUFFIXES, ci) + r"\b\.?"
ROUTE = (r"(?:(?:FM|RM|CR|SR|US|IH|I-)\s?\d{1,4}|"
         + alt(["Interstate", "Highway", "State Highway", "State Route", "County Road", "Route", "Rte"], ci)
         + r"\s+\d{1,4})[A-Za-z]?\b")
UNIT = (r"(?:,?\s*" + alt(["Apt", "Apartment", "Unit", "Suite", "Ste", "Bldg", "Building", "Floor", "Fl", "Room",
                          "Rm", "Lot", "Flat"], ci) + r"\.?\s*#?\s*[A-Za-z0-9-]{1,6}\b|,?\s*#\s*[A-Za-z0-9-]{1,6}\b)")
UNIT_FIRST = r"(?:" + alt(["Apt", "Apartment", "Unit", "Suite", "Ste", "Flat"], ci) + r"\.?\s*#?\s*[A-Za-z0-9-]{1,6},?\s+)"
CITY = r"[A-Z][a-zA-Z.'-]+(?:[ \t][A-Z][a-zA-Z.'-]+){0,2}\b"
STATE = r"(?:" + alt(STATE_ABBR) + "|" + alt(STATE_NAMES) + r")\b"
STATE_ANYCASE = r"(?:" + alt(STATE_ABBR, ci) + "|" + alt(STATE_NAMES, ci) + r")\b"
ZIP = r"\d{5}(?:-\d{4})?\b"
UK_POSTCODE = r"[A-Z]{1,2}\d[A-Z\d]?[ \t]?\d[A-Z]{2}\b"
TAIL = (r"(?:(?:,[ \t]*|[ \t]*\n[ \t]*|[ \t]+)" + CITY + r",?[ \t]+" + STATE + r"(?:,?[ \t]+" + ZIP + r")?"
        r"|,[ \t]*" + CITY + r"(?:,?[ \t]+(?:" + ZIP + "|" + UK_POSTCODE + r"))?"
        r"|,?[ \t]+" + STATE + r"(?:,?[ \t]+" + ZIP + r")?"
        r"|,?[ \t]+" + ZIP + r")?")

STREET_RE = re.compile(r"\b" + UNIT_FIRST + r"?" + NUM + r"[ \t]+(?:" + DIR + r"[ \t]+)?(?:" + ROUTE
                       + r"|(?:" + CAP_WORD + r"[ \t]+){0,3}" + CAP_WORD + r"[ \t]+" + SUFFIX + r")"
                       + r"(?:[ \t]+" + DIR + r"\b)?" + UNIT + r"?" + TAIL)
PO_BOX_RE = re.compile(r"\b(?:[Pp]\.?[ \t]?[Oo]\.?[ \t]*[Bb][Oo][Xx]|" + ci("Post Office Box") + r")[ \t]*#?[ \t]*\d{1,8}\b"
                       + TAIL)
CITY_ZIP_RE = re.compile(r"\b" + CITY + r",[ \t]*" + STATE + r"[ \t]+" + ZIP)
STATE_ZIP_RE = re.compile(r"\b" + NUM + r"[ \t]+(?:" + ANY_WORD + r"[ \t,]+){1,6}?" + STATE_ANYCASE + r",?[ \t]+" + ZIP)
CUE_RE = re.compile(r"\b" + alt(CUES, ci) + r"[ \t]*[:\-]?\s*")
# After a cue: take a house number and the rest of the phrase, up to the end of the sentence or a joining word.
LOOSE_RE = re.compile(NUM + r"[ \t]+[^\n;!?]{2,80}?(?=[ \t]*(?:[;!?\n]|\.(?:[ \t]+[A-Z]|[ \t]*\Z)|\Z)|,?[ \t]+"
                      + alt(["and", "but", "so", "then", "please", "thanks", "thank", "because", "since", "before",
                             "after", "by", "on", "for", "today", "tomorrow"], ci) + r"\b)")


def find(text: str):
    """Yield (start, end) spans of addresses."""
    for rx in (STREET_RE, PO_BOX_RE, CITY_ZIP_RE, STATE_ZIP_RE):
        for m in rx.finditer(text):
            yield m.start(), _trim(text, m.start(), m.end())
    for cue in CUE_RE.finditer(text):
        m = LOOSE_RE.match(text, cue.end())
        if m:
            yield m.start(), _trim(text, m.start(), m.end())


def _trim(text: str, start: int, end: int) -> int:
    """Drop trailing spaces, commas and periods; "123 Main St." redacts to "[ADDRESS_1]."."""
    while end > start and text[end - 1] in " \t,.":
        end -= 1
    return end
