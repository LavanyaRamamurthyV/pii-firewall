"""Generate a labeled synthetic PII dataset (all values are fake, from Faker).

Templates mix PII, decoys that look like PII but aren't (order numbers, prices,
ZIPs, dates with no birth context), and "hard" cases the detector is known to
miss, so the scorecard shows real limits instead of a perfect score.

Usage: python evals/generate.py  -> evals/dataset.jsonl
"""

import json
import random
from pathlib import Path

from faker import Faker

SEED = 7
N = 1000
fake = Faker("en_US")
Faker.seed(SEED)
rng = random.Random(SEED)


def luhn_card(prefix: str, length: int) -> str:
    digits = [int(c) for c in prefix] + [rng.randint(0, 9) for _ in range(length - len(prefix) - 1)]
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 0:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return "".join(map(str, digits + [(10 - total % 10) % 10]))


def fmt_card(n: str) -> str:
    sep = rng.choice([" ", "-", ""])
    return sep.join(n[i:i + 4] for i in range(0, len(n), 4))


def ssn() -> str:
    area = rng.choice([a for a in range(1, 900) if a != 666])
    s = f"{area:03d}{rng.randint(1, 99):02d}{rng.randint(1, 9999):04d}"
    sep = rng.choice(["-", "-", "-", " ", ""])
    return f"{s[:3]}{sep}{s[3:5]}{sep}{s[5:]}"


def phone() -> str:
    a, b, c = rng.randint(201, 989), rng.randint(200, 999), rng.randint(0, 9999)
    return rng.choice([f"({a}) {b}-{c:04d}", f"{a}-{b}-{c:04d}", f"{a}.{b}.{c:04d}", f"+1 {a}-{b}-{c:04d}"])


def dob() -> str:
    d = fake.date_of_birth(minimum_age=18, maximum_age=90)
    return rng.choice([d.strftime("%m/%d/%Y"), d.strftime("%Y-%m-%d"), d.strftime("%B %-d, %Y")])


# Names come from locales NOT used to build the name dictionary (scripts/build_names.py),
# so the scorecard measures names the detector has never seen.
HELD_OUT = ["sv_SE", "fi_FI", "cs_CZ", "da_DK", "no_NO", "ro_RO", "hr_HR", "sk_SK", "zu_ZA", "tw_GH", "en_PK",
            "sl_SI", "et_EE", "id_ID"]
_fakers = [Faker(loc) for loc in HELD_OUT]
for _f in _fakers:
    _f.seed_instance(SEED)


def _ascii(s: str) -> str:
    import unicodedata
    return unicodedata.normalize("NFKD", s).encode("ascii", "ignore").decode()


def first() -> str:
    return _ascii(rng.choice(_fakers).first_name())


def name() -> str:
    f = rng.choice(_fakers)
    return _ascii(f"{f.first_name()} {f.last_name()}")


def us_name() -> str:
    return f"{fake.first_name()} {fake.last_name()}"


def ordinal(n: int) -> str:
    return f"{n}{'th' if 10 <= n % 100 <= 20 else {1: 'st', 2: 'nd', 3: 'rd'}.get(n % 10, 'th')}"


def city_line() -> str:
    return f"{fake.city()}, {fake.state_abbr()} {fake.zipcode()}"


def address() -> str:
    suffix = rng.choice(["Street", "St", "Avenue", "Ave", "Road", "Drive", "Lane", "Blvd", "Court", "Way"])
    street = f"{rng.randint(1, 9999)} {fake.last_name()} {suffix}"
    return rng.choice([street, f"{street}, {fake.city()}, {fake.state_abbr()} {fake.zipcode()}"])


# (template, {slot: (TYPE or None, generator)}). TYPE None = decoy, must NOT be flagged.
TEMPLATES = [
    ("Hi, my name is {n} and my SSN is {s}.", {"n": ("PERSON", name), "s": ("SSN", ssn)}),
    ("Applicant: {n}, DOB: {d}, phone {p}", {"n": ("PERSON", name), "d": ("DOB", dob), "p": ("PHONE", phone)}),
    ("Please charge card {c} and email the receipt to {e}.", {"c": ("CREDIT_CARD", lambda: fmt_card(luhn_card(rng.choice(["4", "51", "55"]), 16))), "e": ("EMAIL", fake.email)}),
    ("Amex {c} was declined for order #{o}.", {"c": ("CREDIT_CARD", lambda: luhn_card(rng.choice(["34", "37"]), 15)), "o": (None, lambda: str(rng.randint(100000, 9999999)))}),
    ("Ship to {a} before Friday.", {"a": ("ADDRESS", address)}),
    ("Dear {n}, your claim was approved.", {"n": ("PERSON", name)}),
    ("Login from {i} at 3am looks suspicious.", {"i": ("IP_ADDRESS", fake.ipv4)}),
    ("She was born on {d} in {city}.", {"d": ("DOB", dob), "city": (None, fake.city)}),
    ("Customer: {n}, contact {e} or {p}.", {"n": ("PERSON", name), "e": ("EMAIL", fake.email), "p": ("PHONE", phone)}),
    ("Text me at {p} about the {amt} refund.", {"p": ("PHONE", phone), "amt": (None, lambda: f"${rng.randint(5, 900)}.{rng.randint(0, 99):02d}")}),
    # Decoy-only sentences.
    ("The meeting moved to {dt} in room {r}.", {"dt": (None, lambda: fake.date(pattern="%m/%d/%Y")), "r": (None, lambda: str(rng.randint(100, 999)))}),
    ("Tracking number {t} ships to ZIP {z}.", {"t": (None, lambda: "1Z" + fake.bothify("??######").upper()), "z": (None, fake.zipcode)}),
    ("What APR does the {bank} card charge after {m} months?", {"bank": (None, lambda: rng.choice(["Citi", "Chase", "Discover"])), "m": (None, lambda: str(rng.randint(6, 21)))}),
    # Realistic name forms.
    ("{n} called yesterday about the account.", {"n": ("PERSON", name)}),
    ("please email {n} about the refund", {"n": ("PERSON", lambda: us_name().lower())}),
    ("Hi {f}, thanks for the update.", {"f": ("PERSON", lambda: fake.first_name_female())}),
    ("Regards,\n{n}", {"n": ("PERSON", name)}),
    ("Borrower: {n} signed today.", {"n": ("PERSON", lambda: f"{fake.first_name()} {rng.choice('ABCDJKMR')}. {fake.last_name()} Jr.")}),
    ("Send it to {a} and {b}.", {"a": ("PERSON", name), "b": ("PERSON", name)}),
    # Realistic address forms.
    ("Office: {a}", {"a": ("ADDRESS", lambda: f"{rng.randint(10, 9999)} {rng.choice(['N', 'S', 'E', 'W'])} {ordinal(rng.randint(1, 120))} Street, {city_line()}")}),
    ("Mail checks to {a}.", {"a": ("ADDRESS", lambda: f"PO Box {rng.randint(10, 99999)}, {city_line()}")}),
    ("{a}", {"a": ("ADDRESS", lambda: f"Apt {rng.randint(1, 40)}{rng.choice('ABCD')}, {rng.randint(1, 9999)} {fake.last_name()} Ave, {city_line()}")}),
    ("Warehouse at {a}", {"a": ("ADDRESS", lambda: f"{rng.randint(100, 9999)} FM {rng.randint(100, 3000)}, {city_line()}")}),
    ("I live at {a}", {"a": ("ADDRESS", lambda: f"{rng.randint(1, 9999)} {fake.street_name().lower()} {fake.city().lower()} {fake.state_abbr().lower()} {fake.zipcode()}")}),
    ("Mail to:\n{a}", {"a": ("ADDRESS", lambda: f"{rng.randint(1, 9999)} {fake.last_name()} Blvd\n{city_line()}")}),
    # Decoys that look like names or addresses.
    ("Meet me at {p} at noon.", {"p": (None, lambda: rng.choice(["Grant Park", "Victoria Station", "Chase Bank", "Lincoln Center", "Jackson Heights"]))}),
    ("{w} you call the bank about {m}?", {"w": (None, lambda: rng.choice(["Will", "Can", "Should"])), "m": (None, lambda: rng.choice(["April", "June", "the Grace Period"]))}),
    ("I have {a} dogs and {b} cats on the {c} floor.", {"a": (None, lambda: str(rng.randint(2, 9))), "b": (None, lambda: str(rng.randint(2, 9))), "c": (None, lambda: ordinal(rng.randint(2, 30)))}),
    ("I moved from {c}, {s} last year.", {"c": (None, fake.city), "s": (None, fake.state_abbr)}),
    ("my friend {n} is coming", {"n": ("PERSON", lambda: name().lower())}),
    ("Our UK office: {a}", {"a": ("ADDRESS", lambda: f"Flat {rng.randint(1, 9)}, {rng.randint(1, 99)} High Road, Leeds LS1 4AP")}),
    # Hard cases (known gaps, kept on purpose).
    ("{n} agreed to the terms", {"n": ("PERSON", lambda: name().lower())}),
    ("Our Hyderabad office: {a}", {"a": ("ADDRESS", lambda: f"Flat {rng.randint(101, 909)}, Sai Residency, Madhapur, Hyderabad 500081")}),
]


def render(template, slots):
    text, spans, pos = "", [], 0
    import re
    for m in re.finditer(r"\{(\w+)\}", template):
        text += template[pos:m.start()]
        typ, gen = slots[m.group(1)]
        val = gen()
        if typ:
            spans.append({"type": typ, "start": len(text), "end": len(text) + len(val), "value": val})
        text += val
        pos = m.end()
    text += template[pos:]
    return text, spans


def main():
    out = Path(__file__).with_name("dataset.jsonl")
    with out.open("w") as f:
        for i in range(N):
            tpl, slots = TEMPLATES[i % len(TEMPLATES)]
            text, spans = render(tpl, slots)
            f.write(json.dumps({"id": i, "text": text, "spans": spans}) + "\n")
    print(f"wrote {N} examples to {out}")


if __name__ == "__main__":
    main()
