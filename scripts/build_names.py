"""Build the name dictionary used by both engines.

Sources: Faker's name lists (MIT licence, many locales), a hand-added list of
common names Faker lacks, and wordfreq's English frequency list to find names
that are also everyday words ("Will", "Mark", "Grace").

Writes:
  core/python/pii_firewall/data/names.json   (Python engine)
  core/js/pii-names.js                       (JavaScript engine, same data)

Usage: pip install faker wordfreq && python scripts/build_names.py
"""

import json
import unicodedata
from pathlib import Path

from faker import Faker
from wordfreq import top_n_list

ROOT = Path(__file__).resolve().parents[1]
LOCALES = ["en_US", "en_GB", "en_IN", "hi_IN", "es_MX", "es_ES", "pt_BR", "fr_FR", "de_DE", "it_IT",
           "tl_PH", "en_NG", "yo_NG", "vi_VN", "zh_CN", "ja_JP", "tr_TR", "pl_PL", "nl_NL"]

EXTRA_FIRST = """
rajesh ramesh suresh mahesh ganesh venkat venkatesh srinivas lakshman karthik arjun vikram sanjay deepak anil sunil
vijay ajay rahul rohit amit sumit nikhil pradeep praveen naveen harish girish satish manoj vinod ashok prakash kiran
srikanth sai balaji murali gopal krishna ravi raju kavya divya swathi sowmya lavanya bhavana keerthi sneha pooja neha
shreya ananya meera padma sudha usha geetha revathi varun tarun arun aditya akash ankit gaurav harsh kunal mohit
pranav rakesh sandeep saurabh shankar siddharth sachin vivek yash aarav vihaan ishaan priyanka shweta nisha anjali
deepika kavitha radha sita gita lata sangeetha sharmila vasanthi
kwame kofi kwesi kwabena yaw ama akua abena efua chinedu chukwuemeka chidi ngozi adebayo oluwaseun tunde femi folake
emeka obinna uchenna amara zuri jabari
fatima aisha mohammed muhammad mohamed ahmed omar hassan hussein yusuf ibrahim khalid tariq zainab layla amir karim
rashid samir nadia yasmin leila farah
mei ling xin jun hui yan ying wei jing hao yu xiao hiroshi takeshi yuki sakura kenji haruto yuto sora minh thanh duc
linh anh tuan hoa
olga ivan dmitri sergei natasha svetlana igor alexei giovanni luca matteo francesca chiara
will bill may ray art gene frank earl miles drew dale glen dean chip cliff penny holly ivy ruby pearl rose
""".split()

EXTRA_LAST = """
kumar reddy rao naidu iyer iyengar nair pillai menon patel shah mehta gupta agarwal jain singh kaur gill chopra
malhotra kapoor khanna bose banerjee chatterjee mukherjee ghosh verma mishra pandey tiwari yadav chauhan joshi desai
kulkarni deshpande rajan krishnan subramanian venkatesan ramamurthy ramachandran srinivasan raghavan venkataraman
narayanan sharma varma chandra prasad murthy sastry hegde shetty bhat
mensah owusu boateng asante okafor okonkwo adeyemi abubakar oyelaran nwosu eze
khan hussain rahman chowdhury siddiqui qureshi malik
nguyen tran pham huang wang zhang liu chen yang zhao zhou sun zhu guo lin gao luo zheng
kim park choi jung kang cho yoon jang lim
tanaka suzuki sato takahashi watanabe yamamoto nakamura kobayashi
ivanov petrov smirnov kowalski nowak rossi russo ferrari esposito bianchi muller schmidt schneider fischer weber
""".split()

# Faker noise and words that are almost never first names.
DROP_FIRST = set("""
edit else floor forum gang harm job kick lot na nazi over server side sole ties till toy us calm canal ball jet
africa america hong angeles francisco carolina
""".split())

# First names that are everyday words or places: need a known surname after them.
AMBIGUOUS_FIRST = set("""
angel april august autumn bill charity chase chelsea christian comfort crystal dawn dean diamond drew faith georgia
german grace grant guy hope hunter isis israel jack jackson jordan joy june justin lucky marine mark max min parker
peace rose roman ross summer sydney urban van victoria virginia wolf will may gene ray robin art frank earl miles
page penny sterling stone young cash chance cliff dale glen heath holly ivy jade ruby pearl amber lily iris violet
sky sunny storm river rocky rusty sage destiny harmony melody honor liberty royal star sugar candy ginger
sue pat rob nick morgan
""".split())


def ascii_lower(s: str) -> str:
    return unicodedata.normalize("NFKD", s).encode("ascii", "ignore").decode().strip().lower()


def ok(name: str) -> bool:
    return len(name) > 1 and name.replace("-", "").replace("'", "").isalpha()


def main():
    first, last = set(), set()
    for loc in LOCALES:
        p = Faker(loc).provider("faker.providers.person")
        for attr, bag in [("first_names", first), ("first_names_male", first), ("first_names_female", first),
                          ("last_names", last), ("first_romanized_names", first), ("last_romanized_names", last)]:
            v = getattr(p, attr, None)
            if v is None:
                continue
            for n in (v.keys() if isinstance(v, dict) else v):
                if n[:1].isupper() and " " not in n.strip():
                    a = ascii_lower(n)
                    if ok(a):
                        bag.add(a)
    first |= set(EXTRA_FIRST)
    last |= set(EXTRA_LAST)
    first -= DROP_FIRST

    common5k = set(top_n_list("en", 5000))
    common1k = set(top_n_list("en", 1000))
    data = {
        "_source": "Faker name lists (MIT) + hand-added names; wordfreq English frequencies. Built by scripts/build_names.py",
        "first": sorted(first),
        "last": sorted(last),
        "ambiguous_first": sorted(AMBIGUOUS_FIRST & first),
        # Surnames that are everyday words ("brown", "king"); only trusted when capitalised.
        "ambiguous_last": sorted(last & common1k),
        # Everyday words that are not surnames; a capitalised one can't end a name.
        "common": sorted(w for w in common5k - last if w.isalpha()),
    }
    out_py = ROOT / "core/python/pii_firewall/data/names.json"
    out_py.parent.mkdir(parents=True, exist_ok=True)
    out_py.write_text(json.dumps(data, separators=(",", ":")) + "\n")
    js = (
        "// Generated by scripts/build_names.py from core/python/pii_firewall/data/names.json. Do not edit.\n"
        "(function (root) {\n  const data = " + json.dumps(data, separators=(",", ":")) + ";\n"
        "  if (typeof module === \"object\" && module.exports) module.exports = data;\n"
        "  else root.PIINames = data;\n"
        "})(typeof globalThis !== \"undefined\" ? globalThis : this);\n"
    )
    (ROOT / "core/js/pii-names.js").write_text(js)
    print(f"first={len(first)} last={len(last)} ambiguous_first={len(data['ambiguous_first'])} "
          f"ambiguous_last={len(data['ambiguous_last'])} common={len(data['common'])} "
          f"size={len(js) // 1024} KB")


if __name__ == "__main__":
    main()
