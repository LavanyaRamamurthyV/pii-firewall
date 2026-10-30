import json
from pathlib import Path

import pytest
from pii_firewall import Firewall, detect

CASES = json.loads((Path(__file__).parents[2] / "fixtures" / "cases.json").read_text())


@pytest.mark.parametrize("case", CASES, ids=[c["id"] for c in CASES])
def test_fixture(case):
    got = [[e.type, e.value] for e in detect(case["text"])]
    assert got == case["expect"]


def test_tokenize_and_rehydrate_roundtrip():
    fw = Firewall()
    text = "SSN 123-45-6789 and again 123456789, email a@b.com"
    r = fw.redact(text)
    assert r.text == "SSN [SSN_1] and again [SSN_1], email [EMAIL_1]"
    assert "123" not in r.text
    reply = "I see [SSN_1] belongs to [EMAIL_1]; [SSN_9] is unknown."
    assert fw.rehydrate(reply) == "I see 123-45-6789 belongs to a@b.com; [SSN_9] is unknown."


def test_mask_block_allow():
    fw = Firewall(policy={"SSN": "mask", "CREDIT_CARD": "block", "EMAIL": "allow"})
    r = fw.redact("123-45-6789 / 4111 1111 1111 1111 / a@b.com")
    assert r.text == "***-**-6789 / [REDACTED_CREDIT_CARD] / a@b.com"
    assert r.blocked is True


def test_audit_log_has_no_raw_values():
    fw = Firewall()
    fw.redact("SSN 123-45-6789")
    assert fw.audit_log[0]["counts"] == {"SSN": 1}
    assert "123-45-6789" not in json.dumps(fw.audit_log)


def test_bad_policy_rejected():
    with pytest.raises(ValueError):
        Firewall(policy={"SSN": "shred"})
