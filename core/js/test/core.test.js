// Run with: node --test core/js/test
const test = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");
const fs = require("node:fs");
const { detect, Firewall } = require("../pii-core.js");

const cases = JSON.parse(fs.readFileSync(path.join(__dirname, "../../fixtures/cases.json"), "utf8"));

for (const c of cases) {
  test(`fixture: ${c.id}`, () => {
    assert.deepEqual(detect(c.text).map((e) => [e.type, e.value]), c.expect);
  });
}

test("tokenize and rehydrate roundtrip", () => {
  const fw = new Firewall();
  const r = fw.redact("SSN 123-45-6789 and again 123456789, email a@b.com");
  assert.equal(r.text, "SSN [SSN_1] and again [SSN_1], email [EMAIL_1]");
  assert.equal(
    fw.rehydrate("I see [SSN_1] belongs to [EMAIL_1]; [SSN_9] is unknown."),
    "I see 123-45-6789 belongs to a@b.com; [SSN_9] is unknown."
  );
});

test("mask, block, allow", () => {
  const fw = new Firewall({ SSN: "mask", CREDIT_CARD: "block", EMAIL: "allow" });
  const r = fw.redact("123-45-6789 / 4111 1111 1111 1111 / a@b.com");
  assert.equal(r.text, "***-**-6789 / [REDACTED_CREDIT_CARD] / a@b.com");
  assert.equal(r.blocked, true);
});

test("state survives export/import", () => {
  const a = new Firewall();
  a.redact("a@b.com");
  const b = new Firewall(null, JSON.parse(JSON.stringify(a.exportState())));
  assert.equal(b.redact("again a@b.com").text, "again [EMAIL_1]");
  assert.equal(b.rehydrate("[EMAIL_1]"), "a@b.com");
});
