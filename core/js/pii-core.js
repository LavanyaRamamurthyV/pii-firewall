/*
 * PII Firewall core (JavaScript port). Mirrors core/python/pii_firewall.
 * Works in the browser (globalThis.PIICore) and in Node (module.exports).
 * Keep in sync with Python; core/fixtures/cases.json is tested against both.
 */
(function (root, factory) {
  const api = factory();
  if (typeof module === "object" && module.exports) module.exports = api;
  else root.PIICore = api;
})(typeof globalThis !== "undefined" ? globalThis : this, function () {
  "use strict";

  const PRIORITY = {
    CREDIT_CARD: 1, SSN: 2, EMAIL: 3, IP_ADDRESS: 4, PHONE: 5, DOB: 6, ADDRESS: 7, PERSON: 8,
  };
  const ENTITY_TYPES = Object.keys(PRIORITY);
  const ACTIONS = ["tokenize", "mask", "block", "allow"];

  // Case-insensitive literal without the (?i:) modifier (not in all browsers yet).
  const ci = (s) => s.replace(/[a-z]/gi, (c) => `[${c.toLowerCase()}${c.toUpperCase()}]`);

  const EMAIL_RE = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}\b/g;
  const SSN_RE = /(?<![\d-])(\d{3})([- ]?)(\d{2})\2(\d{4})(?![\d-])/g;
  const WORD_DIGITS = { zero: "0", oh: "0", one: "1", two: "2", three: "3", four: "4", five: "5", six: "6", seven: "7", eight: "8", nine: "9" };
  const WD = "(?:zero|oh|one|two|three|four|five|six|seven|eight|nine)";
  const SSN_WORDS_RE = new RegExp(String.raw`\b` + WD + String.raw`(?:[\s,-]+` + WD + String.raw`){8}\b(?![\s,-]+` + WD + String.raw`\b)`, "gi");
  const WD_BEFORE_RE = new RegExp(String.raw`\b` + WD + String.raw`[\s,-]+$`, "i");
  const CARD_RE = /(?<![\d-])(?:\d[ -]?){12,18}\d(?![\d-])/g;
  const PHONE_RE = /(?<![\w+])(?:\+?1[ .-]?)?(?:\(\d{3}\)\s?|\d{3}[ .-])\d{3}[ .-]\d{4}(?!\d)/g;
  const IP_RE = /(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?![\d.])/g;

  const DATE = String.raw`(?:\d{1,2}[/-]\d{1,2}[/-](?:\d{4}|\d{2})|\d{4}-\d{2}-\d{2}|(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Sept|Oct|Nov|Dec)[a-z]*\.? \d{1,2},? \d{4})`;
  const DOB_RE = new RegExp(
    String.raw`\b(?:dob|d\.o\.b\.?|date of birth|birth ?date|born(?: on)?)\b\s*[:\-]?\s*(` + DATE + ")",
    "gi"
  );

  const STREET_SUFFIX =
    "(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Drive|Dr|Lane|Ln|Court|Ct|Way|" +
    "Place|Pl|Terrace|Ter|Circle|Cir|Parkway|Pkwy|Highway|Hwy|Trail|Trl)";
  const ADDRESS_RE = new RegExp(
    String.raw`\b\d{1,6}\s+(?:[NSEW]\.?\s+)?(?:[A-Z][a-zA-Z]+\s+){1,3}` + STREET_SUFFIX + String.raw`\b\.?` +
      String.raw`(?:,?\s+(?:Apt|Apartment|Unit|Suite|Ste|#)\.?\s*[\w-]+)?` +
      String.raw`(?:,\s*[A-Z][a-zA-Z]+(?:\s[A-Z][a-zA-Z]+)*)?` +
      String.raw`(?:,\s*[A-Z]{2})?(?:\s+\d{5}(?:-\d{4})?)?`,
    "g"
  );

  const NAME = "[A-Z][a-z]+(?:[-'][A-Z][a-z]+)?";
  const FULL_NAME = NAME + String.raw`(?:\s+[A-Z]\.)?(?:\s+` + NAME + "){0,2}";
  const alt = (words) => "(?:" + words.map(ci).join("|") + ")";
  const PERSON_RES = [
    new RegExp(String.raw`\b` + alt(["my name is", "name is", "i am", "i'm", "this is"]) + String.raw`\s+(` + FULL_NAME + String.raw`\s+` + NAME + ")", "g"),
    new RegExp(String.raw`\b` + alt(["full name", "name", "applicant", "cardholder", "customer", "patient", "employee"]) + String.raw`\s*:\s*(` + FULL_NAME + ")", "g"),
    new RegExp(String.raw`\b(?:Mr|Mrs|Ms|Miss|Dr|Prof)\.?\s+(` + FULL_NAME + ")", "g"),
    new RegExp(String.raw`\b` + alt(["dear", "hi", "hello", "sincerely", "regards", "thanks"]) + String.raw`,?\s+(` + NAME + String.raw`\s+` + NAME + ")", "g"),
  ];
  const PERSON_STOPWORDS = new Set(["Street", "Avenue", "Road", "Drive", "Lane", "Bank", "Card", "The", "Team", "Customer", "Support"]);

  function luhnOk(digits) {
    let total = 0, altFlag = false;
    for (let i = digits.length - 1; i >= 0; i--) {
      let d = +digits[i];
      if (altFlag) { d *= 2; if (d > 9) d -= 9; }
      total += d;
      altFlag = !altFlag;
    }
    return total % 10 === 0;
  }

  function ssnOk(area, group, serial) {
    const a = +area;
    return a !== 0 && a !== 666 && a < 900 && group !== "00" && serial !== "0000";
  }

  const ent = (type, start, value) => ({ type, start, end: start + value.length, value });

  const DETECTORS = {
    EMAIL: (t) => [...t.matchAll(EMAIL_RE)].map((m) => ent("EMAIL", m.index, m[0])),
    SSN: (t) => [
      ...[...t.matchAll(SSN_RE)].filter((m) => ssnOk(m[1], m[3], m[4])).map((m) => ent("SSN", m.index, m[0])),
      ...[...t.matchAll(SSN_WORDS_RE)]
        .filter((m) => {
          if (WD_BEFORE_RE.test(t.slice(0, m.index))) return false; // part of a longer run of number words
          const d = m[0].match(/[A-Za-z]+/g).map((w) => WORD_DIGITS[w.toLowerCase()]).join("");
          return ssnOk(d.slice(0, 3), d.slice(3, 5), d.slice(5));
        })
        .map((m) => ent("SSN", m.index, m[0])),
    ],
    CREDIT_CARD: (t) =>
      [...t.matchAll(CARD_RE)]
        .filter((m) => {
          const d = m[0].replace(/\D/g, "");
          return d.length >= 13 && d.length <= 19 && luhnOk(d) && new Set(d).size > 1;
        })
        .map((m) => ent("CREDIT_CARD", m.index, m[0])),
    PHONE: (t) =>
      [...t.matchAll(PHONE_RE)]
        .filter((m) => {
          let d = m[0].replace(/\D/g, "");
          if (d.length === 11 && d[0] === "1") d = d.slice(1);
          return d.length === 10 && !"01".includes(d[0]) && !"01".includes(d[3]);
        })
        .map((m) => ent("PHONE", m.index, m[0])),
    IP_ADDRESS: (t) => [...t.matchAll(IP_RE)].map((m) => ent("IP_ADDRESS", m.index, m[0])),
    // Captured value is always the suffix of the match for DOB and PERSON.
    DOB: (t) => [...t.matchAll(DOB_RE)].map((m) => ent("DOB", m.index + m[0].length - m[1].length, m[1])),
    ADDRESS: (t) =>
      [...t.matchAll(ADDRESS_RE)].map((m) => ent("ADDRESS", m.index, m[0].replace(/[.,]+$/, ""))),
    PERSON: (t) =>
      PERSON_RES.flatMap((rx) =>
        [...t.matchAll(rx)]
          .filter((m) => !m[1].split(/\s+/).some((w) => PERSON_STOPWORDS.has(w.replace(/\./g, ""))))
          .map((m) => ent("PERSON", m.index + m[0].length - m[1].length, m[1]))
      ),
  };

  function detect(text, types) {
    const wanted = new Set(types && types.length ? types : ENTITY_TYPES);
    const found = [];
    for (const [t, fn] of Object.entries(DETECTORS)) if (wanted.has(t)) found.push(...fn(text));
    found.sort((a, b) => PRIORITY[a.type] - PRIORITY[b.type] || (b.end - b.start) - (a.end - a.start) || a.start - b.start);
    const kept = [];
    for (const e of found) if (kept.every((k) => e.end <= k.start || e.start >= k.end)) kept.push(e);
    return kept.sort((a, b) => a.start - b.start);
  }

  function mask(e) {
    const v = e.value;
    if (["SSN", "CREDIT_CARD", "PHONE"].includes(e.type)) {
      let seen = 0;
      return v.split("").reverse().map((ch) => (/\d/.test(ch) ? (seen++ < 4 ? ch : "*") : ch)).reverse().join("");
    }
    if (e.type === "EMAIL") {
      const at = v.indexOf("@");
      return v.slice(0, 1) + "***" + v.slice(at);
    }
    return `[${e.type}]`;
  }

  function normalise(e) {
    if (["SSN", "CREDIT_CARD", "PHONE"].includes(e.type)) {
      const d = e.value.replace(/\D/g, "");
      return e.type === "PHONE" && d.length === 11 ? d.slice(1) : d;
    }
    return e.type === "EMAIL" ? e.value.toLowerCase() : e.value;
  }

  const TOKEN_RE = new RegExp(String.raw`\[(` + ENTITY_TYPES.join("|") + String.raw`)_(\d+)\]`, "g");

  class Firewall {
    constructor(policy, state) {
      this.policy = Object.assign(Object.fromEntries(ENTITY_TYPES.map((t) => [t, "tokenize"])), policy || {});
      for (const [t, a] of Object.entries(this.policy)) {
        if (!ENTITY_TYPES.includes(t)) throw new Error(`Unknown entity type: ${t}`);
        if (!ACTIONS.includes(a)) throw new Error(`Unknown action for ${t}: ${a}`);
      }
      const s = state || {};
      this.vault = s.vault || {};      // token -> value
      this.index = s.index || {};      // "TYPE|normalised" -> token
      this.counters = s.counters || {};
    }

    exportState() {
      return { vault: this.vault, index: this.index, counters: this.counters };
    }

    tokenFor(e) {
      const key = e.type + "|" + normalise(e);
      if (!this.index[key]) {
        const n = (this.counters[e.type] || 0) + 1;
        this.counters[e.type] = n;
        const tok = `[${e.type}_${n}]`;
        this.index[key] = tok;
        this.vault[tok] = e.value;
      }
      return this.index[key];
    }

    scan(text) {
      return detect(text, ENTITY_TYPES.filter((t) => this.policy[t] !== "allow"));
    }

    redact(text) {
      const findings = [];
      let out = "", pos = 0, blocked = false;
      for (const e of this.scan(text)) {
        const action = this.policy[e.type];
        let rep;
        if (action === "tokenize") rep = this.tokenFor(e);
        else if (action === "mask") rep = mask(e);
        else { rep = `[REDACTED_${e.type}]`; blocked = true; }
        out += text.slice(pos, e.start) + rep;
        pos = e.end;
        findings.push({ type: e.type, action, start: e.start, end: e.end, replacement: rep });
      }
      out += text.slice(pos);
      return { text: out, findings, blocked };
    }

    rehydrate(text) {
      return text.replace(TOKEN_RE, (tok) => (tok in this.vault ? this.vault[tok] : tok));
    }
  }

  return { ENTITY_TYPES, ACTIONS, detect, mask, luhnOk, Firewall, TOKEN_RE };
});
