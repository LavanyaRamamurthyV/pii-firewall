/*
 * PII Firewall core (JavaScript port). Mirrors core/python/pii_firewall.
 * Works in the browser (globalThis.PIICore) and in Node (module.exports).
 * Keep in sync with Python; core/fixtures/cases.json is tested against both.
 */
(function (root, factory) {
  const isNode = typeof module === "object" && module.exports;
  // Name dictionary: core/js/pii-names.js (load it before this file in a browser).
  const api = factory(isNode ? require("./pii-names.js") : root.PIINames);
  if (isNode) module.exports = api;
  else root.PIICore = api;
})(typeof globalThis !== "undefined" ? globalThis : this, function (NAMES) {
  "use strict";

  const PRIORITY = {
    CREDIT_CARD: 1, SSN: 2, EMAIL: 3, IP_ADDRESS: 4, PHONE: 5, DOB: 6, ADDRESS: 7, PERSON: 8,
  };
  const ENTITY_TYPES = Object.keys(PRIORITY);
  const ACTIONS = ["tokenize", "mask", "block", "allow"];

  if (!NAMES) throw new Error("PII Firewall: load pii-names.js before pii-core.js");

  // ---------- regex helpers (same as core/python/pii_firewall/_rx.py) ----------
  const esc = (s) => s.replace(/([.*+?^${}()|[\]\\])/g, "\\$1");
  // Case-insensitive pattern for a plain phrase; spaces match any whitespace run.
  const ci = (phrase) =>
    phrase.split(/\s+/).filter(Boolean)
      .map((w) => w.split("").map((c) => (/[A-Za-z]/.test(c) ? `[${c.toLowerCase()}${c.toUpperCase()}]` : esc(c))).join(""))
      .join(String.raw`\s+`);
  // Alternation, longest first so "Street" wins over "St".
  const alt = (words, fn = esc) => "(?:" + [...words].sort((a, b) => b.length - a.length).map(fn).join("|") + ")";
  const words = (s) => s.trim().split(/\s+/);

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

  // ---------- addresses (same as core/python/pii_firewall/addresses.py) ----------
  const A_SUFFIXES = words(`Street St Avenue Ave Av Road Rd Boulevard Blvd Drive Dr Lane Ln Court Ct Way Place Pl Terrace Ter
    Circle Cir Parkway Pkwy Highway Hwy Trail Trl Square Sq Loop Path Pike Row Alley Aly Crossing Xing Point Pt Ridge Rdg
    Cove Cv Bend Hollow Holw Commons Plaza Plz Expressway Expy Freeway Fwy Turnpike Tpke Walk Mews Close Crescent Cres
    Gardens Gdns Grove Grv Heights Hts Meadow Meadows Mdw Park Pass Glen Creek Crk Landing Lndg Manor Mnr Estates View
    Vw Vista Center Ctr Junction Jct Run Trace Hill Hills`);
  const STATE_ABBR = words(`AL AK AZ AR CA CO CT DE DC FL GA HI ID IL IN IA KS KY LA ME MD MA MI MN MS MO MT NE NV NH NJ NM NY
    NC ND OH OK OR PA RI SC SD TN TX UT VT VA WA WV WI WY PR VI GU AS MP FM MH PW AA AE AP`);
  const STATE_NAMES = ["Alabama", "Alaska", "Arizona", "Arkansas", "California", "Colorado", "Connecticut", "Delaware",
    "District of Columbia", "Florida", "Georgia", "Hawaii", "Idaho", "Illinois", "Indiana", "Iowa",
    "Kansas", "Kentucky", "Louisiana", "Maine", "Maryland", "Massachusetts", "Michigan", "Minnesota",
    "Mississippi", "Missouri", "Montana", "Nebraska", "Nevada", "New Hampshire", "New Jersey",
    "New Mexico", "New York", "North Carolina", "North Dakota", "Ohio", "Oklahoma", "Oregon",
    "Pennsylvania", "Rhode Island", "South Carolina", "South Dakota", "Tennessee", "Texas", "Utah",
    "Vermont", "Virginia", "Washington", "West Virginia", "Wisconsin", "Wyoming", "Puerto Rico", "Guam",
    "American Samoa", "U.S. Virgin Islands", "Northern Mariana Islands"];
  const A_CUES = ["address is", "address", "addr", "live at", "lives at", "living at", "reside at", "resides at",
    "residing at", "located at", "staying at", "stay at", "moved to", "move to", "ship to", "ship it to",
    "ship this to", "deliver to", "deliver it to", "mail to", "mail it to", "send to", "send it to",
    "send this to", "house is at", "home is at"];

  const NUM = String.raw`\d{1,6}[A-Za-z]?(?:-\d{1,5})?`;
  const DIR = String.raw`(?:(?:N|S|E|W|NE|NW|SE|SW)\.?|` + alt(["North", "South", "East", "West", "Northeast", "Northwest",
    "Southeast", "Southwest"], ci) + ")";
  const CAP_WORD = String.raw`(?:[A-Z][a-zA-Z'-]*|\d{1,3}(?:st|nd|rd|th))`;
  const ANY_WORD = String.raw`(?:[A-Za-z][A-Za-z'-]*|\d{1,3}(?:st|nd|rd|th))`;
  const SUFFIX = alt(A_SUFFIXES, ci) + String.raw`\b\.?`;
  const ROUTE = String.raw`(?:(?:FM|RM|CR|SR|US|IH|I-)\s?\d{1,4}|`
    + alt(["Interstate", "Highway", "State Highway", "State Route", "County Road", "Route", "Rte"], ci)
    + String.raw`\s+\d{1,4})[A-Za-z]?\b`;
  const UNIT = String.raw`(?:,?\s*` + alt(["Apt", "Apartment", "Unit", "Suite", "Ste", "Bldg", "Building", "Floor", "Fl", "Room",
    "Rm", "Lot", "Flat"], ci) + String.raw`\.?\s*#?\s*[A-Za-z0-9-]{1,6}\b|,?\s*#\s*[A-Za-z0-9-]{1,6}\b)`;
  const UNIT_FIRST = "(?:" + alt(["Apt", "Apartment", "Unit", "Suite", "Ste", "Flat"], ci) + String.raw`\.?\s*#?\s*[A-Za-z0-9-]{1,6},?\s+)`;
  const CITY = String.raw`[A-Z][a-zA-Z.'-]+(?:[ \t][A-Z][a-zA-Z.'-]+){0,2}\b`;
  const STATE = "(?:" + alt(STATE_ABBR) + "|" + alt(STATE_NAMES) + String.raw`)\b`;
  const STATE_ANYCASE = "(?:" + alt(STATE_ABBR, ci) + "|" + alt(STATE_NAMES, ci) + String.raw`)\b`;
  const ZIP = String.raw`\d{5}(?:-\d{4})?\b`;
  const UK_POSTCODE = String.raw`[A-Z]{1,2}\d[A-Z\d]?[ \t]?\d[A-Z]{2}\b`;
  const TAIL = String.raw`(?:(?:,[ \t]*|[ \t]*\n[ \t]*|[ \t]+)` + CITY + String.raw`,?[ \t]+` + STATE + String.raw`(?:,?[ \t]+` + ZIP + ")?"
    + String.raw`|,[ \t]*` + CITY + String.raw`(?:,?[ \t]+(?:` + ZIP + "|" + UK_POSTCODE + "))?"
    + String.raw`|,?[ \t]+` + STATE + String.raw`(?:,?[ \t]+` + ZIP + ")?"
    + String.raw`|,?[ \t]+` + ZIP + ")?";

  const STREET_RE = new RegExp(String.raw`\b` + UNIT_FIRST + "?" + NUM + String.raw`[ \t]+(?:` + DIR + String.raw`[ \t]+)?(?:` + ROUTE
    + "|(?:" + CAP_WORD + String.raw`[ \t]+){0,3}` + CAP_WORD + String.raw`[ \t]+` + SUFFIX + ")"
    + String.raw`(?:[ \t]+` + DIR + String.raw`\b)?` + UNIT + "?" + TAIL, "g");
  const PO_BOX_RE = new RegExp(String.raw`\b(?:[Pp]\.?[ \t]?[Oo]\.?[ \t]*[Bb][Oo][Xx]|` + ci("Post Office Box") + String.raw`)[ \t]*#?[ \t]*\d{1,8}\b`
    + TAIL, "g");
  const CITY_ZIP_RE = new RegExp(String.raw`\b` + CITY + String.raw`,[ \t]*` + STATE + String.raw`[ \t]+` + ZIP, "g");
  const STATE_ZIP_RE = new RegExp(String.raw`\b` + NUM + String.raw`[ \t]+(?:` + ANY_WORD + String.raw`[ \t,]+){1,6}?` + STATE_ANYCASE + String.raw`,?[ \t]+` + ZIP, "g");
  const A_CUE_RE = new RegExp(String.raw`\b` + alt(A_CUES, ci) + String.raw`[ \t]*[:\-]?\s*`, "g");
  // After a cue: a house number and the rest of the phrase, up to the end of the sentence or a joining word.
  const LOOSE_RE = new RegExp(NUM + String.raw`[ \t]+[^\n;!?]{2,80}?(?=[ \t]*(?:[;!?\n]|\.(?:[ \t]+[A-Z]|[ \t]*$)|$)|,?[ \t]+`
    + alt(["and", "but", "so", "then", "please", "thanks", "thank", "because", "since", "before",
      "after", "by", "on", "for", "today", "tomorrow"], ci) + String.raw`\b)`, "y");

  function trimEnd(text, start, end) {
    while (end > start && " \t,.".includes(text[end - 1])) end--;
    return end;
  }

  function findAddresses(text) {
    const out = [];
    for (const rx of [STREET_RE, PO_BOX_RE, CITY_ZIP_RE, STATE_ZIP_RE]) {
      for (const m of text.matchAll(rx)) out.push([m.index, trimEnd(text, m.index, m.index + m[0].length)]);
    }
    for (const cue of text.matchAll(A_CUE_RE)) {
      LOOSE_RE.lastIndex = cue.index + cue[0].length;
      const m = LOOSE_RE.exec(text);
      if (m) out.push([m.index, trimEnd(text, m.index, m.index + m[0].length)]);
    }
    return out;
  }

  // ---------- names (same as core/python/pii_firewall/names.py) ----------
  const FIRST = new Set(NAMES.first);
  const LAST = new Set(NAMES.last);
  const AMBIGUOUS_FIRST = new Set(NAMES.ambiguous_first);
  const AMBIGUOUS_LAST = new Set(NAMES.ambiguous_last);
  const COMMON = new Set(NAMES.common);
  const PLACE_ORG = new Set(words(`
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
    texas california florida georgia virginia washington carolina dakota york jersey india china america england`));
  const PLACE_PREFIX = new Set(words("saint st mount mt fort ft lake port san santa los las new north south east west university college bank"));
  const STOP_TOKENS = new Set(words("jan feb mar apr jun jul aug sep sept oct nov dec mon tue tues wed thu thur thurs fri sat sun"));
  const PARTICLES = new Set(words("de da del della di dos du la le van von der den bin ibn al el ter"));
  const N_SUFFIXES = new Set(words("jr sr ii iii iv"));
  const GREETING_CUES = ["hi", "hello", "hey", "dear", "thanks", "thank you", "thx", "cc", "attn", "attention"];
  const SELF_CUES = ["my name is", "my name's", "name is", "i am", "i'm", "this is", "call me", "i go by"];
  const SIGNOFF_CUES = ["dear", "hi", "hello", "hey", "sincerely", "regards", "best", "thanks", "cheers"];
  const LABELS = ["full name", "name", "applicant", "co-applicant", "borrower", "co-borrower", "cardholder", "card holder",
    "account holder", "customer", "client", "patient", "employee", "member", "beneficiary", "insured",
    "policyholder", "tenant", "guarantor", "spouse", "student", "guest", "passenger", "owner", "contact",
    "signed", "signature", "from", "to", "attn", "recipient", "sender", "payee"];

  // Context that says the next/previous words are a person, for names the dictionary doesn't know.
  const BEFORE_CUES = ["email", "e-mail", "call", "ask", "tell", "cc", "contact", "meet", "pay", "text", "message",
    "send it to", "send this to", "send to", "forward to", "forward it to", "introduce", "named"];
  const AFTER_CUES = ["called", "said", "says", "emailed", "wrote", "asked", "told", "replied", "mentioned", "signed",
    "paid", "texted", "phoned"];
  const RELATIONS = ["friend", "wife", "husband", "son", "daughter", "mother", "mom", "father", "dad", "brother", "sister",
    "colleague", "coworker", "boss", "manager", "neighbor", "neighbour", "partner", "cousin", "uncle", "aunt",
    "grandma", "grandpa", "grandmother", "grandfather", "client", "doctor", "lawyer", "landlord", "tenant"];
  const WORD_RE = /[A-Za-z]+(?:['’-][A-Za-z]+)*\.?/g;
  const NAME = "[A-Z][a-z]+(?:[-'’][A-Z]?[a-z]+)?";
  const FULL_NAME = NAME + String.raw`(?:[ \t]+[A-Z]\.)?(?:[ \t]+` + NAME + "){0,2}";
  const CUE_RES = [
    new RegExp(String.raw`\b` + alt(SELF_CUES, ci) + String.raw`[ \t]+(` + FULL_NAME + String.raw`[ \t]+` + NAME + ")", "g"),
    new RegExp(String.raw`\b` + alt(LABELS, ci) + String.raw`(?:[ \t]*:\s*|[ \t]+[-–][ \t]+)(` + FULL_NAME + ")", "g"),
    new RegExp(String.raw`\b(?:Mr|Mrs|Ms|Miss|Mx|Dr|Prof)\.?[ \t]+(` + FULL_NAME + ")", "g"),
    new RegExp(String.raw`\b` + alt(SIGNOFF_CUES, ci) + String.raw`,?\s+(` + NAME + String.raw`(?:[ \t]+` + NAME + "){1,2})", "g"),
  ];
  const CTX_BEFORE_RE = new RegExp(String.raw`\b` + alt(BEFORE_CUES, ci) + String.raw`[ \t]+(` + NAME + String.raw`[ \t]+` + NAME + String.raw`|[a-z]+[ \t]+[a-z]+)\b`, "g");
  const CTX_AFTER_RE = new RegExp(String.raw`\b(` + NAME + String.raw`[ \t]+` + NAME + String.raw`)[ \t]+` + alt(AFTER_CUES, ci) + String.raw`\b`, "g");
  const RELATION_RE = new RegExp(String.raw`\b` + alt(["my", "our", "your", "his", "her", "their"], ci) + String.raw`[ \t]+` + alt(RELATIONS, ci)
    + String.raw`[ \t]*,?[ \t]+([A-Za-z][A-Za-z'’-]*(?:[ \t]+[A-Za-z][A-Za-z'’-]*){0,2})`, "g");
  // More names joined to a found one: "Mats Brandt and Belo Durka", "A, B and C"
  const JOINED_RE = new RegExp(String.raw`[ \t]*(?:,[ \t]*(?:and|or|&)?|and|or|&)[ \t]+(` + NAME + String.raw`(?:[ \t]+` + NAME + String.raw`){1,2})\b`, "y");
  // Single known first name after a greeting: "Hi Priya," / "Thanks, Rahul!"
  const GREETING_RE = new RegExp(String.raw`\b` + alt(GREETING_CUES, ci) + String.raw`[ \t]*,?[ \t]+(` + NAME + String.raw`)\b(?![ \t]+[A-Z])`, "g");
  // Lowercase self-introduction: "my name is rahul", "i'm priya sharma"
  const SELF_LOWER_RE = new RegExp(String.raw`\b` + alt(SELF_CUES, ci) + String.raw`[ \t]+([a-z]+(?:[ \t]+[a-z]+){0,2})\b`, "g");

  const isLower = (s) => s === s.toLowerCase() && s !== s.toUpperCase();
  const isUpper = (s) => s === s.toUpperCase() && s !== s.toLowerCase();
  function style(tok) {
    const core = tok.replace(/\.+$/, "");
    if (core.length === 1 && isUpper(core)) return "initial";
    if (isLower(core)) return "lower";
    if (isUpper(core)) return "upper";
    if (isUpper(core[0])) return "cap";
    return "other";
  }
  const key = (tok) => tok.replace(/\.+$/, "").replace(/['’]s$/, "").toLowerCase();

  function validLast(tok, strict) {
    const k = key(tok);
    if (PLACE_ORG.has(k) || k.length < 2) return false;
    const parts = k.replace(/’/g, "'").split("-");
    if (strict) return parts.every((p) => LAST.has(p) && !AMBIGUOUS_LAST.has(p) && p.length >= 3);
    return parts.every((p) => LAST.has(p) || !COMMON.has(p));
  }

  function dictionaryNames(text, out) {
    const toks = [...text.matchAll(WORD_RE)].map((m) => [m.index, m.index + m[0].length, m[0]]);
    const joined = (a, b) => /^[ \t]+$/.test(text.slice(toks[a][1], toks[b][0]));
    let i = 0;
    while (i < toks.length) {
      const [s, , t] = toks[i];
      const st = style(t), k = key(t);
      if (!["cap", "lower", "upper"].includes(st) || !FIRST.has(k) || t.endsWith(".")) { i++; continue; }
      // A place word right before ("Lake Victoria", "St. John") makes this a place.
      if (i > 0 && joined(i - 1, i) && PLACE_PREFIX.has(key(toks[i - 1][2])) && style(toks[i - 1][2]) !== "lower") { i++; continue; }
      const strict = st !== "cap";
      if (strict && AMBIGUOUS_FIRST.has(k)) { i++; continue; }
      let best = null, j = i;
      while (j + 1 < toks.length && j - i < 4 && joined(j, j + 1)) {
        const nt = toks[j + 1][2];
        const ns = style(nt), nk = key(nt);
        if (!strict && ns === "initial") { j++; continue; }                         // "Robert J. Smith"
        if (!strict && ns === "lower" && PARTICLES.has(nk)) { j++; continue; }      // "Maria de la Cruz"
        if (strict ? ns !== st : ns !== "cap") break;
        if (PLACE_ORG.has(nk)) { best = null; break; }                             // "Grant Park"
        if (STOP_TOKENS.has(nk)) break;                                             // "Briggs Mar"
        if (N_SUFFIXES.has(nk)) { if (best !== null) best = j + 1; break; }         // "Smith Jr."
        if (validLast(nt, strict) && (!AMBIGUOUS_FIRST.has(k) || LAST.has(nk))) best = j + 1;
        else if (strict || COMMON.has(nk)) break;
        if (nt.endsWith(".") || /['’]s$/.test(nt)) break;                           // possessive ends the name
        j++;
      }
      if (best === null) { i++; continue; }
      // Optional suffix after a comma: "Robert Smith, Sr."
      let end = toks[best][1];
      const nxt = best + 1;
      if (nxt < toks.length && N_SUFFIXES.has(key(toks[nxt][2])) && /^,[ \t]*$/.test(text.slice(end, toks[nxt][0]))) {
        best = nxt;
        end = toks[nxt][1];
      }
      if (!N_SUFFIXES.has(key(toks[best][2]))) end = s + text.slice(s, end).replace(/\.+$/, "").length;
      end -= text.slice(s, end).match(/(?:['’]s)?$/)[0].length;                    // "Brown's" -> "Brown"
      out.push([s, end]);
      i = best + 1;
    }
  }

  function cueNames(text, out) {
    CUE_RES.forEach((rx, idx) => {
      for (const m of text.matchAll(rx)) {
        const ws = m[1].split(/\s+/).map(key);
        if (ws.some((w) => PLACE_ORG.has(w) || STOP_TOKENS.has(w))) continue;
        const known = ws.map((w) => FIRST.has(w) || LAST.has(w));
        if (ws.length === 1) {
          if (!known[0] && !(idx === 2 && !COMMON.has(ws[0]))) continue;
        } else if (!known.some(Boolean) && ws.every((w) => COMMON.has(w))) continue;
        const start = m.index + m[0].length - m[1].length;
        out.push([start, start + m[1].length]);
      }
    });
    for (const m of text.matchAll(GREETING_RE)) {
      const k = m[1].toLowerCase();
      // After a greeting even word-names are names ("Hi Grace,") when punctuation follows.
      if (FIRST.has(k) && (!AMBIGUOUS_FIRST.has(k) || /^[ \t]*[,.!:]/.test(text.slice(m.index + m[0].length)))) {
        const start = m.index + m[0].length - m[1].length;
        out.push([start, start + m[1].length]);
      }
    }
    for (const m of text.matchAll(SELF_LOWER_RE)) {
      const ws = m[1].split(/\s+/);
      if (!FIRST.has(ws[0]) || AMBIGUOUS_FIRST.has(ws[0])) continue;
      let keep = 1;
      for (const w of ws.slice(1)) {
        if ((LAST.has(w) || FIRST.has(w)) && !COMMON.has(w) && !AMBIGUOUS_LAST.has(w)) keep++;
        else break;
      }
      const start = m.index + m[0].length - m[1].length;
      const span = text.slice(start).match(new RegExp(String.raw`^[a-z]+(?:[ \t]+[a-z]+){${keep - 1}}`));
      out.push([start, start + span[0].length]);
    }
  }

  // A word that can be part of an unknown name: a known name or not an everyday word.
  const namelike = (w) => !PLACE_ORG.has(w) && !STOP_TOKENS.has(w) &&
    (((FIRST.has(w) || LAST.has(w)) && !AMBIGUOUS_FIRST.has(w)) || !COMMON.has(w));

  function contextNames(text, out) {
    for (const rx of [CTX_BEFORE_RE, CTX_AFTER_RE]) {
      for (const m of text.matchAll(rx)) {
        const ws = m[1].split(/\s+/).map(key);
        const ok = isLower(m[1].replace(/[^A-Za-z]/g, ""))   // "email lisa white": both must be known names
          ? FIRST.has(ws[0]) && !AMBIGUOUS_FIRST.has(ws[0]) && LAST.has(ws[1])
          : ws.every(namelike);
        if (!ok) continue;
        const start = rx === CTX_BEFORE_RE ? m.index + m[0].length - m[1].length : m.index;
        out.push([start, start + m[1].length]);
      }
    }
    for (const m of text.matchAll(RELATION_RE)) {                // "my friend nevenka dretvic"
      const toks = [...m[1].matchAll(/[A-Za-z][A-Za-z'’-]*/g)];
      let keep = 0;
      for (const t of toks) {
        if (namelike(key(t[0]))) keep++;
        else break;
      }
      if (keep) {
        const start = m.index + m[0].length - m[1].length;
        out.push([start, start + toks[keep - 1].index + toks[keep - 1][0].length]);
      }
    }
  }

  function findNames(text) {
    const out = [];
    dictionaryNames(text, out);
    cueNames(text, out);
    contextNames(text, out);
    const seen = new Set(out.map((x) => x.join(":")));
    const todo = [...out];
    while (todo.length) {                                       // follow lists of names: "A and B", "A, B and C"
      const [, end] = todo.pop();
      JOINED_RE.lastIndex = end;
      const m = JOINED_RE.exec(text);
      if (!m) continue;
      const start = m.index + m[0].length - m[1].length;
      const span = [start, start + m[1].length];
      if (m[1].split(/\s+/).every((w) => namelike(key(w))) && !seen.has(span.join(":"))) {
        seen.add(span.join(":"));
        out.push(span);
        todo.push(span);
      }
    }
    return out;
  }

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
    ADDRESS: (t) => findAddresses(t).map(([a, b]) => ent("ADDRESS", a, t.slice(a, b))),
    PERSON: (t) => findNames(t).map(([a, b]) => ent("PERSON", a, t.slice(a, b))),
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
