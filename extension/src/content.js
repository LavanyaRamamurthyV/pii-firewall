/*
 * PII Firewall content script. Runs in the extension's isolated world on AI chat sites.
 *
 * 1. Watches the message box and warns when it contains personal data.
 * 2. Holds back Enter / the Send button while PII is present, until the user redacts or overrides.
 * 3. Optionally auto-redacts pasted text.
 * 4. Optionally shows the real values in place of tokens in AI replies (off by default).
 *
 * Nothing leaves the browser: detection is regex + checksum code in lib/pii-core.js.
 */
(() => {
  "use strict";
  const { Firewall, TOKEN_RE } = globalThis.PIICore;

  const DEFAULTS = { enabled: true, mode: "warn", restore: false, policy: {} };
  const LABELS = {
    SSN: "SSN", CREDIT_CARD: "card number", EMAIL: "email", PHONE: "phone",
    IP_ADDRESS: "IP address", DOB: "date of birth", ADDRESS: "address", PERSON: "name",
  };

  let settings = { ...DEFAULTS };
  let fw = new Firewall();
  let composer = null;      // last focused editable element
  let overrideText = null;  // text the user chose to "send anyway"

  // ---------- storage ----------
  const safe = (fn) => { try { return fn(); } catch { return undefined; } }; // extension reloaded

  async function load() {
    const s = await chrome.storage.sync.get(DEFAULTS);
    settings = { ...DEFAULTS, ...s };
    const { fwState } = (await safe(() => chrome.storage.session.get("fwState"))) || {};
    fw = new Firewall(settings.policy, fwState);
  }

  function saveState() {
    safe(() => chrome.storage.session.set({ fwState: fw.exportState() }));
  }

  async function recordStats(findings) {
    if (!findings.length) return;
    const { stats = { total: 0, byType: {} } } = await chrome.storage.local.get("stats");
    for (const f of findings) {
      stats.total++;
      stats.byType[f.type] = (stats.byType[f.type] || 0) + 1;
    }
    safe(() => chrome.storage.local.set({ stats }));
  }

  chrome.storage.onChanged.addListener((changes, area) => {
    if (area === "session" && changes.fwState && !changes.fwState.newValue) {
      fw = new Firewall(settings.policy); // user clicked "Forget tokens"
      return;
    }
    if (area !== "sync") return;
    for (const [k, { newValue }] of Object.entries(changes)) settings[k] = newValue ?? DEFAULTS[k];
    fw = new Firewall(settings.policy, fw.exportState());
    if (!settings.enabled || settings.mode === "off") panel.hide();
    if (settings.restore) restoreAll();
  });

  // ---------- editable helpers ----------
  const isEditable = (el) =>
    el && (el.tagName === "TEXTAREA" || (el.tagName === "INPUT" && el.type === "text") || el.isContentEditable);

  const editableFrom = (node) => {
    let el = node && node.nodeType === 1 ? node : node && node.parentElement;
    while (el && !isEditable(el)) el = el.parentElement;
    if (!el) return null;
    // Climb to the outermost contenteditable (the actual composer).
    while (el.parentElement && el.parentElement.isContentEditable) el = el.parentElement;
    return el;
  };

  const getText = (el) => (el.tagName === "TEXTAREA" || el.tagName === "INPUT" ? el.value : el.innerText);

  function setText(el, text) {
    el.focus();
    if (el.tagName === "TEXTAREA" || el.tagName === "INPUT") {
      const proto = el.tagName === "TEXTAREA" ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
      Object.getOwnPropertyDescriptor(proto, "value").set.call(el, text);
      el.dispatchEvent(new Event("input", { bubbles: true }));
      return;
    }
    // Rich editors (ProseMirror, Lexical, Quill) accept insertText as a real user edit.
    const range = document.createRange();
    range.selectNodeContents(el);
    const sel = getSelection();
    sel.removeAllRanges();
    sel.addRange(range);
    document.execCommand("insertText", false, text);
  }

  const active = () => settings.enabled && settings.mode !== "off";

  function summarise(findings) {
    const c = {};
    for (const f of findings) c[f.type] = (c[f.type] || 0) + 1;
    return Object.entries(c).map(([t, n]) => `${n} ${LABELS[t]}${n > 1 ? "s" : ""}`).join(", ");
  }

  // ---------- warning panel (closed shadow DOM so the page can't restyle or read it) ----------
  const panel = (() => {
    const host = document.createElement("div");
    host.style.cssText = "position:fixed;z-index:2147483647;right:20px;bottom:120px;";
    const root = host.attachShadow({ mode: "closed" });
    root.innerHTML = `
      <style>
        .box{font:13px/1.4 system-ui,sans-serif;background:#111827;color:#f9fafb;border-radius:12px;
             padding:12px 14px;max-width:320px;box-shadow:0 8px 30px rgba(0,0,0,.35);border:1px solid #374151}
        .title{font-weight:600;margin-bottom:4px;display:flex;gap:6px;align-items:center}
        .msg{color:#d1d5db;margin-bottom:10px}
        .row{display:flex;gap:8px;flex-wrap:wrap}
        button{font:inherit;border:0;border-radius:8px;padding:6px 10px;cursor:pointer}
        .primary{background:#10b981;color:#062e22;font-weight:600}
        .ghost{background:#374151;color:#f9fafb}
        .hidden{display:none}
      </style>
      <div class="box hidden" role="alert">
        <div class="title">🛡️ <span id="t"></span></div>
        <div class="msg" id="m"></div>
        <div class="row">
          <button class="primary" id="redact">Redact</button>
          <button class="ghost" id="anyway">Send anyway</button>
          <button class="ghost" id="close">Dismiss</button>
        </div>
      </div>`;
    const $ = (id) => root.getElementById(id);
    const box = root.querySelector(".box");
    let timer;
    (document.body || document.documentElement).appendChild(host);

    $("redact").onclick = () => { redactComposer(); };
    $("anyway").onclick = () => {
      if (composer) overrideText = getText(composer);
      show("Override on", "Press Enter or click Send to send this message unchanged.", { actions: false, ttl: 4000 });
    };
    $("close").onclick = () => hide();

    function show(title, msg, { actions = true, ttl = 0 } = {}) {
      clearTimeout(timer);
      $("t").textContent = title;
      $("m").textContent = msg;
      root.querySelector(".row").classList.toggle("hidden", !actions);
      box.classList.remove("hidden");
      if (ttl) timer = setTimeout(hide, ttl);
    }
    function hide() { box.classList.add("hidden"); }
    return { show, hide };
  })();

  // ---------- core actions ----------
  function redactComposer() {
    if (!composer) return;
    const r = fw.redact(getText(composer));
    if (!r.findings.length) return panel.hide();
    setText(composer, r.text);
    saveState();
    recordStats(r.findings);
    overrideText = null;
    panel.show("Redacted", `Replaced ${summarise(r.findings)}. You can send now.`, { actions: false, ttl: 3500 });
  }

  function checkComposer({ blocking }) {
    if (!active() || !composer) return false;
    const text = getText(composer);
    if (overrideText !== null && text === overrideText) return false;
    const found = fw.scan(text);
    if (!found.length) { if (!blocking) panel.hide(); return false; }
    const what = summarise(found.map((e) => ({ type: e.type })));
    panel.show(
      blocking ? "Hold on: personal data in your message" : "Personal data detected",
      `Found ${what}. Redact it before the AI sees it?`
    );
    return true;
  }

  // ---------- event wiring ----------
  document.addEventListener("focusin", (e) => {
    const el = editableFrom(e.target);
    if (el) composer = el;
  }, true);

  let typingTimer;
  document.addEventListener("input", (e) => {
    const el = editableFrom(e.target);
    if (!el) return;
    composer = el;
    clearTimeout(typingTimer);
    typingTimer = setTimeout(() => checkComposer({ blocking: false }), 400);
  }, true);

  // Enter to send.
  window.addEventListener("keydown", (e) => {
    if (e.key !== "Enter" || e.shiftKey || e.isComposing) return;
    const el = editableFrom(e.target);
    if (!el) return;
    composer = el;
    if (checkComposer({ blocking: true })) {
      e.preventDefault();
      e.stopImmediatePropagation();
    }
  }, true);

  // Send button.
  const SEND_RE = /send|submit/i;
  window.addEventListener("click", (e) => {
    const btn = e.target.closest && e.target.closest("button");
    if (!btn) return;
    const label = [btn.getAttribute("aria-label"), btn.getAttribute("data-testid"), btn.type === "submit" ? "submit" : ""].join(" ");
    if (!SEND_RE.test(label)) return;
    if (checkComposer({ blocking: true })) {
      e.preventDefault();
      e.stopImmediatePropagation();
    }
  }, true);

  // Paste: auto-redact in "auto" mode, otherwise just warn.
  window.addEventListener("paste", (e) => {
    const el = editableFrom(e.target);
    if (!el || !active()) return;
    composer = el;
    const text = e.clipboardData && e.clipboardData.getData("text/plain");
    if (!text || settings.mode !== "auto") return;
    const r = fw.redact(text);
    if (!r.findings.length) return;
    e.preventDefault();
    e.stopImmediatePropagation();
    document.execCommand("insertText", false, r.text);
    saveState();
    recordStats(r.findings);
    panel.show("Pasted safely", `Replaced ${summarise(r.findings)} before it reached the page.`, { actions: false, ttl: 3500 });
  }, true);

  // Files: we can't read inside images/PDFs yet, so warn.
  window.addEventListener("change", (e) => {
    const input = e.target;
    if (!active() || input.tagName !== "INPUT" || input.type !== "file") return;
    if ([...(input.files || [])].some((f) => /^image\/|pdf/.test(f.type))) {
      panel.show("Check this file", "Photos, IDs and statements often contain personal data. PII Firewall can't scan files yet.", { actions: false, ttl: 6000 });
    }
  }, true);

  // ---------- optional: show real values in AI replies ----------
  // Off by default: once real values are on the page, the page's own scripts could read them.
  // Values are drawn inside closed shadow roots to make that harder, not impossible.
  function restoreNode(textNode) {
    const text = textNode.nodeValue;
    if (!text || !text.includes("[")) return;
    const parent = textNode.parentElement;
    if (!parent || editableFrom(parent) || parent.closest("[data-pii-fw]")) return;
    const parts = text.split(new RegExp(`(${TOKEN_RE.source})`, "g"));
    if (parts.length < 2) return;
    const frag = document.createDocumentFragment();
    let changed = false;
    for (let i = 0; i < parts.length; i++) {
      const p = parts[i];
      if (p === undefined) continue;
      // split() also returns the inner capture groups; skip them.
      if (i % 4 === 2 || i % 4 === 3) continue;
      if (i % 4 === 1 && p in fw.vault) {
        const span = document.createElement("span");
        span.setAttribute("data-pii-fw", "");
        span.title = `${p} restored on your screen only`;
        const sr = span.attachShadow({ mode: "closed" });
        sr.innerHTML = `<style>b{background:#d1fae5;color:#064e3b;border-radius:4px;padding:0 3px;font-weight:600}</style><b></b>`;
        sr.querySelector("b").textContent = fw.vault[p];
        frag.appendChild(span);
        changed = true;
      } else {
        frag.appendChild(document.createTextNode(p));
      }
    }
    if (changed) parent.replaceChild(frag, textNode);
  }

  function restoreAll(root = document.body) {
    if (!settings.restore || !root) return;
    const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
    const nodes = [];
    while (walker.nextNode()) nodes.push(walker.currentNode);
    nodes.forEach(restoreNode);
  }

  new MutationObserver((muts) => {
    if (!settings.restore) return;
    for (const m of muts) {
      if (m.type === "characterData") restoreNode(m.target);
      for (const n of m.addedNodes) n.nodeType === 3 ? restoreNode(n) : n.nodeType === 1 && restoreAll(n);
    }
  }).observe(document.documentElement, { childList: true, subtree: true, characterData: true });

  load().then(() => restoreAll());
})();
