"""End-to-end test: loads the real unpacked extension in Chromium and serves fake
chat pages at the real AI site URLs (network is intercepted, nothing is fetched).

Run:  CHROME_PATH=/path/to/chrome python -m pytest extension/test -q
"""

import os
import re
import time
from pathlib import Path

import pytest

pw = pytest.importorskip("playwright.sync_api")

EXT = Path(__file__).resolve().parents[1]
CHROME = os.environ.get("CHROME_PATH")

FAKE_CHAT = """<!doctype html><html><body>
<div id="composer" contenteditable="true" style="border:1px solid #ccc;min-height:40px;width:400px"></div>
<textarea id="ta" style="width:400px"></textarea>
<button aria-label="Send message" id="send">Send</button>
<div id="replies"></div>
<script>
  window.sent = [];
  const box = () => document.activeElement && document.activeElement.id === 'ta'
      ? document.getElementById('ta') : document.getElementById('composer');
  function send() {
    const el = box();
    window.sent.push(el.value !== undefined ? el.value : el.innerText);
  }
  document.addEventListener('keydown', e => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); send(); } });
  document.getElementById('send').addEventListener('click', send);
</script></body></html>"""


@pytest.fixture(scope="module")
def ctx(tmp_path_factory):
    if not CHROME:
        pytest.skip("set CHROME_PATH to a Chromium build to run browser tests")
    with pw.sync_playwright() as p:
        context = p.chromium.launch_persistent_context(
            str(tmp_path_factory.mktemp("profile")),
            executable_path=CHROME,
            headless=True,
            args=[f"--disable-extensions-except={EXT}", f"--load-extension={EXT}", "--headless=new"],
        )
        context.route("https://claude.ai/**", lambda r: r.fulfill(body=FAKE_CHAT, content_type="text/html"))
        sw = context.service_workers[0] if context.service_workers else context.wait_for_event("serviceworker")
        context.sw = sw
        yield context
        context.close()


def set_settings(ctx, **kw):
    import json
    ctx.sw.evaluate(f"chrome.storage.sync.set({json.dumps(kw)})")
    time.sleep(0.2)


def open_chat(ctx):
    page = ctx.new_page()
    page.goto("https://claude.ai/new")
    page.wait_for_timeout(600)  # content script at document_idle
    return page


def click_panel_button(page, index):
    # Panel lives in a closed shadow root; click by position (buttons are on the bottom row).
    host = page.locator("body > div").last
    box = host.bounding_box()
    xs = [box["x"] + 38, box["x"] + 130, box["x"] + 225]
    page.mouse.click(xs[index], box["y"] + box["height"] - 26)


def test_enter_is_held_back_until_redacted(ctx):
    set_settings(ctx, enabled=True, mode="warn", restore=False, policy={})
    page = open_chat(ctx)
    page.click("#composer")
    page.keyboard.type("My SSN is 123-45-6789 and card 4111 1111 1111 1111")
    page.keyboard.press("Enter")
    assert page.evaluate("window.sent") == []

    click_panel_button(page, 0)  # Redact
    page.wait_for_timeout(200)
    text = page.inner_text("#composer")
    assert "123-45-6789" not in text and "[SSN_1]" in text and "[CREDIT_CARD_1]" in text

    page.click("#composer")
    page.keyboard.press("End")
    page.keyboard.press("Enter")
    assert page.evaluate("window.sent") == ["My SSN is [SSN_1] and card [CREDIT_CARD_1]"]


def test_send_button_is_held_back(ctx):
    page = open_chat(ctx)
    page.click("#ta")
    page.keyboard.type("email me at jane@example.com")
    page.click("#send")
    assert page.evaluate("window.sent") == []


def test_send_anyway_override(ctx):
    page = open_chat(ctx)
    page.click("#composer")
    page.keyboard.type("call (214) 555-0182")
    page.keyboard.press("Enter")
    assert page.evaluate("window.sent") == []
    click_panel_button(page, 1)  # Send anyway
    page.click("#composer")
    page.keyboard.press("Enter")
    assert page.evaluate("window.sent") == ["call (214) 555-0182"]


def test_clean_text_sends_normally(ctx):
    page = open_chat(ctx)
    page.click("#composer")
    page.keyboard.type("What is a good balance transfer card?")
    page.keyboard.press("Enter")
    assert page.evaluate("window.sent") == ["What is a good balance transfer card?"]


def test_auto_mode_redacts_paste(ctx):
    set_settings(ctx, mode="auto")
    page = open_chat(ctx)
    page.click("#ta")
    page.evaluate("""() => {
      const dt = new DataTransfer(); dt.setData('text/plain', 'SSN 234-56-7890 please');
      document.getElementById('ta').dispatchEvent(new ClipboardEvent('paste', {clipboardData: dt, bubbles: true, cancelable: true}));
    }""")
    page.wait_for_timeout(200)
    # Token number depends on earlier tests: the session vault is shared across tabs.
    assert re.fullmatch(r"SSN \[SSN_\d+\] please", page.input_value("#ta"))
    set_settings(ctx, mode="warn")


def test_restore_shows_real_value_in_reply(ctx):
    set_settings(ctx, restore=True)
    page = open_chat(ctx)
    page.click("#composer")
    page.keyboard.type("my email is lee@example.org")
    page.keyboard.press("Enter")
    click_panel_button(page, 0)
    page.wait_for_timeout(200)
    page.evaluate("document.getElementById('replies').textContent = 'I will write to [EMAIL_1] today.'")
    page.wait_for_timeout(300)
    # The token text node was replaced by a shadow-root span; the page's own text no longer has the token.
    assert page.evaluate("document.getElementById('replies').querySelectorAll('[data-pii-fw]').length") == 1
    assert "[EMAIL_1]" not in page.inner_text("#replies")
    set_settings(ctx, restore=False)


def test_names_and_addresses_in_real_extension(ctx):
    set_settings(ctx, enabled=True, mode="auto", restore=False, policy={})
    page = open_chat(ctx)
    page.click("#ta")
    text = ("please email priya sharma. Hi Rahul, ship to 9 oak hollow by friday. "
            "Office: 456 W 34th Street, New York, NY 10001. Meet at Grant Park.")
    page.evaluate("""(t) => {
      const dt = new DataTransfer(); dt.setData('text/plain', t);
      document.getElementById('ta').dispatchEvent(new ClipboardEvent('paste', {clipboardData: dt, bubbles: true, cancelable: true}));
    }""", text)
    page.wait_for_timeout(200)
    out = page.input_value("#ta")
    for secret in ["priya", "sharma", "Rahul", "oak hollow", "34th Street", "10001"]:
        assert secret not in out, out
    assert "Grant Park" in out  # place, not a person
    assert re.search(r"\[PERSON_\d+\]", out) and re.search(r"\[ADDRESS_\d+\]", out)
    set_settings(ctx, mode="warn")
