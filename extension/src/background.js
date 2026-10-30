// Lets content scripts use chrome.storage.session for the token vault.
// Session storage lives in memory and is wiped when the browser closes.
const allowContentScripts = () =>
  chrome.storage.session.setAccessLevel({ accessLevel: "TRUSTED_AND_UNTRUSTED_CONTEXTS" });

chrome.runtime.onInstalled.addListener(allowContentScripts);
chrome.runtime.onStartup.addListener(allowContentScripts);
allowContentScripts();
