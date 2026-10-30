const DEFAULTS = { enabled: true, mode: "warn", restore: false, policy: {} };
const LABELS = {
  SSN: "Social Security number", CREDIT_CARD: "Card number", EMAIL: "Email", PHONE: "Phone",
  IP_ADDRESS: "IP address", DOB: "Date of birth", ADDRESS: "Street address", PERSON: "Name (with context)",
};
const ACTION_LABELS = { tokenize: "Replace with token", mask: "Mask (•••6789)", block: "Remove", allow: "Allow" };

const $ = (id) => document.getElementById(id);

async function render() {
  const s = { ...DEFAULTS, ...(await chrome.storage.sync.get(DEFAULTS)) };
  $("enabled").checked = s.enabled;
  $("restore").checked = s.restore;
  document.querySelectorAll('input[name="mode"]').forEach((r) => (r.checked = r.value === s.mode));

  const box = $("types");
  box.textContent = "";
  for (const t of PIICore.ENTITY_TYPES) {
    const row = document.createElement("div");
    row.className = "row";
    const name = document.createElement("span");
    name.textContent = LABELS[t];
    const sel = document.createElement("select");
    for (const a of PIICore.ACTIONS) sel.add(new Option(ACTION_LABELS[a], a));
    sel.value = s.policy[t] || "tokenize";
    sel.onchange = async () => {
      const { policy = {} } = await chrome.storage.sync.get("policy");
      policy[t] = sel.value;
      chrome.storage.sync.set({ policy });
    };
    row.append(name, sel);
    box.appendChild(row);
  }

  const { stats = { total: 0 } } = await chrome.storage.local.get("stats");
  $("total").textContent = stats.total;
  const { fwState } = await chrome.storage.session.get("fwState");
  const n = fwState ? Object.keys(fwState.vault || {}).length : 0;
  $("tokens").textContent = `${n} token${n === 1 ? "" : "s"} in vault`;
}

$("enabled").onchange = (e) => chrome.storage.sync.set({ enabled: e.target.checked });
$("restore").onchange = (e) => chrome.storage.sync.set({ restore: e.target.checked });
document.querySelectorAll('input[name="mode"]').forEach((r) => (r.onchange = () => chrome.storage.sync.set({ mode: r.value })));
$("clear").onclick = async () => {
  await chrome.storage.session.remove("fwState");
  render();
};

render();
