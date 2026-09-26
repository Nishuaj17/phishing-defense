"use strict";

// Server data (evidence text, guidance, the checked URL) is attacker-influenced: render it with
// textContent / element creation only, never innerHTML. On-demand only — this extension never
// watches or logs the pages you browse; it checks a page only when you click the button.

const DEFAULT_API = "https://phishing-defense-h161.onrender.com";

const els = {
  tabUrl: document.getElementById("tabUrl"),
  check: document.getElementById("check"),
  error: document.getElementById("error"),
  result: document.getElementById("result"),
  gear: document.getElementById("gear"),
  settings: document.getElementById("settings"),
  apiBase: document.getElementById("apiBase"),
  saveApi: document.getElementById("saveApi"),
};

let currentUrl = null;

function el(tag, props = {}, ...kids) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (k === "class") node.className = v;
    else node.setAttribute(k, v);
  }
  for (const kid of kids) if (kid !== null && kid !== undefined) node.append(kid);
  return node;
}

function showError(msg) {
  els.error.textContent = msg;
  els.error.hidden = !msg;
}

async function getApiBase() {
  const { apiBase } = await chrome.storage.local.get({ apiBase: DEFAULT_API });
  return apiBase.replace(/\/+$/, "");
}

async function getActiveTabUrl() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  return tab ? tab.url : null;
}

const VERDICT = {
  allow: { title: "Clean. No notes.", lead: "No red flags found." },
  warn: { title: "Kinda fishy.", lead: "A few red flags. Don't enter passwords or card details." },
  block: { title: "Do not bite.", lead: "Strong phishing signs. Don't open it or log in there." },
  unverified: { title: "Couldn't verify.", lead: "The page couldn't be opened, so this is unchecked, not safe." },
};
const SOURCE_LABEL = { url: "address", page: "page", text: "message", intel: "threat list" };

function render(data) {
  const key = data.label === "unverified" ? "unverified" : (VERDICT[data.recommended_action] ? data.recommended_action : "warn");
  const mood = key === "unverified" ? "warn" : key;
  const v = VERDICT[key];

  const verdict = el("div", { class: "verdict" },
    el("h2", {}, v.title), el("p", {}, v.lead),
    el("span", { class: "score" }, `Fishiness ${data.risk} / 100`));

  const wrap = el("div", { "data-state": mood }, verdict);

  if (data.evidence.length) {
    const list = el("ul", { class: "flags" });
    for (const e of data.evidence.slice(0, 4)) {
      list.append(el("li", {},
        el("div", { class: "sig" }, `${e.signal} `, el("span", { style: "font-weight:400;color:var(--muted)" }, `(${SOURCE_LABEL[e.stage] || ""})`)),
        el("p", { class: "det" }, e.detail)));
    }
    wrap.append(list);
  } else {
    wrap.append(el("p", { class: "none" }, "Nothing stood out."));
  }

  if (data.guidance && data.guidance.do_now.length) {
    const todo = el("ul", { class: "todo" });
    for (const step of data.guidance.do_now.slice(0, 3)) todo.append(el("li", {}, step));
    wrap.append(todo);
  }

  els.result.replaceChildren(wrap);
  els.result.hidden = false;
}

async function checkCurrentPage() {
  showError("");
  els.result.hidden = true;
  if (!currentUrl) {
    showError("No page to check.");
    return;
  }
  els.check.disabled = true;
  els.check.textContent = "Checking…";
  try {
    const base = await getApiBase();
    const res = await fetch(`${base}/api/analyze`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: currentUrl, mode: "cascade" }),
    });
    if (!res.ok) {
      let msg = "Something went wrong. Try again.";
      if (res.status === 429) msg = "Too many checks — wait a moment and try again.";
      else if (res.status === 422) {
        try {
          const body = await res.json();
          msg = typeof body.detail === "string" ? body.detail : msg;
        } catch { /* keep default */ }
      }
      throw new Error(msg);
    }
    render(await res.json());
  } catch (err) {
    showError(err instanceof TypeError ? "Couldn't reach the API. Check the address in settings and that the server is running." : err.message);
  } finally {
    els.check.disabled = false;
    els.check.textContent = "Check this page";
  }
}

function isCheckable(url) {
  return typeof url === "string" && /^https?:\/\//i.test(url);
}

async function init() {
  els.apiBase.value = await getApiBase();

  const url = await getActiveTabUrl();
  if (isCheckable(url)) {
    currentUrl = url;
    els.tabUrl.textContent = url;
  } else {
    currentUrl = null;
    els.tabUrl.textContent = "This isn't a checkable web page.";
    els.check.disabled = true;
  }

  els.check.addEventListener("click", checkCurrentPage);

  els.gear.addEventListener("click", () => {
    const open = els.settings.hidden;
    els.settings.hidden = !open;
    els.gear.setAttribute("aria-expanded", String(open));
  });

  els.saveApi.addEventListener("click", async () => {
    const value = els.apiBase.value.trim().replace(/\/+$/, "") || DEFAULT_API;
    await chrome.storage.local.set({ apiBase: value });
    els.apiBase.value = value;
  });
}

init();
