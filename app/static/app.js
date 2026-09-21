"use strict";

// Server data (URLs, page text, evidence, message wording) is attacker-controlled: render it
// with textContent / append(string) only, never innerHTML. The SVG scene below is a static
// constant that contains no server data.

const form = document.getElementById("check");
const full = document.getElementById("full");
const errorEl = document.getElementById("error");
const result = document.getElementById("result");
const empty = document.getElementById("empty");
const fields = {
  url: document.getElementById("url"),
  msg: document.getElementById("msg"),
  sender: document.getElementById("sender"),
  subject: document.getElementById("subject"),
};
const tabs = { link: document.getElementById("tab-link"), message: document.getElementById("tab-message") };
const panels = { link: document.getElementById("panel-link"), message: document.getElementById("panel-message") };
let mode = "link";

const VERDICT = {
  allow: {
    title: "Clean. No notes.",
    lead: "Zero red flags. This one is behaving itself.",
    alt: "A fish in sunglasses, totally unbothered by the bait.",
    flags: "Anything we noticed",
  },
  warn: {
    title: "Mmm, kinda fishy.",
    lead: "A few red flags. Don't type passwords or card details here.",
    alt: "A fish giving the bait a suspicious side-eye.",
    flags: "The red flags",
  },
  block: {
    title: "Nope. Do not bite.",
    lead: "This has strong phishing energy. Don't open it, and never log in there.",
    alt: "A shocked fish staring at the bait.",
    flags: "The red flags",
  },
  unverified: {
    title: "Couldn't verify this one.",
    lead: "We couldn't open the page, so this is a guess from the address alone. Treat it as unchecked, not safe.",
    alt: "A fish giving the bait a suspicious side-eye.",
    flags: "What we did notice",
  },
};

const STAGE_NAMES = {
  text: { title: "Message read", what: "the wording and sender" },
  url: { title: "Sniff test", what: "the address" },
  page: { title: "Deep dive", what: "the page" },
};
const SOURCE_LABEL = { url: "from the address", page: "from the page", text: "from the message", intel: "from a threat list" };
const USED_LABEL = { text: "message wording", url: "address", webpage: "page", threat_intel: "threat lists" };

/* ---------- little DOM helpers ---------- */
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
  errorEl.textContent = msg;
  errorEl.hidden = !msg;
}

function fmtMs(ms) {
  return ms >= 1 ? `${Math.round(ms)} ms` : "under 1 ms";
}

/* ---------- the fish ---------- */
const INK = "#0B3B47", KOI = "#FF6A3D", KOI2 = "#E8481C", BERRY = "#D01F5B", SUN = "#FFD84D", SKY = "#8ED3F5", PINK = "#FF9DBF";

const FACES = {
  allow: `
    <g class="shades">
      <rect x="122" y="90" width="44" height="20" rx="8" fill="${INK}"/>
      <rect x="128" y="94" width="14" height="4" rx="2" fill="#fff" opacity=".55"/>
    </g>
    <path d="M158 126 q10 8 19 -3" stroke="${INK}" stroke-width="3.5" fill="none" stroke-linecap="round"/>
    <path d="M204 62 l4 -10 l4 10 l10 4 l-10 4 l-4 10 l-4 -10 l-10 -4z" fill="${SUN}" stroke="${INK}" stroke-width="2.5" stroke-linejoin="round"/>
    <path d="M34 66 l3 -8 l3 8 l8 3 l-8 3 l-3 8 l-3 -8 l-8 -3z" fill="${SUN}" stroke="${INK}" stroke-width="2.5" stroke-linejoin="round"/>`,
  warn: `
    <circle cx="144" cy="102" r="12" fill="#fff" stroke="${INK}" stroke-width="3"/>
    <circle cx="150" cy="103" r="5.5" fill="${INK}"/>
    <path d="M128 85 L158 92" stroke="${INK}" stroke-width="4.5" stroke-linecap="round"/>
    <path d="M160 126 h16" stroke="${INK}" stroke-width="3.5" stroke-linecap="round"/>
    <path d="M110 74 q8 13 0 19 q-8 -6 0 -19z" fill="${SKY}" stroke="${INK}" stroke-width="2.5" stroke-linejoin="round"/>`,
  block: `
    <circle cx="142" cy="100" r="15" fill="#fff" stroke="${INK}" stroke-width="3"/>
    <circle cx="145" cy="100" r="3.5" fill="${INK}"/>
    <path d="M124 78 Q140 64 158 76" stroke="${INK}" stroke-width="4.5" fill="none" stroke-linecap="round"/>
    <ellipse cx="171" cy="126" rx="7" ry="11" fill="${INK}"/>
    <path d="M112 76 q8 13 0 19 q-8 -6 0 -19z" fill="${SKY}" stroke="${INK}" stroke-width="2.5" stroke-linejoin="round"/>
    <path d="M92 90 q6 10 0 14 q-6 -4 0 -14z" fill="${SKY}" stroke="${INK}" stroke-width="2.5" stroke-linejoin="round"/>
    <path d="M150 52 l4 -14 M168 60 l12 -10 M180 78 l14 -4" stroke="${BERRY}" stroke-width="4.5" stroke-linecap="round"/>
    <text x="196" y="56" font-family="Shrikhand, Georgia, serif" font-size="40" fill="#fff" stroke="${INK}" stroke-width="5" paint-order="stroke" stroke-linejoin="round">!!</text>`,
};

function sceneMarkup(mood, alt) {
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 320 210" class="scene" role="img" aria-label="${alt}">
    <circle cx="36" cy="150" r="6" fill="none" stroke="${INK}" stroke-width="2.5" opacity=".5"/>
    <circle cx="54" cy="176" r="4" fill="none" stroke="${INK}" stroke-width="2.5" opacity=".5"/>
    <path d="M270 0 V96" stroke="${INK}" stroke-width="3.5" fill="none"/>
    <path d="M270 96 V134 C270 158 240 158 240 132" stroke="${INK}" stroke-width="4.5" fill="none" stroke-linecap="round"/>
    <path d="M270 112 q12 -15 24 0 t24 0" stroke="${INK}" stroke-width="15" fill="none" stroke-linecap="round"/>
    <path d="M270 112 q12 -15 24 0 t24 0" stroke="${PINK}" stroke-width="9" fill="none" stroke-linecap="round"/>
    <g class="fish"><g transform="rotate(${mood === "block" ? -8 : 0} 110 118)">
      <path d="M52 118 L12 82 Q28 118 12 154 Z" fill="${KOI}" stroke="${INK}" stroke-width="3.5" stroke-linejoin="round"/>
      <path d="M90 78 Q112 40 140 78 Z" fill="${KOI2}" stroke="${INK}" stroke-width="3.5" stroke-linejoin="round"/>
      <path d="M48 118 C48 76 116 62 158 96 C178 111 178 127 158 141 C116 174 48 162 48 118 Z" fill="${KOI}" stroke="${INK}" stroke-width="3.5"/>
      <ellipse cx="110" cy="142" rx="34" ry="9" fill="#fff" opacity=".85"/>
      <path d="M98 116 q-16 18 4 30 q9 -15 -4 -30z" fill="${KOI2}" stroke="${INK}" stroke-width="3" stroke-linejoin="round"/>
      <path d="M72 108 q6 6 12 0 M86 96 q6 6 12 0 M78 128 q6 6 12 0" stroke="#fff" stroke-opacity=".65" fill="none" stroke-width="3" stroke-linecap="round"/>
      <circle cx="148" cy="124" r="7" fill="${PINK}" opacity=".95"/>
      ${FACES[mood]}
    </g></g>
  </svg>`;
}

function scene(mood, alt) {
  const doc = new DOMParser().parseFromString(sceneMarkup(mood, alt), "image/svg+xml");
  return document.importNode(doc.documentElement, true);
}

/* ---------- sections ---------- */
function section(title, intro, ...body) {
  return el("section", {}, el("h3", {}, title), intro ? el("p", {}, intro) : null, ...body);
}

function renderBait(data) {
  const parts = data.parts;
  const code = el("code", {}, el("span", { class: "scheme" }, `${parts.scheme}://`));
  if (parts.subdomain) code.append(el("span", { class: "sub" }, parts.subdomain + "."));
  code.append(el("span", { class: "domain" }, parts.domain));
  if (parts.port) code.append(el("span", { class: "rest" }, `:${parts.port}`));
  if (parts.rest) code.append(el("span", { class: "rest" }, parts.rest));
  const caption = parts.subdomain
    ? `This link really goes to ${parts.domain}. The wavy bit (${parts.subdomain}) is picked by whoever owns that domain, so it proves nothing about who they are.`
    : `This link really goes to ${parts.domain}.`;
  return section(
    data.kind === "message" ? "The riskiest link" : "The bait",
    "Here's the link taken apart. The highlighted part is the site that actually owns it.",
    el("div", { class: "bait" }, code, el("p", {}, caption)));
}

function renderLinks(data) {
  const list = el("ul", { class: "linklist" });
  for (const l of data.links) {
    list.append(el("li", {},
      el("span", { class: "u" }, l.url),
      el("span", { class: "pill", "data-a": l.recommended_action }, `Fishiness ${l.risk}`)));
  }
  return section("Links in this message", "Each link goes through the same sniff test and deep dive on its own.", list);
}

function renderStage(s, thresholds) {
  const names = STAGE_NAMES[s.name] || { title: s.title, what: "" };
  const timing = s.score !== null ? fmtMs(s.ms) : (s.outcome === "unavailable" ? "couldn't open it" : "skipped");
  const row = el("div", { class: "stage" },
    el("div", { class: "name" }, names.title, el("small", {}, `${names.what}, ${timing}`)));
  if (s.score === null) {
    row.append(el("p", { class: "note" }, s.note));
    return row;
  }
  const pct = Math.round(s.score * 100);
  const track = el("div", { class: "track", role: "img", "aria-label": `Fishiness ${pct} out of 100` });
  const zones = el("div", { class: "zones" });
  if (s.name === "url") {
    const lo = el("span", { class: "zone lo" });
    lo.style.width = `${thresholds.low * 100}%`;
    const hi = el("span", { class: "zone hi" });
    hi.style.width = `${(1 - thresholds.high) * 100}%`;
    zones.append(lo, hi);
  }
  const mark = el("span", { class: "mark" });
  mark.style.left = `${Math.min(100, Math.max(0, s.score * 100))}%`;
  track.append(zones, mark);
  row.append(track, el("p", { class: "note" }, el("b", {}, `Fishiness ${pct}. `), s.note));
  return row;
}

function renderChecked(data) {
  const rows = el("div", {});
  for (const s of data.stages) rows.append(renderStage(s, data.thresholds));
  return section("How we sniffed it out",
    "The address goes first. The page only gets a deep dive when the address is too murky to call. Green means clearly fine, pink means clearly bad, and the bobber shows where the address landed.",
    rows);
}

function renderFlags(data, v) {
  const sec = section(v.flags, null);
  if (data.evidence.length === 0) {
    sec.append(el("p", { class: "none" }, "Nothing stood out. Suspiciously clean, in a good way."));
    return sec;
  }
  const list = el("ul", { class: "flags" });
  for (const e of data.evidence) {
    const lit = Math.max(1, Math.ceil(e.impact * 5));
    const pips = el("div", { class: "pips", role: "img", "aria-label": `Impact ${lit} out of 5` });
    for (let i = 0; i < 5; i++) pips.append(el("i", { class: i < lit ? "on" : "" }));
    list.append(el("li", {},
      el("div", {}, el("span", { class: "sig" }, e.signal), el("span", { class: "src" }, SOURCE_LABEL[e.stage] || "")),
      pips,
      el("p", { class: "det" }, e.detail)));
  }
  sec.append(list);
  return sec;
}

function renderGuide(data) {
  const g = data.guidance;
  const todo = el("ul", { class: "todo" });
  for (const step of g.do_now) todo.append(el("li", {}, step));
  const sec = section("What to do now", null, todo);
  if (g.if_you_interacted.length) {
    const steps = el("ol", {});
    for (const step of g.if_you_interacted) steps.append(el("li", {}, step));
    sec.append(el("details", { class: "after" }, el("summary", {}, "Already tapped it or typed something in?"), steps));
  }
  if (g.report.length) {
    const rep = el("ul", { class: "reportline todo" });
    for (const step of g.report) rep.append(el("li", {}, step));
    sec.append(rep);
  }
  return sec;
}

function renderFeedback(data) {
  const box = el("div", { class: "feedback" }, el("p", {}, "Was that right?"));
  const chips = el("div", { class: "chips" });
  const send = async (verdict) => {
    try {
      const res = await fetch("/api/feedback", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ analysis_id: data.id, verdict }),
      });
      const ok = res.ok || res.status === 429; // 429 here means this check already has enough votes
      box.replaceChildren(el("p", { class: "thanks" }, ok ? "Thanks, that helps us learn." : "Couldn't send that just now."));
    } catch {
      box.replaceChildren(el("p", { class: "thanks" }, "Couldn't send that just now."));
    }
  };
  for (const [label, verdict] of [["Yep, it's phishy", "phishing"], ["Nope, it's fine", "legitimate"]]) {
    const b = el("button", { type: "button", class: "ghost" }, label);
    b.addEventListener("click", () => send(verdict));
    chips.append(b);
  }
  box.append(chips);
  return box;
}

function renderReceipts(data) {
  const used = Object.entries(data.modalities).filter(([, m]) => m.status === "done" || m.status === "hit").map(([k]) => USED_LABEL[k] || k);
  const meta = el("dl", { class: "meta" },
    el("dt", {}, "Check ID"), el("dd", {}, data.id),
    el("dt", {}, "Signals used"), el("dd", {}, used.join(", ") || "none"),
    el("dt", {}, "Not built yet"), el("dd", {}, "screenshot comparison"),
    el("dt", {}, "Models"), el("dd", {}, Object.values(data.versions).join(", ")),
    el("dt", {}, "Time taken"), el("dd", {}, fmtMs(data.latency_ms)),
    el("dt", {}, "Enforcement"), el("dd", {}, "Advice only. This site can't block anything for you."));
  if (data.final_url) meta.append(el("dt", {}, "Page opened"), el("dd", {}, data.final_url));
  return section("Receipts", null, meta);
}

function render(data) {
  const key = data.label === "unverified" ? "unverified" : (VERDICT[data.recommended_action] ? data.recommended_action : "warn");
  const mood = key === "unverified" ? "warn" : key;
  const v = VERDICT[key];
  const title = el("h2", { tabindex: "-1" }, v.title);
  const text = el("div", {}, title, el("p", {}, v.lead));
  if (data.calibrated) text.append(el("p", {}, `Estimated chance it's phishing: ${Math.round(data.probability * 100)}%.`));
  text.append(el("span", { class: "score" }, `Fishiness ${data.risk} / 100`));
  const verdict = el("div", { class: "verdict" }, scene(mood, v.alt), text);

  const wrap = el("div", { "data-state": mood }, verdict);
  if (data.parts && data.parts.domain) wrap.append(renderBait(data));
  if (data.kind === "message" && data.links.length) wrap.append(renderLinks(data));
  wrap.append(renderChecked(data), renderFlags(data, v), renderGuide(data), renderFeedback(data), renderReceipts(data));

  result.replaceChildren(wrap);
  result.hidden = false;
  empty.hidden = true;
  result.classList.remove("enter");
  void result.offsetWidth; // restart the entrance animation
  result.classList.add("enter");
  title.focus({ preventScroll: true });
  const calm = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  result.scrollIntoView({ behavior: calm ? "auto" : "smooth", block: "start" });
}

/* ---------- talking to the API ---------- */
async function post(path, payload) {
  const res = await fetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  if (!res.ok) {
    let msg = "Something went wrong on our side. Try again in a moment.";
    if (res.status === 429) {
      msg = `Slow down a sec, that's a lot of checks. Try again in ${res.headers.get("Retry-After") || "a few"} seconds.`;
    } else if (res.status === 422) {
      try {
        const body = await res.json();
        msg = typeof body.detail === "string" ? body.detail : "That doesn't look right. Check what you pasted and try again.";
      } catch { /* keep default */ }
    }
    throw new Error(msg);
  }
  return res.json();
}

/* ---------- tabs ---------- */
function setMode(next, focus = false) {
  mode = next;
  for (const name of ["link", "message"]) {
    const on = name === next;
    tabs[name].setAttribute("aria-selected", String(on));
    tabs[name].tabIndex = on ? 0 : -1;
    panels[name].hidden = !on;
  }
  showError("");
  if (focus) (next === "link" ? fields.url : fields.msg).focus();
}
tabs.link.addEventListener("click", () => setMode("link"));
tabs.message.addEventListener("click", () => setMode("message"));
for (const name of ["link", "message"]) {
  tabs[name].addEventListener("keydown", (ev) => {
    if (ev.key === "ArrowRight" || ev.key === "ArrowLeft") {
      const next = name === "link" ? "message" : "link";
      setMode(next);
      tabs[next].focus();
    }
  });
}

/* ---------- submit ---------- */
function setBusy(busy) {
  for (const b of form.querySelectorAll("button.go")) {
    b.disabled = busy;
    b.textContent = busy ? "Sniffing…" : "Vibe-check it";
  }
}

form.addEventListener("submit", async (ev) => {
  ev.preventDefault();
  showError("");
  const deep = full.checked ? "full" : "cascade";
  let request;
  if (mode === "link") {
    const url = fields.url.value.trim();
    if (!url) { showError("Paste a link first."); fields.url.focus(); return; }
    request = () => post("/api/analyze", { url, mode: deep });
  } else {
    const text = fields.msg.value.trim();
    if (!text) { showError("Paste the message first."); fields.msg.focus(); return; }
    request = () => post("/api/analyze-message", {
      text, sender: fields.sender.value.trim(), subject: fields.subject.value.trim(), mode: deep,
    });
  }
  setBusy(true);
  try {
    render(await request());
  } catch (err) {
    showError(err instanceof TypeError ? "Couldn't reach the server. Check your connection and try again." : err.message);
  } finally {
    setBusy(false);
  }
});

for (const chip of document.querySelectorAll("[data-fill]")) {
  chip.addEventListener("click", () => {
    const target = chip.dataset.target;
    setMode(target === "msg" ? "message" : "link");
    fields[target].value = chip.dataset.fill;
    fields[target].focus();
  });
}
