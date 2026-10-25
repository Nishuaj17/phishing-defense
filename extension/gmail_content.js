
"use strict";

(() => {
  if (window.__PHISHY_LOCAL_GMAIL__) return;
  window.__PHISHY_LOCAL_GMAIL__ = true;

  const MAX_TEXT = 5000;
  const BANNER_IN = "phishy-gmail-banner-incoming";
  const BANNER_OUT = "phishy-gmail-banner-outgoing";

  let lastIncomingKey = "";
  let incomingInFlight = "";
  let observerScheduled = false;
  let outgoingInFlight = false;
  let bypassNextSend = false;

  function visible(element) {
    return !!element &&
      element.getClientRects().length > 0 &&
      getComputedStyle(element).visibility !== "hidden";
  }

  function uniqueLinks(root) {
    return [
      ...new Set(
        Array.from(root?.querySelectorAll("a[href]") || [])
          .map(a => a.href)
          .filter(url => /^https?:\/\//i.test(url))
      )
    ];
  }

  function emailText(body, links) {
    return (
      (body || "") +
      (links.length
        ? "\n\nLinks found in email:\n" + links.join("\n")
        : "")
    ).slice(0, MAX_TEXT);
  }

  function getOpenMessage() {
    const subjectElement = document.querySelector("h2.hP");
    if (!subjectElement || !visible(subjectElement)) return null;

    const bodies = Array.from(
      document.querySelectorAll("div.a3s.aiL, div.a3s")
    ).filter(visible);

    if (!bodies.length) return null;

    // In a conversation, prefer the last visible message body.
    const bodyElement = bodies[bodies.length - 1];
    const messageContainer =
      bodyElement.closest(".adn") ||
      bodyElement.closest("[data-message-id]") ||
      bodyElement.parentElement;

    const senderElement =
      messageContainer?.querySelector("span[email]") ||
      document.querySelector("span[email]");

    const sender =
      senderElement?.getAttribute("email") ||
      messageContainer
        ?.querySelector('[data-hovercard-id^="mailto:"]')
        ?.getAttribute("data-hovercard-id")
        ?.replace(/^mailto:/, "") ||
      "";

    const subject = subjectElement.textContent.trim();
    const body = bodyElement.innerText.trim();
    const links = uniqueLinks(bodyElement);

    const text = emailText(body, links);
    if (!text && !subject) return null;

    return { sender, subject, text };
  }

  function getComposeWindows() {
    return Array.from(
      document.querySelectorAll(
        '[role="dialog"], .M9, .AD'
      )
    ).filter(root =>
      visible(root) &&
      root.querySelector('[name="subjectbox"], [contenteditable="true"]')
    );
  }

  function getComposeData(compose) {
    const subject =
      compose.querySelector('[name="subjectbox"]')
        ?.value?.trim() || "";

    const bodyElement =
      compose.querySelector(
        '[contenteditable="true"][aria-label*="Message Body"]'
      ) ||
      compose.querySelector(
        '[contenteditable="true"][role="textbox"]'
      ) ||
      compose.querySelector('[contenteditable="true"]');

    const body = bodyElement?.innerText?.trim() || "";

    const recipients = Array.from(
      compose.querySelectorAll(
        '[name="to"], [name="cc"], [name="bcc"], [email]'
      )
    )
      .map(element =>
        element.getAttribute("email") ||
        element.value ||
        element.getAttribute("data-hovercard-id") ||
        ""
      )
      .map(value => value.replace(/^mailto:/, "").trim())
      .filter(Boolean);

    const links = uniqueLinks(bodyElement);

    // Include the recipient and subject in the locally analyzed text.
    const context = [
      recipients.length
        ? "Recipients: " + [...new Set(recipients)].join(", ")
        : "",
      subject ? "Subject: " + subject : "",
      body
    ].filter(Boolean).join("\n\n");

    return {
      sender: "Outgoing draft",
      subject,
      text: emailText(context || "[Empty email draft]", links)
    };
  }

  function showBanner(kind, message, type = "info", risk = null) {
    const id = kind === "outgoing" ? BANNER_OUT : BANNER_IN;
    let banner = document.getElementById(id);

    if (!banner) {
      banner = document.createElement("div");
      banner.id = id;
      banner.setAttribute("role", "status");
      banner.style.cssText =
        "box-sizing:border-box;padding:12px 16px;margin:10px 0;" +
        "border-radius:8px;font:14px/1.5 Arial,sans-serif;" +
        "white-space:pre-wrap;position:relative;z-index:999999;";

      let anchor;

      if (kind === "outgoing") {
        anchor = getComposeWindows().find(root =>
          root.querySelector('[name="subjectbox"]')
        );
      } else {
        const body =
          document.querySelector("div.a3s.aiL") ||
          document.querySelector("div.a3s");
        anchor = body?.parentElement;
      }

      if (!anchor) return;
      anchor.insertBefore(banner, anchor.firstChild);
    }

    const danger = type === "danger";
    banner.style.background = danger ? "#fff0f0" : "#eff6ff";
    banner.style.color = danger ? "#991b1b" : "#1e3a8a";
    banner.style.border = danger
      ? "1px solid #dc2626"
      : "1px solid #93c5fd";

    banner.textContent =
      "Phishy: " + message +
      (risk !== null ? `\nRisk score: ${risk}/100` : "");
  }

  function analyzeLocally(email) {
    return new Promise((resolve, reject) => {
      chrome.runtime.sendMessage(
        { type: "PHISHY_ANALYZE_EMAIL", email },
        result => {
          if (chrome.runtime.lastError) {
            reject(new Error(chrome.runtime.lastError.message));
            return;
          }

          if (!result || result.error) {
            reject(new Error(result?.error || "No analysis result."));
            return;
          }

          resolve(result);
        }
      );
    });
  }

  function isDangerous(result) {
    const label = String(result.label || "").toLowerCase();
    const action = String(result.recommended_action || "").toLowerCase();

    return (
      ["phishing", "suspicious", "malicious"].includes(label) ||
      ["warn", "block"].includes(action)
    );
  }

  function riskScore(result) {
    const risk = Number(result.risk);
    return Number.isFinite(risk) ? risk : null;
  }

  async function analyzeIncoming() {
    const email = getOpenMessage();
    if (!email) return;

    const key = JSON.stringify(email);
    if (key === lastIncomingKey || key === incomingInFlight) return;

    incomingInFlight = key;
    showBanner("incoming", "Checking this email with your local analyzer…");

    try {
      const result = await analyzeLocally(email);
      lastIncomingKey = key;

      const label = String(result.label || "unknown").toUpperCase();
      const risk = riskScore(result);

      if (isDangerous(result)) {
        showBanner(
          "incoming",
          `WARNING — ${label}. Do not click links or enter credentials.`,
          "danger",
          risk
        );
      } else {
        showBanner(
          "incoming",
          `Analysis complete — ${label}. Review links carefully.`,
          "info",
          risk
        );
      }

      console.log("Phishy incoming email result:", {
        label,
        risk,
        recommended_action: result.recommended_action
      });
    } catch (error) {
      showBanner(
        "incoming",
        "Local analyzer unavailable. Check that the Python service is running. Email content was not sent to Render."
      );
      console.error("Phishy incoming analysis failed:", error);
    } finally {
      incomingInFlight = "";
    }
  }

  function findSendButton(compose) {
    const candidates = Array.from(
      compose.querySelectorAll(
        'div[role="button"], button, [data-tooltip], [aria-label]'
      )
    );

    return candidates.find(element => {
      const label = [
        element.getAttribute("data-tooltip") || "",
        element.getAttribute("aria-label") || "",
        element.innerText || ""
      ].join(" ").trim();

      return (
        visible(element) &&
        /\bsend\b/i.test(label) &&
        !/\bscheduled\b/i.test(label) &&
        !element.disabled
      );
    }) || null;
  }

  async function scanBeforeSending(sendButton, compose) {
    if (outgoingInFlight) return;

    outgoingInFlight = true;
    sendButton.setAttribute("aria-disabled", "true");

    const email = getComposeData(compose);
    showBanner("outgoing", "Checking this draft locally before sending…");

    try {
      const result = await analyzeLocally(email);
      const risk = riskScore(result);
      const label = String(result.label || "unknown").toUpperCase();

      if (isDangerous(result)) {
        showBanner(
          "outgoing",
          `WARNING — ${label}. Review the recipient, links and message before sending.`,
          "danger",
          risk
        );

        const proceed = window.confirm(
          `Phishy detected a potentially suspicious outgoing email.\n\n` +
          `Verdict: ${label}\n` +
          `Risk score: ${risk === null ? "unavailable" : risk + "/100"}\n\n` +
          `Cancel = keep the draft unsent.\n` +
          `OK = send anyway.`
        );

        if (!proceed) return;
      } else {
        showBanner(
          "outgoing",
          `Local check complete — ${label}. Sending your draft.`,
          "info",
          risk
        );
      }

      // Allow exactly one programmatic click through our interception.
      bypassNextSend = true;
      sendButton.click();

      // Reset the bypass if Gmail did not dispatch a click promptly.
      setTimeout(() => {
        bypassNextSend = false;
      }, 1500);
    } catch (error) {
      showBanner(
        "outgoing",
        "The local analyzer is unavailable. This draft has NOT been sent. Email content was not sent to Render.",
        "danger"
      );

      console.error("Phishy outgoing analysis failed:", error);

      const sendAnyway = window.confirm(
        "Phishy could not scan this draft because the local analyzer is unavailable.\n\n" +
        "The email has not been sent.\n\n" +
        "OK = send without a completed scan.\n" +
        "Cancel = keep the draft unsent."
      );

      if (sendAnyway) {
        bypassNextSend = true;
        sendButton.click();

        setTimeout(() => {
          bypassNextSend = false;
        }, 1500);
      }
    } finally {
      outgoingInFlight = false;
      sendButton.removeAttribute("aria-disabled");
    }
  }

  // Intercept Send clicks before Gmail's own click handler runs.
  document.addEventListener("click", event => {
    if (bypassNextSend) {
      bypassNextSend = false;
      return;
    }

    const target = event.target instanceof Element
      ? event.target
      : event.target?.parentElement;

    if (!target) return;

    const compose = target.closest(
      '[role="dialog"], .M9, .AD'
    );

    if (!compose || !visible(compose)) return;

    const button = target.closest(
      'div[role="button"], button, [data-tooltip], [aria-label]'
    );

    if (!button || !findSendButton(compose)) return;

    const label = [
      button.getAttribute("data-tooltip") || "",
      button.getAttribute("aria-label") || "",
      button.innerText || ""
    ].join(" ");

    if (!/\bsend\b/i.test(label) || /\bscheduled\b/i.test(label)) {
      return;
    }

    event.preventDefault();
    event.stopPropagation();
    event.stopImmediatePropagation();

    scanBeforeSending(button, compose);
  }, true);

  // Route Gmail's Ctrl/Cmd+Enter shortcut through the same Send check.
  document.addEventListener("keydown", event => {
    if (
      event.key !== "Enter" ||
      !(event.ctrlKey || event.metaKey)
    ) {
      return;
    }

    const target = event.target instanceof Element ? event.target : null;
    const compose = target?.closest('[role="dialog"], .M9, .AD');

    if (!compose || !visible(compose)) return;

    const button = findSendButton(compose);
    if (!button) return;

    event.preventDefault();
    event.stopPropagation();
    event.stopImmediatePropagation();
    button.click();
  }, true);

  function scheduleIncomingScan() {
    if (observerScheduled) return;

    observerScheduled = true;
    setTimeout(() => {
      observerScheduled = false;
      analyzeIncoming();
    }, 800);
  }

  const observer = new MutationObserver(scheduleIncomingScan);
  observer.observe(document.body, {
    childList: true,
    subtree: true
  });

  window.addEventListener("hashchange", scheduleIncomingScan);
  scheduleIncomingScan();

  console.log("Phishy Gmail scanner loaded.");
})();
