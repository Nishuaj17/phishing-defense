
const API_URL = "https://phishing-defense-h161.onrender.com";
const LOCAL_EMAIL_API_URL = "http://127.0.0.1:8765/analyze";

const recentlyChecked = new Map();
const CHECK_COOLDOWN_MS = 10000;

// Check ordinary website navigation using the public URL-analysis API.
if (chrome.webNavigation?.onBeforeNavigate) {
  chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
    if (details.frameId !== 0) return;

    const url = details.url;

    // Skip browser internals, local development, and Google OAuth.
    if (
      url.startsWith("chrome://") ||
      url.startsWith("chrome-extension://") ||
      url.startsWith("edge://") ||
      url.startsWith("about:") ||
      url.startsWith("http://localhost:") ||
      url.startsWith("http://127.0.0.1:") ||
      url.startsWith("https://accounts.google.com/") ||
      url.startsWith("https://oauth2.googleapis.com/")
    ) {
      return;
    }

    // Prevent repeated checks of the same URL.
    const now = Date.now();
    const lastChecked = recentlyChecked.get(url);

    if (lastChecked && now - lastChecked < CHECK_COOLDOWN_MS) {
      return;
    }

    recentlyChecked.set(url, now);

    // Prevent the cooldown map from growing indefinitely.
    if (recentlyChecked.size > 1000) {
      for (const [key, timestamp] of recentlyChecked) {
        if (now - timestamp >= CHECK_COOLDOWN_MS) {
          recentlyChecked.delete(key);
        }
      }
    }

    try {
      // Only the navigated URL is sent to Render.
      const response = await fetch(`${API_URL}/api/analyze`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify({ url })
      });

      if (response.status === 429) {
        console.warn("Phishy API rate limit reached. Navigation allowed.");
        return;
      }

      if (!response.ok) {
        console.error("Phishy API error:", response.status);
        return;
      }

      const result = await response.json();
      console.log("Phishy URL analysis:", result);

      if (
        result.recommended_action === "block" ||
        result.label === "phishing"
      ) {
        const warningId = `warning_${Date.now()}`;

        let source = "URL analysis";

        if (
          result.threat_intel?.status === "hit" &&
          result.threat_intel?.sources?.length
        ) {
          source =
            "Threat intelligence: " +
            result.threat_intel.sources.join(", ");
        }

        await chrome.storage.local.set({
          [warningId]: {
            url,
            risk: result.risk ?? 0,
            source
          }
        });

        const warningUrl =
          chrome.runtime.getURL("warning.html") +
          `?id=${encodeURIComponent(warningId)}`;

        await chrome.tabs.update(details.tabId, {
          url: warningUrl
        });
      }
    } catch (error) {
      console.error("Phishy URL check failed:", error);
    }
  });
}

// Analyze Gmail messages using ONLY the local Python service.
// This handler must never fall back to the public Render API.
chrome.runtime.onMessage.addListener(
  (message, sender, sendResponse) => {
    if (message?.type !== "PHISHY_ANALYZE_EMAIL") {
      return;
    }

    // Accept analysis requests only from a Gmail tab running this extension.
    if (
      !sender.tab?.url?.startsWith("https://mail.google.com/") ||
      sender.id !== chrome.runtime.id
    ) {
      sendResponse({ error: "Request rejected: not from Gmail." });
      return;
    }

    const email = message.email;

    if (
      !email ||
      typeof email.text !== "string" ||
      email.text.length === 0 ||
      email.text.length > 5000 ||
      typeof email.sender !== "string" ||
      typeof email.subject !== "string"
    ) {
      sendResponse({ error: "Invalid email payload." });
      return;
    }

    (async () => {
      const response = await fetch(LOCAL_EMAIL_API_URL, {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          sender: email.sender.slice(0, 500),
          subject: email.subject.slice(0, 1000),
          text: email.text
        })
      });

      if (!response.ok) {
        throw new Error(`Local analyzer returned HTTP ${response.status}`);
      }

      return await response.json();
    })()
      .then(sendResponse)
      .catch((error) => {
        console.error("Local Gmail analysis failed:", error);
        sendResponse({
          error:
            "Local Phishy analyzer unavailable. Gmail content was not sent to Render."
        });
      });

    // Keep the message channel open for the asynchronous response.
    return true;
  }
);
