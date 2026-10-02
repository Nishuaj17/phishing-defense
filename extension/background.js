const API_URL = "https://phishing-defense-h161.onrender.com";

const recentlyChecked = new Map();
const CHECK_COOLDOWN_MS = 10000;

chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
  if (details.frameId !== 0) return;

  const url = details.url;

  // Never inspect browser, extension, local-development,
  // or Google OAuth navigation.
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

  // Prevent repeated analysis of the same URL.
  const now = Date.now();
  const lastChecked = recentlyChecked.get(url);

  if (lastChecked && now - lastChecked < CHECK_COOLDOWN_MS) {
    return;
  }

  recentlyChecked.set(url, now);

  try {
    const response = await fetch(`${API_URL}/api/analyze`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ url })
    });

    // API rate limit — don't keep retrying automatically.
    if (response.status === 429) {
      console.warn("Phishy API rate limit reached. Navigation allowed.");
      return;
    }

    if (!response.ok) {
      console.error("Phishy API error:", response.status);
      return;
    }

    const result = await response.json();

    console.log("Phishy analysis:", result);

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
    console.error("Phishy check failed:", error);
  }
});