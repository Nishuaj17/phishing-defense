const params = new URLSearchParams(window.location.search);
const warningId = params.get("id");

async function loadWarning() {
  if (!warningId) {
    document.getElementById("url").textContent =
      "Unable to load URL information.";
    return;
  }

  const data = await chrome.storage.local.get(warningId);
  const warning = data[warningId];

  if (!warning) {
    document.getElementById("url").textContent =
      "Warning information unavailable.";
    return;
  }

  document.getElementById("url").textContent =
    warning.url;

  document.getElementById("risk").textContent =
    warning.risk;

  document.getElementById("source").textContent =
    "Threat intelligence / analysis: " +
    warning.source;

  document.getElementById("proceed").addEventListener("click", () => {
    window.location.href = warning.url;
  });
}

document.getElementById("back").addEventListener("click", () => {
  history.back();
});

loadWarning();
