/**
 * Popup Scanner Logic
 */
document.addEventListener("DOMContentLoaded", async () => {
  const currentUrlEl = document.getElementById("current-url");
  const scanCurrentBtn = document.getElementById("scan-current-btn");
  const manualInput = document.getElementById("manual-url-input");
  const manualScanBtn = document.getElementById("manual-scan-btn");
  const statusDot = document.getElementById("status-dot");
  const resultsBox = document.getElementById("popup-results");
  const badgeEl = document.getElementById("result-badge");
  const scoreEl = document.getElementById("result-score");
  const mlEl = document.getElementById("result-ml");
  const reasonsEl = document.getElementById("result-reasons");

  // Check health
  chrome.runtime.sendMessage({ action: "GET_HEALTH" }, (res) => {
    if (res && res.success && res.data.status === "ok") {
      statusDot.className = "status-indicator online";
    } else {
      statusDot.className = "status-indicator offline";
    }
  });

  // Query active tab URL
  let activeTabUrl = "";
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tab && tab.url && (tab.url.startsWith("http://") || tab.url.startsWith("https://"))) {
      activeTabUrl = tab.url;
      currentUrlEl.textContent = activeTabUrl;
    } else {
      currentUrlEl.textContent = "No active web URL";
      scanCurrentBtn.disabled = true;
    }
  } catch (err) {
    currentUrlEl.textContent = "Unavailable";
  }

  scanCurrentBtn.addEventListener("click", () => {
    if (activeTabUrl) executeScan(activeTabUrl);
  });

  manualScanBtn.addEventListener("click", () => {
    const url = manualInput.value.trim();
    if (url) executeScan(url);
  });

  function executeScan(url) {
    badgeEl.textContent = "ANALYZING...";
    badgeEl.className = "result-badge";
    resultsBox.classList.remove("hidden");
    scoreEl.textContent = "--";
    mlEl.textContent = "--";
    reasonsEl.textContent = "";

    chrome.runtime.sendMessage({ action: "CHECK_URL", url }, (res) => {
      if (!res || !res.success) {
        badgeEl.textContent = "ERROR";
        badgeEl.className = "result-badge badge-danger";
        reasonsEl.textContent = res ? res.error : "Failed to connect to PhishGuard";
        return;
      }

      const data = res.data;
      const verdict = data.verdict;
      badgeEl.textContent = verdict.toUpperCase();

      if (verdict === "phishing" || verdict === "high_risk") {
        badgeEl.className = "result-badge badge-danger";
      } else if (verdict === "suspicious") {
        badgeEl.className = "result-badge badge-warn";
      } else {
        badgeEl.className = "result-badge badge-safe";
      }

      scoreEl.textContent = `${data.risk_score || 0}/100`;
      mlEl.textContent = data.phishing_probability !== null
        ? `${(data.phishing_probability * 100).toFixed(1)}%`
        : "N/A";

      if (data.reasons && data.reasons.length > 0) {
        reasonsEl.textContent = data.reasons.join(" • ");
      } else {
        reasonsEl.textContent = "No threat indicators detected.";
      }
    });
  }
});
