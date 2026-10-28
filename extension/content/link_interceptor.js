/**
 * PhishGuard Content Script — Link Click Interception & Real-Time Warning (Tickets 4.4 & 4.5)
 *
 * Intercepts external link clicks, consults background worker cache/API,
 * and displays an in-page security warning dialog if dangerous.
 */

document.addEventListener("click", handleLinkClick, true);

function handleLinkClick(event) {
  // Find closest anchor tag
  const anchor = event.target.closest("a");
  if (!anchor || !anchor.href) return;

  const targetUrl = anchor.href;

  // Ignore internal hashes, javascript:, mailto:, and same-origin links
  if (!targetUrl.startsWith("http://") && !targetUrl.startsWith("https://")) return;

  try {
    const targetHost = new URL(targetUrl).hostname;
    const currentHost = window.location.hostname;
    if (targetHost === currentHost) return; // Same-origin navigation allowed
  } catch (e) {
    return;
  }

  // Intercept external link click
  event.preventDefault();
  event.stopPropagation();

  // Check background worker for fast verdict
  chrome.runtime.sendMessage({ action: "CHECK_URL", url: targetUrl }, (response) => {
    if (!response || !response.success) {
      // If service worker is unreachable, fail-safe allow navigation
      window.location.href = targetUrl;
      return;
    }

    const data = response.data;
    if (data.is_override) {
      window.location.href = targetUrl;
      return;
    }

    const verdict = data.verdict;
    const action = data.action;

    // Show warning dialog on PHISHING, HIGH_RISK, or SUSPICIOUS
    if (verdict === "phishing" || verdict === "high_risk" || action === "block" || action === "warn") {
      showPhishGuardWarning(targetUrl, data);
    } else {
      // Safe link — proceed
      window.location.href = targetUrl;
    }
  });
}

function showPhishGuardWarning(targetUrl, data) {
  // Remove existing modal if any
  const existing = document.getElementById("phishguard-warning-overlay");
  if (existing) existing.remove();

  const overlay = document.createElement("div");
  overlay.id = "phishguard-warning-overlay";
  overlay.className = "phishguard-overlay";

  const isPhishing = data.verdict === "phishing" || data.verdict === "high_risk";
  const title = isPhishing ? "Critical Security Warning: Phishing Detected" : "Suspicious Link Warning";
  const badgeClass = isPhishing ? "phishguard-badge-danger" : "phishguard-badge-warn";

  const reasonsHtml = (data.reasons || [])
    .map((r) => `<li>${escapeHtml(r)}</li>`)
    .join("");

  overlay.innerHTML = `
    <div class="phishguard-modal">
      <div class="phishguard-modal-header">
        <span class="phishguard-icon">🛡️</span>
        <div>
          <span class="phishguard-badge ${badgeClass}">${escapeHtml(data.verdict.toUpperCase())}</span>
          <h2 class="phishguard-title">${escapeHtml(title)}</h2>
        </div>
      </div>

      <div class="phishguard-modal-body">
        <p class="phishguard-desc">
          PhishGuard blocked navigation to this website because it triggered known credential harvesting or deceptive domain indicators.
        </p>

        <div class="phishguard-target-box">
          <span class="phishguard-target-label">Target URL:</span>
          <code class="phishguard-target-url">${escapeHtml(targetUrl)}</code>
        </div>

        <div class="phishguard-meta-row">
          <span>Risk Score: <strong>${data.risk_score || 0}/100</strong></span>
          <span>ML Confidence: <strong>${data.phishing_probability ? (data.phishing_probability * 100).toFixed(1) + '%' : 'Static Rules'}</strong></span>
        </div>

        ${reasonsHtml ? `<ul class="phishguard-reasons">${reasonsHtml}</ul>` : ""}
      </div>

      <div class="phishguard-modal-footer">
        <button id="phishguard-btn-safe" class="phishguard-btn phishguard-btn-safe">
          ✓ Go Back to Safety (Recommended)
        </button>
        <button id="phishguard-btn-override" class="phishguard-btn phishguard-btn-override">
          Continue Anyway (Unsafe)
        </button>
      </div>
    </div>
  `;

  document.body.appendChild(overlay);

  // Safe button
  overlay.querySelector("#phishguard-btn-safe").addEventListener("click", () => {
    overlay.remove();
  });

  // Override button
  overlay.querySelector("#phishguard-btn-override").addEventListener("click", () => {
    chrome.runtime.sendMessage({ action: "ADD_OVERRIDE", url: targetUrl, durationMinutes: 10 }, () => {
      overlay.remove();
      window.location.href = targetUrl;
    });
  });
}

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}
