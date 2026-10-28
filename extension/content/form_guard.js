/**
 * PhishGuard Form Guard — Zero-Hour Credential Submission Protection (Tickets 5.1 & 5.2)
 *
 * Scans page DOM for password input fields. Intercepts form submission
 * to verify destination safety before sensitive credentials leave the browser.
 */

(function () {
  const currentUrl = window.location.href;

  // Listen for submit events on forms containing password fields
  document.addEventListener("submit", handleFormSubmit, true);

  function handleFormSubmit(event) {
    const form = event.target;
    if (!form || !form.querySelector) return;

    const passwordField = form.querySelector('input[type="password"]');
    if (!passwordField) return; // Only guard credential submission

    // Query PhishGuard backend for current site verdict
    chrome.runtime.sendMessage({ action: "CHECK_URL", url: currentUrl }, (response) => {
      if (!response || !response.success) return; // Fail-open if backend unreachable

      const data = response.data;
      if (data.is_override) return; // User previously authorized override

      const verdict = data.verdict;
      if (verdict === "phishing" || verdict === "high_risk" || verdict === "suspicious") {
        event.preventDefault();
        event.stopPropagation();
        showCredentialWarning(form, data);
      }
    });
  }

  function showCredentialWarning(form, data) {
    const existing = document.getElementById("phishguard-cred-warning");
    if (existing) existing.remove();

    const banner = document.createElement("div");
    banner.id = "phishguard-cred-warning";
    banner.className = "phishguard-overlay";
    banner.innerHTML = `
      <div class="phishguard-modal" style="border-color: #ef4444 !important; max-width: 500px !important;">
        <div class="phishguard-modal-header">
          <span class="phishguard-icon">🚨</span>
          <div>
            <span class="phishguard-badge phishguard-badge-danger">CREDENTIAL THEFT WARNING</span>
            <h2 class="phishguard-title">Password Submission Blocked</h2>
          </div>
        </div>
        <div class="phishguard-modal-body">
          <p class="phishguard-desc" style="color: #fca5a5 !important; font-weight: 500 !important;">
            PhishGuard intercepted your password. This destination (${escapeHtml(window.location.hostname)}) exhibits strong indicators of a phishing or credential-harvesting trap.
          </p>
          <div class="phishguard-meta-row">
            <span>Risk Score: <strong>${data.risk_score || 0}/100</strong></span>
            <span>Verdict: <strong>${escapeHtml(data.verdict.toUpperCase())}</strong></span>
          </div>
        </div>
        <div class="phishguard-modal-footer">
          <button id="phishguard-cancel-cred" class="phishguard-btn phishguard-btn-safe">
            ✓ Abort Submission & Clear Password (Safe)
          </button>
          <button id="phishguard-force-cred" class="phishguard-btn phishguard-btn-override">
            Submit Anyway (High Risk)
          </button>
        </div>
      </div>
    `;

    document.body.appendChild(banner);

    banner.querySelector("#phishguard-cancel-cred").addEventListener("click", () => {
      const pwd = form.querySelector('input[type="password"]');
      if (pwd) pwd.value = "";
      banner.remove();
    });

    banner.querySelector("#phishguard-force-cred").addEventListener("click", () => {
      banner.remove();
      // Allow single submission bypass
      chrome.runtime.sendMessage({ action: "ADD_OVERRIDE", url: currentUrl, durationMinutes: 5 }, () => {
        form.submit();
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
})();
