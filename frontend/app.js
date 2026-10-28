/**
 * PhishGuard Frontend Application Logic
 *
 * Handles API communication, Quick Scan submission, reactive UI updates,
 * animated risk gauges, and settings persistence.
 */

// Configuration defaults
const DEFAULT_BACKEND_URL = "http://127.0.0.1:8000";
const DEFAULT_API_KEY = "pg_dev_8f2a1b9c4e7d0f3a6b5c2e1d8f4a7b0c";

const state = {
  backendUrl: localStorage.getItem("pg_backend_url") || DEFAULT_BACKEND_URL,
  apiKey: localStorage.getItem("pg_api_key") || DEFAULT_API_KEY,
  isScanning: false,
  scanMode: "quick",
};

// DOM Elements
const elements = {
  urlInput: document.getElementById("url-input"),
  clearBtn: document.getElementById("clear-btn"),
  scanForm: document.getElementById("scan-form"),
  scanSubmitBtn: document.getElementById("scan-submit-btn"),
  btnText: document.querySelector(".btn-text"),
  btnLoader: document.querySelector(".btn-loader"),
  backendStatusBadge: document.getElementById("backend-status-badge"),
  backendStatusText: document.getElementById("backend-status-text"),
  errorBanner: document.getElementById("error-banner"),
  errorMessage: document.getElementById("error-message"),
  resultsSection: document.getElementById("results-section"),
  verdictCard: document.getElementById("verdict-card"),
  verdictBadge: document.getElementById("verdict-badge"),
  verdictTitle: document.getElementById("verdict-title"),
  actionRecommendation: document.getElementById("action-recommendation"),
  cachedIndicator: document.getElementById("cached-indicator"),
  scanTimePill: document.getElementById("scan-time-pill"),
  scanIdPill: document.getElementById("scan-id-pill"),
  displayTargetUrl: document.getElementById("display-target-url"),
  riskScoreValue: document.getElementById("risk-score-value"),
  riskLevelCaption: document.getElementById("risk-level-caption"),
  gaugeProgress: document.getElementById("gauge-progress"),
  mlProbPercent: document.getElementById("ml-prob-percent"),
  mlProgressFill: document.getElementById("ml-progress-fill"),
  mlModelName: document.getElementById("ml-model-name"),
  mlDecisionText: document.getElementById("ml-decision-text"),
  mlLatencyVal: document.getElementById("ml-latency-val"),
  reasonsList: document.getElementById("reasons-list"),
  lexicalFeaturesList: document.getElementById("lexical-features-list"),
  structuralFeaturesList: document.getElementById("structural-features-list"),
  pillarMlStatus: document.getElementById("pillar-ml-status"),
  rawJsonCode: document.getElementById("raw-json-code"),
  toggleJsonBtn: document.getElementById("toggle-json-btn"),
  jsonArrow: document.getElementById("json-arrow"),
  settingsBtn: document.getElementById("settings-btn"),
  settingsModal: document.getElementById("settings-modal"),
  modalCloseBtn: document.getElementById("modal-close-btn"),
  saveSettingsBtn: document.getElementById("save-settings-btn"),
  backendUrlInput: document.getElementById("backend-url-input"),
  apiKeyInput: document.getElementById("api-key-input"),
  modalMetaContent: document.getElementById("modal-meta-content"),
  modeQuickBtn: document.getElementById("mode-quick-btn"),
  modeDeepBtn: document.getElementById("mode-deep-btn"),
};

// ---------------------------------------------------------------------------
// Initialization
// ---------------------------------------------------------------------------

document.addEventListener("DOMContentLoaded", () => {
  setupEventListeners();
  checkBackendHealth();
  elements.backendUrlInput.value = state.backendUrl;
  elements.apiKeyInput.value = state.apiKey;
});

function setupEventListeners() {
  // Input change
  elements.urlInput.addEventListener("input", (e) => {
    if (e.target.value.trim().length > 0) {
      elements.clearBtn.classList.remove("hidden");
    } else {
      elements.clearBtn.classList.add("hidden");
    }
  });

  // Clear button
  elements.clearBtn.addEventListener("click", () => {
    elements.urlInput.value = "";
    elements.clearBtn.classList.add("hidden");
    elements.urlInput.focus();
  });

  // Form submit
  elements.scanForm.addEventListener("submit", (e) => {
    e.preventDefault();
    const url = elements.urlInput.value.trim();
    if (url) {
      performScan(url);
    }
  });

  // Sample buttons
  document.querySelectorAll(".sample-pill").forEach((btn) => {
    btn.addEventListener("click", () => {
      const url = btn.dataset.url;
      elements.urlInput.value = url;
      elements.clearBtn.classList.remove("hidden");
      performScan(url);
    });
  });

  // Mode switcher tabs (Quick Scan vs Deep Scan)
  elements.modeQuickBtn.addEventListener("click", () => {
    state.scanMode = "quick";
    elements.modeQuickBtn.classList.add("active");
    elements.modeDeepBtn.classList.remove("active");
    hideError();
  });

  elements.modeDeepBtn.addEventListener("click", () => {
    state.scanMode = "deep";
    elements.modeDeepBtn.classList.add("active");
    elements.modeQuickBtn.classList.remove("active");
    hideError();
  });

  // Raw JSON toggle
  elements.toggleJsonBtn.addEventListener("click", () => {
    const isHidden = elements.rawJsonCode.classList.contains("hidden");
    if (isHidden) {
      elements.rawJsonCode.classList.remove("hidden");
      elements.jsonArrow.textContent = "▲";
    } else {
      elements.rawJsonCode.classList.add("hidden");
      elements.jsonArrow.textContent = "▼";
    }
  });

  // Settings modal
  elements.settingsBtn.addEventListener("click", openSettingsModal);
  elements.modalCloseBtn.addEventListener("click", closeSettingsModal);
  elements.settingsModal.addEventListener("click", (e) => {
    if (e.target === elements.settingsModal) closeSettingsModal();
  });

  elements.saveSettingsBtn.addEventListener("click", () => {
    state.backendUrl = elements.backendUrlInput.value.trim() || DEFAULT_BACKEND_URL;
    state.apiKey = elements.apiKeyInput.value.trim() || DEFAULT_API_KEY;
    localStorage.setItem("pg_backend_url", state.backendUrl);
    localStorage.setItem("pg_api_key", state.apiKey);
    closeSettingsModal();
    checkBackendHealth();
  });
}

// ---------------------------------------------------------------------------
// Backend Communication
// ---------------------------------------------------------------------------

async function checkBackendHealth() {
  updateStatus("checking", "Connecting...");
  try {
    const res = await fetch(`${state.backendUrl}/health`, {
      method: "GET",
      headers: { "Accept": "application/json" },
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    if (data.model_loaded) {
      updateStatus("online", "Online • Model Loaded (rf_v1)");
    } else {
      updateStatus("online", "Online • Degraded Mode (No Model)");
    }
  } catch (err) {
    updateStatus("offline", "Backend Offline");
  }
}

function updateStatus(type, message) {
  elements.backendStatusBadge.className = `status-pill status-${type}`;
  elements.backendStatusText.textContent = message;
}

async function fetchModelMetadata() {
  elements.modalMetaContent.textContent = "Loading metadata...";
  try {
    const res = await fetch(`${state.backendUrl}/model-info`, {
      headers: {
        "X-API-Key": state.apiKey,
        "Accept": "application/json",
      },
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    elements.modalMetaContent.textContent = JSON.stringify(data, null, 2);
  } catch (err) {
    elements.modalMetaContent.textContent = `Could not load metadata: ${err.message}`;
  }
}

// ---------------------------------------------------------------------------
// Scanning Pipeline
// ---------------------------------------------------------------------------

async function performScan(url) {
  if (state.isScanning) return;
  setScanning(true);
  hideError();

  const startTime = performance.now();

  try {
    const endpoint = state.scanMode === "deep" ? "/api/v1/deep-scan" : "/api/v1/check-url";
    const res = await fetch(`${state.backendUrl}${endpoint}`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-API-Key": state.apiKey,
      },
      body: JSON.stringify({ url }),
    });

    const elapsedMs = Math.round(performance.now() - startTime);

    if (!res.ok) {
      const errData = await res.json().catch(() => ({}));
      throw new Error(errData.detail || `Request failed with status ${res.status}`);
    }

    const rawJson = await res.json();
    const data = rawJson.result || rawJson;
    renderResults(data, elapsedMs);
  } catch (err) {
    showError(err.message || "Unable to reach PhishGuard backend service");
  } finally {
    setScanning(false);
  }
}

function setScanning(scanning) {
  state.isScanning = scanning;
  elements.scanSubmitBtn.disabled = scanning;
  if (scanning) {
    elements.btnText.textContent = "Analyzing...";
    elements.btnLoader.classList.remove("hidden");
  } else {
    elements.btnText.textContent = "Scan URL";
    elements.btnLoader.classList.add("hidden");
  }
}

function showError(msg) {
  elements.errorMessage.textContent = msg;
  elements.errorBanner.classList.remove("hidden");
}

function hideError() {
  elements.errorBanner.classList.add("hidden");
}

// ---------------------------------------------------------------------------
// Results Rendering
// ---------------------------------------------------------------------------

function renderResults(data, clientLatencyMs) {
  elements.resultsSection.classList.remove("hidden");

  // 1. Verdict & Action
  const verdict = data.verdict;
  const action = data.action;

  elements.verdictCard.className = `verdict-card verdict-${verdict.replace(/_/g, "-")}`;
  elements.verdictBadge.textContent = verdict.toUpperCase();
  elements.displayTargetUrl.textContent = data.normalized_url || data.url;

  let title = "No Known Threat Detected";
  let actionText = "ALLOW — Standard navigation safe";

  if (verdict === "phishing") {
    title = "Phishing Threat Detected";
    actionText = "BLOCK — Immediate credential or malware hazard";
  } else if (verdict === "high_risk") {
    title = "High Risk Destination";
    actionText = "BLOCK / RESTRICT — Strong malicious indicators";
  } else if (verdict === "suspicious") {
    title = "Suspicious Link Detected";
    actionText = "WARN — Proceed with extreme caution";
  } else if (verdict === "low_risk") {
    title = "Low Risk Link";
    actionText = "ALLOW — Minor irregularities noted";
  }

  elements.verdictTitle.textContent = title;
  elements.actionRecommendation.textContent = `Action: ${action.toUpperCase()} (${actionText})`;

  // Meta pills
  if (data.cached) {
    elements.cachedIndicator.classList.remove("hidden");
  } else {
    elements.cachedIndicator.classList.add("hidden");
  }
  elements.scanTimePill.textContent = `Latency: ${clientLatencyMs}ms`;
  elements.scanIdPill.textContent = `ID: ${data.scan_id.slice(0, 8)}...`;

  // 2. Risk Score Gauge
  const score = data.risk_score || 0;
  elements.riskScoreValue.textContent = score;

  // SVG Gauge progress calculation: circumference = 2 * PI * 50 = 314
  const circumference = 314;
  const offset = circumference - (score / 100) * circumference;
  elements.gaugeProgress.style.strokeDashoffset = offset;

  // Gauge color based on score
  let gaugeColor = "#10b981"; // safe
  if (score >= 80) gaugeColor = "#ef4444";
  else if (score >= 50) gaugeColor = "#f59e0b";
  else if (score >= 25) gaugeColor = "#06b6d4";
  elements.gaugeProgress.style.stroke = gaugeColor;

  if (score >= 80) {
    elements.riskLevelCaption.textContent = "Critical threat signals detected.";
  } else if (score >= 50) {
    elements.riskLevelCaption.textContent = "Elevated risk signals detected.";
  } else if (score >= 25) {
    elements.riskLevelCaption.textContent = "Low risk detected.";
  } else {
    elements.riskLevelCaption.textContent = "No critical threat signatures found.";
  }

  // 3. ML Probability
  const prob = data.phishing_probability;
  if (prob !== null && prob !== undefined) {
    const percent = (prob * 100).toFixed(1);
    elements.mlProbPercent.textContent = `${percent}%`;
    elements.mlProgressFill.style.width = `${percent}%`;
    elements.mlDecisionText.textContent = prob >= 0.5 ? "Phishing Hazard" : "Candidate Benign";
    const mlLatency = data.evidence?.ml_prediction?.latency_ms;
    elements.mlLatencyVal.textContent = mlLatency ? `${mlLatency} ms` : "< 2 ms";
  } else {
    elements.mlProbPercent.textContent = "N/A";
    elements.mlProgressFill.style.width = "0%";
    elements.mlDecisionText.textContent = "Model Degraded / Offline";
    elements.mlLatencyVal.textContent = "N/A";
  }

  // 4. Policy Reasons
  elements.reasonsList.innerHTML = "";
  if (data.reasons && data.reasons.length > 0) {
    data.reasons.forEach((reason) => {
      const li = document.createElement("li");
      li.className = "reason-item";
      li.innerHTML = `<span>⚠️</span> <span>${escapeHtml(reason)}</span>`;
      elements.reasonsList.appendChild(li);
    });
  } else {
    const li = document.createElement("li");
    li.className = "reason-item empty-reasons";
    li.innerHTML = `<span>✓</span> <span>No deterministic red flags triggered</span>`;
    elements.reasonsList.appendChild(li);
  }

  // 5. Evidence Pillars
  renderFeatures(data.evidence?.static_analysis?.details || {});

  // 6. TLS Evidence (Deep Scan)
  const tls = data.evidence?.tls;
  const pillarTlsStatus = document.getElementById("pillar-tls-status");
  const tlsBody = document.getElementById("tls-features-body");
  if (pillarTlsStatus && tlsBody) {
    if (tls && tls.status === "completed") {
      const details = tls.details || {};
      pillarTlsStatus.className = details.valid ? "pillar-status status-completed" : "pillar-status status-failed";
      pillarTlsStatus.textContent = details.valid ? "Valid Certificate" : "Certificate Invalid";
      tlsBody.innerHTML = `
        <div class="feature-row"><span class="feat-name">HTTPS Verified</span><span class="feat-val">${details.valid ? "✓ Yes" : "✗ No"}</span></div>
        <div class="feature-row"><span class="feat-name">Hostname Match</span><span class="feat-val">${details.hostname_match ? "✓ Match" : "✗ Mismatch"}</span></div>
        <div class="feature-row"><span class="feat-name">Issuer</span><span class="feat-val">${escapeHtml(details.issuer_common_name || details.issuer_organization || details.error || "N/A")}</span></div>
        <div class="feature-row"><span class="feat-name">Days Remaining</span><span class="feat-val">${details.days_remaining !== undefined ? details.days_remaining : "N/A"}</span></div>
      `;
    } else {
      pillarTlsStatus.className = "pillar-status status-not-checked";
      pillarTlsStatus.textContent = "Not Checked (Quick Scan)";
      tlsBody.innerHTML = `<p class="pillar-note">TLS handshake and certificate chain inspection triggers in Deep Scan mode.</p>`;
    }
  }

  // 7. Dynamic Sandbox Evidence (Deep Scan)
  const sandbox = data.evidence?.dynamic_analysis;
  const pillarSandboxStatus = document.getElementById("pillar-sandbox-status");
  const sandboxBody = document.getElementById("sandbox-features-body");
  if (pillarSandboxStatus && sandboxBody) {
    if (sandbox && sandbox.status === "completed") {
      const details = sandbox.details || {};
      pillarSandboxStatus.className = "pillar-status status-completed";
      pillarSandboxStatus.textContent = "Sandbox Verified";
      sandboxBody.innerHTML = `
        <div class="feature-row"><span class="feat-name">Environment</span><span class="feat-val">${escapeHtml(details.environment || "hardened_sandbox")}</span></div>
        <div class="feature-row"><span class="feat-name">SSRF Egress Guard</span><span class="feat-val">${details.destination_allowed ? "✓ Safe Public Destination" : "✗ SSRF Blocked"}</span></div>
        <div class="feature-row"><span class="feat-name">Redirect Hops</span><span class="feat-val">${details.hop_count !== undefined ? details.hop_count : 0} hops</span></div>
      `;
    } else {
      pillarSandboxStatus.className = "pillar-status status-not-run";
      pillarSandboxStatus.textContent = "Not Run (Deep Scan Only)";
      sandboxBody.innerHTML = `<p class="pillar-note">Headless DOM inspection and redirect chain tracking execute inside the hardened sandbox.</p>`;
    }
  }

  // Raw JSON display
  elements.rawJsonCode.textContent = JSON.stringify(data, null, 2);

  // Smooth scroll into results
  elements.resultsSection.scrollIntoView({ behavior: "smooth", block: "start" });
}

function renderFeatures(feats) {
  // Lexical
  const lexicalKeys = [
    { key: "url_length", label: "URL Length" },
    { key: "hostname_length", label: "Hostname Length" },
    { key: "url_entropy", label: "URL Shannon Entropy" },
    { key: "hostname_entropy", label: "Hostname Entropy" },
    { key: "subdomain_count", label: "Subdomain Count" },
    { key: "is_ip_address", label: "IP Host Detected", flagIfTrue: true },
    { key: "is_known_shortener", label: "URL Shortener Domain", flagIfTrue: true },
    { key: "punycode_detected", label: "Punycode (Homograph)", flagIfTrue: true },
    { key: "tld_risk_score", label: "High-Risk TLD", flagIfTrue: true },
    { key: "has_credentials", label: "Embedded Credentials", flagIfTrue: true },
  ];

  elements.lexicalFeaturesList.innerHTML = "";
  lexicalKeys.forEach(({ key, label, flagIfTrue }) => {
    const val = feats[key] !== undefined ? feats[key] : "—";
    const isFlagged = flagIfTrue && (val === 1 || val === true);
    const row = document.createElement("div");
    row.className = "feature-row";
    row.innerHTML = `
      <span class="feat-name">${label}</span>
      <span class="feat-val ${isFlagged ? "val-flagged" : ""}">${val}</span>
    `;
    elements.lexicalFeaturesList.appendChild(row);
  });

  // Structural
  const structuralKeys = [
    { key: "brand_in_subdomain", label: "Brand in Subdomain", flagIfTrue: true },
    { key: "brand_domain_mismatch", label: "Brand Domain Mismatch", flagIfTrue: true },
    { key: "scheme_mismatch", label: "Scheme Insecurity", flagIfTrue: true },
    { key: "suspicious_token_count", label: "Suspicious Keyword Count" },
    { key: "redirect_token_in_url", label: "Redirect Parameter", flagIfTrue: true },
    { key: "excessive_subdomains", label: "Excessive Subdomains", flagIfTrue: true },
  ];

  elements.structuralFeaturesList.innerHTML = "";
  structuralKeys.forEach(({ key, label, flagIfTrue }) => {
    const val = feats[key] !== undefined ? feats[key] : "—";
    const isFlagged = flagIfTrue && (val === 1 || val === true);
    const row = document.createElement("div");
    row.className = "feature-row";
    row.innerHTML = `
      <span class="feat-name">${label}</span>
      <span class="feat-val ${isFlagged ? "val-flagged" : ""}">${val}</span>
    `;
    elements.structuralFeaturesList.appendChild(row);
  });
}

function openSettingsModal() {
  elements.settingsModal.classList.remove("hidden");
  fetchModelMetadata();
}

function closeSettingsModal() {
  elements.settingsModal.classList.add("hidden");
}

function escapeHtml(str) {
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}
