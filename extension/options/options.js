/**
 * PhishGuard Options Page Logic
 */

document.addEventListener("DOMContentLoaded", async () => {
  const backendUrlInput = document.getElementById("backend-url");
  const apiKeyInput = document.getElementById("api-key");
  const blockPhishingCheck = document.getElementById("block-phishing");
  const warnSuspiciousCheck = document.getElementById("warn-suspicious");
  const cacheTtlInput = document.getElementById("cache-ttl");
  const form = document.getElementById("settings-form");
  const saveStatus = document.getElementById("save-status");
  const healthBadge = document.getElementById("health-badge");

  // Load existing settings
  const stored = await chrome.storage.local.get("settings");
  const settings = stored.settings || {
    backendUrl: "http://127.0.0.1:8000",
    apiKey: "pg_dev_8f2a1b9c4e7d0f3a6b5c2e1d8f4a7b0c",
    blockOnPhishing: true,
    warnOnSuspicious: true,
    cacheTtlMinutes: 15,
  };

  backendUrlInput.value = settings.backendUrl;
  apiKeyInput.value = settings.apiKey;
  blockPhishingCheck.checked = settings.blockOnPhishing !== false;
  warnSuspiciousCheck.checked = settings.warnOnSuspicious !== false;
  cacheTtlInput.value = settings.cacheTtlMinutes || 15;

  checkHealth(settings.backendUrl);

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const newSettings = {
      backendUrl: backendUrlInput.value.trim(),
      apiKey: apiKeyInput.value.trim(),
      blockOnPhishing: blockPhishingCheck.checked,
      warnOnSuspicious: warnSuspiciousCheck.checked,
      cacheTtlMinutes: parseInt(cacheTtlInput.value, 10) || 15,
    };

    await chrome.storage.local.set({ settings: newSettings });

    saveStatus.classList.remove("hidden");
    setTimeout(() => {
      saveStatus.classList.add("hidden");
    }, 2500);

    checkHealth(newSettings.backendUrl);
  });

  async function checkHealth(url) {
    healthBadge.className = "badge checking";
    healthBadge.textContent = "Checking...";
    try {
      const res = await fetch(`${url}/health`);
      if (res.ok) {
        healthBadge.className = "badge online";
        healthBadge.textContent = "Backend Online";
      } else {
        throw new Error();
      }
    } catch {
      healthBadge.className = "badge offline";
      healthBadge.textContent = "Offline";
    }
  }
});
