/**
 * PhishGuard Background Service Worker (Manifest V3)
 *
 * Handles API communication, storage caching, and message dispatching
 * for popups and content scripts.
 */

const DEFAULT_SETTINGS = {
  backendUrl: "http://127.0.0.1:8000",
  apiKey: "pg_dev_8f2a1b9c4e7d0f3a6b5c2e1d8f4a7b0c",
  blockOnPhishing: true,
  warnOnSuspicious: true,
  cacheTtlMinutes: 15,
};

// In-memory cache for fast lookups
const memoryCache = new Map();

// Temporary user overrides: url -> expiry timestamp
const temporaryOverrides = new Map();

chrome.runtime.onInstalled.addListener(async () => {
  const current = await chrome.storage.local.get("settings");
  if (!current.settings) {
    await chrome.storage.local.set({ settings: DEFAULT_SETTINGS });
  }
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === "CHECK_URL") {
    handleCheckUrl(message.url)
      .then((res) => sendResponse({ success: true, data: res }))
      .catch((err) => sendResponse({ success: false, error: err.message }));
    return true; // Keep channel open for async response
  }

  if (message.action === "ADD_OVERRIDE") {
    const expiry = Date.now() + (message.durationMinutes || 10) * 60 * 1000;
    temporaryOverrides.set(message.url, expiry);
    sendResponse({ success: true, expiry });
    return false;
  }

  if (message.action === "CHECK_OVERRIDE") {
    const expiry = temporaryOverrides.get(message.url);
    const isValid = expiry && expiry > Date.now();
    sendResponse({ hasOverride: Boolean(isValid) });
    return false;
  }

  if (message.action === "GET_HEALTH") {
    getBackendSettings().then((settings) => {
      fetch(`${settings.backendUrl}/health`)
        .then((r) => r.json())
        .then((data) => sendResponse({ success: true, data }))
        .catch((err) => sendResponse({ success: false, error: err.message }));
    });
    return true;
  }
});

async function getBackendSettings() {
  const data = await chrome.storage.local.get("settings");
  return data.settings || DEFAULT_SETTINGS;
}

async function handleCheckUrl(url) {
  // 1. Check temporary overrides
  const overrideExpiry = temporaryOverrides.get(url);
  if (overrideExpiry && overrideExpiry > Date.now()) {
    return {
      url,
      verdict: "no_known_threat",
      action: "allow",
      risk_score: 0,
      reasons: ["User temporary bypass active"],
      is_override: true,
    };
  }

  // 2. Memory cache check
  const now = Date.now();
  if (memoryCache.has(url)) {
    const cached = memoryCache.get(url);
    if (cached.expiresAt > now) {
      return { ...cached.data, cached: true };
    }
    memoryCache.delete(url);
  }

  // 3. API Request to PhishGuard local backend
  const settings = await getBackendSettings();
  const response = await fetch(`${settings.backendUrl}/api/v1/check-url`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-API-Key": settings.apiKey,
      "Origin": "http://127.0.0.1:3000",
    },
    body: JSON.stringify({ url }),
  });

  if (!response.ok) {
    const errText = await response.text();
    throw new Error(`API error (${response.status}): ${errText}`);
  }

  const result = await response.json();

  // Cache in memory
  const ttlMs = (settings.cacheTtlMinutes || 15) * 60 * 1000;
  memoryCache.set(url, {
    data: result,
    expiresAt: now + ttlMs,
  });

  return result;
}
