const textEncoder = new TextEncoder();
const i18n = window.VaultOtpI18n;
let currentLocale = i18n.getInitialLocale();
const t = (key, params = {}) => i18n.t(key, currentLocale, params);

const state = {
  locale: currentLocale,
  serviceUrl: "",
  pat: "",
  entries: [],
  codes: new Map(),
  importItems: [],
};

const els = {
  serviceUrl: document.getElementById("service-url"),
  pat: document.getElementById("pat"),
  saveSettings: document.getElementById("save-settings"),
  refreshEntries: document.getElementById("refresh-entries"),
  search: document.getElementById("search"),
  entries: document.getElementById("entries"),
  message: document.getElementById("message"),
  scanPage: document.getElementById("scan-page"),
  importText: document.getElementById("import-text"),
  previewImport: document.getElementById("preview-import"),
  importValid: document.getElementById("import-valid"),
  importPreview: document.getElementById("import-preview"),
};
i18n.setLocale(currentLocale);

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function uid() {
  return `${Date.now().toString(36)}${crypto.getRandomValues(new Uint32Array(1))[0].toString(36)}`;
}

function normalizeSecret(secret) {
  return String(secret || "").replace(/\s+/g, "").replace(/=+$/g, "").toUpperCase();
}

function normalizeServiceUrl(value) {
  const raw = String(value || "").trim().replace(/\/+$/g, "");
  if (!raw) throw new Error(t("serviceUrlRequired"));
  const url = new URL(raw);
  const isLocal = ["localhost", "127.0.0.1"].includes(url.hostname);
  if (url.protocol !== "https:" && !(url.protocol === "http:" && isLocal)) {
    throw new Error(t("httpsRequired"));
  }
  return url.toString().replace(/\/+$/g, "");
}

function toBase64(bytes) {
  return btoa(String.fromCharCode(...new Uint8Array(bytes)));
}

function base32ToBytes(secret) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const normalized = normalizeSecret(secret);
  let bits = "";
  for (const char of normalized) {
    const value = alphabet.indexOf(char);
    if (value === -1) throw new Error("invalid_secret");
    bits += value.toString(2).padStart(5, "0");
  }
  const bytes = [];
  for (let index = 0; index + 8 <= bits.length; index += 8) {
    bytes.push(parseInt(bits.slice(index, index + 8), 2));
  }
  return new Uint8Array(bytes);
}

function normalizeAlgorithm(value) {
  const normalized = String(value || "SHA-1").replace("-", "").toUpperCase();
  if (normalized === "SHA1") return "SHA-1";
  if (normalized === "SHA256") return "SHA-256";
  if (normalized === "SHA512") return "SHA-512";
  return "SHA-1";
}

function normalizeOtpType(value) {
  return String(value || "TOTP").toUpperCase().includes("HOTP") ? "HOTP" : "TOTP";
}

function duplicateKey(entry) {
  const period = entry.type === "TOTP" ? Number(entry.period || 30) : "";
  return [entry.type, entry.issuer, entry.account, entry.algorithm, entry.digits, period]
    .map((part) => String(part || "").toLowerCase())
    .join("|");
}

function parseOtpAuthUri(uri) {
  const url = new URL(uri.trim());
  if (url.protocol !== "otpauth:") throw new Error("unsupported");
  const type = normalizeOtpType(url.hostname);
  const label = decodeURIComponent(url.pathname.replace(/^\//, ""));
  const labelParts = label.split(":");
  const issuerParam = url.searchParams.get("issuer") || "";
  const issuer = issuerParam || (labelParts.length > 1 ? labelParts[0] : "");
  const account = labelParts.length > 1 ? labelParts.slice(1).join(":") : label;
  return {
    issuer: issuer.trim(),
    account: account.trim(),
    secret: normalizeSecret(url.searchParams.get("secret") || ""),
    type,
    algorithm: normalizeAlgorithm(url.searchParams.get("algorithm") || "SHA1"),
    digits: Number(url.searchParams.get("digits") || 6),
    period: Number(url.searchParams.get("period") || 30),
    counter: Number(url.searchParams.get("counter") || 0),
    groupId: "default",
    note: "",
    icon: "",
  };
}

function parseImportText(text) {
  return String(text || "")
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line.startsWith("otpauth://"))
    .map(parseOtpAuthUri);
}

function previewImportItems(entries) {
  const existingKeys = new Set(state.entries.map(duplicateKey));
  const previewKeys = new Set();
  return entries.map((entry) => {
    let status = "valid";
    let reason = "";
    try {
      base32ToBytes(entry.secret);
    } catch {
      status = "invalid";
      reason = t("invalidSecretShort");
    }
    if (!entry.issuer || !entry.account || !entry.secret) {
      status = "invalid";
      reason = t("missingFields");
    }
    const key = duplicateKey(entry);
    if (status === "valid" && (existingKeys.has(key) || previewKeys.has(key))) {
      status = "duplicate";
      reason = t("duplicate");
    }
    previewKeys.add(key);
    return { id: uid(), entry, status, reason };
  });
}

async function api(path, options = {}) {
  if (!state.serviceUrl || !state.pat) throw new Error(t("settingsRequired"));
  const headers = { ...(options.headers || {}), Authorization: `Bearer ${state.pat}` };
  if (options.body && !headers["Content-Type"]) headers["Content-Type"] = "application/json";
  const response = await fetch(`${state.serviceUrl}${path}`, { ...options, headers });
  const text = await response.text();
  const payload = text ? JSON.parse(text) : {};
  if (!response.ok) throw new Error(payload.error || "request_failed");
  return payload;
}

async function encryptSecret(secret) {
  const response = await fetch(`${state.serviceUrl}/api/bootstrap`, { cache: "no-store" });
  const bootstrap = await response.json();
  if (!response.ok || !bootstrap.secretPublicKey) throw new Error(t("publicKeyError"));
  const publicKey = await crypto.subtle.importKey(
    "jwk",
    bootstrap.secretPublicKey,
    { name: "RSA-OAEP", hash: "SHA-256" },
    false,
    ["encrypt"],
  );
  const encrypted = await crypto.subtle.encrypt({ name: "RSA-OAEP" }, publicKey, textEncoder.encode(normalizeSecret(secret)));
  return toBase64(encrypted);
}

function setMessage(message, isError = true) {
  els.message.textContent = message;
  els.message.style.color = isError ? "var(--danger)" : "var(--muted)";
}

function renderStaticText() {
  document.title = t("authTitle");
  document.querySelectorAll("[data-i18n]").forEach((node) => {
    node.textContent = t(node.dataset.i18n);
  });
  document.querySelectorAll("[data-i18n-placeholder]").forEach((node) => {
    node.placeholder = t(node.dataset.i18nPlaceholder);
  });
  document.querySelectorAll("[data-i18n-aria-label]").forEach((node) => {
    node.setAttribute("aria-label", t(node.dataset.i18nAriaLabel));
  });
  document.querySelectorAll("[data-locale]").forEach((node) => {
    node.classList.toggle("active", node.dataset.locale === state.locale);
  });
}

function changeLocale(locale) {
  currentLocale = i18n.setLocale(locale);
  state.locale = currentLocale;
  renderStaticText();
  renderEntries();
  if (els.importText.value.trim()) {
    previewImport();
  } else {
    renderImportPreview();
  }
}

function renderEntries() {
  const query = els.search.value.trim().toLowerCase();
  const entries = state.entries.filter((entry) =>
    `${entry.issuer} ${entry.account}`.toLowerCase().includes(query),
  );
  if (!entries.length) {
    els.entries.innerHTML = `<div class="empty">${t("noMatchingEntries")}</div>`;
    return;
  }
  els.entries.innerHTML = entries
    .map((entry) => {
      const code = state.codes.get(entry.id) || "";
      return `
        <article class="entry">
          <div class="entry-top">
            <div class="entry-title">
              <strong>${escapeHtml(entry.issuer || "-")}</strong>
              <span class="muted">${escapeHtml(entry.account || "-")}</span>
            </div>
            <span class="badge">${escapeHtml(entry.type || "TOTP")}</span>
          </div>
          <div class="entry-actions">
            <button type="button" data-action="copy-code" data-id="${escapeHtml(entry.id)}">${t("copyCode")}</button>
            ${code ? `<span class="code">${escapeHtml(code)}</span>` : ""}
          </div>
        </article>
      `;
    })
    .join("");
}

function renderImportPreview() {
  if (!state.importItems.length) {
    els.importPreview.innerHTML = `<div class="empty">${t("noPreviewItems")}</div>`;
    return;
  }
  els.importPreview.innerHTML = state.importItems
    .map((item) => `
      <div class="import-row ${escapeHtml(item.status)}">
        <div>
          <strong>${escapeHtml(item.entry.issuer || "-")}</strong>
          <div class="muted">${escapeHtml(item.entry.account || "-")}</div>
        </div>
        <span class="badge">${escapeHtml(item.reason || t(item.status))}</span>
      </div>
    `)
    .join("");
}

async function loadSettings() {
  const data = await chrome.storage.local.get(["serviceUrl", "pat"]);
  state.serviceUrl = data.serviceUrl || "";
  state.pat = data.pat || "";
  els.serviceUrl.value = state.serviceUrl;
  els.pat.value = state.pat;
}

async function saveSettings() {
  state.serviceUrl = normalizeServiceUrl(els.serviceUrl.value);
  state.pat = els.pat.value.trim();
  if (!state.pat) throw new Error(t("patRequired"));
  const me = await api("/api/me");
  if (me.role !== "user" || me.authType !== "pat") throw new Error(t("patOnly"));
  await chrome.storage.local.set({ serviceUrl: state.serviceUrl, pat: state.pat });
  setMessage(t("settingsSaved"), false);
}

async function refreshEntries() {
  const payload = await api("/api/entries");
  state.entries = (payload.items || []).map((entry) => ({
    id: entry.id,
    issuer: entry.issuer,
    account: entry.account,
    type: entry.type,
    algorithm: entry.algorithm,
    digits: entry.digits,
    period: entry.period,
    counter: entry.counter,
    groupId: entry.groupId,
  }));
  state.codes = new Map();
  renderEntries();
}

async function copyCode(entryId) {
  const payload = await api(`/api/entries/${encodeURIComponent(entryId)}/code`);
  await navigator.clipboard.writeText(payload.code);
  state.codes.set(entryId, payload.code);
  setMessage(t("copiedCode"), false);
  renderEntries();
}

async function scanPageForOtpAuthUris() {
  const values = new Set();
  const pattern = /otpauth:\/\/[^\s"'<>]+/g;
  const addMatches = (value) => {
    for (const match of String(value || "").matchAll(pattern)) {
      values.add(decodeURIComponent(match[0]));
    }
  };
  for (const element of document.querySelectorAll("a[href], img[src], img[alt], img[title], [data-otpauth]")) {
    addMatches(element.getAttribute("href"));
    addMatches(element.getAttribute("src"));
    addMatches(element.getAttribute("alt"));
    addMatches(element.getAttribute("title"));
    addMatches(element.getAttribute("data-otpauth"));
  }
  addMatches(document.body?.innerText || "");
  if ("BarcodeDetector" in window) {
    const detector = new BarcodeDetector({ formats: ["qr_code"] });
    for (const image of document.querySelectorAll("img, canvas")) {
      try {
        const codes = await detector.detect(image);
        for (const code of codes) {
          addMatches(code.rawValue);
        }
      } catch {
        // Cross-origin or unsupported elements cannot be scanned safely.
      }
    }
  }
  return [...values];
}

async function scanCurrentPage() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab?.id) throw new Error(t("noPageAccess"));
  const results = await chrome.scripting.executeScript({
    target: { tabId: tab.id },
    func: scanPageForOtpAuthUris,
  });
  const uris = results.flatMap((item) => item.result || []);
  if (!uris.length) {
    setMessage(t("noOtpAuthOnPage"));
    return;
  }
  els.importText.value = uris.join("\n");
  previewImport();
  setMessage(t("foundOtpAuth", { count: uris.length }), false);
}

function previewImport() {
  state.importItems = previewImportItems(parseImportText(els.importText.value));
  renderImportPreview();
}

async function importValidItems() {
  const items = state.importItems.filter((item) => item.status === "valid");
  if (!items.length) throw new Error(t("noValidImportItems"));
  const entries = [];
  for (const item of items) {
    entries.push({
      ...item.entry,
      encryptedSecret: await encryptSecret(item.entry.secret),
      secret: undefined,
    });
  }
  await api("/api/import", { method: "POST", body: JSON.stringify({ entries }) });
  els.importText.value = "";
  state.importItems = [];
  renderImportPreview();
  await refreshEntries();
  setMessage(t("importedCount", { count: entries.length }), false);
}

async function run(action) {
  try {
    await action();
  } catch (error) {
    setMessage(error.message || t("actionFailed"));
  }
}

els.saveSettings.addEventListener("click", () => run(saveSettings));
els.refreshEntries.addEventListener("click", () => run(refreshEntries));
els.search.addEventListener("input", renderEntries);
els.scanPage.addEventListener("click", () => run(scanCurrentPage));
els.previewImport.addEventListener("click", () => run(async () => previewImport()));
els.importValid.addEventListener("click", () => run(importValidItems));
document.querySelectorAll("[data-locale]").forEach((node) => {
  node.addEventListener("click", () => changeLocale(node.dataset.locale));
});
els.entries.addEventListener("click", (event) => {
  const button = event.target.closest("button[data-action='copy-code']");
  if (button) run(() => copyCode(button.dataset.id));
});

loadSettings()
  .then(() => {
    renderStaticText();
    renderEntries();
    renderImportPreview();
    return state.serviceUrl && state.pat ? refreshEntries() : undefined;
  })
  .catch((error) => setMessage(error.message || t("initFailed")));
