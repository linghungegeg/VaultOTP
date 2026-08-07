(() => {
  const textEncoder = new TextEncoder();
  const textDecoder = new TextDecoder();
  const app = document.getElementById("app");
  const i18n = window.VaultOtpI18n;
  let currentLocale = i18n.getInitialLocale();
  const t = (key, params = {}) => i18n.t(key, currentLocale, params);
  const uid = () => `${Date.now().toString(36)}${crypto.getRandomValues(new Uint32Array(1))[0].toString(36)}`;

  const state = {
    route: "app",
    locale: currentLocale,
    authMode: "login",
    hasAdmin: null,
    secretPublicKey: null,
    userToken: "",
    adminToken: "",
    user: null,
    admin: null,
    groups: [],
    entries: [],
    pats: [],
    patToken: "",
    adminUsers: [],
    adminDetail: null,
    adminSelectedUserEmail: "",
    adminAudit: [],
    adminReveals: {},
    editingId: null,
    groupFilter: "all",
    search: "",
    message: "",
    adminMessage: "",
    otpCodes: new Map(),
    copiedId: "",
    renderScheduled: false,
    importOpen: false,
    importText: "",
    importItems: [],
    importMessage: "",
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

  function languageSwitch() {
    return `
      <div class="language-switch" aria-label="${t("language")}">
        <button type="button" class="${state.locale === "zh-CN" ? "active" : ""}" data-locale="zh-CN">${t("localeZh")}</button>
        <button type="button" class="${state.locale === "en" ? "active" : ""}" data-locale="en">${t("localeEn")}</button>
      </div>
    `;
  }

  function changeLocale(locale) {
    currentLocale = i18n.setLocale(locale);
    state.locale = currentLocale;
    render();
  }

  function normalizeEmail(value) {
    return String(value || "").trim().toLowerCase();
  }

  async function api(path, options = {}, token = state.userToken) {
    const headers = { ...(options.headers || {}) };
    if (options.body && !headers["Content-Type"]) {
      headers["Content-Type"] = "application/json";
    }
    if (token) {
      headers.Authorization = `Bearer ${token}`;
    }
    const response = await fetch(path, { ...options, headers });
    const text = await response.text();
    const payload = text ? JSON.parse(text) : {};
    if (!response.ok) {
      const error = new Error(payload.error || "request_failed");
      error.status = response.status;
      error.payload = payload;
      throw error;
    }
    return payload;
  }

  async function bootstrap() {
    const data = await api("/api/bootstrap", {}, "");
    state.hasAdmin = Boolean(data.hasAdmin);
    state.secretPublicKey = data.secretPublicKey;
  }

  async function encryptSecret(secret) {
    if (!state.secretPublicKey) {
      await bootstrap();
    }
    const publicKey = await crypto.subtle.importKey(
      "jwk",
      state.secretPublicKey,
      { name: "RSA-OAEP", hash: "SHA-256" },
      false,
      ["encrypt"],
    );
    const encrypted = await crypto.subtle.encrypt({ name: "RSA-OAEP" }, publicKey, textEncoder.encode(normalizeSecret(secret)));
    return toBase64(encrypted);
  }

  function toBase64(bytes) {
    return btoa(String.fromCharCode(...new Uint8Array(bytes)));
  }

  function fromBase64(value) {
    return Uint8Array.from(atob(value), (char) => char.charCodeAt(0));
  }

  function syncRouteFromLocation() {
    const hashRoute = window.location.hash.replace(/^#\/?/, "");
    state.route = window.location.pathname.startsWith("/admin") || hashRoute === "admin" ? "admin" : "app";
    document.title = state.route === "admin" ? t("adminTitle") : t("authTitle");
  }

  function goToRoute(route) {
    if (route === "admin") {
      clearUserSession();
    } else {
      clearAdminSession();
    }
    if (window.location.protocol === "file:") {
      window.location.hash = route;
    } else {
      const target = route === "admin" ? "/admin" : "/app";
      if (window.location.pathname !== target) {
        history.pushState({}, "", target);
      }
    }
    syncRouteFromLocation();
    render();
  }

  function clearUserSession() {
    state.userToken = "";
    state.user = null;
    state.groups = [];
    state.entries = [];
    state.pats = [];
    state.patToken = "";
    state.editingId = null;
    state.message = "";
    state.otpCodes = new Map();
  }

  function clearAdminSession() {
    state.adminToken = "";
    state.admin = null;
    state.adminUsers = [];
    state.adminDetail = null;
    state.adminSelectedUserEmail = "";
    state.adminAudit = [];
    state.adminReveals = {};
    state.adminMessage = "";
  }

  function scheduleRender() {
    if (state.renderScheduled) return;
    state.renderScheduled = true;
    requestAnimationFrame(() => {
      state.renderScheduled = false;
      render();
    });
  }

  function normalizeSecret(secret) {
    return String(secret || "").replace(/\s+/g, "").replace(/=+$/g, "").toUpperCase();
  }

  function base32ToBytes(secret) {
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    const normalized = normalizeSecret(secret);
    let bits = "";
    for (const char of normalized) {
      const value = alphabet.indexOf(char);
      if (value === -1) {
        throw new Error("invalid base32");
      }
      bits += value.toString(2).padStart(5, "0");
    }
    const bytes = [];
    for (let i = 0; i + 8 <= bits.length; i += 8) {
      bytes.push(parseInt(bits.slice(i, i + 8), 2));
    }
    return new Uint8Array(bytes);
  }

  function bytesToBase32(bytes) {
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let bits = "";
    for (const byte of bytes) {
      bits += byte.toString(2).padStart(8, "0");
    }
    let output = "";
    for (let i = 0; i < bits.length; i += 5) {
      const chunk = bits.slice(i, i + 5);
      output += alphabet[parseInt(chunk.padEnd(5, "0"), 2)];
    }
    return output;
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

  function normalizeImportedEntry(raw, source) {
    const type = normalizeOtpType(raw.type || raw.otp_type || raw.tokenType);
    return {
      id: uid(),
      issuer: String(raw.issuer || raw.service || raw.name || "").trim(),
      account: String(raw.account || raw.accountName || raw.username || "").trim(),
      secret: normalizeSecret(raw.secret),
      type,
      algorithm: normalizeAlgorithm(raw.algorithm || raw.algo),
      digits: Number(raw.digits || 6),
      period: Number(raw.period || 30),
      counter: Number(raw.counter || 0),
      groupId: "default",
      note: String(raw.note || "").trim(),
      icon: String(raw.icon || "").trim().slice(0, 8),
      source,
    };
  }

  function entryDuplicateKey(entry) {
    const period = entry.type === "TOTP" ? Number(entry.period || 30) : "";
    return [entry.type, entry.issuer, entry.account, entry.algorithm, entry.digits, period]
      .map((part) => String(part || "").toLowerCase())
      .join("|");
  }

  function parseOtpAuthUri(uri, source = "otpauth") {
    const url = new URL(uri.trim());
    if (url.protocol !== "otpauth:") throw new Error(t("reasonUnsupported"));
    const type = normalizeOtpType(url.hostname);
    const label = decodeURIComponent(url.pathname.replace(/^\//, ""));
    const labelParts = label.split(":");
    const issuerParam = url.searchParams.get("issuer") || "";
    const issuer = issuerParam || (labelParts.length > 1 ? labelParts[0] : "");
    const account = labelParts.length > 1 ? labelParts.slice(1).join(":") : label;
    return normalizeImportedEntry(
      {
        type,
        issuer,
        account,
        secret: url.searchParams.get("secret") || "",
        algorithm: url.searchParams.get("algorithm") || "SHA1",
        digits: url.searchParams.get("digits") || 6,
        period: url.searchParams.get("period") || 30,
        counter: url.searchParams.get("counter") || 0,
      },
      source,
    );
  }

  function readVarint(bytes, start) {
    let result = 0;
    let shift = 0;
    let index = start;
    while (index < bytes.length) {
      const byte = bytes[index];
      result += (byte & 0x7f) * 2 ** shift;
      index += 1;
      if ((byte & 0x80) === 0) return { value: result, next: index };
      shift += 7;
    }
    throw new Error("invalid varint");
  }

  function readProtoFields(bytes) {
    const fields = [];
    let index = 0;
    while (index < bytes.length) {
      const tag = readVarint(bytes, index);
      index = tag.next;
      const field = Math.floor(tag.value / 8);
      const wireType = tag.value % 8;
      if (wireType === 0) {
        const value = readVarint(bytes, index);
        fields.push({ field, wireType, value: value.value });
        index = value.next;
      } else if (wireType === 2) {
        const length = readVarint(bytes, index);
        index = length.next;
        fields.push({ field, wireType, value: bytes.slice(index, index + length.value) });
        index += length.value;
      } else {
        throw new Error("unsupported protobuf wire type");
      }
    }
    return fields;
  }

  function parseGoogleOtpParameter(bytes) {
    const parsed = {};
    for (const item of readProtoFields(bytes)) {
      if (item.field === 1) parsed.secret = bytesToBase32(item.value);
      if (item.field === 2) parsed.name = textDecoder.decode(item.value);
      if (item.field === 3) parsed.issuer = textDecoder.decode(item.value);
      if (item.field === 4) parsed.algorithm = { 1: "SHA-1", 2: "SHA-256", 3: "SHA-512" }[item.value] || "SHA-1";
      if (item.field === 5) parsed.digits = { 1: 6, 2: 8 }[item.value] || 6;
      if (item.field === 6) parsed.type = { 1: "HOTP", 2: "TOTP" }[item.value] || "TOTP";
      if (item.field === 7) parsed.counter = item.value;
      if (item.field === 8) parsed.period = item.value;
    }
    const issuerPrefix = parsed.issuer ? `${parsed.issuer}:` : "";
    const account = parsed.name && parsed.name.startsWith(issuerPrefix) ? parsed.name.slice(issuerPrefix.length) : parsed.name;
    return normalizeImportedEntry({ ...parsed, account }, "Google Authenticator");
  }

  function parseGoogleMigrationUri(uri) {
    const url = new URL(uri.trim());
    if (url.protocol !== "otpauth-migration:") throw new Error(t("reasonUnsupported"));
    const data = url.searchParams.get("data");
    if (!data) throw new Error(t("reasonUnsupported"));
    const payload = fromBase64(data.replaceAll(" ", "+"));
    return readProtoFields(payload)
      .filter((item) => item.field === 1 && item.wireType === 2)
      .map((item) => parseGoogleOtpParameter(item.value));
  }

  function parseAegisJson(json) {
    if (!json?.db?.entries || !Array.isArray(json.db.entries)) return [];
    return json.db.entries.map((item) =>
      normalizeImportedEntry(
        {
          issuer: item.issuer,
          account: item.name || item.issuer,
          secret: item.info?.secret,
          type: item.type,
          algorithm: item.info?.algo,
          digits: item.info?.digits,
          period: item.info?.period,
          counter: item.info?.counter,
          note: item.note,
        },
        "Aegis",
      ),
    );
  }

  function parseTwoFasJson(json) {
    if (!Array.isArray(json?.services)) return [];
    return json.services.map((item) =>
      normalizeImportedEntry(
        {
          issuer: item.name,
          account: item.otp?.account || item.name,
          secret: item.secret,
          type: item.otp?.tokenType,
          algorithm: item.otp?.algorithm,
          digits: item.otp?.digits,
          period: item.otp?.period,
          counter: item.otp?.counter,
          icon: item.icon?.label?.text,
        },
        "2FAS",
      ),
    );
  }

  function parseTwoFAuthJson(json) {
    if (!String(json?.app || "").startsWith("2fauth_") || !json?.schema || !Array.isArray(json?.data)) return [];
    return json.data.flatMap((item) => {
      if (item.legacy_uri) {
        try {
          return [parseOtpAuthUri(item.legacy_uri, "2FAuth JSON")];
        } catch {
          return [];
        }
      }
      return [normalizeImportedEntry(item, "2FAuth JSON")];
    });
  }

  function parseGenericJson(json) {
    const values = Array.isArray(json) ? json : [];
    return values
      .filter((item) => item && typeof item === "object")
      .flatMap((item) => {
        if (item.otpauth || item.uri || item.legacy_uri) {
          try {
            return [parseOtpAuthUri(item.otpauth || item.uri || item.legacy_uri, "JSON")];
          } catch {
            return [];
          }
        }
        return item.secret ? [normalizeImportedEntry(item, "JSON")] : [];
      });
  }

  function parseJsonImport(text) {
    const json = JSON.parse(text);
    return [...parseAegisJson(json), ...parseTwoFasJson(json), ...parseTwoFAuthJson(json), ...parseGenericJson(json)];
  }

  function parseImportPayload(text) {
    const trimmed = text.trim();
    if (!trimmed) return [];
    const results = [];
    if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
      results.push(...parseJsonImport(trimmed));
    }
    for (const line of trimmed.split(/\r?\n/).map((item) => item.trim()).filter(Boolean)) {
      if (line.startsWith("otpauth://")) results.push(parseOtpAuthUri(line));
      if (line.startsWith("otpauth-migration://")) results.push(...parseGoogleMigrationUri(line));
    }
    return results;
  }

  function previewImportItems(entries) {
    const existingKeys = new Set(state.entries.map(entryDuplicateKey));
    const previewKeys = new Set();
    return entries.map((entry) => {
      let status = "valid";
      let reason = "";
      try {
        base32ToBytes(entry.secret);
      } catch {
        status = "invalid";
        reason = t("reasonInvalidSecret");
      }
      if (!entry.issuer || !entry.account || !entry.secret) {
        status = "invalid";
        reason = t("reasonMissingFields");
      }
      const key = entryDuplicateKey(entry);
      if (status === "valid" && (existingKeys.has(key) || previewKeys.has(key))) {
        status = "duplicate";
        reason = t("reasonDuplicate");
      }
      previewKeys.add(key);
      return { id: uid(), entry, status, reason, selected: status === "valid" };
    });
  }

  async function loadUserData() {
    const [groups, entries, pats] = await Promise.all([
      api("/api/groups"),
      api("/api/entries"),
      api("/api/pats"),
    ]);
    state.groups = groups.items;
    state.entries = entries.items;
    state.pats = pats.items;
    await refreshOtpCodes();
  }

  async function loadAdminData() {
    const [users, audit] = await Promise.all([
      api("/api/admin/users", {}, state.adminToken),
      api("/api/admin/audit", {}, state.adminToken),
    ]);
    state.adminUsers = users.items;
    state.adminAudit = audit.items;
    const selected = state.adminUsers.find((item) => item.email === state.adminSelectedUserEmail) || state.adminUsers[0] || null;
    if (selected) {
      await loadAdminUser(selected.email, false);
    } else {
      state.adminSelectedUserEmail = "";
      state.adminDetail = null;
    }
  }

  async function loadAdminUser(email, shouldRender = true) {
    state.adminSelectedUserEmail = email;
    state.adminReveals = {};
    state.adminDetail = await api(`/api/admin/users/${encodeURIComponent(email)}`, {}, state.adminToken);
    if (shouldRender) render();
  }

  async function refreshOtpCodes() {
    if (!state.userToken || !state.entries.length) {
      state.otpCodes = new Map();
      renderOtpCodes();
      return;
    }
    const codes = new Map();
    for (const entry of state.entries) {
      try {
        const payload = await api(`/api/entries/${entry.id}/code`);
        codes.set(entry.id, payload.code);
      } catch {
        codes.set(entry.id, "------");
      }
    }
    state.otpCodes = codes;
    renderOtpCodes();
  }

  function renderOtpCodes() {
    document.querySelectorAll("[data-otp-id]").forEach((node) => {
      const id = node.getAttribute("data-otp-id");
      node.textContent = state.otpCodes.get(id) || "------";
    });
    document.querySelectorAll("[data-period-id]").forEach((node) => {
      const id = node.getAttribute("data-period-id");
      const entry = state.entries.find((item) => item.id === id);
      node.textContent = entry ? periodRemaining(entry) : "";
    });
  }

  function findGroupName(groupId) {
    return (state.groups.find((group) => group.id === groupId) || {}).name || t("defaultGroup");
  }

  function filteredEntries() {
    const query = state.search.trim().toLowerCase();
    return state.entries.filter((entry) => {
      const groupOk = state.groupFilter === "all" || entry.groupId === state.groupFilter;
      const text = `${entry.issuer} ${entry.account} ${entry.note} ${findGroupName(entry.groupId)}`.toLowerCase();
      return groupOk && (!query || text.includes(query));
    });
  }

  function selectedEntry() {
    return state.entries.find((entry) => entry.id === state.editingId) || null;
  }

  function countGroup(groupId) {
    return state.entries.filter((entry) => entry.groupId === groupId).length;
  }

  function periodRemaining(entry) {
    if (entry.type === "HOTP") return `#${entry.counter || 0}`;
    const period = Number(entry.period || 30);
    return `${period - (Math.floor(Date.now() / 1000) % period)}s`;
  }

  function render() {
    syncRouteFromLocation();
    if (state.route === "admin") {
      if (state.userToken) clearUserSession();
      if (!state.adminToken) {
        renderAdminAuth();
        return;
      }
      renderAdminApp();
      return;
    }
    if (state.adminToken) clearAdminSession();
    if (!state.userToken) {
      renderAuth();
      return;
    }
    renderUserApp();
  }

  function renderAuth() {
    app.className = "screen auth-screen";
    app.innerHTML = `
      <section class="auth-panel">
        <div class="brand-row">
          <div>
            <div class="brand">${t("authTitle")}</div>
            <div class="muted">${t("authSubtitle")}</div>
          </div>
          ${languageSwitch()}
        </div>
        <div class="tabs">
          <button class="tab ${state.authMode === "login" ? "active" : ""}" data-auth-mode="login">${t("login")}</button>
          <button class="tab ${state.authMode === "register" ? "active" : ""}" data-auth-mode="register">${t("register")}</button>
        </div>
        <form id="auth-form">
          <div class="field">
            <label for="email">${t("email")}</label>
            <input id="email" name="email" type="email" autocomplete="username" required />
          </div>
          <div class="field">
            <label for="password">${t("password")}</label>
            <input id="password" name="password" type="password" autocomplete="${state.authMode === "login" ? "current-password" : "new-password"}" required />
          </div>
          ${
            state.authMode === "register"
              ? `<div class="field">
                  <label for="confirmPassword">${t("confirmPassword")}</label>
                  <input id="confirmPassword" name="confirmPassword" type="password" autocomplete="new-password" required />
                </div>`
              : ""
          }
          <div class="error">${escapeHtml(state.message)}</div>
          <button class="primary" type="submit">${state.authMode === "login" ? t("loginAction") : t("createAccount")}</button>
        </form>
        <div class="auth-switch">
          <button class="ghost" type="button" data-route="admin">${t("adminEntry")}</button>
        </div>
      </section>
    `;
  }

  function renderAdminAuth() {
    app.className = "screen auth-screen";
    const setupMode = state.hasAdmin === false;
    app.innerHTML = `
      <section class="auth-panel admin-auth">
        <div class="brand-row">
          <div>
            <div class="brand">${t("adminTitle")}</div>
            <div class="muted">${setupMode ? t("adminCreateHint") : t("adminLoginHint")}</div>
          </div>
          <div class="inline-actions">
            ${languageSwitch()}
            <button class="ghost" type="button" data-route="app">${t("adminBackToUser")}</button>
          </div>
        </div>
        <div class="tabs">
          <button class="tab active" disabled>${setupMode ? t("adminSetupTitle") : t("adminLoginTitle")}</button>
        </div>
        <form id="admin-auth-form">
          <div class="field">
            <label for="adminEmail">${t("email")}</label>
            <input id="adminEmail" name="email" type="email" autocomplete="username" required />
          </div>
          <div class="field">
            <label for="adminPassword">${t("password")}</label>
            <input id="adminPassword" name="password" type="password" autocomplete="${setupMode ? "new-password" : "current-password"}" required />
          </div>
          ${
            setupMode
              ? `<div class="field">
                  <label for="adminConfirmPassword">${t("confirmPassword")}</label>
                  <input id="adminConfirmPassword" name="confirmPassword" type="password" autocomplete="new-password" required />
                </div>`
              : ""
          }
          <div class="error">${escapeHtml(state.adminMessage)}</div>
          <button class="primary" type="submit">${setupMode ? t("setupAdmin") : t("adminLogin")}</button>
        </form>
      </section>
    `;
  }

  function renderUserApp() {
    app.className = "screen";
    const entries = filteredEntries();
    app.innerHTML = `
      <div class="layout">
        <aside class="sidebar">
          <div class="brand-row">
            <div>
              <div class="brand">${t("authTitle")}</div>
              <div class="muted">${t("serverBacked")}</div>
            </div>
            ${languageSwitch()}
          </div>
          <div class="field">
            <label for="search">${t("search")}</label>
            <input id="search" value="${escapeHtml(state.search)}" />
          </div>
          <div class="inline-actions sidebar-actions">
            <button class="primary" data-action="new-entry">${t("addEntry")}</button>
            <button class="ghost" data-action="open-import">${t("importEntries")}</button>
          </div>
          <div class="group-list">
            ${groupButton("all", t("allGroups"), state.entries.length)}
            ${state.groups.map((group) => groupButton(group.id, group.name, countGroup(group.id))).join("")}
          </div>
          ${patPanel()}
        </aside>
        <main class="content">
          <header class="topbar">
            <div>
              <strong>${escapeHtml(state.user?.email || "")}</strong>
              <span class="muted">${t("currentUser")}</span>
            </div>
            <div class="inline-actions">
              <button class="ghost" data-action="logout">${t("logout")}</button>
              <button class="danger" data-action="delete-account">${t("deleteAccount")}</button>
            </div>
          </header>
          <section class="entry-list">
            ${entries.length ? entries.map(entryView).join("") : `<div class="empty">${t("noEntries")}</div>`}
          </section>
        </main>
        <aside class="inspector">
          ${entryForm()}
        </aside>
      </div>
      ${state.importOpen ? importPanel() : ""}
    `;
  }

  function patPanel() {
    return `
      <div class="sidebar-section">
        <div class="section-title">${t("pats")}</div>
        <form id="pat-form" class="inline-actions sidebar-actions">
          <input name="name" placeholder="${t("patName")}" />
          <button class="ghost" type="submit">${t("createPat")}</button>
        </form>
        ${state.patToken ? `<div class="admin-value">${t("oneTimeToken")}: ${escapeHtml(state.patToken)}</div>` : ""}
        <div class="admin-audit-list">
          ${
            state.pats.length
              ? state.pats
                  .map(
                    (pat) => `
                      <div class="audit-row">
                        <span>${escapeHtml(pat.name)}</span>
                        <span>${escapeHtml(pat.lastUsedAt || pat.createdAt || "-")}</span>
                        <button class="ghost" data-action="rename-pat" data-id="${pat.id}">${t("renamePat")}</button>
                        <button class="danger" data-action="delete-pat" data-id="${pat.id}">${t("deletePat")}</button>
                      </div>
                    `,
                  )
                  .join("")
              : `<div class="empty">${t("pats")}</div>`
          }
        </div>
      </div>
    `;
  }

  function renderAdminApp() {
    app.className = "screen admin-screen";
    const selected = state.adminUsers.find((item) => item.email === state.adminSelectedUserEmail) || state.adminUsers[0] || null;
    app.innerHTML = `
      <div class="admin-layout">
        <aside class="admin-sidebar">
          <div class="brand-row">
            <div>
              <div class="brand">${t("adminTitle")}</div>
              <div class="muted">${escapeHtml(state.admin?.email || "")}</div>
            </div>
            <div class="inline-actions">
              ${languageSwitch()}
              <button class="ghost" type="button" data-route="app">${t("adminBackToUser")}</button>
            </div>
          </div>
          <div class="sidebar-section">
            <div class="section-title">${t("adminUsersTitle")}</div>
            <div class="admin-user-list">
              ${
                state.adminUsers.length
                  ? state.adminUsers
                      .map(
                        (user) => `
                          <button class="admin-user-item ${state.adminSelectedUserEmail === user.email ? "active" : ""}" data-admin-user="${escapeHtml(user.email)}">
                            <span>${escapeHtml(user.email)}</span>
                            <span class="badge ${user.status === "disabled" ? "disabled-badge" : ""}">${escapeHtml(t(user.status || "active"))}</span>
                          </button>
                        `,
                      )
                      .join("")
                  : `<div class="empty">${t("noUsers")}</div>`
              }
            </div>
          </div>
          <div class="sidebar-section">
            <div class="section-title">${t("adminAuditTitle")}</div>
            <div class="admin-audit-list">
              ${state.adminAudit.length ? state.adminAudit.slice(0, 12).map(adminAuditRow).join("") : `<div class="empty">${t("adminAuditTitle")}</div>`}
            </div>
          </div>
        </aside>
        <main class="admin-main">
          <header class="topbar admin-topbar">
            <div>
              <strong>${t("adminUsersTitle")}</strong>
              <span class="muted">${selected ? escapeHtml(selected.email) : t("adminNoSelection")}</span>
            </div>
            <div class="inline-actions">
              <button class="ghost" type="button" data-action="admin-logout">${t("adminLogout")}</button>
            </div>
          </header>
          <section class="admin-content">
            ${selected && state.adminDetail ? adminDetailPanel() : `<div class="empty">${t("adminNoSelection")}</div>`}
          </section>
        </main>
      </div>
    `;
  }

  function groupButton(id, name, count) {
    return `
      <button class="group-item ${state.groupFilter === id ? "active" : ""}" data-group="${escapeHtml(id)}">
        <span>${escapeHtml(name)}</span>
        <span>${count}</span>
      </button>
    `;
  }

  function entryView(entry) {
    const code = state.otpCodes.get(entry.id) || "------";
    return `
      <article class="entry ${state.editingId === entry.id ? "selected" : ""}" data-entry-id="${entry.id}">
        <div class="entry-main">
          <div class="entry-title">
            <strong>${escapeHtml(entry.icon || "")} ${escapeHtml(entry.issuer)}</strong>
            <span class="muted">${escapeHtml(entry.account)}</span>
          </div>
          <div class="entry-actions">
            <span class="otp" data-otp-id="${entry.id}">${escapeHtml(code)}</span>
            <button class="icon-button" data-action="copy" data-id="${entry.id}">${state.copiedId === entry.id ? t("copied") : t("copy")}</button>
            ${entry.type === "HOTP" ? `<button class="icon-button" data-action="next-hotp" data-id="${entry.id}">${t("next")}</button>` : ""}
          </div>
        </div>
        <div class="entry-meta">
          <span class="badge">${escapeHtml(entry.type)}</span>
          <span class="badge">${escapeHtml(findGroupName(entry.groupId))}</span>
          <span class="badge" data-period-id="${entry.id}">${escapeHtml(periodRemaining(entry))}</span>
        </div>
      </article>
    `;
  }

  function entryForm() {
    const entry = selectedEntry();
    const isEditing = Boolean(entry);
    const data = entry || {
      issuer: "",
      account: "",
      type: "TOTP",
      algorithm: "SHA-1",
      digits: 6,
      period: 30,
      counter: 0,
      groupId: "default",
      note: "",
      icon: "",
    };
    return `
      <div class="panel-title">
        <h2>${isEditing ? t("editEntry") : t("addEntry")}</h2>
        ${isEditing ? `<button class="danger" data-action="delete-entry" data-id="${entry.id}">${t("delete")}</button>` : ""}
      </div>
      <form id="entry-form" class="form-grid">
        <input type="hidden" name="id" value="${escapeHtml(entry ? entry.id : "")}" />
        <div class="field">
          <label>${t("issuer")}</label>
          <input name="issuer" required value="${escapeHtml(data.issuer)}" />
        </div>
        <div class="field">
          <label>${t("account")}</label>
          <input name="account" required value="${escapeHtml(data.account)}" />
        </div>
        <div class="field">
          <label>${t("secret")}</label>
          <input name="secret" ${isEditing ? "" : "required"} placeholder="${isEditing ? t("hiddenByDefault") : ""}" />
        </div>
        <div class="form-row">
          <div class="field">
            <label>${t("type")}</label>
            <select name="type">
              <option value="TOTP" ${data.type === "TOTP" ? "selected" : ""}>TOTP</option>
              <option value="HOTP" ${data.type === "HOTP" ? "selected" : ""}>HOTP</option>
            </select>
          </div>
          <div class="field">
            <label>${t("algorithm")}</label>
            <select name="algorithm">
              ${["SHA-1", "SHA-256", "SHA-512"].map((algorithm) => `<option value="${algorithm}" ${data.algorithm === algorithm ? "selected" : ""}>${algorithm}</option>`).join("")}
            </select>
          </div>
        </div>
        <div class="form-row">
          <div class="field">
            <label>${t("digits")}</label>
            <select name="digits">
              <option value="6" ${Number(data.digits) === 6 ? "selected" : ""}>6</option>
              <option value="8" ${Number(data.digits) === 8 ? "selected" : ""}>8</option>
            </select>
          </div>
          <div class="field">
            <label>${t("period")}</label>
            <input name="period" type="number" min="10" value="${escapeHtml(data.period)}" />
          </div>
          <div class="field">
            <label>${t("counter")}</label>
            <input name="counter" type="number" min="0" value="${escapeHtml(data.counter)}" />
          </div>
        </div>
        <div class="form-row">
          <div class="field">
            <label>${t("group")}</label>
            <select name="groupId">
              ${state.groups.map((group) => `<option value="${group.id}" ${data.groupId === group.id ? "selected" : ""}>${escapeHtml(group.name)}</option>`).join("")}
            </select>
          </div>
          <div class="field">
            <label>${t("newGroup")}</label>
            <input name="newGroup" />
          </div>
        </div>
        <div class="field">
          <label>${t("icon")}</label>
          <input name="icon" maxlength="8" value="${escapeHtml(data.icon)}" />
        </div>
        <div class="field">
          <label>${t("note")}</label>
          <textarea name="note">${escapeHtml(data.note)}</textarea>
        </div>
        <div class="error">${escapeHtml(state.message)}</div>
        <div class="inline-actions">
          <button class="primary" type="submit">${t("save")}</button>
          <button class="ghost" type="button" data-action="clear-edit">${t("cancel")}</button>
        </div>
      </form>
    `;
  }

  function importPanel() {
    return `
      <section class="modal-backdrop">
        <div class="modal">
          <div class="panel-title">
            <h2>${t("importTitle")}</h2>
            <button class="ghost" data-action="close-import">${t("close")}</button>
          </div>
          <div class="field">
            <label>${t("chooseFile")}</label>
            <input type="file" data-action="import-file" accept=".txt,.json,.2fas,.aegis" />
          </div>
          <div class="field">
            <label>${t("importSource")}</label>
            <textarea id="import-text" class="import-text" placeholder="${t("importHint")}">${escapeHtml(state.importText)}</textarea>
          </div>
          <div class="inline-actions">
            <button class="primary" data-action="parse-import">${t("parseImport")}</button>
            <button class="ghost" data-action="import-all">${t("importAll")}</button>
            <button class="ghost" data-action="import-selected">${t("importSelected")}</button>
          </div>
          <div class="error">${escapeHtml(state.importMessage)}</div>
          ${importPreview()}
        </div>
      </section>
    `;
  }

  function importPreview() {
    if (!state.importItems.length) return `<div class="empty">${t("importEmpty")}</div>`;
    return `<div class="import-preview" aria-label="${t("preview")}">${state.importItems.map(importPreviewRow).join("")}</div>`;
  }

  function importPreviewRow(item) {
    const entry = item.entry;
    return `
      <label class="import-row ${item.status}">
        <input type="checkbox" data-import-id="${item.id}" ${item.selected ? "checked" : ""} ${item.status !== "valid" ? "disabled" : ""} />
        <span>
          <strong>${escapeHtml(entry.issuer || "-")}</strong>
          <span class="muted">${escapeHtml(entry.account || "-")}</span>
        </span>
        <span class="badge">${escapeHtml(entry.type)}</span>
        <span class="badge">${escapeHtml(entry.source)}</span>
        <span class="badge">${t(item.status)}</span>
        <span class="muted">${escapeHtml(item.reason || "")}</span>
      </label>
    `;
  }

  function adminAuditRow(log) {
    return `
      <div class="audit-row">
        <span>${escapeHtml(log.createdAt || log.created_at || "")}</span>
        <span>${escapeHtml(log.action)}</span>
        <span>${escapeHtml(log.targetUserId || log.target_user_id || "-")}</span>
        <span>${escapeHtml(log.targetEntryId || log.target_entry_id || "-")}</span>
      </div>
    `;
  }

  function adminDetailPanel() {
    const detail = state.adminDetail;
    const user = detail.user;
    const entries = detail.entries || [];
    return `
      <section class="admin-detail">
        <div class="admin-summary">
          <div>
            <div class="section-title">${t("savedItems")}</div>
            <div class="muted">${escapeHtml(user.email)}</div>
          </div>
          <div class="inline-actions">
            <button class="danger" type="button" data-action="admin-disable-user" data-id="${escapeHtml(user.email)}">${t("adminDisable")}</button>
            <button class="danger" type="button" data-action="admin-delete-user" data-id="${escapeHtml(user.email)}">${t("adminDelete")}</button>
          </div>
        </div>
        <div class="detail-grid">
          <div class="detail-item"><span class="muted">${t("accountStatus")}</span><strong>${escapeHtml(t(user.status || "active"))}</strong></div>
          <div class="detail-item"><span class="muted">${t("createdAt")}</span><strong>${escapeHtml(user.createdAt || "-")}</strong></div>
          <div class="detail-item"><span class="muted">${t("lastLogin")}</span><strong>${escapeHtml(user.lastLoginAt || "-")}</strong></div>
          <div class="detail-item"><span class="muted">${t("savedItems")}</span><strong>${entries.length}</strong></div>
        </div>
        <div class="section-title">${t("savedItems")}</div>
        ${entries.length ? `<div class="admin-entry-list">${entries.map((entry) => adminEntryRow(user.email, entry)).join("")}</div>` : `<div class="empty">${t("noEntries")}</div>`}
      </section>
    `;
  }

  function adminEntryRow(userEmail, entry) {
    const reveal = state.adminReveals[entry.id] || {};
    const groups = state.adminDetail?.groups || [];
    const groupName = (groups.find((group) => group.id === entry.groupId) || {}).name || t("defaultGroup");
    return `
      <article class="admin-entry-row">
        <div class="admin-entry-top">
          <div>
            <strong>${escapeHtml(entry.issuer)}</strong>
            <div class="muted">${escapeHtml(entry.account)} · ${escapeHtml(entry.type)}</div>
          </div>
          <span class="badge">${escapeHtml(groupName)}</span>
        </div>
        <div class="admin-entry-actions">
          <button class="ghost" type="button" data-action="admin-view-secret" data-user="${escapeHtml(userEmail)}" data-entry="${entry.id}">${t("adminViewSecret")}</button>
          <button class="ghost" type="button" data-action="admin-view-otp" data-user="${escapeHtml(userEmail)}" data-entry="${entry.id}">${t("adminViewOtp")}</button>
        </div>
        <div class="admin-entry-values">
          <div><span class="muted">${t("secret")}</span><div class="admin-value">${escapeHtml(reveal.secret || t("hiddenByDefault"))}</div></div>
          <div><span class="muted">${t("viewOtp")}</span><div class="admin-value">${escapeHtml(reveal.otp || t("hiddenByDefault"))}</div></div>
        </div>
      </article>
    `;
  }

  async function handleAuth(form) {
    const data = new FormData(form);
    const email = normalizeEmail(data.get("email"));
    const password = String(data.get("password") || "");
    const confirmPassword = String(data.get("confirmPassword") || "");
    if (!email.includes("@")) return setMessage(t("invalidEmail"));
    if (!password) return setMessage(t("required"));
    if (state.authMode === "register" && password !== confirmPassword) return setMessage(t("passwordMismatch"));
    try {
      const payload = await api(
        state.authMode === "register" ? "/api/auth/register" : "/api/auth/login",
        { method: "POST", body: JSON.stringify({ email, password }) },
        "",
      );
      state.userToken = payload.token;
      state.user = payload.user;
      state.message = "";
      await loadUserData();
      render();
    } catch (error) {
      setMessage(error.status === 409 ? t("userExists") : error.status === 401 ? t("invalidLogin") : t("serverError"));
    }
  }

  async function handleAdminAuth(form) {
    const data = new FormData(form);
    const email = normalizeEmail(data.get("email"));
    const password = String(data.get("password") || "");
    const confirmPassword = String(data.get("confirmPassword") || "");
    const setupMode = state.hasAdmin === false;
    if (!email.includes("@")) {
      state.adminMessage = t("invalidEmail");
      render();
      return;
    }
    if (!password) {
      state.adminMessage = t("required");
      render();
      return;
    }
    if (setupMode && password !== confirmPassword) {
      state.adminMessage = t("passwordMismatch");
      render();
      return;
    }
    try {
      const payload = await api(
        setupMode ? "/api/admin/setup" : "/api/admin/login",
        { method: "POST", body: JSON.stringify({ email, password }) },
        "",
      );
      state.adminToken = payload.token;
      state.admin = payload.admin;
      state.hasAdmin = true;
      state.adminMessage = "";
      await loadAdminData();
      render();
    } catch (error) {
      state.adminMessage = error.status === 409 ? t("adminExists") : error.status === 401 ? t("invalidLogin") : t("serverError");
      render();
    }
  }

  async function handlePatCreate(form) {
    const name = String(new FormData(form).get("name") || "").trim();
    if (!name) return;
    try {
      const payload = await api("/api/pats", { method: "POST", body: JSON.stringify({ name }) });
      state.patToken = payload.token;
      await loadUserData();
      render();
    } catch {
      setMessage(t("serverError"));
    }
  }

  async function handleEntrySave(form) {
    const data = new FormData(form);
    const id = String(data.get("id") || "");
    const secret = normalizeSecret(data.get("secret"));
    if (!data.get("issuer") || !data.get("account") || (!id && !secret)) return setMessage(t("required"));
    if (secret) {
      try {
        base32ToBytes(secret);
      } catch {
        return setMessage(t("invalidSecret"));
      }
    }
    try {
      let groupId = String(data.get("groupId") || "default");
      const newGroup = String(data.get("newGroup") || "").trim();
      if (newGroup) {
        const created = await api("/api/groups", { method: "POST", body: JSON.stringify({ name: newGroup }) });
        groupId = created.group.id;
      }
      const body = {
        issuer: String(data.get("issuer") || "").trim(),
        account: String(data.get("account") || "").trim(),
        type: String(data.get("type") || "TOTP"),
        algorithm: String(data.get("algorithm") || "SHA-1"),
        digits: Number(data.get("digits") || 6),
        period: Number(data.get("period") || 30),
        counter: Number(data.get("counter") || 0),
        groupId,
        note: String(data.get("note") || "").trim(),
        icon: String(data.get("icon") || "").trim().slice(0, 8),
      };
      if (secret) {
        body.encryptedSecret = await encryptSecret(secret);
        body.secretVersion = 1;
      }
      const path = id ? `/api/entries/${id}` : "/api/entries";
      await api(path, { method: id ? "PATCH" : "POST", body: JSON.stringify(body) });
      state.editingId = "";
      state.message = "";
      await loadUserData();
      render();
    } catch {
      setMessage(t("serverError"));
    }
  }

  function parseCurrentImportText() {
    if (!state.importText.trim()) {
      state.importItems = [];
      state.importMessage = t("importRequired");
      render();
      return;
    }
    try {
      state.importItems = previewImportItems(parseImportPayload(state.importText));
      state.importMessage = state.importItems.length ? "" : t("reasonUnsupported");
    } catch {
      state.importItems = [];
      state.importMessage = t("reasonUnsupported");
    }
    render();
  }

  async function importPreviewItems(onlySelected) {
    const items = state.importItems.filter((item) => item.status === "valid" && (!onlySelected || item.selected));
    if (!items.length) {
      state.importMessage = t("importNoSelection");
      render();
      return;
    }
    try {
      const entries = [];
      for (const item of items) {
        entries.push({ ...item.entry, encryptedSecret: await encryptSecret(item.entry.secret), secret: undefined });
      }
      await api("/api/import", { method: "POST", body: JSON.stringify({ entries }) });
      state.importOpen = false;
      state.importText = "";
      state.importItems = [];
      state.importMessage = "";
      await loadUserData();
      render();
    } catch {
      state.importMessage = t("serverError");
      render();
    }
  }

  async function readImportFile(file) {
    try {
      state.importText = await file.text();
      state.importMessage = "";
      state.importItems = previewImportItems(parseImportPayload(state.importText));
    } catch {
      state.importItems = [];
      state.importMessage = t("importFileUnsupported");
    }
    render();
  }

  function setMessage(message) {
    state.message = message;
    render();
  }

  async function deleteEntry(id) {
    if (!confirm(t("deleteEntryConfirm"))) return;
    await api(`/api/entries/${id}`, { method: "DELETE" });
    state.editingId = "";
    await loadUserData();
    render();
  }

  async function nextHotp(id) {
    const entry = state.entries.find((item) => item.id === id);
    if (!entry) return;
    await api(`/api/entries/${id}`, { method: "PATCH", body: JSON.stringify({ counter: Number(entry.counter || 0) + 1 }) });
    await loadUserData();
    render();
  }

  async function copyCode(id) {
    const code = state.otpCodes.get(id);
    if (!code) return;
    await navigator.clipboard.writeText(code);
    state.copiedId = id;
    renderOtpCodes();
    setTimeout(() => {
      state.copiedId = "";
      renderOtpCodes();
    }, 1200);
  }

  async function deleteAccount() {
    if (!confirm(t("deleteAccountConfirm"))) return;
    await api("/api/me", { method: "DELETE" });
    clearUserSession();
    render();
  }

  async function revealAdminEntry(userEmail, entryId, field) {
    const suffix = field === "secret" ? "secret" : "code";
    const payload = await api(
      `/api/admin/users/${encodeURIComponent(userEmail)}/entries/${entryId}/${suffix}`,
      {},
      state.adminToken,
    );
    const reveal = state.adminReveals[entryId] || {};
    if (field === "secret") reveal.secret = payload.secret;
    if (field === "otp") reveal.otp = payload.code;
    state.adminReveals[entryId] = reveal;
    const audit = await api("/api/admin/audit", {}, state.adminToken);
    state.adminAudit = audit.items;
    render();
  }

  async function disableAdminUser(email) {
    if (!confirm(t("adminDisableUserConfirm"))) return;
    await api(`/api/admin/users/${encodeURIComponent(email)}/disable`, { method: "POST" }, state.adminToken);
    await loadAdminData();
    render();
  }

  async function deleteAdminUser(email) {
    if (!confirm(t("adminDeleteUserConfirm"))) return;
    await api(`/api/admin/users/${encodeURIComponent(email)}`, { method: "DELETE" }, state.adminToken);
    await loadAdminData();
    render();
  }

  async function renamePat(id) {
    const pat = state.pats.find((item) => item.id === id);
    const name = prompt(t("patName"), pat?.name || "");
    if (!name) return;
    await api(`/api/pats/${id}`, { method: "PATCH", body: JSON.stringify({ name }) });
    await loadUserData();
    render();
  }

  async function deletePat(id) {
    if (!confirm(t("deletePatConfirm"))) return;
    await api(`/api/pats/${id}`, { method: "DELETE" });
    await loadUserData();
    render();
  }

  async function logout() {
    let logoutFailed = false;
    if (state.userToken) {
      try {
        await api("/api/auth/logout", { method: "POST" });
      } catch {
        logoutFailed = true;
      }
    }
    clearUserSession();
    if (logoutFailed) {
      state.message = t("serverError");
    }
    render();
  }

  async function adminLogout() {
    let logoutFailed = false;
    if (state.adminToken) {
      try {
        await api("/api/auth/logout", { method: "POST" }, state.adminToken);
      } catch {
        logoutFailed = true;
      }
    }
    clearAdminSession();
    if (logoutFailed) {
      state.adminMessage = t("serverError");
    }
    render();
  }

  document.addEventListener("submit", async (event) => {
    event.preventDefault();
    const formId = event.target.id;
    if (formId === "auth-form") await handleAuth(event.target);
    if (formId === "admin-auth-form") await handleAdminAuth(event.target);
    if (formId === "entry-form") await handleEntrySave(event.target);
    if (formId === "pat-form") await handlePatCreate(event.target);
  });

  document.addEventListener("click", async (event) => {
    const target = event.target.closest("button, [data-entry-id]");
    if (!target) return;
    if (target.dataset.locale) {
      changeLocale(target.dataset.locale);
      return;
    }
    if (target.dataset.route) {
      goToRoute(target.dataset.route);
      return;
    }
    if (target.dataset.authMode) {
      state.authMode = target.dataset.authMode;
      state.message = "";
      render();
      return;
    }
    if (target.dataset.group) {
      state.groupFilter = target.dataset.group;
      render();
      return;
    }
    if (target.dataset.entryId) {
      state.editingId = target.dataset.entryId;
      render();
      return;
    }
    if (target.dataset.adminUser) {
      await loadAdminUser(target.dataset.adminUser);
      return;
    }
    const action = target.dataset.action;
    const id = target.dataset.id;
    if (action === "new-entry") {
      state.editingId = "";
      render();
    }
    if (action === "clear-edit") {
      state.editingId = "";
      state.message = "";
      render();
    }
    if (action === "delete-entry") await deleteEntry(id);
    if (action === "next-hotp") await nextHotp(id);
    if (action === "copy") await copyCode(id);
    if (action === "logout") await logout();
    if (action === "delete-account") await deleteAccount();
    if (action === "open-import") {
      state.importOpen = true;
      state.importMessage = "";
      render();
    }
    if (action === "close-import") {
      state.importOpen = false;
      state.importMessage = "";
      render();
    }
    if (action === "parse-import") parseCurrentImportText();
    if (action === "import-all") await importPreviewItems(false);
    if (action === "import-selected") await importPreviewItems(true);
    if (action === "admin-logout") await adminLogout();
    if (action === "admin-disable-user") await disableAdminUser(id);
    if (action === "admin-delete-user") await deleteAdminUser(id);
    if (action === "admin-view-secret") await revealAdminEntry(target.dataset.user, target.dataset.entry, "secret");
    if (action === "admin-view-otp") await revealAdminEntry(target.dataset.user, target.dataset.entry, "otp");
    if (action === "rename-pat") await renamePat(id);
    if (action === "delete-pat") await deletePat(id);
  });

  document.addEventListener("input", (event) => {
    if (event.target.id === "search") {
      state.search = event.target.value;
      scheduleRender();
    }
    if (event.target.id === "import-text") {
      state.importText = event.target.value;
    }
  });

  document.addEventListener("change", async (event) => {
    if (event.target.dataset.action === "import-file" && event.target.files[0]) {
      await readImportFile(event.target.files[0]);
    }
    if (event.target.dataset.importId) {
      const item = state.importItems.find((candidate) => candidate.id === event.target.dataset.importId);
      if (item) item.selected = event.target.checked;
    }
  });

  window.addEventListener("popstate", render);
  setInterval(() => {
    if (state.userToken) refreshOtpCodes();
  }, 1000);

  bootstrap()
    .catch(() => {
      state.message = t("serverError");
      state.adminMessage = t("serverError");
    })
    .finally(() => {
      syncRouteFromLocation();
      render();
    });
})();
