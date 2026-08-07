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
    siteSettings: null,
    adminSelectedUserEmail: "",
    adminAudit: [],
    adminReveals: {},
    editingId: null,
    groupFilter: "all",
    sortMode: "recent",
    search: "",
    message: "",
    adminMessage: "",
    otpCodes: new Map(),
    otpRefreshVersion: 0,
    copiedId: "",
    renderScheduled: false,
    importOpen: false,
    settingsOpen: false,
    scannerOpen: false,
    importText: "",
    importItems: [],
    importMessage: "",
    online: navigator.onLine,
    serviceWorkerReady: false,
    offlineSecrets: new Map(),
    offlineSecretIds: new Set(),
    pwaMessage: "",
    revealedEntryIds: new Set(),
  };
  let qrScannerStream = null;
  let qrScannerTimer = null;
  let qrScannerBusy = false;
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

  function idbRequest(request) {
    return new Promise((resolve, reject) => {
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error);
    });
  }

  async function openOfflineDb() {
    if (!window.indexedDB) throw new Error("indexeddb_unavailable");
    const request = indexedDB.open("vaultotp-pwa-offline", 1);
    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains("secrets")) db.createObjectStore("secrets");
      if (!db.objectStoreNames.contains("meta")) db.createObjectStore("meta");
    };
    return idbRequest(request);
  }

  async function offlineStore(storeName, mode, callback) {
    const db = await openOfflineDb();
    return new Promise((resolve, reject) => {
      const tx = db.transaction(storeName, mode);
      const store = tx.objectStore(storeName);
      const result = callback(store);
      tx.oncomplete = () => {
        db.close();
        resolve(result);
      };
      tx.onerror = () => {
        db.close();
        reject(tx.error);
      };
    });
  }

  async function offlineKey() {
    const existing = await offlineStore("meta", "readonly", (store) => idbRequest(store.get("offlineKey")));
    if (existing) return existing;
    const key = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
    await offlineStore("meta", "readwrite", (store) => store.put(key, "offlineKey"));
    return key;
  }

  async function offlineMeta(key, value) {
    if (arguments.length === 1) {
      return offlineStore("meta", "readonly", (store) => idbRequest(store.get(key)));
    }
    return offlineStore("meta", "readwrite", (store) => store.put(value, key));
  }

  async function deleteOfflineMeta(key) {
    return offlineStore("meta", "readwrite", (store) => store.delete(key));
  }

  function offlineEntrySnapshot(entry) {
    return {
      id: entry.id,
      userId: entry.userId,
      issuer: entry.issuer,
      account: entry.account,
      type: entry.type,
      algorithm: entry.algorithm,
      digits: entry.digits,
      period: entry.period,
      counter: entry.counter,
      groupId: entry.groupId,
      pinned: Boolean(entry.pinned),
      note: entry.note || "",
      icon: entry.icon || "",
      createdAt: entry.createdAt,
      updatedAt: entry.updatedAt,
    };
  }

  async function cacheOfflineSnapshot() {
    if (!state.user?.id) return;
    const snapshot = {
      user: state.user,
      groups: state.groups,
      entries: state.entries.map(offlineEntrySnapshot),
      updatedAt: new Date().toISOString(),
    };
    await offlineMeta(`snapshot:${state.user.id}`, snapshot);
    await offlineMeta("activeUserId", state.user.id);
  }

  async function loadActiveOfflineSnapshot() {
    const userId = await offlineMeta("activeUserId");
    if (!userId) return null;
    return offlineMeta(`snapshot:${userId}`);
  }

  async function clearOfflineSession(deleteSnapshot = false) {
    const userId = await offlineMeta("activeUserId");
    await deleteOfflineMeta("activeUserId");
    if (deleteSnapshot && userId) {
      await deleteOfflineMeta(`snapshot:${userId}`);
    }
  }

  async function cacheOfflineSecret(entry, secret) {
    if (!entry?.id || !state.user?.id || !secret || entry.type === "HOTP") return;
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const cipher = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, await offlineKey(), textEncoder.encode(normalizeSecret(secret)));
    const payload = {
      userId: state.user.id,
      entryId: entry.id,
      cipher: toBase64(cipher),
      iv: toBase64(iv),
      updatedAt: new Date().toISOString(),
    };
    await offlineStore("secrets", "readwrite", (store) => store.put(payload, entry.id));
    state.offlineSecrets.set(entry.id, normalizeSecret(secret));
    state.offlineSecretIds.add(entry.id);
  }

  async function deleteOfflineSecret(id) {
    await offlineStore("secrets", "readwrite", (store) => store.delete(id));
    state.offlineSecrets.delete(id);
    state.offlineSecretIds.delete(id);
  }

  async function loadOfflineSecrets() {
    state.offlineSecrets = new Map();
    state.offlineSecretIds = new Set();
    if (!state.user?.id || !state.entries.length) return;
    const key = await offlineKey();
    for (const entry of state.entries) {
      const record = await offlineStore("secrets", "readonly", (store) => idbRequest(store.get(entry.id)));
      if (!record || record.userId !== state.user.id) continue;
      state.offlineSecretIds.add(entry.id);
      try {
        const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: fromBase64(record.iv) }, key, fromBase64(record.cipher));
        state.offlineSecrets.set(entry.id, normalizeSecret(textDecoder.decode(plain)));
      } catch {
        state.offlineSecrets.delete(entry.id);
      }
    }
  }

  async function clearCurrentOfflineSecrets() {
    for (const id of state.entries.map((entry) => entry.id)) {
      await deleteOfflineSecret(id);
    }
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
    state.groupFilter = "all";
    state.sortMode = "recent";
    state.search = "";
    state.message = "";
    state.otpCodes = new Map();
    state.importOpen = false;
    state.settingsOpen = false;
    state.scannerOpen = false;
    state.importText = "";
    state.importItems = [];
    state.importMessage = "";
    stopQrScanner();
    state.offlineSecrets = new Map();
    state.offlineSecretIds = new Set();
    state.pwaMessage = "";
    state.revealedEntryIds = new Set();
  }

  function clearAdminSession() {
    state.adminToken = "";
    state.admin = null;
    state.adminUsers = [];
    state.adminDetail = null;
    state.siteSettings = null;
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
    if (normalized.length < 8 || [1, 3, 6].includes(normalized.length % 8)) throw new Error("invalid base32");
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
    if (bits.slice(bytes.length * 8).includes("1")) throw new Error("invalid base32");
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

  async function hotp(secret, counter, digits, algorithm) {
    const key = await crypto.subtle.importKey(
      "raw",
      base32ToBytes(secret),
      { name: "HMAC", hash: normalizeAlgorithm(algorithm) },
      false,
      ["sign"],
    );
    const counterBytes = new ArrayBuffer(8);
    const view = new DataView(counterBytes);
    view.setUint32(0, Math.floor(counter / 0x100000000));
    view.setUint32(4, counter >>> 0);
    const digest = new Uint8Array(await crypto.subtle.sign("HMAC", key, counterBytes));
    const offset = digest[digest.length - 1] & 0x0f;
    const binary =
      ((digest[offset] & 0x7f) << 24) |
      ((digest[offset + 1] & 0xff) << 16) |
      ((digest[offset + 2] & 0xff) << 8) |
      (digest[offset + 3] & 0xff);
    return String(binary % 10 ** Number(digits || 6)).padStart(Number(digits || 6), "0");
  }

  async function offlineCode(entry) {
    if (entry.type === "HOTP") return "";
    const secret = state.offlineSecrets.get(entry.id);
    if (!secret) return "";
    const period = Number(entry.period || 30);
    const counter = Math.floor(Date.now() / 1000 / period);
    return hotp(secret, counter, entry.digits, entry.algorithm);
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
    return [entry.type, entry.issuer, entry.account, entry.secret, entry.algorithm, entry.digits, period]
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

  function parseImportedOtpValue(value, raw, source) {
    const candidate = String(value || "").trim();
    if (candidate.toLowerCase().startsWith("otpauth://")) {
      try {
        return parseOtpAuthUri(candidate, source);
      } catch {
        // Keep the original value so the preview can mark it invalid.
      }
    }
    return normalizeImportedEntry({ ...raw, secret: candidate }, source);
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

  function parseBitwardenJson(json) {
    if (!Array.isArray(json?.items)) return [];
    return json.items.flatMap((item) => {
      const value = item?.login?.totp;
      if (!value) return [];
      return [
        parseImportedOtpValue(
          value,
          {
            issuer: item.name,
            account: item.login?.username || item.name,
            note: item.notes,
          },
          "Bitwarden",
        ),
      ];
    });
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

  function parseRaivoJson(json) {
    const values = Array.isArray(json) ? json : [];
    if (
      !values.some(
        (item) => item && typeof item === "object" && ("kind" in item || "timer" in item || "iconType" in item),
      )
    )
      return [];
    return values
      .filter(
        (item) =>
          item &&
          typeof item === "object" &&
          item.secret &&
          ("kind" in item || "timer" in item || "iconType" in item),
      )
      .map((item) =>
        normalizeImportedEntry(
          {
            issuer: item.issuer,
            account: item.account,
            secret: item.secret,
            type: item.kind,
            algorithm: item.algorithm,
            digits: item.digits,
            period: item.timer,
            counter: item.counter,
            icon: item.iconValue,
          },
          "Raivo",
        ),
      );
  }

  function parseAndOtpJson(json) {
    const values = Array.isArray(json) ? json : [];
    if (
      !values.some(
        (item) => item && typeof item === "object" && "label" in item && ("tags" in item || "algorithm" in item),
      )
    )
      return [];
    return values
      .filter(
        (item) =>
          item &&
          typeof item === "object" &&
          item.secret &&
          "label" in item &&
          ("tags" in item || "algorithm" in item),
      )
      .map((item) =>
        normalizeImportedEntry(
          {
            issuer: item.issuer,
            account: item.label,
            secret: item.secret,
            type: item.type,
            algorithm: item.algorithm,
            digits: item.digits,
            period: item.period,
            counter: item.counter,
          },
          "andOTP",
        ),
      );
  }

  function parseProtonJson(json) {
    const values = [
      ...(Array.isArray(json) ? json : []),
      ...(Array.isArray(json?.items) ? json.items : []),
      ...(Array.isArray(json?.vaults) ? json.vaults.flatMap((vault) => (Array.isArray(vault?.items) ? vault.items : [])) : []),
    ];
    return values.flatMap((item) => {
      const value = item?.totp || item?.otp || item?.login?.totp || item?.content?.totp || item?.data?.totp;
      if (!value) return [];
      return [
        parseImportedOtpValue(
          value,
          {
            issuer: item.issuer || item.name || item.title,
            account: item.account || item.username || item.login?.username || item.name || item.title,
            note: item.note || item.notes,
            algorithm: item.algorithm || item.algo,
            digits: item.digits,
            period: item.period,
            counter: item.counter,
            type: item.type || item.kind,
          },
          "Proton Pass",
        ),
      ];
    });
  }

  function parseGenericJson(json) {
    const values = Array.isArray(json) ? json : [];
    return values
      .filter((item) => item && typeof item === "object")
      .filter(
        (item) =>
          !("kind" in item || "timer" in item || "iconType" in item) &&
          !("label" in item && ("tags" in item || "algorithm" in item)),
      )
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

  function parseCsvRows(text) {
    const rows = [];
    let row = [];
    let value = "";
    let quoted = false;
    for (let index = 0; index < text.length; index += 1) {
      const char = text[index];
      if (char === '"') {
        if (quoted && text[index + 1] === '"') {
          value += '"';
          index += 1;
        } else {
          quoted = !quoted;
        }
      } else if (char === "," && !quoted) {
        row.push(value);
        value = "";
      } else if ((char === "\n" || char === "\r") && !quoted) {
        if (char === "\r" && text[index + 1] === "\n") index += 1;
        row.push(value);
        if (row.some((item) => item.trim())) rows.push(row);
        row = [];
        value = "";
      } else {
        value += char;
      }
    }
    row.push(value);
    if (row.some((item) => item.trim())) rows.push(row);
    return rows;
  }

  function csvValue(row, indexes, ...names) {
    for (const name of names) {
      const index = indexes.get(name);
      if (index !== undefined) return String(row[index] || "").trim();
    }
    return "";
  }

  function extractCsvOtp(value, allowRaw = false) {
    const text = String(value || "").trim();
    const uri = text.match(/otpauth:\/\/[^\s]+/i)?.[0];
    if (uri) return uri;
    const labeled = text.match(/(?:totp|otp)(?:\s+(?:secret|key))?\s*[:=]\s*([A-Z2-7][A-Z2-7\s-]{7,})/i)?.[1];
    return labeled || (allowRaw ? text : "");
  }

  function parseCsvImport(text) {
    const rows = parseCsvRows(text);
    if (rows.length < 2) return [];
    const headers = rows[0].map((item) => item.trim().toLowerCase());
    const indexes = new Map(headers.map((name, index) => [name, index]));
    const hasLastPassHeaders = ["url", "username", "password", "extra", "name", "grouping", "fav"].every((name) =>
      indexes.has(name),
    );
    const otpHeader = ["totp", "otp", "one-time password", "otp secret"].find((name) => indexes.has(name));
    const hasProtonHeaders = indexes.has("name") && (Boolean(otpHeader) || indexes.has("urls") || indexes.has("url"));
    if (!hasLastPassHeaders && !hasProtonHeaders) return [];
    const source = hasLastPassHeaders ? "LastPass" : "Proton Pass";
    return rows.slice(1).flatMap((row) => {
      const explicitOtp = csvValue(row, indexes, otpHeader);
      const extra = csvValue(row, indexes, "extra", "note", "notes");
      const value = explicitOtp
        ? extractCsvOtp(explicitOtp, true)
        : extractCsvOtp(extra) || extractCsvOtp(csvValue(row, indexes, "url", "urls"));
      if (!value) return [];
      return [
        parseImportedOtpValue(
          value,
          {
            issuer: csvValue(row, indexes, "issuer", "service", "name"),
            account: csvValue(row, indexes, "username", "account", "email", "name"),
            note: explicitOtp ? extra : "",
          },
          source,
        ),
      ];
    });
  }

  function parseJsonImport(text) {
    const json = JSON.parse(text);
    const parsers = [
      parseAegisJson,
      parseBitwardenJson,
      parseTwoFasJson,
      parseTwoFAuthJson,
      parseProtonJson,
      parseRaivoJson,
      parseAndOtpJson,
      parseGenericJson,
    ];
    const entries = [];
    const seen = new Set();
    for (const parser of parsers) {
      for (const entry of parser(json)) {
        const key = entryDuplicateKey(entry);
        if (seen.has(key)) continue;
        seen.add(key);
        entries.push(entry);
      }
    }
    return entries;
  }

  function parseImportPayload(text) {
    const trimmed = text.trim();
    if (!trimmed) return [];
    const results = [];
    if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
      results.push(...parseJsonImport(trimmed));
    } else {
      results.push(...parseCsvImport(trimmed));
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
    const groups = await api("/api/groups");
    const entries = await api("/api/entries");
    const pats = await api("/api/pats");
    state.groups = groups.items;
    state.entries = entries.items;
    state.pats = pats.items;
    try {
      await cacheOfflineSnapshot();
      await loadOfflineSecrets();
    } catch {
      state.offlineSecrets = new Map();
      state.offlineSecretIds = new Set();
    }
    await refreshOtpCodes();
  }

  async function loadAdminData() {
    const [users, audit, settings] = await Promise.all([
      api("/api/admin/users", {}, state.adminToken),
      api("/api/admin/audit", {}, state.adminToken),
      api("/api/admin/site-settings", {}, state.adminToken),
    ]);
    state.adminUsers = users.items;
    state.adminAudit = audit.items;
    state.siteSettings = settings.settings;
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
    if (!state.entries.length) {
      state.otpCodes = new Map();
      renderOtpCodes();
      return;
    }
    const refreshVersion = ++state.otpRefreshVersion;
    const codes = new Map();
    const concurrency = state.userToken ? 3 : state.entries.length;
    for (let index = 0; index < state.entries.length; index += concurrency) {
      await Promise.all(
        state.entries.slice(index, index + concurrency).map(async (entry) => {
          try {
            if (state.userToken) {
              const payload = await api(`/api/entries/${entry.id}/code`);
              codes.set(entry.id, payload.code);
            } else {
              codes.set(entry.id, (await offlineCode(entry)) || "------");
            }
          } catch {
            codes.set(entry.id, (await offlineCode(entry)) || "------");
          }
        }),
      );
    }
    if (refreshVersion === state.otpRefreshVersion) {
      state.otpCodes = codes;
      renderOtpCodes();
    }
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
    const entries = state.entries.filter((entry) => {
      const groupOk = state.groupFilter === "all" || entry.groupId === state.groupFilter;
      const text = `${entry.issuer} ${entry.account} ${entry.note} ${findGroupName(entry.groupId)}`.toLowerCase();
      return groupOk && (!query || text.includes(query));
    });
    return sortEntries(entries);
  }

  function sortEntries(entries) {
    const compareText = (left, right) => String(left || "").localeCompare(String(right || ""), currentLocale === "zh-CN" ? "zh-Hans-CN" : "en", { sensitivity: "base" });
    const selected = state.sortMode || "recent";
    return [...entries].sort((left, right) => {
      const pinnedDelta = Number(Boolean(right.pinned)) - Number(Boolean(left.pinned));
      if (pinnedDelta) return pinnedDelta;
      if (selected === "name") {
        const issuerDelta = compareText(left.issuer, right.issuer);
        return issuerDelta || compareText(left.account, right.account);
      }
      if (selected === "group") {
        const groupDelta = compareText(findGroupName(left.groupId), findGroupName(right.groupId));
        return groupDelta || compareText(left.issuer, right.issuer) || compareText(left.account, right.account);
      }
      if (selected === "created") {
        return String(right.createdAt || "").localeCompare(String(left.createdAt || ""));
      }
      return String(right.updatedAt || "").localeCompare(String(left.updatedAt || ""));
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
    if (!state.userToken && !state.user) {
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
          <div class="brand">${t("authTitle")}</div>
          ${languageSwitch()}
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
          <div class="auth-actions">
            <button class="primary" type="submit">${state.authMode === "login" ? t("loginAction") : t("createAccount")}</button>
            <button class="ghost" type="button" data-auth-mode="${state.authMode === "login" ? "register" : "login"}">
              ${state.authMode === "login" ? t("register") : t("login")}
            </button>
          </div>
        </form>
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
            ${setupMode ? `<div class="muted">${t("adminCreateHint")}</div>` : ""}
          </div>
          ${languageSwitch()}
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
      <div class="layout user-layout">
        <aside class="sidebar user-sidebar">
          <div class="sidebar-heading">
            <div class="section-title">${t("group")}</div>
            <div class="muted">${t("serverBacked")}</div>
          </div>
          <div class="group-list">
            ${groupButton("all", t("allGroups"), state.entries.length)}
            ${state.groups.map((group) => groupButton(group.id, group.name, countGroup(group.id))).join("")}
          </div>
        </aside>
        <main class="content user-content">
          <header class="topbar user-topbar">
            <div class="user-account">
              <span class="muted">${t("currentUser")}</span>
              <strong>${escapeHtml(state.user?.email || "")}</strong>
            </div>
            <div class="field user-search">
              <label for="search">${t("search")}</label>
              <input id="search" value="${escapeHtml(state.search)}" />
            </div>
            <div class="inline-actions user-top-actions">
              <button class="primary" data-action="open-import">${t("importEntries")}</button>
              <button class="ghost" data-action="new-entry">${t("addEntry")}</button>
              <button class="ghost" data-action="toggle-settings" aria-expanded="${state.settingsOpen ? "true" : "false"}">${t("settings")}</button>
            </div>
          </header>
          <div class="user-main-stack">
            ${listToolbar(entries.length)}
            <section class="entry-list">
              ${entries.length ? entries.map(entryView).join("") : emptyEntryState()}
            </section>
            ${state.editingId !== null ? `<section class="user-form-section">${entryForm()}</section>` : ""}
            ${state.settingsOpen ? settingsPanel() : ""}
          </div>
        </main>
      </div>
      ${state.importOpen ? importPanel() : ""}
    `;
  }

  function listToolbar(count) {
    return `
      <section class="entry-toolbar">
        <div class="field sort-field">
          <label for="sort-mode">${t("sortBy")}</label>
          <select id="sort-mode" data-action="sort-mode">
            <option value="recent" ${state.sortMode === "recent" ? "selected" : ""}>${t("sortRecent")}</option>
            <option value="name" ${state.sortMode === "name" ? "selected" : ""}>${t("sortName")}</option>
            <option value="group" ${state.sortMode === "group" ? "selected" : ""}>${t("sortGroup")}</option>
            <option value="created" ${state.sortMode === "created" ? "selected" : ""}>${t("sortCreated")}</option>
          </select>
        </div>
        <div class="inline-actions entry-toolbar-actions">
          <span class="muted">${t("entriesCount", { count })}</span>
          <button class="ghost" data-action="clear-filters">${t("clearFilters")}</button>
        </div>
      </section>
    `;
  }

  function emptyEntryState() {
    const hasFilters = Boolean(state.search.trim()) || state.groupFilter !== "all";
    if (hasFilters) {
      return `
        <div class="empty-state">
          <div class="empty">${t("noMatchingEntries")}</div>
          <div class="inline-actions empty-actions">
            <button class="ghost" data-action="clear-filters">${t("clearFilters")}</button>
          </div>
        </div>
      `;
    }
    return `
      <div class="empty-state">
        <div class="empty">${t("emptyEntries")}</div>
        <div class="inline-actions empty-actions">
          <button class="primary" data-action="open-import">${t("importEntries")}</button>
          <button class="ghost" data-action="new-entry">${t("addEntry")}</button>
        </div>
      </div>
    `;
  }

  function settingsPanel() {
    return `
      <section class="user-settings-panel">
        <div class="panel-title">
          <h2>${t("settings")}</h2>
          <button class="ghost" data-action="toggle-settings">${t("close")}</button>
        </div>
        <div class="user-utility-grid">
          ${accountSecurityPanel()}
          ${pwaPanel()}
          ${patPanel()}
        </div>
      </section>
    `;
  }

  function accountSecurityPanel() {
    return `
      <div class="sidebar-section">
        <div class="section-title">${t("accountSecurity")}</div>
        <div class="muted">${escapeHtml(state.user?.email || "")}</div>
        ${languageSwitch()}
        <div class="inline-actions settings-actions">
          <button class="ghost" data-action="logout">${t("logout")}</button>
          <button class="danger" data-action="delete-account" ${state.userToken ? "" : "disabled"}>${t("deleteAccount")}</button>
        </div>
      </div>
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

  function pwaPanel() {
    const cached = state.entries.filter((entry) => state.offlineSecretIds.has(entry.id)).length;
    return `
      <div class="sidebar-section pwa-panel">
        <div class="section-title">${t("pwaTitle")}</div>
        <div class="status-row">
          <span class="status-dot ${state.online ? "online" : "offline"}"></span>
          <span>${state.online ? t("online") : t("offline")}</span>
        </div>
        <div class="muted">${t(state.serviceWorkerReady ? "offlineReady" : "offlineInstalling")}</div>
        <div class="muted">${t("offlineCachedCount", { count: cached })}</div>
        ${state.pwaMessage ? `<div class="error">${escapeHtml(state.pwaMessage)}</div>` : ""}
        <button class="ghost full-width" data-action="sync-now" ${state.online && state.userToken ? "" : "disabled"}>${t("syncNow")}</button>
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
          ${siteSettingsPanel()}
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

  function siteSettingsPanel() {
    const settings = state.siteSettings || {};
    return `
      <div class="sidebar-section">
        <div class="section-title">${t("siteSettingsTitle")}</div>
        <form id="site-settings-form" class="site-settings-form">
          <div class="field">
            <label>${t("siteName")}</label>
            <input name="siteName" value="${escapeHtml(settings.siteName || "")}" />
          </div>
          <div class="field">
            <label>${t("seoTitle")}</label>
            <input name="seoTitle" value="${escapeHtml(settings.seoTitle || "")}" />
          </div>
          <div class="field">
            <label>${t("seoKeywords")}</label>
            <input name="seoKeywords" value="${escapeHtml(settings.seoKeywords || "")}" />
          </div>
          <div class="field">
            <label>${t("seoDescription")}</label>
            <textarea name="seoDescription">${escapeHtml(settings.seoDescription || "")}</textarea>
          </div>
          <div class="field">
            <label>${t("logo")}</label>
            <input name="logo" value="${escapeHtml(settings.logo || "")}" />
          </div>
          <div class="field">
            <label>${t("ogTitle")}</label>
            <input name="ogTitle" value="${escapeHtml(settings.ogTitle || "")}" />
          </div>
          <div class="field">
            <label>${t("ogDescription")}</label>
            <textarea name="ogDescription">${escapeHtml(settings.ogDescription || "")}</textarea>
          </div>
          <label class="checkbox-field">
            <input type="checkbox" name="allowPublicIndexing" ${settings.allowPublicIndexing === false ? "" : "checked"} />
            <span>${t("allowPublicIndexing")}</span>
          </label>
          <button class="ghost" type="submit">${t("saveSiteSettings")}</button>
        </form>
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
    const revealed = state.revealedEntryIds.has(entry.id);
    return `
      <article class="entry ${state.editingId === entry.id ? "selected" : ""} ${entry.pinned ? "pinned" : ""}" data-entry-id="${entry.id}">
        <div class="entry-main">
          <div class="entry-title">
            <strong>${escapeHtml(entry.issuer)}</strong>
            <span class="muted">${escapeHtml(entry.account)}</span>
          </div>
          <div class="entry-actions">
            <button class="otp otp-toggle" type="button" data-action="toggle-code" data-id="${entry.id}" aria-label="${revealed ? t("hideCode") : t("showCode")}">
              ${escapeHtml(revealed ? code : "******")}
            </button>
            <button class="icon-button" data-action="copy" data-id="${entry.id}">${state.copiedId === entry.id ? t("copied") : t("copy")}</button>
            <button class="icon-button" data-action="toggle-pin" data-id="${entry.id}">${entry.pinned ? t("unpin") : t("pin")}</button>
            ${entry.type === "HOTP" ? `<button class="icon-button" data-action="next-hotp" data-id="${entry.id}">${t("next")}</button>` : ""}
          </div>
        </div>
        <div class="entry-meta">
          <span class="badge">${escapeHtml(findGroupName(entry.groupId))}</span>
          <span class="badge" data-period-id="${entry.id}">${escapeHtml(periodRemaining(entry))}</span>
          ${entry.pinned ? `<span class="badge">${t("pinned")}</span>` : ""}
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
        <div class="field">
          <label>${t("group")}</label>
          <select name="groupId">
            ${state.groups.map((group) => `<option value="${group.id}" ${data.groupId === group.id ? "selected" : ""}>${escapeHtml(group.name)}</option>`).join("")}
          </select>
        </div>
        <details class="advanced-options">
          <summary>${t("advancedOptions")}</summary>
          <div class="form-grid advanced-grid">
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
            <div class="field">
              <label>${t("newGroup")}</label>
              <input name="newGroup" />
            </div>
            <div class="field advanced-note">
              <label>${t("note")}</label>
              <textarea name="note">${escapeHtml(data.note)}</textarea>
            </div>
          </div>
        </details>
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
            <input type="file" data-action="import-file" accept=".txt,.json,.csv,.2fas,.aegis,image/*" />
          </div>
          <div class="import-scan-panel">
            <div>
              <div class="section-title">${t("scanQr")}</div>
              <div class="muted">${t("scanQrHint")}</div>
            </div>
            <div class="inline-actions">
              <button class="ghost" data-action="open-scanner" ${state.scannerOpen ? "disabled" : ""}>${t("startScan")}</button>
              ${state.scannerOpen ? `<button class="ghost" data-action="close-scanner">${t("stopScan")}</button>` : ""}
            </div>
            ${state.scannerOpen ? `<video id="qr-scan-video" class="qr-scan-video" autoplay muted playsinline></video>` : ""}
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

  async function handleSiteSettingsSave(form) {
    const data = new FormData(form);
    try {
      const payload = await api(
        "/api/admin/site-settings",
        {
          method: "PATCH",
          body: JSON.stringify({
            siteName: String(data.get("siteName") || "").trim(),
            seoTitle: String(data.get("seoTitle") || "").trim(),
            seoKeywords: String(data.get("seoKeywords") || "").trim(),
            seoDescription: String(data.get("seoDescription") || "").trim(),
            logo: String(data.get("logo") || "").trim(),
            ogTitle: String(data.get("ogTitle") || "").trim(),
            ogDescription: String(data.get("ogDescription") || "").trim(),
            allowPublicIndexing: data.get("allowPublicIndexing") === "on",
          }),
        },
        state.adminToken,
      );
      state.siteSettings = payload.settings;
      state.adminMessage = t("siteSettingsSaved");
      render();
    } catch {
      state.adminMessage = t("serverError");
      render();
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
      };
      if (secret) {
        body.encryptedSecret = await encryptSecret(secret);
        body.secretVersion = 1;
      }
      const path = id ? `/api/entries/${id}` : "/api/entries";
      const saved = await api(path, { method: id ? "PATCH" : "POST", body: JSON.stringify(body) });
      if (secret && saved.entry) {
        try {
          await cacheOfflineSecret(saved.entry, secret);
        } catch {
          state.pwaMessage = t("offlineCacheUnavailable");
        }
      }
      state.editingId = null;
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
      const imported = await api("/api/import", { method: "POST", body: JSON.stringify({ entries }) });
      const inserted = Array.isArray(imported.entries) ? imported.entries : [];
      for (const [index, entry] of inserted.entries()) {
        try {
          await cacheOfflineSecret(entry, items[index]?.entry.secret);
        } catch {
          state.pwaMessage = t("offlineCacheUnavailable");
        }
      }
      state.importOpen = false;
      state.importText = "";
      state.importItems = [];
      state.importMessage = "";
      state.scannerOpen = false;
      stopQrScanner();
      await loadUserData();
      render();
    } catch {
      state.importMessage = t("serverError");
      render();
    }
  }

  async function readImportFile(file) {
    try {
      applyImportPayload(file.type.startsWith("image/") ? await readQrImportFile(file) : await file.text(), false);
    } catch (error) {
      state.importItems = [];
      state.importMessage = file.type.startsWith("image/") && error.message === "barcode_detector_unavailable" ? t("scanUnsupported") : t("importFileUnsupported");
    }
    render();
  }

  function applyImportPayload(text, append) {
    const value = String(text || "").trim();
    state.importText = append && state.importText.trim() ? `${state.importText.trim()}\n${value}` : value;
    state.importItems = previewImportItems(parseImportPayload(state.importText));
    state.importMessage = state.importItems.length ? "" : t("reasonUnsupported");
  }

  async function readQrImportFile(file) {
    if (!("BarcodeDetector" in window)) throw new Error("barcode_detector_unavailable");
    const image = await createImageBitmap(file);
    try {
      const detector = new BarcodeDetector({ formats: ["qr_code"] });
      const codes = await detector.detect(image);
      const values = codes.map((code) => code.rawValue).filter(Boolean);
      if (!values.length) throw new Error("qr_not_found");
      return values.join("\n");
    } finally {
      image.close?.();
    }
  }

  function stopQrScanner() {
    if (qrScannerTimer) {
      clearInterval(qrScannerTimer);
      qrScannerTimer = null;
    }
    if (qrScannerStream) {
      qrScannerStream.getTracks().forEach((track) => track.stop());
      qrScannerStream = null;
    }
    qrScannerBusy = false;
  }

  async function startQrScanner() {
    stopQrScanner();
    if (!("BarcodeDetector" in window) || !navigator.mediaDevices?.getUserMedia) {
      state.scannerOpen = false;
      state.importMessage = t("scanUnsupported");
      render();
      return;
    }
    const video = document.getElementById("qr-scan-video");
    if (!video) return;
    try {
      qrScannerStream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: { ideal: "environment" } }, audio: false });
      video.srcObject = qrScannerStream;
      await video.play();
      const detector = new BarcodeDetector({ formats: ["qr_code"] });
      qrScannerTimer = setInterval(async () => {
        if (qrScannerBusy || !qrScannerStream) return;
        qrScannerBusy = true;
        try {
          const codes = await detector.detect(video);
          const values = codes.map((code) => code.rawValue).filter(Boolean);
          if (values.length) {
            stopQrScanner();
            state.scannerOpen = false;
            try {
              applyImportPayload(values.join("\n"), true);
            } catch {
              state.importText = values.join("\n");
              state.importItems = [];
              state.importMessage = t("reasonUnsupported");
            }
            render();
          }
        } catch {
          // Transient decode failures are normal while scanning video frames.
        } finally {
          qrScannerBusy = false;
        }
      }, 500);
    } catch {
      stopQrScanner();
      state.scannerOpen = false;
      state.importMessage = t("scanUnavailable");
      render();
    }
  }

  function setMessage(message) {
    state.message = message;
    render();
  }

  async function deleteEntry(id) {
    if (!confirm(t("deleteEntryConfirm"))) return;
    await api(`/api/entries/${id}`, { method: "DELETE" });
    await deleteOfflineSecret(id);
    state.editingId = null;
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
    if (!code || code === "------") return;
    await navigator.clipboard.writeText(code);
    state.copiedId = id;
    renderOtpCodes();
    setTimeout(() => {
      state.copiedId = "";
      renderOtpCodes();
    }, 1200);
  }

  function toggleCodeVisibility(id) {
    const next = new Set(state.revealedEntryIds);
    if (next.has(id)) next.delete(id);
    else next.add(id);
    state.revealedEntryIds = next;
    render();
  }

  async function togglePinned(id) {
    const entry = state.entries.find((item) => item.id === id);
    if (!entry) return;
    await api(`/api/entries/${id}`, { method: "PATCH", body: JSON.stringify({ pinned: !entry.pinned }) });
    await loadUserData();
    render();
  }

  async function deleteAccount() {
    if (!confirm(t("deleteAccountConfirm"))) return;
    await api("/api/me", { method: "DELETE" });
    await clearCurrentOfflineSecrets();
    await clearOfflineSession(true);
    clearUserSession();
    render();
  }

  async function syncNow() {
    if (!state.online) return;
    try {
      await loadUserData();
      state.pwaMessage = t("syncDone");
    } catch {
      state.pwaMessage = t("serverError");
    }
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
    try {
      await clearOfflineSession(false);
    } catch {
      // Offline cache cleanup is best-effort during sign out.
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
    const formId = event.target.getAttribute("id");
    if (formId === "auth-form") await handleAuth(event.target);
    if (formId === "admin-auth-form") await handleAdminAuth(event.target);
    if (formId === "entry-form") await handleEntrySave(event.target);
    if (formId === "pat-form") await handlePatCreate(event.target);
    if (formId === "site-settings-form") await handleSiteSettingsSave(event.target);
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
      state.editingId = null;
      render();
      return;
    }
    if (target.dataset.entryId) {
      state.editingId = target.dataset.entryId;
      state.settingsOpen = false;
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
      state.settingsOpen = false;
      render();
    }
    if (action === "toggle-settings") {
      state.settingsOpen = !state.settingsOpen;
      state.editingId = null;
      render();
    }
    if (action === "sync-now") await syncNow();
    if (action === "clear-edit") {
      state.editingId = null;
      state.message = "";
      render();
    }
    if (action === "delete-entry") await deleteEntry(id);
    if (action === "next-hotp") await nextHotp(id);
    if (action === "copy") await copyCode(id);
    if (action === "toggle-code") toggleCodeVisibility(id);
    if (action === "toggle-pin") await togglePinned(id);
    if (action === "logout") await logout();
    if (action === "delete-account") await deleteAccount();
    if (action === "open-import") {
      state.importOpen = true;
      state.importMessage = "";
      render();
    }
    if (action === "close-import") {
      stopQrScanner();
      state.importOpen = false;
      state.importMessage = "";
      state.scannerOpen = false;
      render();
    }
    if (action === "open-scanner") {
      state.scannerOpen = true;
      state.importMessage = t("scanStarting");
      render();
      await startQrScanner();
    }
    if (action === "close-scanner") {
      stopQrScanner();
      state.scannerOpen = false;
      state.importMessage = "";
      render();
    }
    if (action === "parse-import") parseCurrentImportText();
    if (action === "import-all") await importPreviewItems(false);
    if (action === "import-selected") await importPreviewItems(true);
    if (action === "clear-filters") {
      state.search = "";
      state.groupFilter = "all";
      render();
    }
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
    if (event.target.dataset.action === "sort-mode") {
      state.sortMode = event.target.value;
      render();
      return;
    }
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
    if (state.entries.length) refreshOtpCodes();
  }, 1000);

  window.addEventListener("online", async () => {
    state.online = true;
    if (state.userToken) await syncNow();
    render();
  });

  window.addEventListener("offline", () => {
    state.online = false;
    state.pwaMessage = t("offlineUsingCache");
    render();
  });

  if ("serviceWorker" in navigator && window.location.protocol !== "file:") {
    navigator.serviceWorker
      .register("/service-worker.js")
      .then(() => navigator.serviceWorker.ready)
      .then((registration) => {
        state.serviceWorkerReady = true;
        registration.active?.postMessage({ type: "refresh-shell" });
        registration.update();
        render();
      })
      .catch(() => {
        state.serviceWorkerReady = false;
      });
  }

  bootstrap()
    .catch(async () => {
      try {
        const snapshot = await loadActiveOfflineSnapshot();
        if (snapshot?.user && Array.isArray(snapshot.entries)) {
          state.user = snapshot.user;
          state.groups = Array.isArray(snapshot.groups) ? snapshot.groups : [];
          state.entries = snapshot.entries;
          state.pats = [];
          state.online = false;
          state.pwaMessage = t("offlineUsingCache");
          await loadOfflineSecrets();
          await refreshOtpCodes();
          return;
        }
      } catch {
        // Fall through to the normal startup error.
      }
      state.message = t("serverError");
      state.adminMessage = t("serverError");
    })
    .finally(() => {
      syncRouteFromLocation();
      render();
    });
})();
