(() => {
  const USERS_KEY = "vaultotp.users.v1";
  const ADMIN_KEY = "vaultotp.admin.v1";
  const ADMIN_AUDIT_KEY = "vaultotp.admin.audit.v1";
  const ITERATIONS = 120000;

  const textEncoder = new TextEncoder();
  const textDecoder = new TextDecoder();

  const dictionary = {
    login: "登录",
    register: "注册",
    email: "邮箱",
    password: "密码",
    confirmPassword: "确认密码",
    createAccount: "创建账号",
    loginAction: "登录",
    logout: "退出",
    deleteAccount: "删除账号",
    deleteAccountConfirm: "确定删除当前账号和本地 vault 吗？",
    addEntry: "添加条目",
    editEntry: "编辑条目",
    save: "保存",
    cancel: "取消",
    delete: "删除",
    deleteEntryConfirm: "确定删除这个 2FA 条目吗？",
    search: "搜索",
    allGroups: "全部",
    issuer: "服务",
    account: "账号",
    secret: "Secret",
    type: "类型",
    algorithm: "算法",
    digits: "位数",
    period: "周期",
    counter: "计数器",
    group: "分组",
    newGroup: "新分组",
    note: "备注",
    icon: "图标",
    copy: "复制",
    copied: "已复制",
    next: "下一个",
    entries: "条目",
    noEntries: "没有匹配的 2FA 条目",
    required: "请填写必要字段",
    invalidEmail: "邮箱格式不正确",
    passwordMismatch: "两次密码不一致",
    userExists: "账号已存在",
    invalidLogin: "邮箱或密码不正确",
    invalidSecret: "Secret 不是有效 Base32",
    authTitle: "VaultOTP",
    authSubtitle: "本地 Web 用户端 MVP",
    currentUser: "当前用户",
    localOnly: "本地 vault",
    importEntries: "导入",
    importTitle: "导入 2FA",
    importSource: "导入内容",
    importHint: "粘贴 otpauth URI、Google migration URI，或 Aegis / 2FAS / 2FAuth JSON。",
    parseImport: "解析",
    importSelected: "导入选中",
    importAll: "导入全部",
    close: "关闭",
    preview: "预览",
    status: "状态",
    valid: "可导入",
    duplicate: "重复",
    invalid: "无效",
    selected: "选中",
    source: "来源",
    importEmpty: "没有可预览的导入条目",
    importRequired: "请先粘贴或选择导入内容",
    importDone: "导入完成",
    importNoSelection: "没有选中的可导入条目",
    chooseFile: "选择文件",
    importFileUnsupported: "无法读取文件内容",
    reasonDuplicate: "已有相同条目",
    reasonInvalidSecret: "Secret 无效",
    reasonMissingFields: "缺少必要字段",
    reasonUnsupported: "未识别的导入格式",
    adminEntry: "Admin 后台",
    userEntry: "用户端",
    adminTitle: "VaultOTP Admin",
    adminSubtitle: "独立后台",
    setupAdmin: "创建唯一 Admin",
    adminLogin: "Admin 登录",
    adminExists: "Admin 已存在",
    adminRequired: "请先创建 Admin",
    adminUseAdminLogin: "Admin 请从后台入口登录",
    userUseUserLogin: "普通用户不能登录 Admin 后台",
    disabledAccount: "账号已禁用",
    users: "用户",
    auditLogs: "审计",
    userList: "用户列表",
    userDetail: "用户详情",
    accountStatus: "账号状态",
    active: "启用",
    disabled: "禁用",
    disableUser: "禁用用户",
    deleteUser: "删除用户",
    disableUserConfirm: "确定禁用这个用户吗？",
    adminDeleteUserConfirm: "确定删除这个用户和本地 vault 吗？",
    noUsers: "暂无普通用户",
    noUserSelected: "请选择用户",
    noAdminAccess: "该用户 vault 尚无 Admin 访问封套；用户下次登录或保存后会补齐。",
    noAdminAccount: "尚未创建 Admin",
    savedItems: "保存项",
    viewSecret: "查看 Secret",
    viewOtp: "查看验证码",
    hiddenByDefault: "默认隐藏",
    lastLogin: "上次登录",
    createdAt: "创建时间",
    updatedAt: "更新时间",
    adminLogout: "退出后台",
    targetUser: "目标用户",
    action: "操作",
    time: "时间",
    adminBackToUser: "返回用户端",
    adminCreateHint: "先创建唯一 Admin，再管理用户。",
    adminLoginHint: "使用 Admin 账号进入独立后台。",
    adminSetupTitle: "创建 Admin",
    adminLoginTitle: "Admin 登录",
    adminUsersTitle: "用户管理",
    adminAuditTitle: "审计记录",
    adminViewSecret: "查看 Secret",
    adminViewOtp: "查看验证码",
    adminDisable: "禁用",
    adminDelete: "删除",
    adminNoSelection: "请选择一个用户",
    loading: "加载中",
  };

  const state = {
    route: "app",
    authMode: "login",
    userEmail: "",
    cryptoKey: null,
    vaultKeyBytes: null,
    vault: null,
    editingId: null,
    groupFilter: "all",
    search: "",
    message: "",
    otpCodes: new Map(),
    copiedId: "",
    renderScheduled: false,
    importOpen: false,
    importText: "",
    importItems: [],
    importMessage: "",
    adminEmail: "",
    adminPrivateKey: null,
    adminPublicKey: null,
    adminSelectedUserEmail: "",
    adminVault: null,
    adminMessage: "",
    adminReveals: {},
  };

  const app = document.getElementById("app");

  const t = (key) => dictionary[key] || key;
  const uid = () => `${Date.now().toString(36)}${crypto.getRandomValues(new Uint32Array(1))[0].toString(36)}`;

  function escapeHtml(value) {
    return String(value ?? "")
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;")
      .replaceAll("'", "&#039;");
  }

  function readUsers() {
    try {
      return JSON.parse(localStorage.getItem(USERS_KEY) || "{}");
    } catch {
      return {};
    }
  }

  function writeUsers(users) {
    localStorage.setItem(USERS_KEY, JSON.stringify(users));
  }

  function readAuditLogs() {
    try {
      return JSON.parse(localStorage.getItem(ADMIN_AUDIT_KEY) || "[]");
    } catch {
      return [];
    }
  }

  function writeAuditLogs(logs) {
    localStorage.setItem(ADMIN_AUDIT_KEY, JSON.stringify(logs));
  }

  function readAdmin() {
    try {
      return JSON.parse(localStorage.getItem(ADMIN_KEY) || "null");
    } catch {
      return null;
    }
  }

  function writeAdmin(admin) {
    if (!admin) {
      localStorage.removeItem(ADMIN_KEY);
      return;
    }
    localStorage.setItem(ADMIN_KEY, JSON.stringify(admin));
  }

  function toBase64(bytes) {
    return btoa(String.fromCharCode(...new Uint8Array(bytes)));
  }

  function fromBase64(value) {
    return Uint8Array.from(atob(value), (char) => char.charCodeAt(0));
  }

  function randomBase64(length) {
    const bytes = new Uint8Array(length);
    crypto.getRandomValues(bytes);
    return toBase64(bytes);
  }

  async function deriveBits(password, saltBase64) {
    const material = await crypto.subtle.importKey(
      "raw",
      textEncoder.encode(password),
      "PBKDF2",
      false,
      ["deriveBits", "deriveKey"],
    );

    return crypto.subtle.deriveBits(
      {
        name: "PBKDF2",
        salt: fromBase64(saltBase64),
        iterations: ITERATIONS,
        hash: "SHA-256",
      },
      material,
      256,
    );
  }

  async function deriveKey(password, saltBase64) {
    const material = await crypto.subtle.importKey(
      "raw",
      textEncoder.encode(password),
      "PBKDF2",
      false,
      ["deriveKey"],
    );

    return crypto.subtle.deriveKey(
      {
        name: "PBKDF2",
        salt: fromBase64(saltBase64),
        iterations: ITERATIONS,
        hash: "SHA-256",
      },
      material,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"],
    );
  }

  async function importAesKey(rawBytes) {
    return crypto.subtle.importKey("raw", rawBytes, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
  }

  function randomBytes(length) {
    const bytes = new Uint8Array(length);
    crypto.getRandomValues(bytes);
    return bytes;
  }

  async function encryptBytes(bytes, key) {
    const iv = new Uint8Array(12);
    crypto.getRandomValues(iv);
    const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, bytes);
    return {
      iv: toBase64(iv),
      data: toBase64(ciphertext),
    };
  }

  async function decryptBytes(record, key) {
    return new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: fromBase64(record.iv) }, key, fromBase64(record.data)));
  }

  async function generateAdminKeyPair(password, keySalt) {
    const pair = await crypto.subtle.generateKey(
      {
        name: "RSA-OAEP",
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: "SHA-256",
      },
      true,
      ["encrypt", "decrypt"],
    );
    const privateJwk = await crypto.subtle.exportKey("jwk", pair.privateKey);
    const publicJwk = await crypto.subtle.exportKey("jwk", pair.publicKey);
    const key = await deriveKey(password, keySalt);
    return {
      publicKey: publicJwk,
      privateKey: await encryptBytes(textEncoder.encode(JSON.stringify(privateJwk)), key),
    };
  }

  async function importAdminPublicKey(jwk) {
    return crypto.subtle.importKey("jwk", jwk, { name: "RSA-OAEP", hash: "SHA-256" }, false, ["encrypt"]);
  }

  async function importAdminPrivateKey(jwk) {
    return crypto.subtle.importKey("jwk", jwk, { name: "RSA-OAEP", hash: "SHA-256" }, false, ["decrypt"]);
  }

  function hasAdmin() {
    return Boolean(readAdmin());
  }

  function adminRecord() {
    return readAdmin();
  }

  async function createAdminAccess(vaultKeyBytes, admin = readAdmin()) {
    if (!admin?.publicKey) {
      return null;
    }
    const publicKey = await importAdminPublicKey(admin.publicKey);
    const wrapped = await crypto.subtle.encrypt({ name: "RSA-OAEP" }, publicKey, vaultKeyBytes);
    return {
      version: 1,
      data: toBase64(wrapped),
    };
  }

  function publicUserRecords(users = readUsers()) {
    return Object.entries(users)
      .filter(([, user]) => user.role !== "admin")
      .map(([email, user]) => ({ email, user }))
      .sort((a, b) => a.email.localeCompare(b.email));
  }

  async function encryptVault(vault, key) {
    const iv = new Uint8Array(12);
    crypto.getRandomValues(iv);
    const ciphertext = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv },
      key,
      textEncoder.encode(JSON.stringify(vault)),
    );
    return {
      iv: toBase64(iv),
      data: toBase64(ciphertext),
    };
  }

  async function decryptVault(record, key) {
    const plaintext = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: fromBase64(record.iv) },
      key,
      fromBase64(record.data),
    );
    return JSON.parse(textDecoder.decode(plaintext));
  }

  async function createUserVaultKey(password, passwordSalt) {
    const vaultKeyBytes = randomBytes(32);
    const passwordKey = await deriveKey(password, passwordSalt);
    return {
      vaultKeyBytes,
      vaultKeyEncrypted: await encryptBytes(vaultKeyBytes, passwordKey),
    };
  }

  async function unwrapUserVaultKey(password, passwordSalt, encryptedVaultKey) {
    const passwordKey = await deriveKey(password, passwordSalt);
    return decryptBytes(encryptedVaultKey, passwordKey);
  }

  async function createAdminRecord(password, email) {
    const passwordSalt = randomBase64(16);
    const passwordHash = toBase64(await deriveBits(password, passwordSalt));
    const keyPair = await generateAdminKeyPair(password, passwordSalt);
    return {
      email,
      passwordSalt,
      passwordHash,
      publicKey: keyPair.publicKey,
      privateKeyEncrypted: keyPair.privateKey,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      lastLoginAt: null,
    };
  }

  async function decryptAdminPrivateKey(admin, password) {
    const key = await deriveKey(password, admin.passwordSalt);
    const privateJwkJson = textDecoder.decode(await decryptBytes(admin.privateKeyEncrypted, key));
    const privateJwk = JSON.parse(privateJwkJson);
    return importAdminPrivateKey(privateJwk);
  }

  async function saveVault() {
    const users = readUsers();
    const user = users[state.userEmail];
    if (!user || user.status === "disabled") {
      logout();
      return;
    }
    user.vault = await encryptVault(state.vault, state.cryptoKey);
    user.updatedAt = new Date().toISOString();
    if (state.vaultKeyBytes && hasAdmin()) {
      user.adminAccess = await createAdminAccess(state.vaultKeyBytes);
    }
    writeUsers(users);
  }

  function currentUserRecord() {
    const users = readUsers();
    return users[state.userEmail] || null;
  }

  function currentAdminRecord() {
    return readAdmin();
  }

  function isCurrentUserActive() {
    const user = currentUserRecord();
    return Boolean(user && user.status !== "disabled");
  }

  function syncRouteFromLocation() {
    const hashRoute = window.location.hash.replace(/^#\/?/, "");
    const route = window.location.pathname.startsWith("/admin") || hashRoute === "admin" ? "admin" : "app";
    state.route = route;
    if (route === "admin") {
      document.title = t("adminTitle");
    } else {
      document.title = t("authTitle");
    }
  }

  function goToRoute(route) {
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
    state.userEmail = "";
    state.cryptoKey = null;
    state.vaultKeyBytes = null;
    state.vault = null;
    state.editingId = null;
    state.message = "";
    state.otpCodes = new Map();
  }

  function clearAdminSession() {
    state.adminEmail = "";
    state.adminPrivateKey = null;
    state.adminPublicKey = null;
    state.adminSelectedUserEmail = "";
    state.adminVault = null;
    state.adminMessage = "";
    state.adminReveals = {};
  }

  function appendAudit(action, targetUserEmail = "", targetEntryId = "", extra = {}) {
    const logs = readAuditLogs();
    logs.unshift({
      id: uid(),
      actor_admin_id: state.adminEmail,
      target_user_id: targetUserEmail,
      target_entry_id: targetEntryId,
      action,
      ip: "local",
      user_agent: navigator.userAgent,
      created_at: new Date().toISOString(),
      ...extra,
    });
    writeAuditLogs(logs.slice(0, 200));
  }

  function scheduleRender() {
    if (state.renderScheduled) {
      return;
    }
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
      if (chunk.length < 5) {
        output += alphabet[parseInt(chunk.padEnd(5, "0"), 2)];
      } else {
        output += alphabet[parseInt(chunk, 2)];
      }
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
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
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
    if (url.protocol !== "otpauth:") {
      throw new Error(t("reasonUnsupported"));
    }
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
      if ((byte & 0x80) === 0) {
        return { value: result, next: index };
      }
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

  function decodeUtf8(bytes) {
    return textDecoder.decode(bytes);
  }

  function parseGoogleOtpParameter(bytes) {
    const parsed = {};
    for (const item of readProtoFields(bytes)) {
      if (item.field === 1) parsed.secret = bytesToBase32(item.value);
      if (item.field === 2) parsed.name = decodeUtf8(item.value);
      if (item.field === 3) parsed.issuer = decodeUtf8(item.value);
      if (item.field === 4) parsed.algorithm = { 1: "SHA-1", 2: "SHA-256", 3: "SHA-512" }[item.value] || "SHA-1";
      if (item.field === 5) parsed.digits = { 1: 6, 2: 8 }[item.value] || 6;
      if (item.field === 6) parsed.type = { 1: "HOTP", 2: "TOTP" }[item.value] || "TOTP";
      if (item.field === 7) parsed.counter = item.value;
      if (item.field === 8) parsed.period = item.value;
    }
    const issuerPrefix = parsed.issuer ? `${parsed.issuer}:` : "";
    const account = parsed.name && parsed.name.startsWith(issuerPrefix) ? parsed.name.slice(issuerPrefix.length) : parsed.name;
    return normalizeImportedEntry(
      {
        issuer: parsed.issuer,
        account,
        secret: parsed.secret,
        type: parsed.type,
        algorithm: parsed.algorithm,
        digits: parsed.digits,
        counter: parsed.counter,
        period: parsed.period,
      },
      "Google Authenticator",
    );
  }

  function parseGoogleMigrationUri(uri) {
    const url = new URL(uri.trim());
    if (url.protocol !== "otpauth-migration:") {
      throw new Error(t("reasonUnsupported"));
    }
    const data = url.searchParams.get("data");
    if (!data) {
      throw new Error(t("reasonUnsupported"));
    }
    const payload = fromBase64(data.replaceAll(" ", "+"));
    return readProtoFields(payload)
      .filter((item) => item.field === 1 && item.wireType === 2)
      .map((item) => parseGoogleOtpParameter(item.value));
  }

  function parseAegisJson(json) {
    if (!json?.db?.entries || !Array.isArray(json.db.entries)) {
      return [];
    }
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
    if (!Array.isArray(json?.services)) {
      return [];
    }
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
    if (!String(json?.app || "").startsWith("2fauth_") || !json?.schema || !Array.isArray(json?.data)) {
      return [];
    }
    return json.data.flatMap((item) => {
      if (item.legacy_uri) {
        try {
          return [parseOtpAuthUri(item.legacy_uri, "2FAuth JSON")];
        } catch {
          return [];
        }
      }
      return [
        normalizeImportedEntry(
          {
            issuer: item.service,
            account: item.account,
            secret: item.secret,
            type: item.otp_type,
            algorithm: item.algorithm,
            digits: item.digits,
            period: item.period,
            counter: item.counter,
          },
          "2FAuth JSON",
        ),
      ];
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
        if (item.secret) {
          return [normalizeImportedEntry(item, "JSON")];
        }
        return [];
      });
  }

  function parseJsonImport(text) {
    const json = JSON.parse(text);
    return [
      ...parseAegisJson(json),
      ...parseTwoFasJson(json),
      ...parseTwoFAuthJson(json),
      ...parseGenericJson(json),
    ];
  }

  function parseImportPayload(text) {
    const trimmed = text.trim();
    if (!trimmed) {
      return [];
    }
    const results = [];
    if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
      results.push(...parseJsonImport(trimmed));
    }
    const lines = trimmed.split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
    for (const line of lines) {
      if (line.startsWith("otpauth://")) {
        results.push(parseOtpAuthUri(line));
      }
      if (line.startsWith("otpauth-migration://")) {
        results.push(...parseGoogleMigrationUri(line));
      }
    }
    return results;
  }

  function previewImportItems(entries) {
    const existingKeys = new Set(state.vault.entries.map(entryDuplicateKey));
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
      return {
        id: uid(),
        entry,
        status,
        reason,
        selected: status === "valid",
      };
    });
  }

  function counterBytes(counter) {
    const bytes = new ArrayBuffer(8);
    const view = new DataView(bytes);
    const high = Math.floor(counter / 0x100000000);
    const low = counter >>> 0;
    view.setUint32(0, high);
    view.setUint32(4, low);
    return bytes;
  }

  async function hotp(secret, counter, digits, algorithm) {
    const key = await crypto.subtle.importKey(
      "raw",
      base32ToBytes(secret),
      { name: "HMAC", hash: algorithm },
      false,
      ["sign"],
    );
    const signature = new Uint8Array(await crypto.subtle.sign("HMAC", key, counterBytes(counter)));
    const offset = signature[signature.length - 1] & 0x0f;
    const binary =
      ((signature[offset] & 0x7f) << 24) |
      ((signature[offset + 1] & 0xff) << 16) |
      ((signature[offset + 2] & 0xff) << 8) |
      (signature[offset + 3] & 0xff);
    return String(binary % 10 ** digits).padStart(digits, "0");
  }

  async function codeFor(entry) {
    const digits = Number(entry.digits || 6);
    const algorithm = entry.algorithm || "SHA-1";
    if (entry.type === "HOTP") {
      return hotp(entry.secret, Number(entry.counter || 0), digits, algorithm);
    }
    const period = Number(entry.period || 30);
    const counter = Math.floor(Date.now() / 1000 / period);
    return hotp(entry.secret, counter, digits, algorithm);
  }

  function periodRemaining(entry) {
    if (entry.type === "HOTP") {
      return `#${entry.counter || 0}`;
    }
    const period = Number(entry.period || 30);
    return `${period - (Math.floor(Date.now() / 1000) % period)}s`;
  }

  async function refreshOtpCodes() {
    if (!state.vault) {
      return;
    }
    const codes = new Map();
    for (const entry of state.vault.entries) {
      try {
        codes.set(entry.id, await codeFor(entry));
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
      const entry = state.vault.entries.find((item) => item.id === id);
      node.textContent = entry ? periodRemaining(entry) : "";
    });
  }

  function emptyVault() {
    return {
      groups: [{ id: "default", name: "Default" }],
      entries: [],
    };
  }

  function findGroupName(groupId) {
    return (state.vault.groups.find((group) => group.id === groupId) || {}).name || "Default";
  }

  function filteredEntries() {
    const query = state.search.trim().toLowerCase();
    return state.vault.entries.filter((entry) => {
      const groupOk = state.groupFilter === "all" || entry.groupId === state.groupFilter;
      const text = `${entry.issuer} ${entry.account} ${entry.note} ${findGroupName(entry.groupId)}`.toLowerCase();
      return groupOk && (!query || text.includes(query));
    });
  }

  function selectedEntry() {
    return state.vault.entries.find((entry) => entry.id === state.editingId) || null;
  }

  function render() {
    syncRouteFromLocation();
    if (state.route === "admin") {
      if (!state.adminEmail) {
        renderAdminAuth();
        return;
      }
      renderAdminApp();
      return;
    }
    if (state.userEmail && !isCurrentUserActive()) {
      clearUserSession();
    }
    if (!state.userEmail) {
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
    const admin = readAdmin();
    const setupMode = !admin;
    app.innerHTML = `
      <section class="auth-panel admin-auth">
        <div class="brand-row">
          <div>
            <div class="brand">${t("adminTitle")}</div>
            <div class="muted">${setupMode ? t("adminCreateHint") : t("adminLoginHint")}</div>
          </div>
          <button class="ghost" type="button" data-route="app">${t("adminBackToUser")}</button>
        </div>
        <div class="tabs">
          ${
            setupMode
              ? `<button class="tab active" disabled>${t("adminSetupTitle")}</button>`
              : `<button class="tab active" disabled>${t("adminLoginTitle")}</button>`
          }
        </div>
        <form id="admin-auth-form">
          <div class="field">
            <label for="adminEmail">${t("email")}</label>
            <input id="adminEmail" name="email" type="email" autocomplete="username" required value="${escapeHtml(state.adminEmail)}" />
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
              <div class="brand">VaultOTP</div>
              <div class="muted">${t("localOnly")}</div>
            </div>
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
            ${groupButton("all", t("allGroups"), state.vault.entries.length)}
            ${state.vault.groups.map((group) => groupButton(group.id, group.name, countGroup(group.id))).join("")}
          </div>
        </aside>
        <main class="main">
          <header class="topbar">
            <div>
              <strong>${t("entries")}</strong>
              <span class="muted">${entries.length}</span>
            </div>
            <div class="inline-actions">
              <span class="muted">${t("currentUser")}: ${escapeHtml(state.userEmail)}</span>
              <button class="ghost" data-action="logout">${t("logout")}</button>
              <button class="danger" data-action="delete-account">${t("deleteAccount")}</button>
            </div>
          </header>
          <section class="main-content">
            ${
              entries.length
                ? `<div class="entry-list">${entries.map(entryView).join("")}</div>`
                : `<div class="empty">${t("noEntries")}</div>`
            }
          </section>
        </main>
        <aside class="inspector">
          ${entryForm()}
        </aside>
      </div>
      ${state.importOpen ? importPanel() : ""}
    `;
  }

  function renderAdminApp() {
    app.className = "screen admin-screen";
    const users = publicUserRecords();
    const selected = users.find((item) => item.email === state.adminSelectedUserEmail) || users[0] || null;
    if (selected && selected.email !== state.adminSelectedUserEmail) {
      state.adminSelectedUserEmail = selected.email;
    }
    const needsLoad = selected && (!state.adminVault || state.adminVault.email !== selected.email);
    if (needsLoad) {
      loadAdminUser(selected.email);
    }
    const audits = readAuditLogs();
    app.innerHTML = `
      <div class="admin-layout">
        <aside class="admin-sidebar">
          <div class="brand-row">
            <div>
              <div class="brand">${t("adminTitle")}</div>
              <div class="muted">${escapeHtml(state.adminEmail)}</div>
            </div>
            <button class="ghost" type="button" data-route="app">${t("adminBackToUser")}</button>
          </div>
          <div class="sidebar-section">
            <div class="section-title">${t("adminUsersTitle")}</div>
            <div class="admin-user-list">
              ${
                users.length
                  ? users
                      .map(
                        ({ email, user }) => `
                          <button class="admin-user-item ${state.adminSelectedUserEmail === email ? "active" : ""}" data-admin-user="${escapeHtml(email)}">
                            <span>${escapeHtml(email)}</span>
                            <span class="badge ${user.status === "disabled" ? "disabled-badge" : ""}">${escapeHtml(user.status || "active")}</span>
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
              ${
                audits.length
                  ? audits.slice(0, 12).map(adminAuditRow).join("")
                  : `<div class="empty">${t("auditLogs")}</div>`
              }
            </div>
          </div>
        </aside>
        <main class="admin-main">
          <header class="topbar admin-topbar">
            <div>
              <strong>${t("userDetail")}</strong>
              <span class="muted">${selected ? escapeHtml(selected.email) : t("adminNoSelection")}</span>
            </div>
            <div class="inline-actions">
              <button class="ghost" type="button" data-action="admin-logout">${t("adminLogout")}</button>
            </div>
          </header>
          <section class="admin-content">
            ${selected ? (needsLoad ? `<div class="empty">${t("loading")}</div>` : adminDetailPanel(selected)) : `<div class="empty">${t("adminNoSelection")}</div>`}
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

  function countGroup(groupId) {
    return state.vault.entries.filter((entry) => entry.groupId === groupId).length;
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
            ${
              entry.type === "HOTP"
                ? `<button class="icon-button" data-action="next-hotp" data-id="${entry.id}">${t("next")}</button>`
                : ""
            }
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
      secret: "",
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
          <input name="secret" required value="${escapeHtml(data.secret)}" />
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
              ${state.vault.groups.map((group) => `<option value="${group.id}" ${data.groupId === group.id ? "selected" : ""}>${escapeHtml(group.name)}</option>`).join("")}
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
    if (!state.importItems.length) {
      return `<div class="empty">${t("importEmpty")}</div>`;
    }
    return `
      <div class="import-preview" aria-label="${t("preview")}">
        ${state.importItems.map(importPreviewRow).join("")}
      </div>
    `;
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
        <span>${escapeHtml(log.created_at)}</span>
        <span>${escapeHtml(log.action)}</span>
        <span>${escapeHtml(log.target_user_id || "-")}</span>
        <span>${escapeHtml(log.target_entry_id || "-")}</span>
      </div>
    `;
  }

  function adminDetailPanel(selected) {
    const vaultState = state.adminVault && state.adminVault.email === selected.email ? state.adminVault : null;
    const user = selected.user;
    const entries = vaultState?.vault?.entries || [];
    return `
      <section class="admin-detail">
        <div class="admin-summary">
          <div>
            <div class="section-title">${t("userDetail")}</div>
            <div class="muted">${escapeHtml(selected.email)}</div>
          </div>
          <div class="inline-actions">
            <button class="danger" type="button" data-action="admin-disable-user" data-id="${escapeHtml(selected.email)}">${t("adminDisable")}</button>
            <button class="danger" type="button" data-action="admin-delete-user" data-id="${escapeHtml(selected.email)}">${t("adminDelete")}</button>
          </div>
        </div>
        <div class="detail-grid">
          <div class="detail-item">
            <span class="muted">${t("accountStatus")}</span>
            <strong>${escapeHtml(user.status || "active")}</strong>
          </div>
          <div class="detail-item">
            <span class="muted">${t("createdAt")}</span>
            <strong>${escapeHtml(user.createdAt || "-")}</strong>
          </div>
          <div class="detail-item">
            <span class="muted">${t("lastLogin")}</span>
            <strong>${escapeHtml(user.lastLoginAt || "-")}</strong>
          </div>
          <div class="detail-item">
            <span class="muted">${t("savedItems")}</span>
            <strong>${entries.length}</strong>
          </div>
        </div>
        <div class="section-title">${t("savedItems")}</div>
        ${
          vaultState?.error
            ? `<div class="empty">${escapeHtml(vaultState.error)}</div>`
            : entries.length
              ? `<div class="admin-entry-list">${entries.map((entry) => adminEntryRow(selected.email, entry)).join("")}</div>`
              : `<div class="empty">${t("noEntries")}</div>`
        }
      </section>
    `;
  }

  function adminEntryRow(userEmail, entry) {
    const reveal = state.adminReveals[entry.id] || {};
    const groups = state.adminVault?.vault?.groups || [];
    const groupName = (groups.find((group) => group.id === entry.groupId) || {}).name || "Default";
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
    const email = String(data.get("email") || "").trim().toLowerCase();
    const password = String(data.get("password") || "");
    const confirmPassword = String(data.get("confirmPassword") || "");

    if (!email.includes("@")) {
      setMessage(t("invalidEmail"));
      return;
    }
    if (!password) {
      setMessage(t("required"));
      return;
    }

    const users = readUsers();
    const admin = readAdmin();
    if (admin?.email === email) {
      setMessage(t("adminUseAdminLogin"));
      return;
    }
    if (state.authMode === "register") {
      if (password !== confirmPassword) {
        setMessage(t("passwordMismatch"));
        return;
      }
      if (users[email]) {
        setMessage(t("userExists"));
        return;
      }

      const passwordSalt = randomBase64(16);
      const vaultKeySalt = randomBase64(16);
      const passwordHash = toBase64(await deriveBits(password, passwordSalt));
      const { vaultKeyBytes, vaultKeyEncrypted } = await createUserVaultKey(password, vaultKeySalt);
      const cryptoKey = await importAesKey(vaultKeyBytes);
      const vault = emptyVault();
      const now = new Date().toISOString();
      users[email] = {
        passwordSalt,
        vaultKeySalt,
        passwordHash,
        vaultKeyEncrypted,
        adminAccess: await createAdminAccess(vaultKeyBytes),
        status: "active",
        vault: await encryptVault(vault, cryptoKey),
        createdAt: now,
        updatedAt: now,
        lastLoginAt: now,
      };
      writeUsers(users);
      state.userEmail = email;
      state.cryptoKey = cryptoKey;
      state.vaultKeyBytes = vaultKeyBytes;
      state.vault = vault;
      state.message = "";
      await refreshOtpCodes();
      render();
      return;
    }

    const user = users[email];
    if (!user) {
      setMessage(t("invalidLogin"));
      return;
    }
    if (user.status === "disabled") {
      setMessage(t("disabledAccount"));
      return;
    }

    const passwordHash = toBase64(await deriveBits(password, user.passwordSalt));
    if (passwordHash !== user.passwordHash) {
      setMessage(t("invalidLogin"));
      return;
    }

    try {
      let vaultKeyBytes;
      let cryptoKey;
      let vault;
      if (user.vaultKeyEncrypted) {
        vaultKeyBytes = await unwrapUserVaultKey(password, user.vaultKeySalt, user.vaultKeyEncrypted);
        cryptoKey = await importAesKey(vaultKeyBytes);
        vault = await decryptVault(user.vault, cryptoKey);
      } else {
        const legacyKey = await deriveKey(password, user.vaultSalt);
        vault = await decryptVault(user.vault, legacyKey);
        vaultKeyBytes = randomBytes(32);
        cryptoKey = await importAesKey(vaultKeyBytes);
        const vaultKeySalt = randomBase64(16);
        const passwordKey = await deriveKey(password, vaultKeySalt);
        user.vaultKeySalt = vaultKeySalt;
        user.vaultKeyEncrypted = await encryptBytes(vaultKeyBytes, passwordKey);
        user.vault = await encryptVault(vault, cryptoKey);
      }
      const now = new Date().toISOString();
      user.status = user.status || "active";
      user.lastLoginAt = now;
      user.updatedAt = now;
      if (hasAdmin()) {
        user.adminAccess = await createAdminAccess(vaultKeyBytes);
      }
      writeUsers(users);
      state.cryptoKey = cryptoKey;
      state.vaultKeyBytes = vaultKeyBytes;
      state.vault = vault;
      state.userEmail = email;
      state.message = "";
      state.editingId = null;
      await refreshOtpCodes();
      render();
    } catch {
      setMessage(t("invalidLogin"));
    }
  }

  async function handleAdminAuth(form) {
    const data = new FormData(form);
    const email = String(data.get("email") || "").trim().toLowerCase();
    const password = String(data.get("password") || "");
    const confirmPassword = String(data.get("confirmPassword") || "");
    const admin = readAdmin();
    const setupMode = !admin;

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

    if (setupMode) {
      if (admin) {
        state.adminMessage = t("adminExists");
        render();
        return;
      }
      if (readUsers()[email]) {
        state.adminMessage = t("userUseUserLogin");
        render();
        return;
      }
      if (password !== confirmPassword) {
        state.adminMessage = t("passwordMismatch");
        render();
        return;
      }
      const record = await createAdminRecord(password, email);
      writeAdmin(record);
      state.adminMessage = "";
      render();
      return;
    }

    if (!admin) {
      state.adminMessage = t("adminRequired");
      render();
      return;
    }
    if (readUsers()[email]) {
      state.adminMessage = t("userUseUserLogin");
      render();
      return;
    }
    if (email !== admin.email) {
      state.adminMessage = t("invalidLogin");
      render();
      return;
    }
    const passwordHash = toBase64(await deriveBits(password, admin.passwordSalt));
    if (passwordHash !== admin.passwordHash) {
      state.adminMessage = t("invalidLogin");
      render();
      return;
    }

    try {
      state.adminPrivateKey = await decryptAdminPrivateKey(admin, password);
      state.adminPublicKey = admin.publicKey;
      state.adminEmail = admin.email;
      state.adminMessage = "";
      admin.lastLoginAt = new Date().toISOString();
      admin.updatedAt = admin.lastLoginAt;
      writeAdmin(admin);
      const first = publicUserRecords()[0];
      if (first) {
        await loadAdminUser(first.email, false);
      }
      render();
    } catch {
      state.adminMessage = t("invalidLogin");
      render();
    }
  }

  async function loadAdminUser(email, shouldRender = true) {
    const users = readUsers();
    const user = users[email];
    state.adminSelectedUserEmail = email;
    state.adminReveals = {};
    if (!user) {
      state.adminVault = null;
      if (shouldRender) render();
      return;
    }
    if (!state.adminPrivateKey || !user.adminAccess?.data) {
      state.adminVault = { email, user, vault: null, error: t("noAdminAccess") };
      if (shouldRender) render();
      return;
    }
    try {
      const vaultKeyBytes = new Uint8Array(
        await crypto.subtle.decrypt({ name: "RSA-OAEP" }, state.adminPrivateKey, fromBase64(user.adminAccess.data)),
      );
      const vaultKey = await importAesKey(vaultKeyBytes);
      const vault = await decryptVault(user.vault, vaultKey);
      state.adminVault = { email, user, vault, vaultKeyBytes };
      state.adminMessage = "";
    } catch {
      state.adminVault = { email, user, vault: null, error: t("noAdminAccess") };
    }
    if (shouldRender) {
      render();
    }
  }

  async function revealAdminEntry(userEmail, entryId, field) {
    if (!state.adminVault || state.adminVault.email !== userEmail) {
      await loadAdminUser(userEmail, false);
    }
    const entry = state.adminVault?.vault?.entries?.find((item) => item.id === entryId);
    if (!entry) {
      return;
    }
    const reveal = state.adminReveals[entryId] || {};
    if (field === "secret") {
      reveal.secret = entry.secret;
      appendAudit("view_secret", userEmail, entryId);
    }
    if (field === "otp") {
      reveal.otp = await codeFor(entry);
      appendAudit("view_otp", userEmail, entryId);
    }
    state.adminReveals[entryId] = reveal;
    render();
  }

  async function disableAdminUser(email) {
    if (!confirm(t("disableUserConfirm"))) {
      return;
    }
    const users = readUsers();
    const user = users[email];
    if (!user) {
      return;
    }
    user.status = "disabled";
    user.updatedAt = new Date().toISOString();
    writeUsers(users);
    appendAudit("disable_user", email);
    await loadAdminUser(email, false);
    render();
  }

  async function deleteAdminUser(email) {
    if (!confirm(t("adminDeleteUserConfirm"))) {
      return;
    }
    const users = readUsers();
    if (!users[email]) {
      return;
    }
    delete users[email];
    writeUsers(users);
    appendAudit("delete_user", email);
    const next = publicUserRecords(users)[0];
    if (next) {
      await loadAdminUser(next.email, false);
    } else {
      state.adminSelectedUserEmail = "";
      state.adminVault = null;
    }
    render();
  }

  async function handleEntrySave(form) {
    const data = new FormData(form);
    const secret = normalizeSecret(data.get("secret"));
    try {
      base32ToBytes(secret);
    } catch {
      setMessage(t("invalidSecret"));
      return;
    }

    const id = String(data.get("id") || "");
    const issuer = String(data.get("issuer") || "").trim();
    const account = String(data.get("account") || "").trim();
    const entry = {
      id: id || uid(),
      issuer,
      account,
      secret,
      type: String(data.get("type") || "TOTP"),
      algorithm: String(data.get("algorithm") || "SHA-1"),
      digits: Number(data.get("digits") || 6),
      period: Number(data.get("period") || 30),
      counter: Number(data.get("counter") || 0),
      groupId: String(data.get("groupId") || "default"),
      note: String(data.get("note") || "").trim(),
      icon: String(data.get("icon") || "").trim(),
      updatedAt: new Date().toISOString(),
    };

    if (!entry.issuer || !entry.account || !entry.secret) {
      setMessage(t("required"));
      return;
    }

    const newGroup = String(data.get("newGroup") || "").trim();
    if (newGroup) {
      const existing = state.vault.groups.find((group) => group.name.toLowerCase() === newGroup.toLowerCase());
      if (existing) {
        entry.groupId = existing.id;
      } else {
        entry.groupId = uid();
        state.vault.groups.push({ id: entry.groupId, name: newGroup });
      }
    }

    const existingIndex = state.vault.entries.findIndex((item) => item.id === entry.id);
    if (existingIndex >= 0) {
      entry.createdAt = state.vault.entries[existingIndex].createdAt;
      state.vault.entries[existingIndex] = entry;
    } else {
      entry.createdAt = entry.updatedAt;
      state.vault.entries.unshift(entry);
    }

    state.editingId = entry.id;
    state.message = "";
    await saveVault();
    await refreshOtpCodes();
    render();
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

    const now = new Date().toISOString();
    for (const item of items) {
      state.vault.entries.unshift({
        ...item.entry,
        id: uid(),
        groupId: item.entry.groupId || "default",
        createdAt: now,
        updatedAt: now,
      });
    }

    state.importOpen = false;
    state.importText = "";
    state.importItems = [];
    state.importMessage = "";
    await saveVault();
    await refreshOtpCodes();
    render();
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
    if (!confirm(t("deleteEntryConfirm"))) {
      return;
    }
    state.vault.entries = state.vault.entries.filter((entry) => entry.id !== id);
    if (state.editingId === id) {
      state.editingId = null;
    }
    await saveVault();
    await refreshOtpCodes();
    render();
  }

  async function nextHotp(id) {
    const entry = state.vault.entries.find((item) => item.id === id);
    if (!entry) {
      return;
    }
    entry.counter = Number(entry.counter || 0) + 1;
    entry.updatedAt = new Date().toISOString();
    await saveVault();
    await refreshOtpCodes();
    render();
  }

  async function copyCode(id) {
    const code = state.otpCodes.get(id);
    if (!code || code === "------") {
      return;
    }
    await navigator.clipboard.writeText(code);
    state.copiedId = id;
    render();
    setTimeout(() => {
      state.copiedId = "";
      render();
    }, 1200);
  }

  async function deleteAccount() {
    if (!confirm(t("deleteAccountConfirm"))) {
      return;
    }
    const users = readUsers();
    delete users[state.userEmail];
    writeUsers(users);
    clearUserSession();
    render();
  }

  function logout() {
    clearUserSession();
    render();
  }

  function adminLogout() {
    clearAdminSession();
    render();
  }

  document.addEventListener("submit", async (event) => {
    event.preventDefault();
    const formId = event.target.getAttribute("id");
    if (formId === "auth-form") {
      await handleAuth(event.target);
    }
    if (formId === "admin-auth-form") {
      await handleAdminAuth(event.target);
    }
    if (formId === "entry-form") {
      await handleEntrySave(event.target);
    }
  });

  document.addEventListener("click", async (event) => {
    const target = event.target.closest("button, article.entry");
    if (!target) {
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

    if (target.dataset.adminUser) {
      await loadAdminUser(target.dataset.adminUser);
      return;
    }

    if (target.dataset.group) {
      state.groupFilter = target.dataset.group;
      render();
      return;
    }

    if (target.classList.contains("entry")) {
      state.editingId = target.dataset.entryId;
      state.message = "";
      render();
      return;
    }

    const action = target.dataset.action;
    const id = target.dataset.id;
    if (action === "admin-logout") {
      adminLogout();
    }
    if (action === "admin-disable-user") {
      await disableAdminUser(id);
    }
    if (action === "admin-delete-user") {
      await deleteAdminUser(id);
    }
    if (action === "admin-view-secret") {
      await revealAdminEntry(target.dataset.user, target.dataset.entry, "secret");
    }
    if (action === "admin-view-otp") {
      await revealAdminEntry(target.dataset.user, target.dataset.entry, "otp");
    }
    if (action === "new-entry") {
      state.editingId = null;
      state.message = "";
      render();
    }
    if (action === "clear-edit") {
      state.editingId = null;
      state.message = "";
      render();
    }
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
    if (action === "parse-import") {
      parseCurrentImportText();
    }
    if (action === "import-all") {
      await importPreviewItems(false);
    }
    if (action === "import-selected") {
      await importPreviewItems(true);
    }
    if (action === "delete-entry") {
      await deleteEntry(id);
    }
    if (action === "copy") {
      await copyCode(id);
    }
    if (action === "next-hotp") {
      await nextHotp(id);
    }
    if (action === "logout") {
      logout();
    }
    if (action === "delete-account") {
      await deleteAccount();
    }
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
      if (item && item.status === "valid") {
        item.selected = event.target.checked;
      }
    }
  });

  setInterval(() => {
    if (state.userEmail && !isCurrentUserActive()) {
      clearUserSession();
      render();
      return;
    }
    if (state.vault) {
      refreshOtpCodes();
    }
  }, 1000);

  window.addEventListener("popstate", () => {
    syncRouteFromLocation();
    render();
  });

  window.addEventListener("hashchange", () => {
    syncRouteFromLocation();
    render();
  });

  render();
})();
