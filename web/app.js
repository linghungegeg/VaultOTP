(() => {
  const USERS_KEY = "vaultotp.users.v1";
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
  };

  const state = {
    authMode: "login",
    userEmail: "",
    cryptoKey: null,
    vault: null,
    editingId: null,
    groupFilter: "all",
    search: "",
    message: "",
    otpCodes: new Map(),
    copiedId: "",
    renderScheduled: false,
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

  async function saveVault() {
    const users = readUsers();
    const user = users[state.userEmail];
    user.vault = await encryptVault(state.vault, state.cryptoKey);
    writeUsers(users);
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
    if (!state.userEmail) {
      renderAuth();
      return;
    }
    renderApp();
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
      </section>
    `;
  }

  function renderApp() {
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
          <button class="primary" data-action="new-entry">${t("addEntry")}</button>
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
      const vaultSalt = randomBase64(16);
      const passwordHash = toBase64(await deriveBits(password, passwordSalt));
      const cryptoKey = await deriveKey(password, vaultSalt);
      const vault = emptyVault();
      users[email] = {
        passwordSalt,
        vaultSalt,
        passwordHash,
        vault: await encryptVault(vault, cryptoKey),
        createdAt: new Date().toISOString(),
      };
      writeUsers(users);
      state.userEmail = email;
      state.cryptoKey = cryptoKey;
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

    const passwordHash = toBase64(await deriveBits(password, user.passwordSalt));
    if (passwordHash !== user.passwordHash) {
      setMessage(t("invalidLogin"));
      return;
    }

    try {
      state.cryptoKey = await deriveKey(password, user.vaultSalt);
      state.vault = await decryptVault(user.vault, state.cryptoKey);
      state.userEmail = email;
      state.message = "";
      state.editingId = null;
      await refreshOtpCodes();
      render();
    } catch {
      setMessage(t("invalidLogin"));
    }
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
    state.userEmail = "";
    state.cryptoKey = null;
    state.vault = null;
    state.editingId = null;
    state.message = "";
    state.otpCodes = new Map();
    render();
  }

  function logout() {
    state.userEmail = "";
    state.cryptoKey = null;
      state.vault = null;
      state.editingId = null;
      state.message = "";
      state.otpCodes = new Map();
      render();
  }

  document.addEventListener("submit", async (event) => {
    event.preventDefault();
    const formId = event.target.getAttribute("id");
    if (formId === "auth-form") {
      await handleAuth(event.target);
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

    if (target.classList.contains("entry")) {
      state.editingId = target.dataset.entryId;
      state.message = "";
      render();
      return;
    }

    const action = target.dataset.action;
    const id = target.dataset.id;
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
  });

  setInterval(() => {
    if (state.vault) {
      refreshOtpCodes();
    }
  }, 1000);

  render();
})();
