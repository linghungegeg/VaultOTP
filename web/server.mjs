import { createServer } from "node:http";
import { readFile, rename, writeFile, mkdir } from "node:fs/promises";
import { extname, join, normalize, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { webcrypto, createHash, createHmac } from "node:crypto";

const { subtle } = webcrypto;
const getRandomValues = webcrypto.getRandomValues.bind(webcrypto);
const root = dirname(fileURLToPath(import.meta.url));
const storePath = normalize(process.env.VAULTOTP_STORE_PATH || join(root, "..", "vaultotp-store.json"));
const port = Number(process.env.PORT || 4173);
const host = process.env.HOST || "127.0.0.1";
const tokenTtlMs = 1000 * 60 * 60 * 24 * 30;
const contentTypes = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
};

let storeCache = null;

function jsonResponse(response, status, payload) {
  response.writeHead(status, {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Headers": "Authorization, Content-Type",
    "Access-Control-Allow-Methods": "GET,POST,PATCH,DELETE,OPTIONS",
    "Cache-Control": "no-store",
    "Content-Type": "application/json; charset=utf-8",
  });
  response.end(JSON.stringify(payload));
}

function textResponse(response, status, body) {
  response.writeHead(status, {
    "Cache-Control": "no-store",
    "Content-Type": "text/plain; charset=utf-8",
  });
  response.end(body);
}

function now() {
  return new Date().toISOString();
}

function uid() {
  const bytes = new Uint8Array(16);
  getRandomValues(bytes);
  return [...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

function base64(bytes) {
  return Buffer.from(bytes).toString("base64");
}

function fromBase64(value) {
  return new Uint8Array(Buffer.from(String(value || ""), "base64"));
}

function base32ToBuffer(secret) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const normalized = String(secret || "").replace(/\s+/g, "").replace(/=+$/g, "").toUpperCase();
  let bits = "";
  for (const char of normalized) {
    const value = alphabet.indexOf(char);
    if (value === -1) {
      throw new Error("invalid_secret");
    }
    bits += value.toString(2).padStart(5, "0");
  }
  const bytes = [];
  for (let index = 0; index + 8 <= bits.length; index += 8) {
    bytes.push(parseInt(bits.slice(index, index + 8), 2));
  }
  return Buffer.from(bytes);
}

function sha256Hex(value) {
  return createHash("sha256").update(String(value)).digest("hex");
}

function normalizeEmail(value) {
  return String(value || "").trim().toLowerCase();
}

function defaultStore() {
  return {
    schemaVersion: 1,
    crypto: null,
    admin: null,
    users: [],
    sessions: [],
    pats: [],
    groups: [],
    entries: [],
    auditLogs: [],
  };
}

async function loadStore() {
  if (storeCache) {
    return storeCache;
  }
  try {
    storeCache = JSON.parse(await readFile(storePath, "utf8"));
  } catch {
    storeCache = defaultStore();
    await saveStore(storeCache);
  }
  return storeCache;
}

async function saveStore(store) {
  await mkdir(dirname(storePath), { recursive: true });
  const tmpPath = `${storePath}.${process.pid}.tmp`;
  await writeFile(tmpPath, JSON.stringify(store, null, 2), "utf8");
  await rename(tmpPath, storePath);
  storeCache = store;
}

async function ensureCrypto(store) {
  if (store.crypto?.secretKeyPair?.publicKeyJwk && store.crypto?.secretKeyPair?.privateKeyJwk) {
    return store.crypto.secretKeyPair;
  }
  const pair = await subtle.generateKey(
    {
      name: "RSA-OAEP",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
    },
    true,
    ["encrypt", "decrypt"],
  );
  const publicKeyJwk = await subtle.exportKey("jwk", pair.publicKey);
  const privateKeyJwk = await subtle.exportKey("jwk", pair.privateKey);
  store.crypto = { secretKeyPair: { publicKeyJwk, privateKeyJwk } };
  await saveStore(store);
  return store.crypto.secretKeyPair;
}

async function importSecretPrivateKey(store) {
  const pair = await ensureCrypto(store);
  return subtle.importKey("jwk", pair.privateKeyJwk, { name: "RSA-OAEP", hash: "SHA-256" }, false, ["decrypt"]);
}

async function pbkdf2Hash(password, saltBase64) {
  const material = await subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await subtle.deriveBits(
    {
      name: "PBKDF2",
      salt: fromBase64(saltBase64),
      iterations: 120000,
      hash: "SHA-256",
    },
    material,
    256,
  );
  return base64(bits);
}

async function decryptSecret(store, encryptedSecret) {
  const privateKey = await importSecretPrivateKey(store);
  const plain = await subtle.decrypt({ name: "RSA-OAEP" }, privateKey, fromBase64(encryptedSecret));
  return new TextDecoder().decode(plain);
}

function hotp(secret, counter, digits, algorithm) {
  const key = base32ToBuffer(secret);
  const algo = String(algorithm || "SHA-1").replace("-", "").toLowerCase();
  const counterBytes = Buffer.alloc(8);
  counterBytes.writeUInt32BE(Math.floor(counter / 0x100000000), 0);
  counterBytes.writeUInt32BE(counter >>> 0, 4);
  const hmac = createHmac(algo, key);
  hmac.update(counterBytes);
  const digest = hmac.digest();
  const offset = digest[digest.length - 1] & 0x0f;
  const binary =
    ((digest[offset] & 0x7f) << 24) |
    ((digest[offset + 1] & 0xff) << 16) |
    ((digest[offset + 2] & 0xff) << 8) |
    (digest[offset + 3] & 0xff);
  return String(binary % 10 ** digits).padStart(digits, "0");
}

async function codeForEntry(store, entry) {
  const secret = await decryptSecret(store, entry.secretEncrypted);
  const digits = Number(entry.digits || 6);
  const algorithm = entry.algorithm || "SHA-1";
  if (entry.type === "HOTP") {
    return hotp(secret, Number(entry.counter || 0), digits, algorithm);
  }
  const period = Number(entry.period || 30);
  const counter = Math.floor(Date.now() / 1000 / period);
  return hotp(secret, counter, digits, algorithm);
}

function publicUser(user) {
  return {
    id: user.id,
    email: user.email,
    displayName: user.displayName || "",
    status: user.status || "active",
    lastLoginAt: user.lastLoginAt || null,
    createdAt: user.createdAt,
    updatedAt: user.updatedAt,
  };
}

function publicEntry(entry) {
  return {
    id: entry.id,
    userId: entry.userId,
    issuer: entry.issuer,
    account: entry.account,
    type: entry.type,
    encryptedSecret: entry.secretEncrypted,
    secretVersion: entry.secretVersion || 1,
    algorithm: entry.algorithm,
    digits: entry.digits,
    period: entry.period,
    counter: entry.counter,
    groupId: entry.groupId,
    note: entry.note || "",
    icon: entry.icon || "",
    createdAt: entry.createdAt,
    updatedAt: entry.updatedAt,
  };
}

function publicGroup(group) {
  return {
    id: group.id,
    userId: group.userId,
    name: group.name,
    sortOrder: group.sortOrder || 0,
    createdAt: group.createdAt,
    updatedAt: group.updatedAt,
  };
}

function publicPat(pat) {
  return {
    id: pat.id,
    userId: pat.userId,
    name: pat.name,
    lastUsedAt: pat.lastUsedAt || null,
    createdAt: pat.createdAt,
    revokedAt: pat.revokedAt || null,
  };
}

async function readJsonBody(request) {
  const chunks = [];
  for await (const chunk of request) {
    chunks.push(chunk);
  }
  if (!chunks.length) return {};
  return JSON.parse(Buffer.concat(chunks).toString("utf8"));
}

function findUser(store, email) {
  return store.users.find((user) => user.email === normalizeEmail(email)) || null;
}

function findUserById(store, id) {
  return store.users.find((user) => user.id === id) || null;
}

function findAdmin(store) {
  return store.admin || null;
}

function issueToken(prefix) {
  return `${prefix}_${uid()}${uid()}`;
}

async function createSession(store, kind, ownerId, ttlMs = tokenTtlMs) {
  const token = issueToken(kind === "admin" ? "adm" : "usr");
  store.sessions.push({
    id: uid(),
    kind,
    ownerId,
    tokenHash: sha256Hex(token),
    createdAt: now(),
    lastUsedAt: null,
    expiresAt: new Date(Date.now() + ttlMs).toISOString(),
  });
  await saveStore(store);
  return token;
}

async function resolveAuth(request, store) {
  const header = request.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7).trim() : "";
  if (!token) return null;
  const tokenHash = sha256Hex(token);
  const session = store.sessions.find(
    (item) => item.tokenHash === tokenHash && (!item.expiresAt || new Date(item.expiresAt).getTime() > Date.now()),
  );
  if (session) {
    session.lastUsedAt = now();
    await saveStore(store);
    if (session.kind === "admin") {
      const admin = findAdmin(store);
      if (admin && admin.id === session.ownerId && admin.status !== "disabled") {
        return { kind: "admin", admin };
      }
    } else {
      const user = findUserById(store, session.ownerId);
      if (user && user.status !== "disabled") {
        return { kind: "user", user, authType: "session" };
      }
    }
  }
  const pat = store.pats.find((item) => item.tokenHash === tokenHash && !item.revokedAt);
  if (pat) {
    const user = findUserById(store, pat.userId);
    if (user && user.status !== "disabled") {
      pat.lastUsedAt = now();
      await saveStore(store);
      return { kind: "user", user, authType: "pat", pat };
    }
  }
  return null;
}

function requireUser(ctx, response) {
  if (!ctx || ctx.kind !== "user") {
    jsonResponse(response, 403, { error: "forbidden" });
    return false;
  }
  return true;
}

function requireAdmin(ctx, response) {
  if (!ctx || ctx.kind !== "admin") {
    jsonResponse(response, 403, { error: "forbidden" });
    return false;
  }
  return true;
}

async function recordAudit(store, action, adminId, targetUserId = "", targetEntryId = "", details = {}) {
  store.auditLogs.unshift({
    id: uid(),
    actorAdminId: adminId,
    targetUserId,
    targetEntryId,
    action,
    ip: "local",
    userAgent: details.userAgent || "",
    createdAt: now(),
    details,
  });
  store.auditLogs = store.auditLogs.slice(0, 500);
  await saveStore(store);
}

function parseEntryBody(body) {
  return {
    issuer: String(body.issuer || "").trim(),
    account: String(body.account || "").trim(),
    type: String(body.type || "TOTP").toUpperCase() === "HOTP" ? "HOTP" : "TOTP",
    encryptedSecret: String(body.encryptedSecret || body.secretEncrypted || "").trim(),
    secretVersion: Number(body.secretVersion || 1),
    algorithm: String(body.algorithm || "SHA-1"),
    digits: Number(body.digits || 6),
    period: Number(body.period || 30),
    counter: Number(body.counter || 0),
    groupId: String(body.groupId || "").trim(),
    note: String(body.note || "").trim(),
    icon: String(body.icon || "").trim(),
  };
}

async function ensureDefaultGroup(store, userId) {
  let group = store.groups.find((item) => item.userId === userId && item.id === "default");
  if (!group) {
    group = {
      id: "default",
      userId,
      name: "Default",
      sortOrder: 0,
      createdAt: now(),
      updatedAt: now(),
    };
    store.groups.push(group);
  }
  return group;
}

async function handleApi(request, response, pathname) {
  const store = await loadStore();
  await ensureCrypto(store);
  if (request.method === "OPTIONS") {
    jsonResponse(response, 204, {});
    return;
  }

  const ctx = await resolveAuth(request, store);

  if (pathname === "/api/bootstrap" && request.method === "GET") {
    const pair = await ensureCrypto(store);
    jsonResponse(response, 200, { hasAdmin: Boolean(store.admin), secretPublicKey: pair.publicKeyJwk, serverTime: now() });
    return;
  }

  if (pathname === "/api/admin/setup" && request.method === "POST") {
    if (store.admin) {
      jsonResponse(response, 409, { error: "admin_exists" });
      return;
    }
    const body = await readJsonBody(request);
    const email = normalizeEmail(body.email);
    const password = String(body.password || "");
    if (!email.includes("@") || !password) {
      jsonResponse(response, 400, { error: "invalid_input" });
      return;
    }
    const passwordSalt = base64(webcrypto.getRandomValues(new Uint8Array(16)));
    store.admin = {
      id: uid(),
      email,
      passwordSalt,
      passwordHash: await pbkdf2Hash(password, passwordSalt),
      status: "active",
      createdAt: now(),
      updatedAt: now(),
      lastLoginAt: null,
    };
    await saveStore(store);
    const token = await createSession(store, "admin", store.admin.id);
    jsonResponse(response, 201, { admin: publicUser(store.admin), token });
    return;
  }

  if (pathname === "/api/admin/login" && request.method === "POST") {
    const body = await readJsonBody(request);
    const admin = findAdmin(store);
    const email = normalizeEmail(body.email);
    const password = String(body.password || "");
    if (!admin || admin.status === "disabled" || admin.email !== email) {
      jsonResponse(response, 401, { error: "invalid_login" });
      return;
    }
    const passwordHash = await pbkdf2Hash(password, admin.passwordSalt);
    if (passwordHash !== admin.passwordHash) {
      jsonResponse(response, 401, { error: "invalid_login" });
      return;
    }
    admin.lastLoginAt = now();
    admin.updatedAt = admin.lastLoginAt;
    await saveStore(store);
    await recordAudit(store, "admin_login", admin.id, "", "", { userAgent: request.headers["user-agent"] || "" });
    const token = await createSession(store, "admin", admin.id);
    jsonResponse(response, 200, { admin: publicUser(admin), token });
    return;
  }

  if (pathname === "/api/auth/register" && request.method === "POST") {
    const body = await readJsonBody(request);
    const email = normalizeEmail(body.email);
    const password = String(body.password || "");
    if (!email.includes("@") || !password) {
      jsonResponse(response, 400, { error: "invalid_input" });
      return;
    }
    if (findUser(store, email) || (store.admin && store.admin.email === email)) {
      jsonResponse(response, 409, { error: "user_exists" });
      return;
    }
    const passwordSalt = base64(webcrypto.getRandomValues(new Uint8Array(16)));
    const user = {
      id: uid(),
      email,
      displayName: String(body.displayName || "").trim(),
      passwordSalt,
      passwordHash: await pbkdf2Hash(password, passwordSalt),
      status: "active",
      createdAt: now(),
      updatedAt: now(),
      lastLoginAt: now(),
    };
    store.users.push(user);
    await ensureDefaultGroup(store, user.id);
    await saveStore(store);
    const token = await createSession(store, "user", user.id);
    jsonResponse(response, 201, { user: publicUser(user), token });
    return;
  }

  if (pathname === "/api/auth/login" && request.method === "POST") {
    const body = await readJsonBody(request);
    const email = normalizeEmail(body.email);
    const password = String(body.password || "");
    const user = findUser(store, email);
    if (!user || user.status === "disabled") {
      jsonResponse(response, 401, { error: "invalid_login" });
      return;
    }
    const passwordHash = await pbkdf2Hash(password, user.passwordSalt);
    if (passwordHash !== user.passwordHash) {
      jsonResponse(response, 401, { error: "invalid_login" });
      return;
    }
    user.lastLoginAt = now();
    user.updatedAt = user.lastLoginAt;
    await saveStore(store);
    const token = await createSession(store, "user", user.id);
    jsonResponse(response, 200, { user: publicUser(user), token });
    return;
  }

  if (pathname === "/api/auth/logout" && request.method === "POST") {
    if (!ctx) {
      jsonResponse(response, 200, { ok: true });
      return;
    }
    const tokenHash = sha256Hex(String((request.headers.authorization || "").slice(7).trim()));
    store.sessions = store.sessions.filter((item) => item.tokenHash !== tokenHash);
    await saveStore(store);
    jsonResponse(response, 200, { ok: true });
    return;
  }

  if (pathname === "/api/me" && request.method === "GET") {
    if (!ctx) {
      jsonResponse(response, 401, { error: "unauthorized" });
      return;
    }
    if (ctx.kind === "admin") {
      jsonResponse(response, 200, { role: "admin", admin: publicUser(ctx.admin) });
      return;
    }
    const pats = store.pats.filter((item) => item.userId === ctx.user.id && !item.revokedAt).map(publicPat);
    jsonResponse(response, 200, { role: "user", authType: ctx.authType || "session", user: publicUser(ctx.user), patCount: pats.length });
    return;
  }

  if (pathname === "/api/me" && request.method === "DELETE") {
    if (!requireUser(ctx, response)) return;
    const userId = ctx.user.id;
    store.users = store.users.filter((item) => item.id !== userId);
    store.entries = store.entries.filter((item) => item.userId !== userId);
    store.groups = store.groups.filter((item) => item.userId !== userId);
    store.pats = store.pats.filter((item) => item.userId !== userId);
    store.sessions = store.sessions.filter((item) => item.ownerId !== userId);
    await saveStore(store);
    jsonResponse(response, 200, { ok: true });
    return;
  }

  if (pathname === "/api/pats" && request.method === "GET") {
    if (!requireUser(ctx, response)) return;
    const pats = store.pats.filter((item) => item.userId === ctx.user.id).map(publicPat);
    jsonResponse(response, 200, { items: pats });
    return;
  }

  if (pathname === "/api/pats" && request.method === "POST") {
    if (!requireUser(ctx, response)) return;
    const body = await readJsonBody(request);
    const name = String(body.name || "").trim();
    if (!name) {
      jsonResponse(response, 400, { error: "invalid_input" });
      return;
    }
    const token = issueToken("pat");
    const pat = {
      id: uid(),
      userId: ctx.user.id,
      name,
      tokenHash: sha256Hex(token),
      createdAt: now(),
      lastUsedAt: null,
      revokedAt: null,
    };
    store.pats.push(pat);
    await saveStore(store);
    jsonResponse(response, 201, { pat: publicPat(pat), token });
    return;
  }

  if (/^\/api\/pats\/[0-9a-f]+$/.test(pathname) && request.method === "PATCH") {
    if (!requireUser(ctx, response)) return;
    const patId = pathname.split("/").pop();
    const body = await readJsonBody(request);
    const pat = store.pats.find((item) => item.id === patId && item.userId === ctx.user.id);
    if (!pat || pat.revokedAt) {
      jsonResponse(response, 404, { error: "not_found" });
      return;
    }
    pat.name = String(body.name || pat.name).trim();
    await saveStore(store);
    jsonResponse(response, 200, { pat: publicPat(pat) });
    return;
  }

  if (/^\/api\/pats\/[0-9a-f]+$/.test(pathname) && request.method === "DELETE") {
    if (!requireUser(ctx, response)) return;
    const patId = pathname.split("/").pop();
    const pat = store.pats.find((item) => item.id === patId && item.userId === ctx.user.id);
    if (!pat || pat.revokedAt) {
      jsonResponse(response, 404, { error: "not_found" });
      return;
    }
    pat.revokedAt = now();
    await saveStore(store);
    jsonResponse(response, 200, { ok: true });
    return;
  }

  if (pathname === "/api/groups" && request.method === "GET") {
    if (!requireUser(ctx, response)) return;
    const groups = store.groups.filter((group) => group.userId === ctx.user.id).map(publicGroup);
    jsonResponse(response, 200, { items: groups });
    return;
  }

  if (pathname === "/api/groups" && request.method === "POST") {
    if (!requireUser(ctx, response)) return;
    const body = await readJsonBody(request);
    const name = String(body.name || "").trim();
    if (!name) {
      jsonResponse(response, 400, { error: "invalid_input" });
      return;
    }
    const group = {
      id: uid(),
      userId: ctx.user.id,
      name,
      sortOrder: Number(body.sortOrder || 0),
      createdAt: now(),
      updatedAt: now(),
    };
    store.groups.push(group);
    await saveStore(store);
    jsonResponse(response, 201, { group: publicGroup(group) });
    return;
  }

  if (/^\/api\/groups\/[^/]+$/.test(pathname) && request.method === "PATCH") {
    if (!requireUser(ctx, response)) return;
    const groupId = pathname.split("/").pop();
    const body = await readJsonBody(request);
    const group = store.groups.find((item) => item.id === groupId && item.userId === ctx.user.id);
    if (!group) {
      jsonResponse(response, 404, { error: "not_found" });
      return;
    }
    group.name = String(body.name || group.name).trim();
    if (body.sortOrder != null) {
      group.sortOrder = Number(body.sortOrder);
    }
    group.updatedAt = now();
    await saveStore(store);
    jsonResponse(response, 200, { group: publicGroup(group) });
    return;
  }

  if (/^\/api\/groups\/[^/]+$/.test(pathname) && request.method === "DELETE") {
    if (!requireUser(ctx, response)) return;
    const groupId = pathname.split("/").pop();
    if (groupId === "default") {
      jsonResponse(response, 400, { error: "cannot_delete_default_group" });
      return;
    }
    const group = store.groups.find((item) => item.id === groupId && item.userId === ctx.user.id);
    if (!group) {
      jsonResponse(response, 404, { error: "not_found" });
      return;
    }
    store.groups = store.groups.filter((item) => item.id !== groupId);
    for (const entry of store.entries.filter((item) => item.userId === ctx.user.id && item.groupId === groupId)) {
      entry.groupId = "default";
      entry.updatedAt = now();
    }
    await saveStore(store);
    jsonResponse(response, 200, { ok: true });
    return;
  }

  if (pathname === "/api/entries" && request.method === "GET") {
    if (!requireUser(ctx, response)) return;
    const entries = store.entries.filter((item) => item.userId === ctx.user.id).map(publicEntry);
    jsonResponse(response, 200, { items: entries });
    return;
  }

  if (pathname === "/api/entries" && request.method === "POST") {
    if (!requireUser(ctx, response)) return;
    const body = await readJsonBody(request);
    const payload = parseEntryBody(body);
    if (!payload.issuer || !payload.account || !payload.encryptedSecret) {
      jsonResponse(response, 400, { error: "invalid_input" });
      return;
    }
    await ensureDefaultGroup(store, ctx.user.id);
    const entry = {
      id: uid(),
      userId: ctx.user.id,
      issuer: payload.issuer,
      account: payload.account,
      type: payload.type,
      secretEncrypted: payload.encryptedSecret,
      secretVersion: payload.secretVersion,
      algorithm: payload.algorithm,
      digits: payload.digits,
      period: payload.period,
      counter: payload.counter,
      groupId: payload.groupId || "default",
      note: payload.note,
      icon: payload.icon,
      createdAt: now(),
      updatedAt: now(),
    };
    store.entries.push(entry);
    await saveStore(store);
    jsonResponse(response, 201, { entry: publicEntry(entry) });
    return;
  }

  if (/^\/api\/entries\/[^/]+$/.test(pathname) && request.method === "PATCH") {
    if (!requireUser(ctx, response)) return;
    const entryId = pathname.split("/").pop();
    const body = await readJsonBody(request);
    const entry = store.entries.find((item) => item.id === entryId && item.userId === ctx.user.id);
    if (!entry) {
      jsonResponse(response, 404, { error: "not_found" });
      return;
    }
    const payload = parseEntryBody(body);
    if (payload.issuer) entry.issuer = payload.issuer;
    if (payload.account) entry.account = payload.account;
    if (payload.encryptedSecret) entry.secretEncrypted = payload.encryptedSecret;
    if (payload.secretVersion) entry.secretVersion = payload.secretVersion;
    if (body.type) entry.type = payload.type;
    if (body.algorithm) entry.algorithm = payload.algorithm;
    if (body.digits != null) entry.digits = payload.digits;
    if (body.period != null) entry.period = payload.period;
    if (body.counter != null) entry.counter = payload.counter;
    if (body.groupId != null) entry.groupId = payload.groupId || "default";
    if (body.note != null) entry.note = payload.note;
    if (body.icon != null) entry.icon = payload.icon;
    entry.updatedAt = now();
    await saveStore(store);
    jsonResponse(response, 200, { entry: publicEntry(entry) });
    return;
  }

  if (/^\/api\/entries\/[^/]+$/.test(pathname) && request.method === "DELETE") {
    if (!requireUser(ctx, response)) return;
    const entryId = pathname.split("/").pop();
    const exists = store.entries.some((item) => item.id === entryId && item.userId === ctx.user.id);
    if (!exists) {
      jsonResponse(response, 404, { error: "not_found" });
      return;
    }
    store.entries = store.entries.filter((item) => !(item.id === entryId && item.userId === ctx.user.id));
    await saveStore(store);
    jsonResponse(response, 200, { ok: true });
    return;
  }

  if (/^\/api\/entries\/[^/]+\/code$/.test(pathname) && request.method === "GET") {
    if (!requireUser(ctx, response)) return;
    const entryId = pathname.split("/")[3];
    const entry = store.entries.find((item) => item.id === entryId && item.userId === ctx.user.id);
    if (!entry) {
      jsonResponse(response, 404, { error: "not_found" });
      return;
    }
    const code = await codeForEntry(store, entry);
    jsonResponse(response, 200, { code });
    return;
  }

  if (pathname === "/api/export" && request.method === "GET") {
    if (!requireUser(ctx, response)) return;
    const entries = store.entries.filter((item) => item.userId === ctx.user.id).map(publicEntry);
    const groups = store.groups.filter((item) => item.userId === ctx.user.id).map(publicGroup);
    jsonResponse(response, 200, { entries, groups });
    return;
  }

  if (pathname === "/api/import" && request.method === "POST") {
    if (!requireUser(ctx, response)) return;
    const body = await readJsonBody(request);
    const items = Array.isArray(body.entries) ? body.entries : [];
    const inserted = [];
    for (const raw of items) {
      const payload = parseEntryBody(raw);
      if (!payload.issuer || !payload.account || !payload.encryptedSecret) {
        continue;
      }
      const entry = {
        id: uid(),
        userId: ctx.user.id,
        issuer: payload.issuer,
        account: payload.account,
        type: payload.type,
        secretEncrypted: payload.encryptedSecret,
        secretVersion: payload.secretVersion,
        algorithm: payload.algorithm,
        digits: payload.digits,
        period: payload.period,
        counter: payload.counter,
        groupId: payload.groupId || "default",
        note: payload.note,
        icon: payload.icon,
        createdAt: now(),
        updatedAt: now(),
      };
      store.entries.push(entry);
      inserted.push(publicEntry(entry));
    }
    await saveStore(store);
    jsonResponse(response, 201, { entries: inserted });
    return;
  }

  if (pathname === "/api/admin/users" && request.method === "GET") {
    if (!requireAdmin(ctx, response)) return;
    jsonResponse(response, 200, { items: store.users.map(publicUser) });
    return;
  }

  if (/^\/api\/admin\/users\/[^/]+$/.test(pathname) && request.method === "GET") {
    if (!requireAdmin(ctx, response)) return;
    const email = normalizeEmail(pathname.split("/").pop());
    const user = findUser(store, email);
    if (!user) {
      jsonResponse(response, 404, { error: "not_found" });
      return;
    }
    const entries = store.entries.filter((item) => item.userId === user.id).map(publicEntry);
    const groups = store.groups.filter((item) => item.userId === user.id).map(publicGroup);
    jsonResponse(response, 200, { user: publicUser(user), entries, groups });
    return;
  }

  if (/^\/api\/admin\/users\/[^/]+\/disable$/.test(pathname) && request.method === "POST") {
    if (!requireAdmin(ctx, response)) return;
    const email = normalizeEmail(pathname.split("/")[4]);
    const user = findUser(store, email);
    if (!user) {
      jsonResponse(response, 404, { error: "not_found" });
      return;
    }
    user.status = "disabled";
    user.updatedAt = now();
    await recordAudit(store, "disable_user", ctx.admin.id, user.id, "");
    jsonResponse(response, 200, { user: publicUser(user) });
    return;
  }

  if (/^\/api\/admin\/users\/[^/]+$/.test(pathname) && request.method === "DELETE") {
    if (!requireAdmin(ctx, response)) return;
    const email = normalizeEmail(pathname.split("/").pop());
    const user = findUser(store, email);
    if (!user) {
      jsonResponse(response, 404, { error: "not_found" });
      return;
    }
    store.users = store.users.filter((item) => item.id !== user.id);
    store.entries = store.entries.filter((item) => item.userId !== user.id);
    store.groups = store.groups.filter((item) => item.userId !== user.id);
    store.pats = store.pats.filter((item) => item.userId !== user.id);
    store.sessions = store.sessions.filter((item) => item.ownerId !== user.id);
    await recordAudit(store, "delete_user", ctx.admin.id, user.id, "");
    await saveStore(store);
    jsonResponse(response, 200, { ok: true });
    return;
  }

  if (/^\/api\/admin\/users\/[^/]+\/entries$/.test(pathname) && request.method === "GET") {
    if (!requireAdmin(ctx, response)) return;
    const email = normalizeEmail(pathname.split("/")[4]);
    const user = findUser(store, email);
    if (!user) {
      jsonResponse(response, 404, { error: "not_found" });
      return;
    }
    const entries = store.entries.filter((item) => item.userId === user.id).map(publicEntry);
    jsonResponse(response, 200, { items: entries });
    return;
  }

  if (/^\/api\/admin\/users\/[^/]+\/entries\/[^/]+\/secret$/.test(pathname) && request.method === "GET") {
    if (!requireAdmin(ctx, response)) return;
    const parts = pathname.split("/");
    const email = normalizeEmail(parts[4]);
    const entryId = parts[6];
    const user = findUser(store, email);
    const entry = store.entries.find((item) => item.id === entryId && (!user || item.userId === user.id));
    if (!user || !entry) {
      jsonResponse(response, 404, { error: "not_found" });
      return;
    }
    const secret = await decryptSecret(store, entry.secretEncrypted);
    await recordAudit(store, "view_secret", ctx.admin.id, user.id, entry.id);
    jsonResponse(response, 200, { secret });
    return;
  }

  if (/^\/api\/admin\/users\/[^/]+\/entries\/[^/]+\/code$/.test(pathname) && request.method === "GET") {
    if (!requireAdmin(ctx, response)) return;
    const parts = pathname.split("/");
    const email = normalizeEmail(parts[4]);
    const entryId = parts[6];
    const user = findUser(store, email);
    const entry = store.entries.find((item) => item.id === entryId && (!user || item.userId === user.id));
    if (!user || !entry) {
      jsonResponse(response, 404, { error: "not_found" });
      return;
    }
    const code = await codeForEntry(store, entry);
    await recordAudit(store, "view_otp", ctx.admin.id, user.id, entry.id);
    jsonResponse(response, 200, { code });
    return;
  }

  if (pathname === "/api/admin/audit" && request.method === "GET") {
    if (!requireAdmin(ctx, response)) return;
    jsonResponse(response, 200, { items: store.auditLogs });
    return;
  }

  jsonResponse(response, 404, { error: "not_found" });
}

async function handleStatic(request, response, pathname) {
  const isAppRoute = pathname === "/app" || pathname === "/admin";
  const requestedPath = pathname === "/" || isAppRoute ? "index.html" : pathname.slice(1);
  const filePath = normalize(join(root, requestedPath));

  if (!filePath.startsWith(normalize(root))) {
    textResponse(response, 403, "Forbidden");
    return;
  }

  try {
    const data = await readFile(filePath);
    const headers = {
      "Cache-Control": "no-store",
      "Content-Type": contentTypes[extname(filePath)] || "application/octet-stream",
    };
    if (isAppRoute && pathname === "/admin") {
      headers["X-Robots-Tag"] = "noindex, nofollow";
    }
    response.writeHead(200, headers);
    response.end(data);
  } catch {
    textResponse(response, 404, "Not found");
  }
}

const server = createServer(async (request, response) => {
  const url = new URL(request.url, `http://${host}`);
  const pathname = decodeURIComponent(url.pathname);
  if (pathname.startsWith("/api/")) {
    try {
      await handleApi(request, response, pathname);
    } catch (error) {
      jsonResponse(response, 500, { error: "server_error", message: String(error?.message || error) });
    }
    return;
  }
  await handleStatic(request, response, pathname);
});

server.listen(port, host, () => {
  console.log(`VaultOTP web server: http://${host}:${port}/`);
});
