import { createServer } from "node:http";
import { readFile, rename, writeFile, mkdir } from "node:fs/promises";
import { extname, join, normalize, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { webcrypto, createHash, createHmac } from "node:crypto";
import { runInNewContext } from "node:vm";

const { subtle } = webcrypto;
const getRandomValues = webcrypto.getRandomValues.bind(webcrypto);
const root = dirname(fileURLToPath(import.meta.url));
const i18nPath = normalize(join(root, "..", "extension", "i18n.js"));
const storePath = normalize(process.env.VAULTOTP_STORE_PATH || join(root, "..", "vaultotp-store.json"));
const port = Number(process.env.PORT || 4173);
const host = process.env.HOST || "127.0.0.1";
const tokenTtlMs = 1000 * 60 * 60 * 24 * 30;
const contentTypes = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".svg": "image/svg+xml; charset=utf-8",
  ".webmanifest": "application/manifest+json; charset=utf-8",
};

let storeCache = null;
let i18nCache = null;

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

function typedTextResponse(response, status, body, contentType) {
  response.writeHead(status, {
    "Cache-Control": "no-store",
    "Content-Type": contentType,
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
    siteSettings: defaultSiteSettings(),
  };
}

function defaultSiteSettings() {
  return {
    siteName: "VaultOTP",
    seoTitle: "VaultOTP",
    seoKeywords: "VaultOTP, 2FA, TOTP, HOTP",
    seoDescription: "VaultOTP saves and manages 2FA verification codes.",
    logo: "",
    ogTitle: "VaultOTP",
    ogDescription: "Save and manage 2FA verification codes.",
    allowPublicIndexing: true,
  };
}

function siteSettings(store) {
  return { ...defaultSiteSettings(), ...(store.siteSettings || {}) };
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

async function loadI18n() {
  if (i18nCache) return i18nCache;
  const source = await readFile(i18nPath, "utf8");
  const context = {
    window: {},
    document: { documentElement: {} },
    navigator: { language: "zh-CN" },
    localStorage: { getItem: () => null, setItem: () => undefined },
  };
  runInNewContext(source, context, { filename: i18nPath });
  i18nCache = context.window.VaultOtpI18n;
  return i18nCache;
}

function requestOrigin(request) {
  const protocol = request.headers["x-forwarded-proto"] || "http";
  return `${protocol}://${request.headers.host || `${host}:${port}`}`;
}

function pageLocale(requestUrl) {
  return requestUrl.searchParams.get("lang") === "en" ? "en" : "zh-CN";
}

function publicPages() {
  return [
    { path: "/", key: "publicHome" },
    { path: "/features", key: "publicFeatures" },
    { path: "/install", key: "publicInstall" },
    { path: "/docs", key: "publicDocs" },
    { path: "/faq", key: "publicFaq" },
    { path: "/compare", key: "publicCompare" },
  ];
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function safeJsonForScript(value) {
  return JSON.stringify(value).replaceAll("<", "\\u003c");
}

function publicPageConfig(pathname) {
  if (/^\/2fa\/[A-Z2-7=\s-]+$/i.test(pathname)) return { path: "/", key: "publicHome" };
  return publicPages().find((page) => page.path === pathname) || null;
}

function publicPageLinks(origin, locale) {
  return publicPages()
    .map((page) => `<a href="${origin}${page.path}${locale === "en" ? "?lang=en" : ""}">{{${page.key}}}</a>`)
    .join("");
}

function publicTotpTool(locale, directSecret) {
  const labels =
    locale === "en"
      ? {
          singleTitle: "Generate one code",
          singleSecret: "Enter 2FA Secret",
          generate: "Generate",
          singleHint: "This only generates a code and does not save it.",
          remaining: "Remaining",
          title: "Offline 2FA manager",
          notice: "Guest data is saved in this browser cache. Clearing browser data or switching devices may delete it. Registered users can save and use codes permanently for free.",
          remark: "Account note",
          secret: "Base32 secret",
          add: "Add manually",
          scan: "Import QR image",
          backup: "Export backup",
          empty: "No accounts yet. Add manually or import a QR image.",
          qrUnsupported: "Cannot read this QR image",
          copied: "Copied",
          secretCopied: "Secret copied",
          deleted: "Deleted",
          invalid: "Invalid secret",
          backupEmpty: "No data to export",
          deleteConfirm: "Delete this account?",
          copySecret: "Copy secret",
          delete: "Delete",
        }
      : {
          singleTitle: "输入生成验证码",
          singleSecret: "输入 2FA Secret",
          generate: "生成",
          singleHint: "这里只生成验证码，不保存数据。",
          remaining: "剩余",
          title: "2FA 离线管理",
          notice: "游客数据保存在当前浏览器缓存中，清理浏览器缓存或更换设备可能被删除。注册用户可永久免费保存和使用。",
          remark: "账号备注",
          secret: "密钥（Base32）",
          add: "手动添加",
          scan: "识别二维码图片",
          backup: "全量备份",
          empty: "暂无账户，请手动添加或导入二维码图片。",
          qrUnsupported: "无法识别这个二维码",
          copied: "已复制",
          secretCopied: "私钥已复制",
          deleted: "已删除",
          invalid: "密钥格式不正确",
          backupEmpty: "暂无数据可导出",
          deleteConfirm: "确定删除这个账户吗？",
          copySecret: "复制私钥",
          delete: "删除",
        };
  return `
    <section class="public-totp" data-direct-secret="${escapeHtml(directSecret)}">
      <div class="public-single-tool">
        <h2>${escapeHtml(labels.singleTitle)}</h2>
        <form id="public-single-form" class="public-totp-form">
          <input id="public-single-secret" autocomplete="off" spellcheck="false" placeholder="${escapeHtml(labels.singleSecret)}" value="${escapeHtml(directSecret)}" />
          <button type="submit">${escapeHtml(labels.generate)}</button>
        </form>
        <div class="public-single-result">
          <button id="public-single-code" class="public-totp-code" type="button"></button>
          <span id="public-single-time" class="muted"></span>
          <p>${escapeHtml(labels.singleHint)}</p>
        </div>
      </div>
      <h2>${escapeHtml(labels.title)}</h2>
      <p class="public-cache-notice">${escapeHtml(labels.notice)}</p>
      <form id="public-totp-form" class="public-totp-form">
        <input id="public-totp-remark" name="remark" autocomplete="off" placeholder="${escapeHtml(labels.remark)}" />
        <input id="public-totp-secret" name="secret" autocomplete="off" spellcheck="false" placeholder="${escapeHtml(labels.secret)}" />
        <button type="submit">${escapeHtml(labels.add)}</button>
      </form>
      <div class="public-totp-actions">
        <button id="public-totp-scan" type="button">${escapeHtml(labels.scan)}</button>
        <button id="public-totp-backup" type="button">${escapeHtml(labels.backup)}</button>
        <input id="public-totp-file" type="file" accept="image/*" hidden />
      </div>
      <div id="public-totp-list" class="public-totp-list" aria-live="polite"></div>
      <div id="public-totp-toast" class="public-totp-toast"></div>
    </section>
    <script src="https://cdn.jsdelivr.net/npm/jsqr@1.4.0/dist/jsQR.min.js"></script>
    <script>
      (() => {
        const labels = ${safeJsonForScript(labels)};
        const storageKey = "vaultotp.public.2fa.accounts";
        const singleForm = document.getElementById("public-single-form");
        const singleSecret = document.getElementById("public-single-secret");
        const singleCode = document.getElementById("public-single-code");
        const singleTime = document.getElementById("public-single-time");
        const form = document.getElementById("public-totp-form");
        const remarkInput = document.getElementById("public-totp-remark");
        const secretInput = document.getElementById("public-totp-secret");
        const fileInput = document.getElementById("public-totp-file");
        const scanButton = document.getElementById("public-totp-scan");
        const backupButton = document.getElementById("public-totp-backup");
        const list = document.getElementById("public-totp-list");
        const toast = document.getElementById("public-totp-toast");
        let accounts = loadAccounts();

        function loadAccounts() {
          try {
            const parsed = JSON.parse(localStorage.getItem(storageKey) || "[]");
            return Array.isArray(parsed) ? parsed : [];
          } catch {
            return [];
          }
        }

        function saveAccounts() {
          localStorage.setItem(storageKey, JSON.stringify(accounts));
        }

        function showToast(text) {
          toast.textContent = text;
          toast.classList.add("visible");
          setTimeout(() => toast.classList.remove("visible"), 1400);
        }

        function base32Bytes(secret) {
          const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
          const normalized = String(secret || "").toUpperCase().replace(/[\\s=-]/g, "");
          if (normalized.length < 8) throw new Error("invalid");
          let bits = "";
          for (const char of normalized) {
            const value = alphabet.indexOf(char);
            if (value === -1) throw new Error("invalid");
            bits += value.toString(2).padStart(5, "0");
          }
          const bytes = [];
          for (let index = 0; index + 8 <= bits.length; index += 8) {
            bytes.push(parseInt(bits.slice(index, index + 8), 2));
          }
          return new Uint8Array(bytes);
        }

        function toBase32(bytes) {
          const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
          let bits = 0;
          let value = 0;
          let output = "";
          for (const byte of bytes) {
            value = (value << 8) | byte;
            bits += 8;
            while (bits >= 5) {
              output += alphabet[(value >>> (bits - 5)) & 31];
              bits -= 5;
            }
          }
          if (bits > 0) output += alphabet[(value << (5 - bits)) & 31];
          return output;
        }

        async function codeForSecret(secret) {
          const key = await crypto.subtle.importKey("raw", base32Bytes(secret), { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
          const counter = Math.floor(Date.now() / 1000 / 30);
          const counterBytes = new ArrayBuffer(8);
          const view = new DataView(counterBytes);
          view.setUint32(4, counter);
          const digest = new Uint8Array(await crypto.subtle.sign("HMAC", key, counterBytes));
          const offset = digest[digest.length - 1] & 15;
          const binary = ((digest[offset] & 127) << 24) | ((digest[offset + 1] & 255) << 16) | ((digest[offset + 2] & 255) << 8) | (digest[offset + 3] & 255);
          return String(binary % 1000000).padStart(6, "0");
        }

        function parseOtpAuth(value) {
          const text = String(value || "").trim();
          if (!text) return [];
          if (text.includes("otpauth-migration://")) return parseMigration(text);
          if (/^[A-Z2-7=\\s-]{8,}$/i.test(text)) return [{ remark: labels.remark, secret: text }];
          const url = new URL(text);
          if (url.protocol !== "otpauth:") throw new Error("invalid");
          const label = decodeURIComponent(url.pathname.replace(/^\\//, ""));
          const issuer = url.searchParams.get("issuer") || "";
          const account = label.includes(":") ? label.split(":").slice(1).join(":") : label;
          const secret = url.searchParams.get("secret") || "";
          return [{ remark: issuer ? issuer + (account ? " (" + account + ")" : "") : account || labels.remark, secret }];
        }

        function parseMigration(text) {
          const data = new URL(text).searchParams.get("data");
          if (!data) return [];
          const binary = atob(decodeURIComponent(data));
          const bytes = Uint8Array.from(binary, (char) => char.charCodeAt(0));
          const entries = [];
          let index = 0;

          function readVarint() {
            let shift = 0;
            let result = 0;
            while (index < bytes.length) {
              const byte = bytes[index++];
              result |= (byte & 127) << shift;
              if (!(byte & 128)) break;
              shift += 7;
            }
            return result;
          }

          while (index < bytes.length) {
            const key = readVarint();
            const field = key >> 3;
            const wire = key & 7;
            if (field === 1 && wire === 2) {
              const end = index + readVarint();
              let secret = "";
              let name = "";
              let issuer = "";
              while (index < end) {
                const innerKey = readVarint();
                const innerField = innerKey >> 3;
                const innerWire = innerKey & 7;
                if (innerWire === 2) {
                  const length = readVarint();
                  const value = bytes.slice(index, index + length);
                  index += length;
                  if (innerField === 1) secret = toBase32(value);
                  if (innerField === 2) name = new TextDecoder().decode(value);
                  if (innerField === 3) issuer = new TextDecoder().decode(value);
                } else if (innerWire === 0) {
                  readVarint();
                } else {
                  break;
                }
              }
              if (secret) entries.push({ remark: issuer ? issuer + (name ? " (" + name + ")" : "") : name || labels.remark, secret });
            } else if (wire === 0) {
              readVarint();
            } else if (wire === 2) {
              index += readVarint();
            } else if (wire === 1) {
              index += 8;
            } else if (wire === 5) {
              index += 4;
            } else {
              break;
            }
          }
          return entries;
        }

        function addAccount(remark, secret) {
          const normalized = String(secret || "").toUpperCase().replace(/[\\s=-]/g, "");
          base32Bytes(normalized);
          accounts.push({ id: Date.now() + Math.random(), remark: String(remark || labels.remark).trim() || labels.remark, secret: normalized });
          saveAccounts();
          renderAccounts();
        }

        function addParsedValues(values) {
          let count = 0;
          for (const value of values) {
            for (const entry of parseOtpAuth(value)) {
              addAccount(entry.remark, entry.secret);
              count++;
            }
          }
          return count;
        }

        async function detectQrFile(file) {
          const image = await createImageBitmap(file);
          try {
            if ("BarcodeDetector" in window) {
              const detector = new BarcodeDetector({ formats: ["qr_code"] });
              const codes = await detector.detect(image);
              if (codes.length) return codes.map((code) => code.rawValue);
            }
            if (!window.jsQR) throw new Error("unsupported");
            const canvas = document.createElement("canvas");
            const ctx = canvas.getContext("2d", { willReadFrequently: true });
            canvas.width = image.width;
            canvas.height = image.height;
            ctx.drawImage(image, 0, 0);
            let imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
            let qr = jsQR(imageData.data, canvas.width, canvas.height);
            if (qr?.data) return [qr.data];

            const size = Math.floor(Math.min(image.width, image.height) * 0.82);
            const x = Math.floor((image.width - size) / 2);
            const y = Math.floor((image.height - size) / 2);
            canvas.width = size;
            canvas.height = size;
            ctx.drawImage(image, x, y, size, size, 0, 0, size, size);
            imageData = ctx.getImageData(0, 0, size, size);
            qr = jsQR(imageData.data, size, size);
            if (qr?.data) return [qr.data];
            throw new Error("not_found");
          } finally {
            image.close?.();
          }
        }

        async function renderAccounts() {
          if (!accounts.length) {
            list.innerHTML = '<div class="empty">' + labels.empty + '</div>';
            return;
          }
          const timeLeft = 30 - (Math.floor(Date.now() / 1000) % 30);
          const rows = await Promise.all(
            accounts.map(async (account) => {
              let code = "ERROR";
              try {
                code = await codeForSecret(account.secret);
              } catch {}
              return '<article class="public-totp-card" data-id="' + account.id + '">' +
                '<div class="remark" title="' + escapeHtml(account.remark) + '">' + escapeHtml(account.remark) + '</div>' +
                '<button class="public-totp-code" type="button" data-copy-code="' + account.id + '">' + code + '</button>' +
                '<div class="progress-container"><div class="progress-bar" style="width:' + ((timeLeft / 30) * 100) + '%"></div></div>' +
                '<div class="card-tools">' +
                  '<button type="button" data-copy-secret="' + account.id + '">' + labels.copySecret + '</button>' +
                  '<button type="button" data-delete-account="' + account.id + '">' + labels.delete + '</button>' +
                '</div>' +
              '</article>';
            }),
          );
          list.innerHTML = rows.join("");
        }

        async function renderSingleCode() {
          const secret = singleSecret.value.trim();
          if (!secret) {
            singleCode.textContent = "";
            singleTime.textContent = "";
            return;
          }
          try {
            singleCode.textContent = await codeForSecret(secret);
            singleTime.textContent = labels.remaining + " " + String(30 - (Math.floor(Date.now() / 1000) % 30)) + "s";
          } catch {
            singleCode.textContent = "";
            singleTime.textContent = labels.invalid;
          }
        }

        singleForm.addEventListener("submit", (event) => {
          event.preventDefault();
          renderSingleCode();
        });
        singleCode.addEventListener("click", async () => {
          if (!singleCode.textContent) return;
          await navigator.clipboard.writeText(singleCode.textContent);
          showToast(labels.copied);
        });

        form.addEventListener("submit", (event) => {
          event.preventDefault();
          try {
            addAccount(remarkInput.value, secretInput.value);
            remarkInput.value = "";
            secretInput.value = "";
          } catch {
            showToast(labels.invalid);
          }
        });
        scanButton.addEventListener("click", () => fileInput.click());
        fileInput.addEventListener("change", async () => {
          const file = fileInput.files?.[0];
          if (!file) return;
          try {
            const values = await detectQrFile(file);
            const count = addParsedValues(values);
            showToast(count ? labels.copied : labels.qrUnsupported);
          } catch {
            showToast(labels.qrUnsupported);
          } finally {
            fileInput.value = "";
          }
        });
        backupButton.addEventListener("click", () => {
          if (!accounts.length) return showToast(labels.backupEmpty);
          const blob = new Blob([JSON.stringify(accounts, null, 2)], { type: "application/json" });
          const url = URL.createObjectURL(blob);
          const link = document.createElement("a");
          link.href = url;
          link.download = "vaultotp-guest-backup-" + new Date().toISOString().slice(0, 10) + ".json";
          link.click();
          URL.revokeObjectURL(url);
        });
        list.addEventListener("click", async (event) => {
          const codeId = event.target.dataset.copyCode;
          const secretId = event.target.dataset.copySecret;
          const deleteId = event.target.dataset.deleteAccount;
          const account = accounts.find((item) => String(item.id) === String(codeId || secretId || deleteId));
          if (!account) return;
          if (codeId) {
            await navigator.clipboard.writeText(event.target.textContent);
            showToast(labels.copied);
          }
          if (secretId) {
            await navigator.clipboard.writeText(account.secret);
            showToast(labels.secretCopied);
          }
          if (deleteId && confirm(labels.deleteConfirm)) {
            accounts = accounts.filter((item) => item !== account);
            saveAccounts();
            showToast(labels.deleted);
            renderAccounts();
          }
        });
        if (singleSecret.value.trim()) renderSingleCode();
        renderAccounts();
        setInterval(() => {
          renderSingleCode();
          renderAccounts();
        }, 1000);

        function escapeHtml(value) {
          return String(value ?? "")
            .replaceAll("&", "&amp;")
            .replaceAll("<", "&lt;")
            .replaceAll(">", "&gt;")
            .replaceAll('"', "&quot;")
            .replaceAll("'", "&#039;");
        }
      })();
    </script>
  `;
}

async function renderPublicPage(request, requestUrl, response, pathname) {
  const page = publicPageConfig(pathname);
  if (!page) return false;
  const store = await loadStore();
  const settings = siteSettings(store);
  const i18n = await loadI18n();
  const locale = pageLocale(requestUrl);
  const t = (key, params = {}) => i18n.t(key, locale, params);
  const origin = requestOrigin(request);
  const title = settings.seoTitle || settings.siteName;
  const description = settings.seoDescription;
  const canonical = `${origin}${pathname}`;
  const directSecret = pathname.startsWith("/2fa/") ? pathname.slice(5) : "";
  const robots = settings.allowPublicIndexing ? "index, follow" : "noindex, nofollow";
  const schema = {
    "@context": "https://schema.org",
    "@type": "SoftwareApplication",
    name: settings.siteName,
    applicationCategory: "SecurityApplication",
    operatingSystem: "Web",
    description,
    url: canonical,
  };
  const links = publicPageLinks(origin, locale).replace(/\{\{([^}]+)\}\}/g, (_, key) => escapeHtml(t(key)));
  const body = `
    <!doctype html>
    <html lang="${locale}">
      <head>
        <meta charset="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <meta name="robots" content="${robots}" />
        <meta name="keywords" content="${escapeHtml(settings.seoKeywords)}" />
        <meta name="description" content="${escapeHtml(description)}" />
        <meta property="og:title" content="${escapeHtml(settings.ogTitle || title)}" />
        <meta property="og:description" content="${escapeHtml(settings.ogDescription || description)}" />
        <meta property="og:type" content="website" />
        <meta property="og:url" content="${escapeHtml(canonical)}" />
        <link rel="canonical" href="${escapeHtml(canonical)}" />
        <link rel="stylesheet" href="/styles.css" />
        <title>${escapeHtml(title)}</title>
        <script type="application/ld+json">${safeJsonForScript(schema)}</script>
      </head>
      <body>
        <main class="public-page">
          <nav class="public-nav">
            <strong>${escapeHtml(settings.siteName)}</strong>
            <span>${links}</span>
            <span class="language-switch">
              <a href="${pathname}">中文</a>
              <a href="${pathname}?lang=en">English</a>
            </span>
          </nav>
          <section class="public-hero">
            <p class="muted">${escapeHtml(t("publicEyebrow"))}</p>
            <h1>${escapeHtml(t(`${page.key}Title`, { siteName: settings.siteName }))}</h1>
            <p>${escapeHtml(t(`${page.key}Body`, { siteName: settings.siteName }))}</p>
            <div class="inline-actions">
              <a class="primary public-link" href="/app">${escapeHtml(t("publicOpenApp"))}</a>
              <a class="ghost public-link" href="/docs${locale === "en" ? "?lang=en" : ""}">${escapeHtml(t("publicReadDocs"))}</a>
            </div>
          </section>
          ${page.key === "publicHome" ? publicTotpTool(locale, directSecret) : ""}
          <section class="public-grid">
            <article><h2>${escapeHtml(t("publicPointUserTitle"))}</h2><p>${escapeHtml(t("publicPointUserBody"))}</p></article>
            <article><h2>${escapeHtml(t("publicPointAdminTitle"))}</h2><p>${escapeHtml(t("publicPointAdminBody"))}</p></article>
            <article><h2>${escapeHtml(t("publicPointApiTitle"))}</h2><p>${escapeHtml(t("publicPointApiBody"))}</p></article>
          </section>
        </main>
      </body>
    </html>
  `;
  typedTextResponse(response, 200, body, "text/html; charset=utf-8");
  return true;
}

async function handlePublicText(request, response, pathname) {
  const store = await loadStore();
  const settings = siteSettings(store);
  const origin = requestOrigin(request);
  if (pathname === "/robots.txt") {
    const sitemap = `Sitemap: ${origin}/sitemap.xml`;
    const body = settings.allowPublicIndexing
      ? `User-agent: *\nAllow: /\nDisallow: /admin\nDisallow: /api\n${sitemap}\n`
      : `User-agent: *\nDisallow: /\n${sitemap}\n`;
    typedTextResponse(response, 200, body, "text/plain; charset=utf-8");
    return true;
  }
  if (pathname === "/sitemap.xml") {
    const urls = settings.allowPublicIndexing
      ? publicPages().map((page) => `<url><loc>${origin}${page.path}</loc></url>`).join("")
      : "";
    typedTextResponse(response, 200, `<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">${urls}</urlset>`, "application/xml; charset=utf-8");
    return true;
  }
  if (pathname === "/llms.txt") {
    const i18n = await loadI18n();
    const t = (key, params = {}) => i18n.t(key, "en", params);
    typedTextResponse(response, 200, `# ${settings.siteName}\n\n${t("publicLlmsSummary", { siteName: settings.siteName })}\n\n- App: ${origin}/app\n- Docs: ${origin}/docs\n- API: ${origin}/api/me\n`, "text/plain; charset=utf-8");
    return true;
  }
  return false;
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
    pinned: Boolean(entry.pinned),
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
    pinned: body.pinned === true || body.pinned === "true" || body.pinned === 1 || body.pinned === "1",
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
      pinned: payload.pinned,
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
    if (body.pinned != null) entry.pinned = payload.pinned;
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
        pinned: payload.pinned,
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

  if (pathname === "/api/admin/site-settings" && request.method === "GET") {
    if (!requireAdmin(ctx, response)) return;
    jsonResponse(response, 200, { settings: siteSettings(store) });
    return;
  }

  if (pathname === "/api/admin/site-settings" && request.method === "PATCH") {
    if (!requireAdmin(ctx, response)) return;
    const body = await readJsonBody(request);
    store.siteSettings = {
      ...siteSettings(store),
      siteName: String(body.siteName || "VaultOTP").trim(),
      seoTitle: String(body.seoTitle || "").trim(),
      seoKeywords: String(body.seoKeywords || "").trim(),
      seoDescription: String(body.seoDescription || "").trim(),
      logo: String(body.logo || "").trim(),
      ogTitle: String(body.ogTitle || "").trim(),
      ogDescription: String(body.ogDescription || "").trim(),
      allowPublicIndexing: body.allowPublicIndexing !== false,
    };
    await saveStore(store);
    jsonResponse(response, 200, { settings: siteSettings(store) });
    return;
  }

  jsonResponse(response, 404, { error: "not_found" });
}

async function handleStatic(request, response, pathname) {
  const isAppRoute = pathname === "/app" || pathname === "/admin";
  const isSharedI18n = pathname === "/extension/i18n.js";
  const requestedPath = pathname === "/" || isAppRoute ? "index.html" : pathname.slice(1);
  const filePath = normalize(isSharedI18n ? join(root, "..", "extension", "i18n.js") : join(root, requestedPath));
  const allowedRoot = normalize(isSharedI18n ? join(root, "..", "extension") : root);

  if (!filePath.startsWith(allowedRoot)) {
    textResponse(response, 403, "Forbidden");
    return;
  }

  try {
    const data = await readFile(filePath);
    const headers = {
      "Cache-Control": pathname === "/service-worker.js" ? "no-cache" : "no-store",
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
  if (await handlePublicText(request, response, pathname)) return;
  if (await renderPublicPage(request, url, response, pathname)) return;
  await handleStatic(request, response, pathname);
});

server.listen(port, host, () => {
  console.log(`VaultOTP web server: http://${host}:${port}/`);
});
