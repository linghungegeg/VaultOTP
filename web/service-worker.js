const CACHE_NAME = "vaultotp-pwa-v1";
const APP_SHELL = ["/app", "/styles.css", "/app.js", "/extension/i18n.js", "/manifest.webmanifest", "/icon.svg"];

async function refreshAppShell() {
  const cache = await caches.open(CACHE_NAME);
  await Promise.all(
    APP_SHELL.map(async (url) => {
      try {
        const response = await fetch(new Request(url, { cache: "reload" }));
        if (response.ok) await cache.put(url, response);
      } catch {
        // Keep the previous app shell cache when the network is unavailable.
      }
    }),
  );
}

self.addEventListener("install", (event) => {
  event.waitUntil(refreshAppShell());
  self.skipWaiting();
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches
      .keys()
      .then((names) => Promise.all(names.filter((name) => name !== CACHE_NAME).map((name) => caches.delete(name))))
      .then(() => self.clients.claim()),
  );
});

self.addEventListener("message", (event) => {
  if (event.data?.type === "refresh-shell") {
    event.waitUntil(refreshAppShell());
  }
});

self.addEventListener("fetch", (event) => {
  const url = new URL(event.request.url);
  if (event.request.method !== "GET" || url.pathname.startsWith("/api/")) return;
  event.respondWith(
    fetch(event.request)
      .then((response) => {
        if (response.ok && url.origin === location.origin) {
          const copy = response.clone();
          caches.open(CACHE_NAME).then((cache) => cache.put(event.request, copy));
        }
        return response;
      })
      .catch(() => caches.match(event.request).then((cached) => cached || caches.match("/app"))),
  );
});
