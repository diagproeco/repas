/* Mes repas et recettes : garde une copie de l'appli (chiffrée) pour l'ouvrir sans réseau. */
const CACHE = "repas-v2";
const BASE = ["./", "index.html", "manifest.webmanifest", "icon-192.png", "icon-512.png", "icon-180.png"];
self.addEventListener("install", (e) => {
  e.waitUntil(caches.open(CACHE).then((c) => c.addAll(BASE)).then(() => self.skipWaiting()));
});
self.addEventListener("activate", (e) => {
  e.waitUntil(caches.keys().then((ks) => Promise.all(ks.filter((k) => k !== CACHE).map((k) => caches.delete(k)))).then(() => self.clients.claim()));
});
/* Réseau d'abord (toujours la dernière version), copie locale si pas de réseau. */
self.addEventListener("fetch", (e) => {
  const req = e.request;
  if (req.method !== "GET") return;
  e.respondWith(
    fetch(req).then((res) => {
      if (res && (res.ok || res.type === "opaque")) { const copie = res.clone(); caches.open(CACHE).then((c) => c.put(req, copie)).catch(() => {}); }
      return res;
    }).catch(() => caches.match(req, { ignoreSearch: true }).then((m) => m || (req.mode === "navigate" ? caches.match("index.html") : Response.error())))
  );
});
