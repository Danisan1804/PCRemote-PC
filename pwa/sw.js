const CACHE = "pc-remote-pwa-v2";
const ASSETS = ["/pwa/", "/pwa/styles.css", "/pwa/control.css", "/pwa/app.js", "/pwa/control.html", "/pwa/control.js", "/pwa/manifest.webmanifest", "/pwa/icon.svg"];
self.addEventListener("install", event => event.waitUntil(caches.open(CACHE).then(cache => cache.addAll(ASSETS))));
self.addEventListener("activate", event => event.waitUntil(caches.keys().then(keys => Promise.all(keys.filter(key => key !== CACHE).map(key => caches.delete(key))))));
self.addEventListener("fetch", event => {
  if (new URL(event.request.url).pathname.startsWith("/api/")) return;
  event.respondWith(caches.match(event.request).then(cached => cached || fetch(event.request)));
});
