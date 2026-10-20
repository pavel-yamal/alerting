// Minimal service worker: it exists so the page can be installed to the home
// screen. It caches nothing -- an order shown from a stale cache would be worse than
// no page at all -- and it receives no push: there is no push provider yet.
self.addEventListener("install", () => self.skipWaiting());
self.addEventListener("activate", (event) => event.waitUntil(self.clients.claim()));
