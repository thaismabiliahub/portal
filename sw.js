// =====================================================================
// AFFECTION PORTAL · Service Worker (PWA mínimo)
// =====================================================================
// Cache estratégia: network-first pra HTML/JS (sempre fresco quando online)
// e cache-first pra fontes/ícones (estáveis).
// =====================================================================
const CACHE = 'affection-portal-v1';
const ASSETS = ['/', '/index.html', '/app.html', '/config.js', '/manifest.json'];

self.addEventListener('install', e => {
    self.skipWaiting();
    e.waitUntil(caches.open(CACHE).then(c => c.addAll(ASSETS).catch(()=>{})));
});

self.addEventListener('activate', e => {
    e.waitUntil(caches.keys().then(keys =>
        Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k)))
    ));
    self.clients.claim();
});

self.addEventListener('fetch', e => {
    const url = new URL(e.request.url);
    // Não cacheia chamadas pra Supabase (sempre online)
    if (url.host.includes('supabase.co')) return;
    e.respondWith(
        fetch(e.request)
            .then(r => { const copy = r.clone(); caches.open(CACHE).then(c => c.put(e.request, copy)); return r; })
            .catch(() => caches.match(e.request))
    );
});
