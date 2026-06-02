// =====================================================================
// AFFECTION PORTAL · Service Worker (PWA mínimo)
// =====================================================================
// Cache estratégia: network-first pra HTML/JS (sempre fresco quando online)
// e cache-first pra fontes/ícones (estáveis).
// =====================================================================
const CACHE = 'affection-portal-v6';
const ASSETS = ['/', '/index.html', '/login.html', '/app.html', '/config.js', '/manifest.json', '/icons/borboleta.png', '/icons/icon-app.png', '/offline.html'];

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
    const req = e.request;
    const url = new URL(req.url);
    // Não cacheia chamadas pra Supabase / chrome-extension / etc — só online
    if (url.host.includes('supabase.co')) return;
    if (url.protocol !== 'http:' && url.protocol !== 'https:') return;
    // SW só cacheia GET (POST/PUT/DELETE não são cacheáveis)
    if (req.method !== 'GET') return;
    e.respondWith(
        fetch(req)
            .then(r => {
                // Só cacheia resposta boa do mesmo origem (evita 'opaque' / errors / 4xx)
                if (r && r.ok && r.type === 'basic') {
                    const copy = r.clone();
                    caches.open(CACHE).then(c => c.put(req, copy).catch(()=>{}));
                }
                return r;
            })
            .catch(() => caches.match(req).then(m => m || (req.mode === 'navigate' ? caches.match('/offline.html') : Response.error())))
    );
});
