// 4E Workshop Scheduler — Service Worker for PWA
const CACHE = 'scheduler-v1';

self.addEventListener('install', e => {
  e.waitUntil(caches.open(CACHE).then(c => c.addAll(['/4E_Scheduler/', '/4E_Scheduler/index.html', '/4E_Scheduler/logo_WHT.png'])));
  self.skipWaiting();
});

self.addEventListener('activate', e => {
  e.waitUntil(caches.keys().then(keys => Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k)))));
  self.clients.claim();
});

self.addEventListener('fetch', e => {
  // Network first, cache fallback
  e.respondWith(fetch(e.request).catch(() => caches.match(e.request)));
});
