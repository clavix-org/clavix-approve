// Service worker de la page d'essai : affiche la notification reçue et
// rouvre la page quand on la touche.
self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', (e) => e.waitUntil(self.clients.claim()));

self.addEventListener('push', (e) => {
  let d = {};
  try { d = e.data ? e.data.json() : {}; } catch (_) { /* charge illisible */ }
  e.waitUntil(self.registration.showNotification(d.title || 'Essai de notification', {
    body: d.body || '',
    data: { sent: d.sent || '' },
  }));
});

self.addEventListener('notificationclick', (e) => {
  e.notification.close();
  const url = '/?demande=' + encodeURIComponent(e.notification.data.sent || 'inconnue');
  e.waitUntil((async () => {
    const all = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });
    for (const c of all) {
      if ('focus' in c) {
        c.postMessage({ demande: e.notification.data.sent || 'inconnue' });
        return c.focus();
      }
    }
    return self.clients.openWindow(url);
  })());
});
