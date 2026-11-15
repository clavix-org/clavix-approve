// Service worker: shows the wake-up notification and brings the page
// forward when it is tapped.
//
// The push carries no content and this worker decrypts nothing: what is
// asked, and for which server, is only shown inside the page, after the
// request has been verified there.

self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', (event) => event.waitUntil(self.clients.claim()));

self.addEventListener('push', (event) => {
  // Always show something: a push without a notification makes the
  // browser withdraw the subscription.
  event.waitUntil(self.registration.showNotification('Demande de signature SSH', {
    body: 'Ouvrir pour voir la destination et décider.',
    tag: 'clavix-sign-request',
    renotify: true,
  }));
});

self.addEventListener('notificationclick', (event) => {
  event.notification.close();
  event.waitUntil((async () => {
    const windows = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });
    for (const client of windows) {
      if ('focus' in client) {
        client.postMessage({ t: 'check' });
        return client.focus();
      }
    }
    // The page fetches pending requests by itself when it starts.
    return self.clients.openWindow('/');
  })());
});
