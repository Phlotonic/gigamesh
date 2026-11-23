// GigaMesh Offline-Resilient PWA Service Worker
// Copyright (C) 2026 Adam Dryden and Quanumis Systems.
const CACHE_NAME = 'gigamesh-shell-v1';
const SHELL_URLS = ['/', '/manifest.webmanifest'];

self.addEventListener('install', (event) => {
  event.waitUntil(caches.open(CACHE_NAME).then((cache) => cache.addAll(SHELL_URLS)));
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil(self.clients.claim());
});

self.addEventListener('fetch', (event) => {
  const url = new URL(event.request.url);
  // Always fetch live API & WebSocket traffic directly (never serve stale security verdicts)
  if (url.pathname.startsWith('/api/') || url.pathname.startsWith('/ws/')) {
    return;
  }
  event.respondWith(
    fetch(event.request).catch(() => caches.match(event.request).then((r) => r || caches.match('/')))
  );
});
