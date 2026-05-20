/* Frickmail Service Worker
 *
 * Cache strategy:
 *   /snappymail/v/<ver>/static/*  cache-first   (version in path → content-addressed)
 *   /?/Css/* and /?/Js/*          stale-while-revalidate
 *   /?Json/* and /?/*             network-only  (live email data must be fresh)
 *   /  (app shell)                network-first, offline fallback to cache
 */
'use strict';

const CACHE = 'fm-v1';

const isVersionedStatic = url =>
	/\/snappymail\/v\/[^/]+\/static\//.test(url.pathname);

const isBundleAsset = url =>
	/[?&]\/(Css|Js)\//.test(url.search) || /\/\?(Css|Js)\//.test(url.pathname + url.search);

const isApiCall = url =>
	url.search.includes('Json') || url.search.startsWith('?/');

// ── Install: activate immediately ────────────────────────────────────────
self.addEventListener('install', () => self.skipWaiting());

// ── Activate: delete stale caches, claim all clients ─────────────────────
self.addEventListener('activate', e => {
	e.waitUntil(
		caches.keys()
			.then(keys => Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k))))
			.then(() => self.clients.claim())
	);
});

// ── Fetch ─────────────────────────────────────────────────────────────────
self.addEventListener('fetch', e => {
	if (e.request.method !== 'GET') return;
	const url = new URL(e.request.url);
	if (url.origin !== self.location.origin) return;

	// API / live actions: always fresh
	if (isApiCall(url)) return;

	// Versioned static files: cache-first (safe — URL changes when content changes)
	if (isVersionedStatic(url)) {
		e.respondWith(
			caches.match(e.request).then(hit => hit || fetchAndCache(e.request))
		);
		return;
	}

	// CSS/JS bundles: stale-while-revalidate
	if (isBundleAsset(url)) {
		e.respondWith(
			caches.match(e.request).then(hit => {
				const fresh = fetchAndCache(e.request);
				return hit || fresh;
			})
		);
		return;
	}

	// App shell (root): network-first, fall back to cache for offline indicator
	if (url.pathname === '/' || url.pathname === '/index.php') {
		e.respondWith(
			fetch(e.request)
				.then(r => { if (r.ok) caches.open(CACHE).then(c => c.put(e.request, r.clone())); return r; })
				.catch(() => caches.match(e.request))
		);
	}
});

function fetchAndCache(request) {
	return fetch(request).then(response => {
		if (response.ok && response.type !== 'opaque') {
			caches.open(CACHE).then(c => c.put(request, response.clone()));
		}
		return response;
	});
}

// ── Web Push ──────────────────────────────────────────────────────────────
self.addEventListener('push', e => {
	if (!e.data) return;
	let d;
	try { d = e.data.json(); } catch { d = { title: 'Frickmail', body: e.data.text() }; }
	e.waitUntil(
		self.registration.showNotification(d.title || 'Frickmail', {
			body:  d.body  || '',
			icon:  '/snappymail/v/0.0.0/static/apple-touch-icon.png',
			badge: '/snappymail/v/0.0.0/static/favicon.png',
			tag:   d.tag   || 'fm-mail',
			data:  { url: d.url || '/' },
		})
	);
});

self.addEventListener('notificationclick', e => {
	e.notification.close();
	e.waitUntil(
		clients.matchAll({ type: 'window', includeUncontrolled: true }).then(cs => {
			const w = cs.find(c => new URL(c.url).origin === self.location.origin);
			return w ? w.focus() : clients.openWindow(e.notification.data?.url || '/');
		})
	);
});
