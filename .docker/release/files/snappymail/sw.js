/* Frickmail Service Worker
 *
 * Cache strategy:
 *   /snappymail/v/<ver>/static/*          cache-first     (content-addressed)
 *   /?/Css/* and /?/Js/*                  stale-while-revalidate
 *   /?Json/…MessageList or …Message       network-first, offline fallback (readable offline)
 *   /?Json/* (other API)                  network-only    (must be fresh)
 *   /  (app shell)                        network-first, offline fallback
 */
'use strict';

const CACHE    = 'fm-v4';
const MSG_CACHE = 'fm-messages-v1'; // separate TTL-controlled cache for email data

const isVersionedStatic = url =>
	/\/snappymail\/v\/[^/]+\/static\//.test(url.pathname);

const isBundleAsset = url =>
	/[?&]\/(Css|Js)\//.test(url.search) || /\/\?(Css|Js)\//.test(url.pathname + url.search);

const isMessageApiCall = url => {
	const s = url.search;
	return s.includes('Json') && (
		s.includes('_action=MessageList') ||
		s.includes('_action=Message') ||
		s.includes('_action=FrickmailUnifiedInbox')
	);
};

const isApiCall = url =>
	url.search.includes('Json') || url.search.startsWith('?/');

// ── Install: activate immediately ────────────────────────────────────────
self.addEventListener('install', () => self.skipWaiting());

// ── Activate: clean up old caches, claim clients ─────────────────────────
self.addEventListener('activate', e => {
	e.waitUntil(
		caches.keys()
			.then(keys => Promise.all(
				keys.filter(k => k !== CACHE && k !== MSG_CACHE).map(k => caches.delete(k))
			))
			.then(() => self.clients.claim())
	);
});

// ── Fetch ─────────────────────────────────────────────────────────────────
self.addEventListener('fetch', e => {
	if (e.request.method !== 'GET') return;
	const url = new URL(e.request.url);
	if (url.origin !== self.location.origin) return;

	// Message data: network-first, serve from cache when offline
	if (isMessageApiCall(url)) {
		e.respondWith(networkFirstMsg(e.request));
		return;
	}

	// Other API calls: always fresh
	if (isApiCall(url)) return;

	// Versioned static: cache-first
	if (isVersionedStatic(url)) {
		e.respondWith(caches.match(e.request).then(hit => hit || fetchAndCache(CACHE, e.request)));
		return;
	}

	// CSS/JS bundles: stale-while-revalidate
	if (isBundleAsset(url)) {
		e.respondWith(
			caches.match(e.request).then(hit => {
				const fresh = fetchAndCache(CACHE, e.request);
				return hit || fresh;
			})
		);
		return;
	}

	// App shell: network-first, offline fallback
	if (url.pathname === '/' || url.pathname === '/index.php') {
		e.respondWith(
			fetch(e.request)
				.then(r => { if (r.ok) caches.open(CACHE).then(c => c.put(e.request, r.clone())); return r; })
				.catch(() => caches.match(e.request))
		);
	}
});

// Network-first for message data: cache up to 30 min, serve stale when offline
async function networkFirstMsg(request) {
	const cached = await caches.match(request, { cacheName: MSG_CACHE });
	try {
		const fresh = await fetch(request);
		if (fresh.ok) {
			const cache = await caches.open(MSG_CACHE);
			cache.put(request, fresh.clone());
			// Prune entries older than 30 min (best-effort)
			pruneOldMsgCache();
		}
		return fresh;
	} catch {
		// Offline: serve cached version with a header indicating it's stale
		if (cached) {
			const headers = new Headers(cached.headers);
			headers.set('X-Frickmail-Offline', '1');
			return new Response(cached.body, { status: cached.status, headers });
		}
		return new Response(JSON.stringify({ Result: null, ErrorCode: 0, ErrorMessage: 'Offline' }), {
			status: 503, headers: { 'Content-Type': 'application/json', 'X-Frickmail-Offline': '1' }
		});
	}
}

let _pruning = false;
async function pruneOldMsgCache() {
	if (_pruning) return;
	_pruning = true;
	try {
		const cache = await caches.open(MSG_CACHE);
		const keys  = await cache.keys();
		const cutoff = Date.now() - 30 * 60 * 1000;
		for (const req of keys) {
			const resp = await cache.match(req);
			const date = resp?.headers.get('date');
			if (date && new Date(date).getTime() < cutoff) await cache.delete(req);
		}
	} finally { _pruning = false; }
}

function fetchAndCache(cacheName, request) {
	return fetch(request).then(response => {
		if (response.ok && response.type !== 'opaque') {
			caches.open(cacheName).then(c => c.put(request, response.clone()));
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
