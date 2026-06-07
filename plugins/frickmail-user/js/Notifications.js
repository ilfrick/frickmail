// Frickmail Desktop Notifications
//
// Detection strategy: long-poll (FrickmailLongPollNewMail).
//   The server holds the connection for up to 25 s, checking IMAP every 5 s,
//   and returns immediately when new mail arrives.  The client reconnects right
//   away, giving ≤5 s latency instead of the previous 60 s fixed interval.
//
// User preference "Notification check interval" (30–300 s, set in
//   Settings → Frickmail Preferences) now controls the *reconnect delay*
//   after a long-poll timeout (i.e. how long to wait before the next
//   long-poll if no new mail was found).  Default 60 s.
//
// Fallback: if long-poll fails repeatedly, drops back to one-shot
//   FrickmailCheckNewMail with the same reconnect interval.
//
// Requires: browser Notifications API.  VAPID / server push not needed.

(function () {
	'use strict';

	const STORAGE_KEY     = 'fm_mail_state';
	const BANNER_ID       = 'fm-notif-banner';
	const DEFAULT_INTERVAL = 60;   // seconds — used if preference not loaded yet
	const MIN_INTERVAL     = 30;
	const MAX_INTERVAL     = 300;

	let reconnectTimer = null;
	let isFirstPoll    = true;
	let mailState      = {};       // account_id → last known uidnext
	let reconnectDelay = DEFAULT_INTERVAL * 1000;
	let stopped        = false;
	let longPollFails  = 0;

	// ── Helpers ──────────────────────────────────────────────────────────────

	function fmToken() {
		return window.rl?.__frickmail_token || window.rl?.settings?.app?.('token') || '';
	}

	function loadState() {
		try { mailState = JSON.parse(localStorage.getItem(STORAGE_KEY) || '{}'); } catch (e) { mailState = {}; }
	}

	function saveState() {
		try { localStorage.setItem(STORAGE_KEY, JSON.stringify(mailState)); } catch (e) {}
	}

	function clearState() {
		mailState = {};
		isFirstPoll = true;
		try { localStorage.removeItem(STORAGE_KEY); } catch (e) {}
	}

	window.addEventListener('rl-logout', clearState);

	// ── Load user preference + register Web Push subscription ────────────────

	function loadPrefThenStart() {
		const r = window.rl;
		if (!r) return;
		r.pluginRemoteRequest((iErr, oData) => {
			const interval = +(oData?.Result?.prefs?.notifications_poll_interval || DEFAULT_INTERVAL);
			reconnectDelay = Math.max(MIN_INTERVAL, Math.min(MAX_INTERVAL, interval)) * 1000;
			registerWebPush();   // fire-and-forget, doesn't block long-poll
			startLongPoll();
		}, 'FrickmailGetPrefs', { XToken: fmToken() }, 10000);
	}

	// ── Web Push subscription ─────────────────────────────────────────────────
	//
	// Fetches the VAPID public key from the server, subscribes the SW to the
	// browser's push service, then POSTs the PushSubscription to the backend.
	// If the SW is not active or push is not supported, silently skips.

	function registerWebPush() {
		if (!navigator.serviceWorker || !('PushManager' in window)) return;

		navigator.serviceWorker.ready.then(reg => {
			window.rl.pluginRemoteRequest((iErr, oData) => {
				const pubKeyB64u = oData?.Result?.public_key;
				if (!pubKeyB64u) return;
				const appServerKey = urlBase64ToUint8Array(pubKeyB64u);
				const subscribe = () => reg.pushManager
					.subscribe({ userVisibleOnly: true, applicationServerKey: appServerKey })
					.then(sub => sendSubscriptionToServer(sub))
					.catch(() => {});   // push blocked by user or browser

				reg.pushManager.getSubscription().then(existing => {
					if (existing && subscriptionUsesServerKey(existing, appServerKey)) {
						// Re-send to server in case it was lost (idempotent upsert on backend).
						sendSubscriptionToServer(existing);
						return;
					}
					if (existing) {
						existing.unsubscribe().catch(() => {}).then(subscribe);
						return;
					}
					subscribe();
				}).catch(() => {});
			}, 'FrickmailGetVapidKey', { XToken: fmToken() }, 10000);
		}).catch(() => {});
	}

	function subscriptionUsesServerKey(sub, appServerKey) {
		const existingKey = sub?.options?.applicationServerKey;
		if (!existingKey) return false;
		const existing = new Uint8Array(existingKey);
		if (existing.length !== appServerKey.length) return false;
		for (let i = 0; i < existing.length; i++) {
			if (existing[i] !== appServerKey[i]) return false;
		}
		return true;
	}

	function sendSubscriptionToServer(sub) {
		const json = sub.toJSON();
		window.rl.pluginRemoteRequest(() => {}, 'FrickmailPushSubscribe', {
			endpoint: json.endpoint,
			p256dh:   json.keys?.p256dh   || '',
			auth:     json.keys?.auth      || '',
			XToken:   fmToken(),
		}, 10000);
	}

	function urlBase64ToUint8Array(b64u) {
		const pad = b64u.length % 4 === 0 ? '' : '===='.slice(b64u.length % 4);
		const b64 = (b64u + pad).replace(/-/g, '+').replace(/_/g, '/');
		const raw = atob(b64);
		return Uint8Array.from(raw, c => c.charCodeAt(0));
	}

	// ── Permission banner ─────────────────────────────────────────────────────

	function removeBanner() {
		document.getElementById(BANNER_ID)?.remove();
	}

	function showPermissionBanner() {
		if (document.getElementById(BANNER_ID)) return;
		if (typeof Notification === 'undefined') return;
		if (Notification.permission !== 'default') return;

		const bar = document.createElement('div');
		bar.id = BANNER_ID;
		bar.setAttribute('role', 'status');
		bar.style.cssText = [
			'position:fixed', 'top:0', 'left:0', 'right:0', 'z-index:10000',
			'display:flex', 'align-items:center', 'gap:10px',
			'padding:8px 16px', 'background:#313244', 'color:#cdd6f4',
			'font-size:.85rem', 'border-bottom:1px solid rgba(255,255,255,.15)',
			'box-shadow:0 2px 8px rgba(0,0,0,.4)',
		].join(';');

		bar.innerHTML =
			'<span style="flex:1">Enable desktop notifications to be alerted when new mail arrives.</span>' +
			'<button id="fm-notif-allow" style="padding:4px 12px;border-radius:4px;border:none;background:#89b4fa;color:#1e1e2e;font-weight:600;cursor:pointer;">Enable</button>' +
			'<button id="fm-notif-dismiss" style="padding:4px 10px;border-radius:4px;border:none;background:rgba(255,255,255,.1);color:inherit;cursor:pointer;">Not now</button>';

		document.body.prepend(bar);

		bar.querySelector('#fm-notif-allow').addEventListener('click', () => {
			removeBanner();
			Notification.requestPermission().then(perm => {
				if (perm === 'granted') loadPrefThenStart();
			});
		});
		bar.querySelector('#fm-notif-dismiss').addEventListener('click', removeBanner);
	}

	// ── Notification dispatch ─────────────────────────────────────────────────

	function notify(accountId, accountEmail, newCount) {
		if (typeof Notification === 'undefined') return;
		if (Notification.permission !== 'granted') return;

		const title   = newCount === 1 ? '1 new message' : newCount + ' new messages';
		const options = { body: accountEmail, icon: '/favicon.png',
		                  tag: 'fm-newmail-' + accountId, renotify: true };

		if (navigator.serviceWorker?.controller) {
			navigator.serviceWorker.ready
				.then(reg => reg.showNotification(title, options))
				.catch(() => { try { new Notification(title, options); } catch (_) {} });
		} else {
			try { new Notification(title, options); } catch (_) {}
		}
	}

	// ── Long-poll cycle ───────────────────────────────────────────────────────
	//
	// One cycle: send FrickmailLongPollNewMail, wait up to 30 s for the server
	// to respond (server holds ≤25 s internally).
	//
	//  • New mail found     → notify, update state, immediately start next cycle.
	//  • Timeout (no mail)  → wait reconnectDelay, then start next cycle.
	//  • Error              → after 3 consecutive failures fall back to
	//                         FrickmailCheckNewMail with the same reconnect delay.

	function startLongPoll() {
		if (stopped) return;
		loadState();

		const action = longPollFails < 3 ? 'FrickmailLongPollNewMail' : 'FrickmailCheckNewMail';
		const timeout = action === 'FrickmailLongPollNewMail' ? 32000 : 15000;

		window.rl.pluginRemoteRequest((iErr, oData) => {
			if (stopped) return;

			const res = oData?.Result;

			if (!res?.ok) {
				longPollFails++;
				scheduleReconnect(reconnectDelay);
				return;
			}

			if (action === 'FrickmailLongPollNewMail') longPollFails = 0;

			const accounts = res.accounts || [];
			processAccounts(accounts);

			if (res.timeout) {
				// Server found nothing in 25 s → wait reconnectDelay before next poll.
				scheduleReconnect(reconnectDelay);
			} else {
				// New mail was found (or this was a one-shot check) → poll again immediately.
				scheduleReconnect(0);
			}
		}, action, { last_uids: mailState, XToken: fmToken() }, timeout);
	}

	function processAccounts(accounts) {
		if (isFirstPoll) {
			// Baseline: record current uidnext without notifying.
			isFirstPoll = false;
			accounts.forEach(acc => { mailState[String(acc.account_id)] = acc.uidnext; });
			saveState();
			return;
		}

		let stateChanged = false;
		accounts.forEach(acc => {
			const key         = String(acc.account_id);
			const lastUidnext = mailState[key] || 0;

			if ((acc.new_count ?? 0) > 0 && lastUidnext > 0) {
				notify(acc.account_id, acc.account_email, acc.new_count);
			}

			if (acc.uidnext > 0) {
				mailState[key] = acc.uidnext;
				stateChanged   = true;
			}
		});

		if (stateChanged) saveState();
	}

	function scheduleReconnect(delayMs) {
		if (stopped) return;
		if (reconnectTimer !== null) clearTimeout(reconnectTimer);
		reconnectTimer = setTimeout(() => { reconnectTimer = null; startLongPoll(); }, delayMs);
	}

	function stopPolling() {
		stopped = true;
		if (reconnectTimer !== null) { clearTimeout(reconnectTimer); reconnectTimer = null; }
	}

	window.addEventListener('rl-logout', stopPolling);

	// ── Entry point ───────────────────────────────────────────────────────────

	let started = false;

	function maybeStart() {
		if (started || !window.rl) return;
		started = true;
		stopped = false;

		if (typeof Notification === 'undefined') return;

		if (Notification.permission === 'granted') {
			loadPrefThenStart();
		} else if (Notification.permission === 'default') {
			showPermissionBanner();
		}
	}

	addEventListener('rl-view-model', e => {
		if (e.detail?.viewModelTemplateID === 'SystemDropDown') {
			setTimeout(maybeStart, 500);
		}
	});

})();
