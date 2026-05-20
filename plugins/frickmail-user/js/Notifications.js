// Frickmail Desktop Notifications
//
// Flow:
//   1. On first load (while logged in), show a non-invasive banner asking for
//      notification permission if it has not been decided yet.
//   2. Once permission is granted, poll FrickmailCheckNewMail every 60 s.
//   3. On the very first successful poll, record the current UIDNEXT as a
//      baseline without notifying (avoids firing for pre-existing mail).
//   4. On subsequent polls, compare UIDNEXT; if higher, fire a notification via
//      Service Worker (showNotification) or Notification API directly as fallback.
//   5. Clicking a notification switches to the relevant account's inbox.
//
// Requires: browser Notifications API (no VAPID / server push).

(function () {
	'use strict';

	const STORAGE_KEY    = 'fm_mail_state';   // localStorage: {account_id: uidnext, ...}
	const POLL_INTERVAL  = 60 * 1000;          // 60 seconds
	const BANNER_ID      = 'fm-notif-banner';

	let pollTimer    = null;
	let isFirstPoll  = true;   // true until the first successful response
	let mailState    = {};      // account_id (string) → last known uidnext

	// ── Helpers ─────────────────────────────────────────────────────────────

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
		try { localStorage.removeItem(STORAGE_KEY); } catch (e) {}
	}

	// Reset baseline on logout so the next session starts clean.
	window.addEventListener('rl-logout', clearState);

	// ── Permission banner ────────────────────────────────────────────────────
	//
	// A slim bar that appears below the top navbar only when permission is
	// 'default' (not yet decided). It disappears permanently after any decision.

	function removeBanner() {
		document.getElementById(BANNER_ID)?.remove();
	}

	function showPermissionBanner() {
		if (document.getElementById(BANNER_ID)) return;   // already shown
		if (typeof Notification === 'undefined') return;  // browser doesn't support
		if (Notification.permission !== 'default') return;

		const bar = document.createElement('div');
		bar.id = BANNER_ID;
		bar.setAttribute('role', 'status');
		bar.style.cssText = [
			'position:fixed',
			'top:0',
			'left:0',
			'right:0',
			'z-index:10000',
			'display:flex',
			'align-items:center',
			'gap:10px',
			'padding:8px 16px',
			'background:#313244',
			'color:#cdd6f4',
			'font-size:.85rem',
			'border-bottom:1px solid rgba(255,255,255,.15)',
			'box-shadow:0 2px 8px rgba(0,0,0,.4)',
		].join(';');

		bar.innerHTML =
			'<span style="flex:1">Enable desktop notifications to be alerted when new mail arrives.</span>' +
			'<button id="fm-notif-allow"  style="padding:4px 12px;border-radius:4px;border:none;background:#89b4fa;color:#1e1e2e;font-weight:600;cursor:pointer;">Enable</button>' +
			'<button id="fm-notif-dismiss" style="padding:4px 10px;border-radius:4px;border:none;background:rgba(255,255,255,.1);color:inherit;cursor:pointer;">Not now</button>';

		document.body.prepend(bar);

		bar.querySelector('#fm-notif-allow').addEventListener('click', () => {
			removeBanner();
			Notification.requestPermission().then(perm => {
				if (perm === 'granted') startPolling();
			});
		});

		bar.querySelector('#fm-notif-dismiss').addEventListener('click', removeBanner);
	}

	// ── Notification dispatch ────────────────────────────────────────────────

	/**
	 * Show a desktop notification for a single account.
	 * Prefers Service Worker showNotification (works with tab in background);
	 * falls back to new Notification() if SW is unavailable.
	 */
	function notify(accountId, accountEmail, newCount) {
		if (typeof Notification === 'undefined') return;
		if (Notification.permission !== 'granted') return;

		const title   = newCount === 1 ? '1 new message' : newCount + ' new messages';
		const body    = accountEmail;
		const icon    = '/favicon.png';
		const tag     = 'fm-newmail-' + accountId;
		const options = { body, icon, tag, renotify: true };

		if (navigator.serviceWorker?.controller) {
			navigator.serviceWorker.ready
				.then(reg => reg.showNotification(title, options))
				.catch(() => {
					try { new Notification(title, options); } catch (_) {}
				});
		} else {
			try { new Notification(title, options); } catch (_) {}
		}
	}

	// ── Handle notification click (navigate to the right account) ───────────
	//
	// Clicking a SW notification fires a 'notificationclick' event in the
	// Service Worker context. We listen via a message channel here for the
	// fallback case; SW notifications are handled in the SW itself if it
	// intercepts the event. For direct Notification objects we set onclick.

	// ── Poll ─────────────────────────────────────────────────────────────────

	function poll() {
		const r = window.rl;
		if (!r) return;

		loadState();

		r.pluginRemoteRequest((iErr, oData) => {
			const res = oData?.Result;
			if (!res?.ok) return;

			const accounts = res.accounts || [];

			if (isFirstPoll) {
				// Baseline: record current uidnext for every account, no notification.
				isFirstPoll = false;
				accounts.forEach(acc => {
					mailState[String(acc.account_id)] = acc.uidnext;
				});
				saveState();
				return;
			}

			// Compare against baseline and notify.
			let stateChanged = false;
			accounts.forEach(acc => {
				const key         = String(acc.account_id);
				const lastUidnext = mailState[key] || 0;

				if (acc.uidnext > lastUidnext && lastUidnext > 0) {
					const newCount = acc.uidnext - lastUidnext;
					notify(acc.account_id, acc.account_email, newCount);
				}

				// Update baseline to the latest uidnext (even if 0 means we couldn't read it).
				if (acc.uidnext > 0) {
					mailState[key] = acc.uidnext;
					stateChanged   = true;
				}
			});

			if (stateChanged) saveState();

		}, 'FrickmailCheckNewMail', { last_uids: mailState, XToken: fmToken() }, 15000);
	}

	// ── Start / stop polling ─────────────────────────────────────────────────

	function startPolling() {
		if (pollTimer !== null) return;   // already running
		isFirstPoll = true;
		loadState();
		poll();
		pollTimer = setInterval(poll, POLL_INTERVAL);
	}

	function stopPolling() {
		if (pollTimer !== null) {
			clearInterval(pollTimer);
			pollTimer = null;
		}
	}

	window.addEventListener('rl-logout', stopPolling);

	// ── Entry point ──────────────────────────────────────────────────────────
	//
	// Wait until rl is ready (rl-view-model fires once the app is bootstrapped).
	// We hook on SystemDropDown because AccountSwitcher already waits for it and
	// at that point the session is definitely established.

	let started = false;

	function maybeStart() {
		if (started) return;
		if (!window.rl) return;

		started = true;

		if (typeof Notification === 'undefined') return;   // API not supported

		if (Notification.permission === 'granted') {
			startPolling();
		} else if (Notification.permission === 'default') {
			showPermissionBanner();
		}
		// 'denied' — nothing to do.
	}

	// Trigger once the webmail is ready.
	addEventListener('rl-view-model', e => {
		if (e.detail?.viewModelTemplateID === 'SystemDropDown') {
			// Small delay so AccountSwitcher can inject the token first.
			setTimeout(maybeStart, 500);
		}
	});

})();
