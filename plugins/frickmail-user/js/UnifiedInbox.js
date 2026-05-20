// Frickmail Unified Inbox — adds an "All accounts" button to the message list
// toolbar. When clicked, fetches recent messages from every IMAP account and
// shows them in an overlay sorted by date. Clicking a message switches to the
// correct account and opens its inbox.
//
// Hooks into rl-view-model when viewModelTemplateID === 'MailMessageList'.

(function () {
	'use strict';

	// ── Colour palette for account badges (cycled by account index) ──────────
	const BADGE_COLORS = [
		'#4a90d9', '#e67e22', '#27ae60', '#8e44ad',
		'#c0392b', '#16a085', '#f39c12', '#2980b9',
	];

	// ── State ─────────────────────────────────────────────────────────────────
	let overlayEl   = null;
	let btnEl       = null;
	let isOpen      = false;
	let isLoading   = false;
	// Map account_email → { id, color, initial }
	let accountMeta = {};

	// ── Helpers — delegate to FrickmailUtils (utils.js loaded first) ─────────

	function fmToken() {
		return window.FrickmailUtils ? FrickmailUtils.fmToken()
			: (window.rl?.__frickmail_token || window.rl?.settings?.app?.('token') || '');
	}

	/**
	 * Format a unix timestamp as a short human-readable date.
	 * Delegates to FrickmailUtils.formatDate (which handles both unix timestamps
	 * and ISO strings).  Keeps same-day → HH:MM, same-year → Mon DD, else → Mon DD YYYY.
	 */
	function formatDate(ts) {
		if (!ts) return '';
		if (window.FrickmailUtils) return FrickmailUtils.formatDate(ts);
		// Fallback (unix seconds)
		const d   = new Date(ts * 1000);
		const now = new Date();
		const pad = n => String(n).padStart(2, '0');
		if (d.toDateString() === now.toDateString()) {
			return pad(d.getHours()) + ':' + pad(d.getMinutes());
		}
		const months = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
		if (d.getFullYear() === now.getFullYear()) {
			return months[d.getMonth()] + ' ' + d.getDate();
		}
		return months[d.getMonth()] + ' ' + d.getDate() + ' ' + d.getFullYear();
	}

	function escHtml(s) {
		return window.FrickmailUtils ? FrickmailUtils.escHtml(s) : String(s || '')
			.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
	}

	// ── Build accountMeta from a ListAccounts response cached by AccountSwitcher
	function refreshAccountMeta(accounts) {
		accountMeta = {};
		(accounts || []).forEach((acc, i) => {
			const initial = (acc.label || acc.email || '?')[0].toUpperCase();
			accountMeta[acc.email] = {
				id:      acc.id,
				color:   BADGE_COLORS[i % BADGE_COLORS.length],
				initial: initial,
				label:   acc.label || acc.email,
			};
		});
	}

	// ── Overlay ────────────────────────────────────────────────────────────────

	function createOverlay() {
		const el = document.createElement('div');
		el.id = 'fm-unified-inbox';
		el.setAttribute('role', 'dialog');
		el.setAttribute('aria-label', 'All accounts inbox');
		el.style.cssText = [
			'position:fixed',
			'top:0','left:0','right:0','bottom:0',
			'z-index:99999',
			'display:flex',
			'flex-direction:column',
			'background:var(--fm-bg-panel,#1a1a2e)',
			'color:var(--fm-text-primary,#e2e4f0)',
			'font-family:inherit',
			'overflow:hidden',
		].join(';');
		el.innerHTML = `
			<div style="display:flex;align-items:center;padding:max(10px,env(safe-area-inset-top)) 16px 10px;border-bottom:1px solid var(--fm-border,rgba(255,255,255,.1));gap:8px;">
				<span style="font-weight:var(--fm-font-weight-semi,600);font-size:var(--fm-font-size-lg,1rem);flex:1">All accounts</span>
				<span id="fm-ui-status" style="font-size:var(--fm-font-size-sm,.8rem);opacity:.7"></span>
				<button id="fm-ui-refresh" title="Refresh" style="background:none;border:none;color:inherit;cursor:pointer;font-size:1rem;opacity:.8;padding:4px 8px;min-width:44px;min-height:44px;touch-action:manipulation;">&#8635;</button>
				<button id="fm-ui-close"   title="Close"   style="background:none;border:none;color:inherit;cursor:pointer;font-size:1.2rem;padding:4px 8px;min-width:44px;min-height:44px;touch-action:manipulation;">&times;</button>
			</div>
			<div id="fm-ui-list" style="flex:1;overflow-y:auto;"></div>
		`;
		document.body.appendChild(el);

		const closeBtn = el.querySelector('#fm-ui-close');
		closeBtn.addEventListener('click', closeOverlay);
		closeBtn.addEventListener('touchend', (e) => { e.preventDefault(); closeOverlay(); });

		const refreshBtn = el.querySelector('#fm-ui-refresh');
		refreshBtn.addEventListener('click', () => loadMessages());
		refreshBtn.addEventListener('touchend', (e) => { e.preventDefault(); loadMessages(); });

		// Close on Escape key
		el._keyHandler = (e) => { if (e.key === 'Escape') closeOverlay(); };
		document.addEventListener('keydown', el._keyHandler);

		return el;
	}

	function openOverlay() {
		if (!overlayEl) overlayEl = createOverlay();
		overlayEl.hidden = false;
		isOpen = true;
		loadMessages();
	}

	function closeOverlay() {
		if (overlayEl) overlayEl.hidden = true;
		isOpen = false;
	}

	// ── Load messages ─────────────────────────────────────────────────────────

	function loadMessages() {
		if (isLoading) return;
		isLoading = true;

		const list   = overlayEl?.querySelector('#fm-ui-list');
		const status = overlayEl?.querySelector('#fm-ui-status');
		if (list)   list.innerHTML = '<div style="padding:32px;text-align:center;opacity:.6">Loading…</div>';
		if (status) status.textContent = '';

		const r = window.rl;
		if (!r) { isLoading = false; return; }

		// Refresh account metadata from cache before displaying
		try {
			const cached = JSON.parse(localStorage.getItem('frickmail_accounts_cache') || 'null');
			if (cached) refreshAccountMeta(cached);
		} catch (e) {}

		r.pluginRemoteRequest((iErr, oData) => {
			isLoading = false;
			const res = oData?.Result;

			if (!res?.ok) {
				if (list) list.innerHTML = '<div style="padding:32px;text-align:center;color:#f38ba8">Failed to load messages: ' + escHtml(res?.error || 'unknown error') + '</div>';
				return;
			}

			const msgs = res.messages || [];
			if (status) status.textContent = msgs.length + ' messages';
			renderMessages(msgs, list);
		}, 'FrickmailUnifiedInbox', { limit: 40, XToken: fmToken() }, 15000);
	}

	// ── Render ────────────────────────────────────────────────────────────────

	function renderMessages(msgs, container) {
		if (!container) return;

		if (!msgs.length) {
			container.innerHTML = '<div style="padding:32px;text-align:center;opacity:.6">No messages found.</div>';
			return;
		}

		const frag = document.createDocumentFragment();

		msgs.forEach(msg => {
			const meta    = accountMeta[msg.account_email] || { color: '#888', initial: '?', id: msg.account_id, label: msg.account_email };
			const isSeen  = msg.is_seen;
			const row     = document.createElement('div');
			row.style.cssText = [
				'display:flex',
				'align-items:center',
				'gap:10px',
				'padding:10px 16px',
				'border-bottom:1px solid var(--fm-border,rgba(255,255,255,.06))',
				'cursor:pointer',
				isSeen ? 'opacity:.7' : 'font-weight:var(--fm-font-weight-semi,600)',
			].join(';');
			row.setAttribute('tabindex', '0');
			row.setAttribute('role', 'button');
			row.setAttribute('aria-label', escHtml((msg.from || '(no sender)') + ' — ' + (msg.subject || '(no subject)')));

			// Account badge
			const badge = document.createElement('span');
			badge.title = meta.label;
			badge.style.cssText = [
				'display:inline-flex',
				'align-items:center',
				'justify-content:center',
				'width:28px','height:28px',
				'border-radius:50%',
				'font-size:.75rem',
				'font-weight:var(--fm-font-weight-bold,700)',
				'flex-shrink:0',
				'background:' + meta.color,
				'color:#fff',
			].join(';');
			badge.textContent = meta.initial;

			// Main content
			const content = document.createElement('div');
			content.style.cssText = 'flex:1;min-width:0;';

			const topLine = document.createElement('div');
			topLine.style.cssText = 'display:flex;justify-content:space-between;gap:8px;';

			const fromEl = document.createElement('span');
			fromEl.style.cssText = 'overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:60%;';
			fromEl.textContent = msg.from || '(no sender)';

			const dateEl = document.createElement('span');
			dateEl.style.cssText = 'font-size:.75rem;opacity:.6;white-space:nowrap;flex-shrink:0;';
			dateEl.textContent = formatDate(msg.date_ts);

			topLine.appendChild(fromEl);
			topLine.appendChild(dateEl);

			const subjectEl = document.createElement('div');
			subjectEl.style.cssText = 'font-size:var(--fm-font-size-sm,.85rem);opacity:.8;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;margin-top:2px;';
			subjectEl.textContent = msg.subject || '(no subject)';

			content.appendChild(topLine);
			content.appendChild(subjectEl);

			row.appendChild(badge);
			row.appendChild(content);

			// Click / Enter / touch: switch account then navigate to inbox
			const handleActivate = () => openMessage(msg, meta);
			row.addEventListener('click', handleActivate);
			row.addEventListener('touchend', (e) => { e.preventDefault(); handleActivate(); });
			row.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') handleActivate(); });

			// Hover highlight
			row.addEventListener('mouseenter', () => { row.style.background = 'var(--fm-bg-hover,rgba(255,255,255,.05))'; });
			row.addEventListener('mouseleave', () => { row.style.background = ''; });

			frag.appendChild(row);
		});

		container.innerHTML = '';
		container.appendChild(frag);
	}

	// ── Open a message: switch account → navigate ─────────────────────────────

	function openMessage(msg, meta) {
		const r = window.rl;
		if (!r) return;

		closeOverlay();

		r.pluginRemoteRequest((iErr, oData) => {
			if (oData?.Result?.ok) {
				// Reload the app into the switched account's inbox.
				r.route?.reload?.();
			} else {
				const err = oData?.Result?.error || 'Account switch failed';
				alert('Frickmail: ' + err);
			}
		}, 'FrickmailSwitchAccount',
			{ id: meta.id, XToken: fmToken() },
			30000
		);
	}

	// ── Inject "All accounts" button into MailMessageList toolbar ─────────────

	function injectButton(toolbarEl) {
		if (btnEl && toolbarEl.contains(btnEl)) return;

		btnEl = document.createElement('button');
		btnEl.type = 'button';
		btnEl.textContent = 'All accounts';
		btnEl.title = 'Unified inbox — messages from all accounts';
		btnEl.style.cssText = [
			'margin-left:4px',
			'padding:4px 10px',
			'border-radius:var(--fm-radius-xs,4px)',
			'border:1px solid var(--fm-border,rgba(255,255,255,.2))',
			'background:var(--fm-bg-input,rgba(255,255,255,.07))',
			'color:inherit',
			'font-size:var(--fm-font-size-sm,.8rem)',
			'cursor:pointer',
			'white-space:nowrap',
			'touch-action:manipulation',
		].join(';');
		btnEl.addEventListener('click', () => {
			if (isOpen) closeOverlay();
			else openOverlay();
		});
		btnEl.addEventListener('touchend', (e) => {
			e.preventDefault();
			if (isOpen) closeOverlay();
			else openOverlay();
		});

		// Try to append after the last toolbar button; fall back to appending directly.
		const btns = toolbarEl.querySelectorAll('button, a.button, .toolbar-button');
		if (btns.length) {
			btns[btns.length - 1].after(btnEl);
		} else {
			toolbarEl.appendChild(btnEl);
		}
	}

	// ── rl-view-model hook ────────────────────────────────────────────────────

	addEventListener('rl-view-model', e => {
		if (e.detail?.viewModelTemplateID !== 'MailMessageList') return;
		const dom = e.detail.viewModelDom;
		if (!dom) return;

		setTimeout(() => {
			// Find the toolbar — try common selectors used by SnappyMail.
			const toolbar = dom.querySelector('.listActions, .toolbar, [class*="toolbar"], .b-mail-message-list .pToolbar')
				|| dom.querySelector('div');
			if (!toolbar) return;

			injectButton(toolbar);
		}, 300);
	});

})();
