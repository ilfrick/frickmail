// Frickmail cross-account full-text search
//
// Adds a "Search all accounts" button next to SnappyMail's native search bar.
// Sends the query to the FrickmailSearch endpoint and displays results in a
// slide-in overlay panel. Clicking a result switches to the owning account via
// FrickmailSwitchAccount, then reloads the app so the folder/message can be
// navigated to.

(function () {
	'use strict';

	// ── Helpers — delegate to FrickmailUtils (utils.js loaded first) ─────────

	function getToken() {
		return window.FrickmailUtils ? FrickmailUtils.fmToken()
			: (window.rl?.__frickmail_token || window.rl?.settings?.app?.('token') || '');
	}

	function pluginRequest(action, params, timeout) {
		return new Promise((resolve, reject) => {
			const r = window.rl;
			if (!r) { reject(new Error('rl not available')); return; }
			r.pluginRemoteRequest((err, data) => {
				if (err) { reject(new Error('Request error ' + err)); return; }
				resolve(data?.Result);
			}, action, Object.assign({ XToken: getToken() }, params), timeout || 15000);
		});
	}

	function escapeHtml(s) {
		return window.FrickmailUtils ? FrickmailUtils.escHtml(s) : (s ? String(s)
			.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;') : '');
	}

	function formatDate(iso) {
		if (!iso) return '';
		if (window.FrickmailUtils) return FrickmailUtils.formatDate(iso);
		try {
			const d = new Date(iso);
			return d.toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' });
		} catch (e) { return iso; }
	}

	// ── Panel ─────────────────────────────────────────────────────────────────

	let panel     = null;
	let panelList = null;
	let panelInput = null;
	let searching  = false;

	function buildPanel() {
		if (panel) return;

		panel = document.createElement('div');
		panel.id = 'fm-search-panel';
		panel.setAttribute('role', 'dialog');
		panel.setAttribute('aria-label', 'Search all accounts');
		panel.innerHTML = [
			'<div id="fm-search-header">',
			'  <input id="fm-search-input" type="search" placeholder="Search all accounts…" autocomplete="off" />',
			'  <button id="fm-search-go" type="button">Search</button>',
			'  <button id="fm-search-close" type="button" aria-label="Close">✕</button>',
			'</div>',
			'<div id="fm-search-status"></div>',
			'<ul id="fm-search-list" role="list"></ul>',
		].join('');

		// Minimal inline styles — enough to be functional without a CSS file.
		panel.style.cssText = [
			'position:fixed;top:0;right:0;width:420px;max-width:100vw;height:100vh',
			'background:var(--fm-bg-panel,#1a1a2e);color:var(--fm-text-primary,#e2e4f0)',
			'box-shadow:var(--fm-shadow-overlay,-4px 0 24px rgba(0,0,0,.35))',
			'display:flex;flex-direction:column;z-index:99999',
			'font-family:inherit;font-size:var(--fm-font-size-base,14px)',
			'transform:translateX(100%);transition:transform .22s ease',
		].join(';');

		const header = panel.querySelector('#fm-search-header');
		header.style.cssText = [
			'display:flex;gap:6px;padding:max(12px,env(safe-area-inset-top)) 12px 12px',
			'align-items:center;border-bottom:1px solid var(--fm-border,#e0e0e0)',
		].join(';');

		panelInput = panel.querySelector('#fm-search-input');
		panelInput.style.cssText = [
			'flex:1;padding:6px 10px',
			'border:1px solid var(--fm-border-input,#ccc)',
			'border-radius:var(--fm-radius-xs,4px)',
			'font-size:var(--fm-font-size-base,14px)',
			'background:var(--fm-bg-input);color:var(--fm-text-primary,inherit)',
		].join(';');

		const goBtn = panel.querySelector('#fm-search-go');
		goBtn.style.cssText = [
			'padding:6px 14px',
			'border:none;border-radius:var(--fm-radius-xs,4px)',
			'background:var(--fm-accent,#1a73e8);color:var(--fm-text-inverse,#fff)',
			'cursor:pointer;font-size:var(--fm-font-size-base,14px)',
			'touch-action:manipulation',
		].join(';');

		const closeBtn = panel.querySelector('#fm-search-close');
		closeBtn.style.cssText = [
			'background:none;border:none;font-size:20px;cursor:pointer',
			'color:inherit;padding:12px 16px;min-width:44px;min-height:44px',
			'display:flex;align-items:center;justify-content:center',
			'-webkit-tap-highlight-color:transparent;touch-action:manipulation',
		].join(';');

		const status = panel.querySelector('#fm-search-status');
		status.style.cssText = 'padding:6px 14px;font-size:var(--fm-font-size-sm,12px);color:var(--fm-text-secondary,#666);min-height:24px';

		panelList = panel.querySelector('#fm-search-list');
		panelList.style.cssText = 'flex:1;overflow-y:auto;margin:0;padding:0;list-style:none';

		document.body.appendChild(panel);

		// Events
		goBtn.addEventListener('click', runSearch);
		goBtn.addEventListener('touchend', (e) => { e.preventDefault(); runSearch(); });

		closeBtn.addEventListener('pointerdown', (e) => { e.stopPropagation(); e.preventDefault(); closePanel(); });
		closeBtn.addEventListener('click', (e) => { e.stopPropagation(); closePanel(); });
		closeBtn.addEventListener('touchend', (e) => { e.stopPropagation(); e.preventDefault(); closePanel(); });

		panelInput.addEventListener('keydown', e => { if (e.key === 'Enter') runSearch(); });
		document.addEventListener('keydown', e => {
			if (e.key === 'Escape' && panel.style.transform === 'translateX(0px)') closePanel();
		});
	}

	function openPanel(prefill) {
		buildPanel();
		panel.style.display = 'flex';
		// rAF ensures display:flex is applied before the transform transition starts
		requestAnimationFrame(() => { panel.style.transform = 'translateX(0px)'; });
		if (prefill !== undefined && prefill !== null) {
			panelInput.value = prefill;
		}
		panelInput.focus();
		if (panelInput.value.trim().length >= 2) runSearch();
	}

	function closePanel() {
		if (!panel) return;
		panel.style.transform = 'translateX(100%)';
		// Belt-and-suspenders: hide after transition in case transform doesn't work on this device
		setTimeout(() => { if (panel) panel.style.display = 'none'; }, 250);
	}

	function setStatus(msg) {
		const el = panel?.querySelector('#fm-search-status');
		if (el) el.textContent = msg;
	}

	// ── Search ────────────────────────────────────────────────────────────────

	async function runSearch() {
		const q = panelInput?.value?.trim() || '';
		if (q.length < 2) { setStatus('Please enter at least 2 characters.'); return; }
		if (searching) return;
		searching = true;
		setStatus('Searching…');
		panelList.innerHTML = '';

		try {
			const res = await pluginRequest('FrickmailSearch', { q, limit: 50 }, 20000);
			if (!res?.ok) {
				setStatus(res?.error || 'Search failed.');
				return;
			}
			const results = res.results || [];
			if (results.length === 0) {
				setStatus('No results for "' + escapeHtml(q) + '".');
				return;
			}
			setStatus(results.length + ' result' + (results.length === 1 ? '' : 's') + ' for "' + escapeHtml(q) + '"');
			renderResults(results);
		} catch (err) {
			setStatus('Error: ' + err.message);
		} finally {
			searching = false;
		}
	}

	function renderResults(rows) {
		panelList.innerHTML = '';
		rows.forEach(row => {
			const li = document.createElement('li');
			li.style.cssText = 'border-bottom:1px solid var(--fm-border,#eee);padding:10px 14px;cursor:pointer';
			li.innerHTML = [
				'<div style="display:flex;align-items:baseline;gap:8px;flex-wrap:wrap">',
				'  <span style="font-weight:var(--fm-font-weight-semi,600);flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">',
				    escapeHtml(row.subject || '(no subject)'),
				'  </span>',
				'  <span style="font-size:var(--fm-font-size-xs,11px);color:var(--fm-text-muted,#888);white-space:nowrap">',
				    escapeHtml(formatDate(row.date_ts)),
				'  </span>',
				'</div>',
				'<div style="display:flex;align-items:center;gap:8px;margin-top:2px;flex-wrap:wrap">',
				'  <span style="font-size:var(--fm-font-size-sm,12px);color:var(--fm-text-secondary,#555);flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">',
				    escapeHtml(row.from_name ? row.from_name + ' <' + row.from_addr + '>' : (row.from_addr || '')),
				'  </span>',
				'  <span style="font-size:var(--fm-font-size-xs,11px);background:var(--fm-accent,#1a73e8);color:var(--fm-text-inverse,#fff);border-radius:10px;padding:1px 8px;white-space:nowrap">',
				    escapeHtml(row.account_email || ''),
				'  </span>',
				'</div>',
				row.snippet ? '<div style="font-size:var(--fm-font-size-sm,12px);color:var(--fm-text-muted,#666);margin-top:4px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">' + escapeHtml(row.snippet) + '</div>' : '',
			].join('');

			li.addEventListener('mouseenter', () => { li.style.background = 'var(--fm-bg-hover,#f5f5f5)'; });
			li.addEventListener('mouseleave', () => { li.style.background = ''; });
			li.addEventListener('click', () => switchAndOpen(row));

			panelList.appendChild(li);
		});
	}

	async function switchAndOpen(row) {
		try {
			setStatus('Switching to ' + escapeHtml(row.account_email) + '…');
			const res = await pluginRequest('FrickmailSwitchAccount', { id: row.account_id }, 30000);
			if (!res?.ok) {
				setStatus('Switch failed: ' + (res?.error || 'unknown error'));
				return;
			}
			// Reload the app — the user lands in the inbox of the target account.
			// A future enhancement could deep-link directly to the folder/uid.
			closePanel();
			window.rl?.route?.reload?.() || window.location.reload();
		} catch (err) {
			setStatus('Error: ' + err.message);
		}
	}

	// ── Toolbar button injection ──────────────────────────────────────────────

	function injectButton(toolbarEl) {
		if (toolbarEl.querySelector('#fm-search-btn')) return;

		const btn = document.createElement('button');
		btn.id = 'fm-search-btn';
		btn.type = 'button';
		btn.title = 'Search all accounts';
		btn.textContent = '🔍 All accounts';
		btn.style.cssText = [
			'margin-left:6px;padding:4px 10px',
			'border:1px solid var(--fm-border,#ccc);border-radius:var(--fm-radius-xs,4px)',
			'background:var(--fm-bg-input,#fff);color:inherit',
			'cursor:pointer;font-size:var(--fm-font-size-sm,13px);white-space:nowrap',
			'touch-action:manipulation',
		].join(';');

		btn.addEventListener('click', () => {
			// Try to grab the current search-input value as prefill.
			const nativeInput = document.querySelector('.b-search-field input, [data-bind*="search"] input, input[type="search"]');
			openPanel(nativeInput?.value?.trim() || null);
		});

		toolbarEl.appendChild(btn);
	}

	// ── rl-view-model integration ─────────────────────────────────────────────
	// Inject button when the MessageList or SystemDropDown view model mounts.

	addEventListener('rl-view-model', e => {
		const id  = e.detail?.viewModelTemplateID;
		const dom = e.detail?.viewModelDom;
		if (!dom) return;
		if (id === 'MessageList' || id === 'MailBox' || id === 'TopToolBar' || id === 'SystemDropDown') {
			setTimeout(() => {
				// Look for SnappyMail's search bar wrapper or the top toolbar.
				const searchBar = dom.querySelector('.b-search, [class*="search-bar"], [class*="toolbar"]');
				const target    = searchBar || dom;
				injectButton(target);
			}, 300);
		}
	});

	// Fallback: watch for DOM changes to find the search bar after initial render.
	const observer = new MutationObserver(() => {
		const toolbar = document.querySelector('.b-search, .toolbar, [class*="top-toolbar"]');
		if (toolbar && !toolbar.querySelector('#fm-search-btn')) {
			injectButton(toolbar);
		}
	});
	observer.observe(document.documentElement, { childList: true, subtree: true });

	// Expose for external use (e.g. from other plugins or console debugging).
	window.FrickmailSearch = { open: openPanel, search: runSearch };
})();
