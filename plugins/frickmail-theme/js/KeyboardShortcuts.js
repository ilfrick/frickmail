// Frickmail Keyboard Shortcuts
// Thunderbird-inspired keybindings for power users.
//
// Active only when focus is NOT in a text input / contenteditable.
//
// Key       Action
// ─────────────────────────────────────────────
// ?         Show / hide this help overlay
// c         Compose new message
// /         Focus search box
// j / n     Select next message
// k / p     Select previous message
// r         Reply
// a         Reply all
// f         Forward
// u         Back to message list
// m         Toggle read / unread
// Escape    Close modal / overlay

(function () {
	'use strict';

	// ── helpers ──────────────────────────────────────────────────────────

	const inTextField = () => {
		const el = document.activeElement;
		if (!el) return false;
		const tag = el.tagName;
		return tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT' ||
			el.isContentEditable || el.closest('[contenteditable]');
	};

	const click = selector => {
		const el = document.querySelector(selector);
		if (el) { el.click(); return true; }
		return false;
	};

	// ── help overlay ─────────────────────────────────────────────────────

	const SHORTCUTS = [
		['?',     'Toggle this help'],
		['c',     'Compose new message'],
		['/',     'Focus search'],
		['j / n', 'Next message'],
		['k / p', 'Previous message'],
		['r',     'Reply'],
		['a',     'Reply all'],
		['f',     'Forward'],
		['u',     'Back to message list'],
		['m',     'Toggle read / unread'],
		['Escape','Close overlay / go back'],
	];

	let helpVisible = false;
	let helpEl = null;

	const showHelp = () => {
		if (helpEl) { helpEl.remove(); helpEl = null; helpVisible = false; return; }
		helpEl = document.createElement('div');
		helpEl.id = 'fm-shortcuts-help';
		helpEl.style.cssText = [
			'position:fixed','top:50%','left:50%',
			'transform:translate(-50%,-50%)',
			'background:var(--fm-bg-panel,#1e2030)',
			'color:var(--fm-text,#cdd6f4)',
			'border:1px solid var(--fm-border,#414868)',
			'border-radius:12px','padding:24px 32px',
			'z-index:9999','min-width:340px',
			'box-shadow:0 8px 32px rgba(0,0,0,.5)',
			'font-family:var(--fm-font,inherit)',
		].join(';');
		helpEl.innerHTML = '<h3 style="margin:0 0 16px;font-size:1rem;opacity:.7">Keyboard shortcuts</h3>'
			+ '<table style="border-collapse:collapse;width:100%">'
			+ SHORTCUTS.map(([k, d]) =>
				`<tr><td style="padding:4px 16px 4px 0;font-family:monospace;color:var(--fm-accent,#7aa2f7);white-space:nowrap">${k}</td>`
				+ `<td style="padding:4px 0;opacity:.85">${d}</td></tr>`
			).join('')
			+ '</table>'
			+ '<p style="margin:16px 0 0;font-size:.78rem;opacity:.5;text-align:right">Press ? or Escape to close</p>';

		document.body.appendChild(helpEl);
		helpVisible = true;

		const closeOnOutside = e => {
			if (!helpEl?.contains(e.target)) { helpEl?.remove(); helpEl = null; helpVisible = false; document.removeEventListener('click', closeOnOutside); }
		};
		setTimeout(() => document.addEventListener('click', closeOnOutside), 50);
	};

	const hideHelp = () => {
		if (helpEl) { helpEl.remove(); helpEl = null; helpVisible = false; }
	};

	// ── message navigation ────────────────────────────────────────────────

	const moveSelection = (dir) => {
		// Try SnappyMail's message list rows
		const rows = [...document.querySelectorAll('.messageListItem, .b-list-item')];
		if (!rows.length) return;
		const active = rows.find(r => r.classList.contains('selected') || r.classList.contains('focused') || r.classList.contains('active'));
		let idx = active ? rows.indexOf(active) : -1;
		idx = Math.max(0, Math.min(rows.length - 1, idx + dir));
		rows[idx]?.click();
		rows[idx]?.scrollIntoView({ block: 'nearest' });
	};

	// ── keydown handler ───────────────────────────────────────────────────

	document.addEventListener('keydown', e => {
		if (inTextField()) return;
		if (e.ctrlKey || e.metaKey || e.altKey) return;

		const key = e.key;

		if (key === '?') {
			e.preventDefault();
			showHelp();
			return;
		}

		if (key === 'Escape') {
			if (helpVisible) { hideHelp(); e.preventDefault(); return; }
			// Let SnappyMail handle Escape for its own modals
			return;
		}

		// Don't act while help is open
		if (helpVisible) return;

		switch (key) {
			case 'c':
				e.preventDefault();
				click('.b-compose, [data-bind*="compose"], .compose-button') ||
				click('[data-i18n="COMPOSE/NEW_MESSAGE"]') ||
				click('button.compose');
				break;

			case '/':
				e.preventDefault();
				const search = document.querySelector('.b-search-field input, input[type="search"], .searchInput');
				if (search) { search.focus(); search.select(); }
				break;

			case 'j':
			case 'n':
				e.preventDefault();
				moveSelection(1);
				break;

			case 'k':
			case 'p':
				e.preventDefault();
				moveSelection(-1);
				break;

			case 'r':
				e.preventDefault();
				click('[data-bind*="replyCommand"], .replyButton, [data-i18n="MESSAGE/REPLY"]');
				break;

			case 'a':
				e.preventDefault();
				click('[data-bind*="replyAllCommand"], .replyAllButton, [data-i18n="MESSAGE/REPLY_ALL"]');
				break;

			case 'f':
				e.preventDefault();
				click('[data-bind*="forwardCommand"], .forwardButton, [data-i18n="MESSAGE/FORWARD"]');
				break;

			case 'u':
				e.preventDefault();
				// Back to message list — click the active folder or use browser back
				click('.b-folder-list .selected, .folderList .active') || window.history.back();
				break;

			case 'm':
				e.preventDefault();
				click('[data-bind*="markAsRead"], [data-i18n*="MARK_AS_READ"], [data-i18n*="MARK_AS_UNREAD"]');
				break;
		}
	});

	// ── hint in status bar ────────────────────────────────────────────────

	// After the app loads, show a subtle "? for shortcuts" hint once
	const RL_READY = 'rl-start-loading-complete';
	const hintShown = sessionStorage.getItem('fm_shortcuts_hint');
	if (!hintShown) {
		const showHint = () => {
			sessionStorage.setItem('fm_shortcuts_hint', '1');
			const hint = document.createElement('div');
			hint.style.cssText = 'position:fixed;bottom:16px;right:16px;background:var(--fm-bg-panel,#1e2030);'
				+ 'color:var(--fm-text,#cdd6f4);padding:8px 14px;border-radius:8px;font-size:.8rem;'
				+ 'opacity:.85;z-index:9990;cursor:pointer;border:1px solid var(--fm-border,#414868)';
			hint.textContent = '⌨  Press ? for keyboard shortcuts';
			hint.onclick = () => { hint.remove(); showHelp(); };
			document.body.appendChild(hint);
			setTimeout(() => hint.style.transition = 'opacity 1s', 4000);
			setTimeout(() => { hint.style.opacity = '0'; setTimeout(() => hint.remove(), 1000); }, 6000);
		};
		document.addEventListener(RL_READY, showHint, { once: true });
		// Fallback if event already fired
		setTimeout(() => { if (!hintShown && document.readyState === 'complete') showHint(); }, 3000);
	}

})();
