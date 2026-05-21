// Frickmail Unified Inbox
//
// Layout: full-screen overlay with a split pane.
//   Left (280 px)  — scrollable message list, coloured account badges.
//   Right (flex:1) — message detail: header + HTML body in sandboxed
//                    iframe + "Open in account" button.
//
// On narrow screens (<600 px) the two panes stack; selecting a message
// slides to the detail view and a ← back button returns to the list.

(function () {
	'use strict';

	const BADGE_COLORS = [
		'#4a90d9','#e67e22','#27ae60','#8e44ad',
		'#c0392b','#16a085','#f39c12','#2980b9',
	];

	// ── State ─────────────────────────────────────────────────────────────────
	let overlayEl    = null;
	let btnEl        = null;
	let isOpen       = false;
	let isLoading    = false;
	let selectedMsg  = null;   // message object currently shown in detail pane
	let accountMeta  = {};     // email → {id, color, initial, label}

	// ── Helpers ───────────────────────────────────────────────────────────────

	function fmToken() {
		return window.FrickmailUtils ? FrickmailUtils.fmToken()
			: (window.rl?.__frickmail_token || window.rl?.settings?.app?.('token') || '');
	}

	function formatDate(ts) {
		if (!ts) return '';
		if (window.FrickmailUtils) return FrickmailUtils.formatDate(ts);
		const d = new Date(ts * 1000), now = new Date();
		const pad = n => String(n).padStart(2,'0');
		if (d.toDateString() === now.toDateString()) return pad(d.getHours())+':'+pad(d.getMinutes());
		const M = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
		return M[d.getMonth()]+' '+d.getDate()+(d.getFullYear()!==now.getFullYear()?' '+d.getFullYear():'');
	}

	function escHtml(s) {
		return window.FrickmailUtils ? FrickmailUtils.escHtml(s)
			: String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
	}

	function refreshAccountMeta(accounts) {
		accountMeta = {};
		(accounts||[]).forEach((acc,i) => {
			accountMeta[acc.email] = {
				id: acc.id, label: acc.label||acc.email, initial: (acc.label||acc.email||'?')[0].toUpperCase(),
				color: BADGE_COLORS[i % BADGE_COLORS.length],
			};
		});
	}

	function isNarrow() { return window.innerWidth < 600; }

	// ── Build overlay ─────────────────────────────────────────────────────────

	function createOverlay() {
		const el = document.createElement('div');
		el.id = 'fm-unified-inbox';
		el.setAttribute('role','dialog');
		el.setAttribute('aria-label','All accounts inbox');
		el.style.cssText = [
			'position:fixed','top:0','left:0','right:0','bottom:0','z-index:99999',
			'display:flex','flex-direction:column',
			'background:var(--fm-bg-panel,#1a1a2e)',
			'color:var(--fm-text-primary,#e2e4f0)',
			'font-family:inherit','overflow:hidden',
		].join(';');

		el.innerHTML = `
<div id="fm-ui-header" style="display:flex;align-items:center;padding:max(10px,env(safe-area-inset-top)) 14px 10px;border-bottom:1px solid var(--fm-border,rgba(255,255,255,.1));gap:8px;flex-shrink:0;">
	<span id="fm-ui-back" style="display:none;cursor:pointer;padding:4px 8px 4px 0;font-size:1.1rem;opacity:.8;touch-action:manipulation;" title="Back to list">&#8592;</span>
	<span style="font-weight:600;font-size:1rem;flex:1">All accounts</span>
	<span id="fm-ui-status" style="font-size:.8rem;opacity:.7"></span>
	<span id="fm-ui-refresh-slot"></span>
	<span id="fm-ui-close-slot"></span>
</div>
<div id="fm-ui-body" style="flex:1;display:flex;overflow:hidden;">
	<div id="fm-ui-list" style="width:280px;flex-shrink:0;overflow-y:auto;border-right:1px solid var(--fm-border,rgba(255,255,255,.1));"></div>
	<div id="fm-ui-detail" style="flex:1;overflow:hidden;display:flex;flex-direction:column;"></div>
</div>`;

		document.body.appendChild(el);

		// Close button
		const closeBtn = (window.FrickmailUtils?.makeCloseButton || function(id,fn){
			var b=document.createElement('a');b.id=id;b.href='#';b.className='close';b.innerHTML='&times;';
			b.style.cssText='float:none;touch-action:manipulation;-webkit-tap-highlight-color:transparent;flex-shrink:0;';
			['pointerdown','click','touchend'].forEach(ev=>b.addEventListener(ev,function(e){e.stopPropagation();e.preventDefault();fn();}));
			return b;
		})('fm-ui-close', closeOverlay);
		el.querySelector('#fm-ui-close-slot').replaceWith(closeBtn);

		// Refresh button
		const refreshBtn = document.createElement('button');
		refreshBtn.id='fm-ui-refresh'; refreshBtn.title='Refresh';
		refreshBtn.innerHTML='&#8635;';
		refreshBtn.style.cssText='background:none;border:none;color:inherit;cursor:pointer;font-size:1.1rem;min-width:44px;min-height:44px;display:flex;align-items:center;justify-content:center;opacity:.7;touch-action:manipulation;flex-shrink:0';
		['pointerdown','click','touchend'].forEach(ev=>refreshBtn.addEventListener(ev,function(e){e.stopPropagation();e.preventDefault();loadMessages();}));
		el.querySelector('#fm-ui-refresh-slot').replaceWith(refreshBtn);

		// Back button (mobile)
		el.querySelector('#fm-ui-back').addEventListener('click', showListPane);
		el.querySelector('#fm-ui-back').addEventListener('touchend', e=>{e.preventDefault();showListPane();});

		// Stop SnappyMail global handlers from closing us
		el.addEventListener('pointerdown', e=>e.stopPropagation());
		el.addEventListener('click',       e=>e.stopPropagation());
		el.addEventListener('touchstart',  e=>e.stopPropagation(), {passive:true});

		el._keyHandler = e=>{ if(e.key==='Escape') closeOverlay(); };
		document.addEventListener('keydown', el._keyHandler);

		// Adapt to window resize
		window.addEventListener('resize', applyLayout);

		return el;
	}

	// ── Pane visibility helpers (mobile vs desktop) ───────────────────────────

	function applyLayout() {
		if (!overlayEl) return;
		const list   = overlayEl.querySelector('#fm-ui-list');
		const detail = overlayEl.querySelector('#fm-ui-detail');
		const back   = overlayEl.querySelector('#fm-ui-back');
		if (!isNarrow()) {
			// Desktop: always show both panes
			list.style.display   = '';
			detail.style.display = 'flex';
			back.style.display   = 'none';
			list.style.width     = '280px';
		} else {
			// Mobile: show one pane at a time
			if (selectedMsg) {
				list.style.display   = 'none';
				detail.style.display = 'flex';
				back.style.display   = '';
			} else {
				list.style.display   = '';
				detail.style.display = 'none';
				back.style.display   = 'none';
				list.style.width     = '100%';
			}
		}
	}

	function showListPane() {
		selectedMsg = null;
		applyLayout();
		// Deselect row highlight
		overlayEl?.querySelectorAll('.fm-ui-row.selected').forEach(r=>r.classList.remove('selected'));
	}

	// ── Overlay open / close ──────────────────────────────────────────────────

	function openOverlay() {
		if (!overlayEl) overlayEl = createOverlay();
		overlayEl.style.display = 'flex';
		isOpen = true;
		applyLayout();
		loadMessages();
	}

	function closeOverlay() {
		if (overlayEl) overlayEl.style.display = 'none';
		isOpen = false;
		selectedMsg = null;
	}

	// ── Load message list ─────────────────────────────────────────────────────

	function loadMessages() {
		if (isLoading) return;
		isLoading = true;
		selectedMsg = null;

		const list   = overlayEl?.querySelector('#fm-ui-list');
		const detail = overlayEl?.querySelector('#fm-ui-detail');
		const status = overlayEl?.querySelector('#fm-ui-status');
		if (list)   list.innerHTML   = '<div style="padding:32px 16px;text-align:center;opacity:.6;font-size:.85rem;">Loading…</div>';
		if (detail) detail.innerHTML = '';
		if (status) status.textContent = '';
		applyLayout();

		try {
			const cached = JSON.parse(localStorage.getItem('frickmail_accounts_cache')||'null');
			if (cached) refreshAccountMeta(cached);
		} catch(e) {}

		const r = window.rl;
		if (!r) { isLoading=false; return; }
		r.pluginRemoteRequest((iErr, oData) => {
			isLoading = false;
			const res = oData?.Result;
			if (!res?.ok) {
				if (list) list.innerHTML = '<div style="padding:24px;color:#f38ba8;font-size:.85rem;">Failed to load: '+escHtml(res?.error||'unknown error')+'</div>';
				return;
			}
			const msgs   = res.messages || [];
			const errors = res.errors   || [];
			if (status) status.textContent = msgs.length+' messages'+(errors.length?' ('+errors.length+' failed)':'');
			if (!msgs.length && errors.length) {
				if (list) list.innerHTML = '<div style="padding:24px;color:#f38ba8;font-size:.85rem;"><strong>Could not reach '+errors.length+' account'+(errors.length>1?'s':'')+':</strong><br>'+errors.map(e=>escHtml(e)).join('<br>')+'</div>';
				return;
			}
			if (!msgs.length) {
				if (list) list.innerHTML = '<div style="padding:32px 16px;text-align:center;opacity:.6;font-size:.85rem;">No messages found.<br><small style="opacity:.7">Only IMAP accounts are shown here.</small></div>';
				return;
			}
			renderList(msgs, list);
			// Auto-select first message on desktop
			if (!isNarrow() && msgs.length) selectMessage(msgs[0]);
		}, 'FrickmailUnifiedInbox', {limit:40, XToken:fmToken()}, 15000);
	}

	// ── Render message list ───────────────────────────────────────────────────

	function renderList(msgs, container) {
		const frag = document.createDocumentFragment();
		msgs.forEach(msg => {
			const meta = accountMeta[msg.account_email] || {color:'#888',initial:'?',id:msg.account_id,label:msg.account_email};
			const row  = document.createElement('div');
			row.className = 'fm-ui-row';
			row.dataset.uid       = msg.uid;
			row.dataset.accountId = msg.account_id;
			row.style.cssText = [
				'display:flex','align-items:flex-start','gap:8px',
				'padding:10px 12px',
				'border-bottom:1px solid var(--fm-border,rgba(255,255,255,.06))',
				'cursor:pointer',
				msg.is_seen ? 'opacity:.7' : 'font-weight:600',
			].join(';');

			const badge = document.createElement('span');
			badge.title = meta.label;
			badge.style.cssText = 'display:inline-flex;align-items:center;justify-content:center;width:26px;height:26px;border-radius:50%;font-size:.7rem;font-weight:700;flex-shrink:0;margin-top:1px;background:'+meta.color+';color:#fff;';
			badge.textContent = meta.initial;

			const body = document.createElement('div');
			body.style.cssText = 'flex:1;min-width:0;';
			body.innerHTML =
				'<div style="display:flex;justify-content:space-between;gap:6px;">'
				+'<span style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:65%;font-size:.85rem;">'+escHtml(msg.from||'(no sender)')+'</span>'
				+'<span style="font-size:.72rem;opacity:.55;white-space:nowrap;flex-shrink:0;">'+escHtml(formatDate(msg.date_ts))+'</span>'
				+'</div>'
				+'<div style="font-size:.8rem;opacity:.75;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;margin-top:2px;">'+escHtml(msg.subject||'(no subject)')+'</div>';

			row.appendChild(badge);
			row.appendChild(body);

			const activate = () => selectMessage(msg, row);
			row.addEventListener('click',    activate);
			row.addEventListener('touchend', e=>{e.preventDefault(); activate();});
			row.addEventListener('keydown',  e=>{if(e.key==='Enter'||e.key===' ') activate();});
			row.setAttribute('tabindex','0');
			row.setAttribute('role','option');
			row.setAttribute('aria-label', escHtml((msg.from||'')+'—'+(msg.subject||'')));

			row.addEventListener('mouseenter', ()=>{ if(!row.classList.contains('selected')) row.style.background='var(--fm-bg-hover,rgba(255,255,255,.05))'; });
			row.addEventListener('mouseleave', ()=>{ if(!row.classList.contains('selected')) row.style.background=''; });

			frag.appendChild(row);
		});
		container.innerHTML = '';
		container.appendChild(frag);
	}

	// ── Select + show message detail ──────────────────────────────────────────

	function selectMessage(msg, rowEl) {
		selectedMsg = msg;

		// Highlight selected row
		overlayEl?.querySelectorAll('.fm-ui-row').forEach(r=>{
			r.classList.remove('selected');
			r.style.background = '';
		});
		if (rowEl) { rowEl.classList.add('selected'); rowEl.style.background='var(--fm-accent-surface,rgba(122,162,247,.14))'; }

		applyLayout();
		renderDetailShell(msg);
		fetchAndRenderBody(msg);
	}

	function renderDetailShell(msg) {
		const meta   = accountMeta[msg.account_email] || {color:'#888',initial:'?',id:msg.account_id,label:msg.account_email};
		const detail = overlayEl?.querySelector('#fm-ui-detail');
		if (!detail) return;

		detail.innerHTML = `
<div style="padding:14px 18px;border-bottom:1px solid var(--fm-border,rgba(255,255,255,.1));flex-shrink:0;">
	<div style="display:flex;align-items:center;gap:8px;margin-bottom:6px;">
		<span style="display:inline-flex;align-items:center;justify-content:center;width:30px;height:30px;border-radius:50%;font-size:.75rem;font-weight:700;background:${meta.color};color:#fff;flex-shrink:0;">${escHtml(meta.initial)}</span>
		<div style="flex:1;min-width:0;">
			<div style="font-weight:600;font-size:.9rem;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${escHtml(msg.from||'(no sender)')}</div>
			<div style="font-size:.75rem;opacity:.55;">${escHtml(meta.label)} · ${escHtml(formatDate(msg.date_ts))}</div>
		</div>
		<button id="fm-ui-open-account" title="Open in account" style="padding:4px 10px;border-radius:4px;border:1px solid var(--fm-border);background:transparent;color:inherit;cursor:pointer;font-size:.78rem;white-space:nowrap;touch-action:manipulation;">Open in account ↗</button>
	</div>
	<div style="font-size:.95rem;font-weight:600;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${escHtml(msg.subject||'(no subject)')}</div>
</div>
<div id="fm-ui-msg-body" style="flex:1;overflow:hidden;position:relative;">
	<div style="position:absolute;inset:0;display:flex;align-items:center;justify-content:center;opacity:.5;font-size:.85rem;">Loading…</div>
</div>`;

		// "Open in account" wires to the old switch+reload behaviour
		const openBtn = detail.querySelector('#fm-ui-open-account');
		['click','touchend'].forEach(ev => openBtn.addEventListener(ev, e=>{ e.preventDefault(); e.stopPropagation(); switchToAccount(msg,meta); }));
	}

	function fetchAndRenderBody(msg) {
		const bodyEl = overlayEl?.querySelector('#fm-ui-msg-body');
		if (!bodyEl) return;

		window.rl.pluginRemoteRequest((iErr, oData) => {
			// Guard: user may have selected a different message while this was loading
			if (selectedMsg?.uid !== msg.uid || selectedMsg?.account_id !== msg.account_id) return;

			const res = oData?.Result;
			const bodyEl2 = overlayEl?.querySelector('#fm-ui-msg-body');
			if (!bodyEl2) return;

			if (!res?.ok) {
				bodyEl2.innerHTML = '<div style="padding:24px;color:#f38ba8;font-size:.85rem;">Could not load message: '+escHtml(res?.error||'request error')+'</div>';
				return;
			}

			const html  = res.html  || '';
			const plain = res.plain || '';

			if (html) {
				// Render HTML in a sandboxed iframe for XSS isolation
				const iframe = document.createElement('iframe');
				iframe.setAttribute('sandbox','allow-same-origin');
				iframe.style.cssText = 'width:100%;height:100%;border:none;background:#fff;display:block;';
				bodyEl2.innerHTML = '';
				bodyEl2.appendChild(iframe);
				// Write after append so contentDocument is available
				const doc = iframe.contentDocument || iframe.contentWindow?.document;
				if (doc) {
					doc.open();
					doc.write('<!DOCTYPE html><html><head><meta charset="utf-8"><style>body{margin:12px 16px;font-family:sans-serif;font-size:14px;line-height:1.5;word-break:break-word;}img{max-width:100%;}a{color:#4a90d9;}</style></head><body>'+html+'</body></html>');
					doc.close();
				}
			} else if (plain) {
				bodyEl2.innerHTML = '<div style="padding:16px;font-family:monospace;font-size:.85rem;white-space:pre-wrap;word-break:break-word;overflow-y:auto;height:100%;box-sizing:border-box;">'+escHtml(plain)+'</div>';
			} else {
				bodyEl2.innerHTML = '<div style="padding:24px;opacity:.5;font-size:.85rem;">(No body content)</div>';
			}
		}, 'FrickmailGetMessageBody', { account_id: msg.account_id, uid: msg.uid, XToken: fmToken() }, 20000);
	}

	// ── Switch to account + open that account's inbox ─────────────────────────

	function switchToAccount(msg, meta) {
		closeOverlay();
		window.rl.pluginRemoteRequest((iErr, oData) => {
			if (oData?.Result?.ok) {
				window.rl.route?.reload?.();
			} else {
				alert('Frickmail: '+(oData?.Result?.error||'Account switch failed'));
			}
		}, 'FrickmailSwitchAccount', {id:meta.id, XToken:fmToken()}, 30000);
	}

	// ── Inject toolbar button ─────────────────────────────────────────────────

	function injectButton(toolbarEl) {
		if (btnEl && toolbarEl.contains(btnEl)) return;
		btnEl = document.createElement('button');
		btnEl.type = 'button';
		btnEl.textContent = 'All accounts';
		btnEl.title = 'Unified inbox — messages from all accounts';
		btnEl.style.cssText = [
			'margin-left:4px','padding:4px 10px',
			'border-radius:var(--fm-radius-xs,4px)',
			'border:1px solid var(--fm-border,rgba(255,255,255,.2))',
			'background:var(--fm-bg-input,rgba(255,255,255,.07))',
			'color:inherit','font-size:var(--fm-font-size-sm,.8rem)',
			'cursor:pointer','white-space:nowrap','touch-action:manipulation',
		].join(';');
		const toggle = () => { if (isOpen) closeOverlay(); else openOverlay(); };
		btnEl.addEventListener('click',    toggle);
		btnEl.addEventListener('touchend', e=>{ e.preventDefault(); toggle(); });
		const btns = toolbarEl.querySelectorAll('button,a.button,.toolbar-button');
		if (btns.length) btns[btns.length-1].after(btnEl); else toolbarEl.appendChild(btnEl);
	}

	// ── rl-view-model hook ────────────────────────────────────────────────────

	addEventListener('rl-view-model', e => {
		if (e.detail?.viewModelTemplateID !== 'MailMessageList') return;
		const dom = e.detail.viewModelDom;
		if (!dom) return;
		setTimeout(() => {
			const toolbar = dom.querySelector('.listActions,.toolbar,[class*="toolbar"],.b-mail-message-list .pToolbar') || dom.querySelector('div');
			if (toolbar) injectButton(toolbar);
		}, 300);
	});

	window.FrickmailUnifiedInbox = { open: openOverlay };

})();
