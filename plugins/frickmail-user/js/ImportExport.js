// Frickmail Import/Export — EML and MBOX support.
//
// Provides three features:
//   1. Export single message as .eml   — button in the MessageView toolbar
//   2. Export current folder as .mbox  — button in the MailMessageList toolbar
//   3. Import .eml file into INBOX     — button in the MailMessageList toolbar
//
// All three use the FrickmailExportMessage / FrickmailExportFolder /
// FrickmailImportEml JSON endpoints provided by frickmail-user's index.php.

(function () {
	'use strict';

	// ── Helpers ───────────────────────────────────────────────────────────────

	function fmToken() {
		return window.rl?.__frickmail_token || window.rl?.settings?.app?.('token') || '';
	}

	/**
	 * Trigger a browser download from a Blob.
	 */
	function downloadBlob(filename, blob) {
		const url = URL.createObjectURL(blob);
		const a   = document.createElement('a');
		a.href     = url;
		a.download = filename;
		a.style.display = 'none';
		document.body.appendChild(a);
		a.click();
		document.body.removeChild(a);
		setTimeout(() => URL.revokeObjectURL(url), 1000);
	}

	/**
	 * Decode a base64 string to a Blob with the given MIME type.
	 */
	function base64ToBlob(b64, mime) {
		const bin = atob(b64);
		const arr = new Uint8Array(bin.length);
		for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
		return new Blob([arr], { type: mime });
	}

	// ── State resolution ──────────────────────────────────────────────────────

	/**
	 * Get the currently active Frickmail account_id from localStorage cache.
	 * Returns null if not available.
	 */
	function getActiveAccountId() {
		try {
			const cached = JSON.parse(localStorage.getItem('frickmail_accounts_cache') || 'null');
			if (!Array.isArray(cached) || !cached.length) return null;
			// Try to match against the SnappyMail current email
			const currentEmail = window.rl?.settings?.app?.('accountEmail')
				|| window.rl?.settings?.get?.('accountEmail')
				|| document.querySelector('[data-email]')?.dataset?.email
				|| null;
			if (currentEmail) {
				const match = cached.find(a => a.email === currentEmail);
				if (match) return match.id;
			}
			// Fall back to the primary account
			const primary = cached.find(a => a.is_primary) || cached[0];
			return primary ? primary.id : null;
		} catch (e) {
			return null;
		}
	}

	/**
	 * Try to determine the currently selected folder name.
	 * SnappyMail stores this on the hash/route or as a data attribute.
	 */
	function getCurrentFolder() {
		// Try hash-based routing: SnappyMail uses #/folder/INBOX/ style URLs
		const hash = window.location.hash || '';
		const m    = hash.match(/#\/?(?:folder\/)?([^/?#]+)/);
		if (m && m[1] && m[1] !== 'message') {
			try { return decodeURIComponent(m[1]); } catch (e) {}
		}
		// Try the rl state
		try {
			const folder = window.rl?.data?.currentFolder?.()
				|| window.rl?.data?.currentFolderFullName?.()
				|| null;
			if (folder) return folder;
		} catch (e) {}
		return 'INBOX';
	}

	// ── Export single message ─────────────────────────────────────────────────

	/**
	 * Read UID, folder and account_id from a message view DOM element.
	 * SnappyMail stores message metadata as data attributes on the view root
	 * or exposes them via the KO view model.
	 */
	function getMsgContext(viewModelDom) {
		// KO view model binding
		try {
			const ko = window.ko;
			if (ko) {
				const vm = ko.dataFor(viewModelDom);
				if (vm) {
					const uid    = +(vm.uid?.()    ?? vm.Uid?.()    ?? 0);
					const folder = vm.folder?.()   ?? vm.Folder?.() ?? '';
					const accId  = getActiveAccountId();
					const subj   = vm.subject?.()  ?? vm.Subject?.() ?? '';
					if (uid && folder && accId) return { uid, folder, account_id: accId, subject: subj };
				}
			}
		} catch (e) {}

		// DOM data attributes fallback
		const el = viewModelDom.querySelector('[data-uid]') || viewModelDom;
		const uid    = +(el.dataset?.uid    ?? 0);
		const folder = el.dataset?.folder   ?? getCurrentFolder();
		const accId  = getActiveAccountId();
		const subj   = viewModelDom.querySelector('.subject, [data-subject]')?.textContent?.trim() || 'message';
		return (uid && accId) ? { uid, folder, account_id: accId, subject: subj } : null;
	}

	function exportMessage(ctx) {
		const r = window.rl;
		if (!r) return;

		const btn = document.getElementById('fm-export-eml-btn');
		if (btn) { btn.disabled = true; btn.textContent = 'Exporting…'; }

		r.pluginRemoteRequest((iErr, oData) => {
			if (btn) { btn.disabled = false; btn.textContent = 'Export .eml'; }
			const res = oData?.Result;
			if (!res?.ok) {
				alert('Frickmail export failed: ' + (res?.error || 'unknown error'));
				return;
			}
			downloadBlob(res.filename, base64ToBlob(res.content_b64, 'message/rfc822'));
		}, 'FrickmailExportMessage', {
			account_id: ctx.account_id,
			folder:     ctx.folder,
			uid:        ctx.uid,
			subject:    ctx.subject,
			XToken:     fmToken(),
		}, 30000);
	}

	function injectExportEmlButton(toolbarEl, viewModelDom) {
		if (document.getElementById('fm-export-eml-btn')) return;

		const btn = document.createElement('button');
		btn.id    = 'fm-export-eml-btn';
		btn.type  = 'button';
		btn.title = 'Download this message as an .eml file';
		btn.textContent = 'Export .eml';
		btn.style.cssText = [
			'margin-left:4px',
			'padding:4px 10px',
			'border-radius:4px',
			'border:1px solid rgba(255,255,255,.2)',
			'background:rgba(255,255,255,.07)',
			'color:inherit',
			'font-size:.8rem',
			'cursor:pointer',
			'white-space:nowrap',
		].join(';');

		btn.addEventListener('click', () => {
			const ctx = getMsgContext(viewModelDom);
			if (!ctx) {
				alert('Frickmail: cannot determine message UID or account. Is an IMAP account selected?');
				return;
			}
			exportMessage(ctx);
		});

		const btns = toolbarEl.querySelectorAll('button, a.button, .toolbar-button');
		if (btns.length) btns[btns.length - 1].after(btn);
		else toolbarEl.appendChild(btn);
	}

	// ── Export folder ─────────────────────────────────────────────────────────

	function exportFolder(folder, accountId) {
		const r = window.rl;
		if (!r) return;

		const btn = document.getElementById('fm-export-mbox-btn');
		if (btn) { btn.disabled = true; btn.textContent = 'Exporting…'; }

		r.pluginRemoteRequest((iErr, oData) => {
			if (btn) { btn.disabled = false; btn.textContent = 'Export .mbox'; }
			const res = oData?.Result;
			if (!res?.ok) {
				alert('Frickmail export failed: ' + (res?.error || 'unknown error'));
				return;
			}
			downloadBlob(res.filename, base64ToBlob(res.content_b64, 'application/mbox'));
		}, 'FrickmailExportFolder', {
			account_id: accountId,
			folder:     folder,
			XToken:     fmToken(),
		}, 120000); // folders can be large
	}

	// ── Import EML ────────────────────────────────────────────────────────────

	function importEml(accountId, targetFolder) {
		const input = document.createElement('input');
		input.type   = 'file';
		input.accept = '.eml,.txt,message/rfc822';
		input.style.display = 'none';
		document.body.appendChild(input);

		input.addEventListener('change', () => {
			const file = input.files?.[0];
			document.body.removeChild(input);
			if (!file) return;

			const btn = document.getElementById('fm-import-eml-btn');
			if (btn) { btn.disabled = true; btn.textContent = 'Importing…'; }

			const reader = new FileReader();
			reader.onload = (e) => {
				const raw = e.target.result;
				// Convert ArrayBuffer to base64
				const bytes = new Uint8Array(raw);
				let binary  = '';
				for (let i = 0; i < bytes.byteLength; i++) binary += String.fromCharCode(bytes[i]);
				const b64 = btoa(binary);

				const r = window.rl;
				if (!r) { if (btn) { btn.disabled = false; btn.textContent = 'Import .eml'; } return; }

				r.pluginRemoteRequest((iErr, oData) => {
					if (btn) { btn.disabled = false; btn.textContent = 'Import .eml'; }
					const res = oData?.Result;
					if (res?.ok) {
						// Brief visual feedback
						if (btn) {
							btn.textContent = 'Imported!';
							setTimeout(() => { btn.textContent = 'Import .eml'; }, 2000);
						}
					} else {
						alert('Frickmail import failed: ' + (res?.error || 'unknown error'));
					}
				}, 'FrickmailImportEml', {
					account_id: accountId,
					folder:     targetFolder || 'INBOX',
					eml_b64:    b64,
					XToken:     fmToken(),
				}, 30000);
			};
			reader.readAsArrayBuffer(file);
		});

		input.click();
	}

	// ── Inject list toolbar buttons ───────────────────────────────────────────

	let listToolbarInjected = false;

	function injectListToolbarButtons(toolbarEl) {
		if (listToolbarInjected
			&& document.getElementById('fm-export-mbox-btn')
			&& document.getElementById('fm-import-eml-btn')) return;

		// Export folder button
		if (!document.getElementById('fm-export-mbox-btn')) {
			const btnExport = document.createElement('button');
			btnExport.id    = 'fm-export-mbox-btn';
			btnExport.type  = 'button';
			btnExport.title = 'Export current folder as an .mbox file';
			btnExport.textContent = 'Export .mbox';
			btnExport.style.cssText = [
				'margin-left:4px',
				'padding:4px 10px',
				'border-radius:4px',
				'border:1px solid rgba(255,255,255,.2)',
				'background:rgba(255,255,255,.07)',
				'color:inherit',
				'font-size:.8rem',
				'cursor:pointer',
				'white-space:nowrap',
			].join(';');
			btnExport.addEventListener('click', () => {
				const accId  = getActiveAccountId();
				const folder = getCurrentFolder();
				if (!accId) { alert('Frickmail: no IMAP account found. Please add an account first.'); return; }
				if (!confirm('Export folder "' + folder + '" as .mbox? This may take a while for large folders.')) return;
				exportFolder(folder, accId);
			});

			const btns = toolbarEl.querySelectorAll('button, a.button, .toolbar-button');
			if (btns.length) btns[btns.length - 1].after(btnExport);
			else toolbarEl.appendChild(btnExport);
		}

		// Import EML button
		if (!document.getElementById('fm-import-eml-btn')) {
			const btnImport = document.createElement('button');
			btnImport.id    = 'fm-import-eml-btn';
			btnImport.type  = 'button';
			btnImport.title = 'Import an .eml file into INBOX';
			btnImport.textContent = 'Import .eml';
			btnImport.style.cssText = [
				'margin-left:4px',
				'padding:4px 10px',
				'border-radius:4px',
				'border:1px solid rgba(255,255,255,.2)',
				'background:rgba(255,255,255,.07)',
				'color:inherit',
				'font-size:.8rem',
				'cursor:pointer',
				'white-space:nowrap',
			].join(';');
			btnImport.addEventListener('click', () => {
				const accId = getActiveAccountId();
				if (!accId) { alert('Frickmail: no IMAP account found. Please add an account first.'); return; }
				importEml(accId, 'INBOX');
			});

			const exportBtn = document.getElementById('fm-export-mbox-btn');
			if (exportBtn) exportBtn.after(btnImport);
			else {
				const btns = toolbarEl.querySelectorAll('button, a.button, .toolbar-button');
				if (btns.length) btns[btns.length - 1].after(btnImport);
				else toolbarEl.appendChild(btnImport);
			}
		}

		listToolbarInjected = true;
	}

	// ── rl-view-model hook ────────────────────────────────────────────────────

	addEventListener('rl-view-model', e => {
		const id  = e.detail?.viewModelTemplateID;
		const dom = e.detail?.viewModelDom;
		if (!dom) return;

		if (id === 'MailMessageList') {
			// List toolbar: Export .mbox + Import .eml
			setTimeout(() => {
				const toolbar = dom.querySelector('.listActions, .toolbar, [class*="toolbar"]')
					|| dom.querySelector('div');
				if (!toolbar) return;
				injectListToolbarButtons(toolbar);
			}, 350);
		}

		if (id === 'MailMessageView' || id === 'MessageView') {
			// Message view toolbar: Export .eml
			setTimeout(() => {
				const toolbar = dom.querySelector('.messageActions, .toolbar, [class*="toolbar"]')
					|| dom.querySelector('div');
				if (!toolbar) return;
				injectExportEmlButton(toolbar, dom);
			}, 350);
		}
	});

})();
