// Frickmail Import/Export — EML and MBOX support.
//
// Export .mbox and Import .eml moved to Settings → Import / Export tab.
// Export .eml (single message) remains in the MailMessageView toolbar
// because it is contextual to the open message.

(function () {
	'use strict';

	// ── Helpers ───────────────────────────────────────────────────────────────

	function fmToken() {
		return window.rl?.__frickmail_token || window.rl?.settings?.app?.('token') || '';
	}

	function downloadBlob(filename, blob) {
		const url = URL.createObjectURL(blob);
		const a   = document.createElement('a');
		a.href = url; a.download = filename; a.style.display = 'none';
		document.body.appendChild(a); a.click(); document.body.removeChild(a);
		setTimeout(() => URL.revokeObjectURL(url), 1000);
	}

	function base64ToBlob(b64, mime) {
		const bin = atob(b64);
		const arr = new Uint8Array(bin.length);
		for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
		return new Blob([arr], { type: mime });
	}

	function getActiveAccountId() {
		try {
			const cached = JSON.parse(localStorage.getItem('frickmail_accounts_cache') || 'null');
			if (!Array.isArray(cached) || !cached.length) return null;
			const currentEmail = window.rl?.settings?.app?.('accountEmail')
				|| document.querySelector('[data-email]')?.dataset?.email || null;
			if (currentEmail) {
				const match = cached.find(a => a.email === currentEmail);
				if (match) return match.id;
			}
			const primary = cached.find(a => a.is_primary) || cached[0];
			return primary ? primary.id : null;
		} catch (e) { return null; }
	}

	function getCurrentFolder() {
		const hash = window.location.hash || '';
		const m = hash.match(/#\/?(?:folder\/)?([^/?#]+)/);
		if (m && m[1] && m[1] !== 'message') {
			try { return decodeURIComponent(m[1]); } catch (e) {}
		}
		try {
			return window.rl?.data?.currentFolder?.()
				|| window.rl?.data?.currentFolderFullName?.() || null;
		} catch (e) {}
		return 'INBOX';
	}

	// ── Export single message (.eml) — stays in MailMessageView toolbar ───────

	function getMsgContext(viewModelDom) {
		try {
			const vm = window.ko?.dataFor(viewModelDom);
			if (vm) {
				const uid    = +(vm.uid?.()    ?? vm.Uid?.()    ?? 0);
				const folder =   vm.folder?.() ?? vm.Folder?.() ?? '';
				const accId  = getActiveAccountId();
				const subj   =   vm.subject?.() ?? vm.Subject?.() ?? '';
				if (uid && folder && accId) return { uid, folder, account_id: accId, subject: subj };
			}
		} catch (e) {}
		const el     = viewModelDom.querySelector('[data-uid]') || viewModelDom;
		const uid    = +(el.dataset?.uid ?? 0);
		const folder =   el.dataset?.folder ?? getCurrentFolder();
		const accId  = getActiveAccountId();
		const subj   = viewModelDom.querySelector('.subject,[data-subject]')?.textContent?.trim() || 'message';
		return (uid && accId) ? { uid, folder, account_id: accId, subject: subj } : null;
	}

	function exportMessage(ctx, btn) {
		if (btn) { btn.disabled = true; btn.textContent = 'Exporting…'; }
		window.rl.pluginRemoteRequest((iErr, oData) => {
			if (btn) { btn.disabled = false; btn.textContent = 'Export .eml'; }
			const res = oData?.Result;
			if (!res?.ok) { alert('Export failed: ' + (res?.error || 'unknown error')); return; }
			downloadBlob(res.filename, base64ToBlob(res.content_b64, 'message/rfc822'));
		}, 'FrickmailExportMessage', {
			account_id: ctx.account_id, folder: ctx.folder,
			uid: ctx.uid, subject: ctx.subject, XToken: fmToken(),
		}, 30000);
	}

	function injectExportEmlButton(toolbarEl, viewModelDom) {
		if (document.getElementById('fm-export-eml-btn')) return;
		const btn = document.createElement('button');
		btn.id = 'fm-export-eml-btn'; btn.type = 'button';
		btn.title = 'Download this message as an .eml file';
		btn.textContent = 'Export .eml';
		btn.style.cssText = 'margin-left:4px;padding:4px 10px;border-radius:4px;border:1px solid rgba(255,255,255,.2);background:rgba(255,255,255,.07);color:inherit;font-size:.8rem;cursor:pointer;white-space:nowrap;';
		btn.addEventListener('click', () => {
			const ctx = getMsgContext(viewModelDom);
			if (!ctx) { alert('Cannot determine message UID or account.'); return; }
			exportMessage(ctx, btn);
		});
		const btns = toolbarEl.querySelectorAll('button,a.button,.toolbar-button');
		if (btns.length) btns[btns.length - 1].after(btn);
		else toolbarEl.appendChild(btn);
	}

	// ── Settings tab view model ───────────────────────────────────────────────

	class FrickmailImportExportSettings {
		constructor() {
			this.exportFolder = ko.observable(getCurrentFolder() || 'INBOX');
			this.importFolder = ko.observable('INBOX');
			this.exporting    = ko.observable(false);
			this.importing    = ko.observable(false);
			this.status       = ko.observable('');
			this.statusOk     = ko.observable(true);
		}

		onBuild() {
			// Refresh exportFolder when the tab is opened
			this.exportFolder(getCurrentFolder() || 'INBOX');
		}

		_setStatus(msg, ok) { this.status(msg); this.statusOk(!!ok); }

		doExportFolder() {
			if (this.exporting()) return;
			const accId  = getActiveAccountId();
			const folder = this.exportFolder().trim() || 'INBOX';
			if (!accId) { this._setStatus('No IMAP account found — add one in Mail Accounts settings.', false); return; }
			if (!confirm('Export folder "' + folder + '" as .mbox? This may take a while for large folders.')) return;

			this.exporting(true);
			this._setStatus('', true);
			window.rl.pluginRemoteRequest((iErr, oData) => {
				this.exporting(false);
				const res = oData?.Result;
				if (!res?.ok) { this._setStatus('Export failed: ' + (res?.error || 'unknown error'), false); return; }
				downloadBlob(res.filename, base64ToBlob(res.content_b64, 'application/mbox'));
				this._setStatus('Exported ' + res.filename, true);
			}, 'FrickmailExportFolder', {
				account_id: accId, folder, XToken: fmToken(),
			}, 120000);
		}

		doImportEml() {
			if (this.importing()) return;
			const accId  = getActiveAccountId();
			const folder = this.importFolder().trim() || 'INBOX';
			if (!accId) { this._setStatus('No IMAP account found — add one in Mail Accounts settings.', false); return; }

			const input = document.createElement('input');
			input.type = 'file'; input.accept = '.eml,.txt,message/rfc822';
			input.style.display = 'none';
			document.body.appendChild(input);

			input.addEventListener('change', () => {
				const file = input.files?.[0];
				document.body.removeChild(input);
				if (!file) return;

				this.importing(true);
				this._setStatus('', true);

				const reader = new FileReader();
				reader.onload = (e) => {
					const bytes = new Uint8Array(e.target.result);
					let binary = '';
					for (let i = 0; i < bytes.byteLength; i++) binary += String.fromCharCode(bytes[i]);

					window.rl.pluginRemoteRequest((iErr, oData) => {
						this.importing(false);
						const res = oData?.Result;
						if (res?.ok) {
							this._setStatus('Imported "' + file.name + '" into ' + folder, true);
						} else {
							this._setStatus('Import failed: ' + (res?.error || 'unknown error'), false);
						}
					}, 'FrickmailImportEml', {
						account_id: accId, folder, eml_b64: btoa(binary), XToken: fmToken(),
					}, 30000);
				};
				reader.readAsArrayBuffer(file);
			});
			input.click();
		}
	}

	// ── rl-view-model hook — Export .eml in message view only ────────────────

	addEventListener('rl-view-model', e => {
		const id  = e.detail?.viewModelTemplateID;
		const dom = e.detail?.viewModelDom;
		if (!dom) return;
		if (id === 'MailMessageView' || id === 'MessageView') {
			setTimeout(() => {
				const toolbar = dom.querySelector('.messageActions,.toolbar,[class*="toolbar"]')
					|| dom.querySelector('div');
				if (toolbar) injectExportEmlButton(toolbar, dom);
			}, 350);
		}
	});

	// Register settings tab — wait for rl.addSettingsViewModel
	(function register() {
		if (!window.rl?.addSettingsViewModel) { setTimeout(register, 200); return; }
		window.rl.addSettingsViewModel(
			FrickmailImportExportSettings,
			'FrickmailImportExportTab',
			'Import / Export',
			'frickmail-import-export'
		);
	})();

})();
