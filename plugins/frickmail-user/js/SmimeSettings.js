/**
 * SmimeSettings.js — S/MIME certificate management panel.
 *
 * Rendered in Settings → Mail Accounts tab (appended after Rules).
 *
 * Features:
 *  - List certificates per user (email, subject, expiry, key icon)
 *  - Upload .p12 (PKCS#12) bundle with passphrase → FrickmailSmimeImportP12
 *  - Upload .pem certificate (public only)        → FrickmailSmimeImportCert
 *  - Delete certificate                           → FrickmailSmimeDeleteCert
 *  - "Sign test message" button                   → FrickmailSmimeSign
 */
(rl => { if (!rl) return;

	function escHtml(s) {
		return String(s ?? '')
			.replace(/&/g, '&amp;')
			.replace(/</g, '&lt;')
			.replace(/>/g, '&gt;')
			.replace(/"/g, '&quot;');
	}

	/** Read a File object and return a base64-encoded string via Promise. */
	function fileToBase64(file) {
		return new Promise((resolve, reject) => {
			const reader = new FileReader();
			reader.onload  = e => resolve(btoa(
				String.fromCharCode(...new Uint8Array(e.target.result))
			));
			reader.onerror = () => reject(new Error('Could not read file'));
			reader.readAsArrayBuffer(file);
		});
	}

	/** Format an ISO date string to a short human-readable form. */
	function formatDate(iso) {
		if (!iso) return '—';
		try {
			return new Date(iso).toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
		} catch (_) {
			return iso;
		}
	}

	class FrickmailSmimeSettings {
		constructor() {
			this.certs       = ko.observableArray([]);
			this.accounts    = ko.observableArray([]);
			this.status      = ko.observable('');
			this.statusOk    = ko.observable(false);
			this.loading     = ko.observable(false);

			// Import P12 form state
			this.p12AccountId = ko.observable('');
			this.p12Password  = ko.observable('');
			this.p12File      = null;

			// Import PEM form state
			this.pemAccountId = ko.observable('');
			this.pemFile      = null;

			// Sign test state
			this.signEmail    = ko.observable('');
			this.signResult   = ko.observable('');

			this.showP12Form  = ko.observable(false);
			this.showPemForm  = ko.observable(false);
		}

		onBuild() {
			this._loadAccounts();
			this._loadCerts();
		}

		_loadAccounts() {
			window.rl.pluginRemoteRequest((iError, oData) => {
				const r = oData?.Result;
				if (r?.ok) this.accounts(r.accounts || []);
			}, 'FrickmailListAccounts', {}, 30000);
		}

		_loadCerts() {
			this.loading(true);
			window.rl.pluginRemoteRequest((iError, oData) => {
				this.loading(false);
				const r = oData?.Result;
				if (r?.ok) {
					this.certs(r.certs || []);
				} else {
					this._setStatus('Failed to load certificates', false);
				}
			}, 'FrickmailSmimeListCerts', {}, 30000);
		}

		_setStatus(msg, ok) {
			this.status(msg);
			this.statusOk(!!ok);
		}

		toggleP12Form() {
			this.showP12Form(!this.showP12Form());
			this.showPemForm(false);
			this._setStatus('', false);
		}

		togglePemForm() {
			this.showPemForm(!this.showPemForm());
			this.showP12Form(false);
			this._setStatus('', false);
		}

		onP12FileChange(vm, ev) {
			this.p12File = ev.target?.files?.[0] || null;
		}

		onPemFileChange(vm, ev) {
			this.pemFile = ev.target?.files?.[0] || null;
		}

		async importP12() {
			const accountId = parseInt(this.p12AccountId(), 10);
			if (!accountId) { this._setStatus('Please select an account', false); return; }
			if (!this.p12File) { this._setStatus('Please select a .p12 file', false); return; }

			this._setStatus('Importing…', false);
			let b64;
			try {
				b64 = await fileToBase64(this.p12File);
			} catch (e) {
				this._setStatus('Could not read file: ' + e.message, false);
				return;
			}

			window.rl.pluginRemoteRequest((iError, oData) => {
				const r = oData?.Result;
				if (false === oData?.Result || null == oData?.Result) {
					this._setStatus('Server error: ' + (oData?.messageAdditional || oData?.message || '?'), false);
					return;
				}
				if (!r?.ok) {
					this._setStatus('Import failed: ' + (r?.error || 'unknown error'), false);
					return;
				}
				this._setStatus('Certificate imported for ' + escHtml(r.email), true);
				this.showP12Form(false);
				this.p12Password('');
				this.p12File = null;
				this._loadCerts();
			}, 'FrickmailSmimeImportP12', {
				account_id: accountId,
				p12_b64:    b64,
				password:   this.p12Password(),
			}, 30000);
		}

		async importPem() {
			const accountId = parseInt(this.pemAccountId(), 10);
			if (!accountId) { this._setStatus('Please select an account', false); return; }
			if (!this.pemFile) { this._setStatus('Please select a .pem file', false); return; }

			this._setStatus('Importing…', false);
			let b64;
			try {
				b64 = await fileToBase64(this.pemFile);
			} catch (e) {
				this._setStatus('Could not read file: ' + e.message, false);
				return;
			}

			window.rl.pluginRemoteRequest((iError, oData) => {
				const r = oData?.Result;
				if (false === oData?.Result || null == oData?.Result) {
					this._setStatus('Server error: ' + (oData?.messageAdditional || oData?.message || '?'), false);
					return;
				}
				if (!r?.ok) {
					this._setStatus('Import failed: ' + (r?.error || 'unknown error'), false);
					return;
				}
				this._setStatus('Certificate imported for ' + escHtml(r.email), true);
				this.showPemForm(false);
				this.pemFile = null;
				this._loadCerts();
			}, 'FrickmailSmimeImportCert', {
				account_id: accountId,
				pem_b64:    b64,
			}, 30000);
		}

		deleteCert(cert) {
			if (!confirm('Delete S/MIME certificate for ' + cert.email + '?')) return;
			this._setStatus('Deleting…', false);
			window.rl.pluginRemoteRequest((iError, oData) => {
				const r = oData?.Result;
				if (!r?.ok) {
					this._setStatus('Delete failed: ' + (r?.error || 'unknown error'), false);
					return;
				}
				this._setStatus('Certificate deleted', true);
				this._loadCerts();
			}, 'FrickmailSmimeDeleteCert', { id: cert.id }, 30000);
		}

		signTest(cert) {
			const email = cert.email;
			const body  = 'Hello, this is a test S/MIME signed message from Frickmail.\r\nDate: ' + new Date().toISOString();
			this.signResult('Signing…');
			window.rl.pluginRemoteRequest((iError, oData) => {
				const r = oData?.Result;
				if (false === oData?.Result || null == oData?.Result) {
					this.signResult('Error: ' + (oData?.messageAdditional || oData?.message || '?'));
					return;
				}
				if (!r?.ok) {
					this.signResult('Sign failed: ' + (r?.error || 'unknown error'));
					return;
				}
				// Show a truncated preview of the signed message
				const preview = atob(r.signed_b64).slice(0, 120).replace(/\r?\n/g, '↵');
				this.signResult('Signed OK for ' + escHtml(email) + '.\nPreview: ' + preview + '…');
			}, 'FrickmailSmimeSign', { email, body }, 30000);
		}

		certExpiry(cert) {
			if (!cert.not_after) return '';
			const d = new Date(cert.not_after);
			const now = new Date();
			if (d < now) return '⚠ expired ' + formatDate(cert.not_after);
			// Warn if expiring within 30 days
			const diffDays = Math.round((d - now) / 86400000);
			if (diffDays < 30) return '⚠ expires ' + formatDate(cert.not_after);
			return 'expires ' + formatDate(cert.not_after);
		}

		certExpiryStyle(cert) {
			if (!cert.not_after) return '';
			const d = new Date(cert.not_after);
			const now = new Date();
			const diffDays = Math.round((d - now) / 86400000);
			if (diffDays < 0)  return 'color:#c33;font-weight:bold';
			if (diffDays < 30) return 'color:#e67e22';
			return 'color:#888';
		}
	}

	rl.addSettingsViewModel(
		FrickmailSmimeSettings,
		'FrickmailSmimeSettings',
		'S/MIME',
		'frickmail-smime'
	);

})(window.rl);
