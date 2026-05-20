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

	// ── Inline KO template ────────────────────────────────────────────────────

	const TMPL_ID = 'frickmail-smime-tmpl';
	if (!document.getElementById(TMPL_ID)) {
		const script = document.createElement('script');
		script.id   = TMPL_ID;
		script.type = 'text/html';
		script.textContent = `
<div style="margin-top:1.5em">
	<div class="legend">S/MIME Certificates</div>
	<p style="font-size:88%;color:#888">
		Manage S/MIME certificates for signing and verifying email messages.
		Import your own .p12 bundle (private key + certificate) or a
		recipient's public .pem certificate.
	</p>

	<!-- Certificate list -->
	<!-- ko if: loading() -->
	<div style="color:#888;font-size:88%">Loading…</div>
	<!-- /ko -->

	<!-- ko ifnot: loading() -->
	<!-- ko if: certs().length === 0 -->
	<div style="color:#aaa;font-size:88%;margin-bottom:.8em">No certificates stored yet.</div>
	<!-- /ko -->

	<!-- ko foreach: certs -->
	<div style="display:flex;align-items:center;gap:.6em;padding:.45em .6em;border-bottom:1px solid rgba(0,0,0,.07);font-size:90%">
		<!-- Key icon only when cert has a private key -->
		<span style="font-size:110%;min-width:1.4em;text-align:center"
		      data-bind="text: has_key ? '🔑' : '📜'"
		      title="data-bind: has_key ? 'Has private key' : 'Public certificate only'"></span>

		<div style="flex:1;min-width:0">
			<strong data-bind="text: email"></strong>
			<!-- ko if: subject -->
			<span style="color:#666;margin-left:.4em;font-size:88%"
			      data-bind="text: subject"></span>
			<!-- /ko -->
		</div>

		<span data-bind="text: $parent.certExpiry($data),
		                 style: {'color': $parent.certExpiryStyle($data).replace('color:','').split(';')[0]}"
		      style="font-size:82%;white-space:nowrap"></span>

		<span style="font-size:76%;color:#bbb;white-space:nowrap;overflow:hidden;max-width:140px;text-overflow:ellipsis"
		      data-bind="text: fingerprint, attr: {title: fingerprint}"></span>

		<!-- ko if: has_key -->
		<button class="btn" style="font-size:80%;padding:2px 8px;white-space:nowrap"
		        data-bind="click: $parent.signTest.bind($parent, $data)">
			Sign test
		</button>
		<!-- /ko -->

		<button class="btn" style="font-size:80%;padding:2px 8px;background:#c33;color:white;white-space:nowrap"
		        data-bind="click: $parent.deleteCert.bind($parent, $data)">
			Delete
		</button>
	</div>
	<!-- /ko -->
	<!-- /ko -->

	<!-- Sign test result -->
	<!-- ko if: signResult().length -->
	<pre style="margin-top:.5em;font-size:80%;color:#555;white-space:pre-wrap;background:rgba(0,0,0,.03);padding:.5em;border-radius:4px;overflow:auto;max-height:100px"
	     data-bind="text: signResult()"></pre>
	<!-- /ko -->

	<!-- Import buttons -->
	<div style="margin-top:.8em;display:flex;gap:.5em;flex-wrap:wrap">
		<button class="btn" style="font-size:85%"
		        data-bind="click: toggleP12Form">
			⬆ Import .p12 (my cert+key)
		</button>
		<button class="btn" style="font-size:85%"
		        data-bind="click: togglePemForm">
			⬆ Import .pem (recipient cert)
		</button>
	</div>

	<!-- Import P12 form -->
	<!-- ko if: showP12Form() -->
	<div style="margin-top:.8em;padding:.8em;border:1px solid #4a90e2;border-radius:6px">
		<h5 style="margin:0 0 .6em">Import PKCS#12 (.p12 / .pfx)</h5>

		<label style="display:block;font-size:85%;margin-bottom:.2em">Account</label>
		<select data-bind="value: p12AccountId, options: accounts,
		                   optionsText: a => a.label || a.email,
		                   optionsValue: 'id',
		                   optionsCaption: '— select account —'"
		        style="width:100%;margin-bottom:.5em"></select>

		<label style="display:block;font-size:85%;margin-bottom:.2em">PKCS#12 file (.p12 / .pfx)</label>
		<input type="file" accept=".p12,.pfx"
		       data-bind="event: { change: onP12FileChange.bind($data) }"
		       style="margin-bottom:.5em" />

		<label style="display:block;font-size:85%;margin-bottom:.2em">Passphrase (if any)</label>
		<input type="password" data-bind="value: p12Password"
		       placeholder="Leave blank if none" style="width:100%;margin-bottom:.5em" />

		<div style="display:flex;gap:.5em;margin-top:.3em">
			<button class="btn" style="background:#4a90e2;color:white"
			        data-bind="click: importP12">Import</button>
			<button class="btn" data-bind="click: toggleP12Form">Cancel</button>
		</div>
	</div>
	<!-- /ko -->

	<!-- Import PEM form -->
	<!-- ko if: showPemForm() -->
	<div style="margin-top:.8em;padding:.8em;border:1px solid #4a90e2;border-radius:6px">
		<h5 style="margin:0 0 .6em">Import PEM certificate (recipient)</h5>

		<label style="display:block;font-size:85%;margin-bottom:.2em">Account</label>
		<select data-bind="value: pemAccountId, options: accounts,
		                   optionsText: a => a.label || a.email,
		                   optionsValue: 'id',
		                   optionsCaption: '— select account —'"
		        style="width:100%;margin-bottom:.5em"></select>

		<label style="display:block;font-size:85%;margin-bottom:.2em">PEM certificate file (.pem / .crt)</label>
		<input type="file" accept=".pem,.crt,.cer"
		       data-bind="event: { change: onPemFileChange.bind($data) }"
		       style="margin-bottom:.5em" />

		<div style="display:flex;gap:.5em;margin-top:.3em">
			<button class="btn" style="background:#4a90e2;color:white"
			        data-bind="click: importPem">Import</button>
			<button class="btn" data-bind="click: togglePemForm">Cancel</button>
		</div>
	</div>
	<!-- /ko -->

	<!-- Status message -->
	<!-- ko if: status().length -->
	<div style="margin-top:.5em;font-size:88%"
	     data-bind="text: status(),
	                style: { color: statusOk() ? '#2a7' : '#c55' }"></div>
	<!-- /ko -->
</div>`;
		document.head.appendChild(script);
	}

	rl.addSettingsViewModel(
		FrickmailSmimeSettings,
		'FrickmailSmimeSettings',
		// Empty label — appends to the same tab pane as Mail Accounts / Rules
		'',
		'mail-accounts'
	);

})(window.rl);
