(rl => { if (!rl) return;

	// Known provider presets: domain pattern → IMAP/SMTP settings.
	const PROVIDERS = {
		'gmail.com':        { imap: ['imap.gmail.com',         993, 'SSL'],     smtp: ['smtp.gmail.com',         587, 'STARTTLS'], oauth: 'gmail' },
		'googlemail.com':   { imap: ['imap.gmail.com',         993, 'SSL'],     smtp: ['smtp.gmail.com',         587, 'STARTTLS'], oauth: 'gmail' },
		'outlook.com':      { imap: ['outlook.office365.com',  993, 'SSL'],     smtp: ['smtp.office365.com',     587, 'STARTTLS'], oauth: 'o365'  },
		'hotmail.com':      { imap: ['outlook.office365.com',  993, 'SSL'],     smtp: ['smtp.office365.com',     587, 'STARTTLS'], oauth: 'o365'  },
		'live.com':         { imap: ['outlook.office365.com',  993, 'SSL'],     smtp: ['smtp.office365.com',     587, 'STARTTLS'], oauth: 'o365'  },
		'msn.com':          { imap: ['outlook.office365.com',  993, 'SSL'],     smtp: ['smtp.office365.com',     587, 'STARTTLS'], oauth: 'o365'  },
		'yahoo.com':        { imap: ['imap.mail.yahoo.com',    993, 'SSL'],     smtp: ['smtp.mail.yahoo.com',    587, 'STARTTLS'] },
		'yahoo.it':         { imap: ['imap.mail.yahoo.com',    993, 'SSL'],     smtp: ['smtp.mail.yahoo.com',    587, 'STARTTLS'] },
		'yahoo.co.uk':      { imap: ['imap.mail.yahoo.com',    993, 'SSL'],     smtp: ['smtp.mail.yahoo.com',    587, 'STARTTLS'] },
		'ymail.com':        { imap: ['imap.mail.yahoo.com',    993, 'SSL'],     smtp: ['smtp.mail.yahoo.com',    587, 'STARTTLS'] },
		'icloud.com':       { imap: ['imap.mail.me.com',       993, 'SSL'],     smtp: ['smtp.mail.me.com',       587, 'STARTTLS'] },
		'me.com':           { imap: ['imap.mail.me.com',       993, 'SSL'],     smtp: ['smtp.mail.me.com',       587, 'STARTTLS'] },
		'mac.com':          { imap: ['imap.mail.me.com',       993, 'SSL'],     smtp: ['smtp.mail.me.com',       587, 'STARTTLS'] },
		'fastmail.com':     { imap: ['imap.fastmail.com',      993, 'SSL'],     smtp: ['smtp.fastmail.com',      587, 'STARTTLS'] },
		'fastmail.fm':      { imap: ['imap.fastmail.com',      993, 'SSL'],     smtp: ['smtp.fastmail.com',      587, 'STARTTLS'] },
		'proton.me':        { imap: ['127.0.0.1',              1143,'NONE'],    smtp: ['127.0.0.1',              1025,'NONE'],    note: 'Requires Proton Mail Bridge running locally' },
		'protonmail.com':   { imap: ['127.0.0.1',              1143,'NONE'],    smtp: ['127.0.0.1',              1025,'NONE'],    note: 'Requires Proton Mail Bridge running locally' },
		'libero.it':        { imap: ['imapmail.libero.it',     993, 'SSL'],     smtp: ['mail.libero.it',         465, 'SSL'] },
		'virgilio.it':      { imap: ['imapmail.libero.it',     993, 'SSL'],     smtp: ['mail.libero.it',         465, 'SSL'] },
		'tiscali.it':       { imap: ['mail.tiscali.it',        993, 'SSL'],     smtp: ['smtp.tiscali.it',        465, 'SSL'] },
		'tim.it':           { imap: ['imap.tim.it',            993, 'SSL'],     smtp: ['smtp.tim.it',            587, 'STARTTLS'] },
	};

	function detectProvider(email) {
		const domain = (email || '').split('@')[1]?.toLowerCase();
		if (!domain) return null;
		return PROVIDERS[domain] || null;
	}

	class FrickmailMailAccountsSettings
	{
		constructor() {
			this.accounts = ko.observableArray([]);
			this.loading = ko.observable(false);
			this.status = ko.observable('');
			this.adding = ko.observable(false);
			this.draft = {
				type: ko.observable('imap'),
				label: ko.observable(''),
				email: ko.observable(''),
				login: ko.observable(''),
				password: ko.observable(''),
				imap_host: ko.observable(''),
				imap_port: ko.observable(993),
				imap_secure: ko.observable('SSL'),
				smtp_host: ko.observable(''),
				smtp_port: ko.observable(465),
				smtp_secure: ko.observable('SSL'),
				is_primary: ko.observable(false)
			};
			this.providerNote = ko.observable('');

			// Auto-detect provider when email changes
			this.draft.email.subscribe(email => {
				const p = detectProvider(email);
				if (!p) { this.providerNote(''); return; }
				this.applyPreset(p);
			});
		}

		applyPreset(p) {
			const d = this.draft;
			if (p.oauth && !d.imap_host()) {
				d.type(p.oauth);
			} else {
				d.type('imap');
			}
			if (p.imap) { d.imap_host(p.imap[0]); d.imap_port(p.imap[1]); d.imap_secure(p.imap[2]); }
			if (p.smtp) { d.smtp_host(p.smtp[0]); d.smtp_port(p.smtp[1]); d.smtp_secure(p.smtp[2]); }
			this.providerNote(p.note || '');
		}

		onBuild() {
			this.refresh();
		}

		refresh() {
			this.loading(true);
			window.rl.pluginRemoteRequest((iError, oData) => {
				this.loading(false);
				const r = oData?.Result;
				if (false === oData?.Result || null == oData?.Result) { this.status('Server: ' + (oData?.messageAdditional || oData?.message || ('error ' + (oData?.code ?? '?')))); return; }
				if (!r?.ok) { this.status('Failed to load: ' + (r?.error || 'request error')); return; }
				this.accounts(r.accounts || []);
				this.status('');
			}, 'FrickmailListAccounts', {}, 30000);
		}

		startAdd() {
			this.adding(true);
		}

		cancelAdd() {
			this.adding(false);
			this.draft.label(''); this.draft.email(''); this.draft.password('');
			this.draft.imap_host(''); this.draft.smtp_host(''); this.draft.login('');
		}

		saveAccount() {
			const d = this.draft;
			const payload = {
				type: d.type(),
				label: d.label() || d.email(),
				email: d.email(),
				is_primary: d.is_primary()
			};
			if ('imap' === payload.type) {
				Object.assign(payload, {
					login: d.login() || d.email(),
					password: d.password(),
					imap_host: d.imap_host(),
					imap_port: parseInt(d.imap_port(), 10),
					imap_secure: d.imap_secure(),
					smtp_host: d.smtp_host(),
					smtp_port: parseInt(d.smtp_port(), 10),
					smtp_secure: d.smtp_secure()
				});
			}
			this.status('Saving…');
			window.rl.pluginRemoteRequest((iError, oData) => {
				const r = oData?.Result;
				if (false === oData?.Result || null == oData?.Result) { this.status('Server: ' + (oData?.messageAdditional || oData?.message || ('error ' + (oData?.code ?? '?')))); return; }
				if (!r?.ok) { this.status('Save failed: ' + (r?.error || 'request error')); return; }
				this.cancelAdd();
				this.refresh();
			}, 'FrickmailAddAccount', payload, 30000);
		}

		deleteAccount(account) {
			if (!confirm('Delete account ' + account.email + '?')) return;
			window.rl.pluginRemoteRequest((iError, oData) => {
				const r = oData?.Result;
				if (false === oData?.Result || null == oData?.Result) { this.status('Server: ' + (oData?.messageAdditional || oData?.message || ('error ' + (oData?.code ?? '?')))); return; }
				if (!r?.ok) { this.status('Delete failed: ' + (r?.error || 'request error')); return; }
				this.refresh();
			}, 'FrickmailDeleteAccount', { id: account.id }, 30000);
		}

		setPrimary(account) {
			window.rl.pluginRemoteRequest((iError, oData) => {
				const r = oData?.Result;
				if (false === oData?.Result || null == oData?.Result) { this.status('Server: ' + (oData?.messageAdditional || oData?.message || ('error ' + (oData?.code ?? '?')))); return; }
				if (!r?.ok) { this.status('Set-primary failed: ' + (r?.error || 'request error')); return; }
				this.refresh();
			}, 'FrickmailSetPrimary', { id: account.id }, 30000);
		}

		switchTo(account) {
			this.status('Switching to ' + account.email + '…');
			window.rl.pluginRemoteRequest((iError, oData) => {
				const r = oData?.Result;
				if (false === oData?.Result || null == oData?.Result) { this.status('Server: ' + (oData?.messageAdditional || oData?.message || ('error ' + (oData?.code ?? '?')))); return; }
				if (!r?.ok) { this.status('Switch failed: ' + (r?.error || 'request error')); return; }
				document.location.reload();
			}, 'FrickmailSwitchAccount', { id: account.id }, 30000);
		}

		launchOAuth(provider) {
			const path = 'gmail' === provider ? 'StartLoginGMail' : 'StartLoginO365';
			const base = document.location.href.replace(/[#?].*$/, '').replace(/\/+$/, '');
			const w = 520, h = 640,
				y = (screen.availHeight - h) / 2,
				x = (screen.availWidth - w) / 2;
			const popup = window.open(base + '/?' + path, 'frickmail-oauth-' + provider,
				`popup=yes,width=${w},height=${h},left=${x},top=${y}`);
			if (!popup) { this.status('Popup blocked — allow popups and retry'); return; }
			this.status('Waiting for ' + provider + ' consent…');

			const onMsg = e => {
				if (e.origin !== window.location.origin) return;
				const d = e.data;
				if (!d || d.type !== 'frickmail-oauth2') return;
				removeEventListener('message', onMsg);
				if (d.status === 'ok') {
					this.status('Linked ' + (d.email || provider) + '. Refreshing…');
					this.refresh();
					this.cancelAdd();
				} else {
					this.status('OAuth failed: ' + (d.error || 'unknown'));
				}
			};
			addEventListener('message', onMsg);
		}
	}

	rl.addSettingsViewModel(FrickmailMailAccountsSettings, 'FrickmailMailAccountsSettings',
		'Mail Accounts', 'mail-accounts');

})(window.rl);
