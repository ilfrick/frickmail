(rl => { if (!rl) return;

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
