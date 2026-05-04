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
			rl.pluginRemoteRequest((iError, oData) => {
				this.loading(false);
				const r = oData?.Result;
				if (!r?.ok) { this.status('Failed to load: ' + (r?.error || 'request error')); return; }
				this.accounts(r.accounts || []);
				this.status('');
			}, 'FrickmailListAccounts', {}, 30);
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
			rl.pluginRemoteRequest((iError, oData) => {
				const r = oData?.Result;
				if (!r?.ok) { this.status('Save failed: ' + (r?.error || 'request error')); return; }
				this.cancelAdd();
				this.refresh();
			}, 'FrickmailAddAccount', payload, 30);
		}

		deleteAccount(account) {
			if (!confirm('Delete account ' + account.email + '?')) return;
			rl.pluginRemoteRequest((iError, oData) => {
				const r = oData?.Result;
				if (!r?.ok) { this.status('Delete failed: ' + (r?.error || 'request error')); return; }
				this.refresh();
			}, 'FrickmailDeleteAccount', { id: account.id }, 30);
		}

		setPrimary(account) {
			rl.pluginRemoteRequest((iError, oData) => {
				const r = oData?.Result;
				if (!r?.ok) { this.status('Set-primary failed: ' + (r?.error || 'request error')); return; }
				this.refresh();
			}, 'FrickmailSetPrimary', { id: account.id }, 30);
		}
	}

	rl.addSettingsViewModel(FrickmailMailAccountsSettings, 'FrickmailMailAccountsSettings',
		'Mail Accounts', 'mail-accounts');

})(window.rl);
