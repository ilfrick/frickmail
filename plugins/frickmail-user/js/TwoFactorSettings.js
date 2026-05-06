(rl => { if (!rl) return;

	const callPlugin = (action, params, cb) => {
		const xtoken = rl.settings?.app?.('token') || rl.__frickmail_token;
		if (xtoken) params.XToken = xtoken;
		rl.pluginRemoteRequest(cb, action, params, 30000);
	};

	class FrickmailTwoFactorSettings
	{
		constructor() {
			this.enabled = ko.observable(false);
			this.loading = ko.observable(false);
			this.status = ko.observable('');
			this.pending = ko.observable(false);  // setup in progress
			this.secret = ko.observable('');
			this.otpauthUri = ko.observable('');
			this.confirmCode = ko.observable('');
			this.disableCode = ko.observable('');
		}

		onBuild() {
			this.refresh();
		}

		refresh() {
			this.loading(true);
			callPlugin('FrickmailGetTotpStatus', {}, (iErr, oData) => {
				this.loading(false);
				const r = oData?.Result;
				if (!r?.ok) { this.status('Failed: ' + (r?.error || 'request error')); return; }
				this.enabled(!!r.enabled);
				this.status('');
			});
		}

		startEnable() {
			this.status('Generating secret…');
			callPlugin('FrickmailEnableTotp', {}, (iErr, oData) => {
				const r = oData?.Result;
				if (!r?.ok) { this.status('Failed: ' + (r?.error || 'request error')); return; }
				this.secret(r.secret);
				this.otpauthUri(r.otpauth_uri);
				this.pending(true);
				this.status(r.message || 'Scan the QR code with your authenticator and confirm with a code.');
			});
		}

		confirmEnable() {
			const code = this.confirmCode().replace(/\s+/g, '');
			if (!code) { this.status('Enter the 6-digit code from your authenticator', 'error'); return; }
			this.status('Verifying…');
			callPlugin('FrickmailConfirmTotp', { code }, (iErr, oData) => {
				const r = oData?.Result;
				if (!r?.ok) { this.status('Failed: ' + (r?.error || 'request error')); return; }
				this.pending(false);
				this.secret('');
				this.otpauthUri('');
				this.confirmCode('');
				this.status(r.message || 'Two-factor enabled.');
				this.refresh();
			});
		}

		cancelEnable() {
			this.pending(false);
			this.secret('');
			this.otpauthUri('');
			this.confirmCode('');
			this.status('');
		}

		disable() {
			const code = this.disableCode().replace(/\s+/g, '');
			if (!code) { this.status('Enter your current 6-digit code to disable', 'error'); return; }
			this.status('Disabling…');
			callPlugin('FrickmailDisableTotp', { code }, (iErr, oData) => {
				const r = oData?.Result;
				if (!r?.ok) { this.status('Failed: ' + (r?.error || 'request error')); return; }
				this.disableCode('');
				this.status(r.message || 'Two-factor disabled.');
				this.refresh();
			});
		}
	}

	rl.addSettingsViewModel(FrickmailTwoFactorSettings, 'FrickmailTwoFactorSettingsTab',
		'Two-Factor (Frickmail user)', 'frickmail-2fa');

})(window.rl);
