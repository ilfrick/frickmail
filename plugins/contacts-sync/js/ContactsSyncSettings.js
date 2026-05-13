(rl => { if (rl) {

	class ContactsSyncSettings
	{
		constructor()
		{
			this.lastResult = ko.observable('');
			this.syncing = ko.observable(false);
		}

		runSync()
		{
			if (this.syncing()) return;
			this.syncing(true);
			this.lastResult('Working...');
			const r = window.rl;
			const xtoken = r.settings?.app?.('token');
			r.pluginRemoteRequest((iError, oData) => {
				this.syncing(false);
				if (iError) {
					this.lastResult('Sync failed: ' + (oData?.Result?.error || 'request error'));
					return;
				}
				const res = oData && oData.Result;
				if (res && res.error) {
					this.lastResult('Sync failed: ' + res.error);
				} else if (res && typeof res.count === 'number') {
					this.lastResult('Synced ' + res.count + ' contact' + (res.count === 1 ? '' : 's') + ' from ' + (res.email || 'provider') + '.');
				} else {
					this.lastResult('Sync done.');
				}
			}, 'JsonContactsSync', xtoken ? {XToken: xtoken} : {}, 60000);
		}

		onBuild() {}
	}

	rl.addSettingsViewModel(ContactsSyncSettings, 'ContactsSyncSettingsTab',
		'Contacts Sync', 'contacts-sync');

}})(window.rl);
