(rl => { if (rl) {

	class ContactsSyncSettings
	{
		constructor()
		{
			this.lastResult = ko.observable('');
			this.syncing    = ko.observable(false);
			this.deduping   = ko.observable(false);
		}

		runSync()
		{
			if (this.syncing() || this.deduping()) return;
			this.syncing(true);
			this.lastResult('Syncing…');
			const xtoken = rl.settings?.app?.('token');
			rl.pluginRemoteRequest((iError, oData) => {
				this.syncing(false);
				const res = oData?.Result;
				if (iError || res?.error) {
					this.lastResult('Sync failed: ' + (res?.error || 'request error'));
				} else if (typeof res?.count === 'number') {
					this.lastResult('Synced ' + res.count + ' contact' + (res.count === 1 ? '' : 's') + ' from ' + (res.email || 'provider') + '.');
				} else {
					this.lastResult('Sync done.');
				}
			}, 'JsonContactsSync', xtoken ? {XToken: xtoken} : {}, 60000);
		}

		runDedup()
		{
			if (this.syncing() || this.deduping()) return;
			this.deduping(true);
			this.lastResult('Scanning for duplicates…');
			const xtoken = rl.settings?.app?.('token');
			rl.pluginRemoteRequest((iError, oData) => {
				this.deduping(false);
				const res = oData?.Result;
				if (iError || res?.error) {
					this.lastResult('Deduplication failed: ' + (res?.error || 'request error'));
				} else {
					const n = res?.removed ?? 0;
					this.lastResult(n === 0
						? 'No duplicates found.'
						: 'Removed ' + n + ' duplicate contact' + (n === 1 ? '' : 's') + '.');
				}
			}, 'JsonDeduplicateContacts', xtoken ? {XToken: xtoken} : {}, 120000);
		}

		onBuild() {}
	}

	rl.addSettingsViewModel(ContactsSyncSettings, 'ContactsSyncSettingsTab',
		'Contacts Sync', 'contacts-sync');

}})(window.rl);
