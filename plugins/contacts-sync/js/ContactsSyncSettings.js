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
			rl.pluginRemoteRequest((iError, oData) => {
				this.syncing(false);
				if (iError) {
					this.lastResult('Sync failed: ' + (oData?.Result?.error || 'request error'));
					return;
				}
				const r = oData && oData.Result;
				if (r && r.error) {
					this.lastResult('Sync failed: ' + r.error);
				} else if (r && typeof r.count === 'number') {
					this.lastResult('Synced ' + r.count + ' contact' + (r.count === 1 ? '' : 's') + ' from ' + (r.email || 'provider') + '.');
				} else {
					this.lastResult('Sync done.');
				}
			}, 'JsonContactsSync', {}, 60000);
		}

		onBuild() {}
	}

	rl.addSettingsViewModel(ContactsSyncSettings, 'ContactsSyncSettingsTab',
		'Contacts Sync', 'contacts-sync');

}})(window.rl);
