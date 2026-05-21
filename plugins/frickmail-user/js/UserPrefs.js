// Frickmail user preferences settings tab.
// Template is registered server-side as FrickmailUserPrefsTab.html (via addTemplate).
(rl => { if (!rl) return;

	const PLUGIN = 'frickmail-user';

	function callPlugin(action, params, cb, timeout) {
		const xtoken = rl.settings?.app?.('token') || rl.__frickmail_token;
		if (xtoken) params.XToken = xtoken;
		rl.pluginRemoteRequest(cb, action, params, timeout || 15000);
	}

	class FrickmailUserPrefs {

		constructor() {
			this.loading = ko.observable(true);
			this.saving  = ko.observable(false);
			this.status  = ko.observable('');

			// Admin feature-flags
			this.notificationsEnabled = !!rl.pluginSettingsGet(PLUGIN, 'notifications_enabled');
			this.smimeEnabled         = !!rl.pluginSettingsGet(PLUGIN, 'smime_enabled');
			this.tasksEnabled         = !!rl.pluginSettingsGet(PLUGIN, 'tasks_enabled');

			// Preference observables
			this.pollInterval    = ko.observable(60);
			this.smimeAutoSign   = ko.observable(false);
			this.unifiedLimit    = ko.observable(40);
			this.tasksDefaultTab = ko.observable('all');
		}

		onBuild() {
			callPlugin('FrickmailGetPrefs', {}, (iErr, oData) => {
				this.loading(false);
				const r = oData?.Result;
				if (!r?.ok) {
					this.status('Could not load preferences: ' + (r?.error || 'request error'));
					return;
				}
				const p = r.prefs || {};
				if (p.notifications_poll_interval != null) this.pollInterval(+p.notifications_poll_interval);
				if (p.smime_auto_sign             != null) this.smimeAutoSign(!!p.smime_auto_sign);
				if (p.unified_inbox_limit         != null) this.unifiedLimit(+p.unified_inbox_limit);
				if (p.tasks_default_tab           != null) this.tasksDefaultTab(p.tasks_default_tab);
			});
		}

		save() {
			if (this.saving()) return;
			this.saving(true);
			this.status('');

			const prefs = { unified_inbox_limit: +this.unifiedLimit() };
			if (this.notificationsEnabled) prefs.notifications_poll_interval = +this.pollInterval();
			if (this.smimeEnabled)         prefs.smime_auto_sign = !!this.smimeAutoSign();
			if (this.tasksEnabled)         prefs.tasks_default_tab = this.tasksDefaultTab();

			callPlugin('FrickmailSetPrefs', { prefs }, (iErr, oData) => {
				this.saving(false);
				const r = oData?.Result;
				if (!r?.ok) {
					this.status('Save failed: ' + (r?.error || 'request error'));
					return;
				}
				const p = r.prefs || {};
				if (p.notifications_poll_interval != null) this.pollInterval(+p.notifications_poll_interval);
				if (p.smime_auto_sign             != null) this.smimeAutoSign(!!p.smime_auto_sign);
				if (p.unified_inbox_limit         != null) this.unifiedLimit(+p.unified_inbox_limit);
				if (p.tasks_default_tab           != null) this.tasksDefaultTab(p.tasks_default_tab);
				this.status('Preferences saved.');
			}, 20000);
		}
	}

	rl.addSettingsViewModel(FrickmailUserPrefs, 'FrickmailUserPrefsTab',
		'Frickmail Preferences', 'frickmail-prefs');

})(window.rl);
