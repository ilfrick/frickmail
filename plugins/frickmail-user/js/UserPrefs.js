/**
 * UserPrefs.js — Frickmail user preferences panel.
 *
 * Adds a "Frickmail Preferences" tab in Settings that lets the user configure:
 *   - Notification poll interval (30–300 s)  — only shown when admin enables notifications
 *   - S/MIME auto-sign toggle                — only shown when admin enables S/MIME
 *   - Unified Inbox messages-per-account     — always visible
 *   - Tasks default tab                      — only shown when admin enables tasks
 *
 * Reads/writes via FrickmailGetPrefs / FrickmailSetPrefs JSON endpoints.
 * Respects admin feature-flags via rl.pluginSettingsGet('frickmail-user', ...).
 */
(rl => { if (!rl) return;

	const PLUGIN = 'frickmail-user';

	function callPlugin(action, params, cb, timeout) {
		const xtoken = rl.settings?.app?.('token') || rl.__frickmail_token;
		if (xtoken) params.XToken = xtoken;
		rl.pluginRemoteRequest(cb, action, params, timeout || 15000);
	}

	function escHtml(s) {
		return String(s ?? '')
			.replace(/&/g, '&amp;')
			.replace(/</g, '&lt;')
			.replace(/>/g, '&gt;')
			.replace(/"/g, '&quot;');
	}

	// ── View-model ────────────────────────────────────────────────────────────

	class FrickmailUserPrefs {

		constructor() {
			this.loading = ko.observable(false);
			this.saving  = ko.observable(false);
			this.status  = ko.observable('');

			// Admin feature-flags
			this.notificationsEnabled = !!rl.pluginSettingsGet(PLUGIN, 'notifications_enabled');
			this.smimeEnabled         = !!rl.pluginSettingsGet(PLUGIN, 'smime_enabled');
			this.tasksEnabled         = !!rl.pluginSettingsGet(PLUGIN, 'tasks_enabled');

			// Preference observables (populated on onBuild)
			this.pollInterval    = ko.observable(60);
			this.smimeAutoSign   = ko.observable(false);
			this.unifiedLimit    = ko.observable(40);
			this.tasksDefaultTab = ko.observable('all');
		}

		onBuild() {
			this._load();
		}

		_load() {
			this.loading(true);
			this.status('');
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

			const prefs = {
				unified_inbox_limit: +this.unifiedLimit(),
			};
			if (this.notificationsEnabled) {
				prefs.notifications_poll_interval = +this.pollInterval();
			}
			if (this.smimeEnabled) {
				prefs.smime_auto_sign = !!this.smimeAutoSign();
			}
			if (this.tasksEnabled) {
				prefs.tasks_default_tab = this.tasksDefaultTab();
			}

			callPlugin('FrickmailSetPrefs', { prefs }, (iErr, oData) => {
				this.saving(false);
				const r = oData?.Result;
				if (!r?.ok) {
					this.status('Save failed: ' + (r?.error || 'request error'));
					return;
				}
				// Reload from the server-side response so we show the final clamped values.
				const p = r.prefs || {};
				if (p.notifications_poll_interval != null) this.pollInterval(+p.notifications_poll_interval);
				if (p.smime_auto_sign             != null) this.smimeAutoSign(!!p.smime_auto_sign);
				if (p.unified_inbox_limit         != null) this.unifiedLimit(+p.unified_inbox_limit);
				if (p.tasks_default_tab           != null) this.tasksDefaultTab(p.tasks_default_tab);
				this.status('Preferences saved.');
			}, 20000);
		}
	}

	// ── Inline template ───────────────────────────────────────────────────────
	//
	// Injected via Knockout's inline template support (ko.applyBindings target).
	// We build the DOM in the view-model's onBuild rather than using a server-side
	// HTML template file, keeping all logic self-contained in a single JS file.

	const TEMPLATE_ID = 'FrickmailUserPrefsTab';

	if (!document.getElementById(TEMPLATE_ID)) {
		const tpl = document.createElement('script');
		tpl.type = 'text/html';
		tpl.id   = TEMPLATE_ID;
		tpl.text = `
<div class="fm-user-prefs-panel" style="max-width:520px;padding:16px 0;">

	<!-- Status message -->
	<div data-bind="visible: status(), text: status"
	     style="margin-bottom:12px;padding:8px 12px;border-radius:4px;
	            background:rgba(137,180,250,.15);color:#89b4fa;
	            border:1px solid rgba(137,180,250,.3);"
	     data-bind="visible: status()"></div>

	<!-- Loading spinner -->
	<div data-bind="visible: loading()" style="color:#a6adc8;margin-bottom:12px;">
		Loading preferences…
	</div>

	<!-- Unified Inbox limit (always visible) -->
	<div style="margin-bottom:20px;" data-bind="visible: !loading()">
		<label style="display:block;margin-bottom:6px;font-weight:600;color:#cdd6f4;">
			Unified Inbox — messages per account
		</label>
		<div style="display:flex;align-items:center;gap:12px;">
			<input type="range" min="10" max="100" step="5"
			       data-bind="value: unifiedLimit, valueUpdate: 'input'"
			       style="flex:1;accent-color:#89b4fa;" />
			<span data-bind="text: unifiedLimit()" style="min-width:30px;text-align:right;color:#89b4fa;font-weight:600;"></span>
		</div>
		<small style="color:#6c7086;">Messages fetched from each account in the Unified Inbox view.</small>
	</div>

	<!-- Notification poll interval (admin-gated) -->
	<!-- ko if: notificationsEnabled -->
	<div style="margin-bottom:20px;" data-bind="visible: !loading()">
		<label style="display:block;margin-bottom:6px;font-weight:600;color:#cdd6f4;">
			Notification check interval (seconds)
		</label>
		<div style="display:flex;align-items:center;gap:12px;">
			<input type="range" min="30" max="300" step="10"
			       data-bind="value: pollInterval, valueUpdate: 'input'"
			       style="flex:1;accent-color:#89b4fa;" />
			<span data-bind="text: pollInterval()" style="min-width:30px;text-align:right;color:#89b4fa;font-weight:600;"></span>
		</div>
		<small style="color:#6c7086;">How often Frickmail checks for new mail in the background (30–300 s).</small>
	</div>
	<!-- /ko -->

	<!-- S/MIME auto-sign (admin-gated) -->
	<!-- ko if: smimeEnabled -->
	<div style="margin-bottom:20px;" data-bind="visible: !loading()">
		<label style="display:flex;align-items:center;gap:10px;cursor:pointer;color:#cdd6f4;">
			<input type="checkbox" data-bind="checked: smimeAutoSign"
			       style="width:16px;height:16px;accent-color:#89b4fa;" />
			<span style="font-weight:600;">Auto-sign outgoing messages with S/MIME</span>
		</label>
		<small style="color:#6c7086;margin-left:26px;display:block;">Automatically attach your S/MIME signature to every sent message.</small>
	</div>
	<!-- /ko -->

	<!-- Tasks default tab (admin-gated) -->
	<!-- ko if: tasksEnabled -->
	<div style="margin-bottom:20px;" data-bind="visible: !loading()">
		<label style="display:block;margin-bottom:6px;font-weight:600;color:#cdd6f4;">
			Tasks panel default tab
		</label>
		<select data-bind="value: tasksDefaultTab"
		        style="padding:6px 10px;border-radius:4px;background:#313244;color:#cdd6f4;border:1px solid #45475a;">
			<option value="all">All tasks</option>
			<option value="pending">Pending only</option>
			<option value="completed">Completed only</option>
		</select>
		<small style="color:#6c7086;display:block;margin-top:4px;">The tab shown by default when you open the task panel.</small>
	</div>
	<!-- /ko -->

	<!-- Save button -->
	<div data-bind="visible: !loading()">
		<button data-bind="click: save, disable: saving()"
		        style="padding:8px 20px;border-radius:4px;border:none;
		               background:#89b4fa;color:#1e1e2e;font-weight:600;cursor:pointer;">
			<!-- ko if: saving() -->Saving…<!-- /ko -->
			<!-- ko ifnot: saving() -->Save preferences<!-- /ko -->
		</button>
	</div>

</div>`;
		document.head.appendChild(tpl);
	}

	rl.addSettingsViewModel(FrickmailUserPrefs, TEMPLATE_ID,
		'Frickmail Preferences', 'frickmail-prefs');

})(window.rl);
