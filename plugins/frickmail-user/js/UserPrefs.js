/**
 * UserPrefs.js — Frickmail user preferences panel.
 *
 * Uses the same imperative onBuild(dom) pattern as ThemeSwitcher so the
 * template renders correctly inside SnappyMail's settings framework.
 */
(rl => { if (!rl) return;

	const PLUGIN = 'frickmail-user';
	const TEMPLATE_ID = 'FrickmailUserPrefsTab';

	function callPlugin(action, params, cb, timeout) {
		const xtoken = rl.settings?.app?.('token') || rl.__frickmail_token;
		if (xtoken) params.XToken = xtoken;
		rl.pluginRemoteRequest(cb, action, params, timeout || 15000);
	}

	// ── View-model ────────────────────────────────────────────────────────────

	class FrickmailUserPrefs {

		constructor() {
			this.loading = false;
			this.saving  = false;

			// Admin feature-flags
			this.notificationsEnabled = !!rl.pluginSettingsGet(PLUGIN, 'notifications_enabled');
			this.smimeEnabled         = !!rl.pluginSettingsGet(PLUGIN, 'smime_enabled');
			this.tasksEnabled         = !!rl.pluginSettingsGet(PLUGIN, 'tasks_enabled');

			// Current preference values
			this.prefs = {
				pollInterval:    60,
				smimeAutoSign:   false,
				unifiedLimit:    40,
				tasksDefaultTab: 'all',
			};

			this._dom = null;
		}

		onBuild(dom) {
			if (!dom) return;
			this._dom = dom;
			this._render(dom);
			this._load();
		}

		_render(dom) {
			const p = this.prefs;
			const notif  = this.notificationsEnabled;
			const smime  = this.smimeEnabled;
			const tasks  = this.tasksEnabled;

			dom.innerHTML = `
<div style="max-width:520px;padding:16px 0;">

	<div id="fm-prefs-status" style="display:none;margin-bottom:12px;padding:8px 12px;border-radius:4px;
		background:rgba(137,180,250,.15);color:#89b4fa;border:1px solid rgba(137,180,250,.3);"></div>

	<div id="fm-prefs-loading" style="color:#a6adc8;margin-bottom:12px;">
		Loading preferences…
	</div>

	<div id="fm-prefs-form" style="display:none;">

		<div style="margin-bottom:20px;">
			<label style="display:block;margin-bottom:6px;font-weight:600;color:var(--fm-text-primary,#cdd6f4);">
				Unified Inbox — messages per account
			</label>
			<div style="display:flex;align-items:center;gap:12px;">
				<input id="fm-prefs-unified" type="range" min="10" max="100" step="5" value="${p.unifiedLimit}"
				       style="flex:1;accent-color:var(--fm-accent,#89b4fa);" />
				<span id="fm-prefs-unified-val" style="min-width:30px;text-align:right;color:var(--fm-accent,#89b4fa);font-weight:600;">${p.unifiedLimit}</span>
			</div>
			<small style="color:var(--fm-text-secondary,#6c7086);">Messages fetched from each account in the Unified Inbox view.</small>
		</div>

		${notif ? `
		<div style="margin-bottom:20px;">
			<label style="display:block;margin-bottom:6px;font-weight:600;color:var(--fm-text-primary,#cdd6f4);">
				Notification check interval (seconds)
			</label>
			<div style="display:flex;align-items:center;gap:12px;">
				<input id="fm-prefs-poll" type="range" min="30" max="300" step="10" value="${p.pollInterval}"
				       style="flex:1;accent-color:var(--fm-accent,#89b4fa);" />
				<span id="fm-prefs-poll-val" style="min-width:30px;text-align:right;color:var(--fm-accent,#89b4fa);font-weight:600;">${p.pollInterval}</span>
			</div>
			<small style="color:var(--fm-text-secondary,#6c7086);">How often Frickmail checks for new mail in the background (30–300 s).</small>
		</div>` : ''}

		${smime ? `
		<div style="margin-bottom:20px;">
			<label style="display:flex;align-items:center;gap:10px;cursor:pointer;color:var(--fm-text-primary,#cdd6f4);">
				<input id="fm-prefs-smime" type="checkbox" ${p.smimeAutoSign ? 'checked' : ''}
				       style="width:16px;height:16px;accent-color:var(--fm-accent,#89b4fa);" />
				<span style="font-weight:600;">Auto-sign outgoing messages with S/MIME</span>
			</label>
			<small style="color:var(--fm-text-secondary,#6c7086);margin-left:26px;display:block;">
				Automatically attach your S/MIME signature to every sent message.
			</small>
		</div>` : ''}

		${tasks ? `
		<div style="margin-bottom:20px;">
			<label style="display:block;margin-bottom:6px;font-weight:600;color:var(--fm-text-primary,#cdd6f4);">
				Tasks panel default tab
			</label>
			<select id="fm-prefs-tasks-tab"
			        style="padding:6px 10px;border-radius:4px;background:var(--fm-bg-input,#313244);color:var(--fm-text-primary,#cdd6f4);border:1px solid var(--fm-border,#45475a);">
				<option value="all" ${p.tasksDefaultTab==='all' ? 'selected' : ''}>All tasks</option>
				<option value="pending" ${p.tasksDefaultTab==='pending' ? 'selected' : ''}>Pending only</option>
				<option value="completed" ${p.tasksDefaultTab==='completed' ? 'selected' : ''}>Completed only</option>
			</select>
			<small style="color:var(--fm-text-secondary,#6c7086);display:block;margin-top:4px;">
				The tab shown by default when you open the task panel.
			</small>
		</div>` : ''}

		<div>
			<button id="fm-prefs-save"
			        style="padding:8px 20px;border-radius:4px;border:none;
			               background:var(--fm-accent,#89b4fa);color:var(--fm-bg-base,#1e1e2e);font-weight:600;cursor:pointer;">
				Save preferences
			</button>
		</div>

	</div>
</div>`;

			// Wire up live-preview for range sliders
			const unifiedInput = dom.querySelector('#fm-prefs-unified');
			const unifiedVal   = dom.querySelector('#fm-prefs-unified-val');
			if (unifiedInput) {
				unifiedInput.addEventListener('input', () => { unifiedVal.textContent = unifiedInput.value; });
			}

			const pollInput = dom.querySelector('#fm-prefs-poll');
			const pollVal   = dom.querySelector('#fm-prefs-poll-val');
			if (pollInput) {
				pollInput.addEventListener('input', () => { pollVal.textContent = pollInput.value; });
			}

			const saveBtn = dom.querySelector('#fm-prefs-save');
			if (saveBtn) {
				saveBtn.addEventListener('click', () => this._save());
			}
		}

		_updateFormValues() {
			if (!this._dom) return;
			const d = this._dom;
			const p = this.prefs;
			const setVal = (id, v) => { const el = d.querySelector(id); if (el) el.value = v; };
			const setTxt = (id, v) => { const el = d.querySelector(id); if (el) el.textContent = v; };
			const setChk = (id, v) => { const el = d.querySelector(id); if (el) el.checked = v; };

			setVal('#fm-prefs-unified',     p.unifiedLimit);
			setTxt('#fm-prefs-unified-val', p.unifiedLimit);
			setVal('#fm-prefs-poll',        p.pollInterval);
			setTxt('#fm-prefs-poll-val',    p.pollInterval);
			setChk('#fm-prefs-smime',       p.smimeAutoSign);
			setVal('#fm-prefs-tasks-tab',   p.tasksDefaultTab);
		}

		_setStatus(msg, isError) {
			if (!this._dom) return;
			const el = this._dom.querySelector('#fm-prefs-status');
			if (!el) return;
			if (msg) {
				el.textContent = msg;
				el.style.display = '';
				el.style.color = isError ? 'var(--fm-error,#f38ba8)' : 'var(--fm-accent,#89b4fa)';
				el.style.borderColor = isError ? 'rgba(243,139,168,.3)' : 'rgba(137,180,250,.3)';
				el.style.background  = isError ? 'rgba(243,139,168,.15)' : 'rgba(137,180,250,.15)';
			} else {
				el.style.display = 'none';
			}
		}

		_load() {
			const loadingEl = this._dom?.querySelector('#fm-prefs-loading');
			const formEl    = this._dom?.querySelector('#fm-prefs-form');

			callPlugin('FrickmailGetPrefs', {}, (iErr, oData) => {
				if (loadingEl) loadingEl.style.display = 'none';
				if (formEl)    formEl.style.display = '';

				const r = oData?.Result;
				if (!r?.ok) {
					this._setStatus('Could not load preferences: ' + (r?.error || 'request error'), true);
					return;
				}
				const p = r.prefs || {};
				if (p.notifications_poll_interval != null) this.prefs.pollInterval    = +p.notifications_poll_interval;
				if (p.smime_auto_sign             != null) this.prefs.smimeAutoSign   = !!p.smime_auto_sign;
				if (p.unified_inbox_limit         != null) this.prefs.unifiedLimit    = +p.unified_inbox_limit;
				if (p.tasks_default_tab           != null) this.prefs.tasksDefaultTab = p.tasks_default_tab;
				this._updateFormValues();
			});
		}

		_save() {
			if (this.saving) return;
			this.saving = true;
			this._setStatus('');

			const saveBtn = this._dom?.querySelector('#fm-prefs-save');
			if (saveBtn) { saveBtn.disabled = true; saveBtn.textContent = 'Saving…'; }

			const d = this._dom;
			const prefs = {
				unified_inbox_limit: +(d?.querySelector('#fm-prefs-unified')?.value ?? this.prefs.unifiedLimit),
			};
			if (this.notificationsEnabled) {
				prefs.notifications_poll_interval = +(d?.querySelector('#fm-prefs-poll')?.value ?? this.prefs.pollInterval);
			}
			if (this.smimeEnabled) {
				prefs.smime_auto_sign = !!(d?.querySelector('#fm-prefs-smime')?.checked);
			}
			if (this.tasksEnabled) {
				prefs.tasks_default_tab = d?.querySelector('#fm-prefs-tasks-tab')?.value ?? this.prefs.tasksDefaultTab;
			}

			callPlugin('FrickmailSetPrefs', { prefs }, (iErr, oData) => {
				this.saving = false;
				if (saveBtn) { saveBtn.disabled = false; saveBtn.textContent = 'Save preferences'; }

				const r = oData?.Result;
				if (!r?.ok) {
					this._setStatus('Save failed: ' + (r?.error || 'request error'), true);
					return;
				}
				const p = r.prefs || {};
				if (p.notifications_poll_interval != null) this.prefs.pollInterval    = +p.notifications_poll_interval;
				if (p.smime_auto_sign             != null) this.prefs.smimeAutoSign   = !!p.smime_auto_sign;
				if (p.unified_inbox_limit         != null) this.prefs.unifiedLimit    = +p.unified_inbox_limit;
				if (p.tasks_default_tab           != null) this.prefs.tasksDefaultTab = p.tasks_default_tab;
				this._updateFormValues();
				this._setStatus('Preferences saved.');
			}, 20000);
		}
	}

	// ── Register template (minimal placeholder — content built in onBuild) ────

	if (!document.getElementById(TEMPLATE_ID)) {
		const tpl = document.createElement('template');
		tpl.id = TEMPLATE_ID;
		tpl.innerHTML = '<div></div>';
		document.body.appendChild(tpl);
	}

	rl.addSettingsViewModel(FrickmailUserPrefs, TEMPLATE_ID,
		'Frickmail Preferences', 'frickmail-prefs');

})(window.rl);
