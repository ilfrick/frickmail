/**
 * Rules.js — Message Rules panel embedded in the Mail Accounts settings tab.
 *
 * Adds a "Message Rules" section below the identity section for each account.
 * Supports: list rules, add rule, toggle on/off, delete, and "Run rules now".
 *
 * Condition fields : from | subject | to
 * Condition ops    : contains | not_contains | equals
 * Actions          : move (requires folder) | read | flag | delete
 * Logic            : all (AND) | any (OR)
 */
(rl => { if (!rl) return;

	function escHtml(s) {
		return String(s ?? '')
			.replace(/&/g, '&amp;')
			.replace(/</g, '&lt;')
			.replace(/>/g, '&gt;')
			.replace(/"/g, '&quot;');
	}

	class FrickmailRulesSettings {
		constructor() {
			this.accounts     = ko.observableArray([]);
			this.expanded     = ko.observable(null);   // account id whose rules panel is open
			this.rulesMap     = ko.observable({});      // accountId → rules[]
			this.addingFor    = ko.observable(null);   // account id for which add-form is open
			this.status       = ko.observable('');
			this.runReport    = ko.observable('');

			// Draft for new rule
			this.draft = {
				name:            ko.observable(''),
				condField:       ko.observable('from'),
				condOp:          ko.observable('contains'),
				condValue:       ko.observable(''),
				condLogic:       ko.observable('all'),
				actionType:      ko.observable('move'),
				actionFolder:    ko.observable(''),
			};
		}

		onBuild() {
			this._loadAccounts();
		}

		_loadAccounts() {
			window.rl.pluginRemoteRequest((iError, oData) => {
				const r = oData?.Result;
				if (!r?.ok) return;
				this.accounts(r.accounts || []);
				// Pre-load rules for each account
				(r.accounts || []).forEach(a => this._loadRules(a.id));
			}, 'FrickmailListAccounts', {}, 30000);
		}

		_loadRules(accountId) {
			window.rl.pluginRemoteRequest((iError, oData) => {
				const r = oData?.Result;
				if (!r?.ok) return;
				const map = Object.assign({}, this.rulesMap());
				map[accountId] = r.rules || [];
				this.rulesMap(map);
			}, 'FrickmailListRules', { account_id: accountId }, 30000);
		}

		rulesFor(accountId) {
			return this.rulesMap()[accountId] || [];
		}

		toggle(account) {
			const isOpen = this.expanded() === account.id;
			this.expanded(isOpen ? null : account.id);
			this.addingFor(null);
			this.clearDraft();
			this.status('');
			this.runReport('');
			if (!isOpen) this._loadRules(account.id);
		}

		isExpanded(account) {
			return this.expanded() === account.id;
		}

		startAdd(account) {
			this.addingFor(account.id);
			this.clearDraft();
			this.status('');
		}

		cancelAdd() {
			this.addingFor(null);
			this.clearDraft();
		}

		clearDraft() {
			const d = this.draft;
			d.name('');
			d.condField('from');
			d.condOp('contains');
			d.condValue('');
			d.condLogic('all');
			d.actionType('move');
			d.actionFolder('');
		}

		saveRule(account) {
			const d = this.draft;
			if (!d.name().trim()) { this.status('Rule name is required'); return; }
			if (!d.condValue().trim()) { this.status('Condition value is required'); return; }
			if (d.actionType() === 'move' && !d.actionFolder().trim()) {
				this.status('Target folder is required for Move action'); return;
			}

			const condition = {
				field: d.condField(),
				op:    d.condOp(),
				value: d.condValue().trim(),
			};
			const action = { type: d.actionType() };
			if (d.actionType() === 'move') {
				action.params = { folder: d.actionFolder().trim() };
			}

			const payload = {
				account_id:       account.id,
				name:             d.name().trim(),
				conditions:       [condition],
				conditions_logic: d.condLogic(),
				actions:          [action],
			};

			this.status('Saving…');
			window.rl.pluginRemoteRequest((iError, oData) => {
				const r = oData?.Result;
				if (false === oData?.Result || null == oData?.Result) {
					this.status('Server error: ' + (oData?.messageAdditional || oData?.message || '?'));
					return;
				}
				if (!r?.ok) { this.status('Failed: ' + (r?.error || 'unknown error')); return; }
				this.status('');
				this.cancelAdd();
				this._loadRules(account.id);
			}, 'FrickmailAddRule', payload, 30000);
		}

		toggleRule(account, rule) {
			const newEnabled = !rule.enabled;
			window.rl.pluginRemoteRequest((iError, oData) => {
				const r = oData?.Result;
				if (!r?.ok) { this.status('Toggle failed: ' + (r?.error || '?')); return; }
				this._loadRules(account.id);
			}, 'FrickmailToggleRule', { id: rule.id, enabled: newEnabled }, 30000);
		}

		deleteRule(account, rule) {
			if (!confirm('Delete rule "' + escHtml(rule.name) + '"?')) return;
			window.rl.pluginRemoteRequest((iError, oData) => {
				const r = oData?.Result;
				if (!r?.ok) { this.status('Delete failed: ' + (r?.error || '?')); return; }
				this._loadRules(account.id);
			}, 'FrickmailDeleteRule', { id: rule.id }, 30000);
		}

		runRules(account) {
			this.runReport('Running rules…');
			this.status('');
			window.rl.pluginRemoteRequest((iError, oData) => {
				const r = oData?.Result;
				if (false === oData?.Result || null == oData?.Result) {
					this.runReport('Error: ' + (oData?.messageAdditional || oData?.message || '?'));
					return;
				}
				if (!r?.ok) { this.runReport('Error: ' + (r?.error || 'unknown error')); return; }
				const applied = r.applied || [];
				if (!applied.length) {
					this.runReport('No rules matched any messages.');
				} else {
					const lines = applied.map(a =>
						`Rule "${escHtml(a.rule_name)}": ${a.matched_count} message(s) → ${escHtml(a.action_type)}`
					);
					this.runReport('Done:\n' + lines.join('\n'));
				}
				this._loadRules(account.id);
			}, 'FrickmailApplyRules', { account_id: account.id }, 60000);
		}
	}

	rl.addSettingsViewModel(
		FrickmailRulesSettings,
		'FrickmailRulesSettings',
		'Rules',
		'frickmail-rules'
	);

})(window.rl);
