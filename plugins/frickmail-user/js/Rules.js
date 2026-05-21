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

	// ── Inline KO template ────────────────────────────────────────────────────

	const TMPL_ID = 'FrickmailRulesSettings';
	if (!document.getElementById(TMPL_ID)) {
		const script = document.createElement('script');
		script.id   = TMPL_ID;
		script.type = 'text/html';
		script.textContent = `
<div style="margin-top:1.5em">
	<div class="legend">Message Rules</div>
	<p style="font-size:88%;color:#888">
		Automatically process incoming INBOX messages for each account.
		Rules are applied when you click "Run rules now".
	</p>

	<!-- ko foreach: accounts -->
	<div style="border:1px solid #ddd;border-radius:6px;margin-bottom:.6em;overflow:hidden">
		<div style="display:flex;align-items:center;gap:.6em;padding:.5em .8em;background:rgba(0,0,0,.04);cursor:pointer"
		     data-bind="click: $parent.toggle.bind($parent, $data)">
			<strong data-bind="text: label || email"></strong>
			<span style="font-size:85%;color:#888" data-bind="text: email"></span>
			<span style="margin-left:auto;font-size:80%;color:#666"
			      data-bind="text: ($parent.rulesFor(id).length) + ' rule' + ($parent.rulesFor(id).length === 1 ? '' : 's')"></span>
			<span data-bind="text: $parent.isExpanded($data) ? '▲' : '▼'" style="font-size:80%;color:#aaa"></span>
		</div>

		<!-- ko if: $parent.isExpanded($data) -->
		<div style="padding:.6em .8em">

			<!-- Existing rules list -->
			<!-- ko foreach: $parent.rulesFor(id) -->
			<div style="display:flex;align-items:center;gap:.5em;padding:.35em 0;border-bottom:1px solid rgba(0,0,0,.06)">
				<div style="flex:1;font-size:90%">
					<strong data-bind="text: name"></strong>
					<!-- ko with: conditions[0] -->
					<span style="color:#666"
					      data-bind="text: ' — ' + field + ' ' + op + ' \'' + value + '\''"></span>
					<!-- /ko -->
					<span style="color:#888" data-bind="text: ' → ' + (actions[0] ? actions[0].type + (actions[0].params && actions[0].params.folder ? ' → ' + actions[0].params.folder : '') : '')"></span>
					<!-- ko if: last_run -->
					<span style="font-size:80%;color:#aaa" data-bind="text: ' (last run: ' + last_run + ')'"></span>
					<!-- /ko -->
				</div>
				<!-- ko if: enabled -->
				<span style="padding:1px 6px;background:#4caf50;color:white;border-radius:3px;font-size:78%">ON</span>
				<!-- /ko -->
				<!-- ko ifnot: enabled -->
				<span style="padding:1px 6px;background:#9e9e9e;color:white;border-radius:3px;font-size:78%">OFF</span>
				<!-- /ko -->
				<button class="btn" style="font-size:80%;padding:2px 8px"
				        data-bind="click: $parents[1].toggleRule.bind($parents[1], $parent, $data),
				                   text: enabled ? 'Disable' : 'Enable'"></button>
				<button class="btn" style="font-size:80%;padding:2px 8px;background:#c33;color:white"
				        data-bind="click: $parents[1].deleteRule.bind($parents[1], $parent, $data)">Delete</button>
			</div>
			<!-- /ko -->

			<!-- Add rule form trigger -->
			<!-- ko ifnot: $parent.addingFor() === id -->
			<div style="margin-top:.6em;display:flex;gap:.5em;align-items:center">
				<button class="btn" style="font-size:85%"
				        data-bind="click: $parent.startAdd.bind($parent, $data)">
					<i class="icon-plus"></i> Add rule
				</button>
				<button class="btn" style="font-size:85%;background:#4a90e2;color:white"
				        data-bind="click: $parent.runRules.bind($parent, $data)">
					&#9654; Run rules now
				</button>
			</div>
			<!-- /ko -->

			<!-- Run-rules report -->
			<!-- ko if: $parent.runReport().length -->
			<pre style="margin-top:.5em;font-size:82%;color:#555;white-space:pre-wrap;background:rgba(0,0,0,.03);padding:.5em;border-radius:4px"
			     data-bind="text: $parent.runReport()"></pre>
			<!-- /ko -->

			<!-- Add rule form -->
			<!-- ko if: $parent.addingFor() === id -->
			<div style="margin-top:.8em;padding:.8em;border:1px solid #4a90e2;border-radius:6px">
				<h5 style="margin:0 0 .6em">New message rule</h5>

				<label style="display:block;font-size:85%;margin-bottom:.2em">Rule name</label>
				<input type="text" data-bind="value: $parent.draft.name"
				       placeholder="e.g. Move newsletters" style="width:100%;margin-bottom:.5em" />

				<label style="display:block;font-size:85%;margin-bottom:.2em">Condition</label>
				<div style="display:flex;gap:.4em;margin-bottom:.5em;flex-wrap:wrap">
					<select data-bind="value: $parent.draft.condField" style="flex:1;min-width:80px">
						<option value="from">From</option>
						<option value="subject">Subject</option>
						<option value="to">To</option>
					</select>
					<select data-bind="value: $parent.draft.condOp" style="flex:1;min-width:100px">
						<option value="contains">contains</option>
						<option value="not_contains">not contains</option>
						<option value="equals">equals</option>
					</select>
					<input type="text" data-bind="value: $parent.draft.condValue"
					       placeholder="value" style="flex:2;min-width:120px" />
				</div>

				<label style="display:block;font-size:85%;margin-bottom:.2em">Logic (when multiple conditions apply)</label>
				<select data-bind="value: $parent.draft.condLogic" style="margin-bottom:.5em">
					<option value="all">All conditions (AND)</option>
					<option value="any">Any condition (OR)</option>
				</select>

				<label style="display:block;font-size:85%;margin-bottom:.2em">Action</label>
				<div style="display:flex;gap:.4em;margin-bottom:.5em;flex-wrap:wrap">
					<select data-bind="value: $parent.draft.actionType" style="flex:1;min-width:100px">
						<option value="move">Move to folder</option>
						<option value="read">Mark as read</option>
						<option value="flag">Flag message</option>
						<option value="delete">Delete</option>
					</select>
					<!-- ko if: $parent.draft.actionType() === 'move' -->
					<input type="text" data-bind="value: $parent.draft.actionFolder"
					       placeholder="Target folder (e.g. Newsletters)"
					       style="flex:2;min-width:140px" />
					<!-- /ko -->
				</div>

				<div style="margin-top:.7em;display:flex;gap:.5em">
					<button class="btn" style="background:#4a90e2;color:white"
					        data-bind="click: $parent.saveRule.bind($parent, $data)">Save rule</button>
					<button class="btn" data-bind="click: $parent.cancelAdd.bind($parent)">Cancel</button>
				</div>
			</div>
			<!-- /ko -->

		</div>
		<!-- /ko -->
	</div>
	<!-- /ko -->

	<div data-bind="text: status, visible: status().length"
	     style="margin-top:.5em;font-size:88%;color:#c55"></div>
</div>`;
		document.head.appendChild(script);
	}

	rl.addSettingsViewModel(
		FrickmailRulesSettings,
		'FrickmailRulesSettings',
		'Rules',
		'frickmail-rules'
	);

})(window.rl);
