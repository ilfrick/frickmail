/**
 * IdentitySettings.js — Sender identities panel embedded in the
 * Mail Accounts settings tab.
 *
 * For every account returned by FrickmailListAccounts (which now includes
 * an `identities` array) we render a collapsible sub-section showing the
 * existing identities plus a form to add new ones.
 *
 * The panel is injected into the DOM after the account list rendered by
 * MailAccountsSettings, hooking into the `rl.addSettingsViewModel`
 * lifecycle via a separate view-model registered on the same tab element.
 */
(rl => { if (!rl) return;

	function escHtml(s) {
		return String(s ?? '')
			.replace(/&/g, '&amp;')
			.replace(/</g, '&lt;')
			.replace(/>/g, '&gt;')
			.replace(/"/g, '&quot;');
	}

	// ── Shared account store (populated by FrickmailListAccounts) ────────────
	// MailAccountsSettings already calls FrickmailListAccounts; we piggyback on
	// the same endpoint so we can read the identities array it now returns.

	class FrickmailIdentitySettings {
		constructor() {
			this.accounts    = ko.observableArray([]);
			this.expanded    = ko.observable(null);   // account id currently showing identities
			this.status      = ko.observable('');
			this.addingFor   = ko.observable(null);   // account id for which add-form is open
			this.draft = {
				name:       ko.observable(''),
				email:      ko.observable(''),
				replyTo:    ko.observable(''),
				isDefault:  ko.observable(false),
			};
		}

		onBuild() {
			this.refresh();
		}

		refresh() {
			window.rl.pluginRemoteRequest((iError, oData) => {
				const r = oData?.Result;
				if (!r?.ok) return;
				this.accounts(r.accounts || []);
			}, 'FrickmailListAccounts', {}, 30000);
		}

		toggle(account) {
			this.expanded(this.expanded() === account.id ? null : account.id);
			this.addingFor(null);
			this.clearDraft();
		}

		isExpanded(account) {
			return this.expanded() === account.id;
		}

		startAdd(account) {
			this.addingFor(account.id);
			this.clearDraft();
		}

		cancelAdd() {
			this.addingFor(null);
			this.clearDraft();
		}

		clearDraft() {
			this.draft.name('');
			this.draft.email('');
			this.draft.replyTo('');
			this.draft.isDefault(false);
		}

		saveIdentity(account) {
			const d = this.draft;
			const payload = {
				account_id: account.id,
				name:       d.name(),
				email:      d.email(),
				reply_to:   d.replyTo() || '',
				is_default: d.isDefault(),
			};
			if (!payload.name.trim()) { this.status('Name is required'); return; }
			if (!payload.email.trim()) { this.status('Email is required'); return; }
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
				this.refresh();
			}, 'FrickmailAddIdentity', payload, 30000);
		}

		setDefault(identity) {
			window.rl.pluginRemoteRequest((iError, oData) => {
				const r = oData?.Result;
				if (!r?.ok) { this.status('Set-default failed: ' + (r?.error || '?')); return; }
				this.status('');
				this.refresh();
			}, 'FrickmailSetDefaultIdentity', { id: identity.id }, 30000);
		}

		deleteIdentity(account, identity) {
			const identities = account.identities || [];
			if (identities.length <= 1) {
				this.status('Cannot delete the only identity for this account.');
				return;
			}
			if (!confirm('Delete identity ' + identity.email + '?')) return;
			window.rl.pluginRemoteRequest((iError, oData) => {
				const r = oData?.Result;
				if (!r?.ok) { this.status('Delete failed: ' + (r?.error || '?')); return; }
				this.status('');
				this.refresh();
			}, 'FrickmailDeleteIdentity', { id: identity.id }, 30000);
		}
	}

	// ── KO template rendered inline via custom binding ────────────────────────
	// We register a second view-model on the *same* tab as MailAccountsSettings.
	// SnappyMail's addSettingsViewModel appends the container div to the tab pane,
	// so both view-models coexist side by side.

	const TMPL_ID = 'frickmail-identity-tmpl';
	if (!document.getElementById(TMPL_ID)) {
		const script = document.createElement('script');
		script.id   = TMPL_ID;
		script.type = 'text/html';
		script.textContent = `
<div style="margin-top:1.5em">
	<div class="legend">Sender identities</div>
	<p style="font-size:88%;color:#888">
		Alias "From" addresses for each account.
		The <em>default</em> identity is pre-selected when composing new messages.
	</p>

	<!-- ko foreach: accounts -->
	<div style="border:1px solid #ddd;border-radius:6px;margin-bottom:.6em;overflow:hidden">
		<div style="display:flex;align-items:center;gap:.6em;padding:.5em .8em;background:rgba(0,0,0,.04);cursor:pointer"
		     data-bind="click: $parent.toggle.bind($parent, $data)">
			<strong data-bind="text: label || email"></strong>
			<span style="font-size:85%;color:#888" data-bind="text: email"></span>
			<span style="margin-left:auto;font-size:80%;color:#666"
			      data-bind="text: (identities && identities.length ? identities.length : 0) + ' identit' + ((identities && identities.length === 1) ? 'y' : 'ies')"></span>
			<span data-bind="text: $parent.isExpanded($data) ? '▲' : '▼'" style="font-size:80%;color:#aaa"></span>
		</div>

		<!-- ko if: $parent.isExpanded($data) -->
		<div style="padding:.6em .8em">

			<!-- Existing identities -->
			<!-- ko foreach: (identities || []) -->
			<div style="display:flex;align-items:center;gap:.5em;padding:.35em 0;border-bottom:1px solid rgba(0,0,0,.06)">
				<div style="flex:1;font-size:90%">
					<strong data-bind="text: name"></strong>
					<span style="color:#666" data-bind="text: ' &lt;' + email + '&gt;'"></span>
					<!-- ko if: reply_to -->
					<span style="font-size:85%;color:#999" data-bind="text: ' · Reply-To: ' + reply_to"></span>
					<!-- /ko -->
				</div>
				<!-- ko if: is_default -->
				<span style="padding:1px 6px;background:#4a90e2;color:white;border-radius:3px;font-size:78%">default</span>
				<!-- /ko -->
				<!-- ko ifnot: is_default -->
				<button class="btn" style="font-size:80%;padding:2px 8px"
				        data-bind="click: $parents[1].setDefault.bind($parents[1], $data)">Set default</button>
				<!-- /ko -->
				<button class="btn" style="font-size:80%;padding:2px 8px;background:#c33;color:white"
				        data-bind="click: $parents[1].deleteIdentity.bind($parents[1], $parent, $data)">Delete</button>
			</div>
			<!-- /ko -->

			<!-- Add new identity form -->
			<!-- ko ifnot: $parent.addingFor() === id -->
			<div style="margin-top:.6em">
				<button class="btn" style="font-size:85%"
				        data-bind="click: $parent.startAdd.bind($parent, $data)">
					<i class="icon-plus"></i> Add identity
				</button>
			</div>
			<!-- /ko -->

			<!-- ko if: $parent.addingFor() === id -->
			<div style="margin-top:.8em;padding:.8em;border:1px solid #4a90e2;border-radius:6px">
				<h5 style="margin:0 0 .6em">New sender identity</h5>
				<label style="display:block;font-size:85%;margin-bottom:.2em">Display name</label>
				<input type="text" data-bind="value: $parent.draft.name"
				       placeholder="Your Name" style="width:100%;margin-bottom:.5em" />
				<label style="display:block;font-size:85%;margin-bottom:.2em">Email address</label>
				<input type="email" data-bind="value: $parent.draft.email"
				       placeholder="alias@example.com" style="width:100%;margin-bottom:.5em" />
				<label style="display:block;font-size:85%;margin-bottom:.2em">Reply-To (optional)</label>
				<input type="email" data-bind="value: $parent.draft.replyTo"
				       placeholder="replies@example.com" style="width:100%;margin-bottom:.5em" />
				<label style="font-size:85%">
					<input type="checkbox" data-bind="checked: $parent.draft.isDefault" />
					Set as default
				</label>
				<div style="margin-top:.7em;display:flex;gap:.5em">
					<button class="btn" style="background:#4a90e2;color:white"
					        data-bind="click: $parent.saveIdentity.bind($parent, $data)">Save</button>
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
		FrickmailIdentitySettings,
		'FrickmailIdentitySettings',
		// Tab label — empty string keeps it on the same tab pane as Mail Accounts
		'',
		// Tab hash — same as MailAccountsSettings so it appends to the same panel
		'mail-accounts'
	);

})(window.rl);
