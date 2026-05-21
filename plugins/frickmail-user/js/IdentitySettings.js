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

	rl.addSettingsViewModel(
		FrickmailIdentitySettings,
		'FrickmailIdentitySettings',
		'Identities',
		'frickmail-identities'
	);

})(window.rl);
