// Frickmail v1 rules screen (Phase 9).
//
// Pure rendering over the v1 `GET /rules` shape plus thin loaders/actions.
// Rule names pass through the shared `escapeHtml`; enablement renders as a
// marker. The row exposes an enable/disable toggle and a delete button wired
// by the shell; the add form collects a name (conditions/actions editing is a
// follow-up — the API accepts full payloads). All pure helpers are unit-tested.

import { escapeHtml } from './mailbox.js';

/// Renders one rule row. Pure.
export function renderRuleRow(rule) {
	const id = Number(rule && rule.id) || 0;
	const name = escapeHtml(rule && rule.name ? rule.name : '(unnamed rule)');
	const enabled = !!(rule && rule.enabled);
	return (
		'<li data-fm="rule" data-id="' + id + '" data-enabled="' + (enabled ? '1' : '0') + '">'
		+ '<span data-fm="state">' + (enabled ? '●' : '○') + '</span>'
		+ '<span data-fm="name">' + name + '</span>'
		+ '<button type="button" data-fm="toggle" data-id="' + id + '">' + (enabled ? 'Disable' : 'Enable') + '</button>'
		+ '<button type="button" data-fm="delete" data-id="' + id + '">Delete</button>'
		+ '</li>'
	);
}

/// Renders the rule list for a `GET /rules` data payload. Pure.
export function renderRules(data) {
	const rules = data && Array.isArray(data.rules) ? data.rules : [];
	if (!rules.length) {
		return '<p data-fm="empty">No filter rules.</p>';
	}
	return '<ul data-fm="rules">' + rules.map(renderRuleRow).join('') + '</ul>';
}

/// Renders the add-rule form (name only for now). Pure.
export function renderRuleForm() {
	return '<form data-fm="add">'
		+ '<label>Rule name <input data-fm="name" required></label>'
		+ '<button type="submit">Add rule</button>'
		+ '</form>';
}

/// Reads the add form into a `POST /rules` payload fragment. The caller
/// supplies `account_id`. Takes a stub-able root. Pure.
export function collectRulePayload(root, accountId) {
	const field = root && root.querySelector ? root.querySelector('[data-fm="name"]') : null;
	return { name: field ? field.value : '', account_id: Number(accountId) || 0 };
}

/// Loads rules through the client. Thin I/O wrapper.
export async function loadRules(api, options) {
	const settings = options || {};
	const query = {};
	if (settings.accountId) {
		query.account_id = settings.accountId;
	}
	return api.request('GET', '/rules', { query });
}

/// Adds a rule through the client. Thin I/O wrapper.
export async function addRule(api, payload) {
	return api.request('POST', '/rules', { body: payload });
}

/// Enables/disables a rule through the client. Thin I/O wrapper.
export async function toggleRule(api, id, enabled) {
	return api.request('POST', '/rules/' + Number(id) + '/toggle', { body: { enabled: !!enabled } });
}

/// Deletes a rule through the client. Thin I/O wrapper.
export async function deleteRule(api, id) {
	return api.request('DELETE', '/rules/' + Number(id));
}