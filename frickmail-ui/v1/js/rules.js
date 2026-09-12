// Frickmail v1 rules screen (Phase 9).
//
// Pure rendering over the v1 `GET /rules` shape plus a thin loader. Rule
// names pass through the shared `escapeHtml`; enablement renders as a
// read-only marker for now (toggling lands with a future rule-mutation
// endpoint). All pure helpers are unit-tested.

import { escapeHtml } from './mailbox.js';

/// Renders one rule row. Pure.
export function renderRuleRow(rule) {
	const name = escapeHtml(rule && rule.name ? rule.name : '(unnamed rule)');
	const enabled = !!(rule && rule.enabled);
	return (
		'<li data-fm="rule" data-enabled="' + (enabled ? '1' : '0') + '">'
		+ '<span data-fm="state">' + (enabled ? '●' : '○') + '</span>'
		+ '<span data-fm="name">' + name + '</span>'
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

/// Loads rules through the client. Thin I/O wrapper.
export async function loadRules(api, options) {
	const settings = options || {};
	const query = {};
	if (settings.accountId) {
		query.account_id = settings.accountId;
	}
	return api.request('GET', '/rules', { query });
}
