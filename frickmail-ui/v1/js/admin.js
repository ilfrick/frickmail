// Frickmail v1 admin screens (Phase 4/9).
//
// Vanilla DOM wiring over the api.js admin client: operator sign-in, domain
// templates (list/create/edit/disable/delete/alias), and curated runtime
// settings with database-vs-environment provenance. Rendering helpers are
// pure (string in, HTML out) and unit-tested; only the thin load/save
// wrappers touch the network, and form collectors take stubbable roots.

import { domainPayload } from './api.js';
import { escapeHtml } from './mailbox.js';

/// Human-readable copy for admin failures. Pure: fully unit-tested.
export function describeAdminFailure(error) {
	if (!error) {
		return 'Administration failed. Try again.';
	}
	switch (error.code) {
		case 'admin_disabled':
			return 'Operator authentication is not configured on this server.';
		case 'invalid_token':
			return 'Invalid operator token.';
		case 'admin_forbidden':
			return 'This session is not an operator session.';
		case 'unknown_setting':
			return 'Unknown setting. Reload and try again.';
		case 'domain_not_found':
			return 'Domain not found. It may have been deleted.';
		case 'setting_not_overridden':
			return 'That setting already follows the server default.';
		case 'invalid_request':
			return error.message || 'Invalid request. Check the fields and try again.';
		default:
			return error.message || 'Administration failed. Try again.';
	}
}

/// Renders the operator sign-in form. Pure.
export function renderAdminLogin() {
	return (
		'<h1 data-fm="title">Frickmail administration</h1>'
		+ '<form data-fm="form">'
		+ '<label for="fm-token">Operator token</label>'
		+ '<input id="fm-token" data-fm="token" type="password"'
		+ ' autocomplete="current-password" required />'
		+ '<div class="actions"><button type="submit" data-fm="submit">Sign in</button></div>'
		+ '<div class="status" data-fm="status" role="status"></div>'
		+ '</form>'
	);
}

/// Renders one domain table row. Pure.
export function renderDomainRow(domain) {
	const source = domain && typeof domain === 'object' ? domain : {};
	const name = escapeHtml(source.name || '');
	const state = source.alias_of
		? 'alias of ' + escapeHtml(source.alias_of)
		: (source.disabled ? 'disabled' : 'enabled');
	const imap = escapeHtml(source.imap_host || '—');
	const smtp = escapeHtml(source.smtp_host || '—');
	return (
		'<tr data-fm="domain-row" data-name="' + name + '">'
		+ '<td>' + name + '</td>'
		+ '<td>' + state + '</td>'
		+ '<td>' + imap + '</td>'
		+ '<td>' + smtp + '</td>'
		+ '<td>'
		+ '<button type="button" data-fm="domain-edit">Edit</button> '
		+ '<button type="button" data-fm="domain-toggle">'
		+ (source.disabled ? 'Enable' : 'Disable') + '</button> '
		+ '<button type="button" data-fm="domain-delete">Delete</button>'
		+ '</td>'
		+ '</tr>'
	);
}

/// Renders the domain list table. Pure.
export function renderDomainsTable(domains) {
	const rows = Array.isArray(domains) ? domains : [];
	if (!rows.length) {
		return '<p data-fm="empty">No mail domains configured.</p>';
	}
	return (
		'<table data-fm="domains">'
		+ '<thead><tr><th>Domain</th><th>State</th><th>IMAP</th><th>SMTP</th><th>Actions</th></tr></thead>'
		+ '<tbody>' + rows.map(renderDomainRow).join('') + '</tbody>'
		+ '</table>'
	);
}

/// Renders the domain create/edit form. Pure.
export function renderDomainEditor(domain) {
	const source = domain && typeof domain === 'object' ? domain : {};
	const field = (key, label, kind) => {
		const value = source[key] === undefined || source[key] === null ? '' : String(source[key]);
		return (
			'<label>' + label
			+ '<input data-fm="field" data-key="' + key + '" type="' + kind + '"'
			+ ' value="' + escapeHtml(value) + '" /></label>'
		);
	};
	return (
		'<form data-fm="domain-form">'
		+ '<h3 data-fm="editor-title">' + (source.name ? 'Edit ' + escapeHtml(source.name) : 'New domain') + '</h3>'
		+ field('name', 'Domain', 'text')
		+ field('imap_host', 'IMAP host', 'text')
		+ field('imap_port', 'IMAP port', 'number')
		+ field('imap_secure', 'IMAP security', 'text')
		+ field('smtp_host', 'SMTP host', 'text')
		+ field('smtp_port', 'SMTP port', 'number')
		+ field('smtp_secure', 'SMTP security', 'text')
		+ '<div class="actions"><button type="submit" data-fm="save">Save domain</button></div>'
		+ '<div class="status" data-fm="status" role="status"></div>'
		+ '</form>'
	);
}

/// Reads a rendered domain form back into a save payload. Pure DOM read.
export function collectDomainForm(root) {
	const raw = {};
	for (const field of root.querySelectorAll('[data-fm="field"]')) {
		const key = field.getAttribute('data-key');
		if (key) {
			raw[key] = field.value;
		}
	}
	return domainPayload(raw);
}

/// Renders the curated settings form with provenance badges. Pure.
export function renderSettingsForm(settings) {
	const entries = settings && typeof settings === 'object' && !Array.isArray(settings)
		? Object.entries(settings)
		: [];
	if (!entries.length) {
		return '<p data-fm="empty">No settings available.</p>';
	}
	return (
		'<form data-fm="settings-form">'
		+ entries.map(([key, entry]) => {
			const value = entry && typeof entry === 'object' ? entry.value : undefined;
			const source = entry && typeof entry === 'object' ? entry.source : 'environment';
			const safeKey = escapeHtml(key);
			const badge = ' <span data-fm="source">(' + escapeHtml(String(source)) + ')</span>';
			if (typeof value === 'boolean') {
				return (
					'<label data-fm="row"><input type="checkbox" data-fm="field"'
					+ ' data-key="' + safeKey + '"' + (value ? ' checked' : '') + ' />'
					+ '<span>' + safeKey + badge + '</span></label>'
				);
			}
			return (
				'<label data-fm="row">' + safeKey + badge
				+ '<input type="number" data-fm="field" data-key="' + safeKey + '"'
				+ ' value="' + (typeof value === 'number' ? value : '') + '" /></label>'
			);
		}).join('')
		+ '<div class="actions"><button type="submit" data-fm="save">Save settings</button></div>'
		+ '<div class="status" data-fm="status" role="status"></div>'
		+ '</form>'
	);
}

/// Reads edited settings back; numbers that do not parse stay raw strings
/// so the server rejects them with a 400 instead of silently coercing.
/// Pure DOM read.
export function collectSettingsPatch(root) {
	const patch = {};
	for (const field of root.querySelectorAll('[data-fm="field"]')) {
		const key = field.getAttribute('data-key');
		if (!key) {
			continue;
		}
		if (field.type === 'checkbox') {
			patch[key] = field.checked;
		} else if (field.type === 'number') {
			const numeric = Number(field.value);
			patch[key] = field.value === '' || !Number.isFinite(numeric) ? field.value : numeric;
		} else {
			patch[key] = field.value;
		}
	}
	return patch;
}

/// Loads everything the dashboard needs. Thin I/O wrapper.
export async function loadAdminDashboard(api) {
	const [domains, settings] = await Promise.all([api.listDomains(), api.getSettings()]);
	return {
		domains: domains && Array.isArray(domains.domains) ? domains.domains : [],
		settings: settings && settings.settings && typeof settings.settings === 'object'
			? settings.settings
			: {}
	};
}

/// Renders the dashboard shell; sections re-render after each mutation.
/// `handlers` wires buttons (kept out for unit-testable purity).
export function renderAdminDashboard(data) {
	const source = data && typeof data === 'object' ? data : {};
	return (
		'<h1 data-fm="title">Frickmail administration</h1>'
		+ '<div data-fm="actions"><button type="button" data-fm="logout">Sign out</button></div>'
		+ '<section data-fm="domains-section"><h2>Mail domains</h2>'
		+ '<div data-fm="domains-wrap">' + renderDomainsTable(source.domains) + '</div>'
		+ '<div class="actions"><button type="button" data-fm="domain-new">New domain</button></div>'
		+ '<div data-fm="editor-wrap"></div>'
		+ '<form data-fm="alias-form"><h3>Domain alias</h3>'
		+ '<label>Domain<input data-fm="alias-name" type="text" /></label>'
		+ '<label>Alias<input data-fm="alias-value" type="text" /></label>'
		+ '<div class="actions"><button type="submit" data-fm="alias-save">Save alias</button></div>'
		+ '</form>'
		+ '<div class="status" data-fm="status" role="status"></div>'
		+ '</section>'
		+ '<section data-fm="settings-section"><h2>Runtime settings</h2>'
		+ '<div data-fm="settings-wrap">' + renderSettingsForm(source.settings) + '</div>'
		+ '</section>'
	);
}
