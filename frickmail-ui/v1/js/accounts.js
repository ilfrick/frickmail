// Frickmail v1 mail-accounts screen (Phase 9).
//
// Pure rendering over the v1 `GET /accounts` shape plus thin loaders.
// Account rows carry no secrets by server contract (listings exclude
// encrypted material, verified by the API tests); everything rendered
// still passes through the shared `escapeHtml`. The editor covers the
// common IMAP fields; OAuth-linked accounts keep working because an
// empty password preserves the stored secret server-side. All pure
// helpers are unit-tested.

import { escapeHtml } from './mailbox.js';

/// Renders one account row with primary marker and actions. Pure.
export function renderAccountRow(account) {
	const id = Number(account && account.id) || 0;
	const label = escapeHtml(account && account.label ? account.label : '');
	const email = escapeHtml(account && account.email ? account.email : '(unknown address)');
	const type = escapeHtml(account && account.type ? account.type : 'imap');
	const primary = !!(account && account.is_primary);
	return (
		'<li data-fm="account" data-id="' + id + '"' + (primary ? ' data-primary="1"' : '') + '>'
		+ '<span data-fm="email">' + email + '</span>'
		+ (label ? ' <span data-fm="label">(' + label + ')</span>' : '')
		+ ' <span data-fm="type">' + type + '</span>'
		+ (primary ? ' <span data-fm="primary">primary</span>' : '')
		+ ' <button type="button" data-fm="switch" data-id="' + id + '">Open</button>'
		+ ' <button type="button" data-fm="edit" data-id="' + id + '">Edit</button>'
		+ (primary ? '' : ' <button type="button" data-fm="make-primary" data-id="' + id + '">Make primary</button>')
		+ (primary ? '' : ' <button type="button" data-fm="delete" data-id="' + id + '">Delete</button>')
		+ '</li>'
	);
}

/// Renders the list for a `GET /accounts` data payload. Pure.
export function renderAccounts(data) {
	const accounts = data && Array.isArray(data.accounts) ? data.accounts : [];
	if (!accounts.length) {
		return '<p data-fm="empty">No mail accounts yet.</p>';
	}
	return '<ul data-fm="accounts">' + accounts.map(renderAccountRow).join('') + '</ul>';
}

/// Renders the account editor. Without an account it creates; with one it
/// edits (password left blank preserves the stored secret). Pure.
export function renderAccountEditor(account) {
	const current = account || {};
	const id = current.id ? String(current.id) : '';
	const text = (value) => escapeHtml(value ? String(value) : '');
	return '<form data-fm="editor">'
		+ '<input type="hidden" data-fm="id" value="' + escapeHtml(id) + '">'
		+ '<label>Label <input data-fm="label" value="' + text(current.label) + '"></label>'
		+ '<label>Email <input data-fm="email" value="' + text(current.email) + '"></label>'
		+ '<label>IMAP host <input data-fm="imap-host" value="' + text(current.imap_host) + '"></label>'
		+ '<label>IMAP login <input data-fm="login" value="' + text(current.login) + '"></label>'
		+ '<label>Password <input type="password" data-fm="password" placeholder="'
		+ (id ? 'leave blank to keep' : '') + '"></label>'
		+ '<label>SMTP host <input data-fm="smtp-host" value="' + text(current.smtp_host) + '"></label>'
		+ '<button type="submit" data-fm="save">' + (id ? 'Update account' : 'Add account') + '</button>'
		+ '</form>';
}

/// Reads the editor form back into an accounts payload. Takes a stub-able
/// root like the other collectors. Pure.
export function collectAccountPayload(root) {
	const read = (selector) => {
		const field = root.querySelector(selector);
		return field ? field.value : '';
	};
	const payload = {
		label: read('[data-fm="label"]'),
		email: read('[data-fm="email"]'),
		imap_host: read('[data-fm="imap-host"]'),
		login: read('[data-fm="login"]'),
		password: read('[data-fm="password"]'),
		smtp_host: read('[data-fm="smtp-host"]')
	};
	const id = read('[data-fm="id"]');
	if (id) {
		payload.id = id;
	}
	return payload;
}

/// Loads accounts through the client. Thin I/O wrapper.
export async function loadAccounts(api) {
	return api.request('GET', '/accounts');
}

/// Adds an account through the client. Thin I/O wrapper.
export async function addAccount(api, payload) {
	return api.request('POST', '/accounts', { body: payload });
}

/// Updates an account through the client. Thin I/O wrapper.
export async function updateAccount(api, id, payload) {
	return api.request('PUT', '/accounts/' + Number(id), { body: payload });
}

/// Deletes an account through the client. Thin I/O wrapper.
export async function deleteAccount(api, id) {
	return api.request('DELETE', '/accounts/' + Number(id));
}

/// Marks an account primary through the client. Thin I/O wrapper.
export async function setPrimaryAccount(api, id) {
	return api.request('POST', '/accounts/' + Number(id) + '/primary');
}

/// Switches the session to an account through the client. Thin I/O wrapper.
export async function switchAccount(api, id) {
	return api.request('POST', '/switch-account', { body: { account_id: Number(id) } });
}
