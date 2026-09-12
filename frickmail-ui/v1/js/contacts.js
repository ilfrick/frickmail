// Frickmail v1 contacts screen (Phase 9).
//
// Pure rendering over the v1 `GET /contacts` shape plus a thin loader.
// Contact display names pass through the shared `escapeHtml`. All pure
// helpers are unit-tested.

import { escapeHtml } from './mailbox.js';

/// Renders one contact row. Pure.
export function renderContactRow(contact) {
	const display = escapeHtml(contact && contact.display ? contact.display : '(unnamed contact)');
	const uid = escapeHtml(contact && contact.uid ? contact.uid : '');
	return (
		'<li data-fm="contact">'
		+ '<span data-fm="name">' + display + '</span>'
		+ '<span data-fm="uid">' + uid + '</span>'
		+ '</li>'
	);
}

/// Renders the contact list for a `GET /contacts` data payload. Pure.
export function renderContacts(data) {
	const contacts = data && Array.isArray(data.contacts) ? data.contacts : [];
	if (!contacts.length) {
		return '<p data-fm="empty">No contacts.</p>';
	}
	return '<ul data-fm="contacts">' + contacts.map(renderContactRow).join('') + '</ul>';
}

/// Loads contacts through the client. Thin I/O wrapper.
export async function loadContacts(api, options) {
	const settings = options || {};
	const query = {};
	if (settings.limit) {
		query.limit = settings.limit;
	}
	return api.request('GET', '/contacts', { query });
}
