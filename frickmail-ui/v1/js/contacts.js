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
	const id = contact && contact.id ? String(contact.id) : '';
	return (
		'<li data-fm="contact">'
		+ '<span data-fm="name">' + display + '</span>'
		+ '<span data-fm="uid">' + uid + '</span>'
		+ (id ? ' <button type="button" data-fm="delete" data-id="' + escapeHtml(id) + '">Delete</button>' : '')
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

/// Renders the add-contact form. Pure.
export function renderContactForm() {
	return '<form data-fm="add">'
		+ '<h2 data-fm="subtitle">Add contact</h2>'
		+ '<label>Name <input data-fm="name"></label>'
		+ '<label>Email <input data-fm="email" type="email"></label>'
		+ '<button type="submit">Add contact</button>'
		+ '</form>';
}

/// Reads the add form into a `POST /contacts` payload. Takes a stub-able
/// root like the other collectors. Pure.
export function collectContactPayload(root) {
	const read = (selector) => {
		const field = root.querySelector(selector);
		return field ? field.value : '';
	};
	return {
		name: read('[data-fm="name"]'),
		email: read('[data-fm="email"]')
	};
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

/// Adds a contact through the client. Thin I/O wrapper.
export async function addContact(api, payload) {
	return api.request('POST', '/contacts', { body: payload });
}

/// Deletes a contact through the client. Thin I/O wrapper.
export async function deleteContact(api, id) {
	return api.request('DELETE', '/contacts/' + Number(id));
}

/// Removes duplicate contacts through the client. Thin I/O wrapper.
export async function deduplicateContacts(api) {
	return api.request('POST', '/contacts/deduplicate');
}
