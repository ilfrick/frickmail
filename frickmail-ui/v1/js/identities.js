// Frickmail v1 sender identities management (Phase 9).
//
// Pure rendering over the v1 `GET /identities` shape plus thin loaders and
// actions (create/delete/set-default reuse the exact v1 endpoints). All
// identity text passes through the shared `escapeHtml`; collectors take a
// stub-able root. Tests are in identities.test.mjs.

import { escapeHtml } from './mailbox.js';

/// Renders one identity row. Pure.
export function renderIdentityRow(identity) {
	const id = Number(identity && identity.id) || 0;
	const name = escapeHtml(identity && identity.name ? identity.name : '(unnamed identity)');
	const email = escapeHtml(identity && identity.email ? identity.email : '');
	const replyTo = escapeHtml(identity && identity.reply_to ? identity.reply_to : '');
	const isDefault = !!(identity && identity.is_default);
	const buttons = (id ? ' <button type="button" data-fm="default" data-id="' + id + '">'
		+ (isDefault ? 'Default' : 'Set default') + '</button>'
		+ ' <button type="button" data-fm="delete" data-id="' + id + '">Delete</button>' : '');
	return (
		'<li data-fm="identity" data-id="' + id + '"' + (isDefault ? ' data-default="1"' : '') + '>'
		+ '<span data-fm="name">' + name + '</span>'
		+ ' <span data-fm="email">' + email + '</span>'
		+ (replyTo ? ' <span data-fm="reply">reply-to: ' + replyTo + '</span>' : '')
		+ buttons
		+ '</li>'
	);
}

/// Renders the identity list for a `GET /identities` data payload. Pure.
export function renderIdentities(data) {
	const identities = data && Array.isArray(data.identities) ? data.identities : [];
	if (!identities.length) {
		return '<p data-fm="empty">No sender identities.</p>';
	}
	return '<ul data-fm="identities">' + identities.map(renderIdentityRow).join('') + '</ul>';
}

/// Renders the add-identity form. Pure.
export function renderIdentityForm() {
	return '<form data-fm="add">'
		+ '<label>Name <input data-fm="name"></label> '
		+ '<label>Email <input data-fm="email" type="email"></label> '
		+ '<label>Reply-to <input data-fm="reply" type="email"></label> '
		+ '<button type="submit">Add identity</button>'
		+ '</form>';
}

/// Reads the add form into a `POST /identities` payload. Takes a stub-able
/// root. Pure.
export function collectIdentityPayload(root, accountId) {
	const read = (selector) => {
		const field = root && root.querySelector ? root.querySelector(selector) : null;
		return field ? field.value : '';
	};
	const replyTo = read('[data-fm="reply"]').trim();
	const payload = {
		account_id: Number(accountId) || 0,
		name: read('[data-fm="name"]').trim(),
		email: read('[data-fm="email"]').trim()
	};
	if (replyTo) {
		payload.reply_to = replyTo;
	}
	return payload;
}

/// Loads a caller's identities through the client. Thin I/O wrapper.
export async function loadIdentities(api, accountId) {
	return api.request('GET', '/identities', { query: { account_id: Number(accountId) || 0 } });
}

/// Adds an identity through the client. Thin I/O wrapper.
export async function addIdentity(api, payload) {
	return api.request('POST', '/identities', { body: payload });
}

/// Sets an identity default through the client. Thin I/O wrapper.
export async function setDefaultIdentity(api, id) {
	return api.request('POST', '/identities/' + Number(id) + '/default');
}

/// Deletes an identity through the client. Thin I/O wrapper.
export async function deleteIdentity(api, id) {
	return api.request('DELETE', '/identities/' + Number(id));
}