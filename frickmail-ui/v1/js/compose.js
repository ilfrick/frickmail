// Frickmail v1 compose screen (Phase 9).
//
// Pure rendering of the compose form plus a thin send wrapper over
// `POST /send`. Field values are escaped on render; submission reads the
// live DOM. All pure helpers are unit-tested.

import { escapeHtml } from './mailbox.js';

/// Renders the compose form, optionally seeded for replies/forwards.
/// `identities` feeds the sender select; without any, the account default
/// sends. Pure.
export function renderComposeForm(seed, identities) {
	const values = seed && typeof seed === 'object' ? seed : {};
	const text = (key) => escapeHtml(typeof values[key] === 'string' ? values[key] : '');
	const options = (identities || []).map((identity) => {
		const id = identity && identity.id ? String(identity.id) : '';
		const name = identity && identity.name ? String(identity.name) : '';
		const email = identity && identity.email ? String(identity.email) : '';
		const label = escapeHtml((name ? name + ' ' : '') + '<' + email + '>');
		return '<option value="' + escapeHtml(id) + '">' + label + '</option>';
	}).join('');
	return (
		'<form data-fm="compose">'
		+ (options
			? '<label data-fm="row">From<select data-fm="identity"><option value="">Account default</option>'
				+ options + '</select></label>'
			: '')
		+ '<label data-fm="row">To'
		+ '<input type="text" data-fm="to" value="' + text('to') + '" required /></label>'
		+ '<label data-fm="row">Subject'
		+ '<input type="text" data-fm="subject" value="' + text('subject') + '" /></label>'
		+ '<label data-fm="row">Message'
		+ '<textarea data-fm="body" rows="10">' + text('body') + '</textarea></label>'
		+ '<div class="actions"><button type="submit" data-fm="send">Send</button></div>'
		+ '<div class="status" data-fm="status" role="status"></div>'
		+ '</form>'
	);
}

/// Reads a compose form root into a send payload. Pure DOM read.
export function collectComposePayload(root) {
	const read = (selector) => {
		const field = root.querySelector(selector);
		return field ? field.value : '';
	};
	const payload = {
		to: read('[data-fm="to"]'),
		subject: read('[data-fm="subject"]'),
		text: read('[data-fm="body"]')
	};
	const identity = read('[data-fm="identity"]');
	if (identity) {
		payload.identity_id = Number(identity);
	}
	return payload;
}

/// Loads sender identities for an account through the client. Thin I/O wrapper.
export async function loadIdentities(api, accountId) {
	const query = {};
	if (accountId !== undefined && accountId !== null && accountId !== '') {
		query.account_id = accountId;
	}
	return api.request('GET', '/identities', { query });
}

/// Sends a composed message through the client. Thin I/O wrapper.
export async function sendMessage(api, payload) {
	return api.request('POST', '/send', { body: payload });
}
