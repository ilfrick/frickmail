// Frickmail v1 compose screen (Phase 9).
//
// Rendering of the compose form plus a thin send wrapper over `POST /send`.
// The markup is a small mail-client window: a title bar, labelled header rows
// (From/To/Cc/Bcc/Subject), the body, and a footer action bar, rather than the
// generic stacked settings form it started as. Field values are escaped on
// render; submission reads the live DOM. All pure helpers are unit-tested.

import { escapeHtml } from './mailbox.js';

/// Renders the compose window, optionally seeded for replies/forwards.
/// `identities` feeds the sender select; without any, the account default
/// sends. `options.replyAll` reveals Cc/Bcc immediately (a reply-all usually
/// already has a Cc); `options.crypto` is pre-rendered OpenPGP markup spliced
/// in above the footer. Pure.
export function renderComposeForm(seed, identities, options) {
	const values = seed && typeof seed === 'object' ? seed : {};
	const settings = options || {};
	const text = (key) => escapeHtml(typeof values[key] === 'string' ? values[key] : '');
	const optionsHtml = (identities || []).map((identity) => {
		const id = identity && identity.id ? String(identity.id) : '';
		const name = identity && identity.name ? String(identity.name) : '';
		const email = identity && identity.email ? String(identity.email) : '';
		const label = escapeHtml((name ? name + ' ' : '') + '<' + email + '>');
		return '<option value="' + escapeHtml(id) + '">' + label + '</option>';
	}).join('');
	const row = (label, field, labelAttrs) =>
		'<label' + (labelAttrs || '') + '>'
		+ '<span data-fm="field-label">' + label + '</span>'
		+ field
		+ '</label>';
	const title = typeof values.title === 'string' && values.title ? values.title : 'New message';
	const reveal = settings.replyAll || text('cc') !== '' || text('bcc') !== '' ? '' : ' hidden';
	return (
		'<form data-fm="compose">'
		+ '<div data-fm="compose-head">'
		+ '<span data-fm="compose-title">' + escapeHtml(title) + '</span>'
		+ '<span data-fm="spacer"></span>'
		+ '<button type="button" data-fm="compose-toggle">Cc / Bcc</button>'
		+ '</div>'
		+ '<div data-fm="compose-fields">'
		+ (optionsHtml
			? row('From', '<select data-fm="identity"><option value="">Account default</option>' + optionsHtml + '</select>')
			: '')
		+ row('To', '<input type="text" data-fm="to" value="' + text('to') + '" required />')
		+ row('Cc', '<input type="text" data-fm="cc" value="' + text('cc') + '" />', ' data-fm-row="cc"' + reveal)
		+ row('Bcc', '<input type="text" data-fm="bcc" value="' + text('bcc') + '" />', ' data-fm-row="cc"' + reveal)
		+ row('Subject', '<input type="text" data-fm="subject" value="' + text('subject') + '" />')
		+ '</div>'
		+ '<textarea data-fm="compose-body" rows="14" placeholder="Write your message…">' + text('body') + '</textarea>'
		+ (typeof settings.crypto === 'string' ? settings.crypto : '')
		+ '<div data-fm="compose-foot">'
		+ '<button type="submit" data-fm="send">Send</button>'
		+ '<span data-fm="spacer"></span>'
		+ '<span data-fm="status" role="status"></span>'
		+ '</div>'
		+ '</form>'
	);
}

/// Reads a compose form root into a send payload. Empty Cc/Bcc are omitted so
/// the server does not treat them as present-but-blank. Pure DOM read.
export function collectComposePayload(root) {
	const read = (selector) => {
		const field = root.querySelector(selector);
		return field ? field.value : '';
	};
	const payload = {
		to: read('[data-fm="to"]'),
		subject: read('[data-fm="subject"]'),
		text: read('[data-fm="compose-body"]')
	};
	const cc = read('[data-fm="cc"]').trim();
	if (cc) {
		payload.cc = cc;
	}
	const bcc = read('[data-fm="bcc"]').trim();
	if (bcc) {
		payload.bcc = bcc;
	}
	const identity = read('[data-fm="identity"]');
	if (identity) {
		payload.identity_id = Number(identity);
	}
	return payload;
}

/// Wires the Cc/Bcc reveal toggle on a rendered compose window. Thin DOM
/// helper; the actual reveal is a `hidden` attribute flip. Returns the toggle
/// button (or null when absent).
export function wireComposeToggle(root) {
	const button = root && root.querySelector ? root.querySelector('[data-fm="compose-toggle"]') : null;
	if (!button) {
		return null;
	}
	button.addEventListener('click', () => {
		for (const row of root.querySelectorAll('[data-fm-row="cc"]')) {
			row.hidden = !row.hidden;
		}
	});
	return button;
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
