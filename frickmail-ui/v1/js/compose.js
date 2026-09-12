// Frickmail v1 compose screen (Phase 9).
//
// Pure rendering of the compose form plus a thin send wrapper over
// `POST /send`. Field values are escaped on render; submission reads the
// live DOM. All pure helpers are unit-tested.

import { escapeHtml } from './mailbox.js';

/// Renders the compose form, optionally seeded for replies/forwards. Pure.
export function renderComposeForm(seed) {
	const values = seed && typeof seed === 'object' ? seed : {};
	const text = (key) => escapeHtml(typeof values[key] === 'string' ? values[key] : '');
	return (
		'<form data-fm="compose">'
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
	return {
		to: read('[data-fm="to"]'),
		subject: read('[data-fm="subject"]'),
		text: read('[data-fm="body"]')
	};
}

/// Sends a composed message through the client. Thin I/O wrapper.
export async function sendMessage(api, payload) {
	return api.request('POST', '/send', { body: payload });
}
