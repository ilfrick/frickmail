// Frickmail v1 message-reading view (Phase 9).
//
// Pure rendering over the v1 `GET /messages/{uid}` shape (the legacy
// `Object/Message` value). Address collections and attachment metadata are
// escaped before concatenation; the HTML body itself arrives pre-sanitized
// from the server and is displayed in a sandboxed frame by the shell wiring
// below, never via innerHTML. All pure helpers are unit-tested.

import { escapeHtml, formatTimestamp } from './mailbox.js';

/// Formats one address entry of an email collection. Pure.
export function formatAddress(entry) {
	if (!entry || typeof entry !== 'object') {
		return '';
	}
	const email = typeof entry.email === 'string' ? entry.email : '';
	const name = typeof entry.name === 'string' && entry.name ? entry.name : '';
	if (name && email && name !== email) {
		return name + ' <' + email + '>';
	}
	return email || name;
}

/// Joins an address collection for display. Pure.
export function formatAddresses(collection) {
	if (!Array.isArray(collection)) {
		return '';
	}
	return collection
		.map(formatAddress)
		.filter((item) => item !== '')
		.join(', ');
}

/// Renders the message header block. Pure.
export function renderMessageHeader(message) {
	const subject = escapeHtml(message && message.subject ? message.subject : '(no subject)');
	const from = escapeHtml(formatAddresses(message && message.from));
	const to = escapeHtml(formatAddresses(message && message.to));
	const date = escapeHtml(formatTimestamp(message && (message.dateTimestamp || message.date_timestamp)));
	return (
		'<header data-fm="headers">'
		+ '<h2 data-fm="subject">' + subject + '</h2>'
		+ '<div data-fm="from">From: ' + from + '</div>'
		+ '<div data-fm="to">To: ' + to + '</div>'
		+ '<div data-fm="date">' + date + '</div>'
		+ '</header>'
	);
}

/// Renders the attachment list. Pure; download URLs stay server-relative.
export function renderAttachments(message) {
	const attachments = message && Array.isArray(message.attachments) ? message.attachments : [];
	if (!attachments.length) {
		return '';
	}
	const items = attachments
		.filter((item) => item && typeof item === 'object')
		.map((item) => {
			const name = escapeHtml(item.fileName || item.file_name || 'attachment');
			const size = Number(item.estimatedSize || item.estimated_size) || 0;
			const index = escapeHtml(item.mimeIndex || item.mime_index || '');
			return (
				'<li data-fm="attachment" data-index="' + index + '">'
				+ '<span data-fm="name">' + name + '</span>'
				+ '<span data-fm="size">' + size + '</span>'
				+ '</li>'
			);
		});
	return '<ul data-fm="attachments">' + items.join('') + '</ul>';
}

/// Selects the display body: server-sanitized HTML wins, plain text is the
/// fallback. Returns `{kind, body}`. Pure.
export function selectMessageBody(message) {
	if (message && typeof message.html === 'string' && message.html !== '') {
		return { kind: 'html', body: message.html };
	}
	if (message && typeof message.plain === 'string') {
		return { kind: 'plain', body: message.plain };
	}
	return { kind: 'empty', body: '' };
}

/// Loads one message through the client. Thin I/O wrapper.
export async function loadMessage(api, folder, uid, options) {
	const settings = options || {};
	const query = { folder };
	if (settings.accountId) {
		query.account_id = settings.accountId;
	}
	return api.request('GET', '/messages/' + Number(uid), { query });
}
