// Frickmail v1 message-reading view (Phase 9).
//
// Pure rendering over the v1 `GET /messages/{uid}` shape (the legacy
// `Object/Message` value). Address collections and attachment metadata are
// escaped before concatenation; the HTML body itself arrives pre-sanitized
// from the server and is displayed in a sandboxed frame by the shell wiring
// below, never via innerHTML. All pure helpers are unit-tested.

import { escapeHtml, formatTimestamp } from './mailbox.js';
import { attachmentUrl } from './reader.js';

/// Formats a byte count for an attachment chip. Pure.
export function formatFileSize(bytes) {
	const size = Number(bytes);
	if (!Number.isFinite(size) || size <= 0) {
		return '';
	}
	if (size < 1024) {
		return size + ' B';
	}
	if (size < 1024 * 1024) {
		return (size / 1024).toFixed(size < 10 * 1024 ? 1 : 0) + ' KB';
	}
	return (size / 1024 / 1024).toFixed(1) + ' MB';
}

/// A short badge for an attachment card: the file extension when there is
/// one, else a generic label. Pure.
export function attachmentBadge(name) {
	const text = String(name || '');
	const dot = text.lastIndexOf('.');
	if (dot > 0 && dot < text.length - 1) {
		return escapeHtml(text.slice(dot + 1).slice(0, 4).toUpperCase());
	}
	return 'FILE';
}

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

/// First letter (or initials) of an address for the sender chip. Pure.
export function senderInitials(message) {
	const first = message && Array.isArray(message.from) ? message.from[0] : null;
	const name = first && typeof first === 'object'
		? (first.name || first.email || '')
		: '';
	const text = String(name).replace(/[^A-Za-z0-9 ]/g, ' ').trim();
	if (!text) {
		return '?';
	}
	const words = text.split(/\s+/).filter(Boolean);
	if (words.length === 1) {
		return words[0].slice(0, 2).toUpperCase();
	}
	return (words[0][0] + words[words.length - 1][0]).toUpperCase();
}

/// Renders the message header block. Pure.
export function renderMessageHeader(message) {
	const subject = escapeHtml(message && message.subject ? message.subject : '(no subject)');
	const from = escapeHtml(formatAddresses(message && message.from));
	const to = escapeHtml(formatAddresses(message && message.to));
	const date = escapeHtml(formatTimestamp(message && (message.dateTimestamp || message.date_timestamp)));
	const initials = escapeHtml(senderInitials(message));
	return (
		'<header data-fm="headers">'
		+ '<h2 data-fm="subject">' + subject + '</h2>'
		+ '<div data-fm="from"><span data-fm="sender-chip">' + initials + '</span>From: ' + from + '</div>'
		+ '<div data-fm="to">To: ' + to + '</div>'
		+ '<div data-fm="date">' + date + '</div>'
		+ '</header>'
	);
}

/// Renders the attachment list as cards with a real download link. Pure; the
/// URL is built from the v1 attachment endpoint using the message context, and
/// the name is escaped before it reaches the markup.
export function renderAttachments(message, context) {
	const attachments = message && Array.isArray(message.attachments) ? message.attachments : [];
	const settings = context || {};
	const items = attachments
		.filter((item) => item && typeof item === 'object')
		.map((item) => {
			const rawName = item.fileName || item.file_name || 'attachment';
			const name = escapeHtml(rawName);
			const size = formatFileSize(item.estimatedSize || item.estimated_size);
			const href = escapeHtml(attachmentUrl(item, settings, { inline: false }));
			return (
				'<li data-fm="attachment">'
				+ '<span data-fm="attachment-icon">' + attachmentBadge(rawName) + '</span>'
				+ '<span data-fm="attachment-meta">'
				+ '<span data-fm="name">' + name + '</span>'
				+ (size ? '<span data-fm="size">' + escapeHtml(size) + '</span>' : '')
				+ '</span>'
				+ '<a data-fm="download" href="' + href + '" download>Download</a>'
				+ '</li>'
			);
		});
	if (!items.length) {
		return '';
	}
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
