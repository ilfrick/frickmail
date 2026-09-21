// Frickmail v1 search and unified-inbox screens (Phase 9).
//
// Pure rendering over the v1 `GET /search` and `GET /unified-inbox`
// shapes plus thin loaders. Subjects, senders, and snippets pass through
// the shared `escapeHtml`; every string the server returns is untrusted
// index data. All pure helpers are unit-tested.

import { escapeHtml } from './mailbox.js';

/// Renders the search form with the current query. Pure.
export function renderSearchForm(query) {
	return '<form data-fm="search-form">'
		+ '<input data-fm="q" value="' + escapeHtml(query || '') + '" placeholder="Search mail…">'
		+ '<button type="submit">Search</button>'
		+ '</form>';
}

/// Sender display: name wins, address falls back. Pure.
export function senderDisplay(entry) {
	if (entry && entry.from_name) {
		return String(entry.from_name);
	}
	if (entry && entry.from_addr) {
		return String(entry.from_addr);
	}
	if (entry && entry.from) {
		return String(entry.from);
	}
	return '(unknown sender)';
}

/// Renders one search-result row. Pure.
export function renderSearchRow(result) {
	const subject = escapeHtml(result && result.subject ? result.subject : '(no subject)');
	const sender = escapeHtml(senderDisplay(result));
	const folder = escapeHtml(result && result.folder ? result.folder : '');
	const snippet = escapeHtml(result && result.snippet ? result.snippet : '');
	const account = Number(result && result.account_id) || 0;
	const uid = Number(result && result.imap_uid) || 0;
	return (
		'<li data-fm="result" data-account="' + account + '" data-uid="' + uid + '" data-folder="' + folder + '">'
		+ '<span data-fm="subject">' + subject + '</span>'
		+ '<span data-fm="sender">' + sender + '</span>'
		+ '<span data-fm="folder">' + folder + '</span>'
		+ '<span data-fm="snippet">' + snippet + '</span>'
		+ '</li>'
	);
}

/// Renders the result list for a `GET /search` data payload. Pure.
export function renderSearchResults(data) {
	const results = data && Array.isArray(data.results) ? data.results : [];
	if (!results.length) {
		return '<p data-fm="empty">No messages match.</p>';
	}
	return '<ul data-fm="results">' + results.map(renderSearchRow).join('') + '</ul>';
}

/// Renders one unified-inbox row, with the account badge and seen state.
/// Pure.
export function renderUnifiedRow(message) {
	const subject = escapeHtml(message && message.subject ? message.subject : '(no subject)');
	const sender = escapeHtml(senderDisplay(message));
	const account = escapeHtml(message && message.account_email ? message.account_email : '');
	const seen = !!(message && message.is_seen);
	const uid = Number(message && (message.uid || message.imap_uid)) || 0;
	const accountId = Number(message && message.account_id) || 0;
	return (
		'<li data-fm="unified" data-account="' + accountId + '" data-uid="' + uid + '"'
		+ (seen ? '' : ' data-unseen="1"') + '>'
		+ '<span data-fm="badge">' + account + '</span>'
		+ '<span data-fm="subject">' + subject + '</span>'
		+ '<span data-fm="sender">' + sender + '</span>'
		+ '</li>'
	);
}

/// Renders the list for a `GET /unified-inbox` data payload. Pure.
export function renderUnifiedInbox(data) {
	const messages = data && Array.isArray(data.messages) ? data.messages : [];
	if (!messages.length) {
		return '<p data-fm="empty">Unified inbox is empty.</p>';
	}
	return '<ul data-fm="unified">' + messages.map(renderUnifiedRow).join('') + '</ul>';
}

/// Runs a search through the client. Thin I/O wrapper.
export async function runSearch(api, options) {
	const settings = options || {};
	const query = {};
	if (settings.q) {
		query.q = settings.q;
	}
	if (settings.limit) {
		query.limit = settings.limit;
	}
	return api.request('GET', '/search', { query });
}

/// Loads the unified inbox through the client. Thin I/O wrapper.
export async function loadUnifiedInbox(api, options) {
	const settings = options || {};
	const query = {};
	if (settings.limit) {
		query.limit = settings.limit;
	}
	return api.request('GET', '/unified-inbox', { query });
}
