// Frickmail v1 mailbox list screen (Phase 9).
//
// Pure rendering over the v1 `GET /messages` shape: every user-controlled
// string passes through `escapeHtml`, so message subjects/senders can never
// become markup. `renderMailbox` returns an HTML string the shell inserts in
// one assignment; all pure helpers are unit-tested under `node --test`.

/// Escapes the five HTML-significant characters. Pure.
export function escapeHtml(value) {
	return String(value === undefined || value === null ? '' : value).replace(
		/[&<>"']/g,
		(character) => {
			switch (character) {
				case '&':
					return '&amp;';
				case '<':
					return '&lt;';
				case '>':
					return '&gt;';
				case '"':
					return '&quot;';
				default:
					return '&#39;';
			}
		}
	);
}

/// Formats a unix timestamp (seconds) as a short local date/time. Pure;
/// invalid input renders as an empty string, never "Invalid Date".
export function formatTimestamp(timestamp) {
	const numeric = Number(timestamp);
	if (!Number.isFinite(numeric) || numeric <= 0) {
		return '';
	}
	try {
		return new Date(numeric * 1000).toLocaleString();
	} catch (error) {
		void error;
		return '';
	}
}

/// Renders one message row. Pure.
export function renderMessageRow(message) {
	const uid = Number(message && message.uid) || 0;
	const subject = escapeHtml(message && message.subject ? message.subject : '(no subject)');
	const from = escapeHtml(message && message.from ? message.from : '');
	const date = escapeHtml(formatTimestamp(message && message.date_timestamp));
	const unread = message && message.flags && message.flags.indexOf('\\seen') === -1;
	return (
		'<li data-fm="message" data-uid="' + uid + '"' + (unread ? ' data-unseen="1"' : '') + '>'
		+ '<span data-fm="from">' + from + '</span>'
		+ '<span data-fm="subject">' + subject + '</span>'
		+ '<time data-fm="date">' + date + '</time>'
		+ '</li>'
	);
}

/// Renders the mailbox list for a `GET /messages` data payload. Pure.
export function renderMailbox(data) {
	const messages = data && Array.isArray(data.messages) ? data.messages : [];
	if (!messages.length) {
		return '<p data-fm="empty">No messages in this folder.</p>';
	}
	return '<ul data-fm="list">' + messages.map(renderMessageRow).join('') + '</ul>';
}

/// Loads one folder page through the client. Thin I/O wrapper; the client
/// carries auth and CSRF state.
export async function loadMailbox(api, folder, options) {
	const settings = options || {};
	const query = { folder };
	if (settings.accountId) {
		query.account_id = settings.accountId;
	}
	if (settings.limit) {
		query.limit = settings.limit;
	}
	if (settings.search) {
		query.search = settings.search;
	}
	return api.request('GET', '/messages', { query });
}
