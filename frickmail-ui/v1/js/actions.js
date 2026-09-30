// Frickmail v1 message and folder actions (mailbox toolbar + reading-pane
// toolbar).
//
// Two responsibilities, kept separate:
//   * pure renderers for the toolbars, the folder picker and the reply /
//     forward seeds — every server-provided string is escaped here, so a
//     folder name or subject can never become markup;
//   * thin I/O wrappers over the v1 action routes, so the shell wiring in
//     `index.html` only deals with clicks and refreshes.
//
// The action routes themselves reuse the native legacy `MessageSet*`,
// `MessageMove`, `MessageCopy`, `MessageDelete`, `MessageSetSeenToAll` and
// `FolderClear` pipelines, so the IMAP semantics are the same ones the
// legacy UI had.

import { escapeHtml } from './mailbox.js';
import { formatAddresses } from './message.js';

/// Candidate folder names for the one-click actions, in preference order.
/// Matches are case-insensitive and prefix-tolerant, because servers spell
/// these `Junk`, `Spam`, `[Gmail]/Spam`, `Archive` and so on.
const SPAM_NAMES = ['junk', 'spam', 'bulk mail', 'bulk'];
const ARCHIVE_NAMES = ['archive', 'archives'];
const TRASH_NAMES = ['trash', 'deleted', 'deleted items', 'bin'];

/// Normalizes a folder name for the special-folder lookups: trimmed,
/// lowercased, and stripped of a leading `[Provider]/` prefix so
/// `[Gmail]/Spam` still matches `Spam`. Pure.
function normalizeFolderName(name) {
	return String(name || '')
		.trim()
		.toLowerCase()
		.replace(/^\[[^\]]*\]\//, '')
		.trim();
}

/// Returns the full name of the first folder matching one of `names`, or an
/// empty string. `folders` is a `GET /folders` data payload. Pure.
export function findSpecialFolder(folders, names) {
	const list = folders && Array.isArray(folders.folders) ? folders.folders : [];
	const wanted = (names || []).map(normalizeFolderName);
	for (const folder of list) {
		if (!folder || typeof folder.full_name !== 'string' || folder.full_name === '') {
			continue;
		}
		if (wanted.indexOf(normalizeFolderName(folder.full_name)) !== -1) {
			return folder.full_name;
		}
	}
	return '';
}

/// Renders the destination `<select>` for Move/Copy: every folder except the
/// one the message is in. Returns an empty string when there is nowhere to
/// move to, so the caller can hide the buttons. Pure.
export function renderFolderTargets(folders, current) {
	const list = folders && Array.isArray(folders.folders) ? folders.folders : [];
	const options = list
		.filter((folder) => folder && typeof folder.full_name === 'string' && folder.full_name !== '')
		.filter((folder) => folder.full_name !== current)
		.map((folder) => {
			const name = folder.name || folder.full_name;
			const unread = Number(folder.unread_emails) || 0;
			const label = unread > 0 ? name + ' (' + unread + ')' : name;
			return (
				'<option value="' + escapeHtml(folder.full_name) + '">'
				+ escapeHtml(label)
				+ '</option>'
			);
		})
		.join('');
	return options === '' ? '' : '<select data-fm="target" aria-label="Destination folder">' + options + '</select>';
}

/// Renders the reading-pane toolbar for one open message. `context` is
/// `{folder, folders, message}`. Pure: only `data-*` attributes and escaped
/// labels cross the boundary, and the actual routing happens in the shell.
export function renderMessageToolbar(context) {
	const settings = context || {};
	const message = settings.message || {};
	const folder = typeof settings.folder === 'string' ? settings.folder : '';
	const flags = Array.isArray(message.flags) ? message.flags : [];
	const starred = flags.indexOf('\\flagged') !== -1;
	const targets = renderFolderTargets(settings.folders, folder);
	const spam = findSpecialFolder(settings.folders, SPAM_NAMES);
	const archive = findSpecialFolder(settings.folders, ARCHIVE_NAMES);
	const parts = [
		'<div data-fm="toolbar" role="toolbar" aria-label="Message actions">',
		'<button type="button" data-fm="action" data-action="reply">Reply</button>',
		'<button type="button" data-fm="action" data-action="reply-all">Reply all</button>',
		'<button type="button" data-fm="action" data-action="forward">Forward</button>',
		'<span data-fm="spacer"></span>',
		'<button type="button" data-fm="action" data-action="flag">'
			+ (starred ? 'Unstar' : 'Star')
			+ '</button>',
		'<button type="button" data-fm="action" data-action="unread">Mark unread</button>'
	];
	if (targets !== '') {
		parts.push(
			targets,
			'<button type="button" data-fm="action" data-action="move">Move</button>',
			'<button type="button" data-fm="action" data-action="copy">Copy</button>'
		);
	}
	if (archive !== '' && archive !== folder) {
		parts.push('<button type="button" data-fm="action" data-action="archive">Archive</button>');
	}
	if (spam !== '' && spam !== folder) {
		parts.push('<button type="button" data-fm="action" data-action="spam">Spam</button>');
	}
	parts.push(
		'<button type="button" data-fm="action" data-action="delete">Delete</button>',
		'<span data-fm="status" role="status"></span>',
		'</div>'
	);
	return parts.join('');
}

/// Renders the toolbar above the message list: the folder being shown, its
/// unread count, and the folder-level actions. `context` is
/// `{folder, folders, folderData}`. Emptying is offered only for the trash,
/// because emptying an arbitrary folder is destructive and easy to misclick.
/// Pure.
export function renderFolderToolbar(context) {
	const settings = context || {};
	const folder = typeof settings.folder === 'string' ? settings.folder : '';
	const folderData = settings.folderData || {};
	const unread = Number(folderData.unread_emails) || 0;
	const trash = findSpecialFolder(settings.folders, TRASH_NAMES);
	const parts = [
		'<div data-fm="folder-toolbar">',
		'<strong data-fm="current-folder">' + escapeHtml(folder) + '</strong>',
		'<span data-fm="unread-count">' + (unread > 0 ? unread + ' unread' : '') + '</span>',
		'<span data-fm="spacer"></span>',
		'<button type="button" data-fm="action" data-action="seen-all">Mark all read</button>'
	];
	if (trash !== '' && trash === folder) {
		parts.push('<button type="button" data-fm="action" data-action="empty">Empty folder</button>');
	}
	parts.push(
		'<button type="button" data-fm="action" data-action="refresh">Refresh</button>',
		'<span data-fm="status" role="status"></span>',
		'</div>'
	);
	return parts.join('');
}

/// Quotes a plain-text body for a reply, prefixing each line with `> `.
/// Pure.
function quoteBody(text) {
	const source = typeof text === 'string' ? text : '';
	if (source.trim() === '') {
		return '';
	}
	return source
		.split('\n')
		.map((line) => '> ' + line)
		.join('\n');
}

/// The plain-text body of a message, preferring `plain` and falling back to
/// a placeholder when only HTML is available (the HTML itself is not pasted
/// into a reply, because the sanitizer may have rewritten it). Pure.
function replySource(message) {
	if (message && typeof message.plain === 'string' && message.plain !== '') {
		return message.plain;
	}
	return '[This message has no plain-text part.]';
}

/// Subject for a reply, without stacking `Re:` prefixes. Pure.
function replySubject(subject) {
	const text = typeof subject === 'string' ? subject.trim() : '';
	if (text === '') {
		return 'Re:';
	}
	return /^re:/i.test(text) ? text : 'Re: ' + text;
}

/// Subject for a forward, without stacking `Fwd:` prefixes. Pure.
function forwardSubject(subject) {
	const text = typeof subject === 'string' ? subject.trim() : '';
	if (text === '') {
		return 'Fwd:';
	}
	return /^fwd?:/i.test(text) ? text : 'Fwd: ' + text;
}

/// Builds the compose seed for `reply`, `reply-all` or `forward`. Any other
/// mode returns an empty seed. Pure.
export function buildActionSeed(message, mode) {
	const source = message || {};
	if (mode !== 'reply' && mode !== 'reply-all' && mode !== 'forward') {
		return {};
	}
	const from = formatAddresses(source.from);
	const cc = formatAddresses(source.cc);
	if (mode === 'forward') {
		return {
			to: '',
			subject: forwardSubject(source.subject),
			body: replySource(source)
		};
	}
	const recipients = mode === 'reply' ? from : [from, cc].filter((item) => item !== '').join(', ');
	return {
		to: recipients,
		subject: replySubject(source.subject),
		body: replySource(source) === '' ? '' : '\n\n' + quoteBody(replySource(source))
	};
}

/// Extracts a human-readable message from a failed client request, so the
/// toolbar can report the real reason instead of a generic failure. Pure.
export function actionErrorMessage(error, fallback) {
	if (error && typeof error.message === 'string' && error.message.trim() !== '') {
		return error.message;
	}
	return typeof fallback === 'string' && fallback !== '' ? fallback : 'Action failed.';
}

/// Stores or clears one flag on a set of messages. `payload` is
/// `{folder, uids, flag, set}`. Thin I/O wrapper.
export async function setMessageFlag(api, payload) {
	return api.request('POST', '/messages/flags', { body: payload });
}

/// Moves messages to `toFolder`. Thin I/O wrapper.
export async function moveMessages(api, payload) {
	return api.request('POST', '/messages/move', { body: payload });
}

/// Copies messages to `toFolder`. Thin I/O wrapper.
export async function copyMessages(api, payload) {
	return api.request('POST', '/messages/copy', { body: payload });
}

/// Deletes messages outright. Thin I/O wrapper.
export async function deleteMessages(api, payload) {
	return api.request('POST', '/messages/delete', { body: payload });
}

/// Marks every message in a folder as read. Thin I/O wrapper.
export async function markFolderRead(api, payload) {
	return api.request('POST', '/messages/seen-all', { body: payload });
}

/// Empties a folder. Thin I/O wrapper.
export async function clearFolder(api, payload) {
	return api.request('POST', '/folders/clear', { body: payload });
}
