// Frickmail v1 folders screen (Phase 9).
//
// Pure rendering over the v1 `GET /folders` shape (the legacy folder
// collection value). Folder names pass through the shared `escapeHtml`;
// counts are numeric-coerced. All pure helpers are unit-tested.

import { escapeHtml } from './mailbox.js';

/// Renders one folder row. Pure.
export function renderFolderRow(folder, selected) {
	const name = escapeHtml(folder && folder.name ? folder.name : '(unnamed folder)');
	const fullName = folder && typeof folder.full_name === 'string' ? folder.full_name : '';
	const unread = Number(folder && folder.unread_emails) || 0;
	const total = Number(folder && folder.total_emails) || 0;
	const isSelected = fullName !== '' && fullName === selected;
	return (
		'<li data-fm="folder" data-name="' + escapeHtml(fullName) + '"'
		+ (isSelected ? ' data-current="1"' : '') + '>'
		+ '<span data-fm="folder-name">' + name + '</span>'
		+ '<span data-fm="counts">' + unread + '/' + total + '</span>'
		+ '</li>'
	);
}

/// Renders the folder list for a `GET /folders` data payload. Pure.
export function renderFolderList(data, selected) {
	const folders = data && Array.isArray(data.folders) ? data.folders : [];
	if (!folders.length) {
		return '<p data-fm="empty">No folders.</p>';
	}
	return (
		'<ul data-fm="folders">'
		+ folders.map((folder) => renderFolderRow(folder, selected)).join('')
		+ '</ul>'
	);
}

/// Loads folders through the client. Thin I/O wrapper.
export async function loadFolders(api, options) {
	const settings = options || {};
	const query = {};
	if (settings.accountId) {
		query.account_id = settings.accountId;
	}
	return api.request('GET', '/folders', { query });
}
