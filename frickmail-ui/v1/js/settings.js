// Frickmail v1 settings screen (Phase 9).
//
// Generic preference editor over the v1 `GET`/`PUT /preferences` shape: each
// preference renders by value type (checkbox for booleans, number input for
// numbers, text otherwise), so new server schema keys need no client change.
// Keys and values pass through the shared `escapeHtml`; `collectPatch`
// reads the live DOM back into a patch object. All pure helpers except the
// thin `loadPreferences`/`savePreferences` I/O wrappers are unit-tested.

import { escapeHtml } from './mailbox.js';

/// Renders one preference control. Pure.
export function renderPreferenceRow(key, value) {
	const safeKey = escapeHtml(key);
	if (typeof value === 'boolean') {
		return (
			'<label data-fm="row"><input type="checkbox" data-fm="field"'
			+ ' data-key="' + safeKey + '"' + (value ? ' checked' : '') + ' />'
			+ '<span>' + safeKey + '</span></label>'
		);
	}
	if (typeof value === 'number' && Number.isFinite(value)) {
		return (
			'<label data-fm="row">' + safeKey
			+ '<input type="number" data-fm="field" data-key="' + safeKey + '"'
			+ ' value="' + value + '" /></label>'
		);
	}
	return (
		'<label data-fm="row">' + safeKey
		+ '<input type="text" data-fm="field" data-key="' + safeKey + '"'
		+ ' value="' + escapeHtml(value) + '" /></label>'
	);
}

/// Renders the whole preferences form. Pure.
export function renderPreferencesForm(preferences) {
	const entries = preferences && typeof preferences === 'object' && !Array.isArray(preferences)
		? Object.entries(preferences)
		: [];
	if (!entries.length) {
		return '<p data-fm="empty">No preferences available.</p>';
	}
	return (
		'<form data-fm="prefs">'
		+ entries.map(([key, value]) => renderPreferenceRow(key, value)).join('')
		+ '<div class="actions"><button type="submit" data-fm="save">Save</button></div>'
		+ '<div class="status" data-fm="status" role="status"></div>'
		+ '</form>'
	);
}

/// Reads edited values back from a rendered form root. Pure DOM read.
export function collectPreferencesPatch(root) {
	const patch = {};
	for (const field of root.querySelectorAll('[data-fm="field"]')) {
		const key = field.getAttribute('data-key');
		if (!key) {
			continue;
		}
		if (field.type === 'checkbox') {
			patch[key] = field.checked;
		} else if (field.type === 'number') {
			const raw = field.value;
			const numeric = Number(raw);
			patch[key] = raw === '' || !Number.isFinite(numeric) ? null : numeric;
		} else {
			patch[key] = field.value;
		}
	}
	return patch;
}

/// Loads preferences through the client. Thin I/O wrapper.
export async function loadPreferences(api) {
	return api.request('GET', '/preferences');
}

/// Saves a patch through the client. Thin I/O wrapper.
export async function savePreferences(api, preferences) {
	return api.request('PUT', '/preferences', { body: { preferences } });
}
