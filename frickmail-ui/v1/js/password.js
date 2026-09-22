// Frickmail v1 password-change form (Phase 9).
//
// Pure rendering plus a thin loader over `POST /security/password`.
// Password values are never rendered back (no prefill); the form only
// collects. All pure helpers are unit-tested.

/// Renders the password change form. Pure.
export function renderPasswordForm() {
	return '<form data-fm="password-form">'
		+ '<h2 data-fm="subtitle">Change password</h2>'
		+ '<p data-fm="hint">Changing the password signs you out everywhere; sign in again afterwards.</p>'
		+ '<label>Current password <input type="password" data-fm="current" autocomplete="current-password"></label>'
		+ '<label>New password <input type="password" data-fm="new" autocomplete="new-password"></label>'
		+ '<button type="submit">Change password</button>'
		+ '</form>';
}

/// Reads the form into a `POST /security/password` payload. Takes a
/// stub-able root like the other collectors. Pure.
export function collectPasswordPayload(root) {
	const read = (selector) => {
		const field = root.querySelector(selector);
		return field ? field.value : '';
	};
	return {
		current_password: read('[data-fm="current"]'),
		new_password: read('[data-fm="new"]')
	};
}

/// Changes the password through the client. Thin I/O wrapper.
export async function changePassword(api, payload) {
	return api.request('POST', '/security/password', { body: payload });
}
