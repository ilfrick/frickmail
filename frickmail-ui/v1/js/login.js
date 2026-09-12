// Frickmail v1 login screen (Phase 9).
//
// Vanilla DOM wiring over the api.js client: renders the sign-in form into
// a root element, submits to POST /login, reveals the two-factor step when
// the server answers `requires_totp`, and reports failures inline. Exported
// `renderLogin`/`describeAuthFailure` stay DOM-pure at the edges so the
// failure copy is unit-testable without a browser.

import { ApiClient } from './api.js';

/// Human-readable copy for login outcomes. Pure: fully unit-tested.
export function describeAuthFailure(data, error) {
	if (data && data.requires_totp) {
		return 'Two-factor authentication required.';
	}
	if (error && error.code === 'invalid_token') {
		return 'Session expired. Reload and try again.';
	}
	if (error && error.code === 'invalid_credentials') {
		return 'Invalid username or password.';
	}
	if (error && error.message) {
		return error.message;
	}
	return 'Sign-in failed. Try again.';
}

function setStatus(root, text) {
	const status = root.querySelector('[data-fm="status"]');
	if (status) {
		status.textContent = text || '';
	}
}

/// Renders the login form into `root` and wires it to `api`.
/// `onAuthenticated(data)` fires once the server confirms the session.
export function renderLogin(root, api, onAuthenticated) {
	const client = api || new ApiClient('');
	root.innerHTML = ''
		+ '<h1 data-fm="title">Sign in to Frickmail</h1>'
		+ '<form data-fm="form">'
		+ '<label for="fm-username">Username</label>'
		+ '<input id="fm-username" data-fm="username" type="text" autocomplete="username" required />'
		+ '<label for="fm-password">Password</label>'
		+ '<input id="fm-password" data-fm="password" type="password"'
		+ ' autocomplete="current-password" required minlength="8" />'
		+ '<div data-fm="totp-row" hidden>'
		+ '<label for="fm-totp">Two-factor code</label>'
		+ '<input id="fm-totp" data-fm="totp" type="text" inputmode="numeric"'
		+ ' autocomplete="one-time-code" maxlength="8" />'
		+ '</div>'
		+ '<div class="actions"><button type="submit" data-fm="submit">Sign in</button></div>'
		+ '<div class="status" data-fm="status" role="status"></div>'
		+ '</form>';

	const form = root.querySelector('[data-fm="form"]');
	form.addEventListener('submit', async (event) => {
		event.preventDefault();
		const username = root.querySelector('[data-fm="username"]').value;
		const password = root.querySelector('[data-fm="password"]').value;
		const totpRow = root.querySelector('[data-fm="totp-row"]');
		const totpCode = totpRow.hidden
			? undefined
			: root.querySelector('[data-fm="totp"]').value;
		setStatus(root, '');
		try {
			const data = await client.login(username, password, totpCode);
			if (data && data.authenticated) {
				onAuthenticated(data);
				return;
			}
			if (data && data.requires_totp) {
				totpRow.hidden = false;
				setStatus(root, describeAuthFailure(data, null));
				return;
			}
			setStatus(root, describeAuthFailure(data, null));
		} catch (error) {
			setStatus(root, describeAuthFailure(null, error));
		}
	});
}
