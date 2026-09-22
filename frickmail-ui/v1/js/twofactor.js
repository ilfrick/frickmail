// Frickmail v1 two-factor screen section (Phase 9).
//
// Pure rendering over the v1 `/security/totp` shapes plus thin loaders.
// The QR data URL and otpauth URI come from the server and are embedded
// verbatim (data: URLs the server generated); all other strings pass
// through the shared `escapeHtml`. The pending secret itself is never
// rendered — only the QR image and the manual-entry secret the user must
// scan or type. All pure helpers are unit-tested.

import { escapeHtml } from './mailbox.js';

/// Renders the status block: current state plus the enable/disable entry
/// point. Pure.
export function renderTotpStatus(enabled) {
	const on = !!enabled;
	return '<div data-fm="totp-status">'
		+ '<p>Two-factor authentication is <strong>' + (on ? 'on' : 'off') + '</strong>.</p>'
		+ (on
			? '<form data-fm="totp-disable">'
				+ '<label>Code <input data-fm="code" inputmode="numeric" autocomplete="one-time-code"></label>'
				+ '<button type="submit">Disable</button>'
				+ '</form>'
			: '<button type="button" data-fm="totp-start">Enable</button>')
		+ '</div>';
}

/// Renders the enrollment form from a setup response: QR image, manual
/// secret, and the confirmation code field. Pure.
export function renderTotpSetup(setup) {
	const current = setup || {};
	const qr = current.qr_data_url ? String(current.qr_data_url) : '';
	const secret = escapeHtml(current.secret ? String(current.secret) : '');
	const uri = escapeHtml(current.otpauth_uri ? String(current.otpauth_uri) : '');
	return '<form data-fm="totp-confirm">'
		+ '<p>Scan the code with your authenticator app, then enter a code to confirm.</p>'
		+ (qr ? '<img data-fm="qr" src="' + qr + '" alt="Two-factor QR code">' : '')
		+ '<p data-fm="secret">Manual entry: <code>' + secret + '</code></p>'
		+ '<p data-fm="uri">' + uri + '</p>'
		+ '<label>Code <input data-fm="code" inputmode="numeric" autocomplete="one-time-code"></label>'
		+ '<button type="submit">Confirm</button>'
		+ '</form>';
}

/// Reads a code field out of a form root. Pure DOM read.
export function collectTotpCode(root) {
	const field = root.querySelector('[data-fm="code"]');
	return field ? field.value : '';
}

/// Loads two-factor status through the client. Thin I/O wrapper.
export async function loadTotpStatus(api) {
	return api.request('GET', '/security/totp');
}

/// Starts enrollment through the client. Thin I/O wrapper.
export async function startTotpSetup(api) {
	return api.request('POST', '/security/totp/setup');
}

/// Confirms enrollment with a live code. Thin I/O wrapper.
export async function confirmTotp(api, code) {
	return api.request('POST', '/security/totp/confirm', { body: { code } });
}

/// Disables two-factor with a live code. Thin I/O wrapper.
export async function disableTotp(api, code) {
	return api.request('POST', '/security/totp/disable', { body: { code } });
}
