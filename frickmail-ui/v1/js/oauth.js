// Frickmail v1 OAuth/SSO sign-in (Phase 9).
//
// Provider buttons over the v1 `GET /oauth/providers` shape plus a small
// popup orchestration. The start URLs are same-origin part hooks served
// by the Rust server; the popup shares the browser cookie jar, so once
// it completes the opener only has to re-bootstrap the session. Popup
// DOM access stays in thin wrappers; completion predicates and rendering
// are pure and unit-tested.

import { escapeHtml } from './mailbox.js';

/// Loads provider entries through the client. Thin I/O wrapper.
export async function loadProviders(api) {
	return api.request('GET', '/oauth/providers');
}

/// Renders one provider button. Pure.
export function renderProviderButton(provider) {
	const id = escapeHtml(provider && provider.id ? String(provider.id) : '');
	const label = escapeHtml(provider && provider.label ? String(provider.label) : id || '(provider)');
	const url = escapeHtml(provider && provider.url ? String(provider.url) : '');
	return '<button type="button" data-fm="oauth" data-id="' + id + '" data-url="' + url + '">'
		+ 'Sign in with ' + label + '</button>';
}

/// Renders the provider button row for a `GET /oauth/providers` data
/// payload. Empty without providers. Pure.
export function renderProviderButtons(data) {
	const providers = data && Array.isArray(data.providers) ? data.providers : [];
	if (!providers.length) {
		return '';
	}
	return '<div data-fm="oauth-row">'
		+ providers.map(renderProviderButton).join('')
		+ '</div>';
}

/// Whether a bootstrapped session proves the popup flow completed. Pure.
export function isAuthenticatedSession(data) {
	return !!(data && data.authenticated);
}

/// Window features for the consent popup, centered at 520x640. Pure.
export function popupFeatures(screenWidth, screenHeight) {
	const width = 520;
	const height = 640;
	const left = Math.max(0, Math.round(((Number(screenWidth) || 0) - width) / 2));
	const top = Math.max(0, Math.round(((Number(screenHeight) || 0) - height) / 2));
	return 'popup=yes,width=' + width + ',height=' + height
		+ ',left=' + left + ',top=' + top;
}

/// Opens the provider start URL in a same-origin popup. Returns the popup
/// reference, or null when popups are blocked (callers fall back to full
/// navigation). Thin DOM wrapper.
export function openProviderPopup(win, url) {
	if (!win || typeof win.open !== 'function') {
		return null;
	}
	const features = popupFeatures(win.screen && win.screen.availWidth, win.screen && win.screen.availHeight);
	try {
		return win.open(url, 'frickmail-oauth', features);
	} catch (error) {
		void error;
		return null;
	}
}

/// Polls `isClosed()` until the popup closes, then calls `done`.
/// `clock` ({setInterval, clearInterval}) is injectable for tests; the
/// default is the global clock. Pure orchestration.
export function watchPopupClose(popup, isClosed, done, clock, intervalMs) {
	const timer = (clock || { setInterval, clearInterval });
	const every = Number(intervalMs) || 500;
	const handle = timer.setInterval(() => {
		let closed = true;
		try {
			closed = !!isClosed();
		} catch (error) {
			void error;
		}
		if (closed) {
			timer.clearInterval(handle);
			done();
		}
	}, every);
	return handle;
}

/// Full flow: open the popup, and when it closes re-bootstrap the session;
/// authenticated sessions continue into the app, anything else reports the
/// outcome through `onStatus`. Thin composition over the tested units.
export async function signInWithProvider(win, api, provider, onAuthenticated, onStatus) {
	const url = provider && provider.url ? String(provider.url) : '';
	if (!url) {
		return;
	}
	const popup = openProviderPopup(win, url);
	if (!popup) {
		// Popups blocked: navigate the main window; the server redirects
		// back into the app shell on completion.
		try {
			win.location = url;
		} catch (error) {
			void error;
		}
		return;
	}
	watchPopupClose(
		popup,
		() => popup.closed,
		async () => {
			try {
				const data = await api.bootstrap();
				if (isAuthenticatedSession(data)) {
					onAuthenticated(data);
					return;
				}
			} catch (error) {
				void error;
			}
			onStatus('Sign-in did not complete. Try again.');
		}
	);
}
