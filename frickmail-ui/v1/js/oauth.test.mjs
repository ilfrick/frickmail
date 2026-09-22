// Unit tests for the v1 OAuth sign-in (Phase 9). Run with:
//   node --test "frickmail-ui/v1/js/*.test.mjs"

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import {
	isAuthenticatedSession,
	loadProviders,
	openProviderPopup,
	popupFeatures,
	renderProviderButton,
	renderProviderButtons,
	watchPopupClose
} from './oauth.js';

describe('renderProviderButton', () => {
	it('renders label and url with escaping', () => {
		const html = renderProviderButton({ id: 'gmail', label: 'Google', url: '/?StartLoginGMail' });
		assert.ok(html.includes('data-id="gmail"'));
		assert.ok(html.includes('data-url="/?StartLoginGMail"'));
		assert.ok(html.includes('Sign in with Google'));
	});

	it('escapes hostile fields', () => {
		const html = renderProviderButton({ id: 'x"y', label: '<b>', url: '/?a"b' });
		assert.ok(!html.includes('<b>'));
		assert.ok(html.includes('&lt;b&gt;'));
		assert.ok(html.includes('data-id="x&quot;y"'));
	});
});

describe('renderProviderButtons', () => {
	it('renders nothing without providers', () => {
		assert.equal(renderProviderButtons({ providers: [] }), '');
		assert.equal(renderProviderButtons(null), '');
	});

	it('renders every provider exactly once', () => {
		const html = renderProviderButtons({
			providers: [
				{ id: 'gmail', label: 'Google', url: '/?StartLoginGMail' },
				{ id: 'oidc', label: 'SSO', url: '/?StartLoginOIDC' }
			]
		});
		assert.equal((html.match(/data-fm="oauth"/g) || []).length, 2);
	});
});

describe('isAuthenticatedSession', () => {
	it('detects authenticated sessions only', () => {
		assert.equal(isAuthenticatedSession({ authenticated: true }), true);
		assert.equal(isAuthenticatedSession({ authenticated: false }), false);
		assert.equal(isAuthenticatedSession(null), false);
		assert.equal(isAuthenticatedSession({}), false);
	});
});

describe('popupFeatures', () => {
	it('centers a 520x640 popup', () => {
		assert.equal(
			popupFeatures(1520, 1080),
			'popup=yes,width=520,height=640,left=500,top=220'
		);
	});

	it('clamps to zero on tiny screens', () => {
		assert.ok(popupFeatures(0, 0).includes('left=0'));
		assert.ok(popupFeatures(null, null).includes('top=0'));
	});
});

describe('openProviderPopup', () => {
	it('opens with the feature string', () => {
		let seen = null;
		const popup = {};
		const win = {
			open: (url, name, features) => {
				seen = { url, name, features };
				return popup;
			},
			screen: { availWidth: 1520, availHeight: 1080 }
		};
		assert.equal(openProviderPopup(win, '/?StartLoginGMail'), popup);
		assert.equal(seen.url, '/?StartLoginGMail');
		assert.equal(seen.name, 'frickmail-oauth');
		assert.ok(seen.features.includes('width=520'));
	});

	it('returns null without window open', () => {
		assert.equal(openProviderPopup(null, '/?x'), null);
		assert.equal(openProviderPopup({}, '/?x'), null);
	});

	it('returns null when open throws', () => {
		const win = {
			open: () => { throw new Error('blocked'); },
			screen: {}
		};
		assert.equal(openProviderPopup(win, '/?x'), null);
	});
});

describe('watchPopupClose', () => {
	const stubClock = () => {
		let callback = null;
		return {
			callback: () => callback,
			setInterval: (fn) => {
				callback = fn;
				return 1;
			},
			clearInterval: () => {
				callback = null;
			}
		};
	};

	it('calls done once the popup closes', () => {
		const clock = stubClock();
		let calls = 0;
		let closed = false;
		watchPopupClose({}, () => closed, () => {
			calls += 1;
		}, clock, 10);
		clock.callback()();
		assert.equal(calls, 0);
		closed = true;
		clock.callback()();
		assert.equal(calls, 1);
	});

	it('treats check errors as closed', () => {
		const clock = stubClock();
		let calls = 0;
		watchPopupClose({}, () => {
			throw new Error('gone');
		}, () => {
			calls += 1;
		}, clock, 10);
		clock.callback()();
		assert.equal(calls, 1);
	});
});

describe('loadProviders', () => {
	it('fetches the provider list', async () => {
		let seen = null;
		const api = { request: async (method, path, options) => { seen = { method, path, options }; return null; } };
		await loadProviders(api);
		assert.deepEqual(seen, { method: 'GET', path: '/oauth/providers', options: undefined });
	});
});
