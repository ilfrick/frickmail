// Unit tests for the v1 two-factor section (Phase 9). Run with:
//   node --test "frickmail-ui/v1/js/*.test.mjs"

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import {
	collectTotpCode,
	confirmTotp,
	disableTotp,
	loadTotpStatus,
	renderTotpSetup,
	renderTotpStatus,
	startTotpSetup
} from './twofactor.js';

describe('renderTotpStatus', () => {
	it('shows the off state with an enable entry', () => {
		const html = renderTotpStatus(false);
		assert.ok(html.includes('<strong>off</strong>'));
		assert.ok(html.includes('data-fm="totp-start"'));
		assert.ok(!html.includes('data-fm="totp-disable"'));
	});

	it('shows the on state with a disable form', () => {
		const html = renderTotpStatus(true);
		assert.ok(html.includes('<strong>on</strong>'));
		assert.ok(html.includes('data-fm="totp-disable"'));
		assert.ok(html.includes('data-fm="code"'));
	});
});

describe('renderTotpSetup', () => {
	it('embeds the QR image and manual secret', () => {
		const html = renderTotpSetup({
			secret: 'JBSW Y3DP',
			otpauth_uri: 'otpauth://totp/x?a=1&b=2',
			qr_data_url: 'data:image/svg+xml;base64,QUJD'
		});
		assert.ok(html.includes('src="data:image/svg+xml;base64,QUJD"'));
		assert.ok(html.includes('JBSW Y3DP'));
		assert.ok(html.includes('otpauth://totp/x?a=1&amp;b=2'));
		assert.ok(html.includes('data-fm="totp-confirm"'));
	});

	it('tolerates missing material', () => {
		const html = renderTotpSetup(null);
		assert.ok(html.includes('data-fm="totp-confirm"'));
		assert.ok(!html.includes('<img'));
	});
});

describe('collectTotpCode', () => {
	it('reads the code field', () => {
		assert.equal(
			collectTotpCode({ querySelector: () => ({ value: '123456' }) }),
			'123456'
		);
	});

	it('defaults without the field', () => {
		assert.equal(collectTotpCode({ querySelector: () => null }), '');
	});
});

describe('loaders', () => {
	const stubApi = () => {
		let seen = null;
		const api = {
			request: async (method, path, options) => {
				seen = { method, path, options };
				return null;
			}
		};
		return { api, seen: () => seen };
	};

	it('loadTotpStatus reads status', async () => {
		const { api, seen } = stubApi();
		await loadTotpStatus(api);
		assert.deepEqual(seen(), { method: 'GET', path: '/security/totp', options: undefined });
	});

	it('startTotpSetup posts', async () => {
		const { api, seen } = stubApi();
		await startTotpSetup(api);
		assert.deepEqual(seen(), {
			method: 'POST',
			path: '/security/totp/setup',
			options: undefined
		});
	});

	it('confirmTotp posts the code', async () => {
		const { api, seen } = stubApi();
		await confirmTotp(api, '123456');
		assert.deepEqual(seen(), {
			method: 'POST',
			path: '/security/totp/confirm',
			options: { body: { code: '123456' } }
		});
	});

	it('disableTotp posts the code', async () => {
		const { api, seen } = stubApi();
		await disableTotp(api, '123456');
		assert.deepEqual(seen(), {
			method: 'POST',
			path: '/security/totp/disable',
			options: { body: { code: '123456' } }
		});
	});
});
