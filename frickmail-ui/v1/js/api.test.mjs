// Unit tests for the v1 API client (Phase 9). Run with:
//   node --test frickmail-ui/v1/js/
// No DOM, no network, no dependencies: the client takes an injected fetch.

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import { ApiClient, ApiError, API_PREFIX, API_VERSION, loginPayload, parseApiBody } from './api.js';

function jsonResponse(status, body) {
	return {
		status,
		json: async () => body
	};
}

describe('parseApiBody', () => {
	it('returns data on success envelopes', () => {
		assert.deepEqual(parseApiBody({ version: 'v1', data: { a: 1 } }, 200), { a: 1 });
	});

	it('throws ApiError on error envelopes', () => {
		assert.throws(
			() => parseApiBody({ version: 'v1', error: { code: 'nope', message: 'No.' } }, 404),
			(error) => error instanceof ApiError
				&& error.status === 404
				&& error.code === 'nope'
				&& error.message === 'No.'
		);
	});

	it('throws unknown_error on malformed bodies', () => {
		assert.throws(() => parseApiBody(null, 500), /Request failed/);
		assert.throws(() => parseApiBody({ version: 'v1' }, 200), /Request failed/);
		try {
			parseApiBody({ version: 'v1' }, 200);
			assert.fail('must throw');
		} catch (error) {
			assert.equal(error.code, 'unknown_error');
			assert.equal(error.status, 200);
		}
	});
});

describe('loginPayload', () => {
	it('omits empty two-factor codes', () => {
		assert.deepEqual(loginPayload('u', 'p'), { username: 'u', password: 'p' });
		assert.deepEqual(loginPayload('u', 'p', ''), { username: 'u', password: 'p' });
		assert.deepEqual(
			loginPayload('u', 'p', '123456'),
			{ username: 'u', password: 'p', totp_code: '123456' }
		);
	});
});

describe('ApiClient', () => {
	it('bootstraps the CSRF token and echoes it on login', async () => {
		const seen = [];
		const client = new ApiClient('', async (path, init) => {
			seen.push({ path, init });
			if (path === `${API_PREFIX}/session`) {
				return jsonResponse(200, { version: API_VERSION, data: { authenticated: false, csrf_token: '0-abc' } });
			}
			return jsonResponse(200, { version: API_VERSION, data: { authenticated: true } });
		});

		await client.bootstrap();
		assert.equal(client.token, '0-abc');
		await client.login('u', 'p');
		assert.equal(seen[1].init.headers['X-SM-Token'], '0-abc');
		assert.equal(seen[1].init.method, 'POST');
	});

	it('maps failure envelopes to ApiError codes', async () => {
		const client = new ApiClient('', async () => jsonResponse(
			401,
			{ version: API_VERSION, error: { code: 'invalid_credentials', message: 'Invalid username or password' } }
		));
		await assert.rejects(client.login('u', 'wrong'), (error) => error.code === 'invalid_credentials');
	});

	it('clears the token on logout', async () => {
		const client = new ApiClient('', async () => jsonResponse(
			200,
			{ version: API_VERSION, data: { logged_out: true } }
		));
		client.token = '0-abc';
	 await client.logout();
		assert.equal(client.token, '');
	});

	it('skips empty query values', async () => {
		let seenPath = '';
		const client = new ApiClient('', async (path) => {
			seenPath = path;
			return jsonResponse(200, { version: API_VERSION, data: {} });
		});
		await client.request('GET', '/messages', { query: { folder: 'INBOX', search: '' } });
		assert.equal(seenPath, `${API_PREFIX}/messages?folder=INBOX`);
	});

	it('sends absolute URLs when constructed with an origin', async () => {
		let seenPath = '';
		const client = new ApiClient('https://mail.example.com', async (path) => {
			seenPath = path;
			return jsonResponse(200, { version: API_VERSION, data: {} });
		});
		await client.request('GET', '/health');
		assert.equal(seenPath, `https://mail.example.com${API_PREFIX}/health`);
	});
});
