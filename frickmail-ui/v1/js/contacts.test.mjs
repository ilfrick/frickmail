// Unit tests for the v1 contacts screen (Phase 9). Run with:
//   node --test "frickmail-ui/v1/js/*.test.mjs"

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import { loadContacts, renderContacts, renderContactRow } from './contacts.js';

describe('renderContactRow', () => {
	it('escapes display names', () => {
		const html = renderContactRow({ display: '<b>Ada</b>', uid: 'manual:1' });
		assert.ok(!html.includes('<b>'));
		assert.ok(html.includes('&lt;b&gt;Ada&lt;/b&gt;'));
		assert.ok(html.includes('manual:1'));
	});

	it('falls back on missing fields', () => {
		const html = renderContactRow({});
		assert.ok(html.includes('(unnamed contact)'));
	});
});

describe('renderContacts', () => {
	it('renders empty lists as a notice', () => {
		assert.ok(renderContacts({ contacts: [] }).includes('data-fm="empty"'));
		assert.ok(renderContacts(null).includes('data-fm="empty"'));
	});

	it('renders every contact exactly once', () => {
		const html = renderContacts({
			contacts: [
				{ display: 'Ada', uid: 'manual:1' },
				{ display: 'Bob', uid: 'manual:2' }
			]
		});
		assert.equal((html.match(/data-fm="contact"/g) || []).length, 2);
	});
});

describe('loadContacts', () => {
	it('passes the limit as a query parameter', async () => {
		let seen = null;
		const api = {
			request: async (method, path, options) => {
				seen = { method, path, options };
				return { contacts: [] };
			}
		};
		await loadContacts(api, { limit: 10 });
		assert.equal(seen.method, 'GET');
		assert.equal(seen.path, '/contacts');
		assert.deepEqual(seen.options.query, { limit: 10 });
	});

	it('omits empty options', async () => {
		let seen = null;
		const api = {
			request: async (method, path, options) => {
				seen = { method, path, options };
				return { contacts: [] };
			}
		};
		await loadContacts(api);
		assert.deepEqual(seen.options.query, {});
	});
});
