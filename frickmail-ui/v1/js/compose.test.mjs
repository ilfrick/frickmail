// Unit tests for the v1 compose screen (Phase 9). Run with:
//   node --test "frickmail-ui/v1/js/*.test.mjs"

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import { collectComposePayload, loadIdentities, renderComposeForm, sendMessage } from './compose.js';

describe('renderComposeForm', () => {
	it('escapes seeded values', () => {
		const html = renderComposeForm({ to: 'a"b', subject: '<Hi>', body: 'x&y' });
		assert.ok(!html.includes('<Hi>'));
		assert.ok(html.includes('value="a&quot;b"'));
		assert.ok(html.includes('&lt;Hi&gt;'));
		assert.ok(html.includes('>x&amp;y</textarea>'));
	});

	it('renders empty forms without seeds', () => {
		const html = renderComposeForm();
		assert.ok(html.includes('data-fm="compose"'));
		assert.ok(html.includes('data-fm="send"'));
	});

	it('renders a sender select when identities exist', () => {
		const html = renderComposeForm(null, [
			{ id: 3, name: 'Work', email: 'w@example.com' },
			{ id: 4, name: '<Other>', email: 'o@example.com' }
		]);
		assert.ok(html.includes('data-fm="identity"'));
		assert.ok(html.includes('<option value="3">Work &lt;w@example.com&gt;</option>'));
		assert.ok(!html.includes('<Other>'));
	});

	it('omits the sender select without identities', () => {
		assert.ok(!renderComposeForm().includes('data-fm="identity"'));
		assert.ok(!renderComposeForm(null, []).includes('data-fm="identity"'));
	});
});

describe('collectComposePayload', () => {
	function fakeRoot(values) {
		return {
			querySelector: (selector) => {
				const table = {
					'[data-fm="to"]': values.to,
					'[data-fm="subject"]': values.subject,
					'[data-fm="body"]': values.text
				};
				return selector in table ? { value: table[selector] } : null;
			}
		};
	}

	it('reads the live form fields', () => {
		assert.deepEqual(
			collectComposePayload(fakeRoot({ to: 'a@example.com', subject: 'Hi', text: 'Yo' })),
			{ to: 'a@example.com', subject: 'Hi', text: 'Yo' }
		);
	});

	it('carries the selected sender identity', () => {
		const root = {
			querySelector: (selector) => {
				const table = {
					'[data-fm="to"]': 'a@example.com',
					'[data-fm="subject"]': '',
					'[data-fm="body"]': '',
					'[data-fm="identity"]': '3'
				};
				return selector in table ? { value: table[selector] } : null;
			}
		};
		const payload = collectComposePayload(root);
		assert.equal(payload.identity_id, 3);
	});

	it('defaults missing fields to empty strings', () => {
		assert.deepEqual(collectComposePayload({ querySelector: () => null }), {
			to: '',
			subject: '',
			text: ''
		});
	});
});

describe('sendMessage', () => {
	it('posts the payload to the send route', async () => {
		let seen = null;
		const api = {
			request: async (method, path, options) => {
				seen = { method, path, options };
				return { sent: true };
			}
		};
		const data = await sendMessage(api, { to: 'a@example.com', text: 'Hi' });
		assert.equal(seen.method, 'POST');
		assert.equal(seen.path, '/send');
		assert.deepEqual(seen.options, { body: { to: 'a@example.com', text: 'Hi' } });
		assert.deepEqual(data, { sent: true });
	});
});

describe('loadIdentities', () => {
	it('passes the account id', async () => {
		let seen = null;
		const api = { request: async (method, path, options) => { seen = { method, path, options }; return null; } };
		await loadIdentities(api, 12);
		assert.deepEqual(seen, {
			method: 'GET',
			path: '/identities',
			options: { query: { account_id: 12 } }
		});
	});

	it('omits empty account ids', async () => {
		let seen = null;
		const api = { request: async (method, path, options) => { seen = { method, path, options }; return null; } };
		await loadIdentities(api, undefined);
		assert.deepEqual(seen.options, { query: {} });
	});
});
