// Unit tests for the v1 compose screen (Phase 9). Run with:
//   node --test "frickmail-ui/v1/js/*.test.mjs"

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import { collectComposePayload, renderComposeForm, sendMessage } from './compose.js';

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
