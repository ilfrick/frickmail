// Unit tests for the v1 message-reading view (Phase 9). Run with:
//   node --test "frickmail-ui/v1/js/*.test.mjs"

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import {
	formatAddress,
	formatAddresses,
	loadMessage,
	renderAttachments,
	renderMessageHeader,
	selectMessageBody
} from './message.js';
describe('formatAddress', () => {
	it('combines display names and mailboxes', () => {
		assert.equal(formatAddress({ name: 'Ada', email: 'ada@example.com' }), 'Ada <ada@example.com>');
		assert.equal(formatAddress({ name: '', email: 'ada@example.com' }), 'ada@example.com');
		assert.equal(formatAddress(null), '');
	});
});

describe('formatAddresses', () => {
	it('joins collections and rejects non-arrays', () => {
		assert.equal(
			formatAddresses([
				{ name: 'Ada', email: 'ada@example.com' },
				{ name: '', email: 'bob@example.com' }
			]),
			'Ada <ada@example.com>, bob@example.com'
		);
		assert.equal(formatAddresses(null), '');
		assert.equal(formatAddresses('not-an-array'), '');
	});
});

describe('renderMessageHeader', () => {
	it('escapes header fields', () => {
		const html = renderMessageHeader({
			subject: '<b>Hi</b>',
			from: [{ name: 'Evil', email: 'evil@example.com' }],
			to: [],
			dateTimestamp: 1057049557
		});
		assert.ok(!html.includes('<b>'));
		assert.ok(html.includes('&lt;b&gt;Hi&lt;/b&gt;'));
		assert.ok(html.includes('Evil &lt;evil@example.com&gt;'));
		assert.ok(!html.includes('<div data-fm="date"></div>'));
	});
});

describe('renderAttachments', () => {
	it('renders nothing without attachments', () => {
		assert.equal(renderAttachments({}), '');
		assert.equal(renderAttachments({ attachments: null }), '');
	});

	it('escapes file names and keeps indexes', () => {
		const html = renderAttachments({
			attachments: [{ fileName: 'a"b.pdf', mimeIndex: '2', estimatedSize: 9 }]
		});
		assert.ok(html.includes('a&quot;b.pdf'));
		assert.ok(html.includes('data-index="2"'));
	});
});

describe('selectMessageBody', () => {
	it('prefers server-sanitized HTML over plain text', () => {
		assert.deepEqual(
			selectMessageBody({ html: '<p>x</p>', plain: 'x' }),
			{ kind: 'html', body: '<p>x</p>' }
		);
		assert.deepEqual(selectMessageBody({ html: '', plain: 'x' }), { kind: 'plain', body: 'x' });
		assert.deepEqual(selectMessageBody({}), { kind: 'empty', body: '' });
	});
});

describe('loadMessage', () => {
	it('addresses messages by uid with folder context', async () => {
		let seen = null;
		const api = {
			request: async (method, path, options) => {
				seen = { method, path, options };
				return {};
			}
		};
		await loadMessage(api, 'INBOX', 60, { accountId: 3 });
		assert.equal(seen.method, 'GET');
		assert.equal(seen.path, '/messages/60');
		assert.deepEqual(seen.options.query, { folder: 'INBOX', account_id: 3 });
	});
});
