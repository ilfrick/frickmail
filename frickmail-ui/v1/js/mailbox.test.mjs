// Unit tests for the v1 mailbox list screen (Phase 9). Run with:
//   node --test "frickmail-ui/v1/js/*.test.mjs"

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import {
	escapeHtml,
	formatTimestamp,
	loadMailbox,
	renderMailbox,
	renderMessageRow
} from './mailbox.js';

describe('escapeHtml', () => {
	it('escapes markup-significant characters', () => {
		assert.equal(
			escapeHtml('<img src=x onerror=alert(1)>'),
			'&lt;img src=x onerror=alert(1)&gt;'
		);
		assert.equal(escapeHtml('a&b"c\'d'), 'a&amp;b&quot;c&#39;d');
	});

	it('renders nullish input as empty', () => {
		assert.equal(escapeHtml(null), '');
		assert.equal(escapeHtml(undefined), '');
		assert.equal(escapeHtml(42), '42');
	});
});

describe('formatTimestamp', () => {
	it('rejects invalid input without Invalid Date', () => {
		assert.equal(formatTimestamp(0), '');
		assert.equal(formatTimestamp(-5), '');
		assert.equal(formatTimestamp('not-a-date'), '');
		assert.equal(formatTimestamp(NaN), '');
	});

	it('formats real timestamps', () => {
		assert.ok(formatTimestamp(1057049557).length > 0);
	});
});

describe('renderMessageRow', () => {
	it('never emits raw markup from message fields', () => {
		const html = renderMessageRow({
			uid: 7,
			subject: '<script>alert(1)</script>',
			from: 'Evil <evil@example.com>',
			date_timestamp: 1057049557,
			flags: []
		});
		assert.ok(!html.includes('<script>'));
		assert.ok(html.includes('&lt;script&gt;'));
		assert.ok(html.includes('data-uid="7"'));
		assert.ok(html.includes('data-unseen="1"'));
		assert.ok(!html.includes('<time data-fm="date"></time>'));
	});

	it('marks seen messages as read', () => {
		const html = renderMessageRow({ uid: 8, subject: 'Hi', flags: ['\\seen'] });
		assert.ok(!html.includes('data-unseen'));
	});

	it('falls back on missing fields', () => {
		const html = renderMessageRow({});
		assert.ok(html.includes('(no subject)'));
		assert.ok(html.includes('data-uid="0"'));
	});
});

describe('renderMailbox', () => {
	it('renders empty folders as a notice', () => {
		assert.ok(renderMailbox({ messages: [] }).includes('data-fm="empty"'));
		assert.ok(renderMailbox(null).includes('data-fm="empty"'));
	});

	it('renders every message exactly once', () => {
		const html = renderMailbox({
			messages: [
				{ uid: 1, subject: 'One', flags: [] },
				{ uid: 2, subject: 'Two', flags: ['\\seen'] }
			]
		});
		assert.equal((html.match(/data-fm="message"/g) || []).length, 2);
	});
});

describe('loadMailbox', () => {
	it('passes folder and options as query parameters', async () => {
		let seen = null;
		const api = {
			request: async (method, path, options) => {
				seen = { method, path, options };
				return { messages: [] };
			}
		};
		await loadMailbox(api, 'INBOX', { accountId: 3, limit: 25, search: 'bob' });
		assert.equal(seen.method, 'GET');
		assert.equal(seen.path, '/messages');
		assert.deepEqual(seen.options.query, {
			folder: 'INBOX',
			account_id: 3,
			limit: 25,
			search: 'bob'
		});
	});
});
