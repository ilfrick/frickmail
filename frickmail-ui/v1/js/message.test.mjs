// Unit tests for the v1 message-reading view (Phase 9). Run with:
//   node --test "frickmail-ui/v1/js/*.test.mjs"

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import {
	attachmentBadge,
	formatAddress,
	formatAddresses,
	formatFileSize,
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

	it('escapes file names and links each part to the download endpoint', () => {
		const html = renderAttachments(
			{ attachments: [{ fileName: 'a"b.pdf', mimeIndex: '2', estimatedSize: 2048 }] },
			{ folder: 'INBOX', uid: 7, accountId: 3 }
		);
		assert.ok(html.includes('a&quot;b.pdf'));
		assert.ok(html.includes('data-fm="download"'));
		assert.ok(html.includes('href="/api/frickmail/v1/messages/7/attachments/2?'));
		assert.ok(html.includes('folder=INBOX'));
		assert.ok(html.includes('account_id=3'));
		assert.ok(html.includes('2.0 KB'));
		assert.ok(!html.includes('a"b.pdf'));
	});

	it('shows an extension badge', () => {
		const html = renderAttachments(
			{ attachments: [{ fileName: 'report.PDF', mimeIndex: '2' }] },
			{ folder: 'INBOX', uid: 1 }
		);
		assert.ok(html.includes('data-fm="attachment-icon">PDF<'));
	});
});

describe('formatFileSize / attachmentBadge', () => {
	it('formats byte counts', () => {
		assert.equal(formatFileSize(0), '');
		assert.equal(formatFileSize(512), '512 B');
		assert.equal(formatFileSize(2048), '2.0 KB');
		assert.equal(formatFileSize(5 * 1024 * 1024), '5.0 MB');
	});

	it('derives a bounded, escaped badge', () => {
		assert.equal(attachmentBadge('a.tar.gz'), 'GZ');
		assert.equal(attachmentBadge('noext'), 'FILE');
		assert.equal(attachmentBadge('<img>.png'), 'PNG');
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
