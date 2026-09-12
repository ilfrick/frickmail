// Unit tests for the v1 folders screen (Phase 9). Run with:
//   node --test "frickmail-ui/v1/js/*.test.mjs"

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import { loadFolders, renderFolderList, renderFolderRow } from './folders.js';

describe('renderFolderRow', () => {
	it('escapes names and marks the selected folder', () => {
		const html = renderFolderRow(
			{ name: '<b>Inbox</b>', full_name: 'INBOX', unread_emails: 3, total_emails: 10 },
			'INBOX'
		);
		assert.ok(!html.includes('<b>'));
		assert.ok(html.includes('&lt;b&gt;Inbox&lt;/b&gt;'));
		assert.ok(html.includes('data-current="1"'));
		assert.ok(html.includes('3/10'));
	});

	it('falls back on missing fields', () => {
		const html = renderFolderRow({}, 'INBOX');
		assert.ok(html.includes('(unnamed folder)'));
		assert.ok(html.includes('0/0'));
		assert.ok(!html.includes('data-current'));
	});
});

describe('renderFolderList', () => {
	it('renders empty collections as a notice', () => {
		assert.ok(renderFolderList({ folders: [] }).includes('data-fm="empty"'));
		assert.ok(renderFolderList(null).includes('data-fm="empty"'));
	});

	it('renders every folder exactly once', () => {
		const html = renderFolderList({
			folders: [
				{ name: 'INBOX', full_name: 'INBOX' },
				{ name: 'Sent', full_name: 'Sent' }
			]
		}, 'Sent');
		assert.equal((html.match(/data-fm="folder"/g) || []).length, 2);
		assert.ok(html.includes('data-name="Sent" data-current="1"'));
	});
});

describe('loadFolders', () => {
	it('passes the account as a query parameter', async () => {
		let seen = null;
		const api = {
			request: async (method, path, options) => {
				seen = { method, path, options };
				return { folders: [] };
			}
		};
		await loadFolders(api, { accountId: 7 });
		assert.equal(seen.method, 'GET');
		assert.equal(seen.path, '/folders');
		assert.deepEqual(seen.options.query, { account_id: 7 });
	});

	it('omits empty options', async () => {
		let seen = null;
		const api = {
			request: async (method, path, options) => {
				seen = { method, path, options };
				return { folders: [] };
			}
		};
		await loadFolders(api);
		assert.deepEqual(seen.options.query, {});
	});
});
