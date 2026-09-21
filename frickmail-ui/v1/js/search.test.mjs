// Unit tests for the v1 search screens (Phase 9). Run with:
//   node --test "frickmail-ui/v1/js/*.test.mjs"

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import {
	loadUnifiedInbox,
	renderSearchForm,
	renderSearchResults,
	renderSearchRow,
	renderUnifiedInbox,
	renderUnifiedRow,
	runSearch,
	senderDisplay
} from './search.js';

describe('renderSearchForm', () => {
	it('prefills and escapes the query', () => {
		const html = renderSearchForm('invo<"x');
		assert.ok(html.includes('value="invo&lt;&quot;x"'));
		assert.ok(html.includes('data-fm="q"'));
	});

	it('tolerates missing queries', () => {
		assert.ok(renderSearchForm(null).includes('value=""'));
	});
});

describe('senderDisplay', () => {
	it('prefers names over addresses', () => {
		assert.equal(senderDisplay({ from_name: 'Billing', from_addr: 'b@x.t' }), 'Billing');
		assert.equal(senderDisplay({ from_addr: 'b@x.t' }), 'b@x.t');
		assert.equal(senderDisplay({ from: 'Some One' }), 'Some One');
		assert.equal(senderDisplay({}), '(unknown sender)');
		assert.equal(senderDisplay(null), '(unknown sender)');
	});
});

describe('renderSearchRow', () => {
	it('renders fields with escaping', () => {
		const html = renderSearchRow({
			account_id: 7,
			imap_uid: 31,
			subject: '<b>Invoice</b>',
			from_name: 'Billing',
			folder: 'INBOX',
			snippet: 'pay <now>'
		});
		assert.ok(html.includes('data-account="7"'));
		assert.ok(html.includes('data-uid="31"'));
		assert.ok(html.includes('data-folder="INBOX"'));
		assert.ok(html.includes('&lt;b&gt;Invoice&lt;/b&gt;'));
		assert.ok(html.includes('Billing'));
		assert.ok(html.includes('INBOX'));
		assert.ok(html.includes('pay &lt;now&gt;'));
	});

	it('falls back on missing fields', () => {
		const html = renderSearchRow({});
		assert.ok(html.includes('(no subject)'));
		assert.ok(html.includes('(unknown sender)'));
		assert.ok(html.includes('data-account="0"'));
	});
});

describe('renderSearchResults', () => {
	it('renders empty payloads as a notice', () => {
		assert.ok(renderSearchResults({ results: [] }).includes('data-fm="empty"'));
		assert.ok(renderSearchResults(null).includes('data-fm="empty"'));
	});

	it('renders every result exactly once', () => {
		const html = renderSearchResults({
			results: [
				{ account_id: 1, imap_uid: 1, subject: 'One' },
				{ account_id: 1, imap_uid: 2, subject: 'Two' }
			]
		});
		assert.equal((html.match(/<li data-fm="result"/g) || []).length, 2);
	});
});

describe('renderUnifiedRow', () => {
	it('badges the account and marks unseen', () => {
		const html = renderUnifiedRow({
			account_id: 3,
			uid: 44,
			account_email: 'me@example.com',
			subject: 'Hi',
			from_addr: 'you@example.com',
			is_seen: false
		});
		assert.ok(html.includes('data-account="3"'));
		assert.ok(html.includes('data-uid="44"'));
		assert.ok(html.includes('me@example.com'));
		assert.ok(html.includes('data-unseen="1"'));
	});

	it('accepts legacy imap_uid and hides the unseen marker when seen', () => {
		const html = renderUnifiedRow({ account_id: 3, imap_uid: 45, is_seen: true });
		assert.ok(html.includes('data-uid="45"'));
		assert.ok(!html.includes('data-unseen'));
	});

	it('escapes everything', () => {
		const html = renderUnifiedRow({ subject: '<x>', account_email: 'a"b@c' });
		assert.ok(!html.includes('<x>'));
		assert.ok(html.includes('a&quot;b@c'));
	});
});

describe('renderUnifiedInbox', () => {
	it('renders empty payloads as a notice', () => {
		assert.ok(renderUnifiedInbox({ messages: [] }).includes('data-fm="empty"'));
		assert.ok(renderUnifiedInbox(null).includes('data-fm="empty"'));
	});

	it('renders every message exactly once', () => {
		const html = renderUnifiedInbox({
			messages: [{ account_id: 1, uid: 1 }, { account_id: 1, uid: 2 }]
		});
		assert.equal((html.match(/<li data-fm="unified"/g) || []).length, 2);
	});
});

describe('runSearch', () => {
	it('passes query and limit', async () => {
		let seen = null;
		const api = { request: async (method, path, options) => { seen = { method, path, options }; return null; } };
		await runSearch(api, { q: 'invoice', limit: 10 });
		assert.deepEqual(seen, {
			method: 'GET',
			path: '/search',
			options: { query: { q: 'invoice', limit: 10 } }
		});
	});

	it('omits empty options', async () => {
		let seen = null;
		const api = { request: async (method, path, options) => { seen = { method, path, options }; return null; } };
		await runSearch(api, {});
		assert.deepEqual(seen.options, { query: {} });
	});
});

describe('loadUnifiedInbox', () => {
	it('passes the limit', async () => {
		let seen = null;
		const api = { request: async (method, path, options) => { seen = { method, path, options }; return null; } };
		await loadUnifiedInbox(api, { limit: 25 });
		assert.deepEqual(seen, {
			method: 'GET',
			path: '/unified-inbox',
			options: { query: { limit: 25 } }
		});
	});
});
