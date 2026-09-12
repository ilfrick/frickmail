// Unit tests for the v1 rules screen (Phase 9). Run with:
//   node --test "frickmail-ui/v1/js/*.test.mjs"

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import { loadRules, renderRules, renderRuleRow } from './rules.js';

describe('renderRuleRow', () => {
	it('escapes names and marks enablement', () => {
		const html = renderRuleRow({ name: '<b>Spam</b>', enabled: true });
		assert.ok(!html.includes('<b>'));
		assert.ok(html.includes('&lt;b&gt;Spam&lt;/b&gt;'));
		assert.ok(html.includes('data-enabled="1"'));
		assert.ok(html.includes('●'));
	});

	it('falls back on missing fields', () => {
		const html = renderRuleRow({});
		assert.ok(html.includes('(unnamed rule)'));
		assert.ok(html.includes('○'));
	});
});

describe('renderRules', () => {
	it('renders empty lists as a notice', () => {
		assert.ok(renderRules({ rules: [] }).includes('data-fm="empty"'));
		assert.ok(renderRules(null).includes('data-fm="empty"'));
	});

	it('renders every rule exactly once', () => {
		const html = renderRules({
			rules: [
				{ name: 'One', enabled: true },
				{ name: 'Two', enabled: false }
			]
		});
		assert.equal((html.match(/data-fm="rule"/g) || []).length, 2);
	});
});

describe('loadRules', () => {
	it('passes the account as a query parameter', async () => {
		let seen = null;
		const api = {
			request: async (method, path, options) => {
				seen = { method, path, options };
				return { rules: [] };
			}
		};
		await loadRules(api, { accountId: 9 });
		assert.equal(seen.method, 'GET');
		assert.equal(seen.path, '/rules');
		assert.deepEqual(seen.options.query, { account_id: 9 });
	});

	it('omits empty options', async () => {
		let seen = null;
		const api = {
			request: async (method, path, options) => {
				seen = { method, path, options };
				return { rules: [] };
			}
		};
		await loadRules(api);
		assert.deepEqual(seen.options.query, {});
	});
});
