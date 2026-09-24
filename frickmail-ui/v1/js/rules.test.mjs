// Unit tests for the v1 rules screen (Phase 9). Run with:
//   node --test "frickmail-ui/v1/js/*.test.mjs"

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import {
	addRule,
	collectRulePayload,
	deleteRule,
	loadRules,
	renderRuleForm,
	renderRules,
	renderRuleRow,
	toggleRule
} from './rules.js';

describe('renderRuleRow', () => {
	it('escapes names and marks enablement', () => {
		const html = renderRuleRow({ id: 3, name: '<b>Spam</b>', enabled: true });
		assert.ok(!html.includes('<b>'));
		assert.ok(html.includes('&lt;b&gt;Spam&lt;/b&gt;'));
		assert.ok(html.includes('data-id="3"'));
		assert.ok(html.includes('data-enabled="1"'));
		assert.ok(html.includes('●'));
	});

	it('falls back on missing fields', () => {
		const html = renderRuleRow({});
		assert.ok(html.includes('(unnamed rule)'));
		assert.ok(html.includes('○'));
	});

	it('renders toggle and delete buttons', () => {
		const html = renderRuleRow({ id: 4, name: 'Rules', enabled: true });
		assert.ok(html.includes('data-fm="toggle"'));
		assert.ok(html.includes('>Disable</button>'));
		assert.ok(html.includes('data-fm="delete"'));
		const disabled = renderRuleRow({ id: 5, name: 'Off', enabled: false });
		assert.ok(disabled.includes('>Enable</button>'));
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
				{ id: 1, name: 'One', enabled: true },
				{ id: 2, name: 'Two', enabled: false }
			]
		});
		assert.equal((html.match(/data-fm="rule"/g) || []).length, 2);
	});
});

describe('renderRuleForm', () => {
	it('renders the add form with a name field', () => {
		const html = renderRuleForm();
		assert.ok(html.includes('data-fm="add"'));
		assert.ok(html.includes('data-fm="name"'));
		assert.ok(html.includes('type="submit"'));
	});
});

describe('collectRulePayload', () => {
	it('reads the name and passes the account id', () => {
		const root = { querySelector: () => ({ value: 'Archive sales' }) };
		assert.deepEqual(collectRulePayload(root, 42), {
			name: 'Archive sales',
			account_id: 42
		});
	});

	it('defaults missing fields', () => {
		assert.deepEqual(collectRulePayload(null, 0), { name: '', account_id: 0 });
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

describe('rule writes', () => {
	it('addRule posts the payload', async () => {
		let seen = null;
		const api = {
			request: async (method, path, options) => {
				seen = { method, path, options };
				return { id: 6 };
			}
		};
		const result = await addRule(api, { name: 'N', account_id: 42 });
		assert.equal(seen.method, 'POST');
		assert.equal(seen.path, '/rules');
		assert.deepEqual(seen.options.body, { name: 'N', account_id: 42 });
		assert.deepEqual(result, { id: 6 });
	});

	it('toggleRule posts the state to /rules/{id}/toggle', async () => {
		let seen = null;
		const api = {
			request: async (method, path, options) => {
				seen = { method, path, options };
				return { ok: true };
			}
		};
		await toggleRule(api, 7, false);
		assert.equal(seen.method, 'POST');
		assert.equal(seen.path, '/rules/7/toggle');
		assert.deepEqual(seen.options.body, { enabled: false });
	});

	it('deleteRule DELETEs /rules/{id}', async () => {
		let seen = null;
		const api = {
			request: async (method, path, options) => {
				seen = { method, path, options };
				return { ok: true };
			}
		};
		await deleteRule(api, 8);
		assert.equal(seen.method, 'DELETE');
		assert.equal(seen.path, '/rules/8');
	});
});