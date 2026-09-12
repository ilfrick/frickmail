// Unit tests for the v1 settings screen (Phase 9). Run with:
//   node --test "frickmail-ui/v1/js/*.test.mjs"

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import {
	collectPreferencesPatch,
	loadPreferences,
	renderPreferencesForm,
	renderPreferenceRow,
	savePreferences
} from './settings.js';

describe('renderPreferenceRow', () => {
	it('escapes keys and branches on value type', () => {
		const checked = renderPreferenceRow('flag', true);
		assert.ok(checked.includes('type="checkbox"'));
		assert.ok(checked.includes(' checked'));

		const number = renderPreferenceRow('limit', 80);
		assert.ok(number.includes('type="number"'));
		assert.ok(number.includes('value="80"'));

		const text = renderPreferenceRow('name', 'Ada');
		assert.ok(text.includes('type="text"'));
		assert.ok(text.includes('value="Ada"'));
	});

	it('neutralizes markup in keys and values', () => {
		const html = renderPreferenceRow('a"><script>', '<b>');
		assert.ok(!html.includes('<script>'));
		assert.ok(html.includes('a&quot;&gt;&lt;script&gt;'));
		assert.ok(html.includes('value="&lt;b&gt;"'));
	});
});

describe('renderPreferencesForm', () => {
	it('renders empty objects as a notice', () => {
		assert.ok(renderPreferencesForm({}).includes('data-fm="empty"'));
		assert.ok(renderPreferencesForm(null).includes('data-fm="empty"'));
		assert.ok(renderPreferencesForm([1]).includes('data-fm="empty"'));
	});

	it('renders one row per preference', () => {
		const html = renderPreferencesForm({ a_bool: true, a_num: 3, a_str: 'x' });
		assert.equal((html.match(/data-fm="row"/g) || []).length, 3);
		assert.ok(html.includes('data-fm="save"'));
	});
});

describe('collectPreferencesPatch', () => {
	function fakeRoot(fields) {
		return {
			querySelectorAll: () => fields.map((field) => ({
				getAttribute: (name) => (name === 'data-key' ? field.key : null),
				type: field.type,
				checked: !!field.checked,
				value: field.value === undefined ? '' : field.value
			}))
		};
	}

	it('reads checkbox, number, and text fields', () => {
		const patch = collectPreferencesPatch(fakeRoot([
			{ key: 'flag', type: 'checkbox', checked: true },
			{ key: 'limit', type: 'number', value: '80' },
			{ key: 'name', type: 'text', value: 'Ada' },
			{ key: '', type: 'text', value: 'skipped' }
		]));
		assert.deepEqual(patch, { flag: true, limit: 80, name: 'Ada' });
	});

	it('maps blank or non-numeric numbers to null', () => {
		const patch = collectPreferencesPatch(fakeRoot([
			{ key: 'limit', type: 'number', value: '' },
			{ key: 'other', type: 'number', value: 'abc' }
		]));
		assert.deepEqual(patch, { limit: null, other: null });
	});
});

describe('preferences I/O', () => {
	it('loads and saves through the client', async () => {
		const seen = [];
		const api = {
			request: async (method, path, options) => {
				seen.push({ method, path, options });
				return { preferences: {} };
			}
		};
		await loadPreferences(api);
		assert.deepEqual(seen[0], { method: 'GET', path: '/preferences', options: undefined });
		await savePreferences(api, { a: 1 });
		assert.equal(seen[1].method, 'PUT');
		assert.equal(seen[1].path, '/preferences');
		assert.deepEqual(seen[1].options, { body: { preferences: { a: 1 } } });
	});
});
