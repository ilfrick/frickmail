// Unit tests for the v1 password form (Phase 9). Run with:
//   node --test "frickmail-ui/v1/js/*.test.mjs"

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import { changePassword, collectPasswordPayload, renderPasswordForm } from './password.js';

describe('renderPasswordForm', () => {
	it('renders password inputs without prefills', () => {
		const html = renderPasswordForm();
		assert.ok(html.includes('data-fm="password-form"'));
		assert.ok(html.includes('type="password" data-fm="current"'));
		assert.ok(html.includes('type="password" data-fm="new"'));
		assert.ok(html.includes('signs you out'));
		assert.ok(!html.includes('value="secret'));
	});
});

describe('collectPasswordPayload', () => {
	it('reads both fields', () => {
		const root = {
			querySelector: (selector) => ({
				'[data-fm="current"]': { value: 'old-horse' },
				'[data-fm="new"]': { value: 'new-horse-stable' }
			}[selector] || null)
		};
		assert.deepEqual(collectPasswordPayload(root), {
			current_password: 'old-horse',
			new_password: 'new-horse-stable'
		});
	});

	it('defaults missing fields', () => {
		assert.deepEqual(collectPasswordPayload({ querySelector: () => null }), {
			current_password: '',
			new_password: ''
		});
	});
});

describe('changePassword', () => {
	it('posts the payload', async () => {
		let seen = null;
		const api = { request: async (method, path, options) => { seen = { method, path, options }; return null; } };
		await changePassword(api, { current_password: 'a', new_password: 'b' });
		assert.deepEqual(seen, {
			method: 'POST',
			path: '/security/password',
			options: { body: { current_password: 'a', new_password: 'b' } }
		});
	});
});
