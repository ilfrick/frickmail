// Unit tests for the v1 mail-accounts screen (Phase 9). Run with:
//   node --test "frickmail-ui/v1/js/*.test.mjs"

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import {
	addAccount,
	collectAccountPayload,
	deleteAccount,
	loadAccounts,
	renderAccountEditor,
	renderAccountRow,
	renderAccounts,
	setPrimaryAccount,
	switchAccount,
	updateAccount
} from './accounts.js';

describe('renderAccountRow', () => {
	it('marks primary accounts and escapes fields', () => {
		const html = renderAccountRow({
			id: 3,
			label: '<Main>',
			email: 'me@example.com',
			type: 'imap',
			is_primary: true
		});
		assert.ok(html.includes('data-id="3"'));
		assert.ok(html.includes('data-primary="1"'));
		assert.ok(html.includes('primary</span>'));
		assert.ok(html.includes('&lt;Main&gt;'));
		assert.ok(!html.includes('data-fm="delete"'));
		assert.ok(!html.includes('data-fm="make-primary"'));
	});

	it('offers actions on secondary accounts', () => {
		const html = renderAccountRow({ id: 4, email: 'two@example.com', is_primary: false });
		assert.ok(html.includes('data-fm="delete"'));
		assert.ok(html.includes('data-fm="make-primary"'));
		assert.ok(html.includes('data-fm="switch"'));
		assert.ok(html.includes('data-fm="edit"'));
	});

	it('falls back on missing fields', () => {
		const html = renderAccountRow({});
		assert.ok(html.includes('(unknown address)'));
		assert.ok(html.includes('data-id="0"'));
	});
});

describe('renderAccounts', () => {
	it('renders empty payloads as a notice', () => {
		assert.ok(renderAccounts({ accounts: [] }).includes('data-fm="empty"'));
		assert.ok(renderAccounts(null).includes('data-fm="empty"'));
	});

	it('renders every account exactly once', () => {
		const html = renderAccounts({ accounts: [{ id: 1 }, { id: 2 }] });
		assert.equal((html.match(/<li data-fm="account"/g) || []).length, 2);
	});
});

describe('renderAccountEditor', () => {
	it('creates with blank fields', () => {
		const html = renderAccountEditor(null);
		assert.ok(html.includes('Add account'));
		assert.ok(html.includes('data-fm="password"'));
		assert.ok(!html.includes('leave blank to keep'));
	});

	it('edits with prefilled values', () => {
		const html = renderAccountEditor({
			id: 5,
			label: 'Work',
			email: 'w@example.com',
			imap_host: 'imap.example.com',
			login: 'w@example.com',
			smtp_host: 'smtp.example.com'
		});
		assert.ok(html.includes('Update account'));
		assert.ok(html.includes('value="Work"'));
		assert.ok(html.includes('leave blank to keep'));
	});
});

describe('collectAccountPayload', () => {
	const stubRoot = (values) => ({
		querySelector: (selector) => (selector in values ? { value: values[selector] } : null)
	});

	it('reads the form with id', () => {
		const payload = collectAccountPayload(stubRoot({
			'[data-fm="id"]': '5',
			'[data-fm="label"]': 'Work',
			'[data-fm="email"]': 'w@example.com',
			'[data-fm="imap-host"]': 'imap.example.com',
			'[data-fm="login"]': 'w@example.com',
			'[data-fm="password"]': '',
			'[data-fm="smtp-host"]': 'smtp.example.com'
		}));
		assert.deepEqual(payload, {
			label: 'Work',
			email: 'w@example.com',
			imap_host: 'imap.example.com',
			login: 'w@example.com',
			password: '',
			smtp_host: 'smtp.example.com',
			id: '5'
		});
	});

	it('omits empty ids', () => {
		const payload = collectAccountPayload(stubRoot({ '[data-fm="email"]': 'n@example.com' }));
		assert.ok(!('id' in payload));
		assert.equal(payload.email, 'n@example.com');
	});
});

describe('loaders', () => {
	const stubApi = () => {
		let seen = null;
		const api = {
			request: async (method, path, options) => {
				seen = { method, path, options };
				return null;
			}
		};
		return { api, seen: () => seen };
	};

	it('loadAccounts lists', async () => {
		const { api, seen } = stubApi();
		await loadAccounts(api);
		assert.deepEqual(seen(), { method: 'GET', path: '/accounts', options: undefined });
	});

	it('addAccount posts the payload', async () => {
		const { api, seen } = stubApi();
		await addAccount(api, { email: 'n@example.com' });
		assert.deepEqual(seen(), {
			method: 'POST',
			path: '/accounts',
			options: { body: { email: 'n@example.com' } }
		});
	});

	it('updateAccount puts by id', async () => {
		const { api, seen } = stubApi();
		await updateAccount(api, 7, { label: 'New' });
		assert.deepEqual(seen(), {
			method: 'PUT',
			path: '/accounts/7',
			options: { body: { label: 'New' } }
		});
	});

	it('deleteAccount deletes by id', async () => {
		const { api, seen } = stubApi();
		await deleteAccount(api, 7);
		assert.deepEqual(seen(), { method: 'DELETE', path: '/accounts/7', options: undefined });
	});

	it('setPrimaryAccount posts to the primary route', async () => {
		const { api, seen } = stubApi();
		await setPrimaryAccount(api, 7);
		assert.deepEqual(seen(), {
			method: 'POST',
			path: '/accounts/7/primary',
			options: undefined
		});
	});

	it('switchAccount posts the account id', async () => {
		const { api, seen } = stubApi();
		await switchAccount(api, 7);
		assert.deepEqual(seen(), {
			method: 'POST',
			path: '/switch-account',
			options: { body: { account_id: 7 } }
		});
	});
});
