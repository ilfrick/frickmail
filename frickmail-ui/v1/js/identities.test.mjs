// Unit tests for the v1 identities management screen (Phase 9). Run with:
//   node --test "frickmail-ui/v1/js/*.test.mjs"

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import {
	addIdentity,
	collectIdentityPayload,
	deleteIdentity,
	loadIdentities,
	renderIdentities,
	renderIdentityForm,
	renderIdentityRow,
	setDefaultIdentity
} from './identities.js';

describe('renderIdentityRow', () => {
	it('escapes fields and marks the default', () => {
		const html = renderIdentityRow({
			id: 4,
			name: '<b>Ada</b>',
			email: '[EMAIL]',
			reply_to: '[EMAIL]',
			is_default: true
		});
		assert.ok(!html.includes('<b>'));
		assert.ok(html.includes('&lt;b&gt;Ada&lt;/b&gt;'));
		assert.ok(html.includes('[EMAIL]'));
		assert.ok(html.includes('data-default="1"'));
		assert.ok(html.includes('data-fm="delete"'));
	});

	it('falls back on missing fields', () => {
		const html = renderIdentityRow({});
		assert.ok(html.includes('(unnamed identity)'));
		assert.ok(!html.includes('data-fm="delete"'));
	});

	it('marks non-default identities with a set-default button', () => {
		const html = renderIdentityRow({ id: 5, name: 'Bob', email: '[EMAIL]', is_default: false });
		assert.ok(html.includes('data-fm="default"'));
		assert.ok(html.includes('>Set default</button>'));
	});
});

describe('renderIdentities', () => {
	it('renders empty lists as a notice', () => {
		assert.ok(renderIdentities({ identities: [] }).includes('data-fm="empty"'));
		assert.ok(renderIdentities(null).includes('data-fm="empty"'));
	});

	it('renders every identity exactly once', () => {
		const html = renderIdentities({
			identities: [
				{ id: 1, name: 'One', email: '[EMAIL]' },
				{ id: 2, name: 'Two', email: '[EMAIL]', is_default: true }
			]
		});
		assert.equal((html.match(/data-fm="identity"/g) || []).length, 2);
	});
});

describe('renderIdentityForm', () => {
	it('renders name, email and reply-to fields', () => {
		const html = renderIdentityForm();
		assert.ok(html.includes('data-fm="add"'));
		assert.ok(html.includes('data-fm="name"'));
		assert.ok(html.includes('data-fm="email"'));
		assert.ok(html.includes('data-fm="reply"'));
	});
});

describe('collectIdentityPayload', () => {
	const root = (values) => ({
		querySelector: (selector) => {
			const key = {
				'[data-fm="name"]': 'name',
				'[data-fm="email"]': 'email',
				'[data-fm="reply"]': 'reply'
			}[selector];
			return { value: values[key] };
		}
	});

	it('reads name/email/reply and the account id', () => {
		const payload = collectIdentityPayload(
			root({ name: 'Ada', email: '[EMAIL]', reply: ' [EMAIL] ' }),
			7
		);
		assert.deepEqual(payload, {
			account_id: 7,
			name: 'Ada',
			email: '[EMAIL]',
			reply_to: '[EMAIL]'
		});
	});

	it('trims fields and omits an empty reply-to', () => {
		const payload = collectIdentityPayload(
			root({ name: ' Ada ', email: '[EMAIL]', reply: '' }),
			0
		);
		assert.deepEqual(payload, { account_id: 0, name: 'Ada', email: '[EMAIL]' });
	});

	it('defaults on a missing root', () => {
		assert.deepEqual(collectIdentityPayload(null, 0), {
			account_id: 0,
			name: '',
			email: ''
		});
	});
});

describe('identity writes', () => {
	const stubApi = () => ({
		request: async (method, path, options) => {
			return { did: { method, path, options } };
		}
	});

	it('loadIdentities passes the account', async () => {
		let seen = null;
		const api = { request: async (_m, _p, o) => { seen = o; return { identities: [] }; } };
		await loadIdentities(api, 9);
		assert.deepEqual(seen.query, { account_id: 9 });
	});

	it('addIdentity posts the payload', async () => {
		const api = stubApi();
		const out = await addIdentity(api, { name: 'N', email: '[EMAIL]', account_id: 3 });
		assert.equal(out.did.method, 'POST');
		assert.equal(out.did.path, '/identities');
		assert.deepEqual(out.did.options.body, { name: 'N', email: '[EMAIL]', account_id: 3 });
	});

	it('setDefaultIdentity posts to /identities/{id}/default', async () => {
		const api = stubApi();
		const out = await setDefaultIdentity(api, 11);
		assert.equal(out.did.method, 'POST');
		assert.equal(out.did.path, '/identities/11/default');
	});

	it('deleteIdentity DELETEs /identities/{id}', async () => {
		const api = stubApi();
		const out = await deleteIdentity(api, 13);
		assert.equal(out.did.method, 'DELETE');
		assert.equal(out.did.path, '/identities/13');
	});
});