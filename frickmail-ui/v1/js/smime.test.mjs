// Unit tests for the v1 S/MIME screen (Phase 9). Run with:
//   node --test "frickmail-ui/v1/js/*.test.mjs"

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import {
	collectCertImport,
	collectP12Import,
	deleteSmimeCert,
	importSmimeCert,
	importSmimeP12,
	loadSmimeCerts,
	renderSmimeCerts,
	renderSmimeImportForms,
	renderSmimeRow
} from './smime.js';

describe('renderSmimeRow', () => {
	it('renders metadata with escaping and key state', () => {
		const html = renderSmimeRow({
			id: 4,
			email: 'user@example.com',
			fingerprint: 'AA:BB',
			subject: '<boss>',
			not_after: '2027-01-01',
			has_key: true
		});
		assert.ok(html.includes('data-id="4"'));
		assert.ok(html.includes('user@example.com'));
		assert.ok(html.includes('AA:BB'));
		assert.ok(html.includes('&lt;boss&gt;'));
		assert.ok(html.includes('has private key'));
		assert.ok(html.includes('data-fm="delete"'));
	});

	it('marks public-only certs and falls back', () => {
		const html = renderSmimeRow({ id: 0, has_key: false });
		assert.ok(html.includes('public only'));
		assert.ok(html.includes('(unknown address)'));
	});
});

describe('renderSmimeCerts', () => {
	it('renders empty payloads as a notice', () => {
		assert.ok(renderSmimeCerts({ certs: [] }).includes('data-fm="empty"'));
		assert.ok(renderSmimeCerts(null).includes('data-fm="empty"'));
	});

	it('renders every cert exactly once', () => {
		const html = renderSmimeCerts({ certs: [{ id: 1 }, { id: 2 }] });
		assert.equal((html.match(/<li data-fm="cert"/g) || []).length, 2);
	});
});

describe('renderSmimeImportForms', () => {
	it('renders both import forms', () => {
		const html = renderSmimeImportForms();
		assert.ok(html.includes('data-fm="import-cert"'));
		assert.ok(html.includes('data-fm="import-p12"'));
		assert.ok(html.includes('data-fm="password"'));
	});
});

describe('collectCertImport', () => {
	const stubRoot = (values) => ({
		querySelector: (selector) => {
			if (selector === '[data-fm="import-cert"]') {
				return {
					querySelector: (inner) => (inner in values ? { value: values[inner] } : null)
				};
			}
			return null;
		}
	});

	it('reads the scoped form', () => {
		const payload = collectCertImport(stubRoot({
			'[data-fm="account-id"]': '12',
			'[data-fm="pem"]': 'QUJD'
		}));
		assert.deepEqual(payload, { account_id: 12, pem_b64: 'QUJD' });
	});

	it('defaults missing fields', () => {
		assert.deepEqual(collectCertImport({ querySelector: () => null }), {
			account_id: 0,
			pem_b64: ''
		});
	});
});

describe('collectP12Import', () => {
	const stubRoot = (values) => ({
		querySelector: (selector) => {
			if (selector === '[data-fm="import-p12"]') {
				return {
					querySelector: (inner) => (inner in values ? { value: values[inner] } : null)
				};
			}
			return null;
		}
	});

	it('reads bundle fields', () => {
		const payload = collectP12Import(stubRoot({
			'[data-fm="account-id"]': '7',
			'[data-fm="p12"]': 'REVG',
			'[data-fm="password"]': 'secret'
		}));
		assert.deepEqual(payload, { account_id: 7, p12_b64: 'REVG', password: 'secret' });
	});
});

describe('loaders', () => {
	it('loadSmimeCerts lists', async () => {
		let seen = null;
		const api = { request: async (method, path, options) => { seen = { method, path, options }; return null; } };
		await loadSmimeCerts(api);
		assert.deepEqual(seen, { method: 'GET', path: '/smime/certs', options: undefined });
	});

	it('importSmimeCert posts the payload', async () => {
		let seen = null;
		const api = { request: async (method, path, options) => { seen = { method, path, options }; return null; } };
		await importSmimeCert(api, { account_id: 1, pem_b64: 'QUJD' });
		assert.deepEqual(seen, {
			method: 'POST',
			path: '/smime/certs',
			options: { body: { account_id: 1, pem_b64: 'QUJD' } }
		});
	});

	it('importSmimeP12 posts the bundle', async () => {
		let seen = null;
		const api = { request: async (method, path, options) => { seen = { method, path, options }; return null; } };
		await importSmimeP12(api, { account_id: 1, p12_b64: 'REVG', password: 's' });
		assert.equal(seen.method, 'POST');
		assert.equal(seen.path, '/smime/p12');
	});

	it('deleteSmimeCert deletes by id', async () => {
		let seen = null;
		const api = { request: async (method, path, options) => { seen = { method, path, options }; return null; } };
		await deleteSmimeCert(api, 9);
		assert.deepEqual(seen, {
			method: 'DELETE',
			path: '/smime/certs',
			options: { query: { id: 9 } }
		});
	});
});
