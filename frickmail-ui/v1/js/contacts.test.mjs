// Unit tests for the v1 contacts screen (Phase 9). Run with:
//   node --test "frickmail-ui/v1/js/*.test.mjs"

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import {
	addContact,
	collectContactPayload,
	deleteContact,
	deduplicateContacts,
	loadContacts,
	renderContactForm,
	renderContacts,
	renderContactRow
} from './contacts.js';

describe('renderContactRow', () => {
	it('escapes display names', () => {
		const html = renderContactRow({ display: '<b>Ada</b>', uid: 'manual:1' });
		assert.ok(!html.includes('<b>'));
		assert.ok(html.includes('&lt;b&gt;Ada&lt;/b&gt;'));
		assert.ok(html.includes('manual:1'));
	});

	it('falls back on missing fields', () => {
		const html = renderContactRow({});
		assert.ok(html.includes('(unnamed contact)'));
	});
});

describe('renderContacts', () => {
	it('renders empty lists as a notice', () => {
		assert.ok(renderContacts({ contacts: [] }).includes('data-fm="empty"'));
		assert.ok(renderContacts(null).includes('data-fm="empty"'));
	});

	it('renders every contact exactly once', () => {
		const html = renderContacts({
			contacts: [
				{ display: 'Ada', uid: 'manual:1' },
				{ display: 'Bob', uid: 'manual:2' }
			]
		});
		assert.equal((html.match(/data-fm="contact"/g) || []).length, 2);
	});
});

describe('loadContacts', () => {
	it('passes the limit as a query parameter', async () => {
		let seen = null;
		const api = {
			request: async (method, path, options) => {
				seen = { method, path, options };
				return { contacts: [] };
			}
		};
		await loadContacts(api, { limit: 10 });
		assert.equal(seen.method, 'GET');
		assert.equal(seen.path, '/contacts');
		assert.deepEqual(seen.options.query, { limit: 10 });
	});

	it('omits empty options', async () => {
		let seen = null;
		const api = {
			request: async (method, path, options) => {
				seen = { method, path, options };
				return { contacts: [] };
			}
		};
		await loadContacts(api);
		assert.deepEqual(seen.options.query, {});
	});
});

describe('renderContactRow', () => {
	it('renders a delete button for contacts with an id', () => {
		const html = renderContactRow({ display: 'Ada', uid: 'manual:1', id: 42 });
		assert.ok(html.includes('data-fm="delete"'));
		assert.ok(html.includes('data-id="42"'));
	});

	it('omits the delete button when no id', () => {
		const html = renderContactRow({ display: 'Bob', uid: 'manual:2' });
		assert.ok(!html.includes('data-fm="delete"'));
	});
});

describe('renderContactForm', () => {
	it('renders the add form with name and email fields', () => {
		const html = renderContactForm();
		assert.ok(html.includes('data-fm="add"'));
		assert.ok(html.includes('data-fm="name"'));
		assert.ok(html.includes('data-fm="email"'));
		assert.ok(html.includes('type="email"'));
		assert.ok(html.includes('Add contact'));
	});
});

describe('collectContactPayload', () => {
	it('reads name and email from form fields', () => {
		const root = {
			querySelector: (selector) => {
				if (selector === '[data-fm="name"]') return { value: 'Ada' };
				if (selector === '[data-fm="email"]') return { value: 'ada@example.com' };
				return null;
			}
		};
		const payload = collectContactPayload(root);
		assert.equal(payload.name, 'Ada');
		assert.equal(payload.email, 'ada@example.com');
	});

	it('returns empty strings for missing fields', () => {
		const root = { querySelector: () => null };
		const payload = collectContactPayload(root);
		assert.equal(payload.name, '');
		assert.equal(payload.email, '');
	});
});

describe('addContact', () => {
	it('POSTs to /contacts with the body', async () => {
		let seen = null;
		const api = {
			request: async (method, path, options) => {
				seen = { method, path, options };
				return { id: 99 };
			}
		};
		const result = await addContact(api, { name: 'Ada', email: 'ada@example.com' });
		assert.equal(seen.method, 'POST');
		assert.equal(seen.path, '/contacts');
		assert.deepEqual(seen.options.body, { name: 'Ada', email: 'ada@example.com' });
		assert.deepEqual(result, { id: 99 });
	});
});

describe('deleteContact', () => {
	it('DELETEs /contacts/{id}', async () => {
		let seen = null;
		const api = {
			request: async (method, path, options) => {
				seen = { method, path, options };
				return {};
			}
		};
		await deleteContact(api, 42);
		assert.equal(seen.method, 'DELETE');
		assert.equal(seen.path, '/contacts/42');
	});
});

describe('deduplicateContacts', () => {
	it('POSTs to /contacts/deduplicate', async () => {
		let seen = null;
		const api = {
			request: async (method, path, options) => {
				seen = { method, path, options };
				return { removed: 3 };
			}
		};
		const result = await deduplicateContacts(api);
		assert.equal(seen.method, 'POST');
		assert.equal(seen.path, '/contacts/deduplicate');
		assert.deepEqual(result, { removed: 3 });
	});
});
