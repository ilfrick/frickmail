// Unit tests for the v1 admin screens (Phase 4/9). Run with:
//   node --test "frickmail-ui/v1/js/*.test.mjs"
// No DOM, no network, no dependencies: collectors take stub roots and the
// client takes an injected fetch.

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import { ApiClient, domainPayload } from './api.js';
import {
	collectDomainForm,
	collectSettingsPatch,
	describeAdminFailure,
	loadAdminDashboard,
	renderAdminDashboard,
	renderAdminLogin,
	renderDomainEditor,
	renderDomainsTable,
	renderDomainRow,
	renderSettingsForm
} from './admin.js';

function jsonResponse(status, body) {
	return {
		status,
		json: async () => body
	};
}

function fakeRoot(fields) {
	return {
		querySelectorAll: () => fields.map((field) => ({
			getAttribute: (name) => (name === 'data-key' ? field.key : null),
			type: field.type,
			value: field.value,
			checked: !!field.checked
		}))
	};
}

describe('domainPayload', () => {
	it('trims and drops empty optionals', () => {
		assert.deepEqual(domainPayload({ name: '  Example.COM  ' }), { name: 'Example.COM' });
		assert.deepEqual(
			domainPayload({ name: 'example.com', imap_host: ' ', imap_port: '', smtp_secure: 'SSL' }),
			{ name: 'example.com', smtp_secure: 'SSL' }
		);
	});

	it('parses valid ports and drops invalid ones', () => {
		assert.deepEqual(
			domainPayload({ name: 'example.com', imap_port: '993', smtp_port: '0' }),
			{ name: 'example.com', imap_port: 993 }
		);
		assert.deepEqual(
			domainPayload({ name: 'example.com', imap_port: 'abc' }),
			{ name: 'example.com' }
		);
	});

	it('keeps explicit disabled flags', () => {
		assert.deepEqual(
			domainPayload({ name: 'example.com', disabled: true }),
			{ name: 'example.com', disabled: true }
		);
	});
});

describe('ApiClient admin methods', () => {
	it('calls the admin endpoints with method, path, and body', async () => {
		const calls = [];
		const api = new ApiClient('', async (target, options) => {
			calls.push({ target, method: options.method, body: options.body });
			return jsonResponse(200, { version: 'v1', data: {} });
		});
		await api.adminLogin('opensesame');
		await api.saveDomain({ name: 'example.com' });
		await api.disableDomain('example.com', true);
		await api.saveDomainAlias('example.com', 'alias.test');
		await api.saveSettings({ open_signup: true });
		await api.deleteDomain('example.com');
		await api.resetSetting('open_signup');
		await api.listDomains();
		await api.getSettings();
		assert.equal(calls[0].target, '/api/frickmail/v1/admin/login');
		assert.equal(calls[0].method, 'POST');
		assert.deepEqual(JSON.parse(calls[0].body), { token: 'opensesame' });
		assert.equal(calls[1].target, '/api/frickmail/v1/admin/domains');
		assert.deepEqual(JSON.parse(calls[1].body), { name: 'example.com' });
		assert.equal(
			calls[2].target,
			'/api/frickmail/v1/admin/domains/example.com/disable'
		);
		assert.deepEqual(JSON.parse(calls[2].body), { disabled: true });
		assert.equal(calls[3].target, '/api/frickmail/v1/admin/domains/aliases');
		assert.equal(calls[4].target, '/api/frickmail/v1/admin/settings');
		assert.equal(calls[4].method, 'PUT');
		assert.deepEqual(JSON.parse(calls[4].body), { settings: { open_signup: true } });
		assert.equal(calls[5].method, 'DELETE');
		assert.equal(calls[5].target, '/api/frickmail/v1/admin/domains/example.com');
		assert.equal(calls[6].target, '/api/frickmail/v1/admin/settings/open_signup');
		assert.equal(calls[7].target, '/api/frickmail/v1/admin/domains');
		assert.equal(calls[8].target, '/api/frickmail/v1/admin/settings');
	});

	it('encodes path segments', async () => {
		let target = '';
		const api = new ApiClient('', async (url) => {
			target = url;
			return jsonResponse(200, { version: 'v1', data: {} });
		});
		await api.getDomain('a/b.test');
		assert.equal(target, '/api/frickmail/v1/admin/domains/a%2Fb.test');
	});
});

describe('describeAdminFailure', () => {
	it('maps operator codes to copy', () => {
		assert.match(describeAdminFailure({ code: 'admin_disabled' }), /not configured/);
		assert.match(describeAdminFailure({ code: 'invalid_token' }), /Invalid operator token/);
		assert.match(describeAdminFailure({ code: 'admin_forbidden' }), /not an operator/);
		assert.match(describeAdminFailure({ code: 'unknown_setting' }), /Unknown setting/);
		assert.match(describeAdminFailure({ code: 'domain_not_found' }), /not found/);
		assert.match(
			describeAdminFailure({ code: 'invalid_request', message: 'Bad port.' }),
			/Bad port/
		);
		assert.match(describeAdminFailure(null), /Try again/);
	});
});

describe('renderDomainsTable', () => {
	it('renders rows with escaped names and states', () => {
		const html = renderDomainsTable([
			{ name: 'example.com', disabled: false, imap_host: 'imap.example.com', smtp_host: '' },
			{ name: 'old.test', disabled: true },
			{ name: '<evil>.test', disabled: false, alias_of: 'example.com' }
		]);
		assert.match(html, /example\.com/);
		assert.match(html, /enabled/);
		assert.match(html, /disabled/);
		assert.match(html, /alias of example\.com/);
		assert.doesNotMatch(html, /<evil>/);
	});

	it('renders an empty note without domains', () => {
		assert.match(renderDomainsTable([]), /No mail domains/);
		assert.match(renderDomainsTable(null), /No mail domains/);
	});

	it('renders single rows with actions', () => {
		const html = renderDomainRow({ name: 'example.com', disabled: false });
		assert.match(html, /data-name="example\.com"/);
		assert.match(html, /domain-delete/);
	});
});

describe('renderDomainEditor', () => {
	it('renders blank and prefilled forms', () => {
		assert.match(renderDomainEditor(null), /New domain/);
		const html = renderDomainEditor({ name: 'example.com', imap_port: 993 });
		assert.match(html, /Edit example\.com/);
		assert.match(html, /value="993"/);
	});
});

describe('collectDomainForm', () => {
	it('builds a save payload from stub fields', () => {
		const root = fakeRoot([
			{ key: 'name', type: 'text', value: ' example.com ' },
			{ key: 'imap_port', type: 'number', value: '993' },
			{ key: 'smtp_host', type: 'text', value: '' }
		]);
		assert.deepEqual(collectDomainForm(root), { name: 'example.com', imap_port: 993 });
	});
});

describe('renderSettingsForm', () => {
	it('renders booleans and numbers with provenance', () => {
		const html = renderSettingsForm({
			open_signup: { value: true, source: 'database' },
			'frickmail_user.export_folder_max_messages': { value: 500, source: 'environment' }
		});
		assert.match(html, /checked/);
		assert.match(html, /\(database\)/);
		assert.match(html, /\(environment\)/);
		assert.match(html, /value="500"/);
	});

	it('renders an empty note without settings', () => {
		assert.match(renderSettingsForm({}), /No settings/);
	});
});

describe('collectSettingsPatch', () => {
	it('keeps types and leaves bad numbers raw', () => {
		const root = fakeRoot([
			{ key: 'open_signup', type: 'checkbox', checked: true },
			{ key: 'frickmail_user.export_folder_max_messages', type: 'number', value: '500' },
			{ key: 'frickmail_user.export_folder_max_bytes', type: 'number', value: 'oops' }
		]);
		assert.deepEqual(collectSettingsPatch(root), {
			open_signup: true,
			'frickmail_user.export_folder_max_messages': 500,
			'frickmail_user.export_folder_max_bytes': 'oops'
		});
	});
});

describe('renderAdminLogin', () => {
	it('renders a token form', () => {
		const html = renderAdminLogin();
		assert.match(html, /Operator token/);
		assert.match(html, /type="password"/);
	});
});

describe('renderAdminDashboard', () => {
	it('renders both sections', () => {
		const html = renderAdminDashboard({
			domains: [{ name: 'example.com' }],
			settings: { open_signup: { value: false, source: 'environment' } }
		});
		assert.match(html, /Mail domains/);
		assert.match(html, /Runtime settings/);
		assert.match(html, /example\.com/);
		assert.match(html, /open_signup/);
	});
});

describe('loadAdminDashboard', () => {
	it('normalizes shapes', async () => {
		const api = {
			listDomains: async () => ({ domains: [{ name: 'example.com' }] }),
			getSettings: async () => ({ settings: { open_signup: { value: true, source: 'database' } } })
		};
		assert.deepEqual(await loadAdminDashboard(api), {
			domains: [{ name: 'example.com' }],
			settings: { open_signup: { value: true, source: 'database' } }
		});
		const empty = await loadAdminDashboard({ listDomains: async () => ({}), getSettings: async () => ({}) });
		assert.deepEqual(empty, { domains: [], settings: {} });
	});
});
