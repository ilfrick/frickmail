// Unit tests for the v1 OpenPGP screen (Phase 9). Run with:
//   node --test "frickmail-ui/v1/js/*.test.mjs"

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import {
	collectExportPayload,
	collectGeneratePayload,
	collectImportPayload,
	collectPgpComposeOptions,
	deletePgpKey,
	encryptablePgpKeys,
	exportPgpKey,
	formatPgpDate,
	formatPgpFingerprint,
	generatePgpKey,
	importPgpKey,
	loadPgpKeys,
	mergePgpKeys,
	normalizePgpFingerprint,
	pgpKeyLabel,
	pgpComposeState,
	pgpKeyRemovalTargets,
	pgpKeyState,
	renderPgpComposeOptions,
	renderPgpForms,
	renderPgpKey,
	renderPgpKeys,
	removePgpKey,
	signingPgpKeys,
	wirePgpComposeToggle
} from './pgp.js';

/// A keyring listing in the exact shape `GET /pgp/keys` returns: the public
/// and secret views of the same key as two rows.
const KEYRING = {
	keys: [
		{
			fingerprint: '379FB40C06CC299F7128B5A1D873670D8740B474',
			key_id: 'D873670D8740B474',
			secret: false,
			can_sign: true,
			can_encrypt: false,
			can_verify: true,
			can_decrypt: false,
			created: 1790838633,
			expires: 1885446633,
			revoked: false,
			expired: false,
			uids: [{ name: 'V1 PGP', email: 'v1pgp@example.com', uid: 'V1 PGP <v1pgp@example.com>', revoked: false }],
			subkeys: [
				{ fingerprint: '379FB40C06CC299F7128B5A1D873670D8740B474', can_sign: true, can_encrypt: false },
				{ fingerprint: 'D138948ADE01FE3C80249E8CA65E24C333E4994C', can_sign: false, can_encrypt: true }
			]
		},
		{
			fingerprint: '379FB40C06CC299F7128B5A1D873670D8740B474',
			key_id: 'D873670D8740B474',
			secret: true,
			can_sign: true,
			can_encrypt: false,
			can_verify: false,
			can_decrypt: true,
			created: 1790838633,
			expires: 1885446633,
			revoked: false,
			expired: false,
			uids: [{ name: 'V1 PGP', email: 'v1pgp@example.com', uid: 'V1 PGP <v1pgp@example.com>', revoked: false }],
			subkeys: []
		}
	]
};

const CONTACT_KEY = {
	fingerprint: 'D2FF938621374C233DA8B795B2A57BF20718C50F',
	secret: false,
	can_sign: true,
	can_encrypt: false,
	can_verify: true,
	can_decrypt: false,
	created: 1790838835,
	expires: 0,
	revoked: false,
	expired: false,
	uids: [{ name: '', email: 'friend@example.net', uid: 'friend@example.net' }],
	subkeys: [{ fingerprint: 'BAE499214DE4E07B9FED28B1471B34CFC6700FBB', can_encrypt: true }]
};

describe('normalizePgpFingerprint', () => {
	it('strips the 0x prefix, spaces and colons, and uppercases', () => {
		assert.equal(
			normalizePgpFingerprint(' 0x37 9f:b4-0c '),
			'379FB40C'
		);
	});

	it('maps absent values to an empty string', () => {
		for (const value of [undefined, null, '', '   ']) {
			assert.equal(normalizePgpFingerprint(value), '');
		}
		assert.equal(normalizePgpFingerprint(0), '0');
	});
});

describe('mergePgpKeys', () => {
	it('folds the public and secret views of one key into a single row', () => {
		const merged = mergePgpKeys(KEYRING.keys);
		assert.equal(merged.length, 1);
		assert.equal(merged[0].fingerprint, '379FB40C06CC299F7128B5A1D873670D8740B474');
		assert.equal(merged[0].secret, true);
		assert.equal(merged[0].can_decrypt, true);
		// Capability flags keep the public view's values.
		assert.equal(merged[0].can_encrypt, false);
		assert.equal(merged[0].can_verify, true);
	});

	it('keeps a public-only key public and does not mutate its input', () => {
		const input = [{ fingerprint: 'ABCDEF0123456789', secret: false }];
		const merged = mergePgpKeys(input);
		assert.equal(merged[0].secret, false);
		assert.equal(merged[0].can_decrypt, false);
		assert.equal(input[0].secret, false);
		assert.equal(Object.prototype.hasOwnProperty.call(input[0], 'can_decrypt'), false);
	});

	it('drops rows with no usable fingerprint and tolerates junk input', () => {
		assert.deepEqual(mergePgpKeys([{ fingerprint: '' }, null, { fingerprint: 'AA' }]), [
			Object.assign({}, { fingerprint: 'AA' }, { secret: false, can_decrypt: false })
		]);
		assert.deepEqual(mergePgpKeys(null), []);
		assert.deepEqual(mergePgpKeys('nope'), []);
	});
});

describe('pgpKeyLabel', () => {
	it('renders name and address, address only, name only, then raw uid', () => {
		assert.equal(pgpKeyLabel({ uids: [{ name: 'V1 PGP', email: 'a@b.c' }] }), 'V1 PGP <a@b.c>');
		assert.equal(pgpKeyLabel({ uids: [{ name: '', email: 'a@b.c' }] }), 'a@b.c');
		assert.equal(pgpKeyLabel({ uids: [{ name: 'Solo', email: '' }] }), 'Solo');
		assert.equal(pgpKeyLabel({ uids: [{ uid: ' raw@example.com ' }] }), 'raw@example.com');
	});

	it('falls back to the fingerprint then a placeholder', () => {
		assert.equal(pgpKeyLabel({ fingerprint: 'ABCDEF0123456789' }), 'ABCDEF0123456789');
		assert.equal(pgpKeyLabel({}), '(unknown key)');
		assert.equal(pgpKeyLabel(null), '(unknown key)');
	});
});

describe('formatPgpDate', () => {
	it('formats a unix timestamp as a UTC date', () => {
		assert.equal(formatPgpDate(1790838633), '2026-10-01');
	});

	it('reports never for the absent-expiry and invalid cases', () => {
		for (const value of [0, -1, undefined, null, 'abc', NaN]) {
			assert.equal(formatPgpDate(value), 'never');
		}
	});
});

describe('formatPgpFingerprint', () => {
	it('groups into four-character blocks', () => {
		assert.equal(
			formatPgpFingerprint('379fb40c06cc299f7128b5a1d873670d8740b474'),
			'379F B40C 06CC 299F 7128 B5A1 D873 670D 8740 B474'
		);
	});

	it('returns an empty string for nothing usable', () => {
		assert.equal(formatPgpFingerprint(''), '');
		assert.equal(formatPgpFingerprint(null), '');
	});
});

describe('pgpKeyState', () => {
	it('summarises the private half, flags and capabilities', () => {
		assert.equal(
			pgpKeyState({ secret: true, can_sign: true, can_encrypt: true, revoked: false, expired: false }),
			'private key held · can sign and encrypt'
		);
		assert.equal(
			pgpKeyState({ secret: false, can_sign: false, revoked: true, expired: true }),
			'public only · revoked · expired'
		);
		assert.equal(pgpKeyState(null), 'public only');
	});
});

describe('renderPgpKey', () => {
	it('renders metadata with escaping and both actions', () => {
		const html = renderPgpKey(
			Object.assign({}, KEYRING.keys[1], {
				uids: [{ name: '<boss>', email: 'b@x.c' }]
			})
		);
		assert.ok(html.includes('data-fm="pgp-key"'));
		assert.ok(html.includes('data-fingerprint="379FB40C06CC299F7128B5A1D873670D8740B474"'));
		assert.ok(html.includes('data-secret="1"'));
		assert.ok(html.includes('&lt;boss&gt; &lt;b@x.c&gt;'));
		assert.ok(html.includes('379F B40C 06CC 299F'));
		assert.ok(html.includes('created 2026-10-01'));
		assert.ok(html.includes('expires 2029-09-30'));
		assert.ok(html.includes('private key held'));
		assert.ok(html.includes('data-fm="pgp-export"'));
		assert.ok(html.includes('data-fm="pgp-delete"'));
	});

	it('normalizes a messy fingerprint in the attributes and the label', () => {
		const html = renderPgpKey({
			fingerprint: '0x37 9f:b4',
			uids: [{ name: '', email: 'a@b.c' }],
			created: 0,
			expires: 0
		});
		assert.ok(html.includes('data-fingerprint="379FB4"'));
		assert.ok(html.includes('379F B4'));
		assert.ok(html.includes('created never'));
	});

	it('marks a public-only key', () => {
		const html = renderPgpKey(CONTACT_KEY);
		assert.ok(html.includes('public only'));
		assert.equal(html.includes('data-secret="1"'), false);
		assert.ok(html.includes('expires never'));
		assert.ok(html.includes('data-secret="0"'));
	});
});

describe('renderPgpKeys', () => {
	it('renders each key once and folds the two keyring views', () => {
		const html = renderPgpKeys(KEYRING);
		assert.equal((html.match(/<li data-fm="pgp-key"/g) || []).length, 1);
		assert.ok(html.includes('data-fm="pgp-keys"'));
	});

	it('renders empty payloads as a notice', () => {
		assert.ok(renderPgpKeys({ keys: [] }).includes('data-fm="empty"'));
		assert.ok(renderPgpKeys(null).includes('data-fm="empty"'));
	});
});

describe('renderPgpForms', () => {
	it('renders the generate, import and export forms', () => {
		const html = renderPgpForms();
		assert.ok(html.includes('data-fm="pgp-generate"'));
		assert.ok(html.includes('data-fm="pgp-import"'));
		assert.ok(html.includes('data-fm="pgp-export-form"'));
		assert.ok(html.includes('data-fm="generate-passphrase"'));
		assert.ok(html.includes('data-fm="export-secret"'));
		assert.ok(html.includes('data-fm="export-output"'));
	});
});

/// Minimal form stub: `values` and `checked` keyed by selector, scoped to the
/// form root that contains them.
function formStub(forms) {
	return {
		querySelector(selector) {
			for (const fields of Object.values(forms)) {
				if (fields[selector] !== undefined) {
					return {
						value: fields[selector].value === undefined ? '' : fields[selector].value,
						checked: !!fields[selector].checked
					};
				}
			}
			return null;
		}
	};
}

describe('collectGeneratePayload', () => {
	it('trims the identity and omits a blank passphrase', () => {
		const root = formStub({
			generate: {
				'[data-fm="name"]': { value: '  V1 PGP  ' },
				'[data-fm="email"]': { value: ' v1pgp@example.com ' },
				'[data-fm="generate-passphrase"]': { value: '' }
			}
		});
		assert.deepEqual(collectGeneratePayload(root), {
			name: 'V1 PGP',
			email: 'v1pgp@example.com'
		});
	});

	it('carries a supplied passphrase', () => {
		const root = formStub({
			generate: {
				'[data-fm="name"]': { value: '' },
				'[data-fm="email"]': { value: 'a@b.c' },
				'[data-fm="generate-passphrase"]': { value: 'horse' }
			}
		});
		assert.equal(collectGeneratePayload(root).passphrase, 'horse');
	});
});

describe('collectImportPayload', () => {
	it('reads the armor and the backup choice', () => {
		const root = formStub({
			import: {
				'[data-fm="armor"]': { value: '  -----BEGIN PGP PUBLIC KEY BLOCK-----  ' },
				'[data-fm="backup"]': { checked: true }
			}
		});
		assert.deepEqual(collectImportPayload(root), {
			key: '-----BEGIN PGP PUBLIC KEY BLOCK-----',
			backup: true
		});
	});

	it('defaults backup to off', () => {
		const root = formStub({ import: { '[data-fm="armor"]': { value: 'x' } } });
		assert.equal(collectImportPayload(root).backup, false);
	});
});

describe('collectExportPayload', () => {
	it('reads the key id, secret flag and passphrase', () => {
		const root = formStub({
			export: {
				'[data-fm="export-key-id"]': { value: '  379FB40C  ' },
				'[data-fm="export-secret"]': { checked: true },
				'[data-fm="export-passphrase"]': { value: 'horse' }
			}
		});
		assert.deepEqual(collectExportPayload(root), {
			key_id: '379FB40C',
			secret: true,
			passphrase: 'horse'
		});
	});

	it('never sends a passphrase for a public export', () => {
		const root = formStub({
			export: {
				'[data-fm="export-key-id"]': { value: 'ABCDEF01' },
				'[data-fm="export-secret"]': { checked: false },
				'[data-fm="export-passphrase"]': { value: 'horse' }
			}
		});
		assert.deepEqual(collectExportPayload(root), { key_id: 'ABCDEF01', secret: false });
	});
});

describe('pgpKeyRemovalTargets', () => {
	it('removes the secret half before the public half', () => {
		assert.deepEqual(
			pgpKeyRemovalTargets({ fingerprint: '379fb40c', secret: true }),
			[
				{ key_id: '379FB40C', secret: true },
				{ key_id: '379FB40C', secret: false }
			]
		);
	});

	it('removes only the public half when no private key is held', () => {
		assert.deepEqual(pgpKeyRemovalTargets(CONTACT_KEY), [
			{ key_id: 'D2FF938621374C233DA8B795B2A57BF20718C50F', secret: false }
		]);
	});

	it('refuses a target with no fingerprint', () => {
		assert.deepEqual(pgpKeyRemovalTargets({}), []);
		assert.deepEqual(pgpKeyRemovalTargets(null), []);
	});
});

describe('signingPgpKeys / encryptablePgpKeys', () => {
	it('offers only held secret keys for signing', () => {
		const keys = signingPgpKeys({
			keys: [KEYRING.keys[0], KEYRING.keys[1], CONTACT_KEY]
		});
		assert.equal(keys.length, 1);
		assert.equal(keys[0].fingerprint, '379FB40C06CC299F7128B5A1D873670D8740B474');
	});

	it('offers every key with an encryption subkey for encryption', () => {
		const keys = encryptablePgpKeys({ keys: [...KEYRING.keys, CONTACT_KEY] });
		assert.deepEqual(
			keys.map((key) => key.fingerprint),
			['379FB40C06CC299F7128B5A1D873670D8740B474', 'D2FF938621374C233DA8B795B2A57BF20718C50F']
		);
	});

	it('tolerates an absent keyring', () => {
		assert.deepEqual(signingPgpKeys(null), []);
		assert.deepEqual(encryptablePgpKeys({}), []);
	});
});

describe('renderPgpComposeOptions', () => {
	it('renders the sign and encrypt controls inside a collapsed details', () => {
		const html = renderPgpComposeOptions({ keys: [...KEYRING.keys, CONTACT_KEY] });
		assert.ok(html.startsWith('<details data-fm="pgp-compose">'));
		assert.ok(html.endsWith('</details>'));
		// Collapsed by default: the bar costs one summary line until wanted.
		assert.equal(html.includes('open'), false);
		assert.ok(html.includes('data-fm="pgp-summary"'));
		assert.ok(html.includes('data-fm="pgp-state"'));
		assert.ok(html.includes('data-fm="pgp-compose-body"'));
		assert.ok(html.includes('data-fm="pgp-sign"'));
		assert.ok(html.includes('data-fm="pgp-sign-key"'));
		assert.ok(html.includes('data-fm="pgp-sign-passphrase"'));
		assert.ok(html.includes('data-fm="pgp-encrypt"'));
		assert.ok(html.includes('data-fm="pgp-encrypt-keys"'));
		assert.ok(html.includes('value="379FB40C06CC299F7128B5A1D873670D8740B474"'));
		assert.ok(html.includes('value="D2FF938621374C233DA8B795B2A57BF20718C50F"'));
		// Both selects start disabled until their checkbox is ticked.
		assert.ok(html.includes('data-fm-pgp-disabled="1"'));
		// The recipient list is capped so it cannot dominate the window.
		assert.ok(html.includes('size="3"'));
	});

	it('renders nothing when there is no key to act with', () => {
		assert.equal(renderPgpComposeOptions({ keys: [] }), '');
		assert.equal(renderPgpComposeOptions(null), '');
	});
});

describe('collectPgpComposeOptions', () => {
	const composeStub = (overrides) => ({
		querySelector(selector) {
			const fields = Object.assign(
				{
					'[data-fm="pgp-sign"]': { checked: false },
					'[data-fm="pgp-sign-key"]': { value: '379FB40C06CC299F7128B5A1D873670D8740B474' },
					'[data-fm="pgp-sign-passphrase"]': { value: '' },
					'[data-fm="pgp-encrypt"]': { checked: false },
					'[data-fm="pgp-encrypt-keys"]': { options: [] }
				},
				overrides
			);
			return fields[selector] === undefined ? null : fields[selector];
		}
	});

	it('omits everything when both boxes are unticked', () => {
		assert.deepEqual(collectPgpComposeOptions(composeStub()), {});
	});

	it('collects the signing key and passphrase', () => {
		const root = composeStub({
			'[data-fm="pgp-sign"]': { checked: true },
			'[data-fm="pgp-sign-passphrase"]': { value: 'horse' }
		});
		assert.deepEqual(collectPgpComposeOptions(root), {
			sign_fingerprint: '379FB40C06CC299F7128B5A1D873670D8740B474',
			sign_passphrase: 'horse'
		});
	});

	it('omits a blank passphrase but keeps the key', () => {
		const root = composeStub({ '[data-fm="pgp-sign"]': { checked: true } });
		assert.deepEqual(collectPgpComposeOptions(root), {
			sign_fingerprint: '379FB40C06CC299F7128B5A1D873670D8740B474'
		});
	});

	it('collects only the selected recipients', () => {
		const root = composeStub({
			'[data-fm="pgp-encrypt"]': { checked: true },
			'[data-fm="pgp-encrypt-keys"]': {
				options: [
					{ value: 'AAAABBBB', selected: true },
					{ value: 'CCCCDDDD', selected: false },
					{ value: 'EEEEFFFF', selected: true }
				]
			}
		});
		assert.deepEqual(collectPgpComposeOptions(root), {
			encrypt_fingerprints: ['AAAABBBB', 'EEEEFFFF']
		});
	});

	it('omits an encrypt request with no recipient chosen', () => {
		const root = composeStub({
			'[data-fm="pgp-encrypt"]': { checked: true },
			'[data-fm="pgp-encrypt-keys"]': { options: [{ value: 'AAAABBBB', selected: false }] }
		});
		assert.deepEqual(collectPgpComposeOptions(root), {});
	});

	it('skips a signing box with no key selected', () => {
		const root = composeStub({
			'[data-fm="pgp-sign"]': { checked: true },
			'[data-fm="pgp-sign-key"]': { value: '' }
		});
		assert.deepEqual(collectPgpComposeOptions(root), {});
	});

	it('tolerates a missing root and a missing block', () => {
		assert.deepEqual(collectPgpComposeOptions(null), {});
		assert.deepEqual(collectPgpComposeOptions({ querySelector: () => null }), {});
	});
});

describe('wirePgpComposeToggle', () => {
	function checkboxStub(initial) {
		const listeners = [];
		const box = {
			checked: initial,
			addEventListener(_event, handler) {
				listeners.push(handler);
			},
			tick(value) {
				this.checked = value;
				for (const handler of listeners) {
					handler();
				}
			}
		};
		return box;
	}

	it('enables the selects only while their checkbox is ticked', () => {
		const sign = checkboxStub(false);
		const encrypt = checkboxStub(false);
		const signKey = { disabled: true };
		const encryptKeys = { disabled: true };
		const passRow = { hidden: true };
		const state = { textContent: '' };
		const root = {
			querySelector(selector) {
				const fields = {
					'[data-fm="pgp-sign"]': sign,
					'[data-fm="pgp-sign-key"]': signKey,
					'[data-fm="pgp-sign-passphrase"]': { value: '' },
					'[data-fm="pgp-sign-passphrase-row"]': passRow,
					'[data-fm="pgp-encrypt"]': encrypt,
					'[data-fm="pgp-encrypt-keys"]': encryptKeys,
					'[data-fm="pgp-state"]': state
				};
				return fields[selector] === undefined ? null : fields[selector];
			}
		};
		const wired = wirePgpComposeToggle(root);
		assert.equal(wired.length, 2);
		assert.equal(signKey.disabled, true);
		assert.equal(passRow.hidden, true);
		assert.equal(state.textContent, 'off');

		sign.tick(true);
		assert.equal(signKey.disabled, false);
		assert.equal(passRow.hidden, false);

		encrypt.tick(true);
		assert.equal(encryptKeys.disabled, false);

		sign.tick(false);
		assert.equal(signKey.disabled, true);
		assert.equal(passRow.hidden, true);
	});

	it('tolerates a root with no OpenPGP block', () => {
		assert.deepEqual(wirePgpComposeToggle(null), []);
		assert.deepEqual(wirePgpComposeToggle({ querySelector: () => null }), []);
	});
});

describe('pgpComposeState', () => {
	function stateStub(overrides) {
		return {
			querySelector(selector) {
				const fields = Object.assign(
					{
						'[data-fm="pgp-sign"]': { checked: false },
						'[data-fm="pgp-sign-key"]': { selectedIndex: 0, options: [{ textContent: 'V1 PGP' }] },
						'[data-fm="pgp-encrypt"]': { checked: false },
						'[data-fm="pgp-encrypt-keys"]': {
							options: [
								{ selected: true },
								{ selected: true },
								{ selected: false }
							]
						}
					},
					overrides
				);
				return fields[selector] === undefined ? null : fields[selector];
			}
		};
	}

	it('reads off until something is ticked', () => {
		assert.equal(pgpComposeState(stateStub()), 'off');
	});

	it('names the signing key', () => {
		const root = stateStub({ '[data-fm="pgp-sign"]': { checked: true } });
		assert.equal(pgpComposeState(root), 'signed with V1 PGP');
	});

	it('counts the chosen recipients', () => {
		const root = stateStub({ '[data-fm="pgp-encrypt"]': { checked: true } });
		assert.equal(pgpComposeState(root), 'encrypted to 2');
	});

	it('calls out an encrypt request with nobody chosen', () => {
		const root = stateStub({
			'[data-fm="pgp-encrypt"]': { checked: true },
			'[data-fm="pgp-encrypt-keys"]': { options: [{ selected: false }] }
		});
		assert.equal(pgpComposeState(root), 'encrypted to nobody');
	});

	it('combines signing and encryption', () => {
		const root = stateStub({
			'[data-fm="pgp-sign"]': { checked: true },
			'[data-fm="pgp-encrypt"]': { checked: true }
		});
		assert.equal(pgpComposeState(root), 'signed with V1 PGP · encrypted to 2');
	});

	it('survives a key select with no selection and a missing root', () => {
		const root = stateStub({
			'[data-fm="pgp-sign"]': { checked: true },
			'[data-fm="pgp-sign-key"]': { selectedIndex: -1, options: [] }
		});
		assert.equal(pgpComposeState(root), 'signed');
		assert.equal(pgpComposeState(null), 'off');
	});
});

describe('I/O wrappers', () => {
	function recordingApi() {
		const calls = [];
		return {
			calls,
			request(method, path, options) {
				calls.push({ method, path, options });
				return Promise.resolve({ ok: true });
			}
		};
	}

	it('maps every operation onto its v1 route', async () => {
		const api = recordingApi();
		await loadPgpKeys(api);
		await generatePgpKey(api, { email: 'a@b.c' });
		await importPgpKey(api, { key: 'x' });
		await exportPgpKey(api, { key_id: 'AABB' });
		await deletePgpKey(api, 'AABB', true);
		assert.deepEqual(
			api.calls.map((call) => call.method + ' ' + call.path),
			[
				'GET /pgp/keys',
				'POST /pgp/keys/generate',
				'POST /pgp/keys/import',
				'POST /pgp/keys/export',
				'DELETE /pgp/keys'
			]
		);
		assert.deepEqual(api.calls[1].options.body, { email: 'a@b.c' });
		assert.deepEqual(api.calls[2].options.body, { key: 'x' });
		assert.deepEqual(api.calls[3].options.body, { key_id: 'AABB' });
		assert.deepEqual(api.calls[4].options.query, { key_id: 'AABB', secret: 1 });
	});

	it('removePgpKey deletes the secret half then the public half', async () => {
		const api = recordingApi();
		await removePgpKey(api, { fingerprint: '379fb40c', secret: true });
		assert.deepEqual(
			api.calls.map((call) => call.options.query),
			[
				{ key_id: '379FB40C', secret: 1 },
				{ key_id: '379FB40C', secret: 0 }
			]
		);
	});

	it('removePgpKey stops at the first failure', async () => {
		const calls = [];
		const api = {
			request(method, path, options) {
				calls.push(options.query);
				return Promise.reject(new Error('keyring unavailable'));
			}
		};
		await assert.rejects(
			() => removePgpKey(api, { fingerprint: '379FB40C', secret: true }),
			/keyring unavailable/
		);
		assert.equal(calls.length, 1);
	});

	it('removePgpKey does nothing for a key with no fingerprint', async () => {
		const api = recordingApi();
		await removePgpKey(api, {});
		assert.equal(api.calls.length, 0);
	});
});
