// Frickmail v1 OpenPGP screen (Phase 9).
//
// Pure rendering over the v1 `GET /pgp/keys` shape plus thin loaders. GnuPG
// reports the same key twice — once from the public keyring, once from the
// secret one — so everything here works on a merged view (`mergePgpKeys`)
// where one row says whether the private half is held. Key material only ever
// appears in the export form's output box, which is filled from an explicit
// export call; the listing itself is metadata by server contract. All pure
// helpers are unit-tested.

import { escapeHtml } from './mailbox.js';

/// Canonicalizes a fingerprint/key id for comparison and display: strips the
/// `0x` prefix plus the separators key managers and key servers print keys
/// with (spaces, colons, dashes), and uppercases. Pure.
export function normalizePgpFingerprint(value) {
	return String(value === undefined || value === null ? '' : value)
		.trim()
		.replace(/^0x/i, '')
		.replace(/[\s:-]/g, '')
		.toUpperCase();
}

/// Groups the public and secret views of the same key into one entry, so the
/// list shows a key once and records whether the private half is held. Rows
/// without a fingerprint are dropped: nothing can act on them. Pure.
export function mergePgpKeys(keys) {
	const merged = new Map();
	for (const key of Array.isArray(keys) ? keys : []) {
		const fingerprint = normalizePgpFingerprint(key && key.fingerprint);
		if (!fingerprint) {
			continue;
		}
		const existing = merged.get(fingerprint);
		if (!existing) {
			// The first row seen may be either view, so its own flags have to be
			// honoured: a keyring holding only a secret view must not be reported
			// as public-only.
			merged.set(
				fingerprint,
				Object.assign({}, key, {
					fingerprint,
					secret: !!key.secret,
					can_decrypt: !!key.can_decrypt
				})
			);
			continue;
		}
		// Capability flags come from the public view; the secret view only
		// adds the private half.
		if (key.secret) {
			existing.secret = true;
			existing.can_decrypt = true;
		}
	}
	return [...merged.values()];
}

/// The display label for a key: its first user ID as `Name <address>`, falling
/// back to the raw uid and then to the fingerprint. Pure.
export function pgpKeyLabel(key) {
	const uids = key && Array.isArray(key.uids) ? key.uids.filter((uid) => uid) : [];
	const uid = uids[0] || {};
	const name = typeof uid.name === 'string' ? uid.name.trim() : '';
	const email = typeof uid.email === 'string' ? uid.email.trim() : '';
	if (name && email) {
		return name + ' <' + email + '>';
	}
	if (email) {
		return email;
	}
	if (name) {
		return name;
	}
	if (typeof uid.uid === 'string' && uid.uid.trim()) {
		return uid.uid.trim();
	}
	return normalizePgpFingerprint(key && key.fingerprint) || '(unknown key)';
}

/// Formats a unix timestamp as a UTC date, or `never` for the absent/invalid
/// case GnuPG uses for "no expiry". Pure.
export function formatPgpDate(seconds) {
	const value = Number(seconds);
	if (!Number.isFinite(value) || value <= 0) {
		return 'never';
	}
	const date = new Date(value * 1000);
	if (Number.isNaN(date.getTime())) {
		return 'never';
	}
	return date.toISOString().slice(0, 10);
}

/// Formats a fingerprint as uppercase 4-character blocks, the way key servers
/// and key managers print it. Pure.
export function formatPgpFingerprint(fingerprint) {
	const value = normalizePgpFingerprint(fingerprint);
	if (!value) {
		return '';
	}
	return (value.match(/.{1,4}/g) || []).join(' ');
}

/// A short status summary for a merged key row. Pure.
export function pgpKeyState(key) {
	const state = [];
	if (key && key.secret) {
		state.push('private key held');
	} else {
		state.push('public only');
	}
	if (key && key.revoked) {
		state.push('revoked');
	}
	if (key && key.expired) {
		state.push('expired');
	}
	const capabilities = [];
	if (key && key.can_sign) {
		capabilities.push('sign');
	}
	if (key && key.can_encrypt) {
		capabilities.push('encrypt');
	}
	if (capabilities.length) {
		state.push('can ' + capabilities.join(' and '));
	}
	return state.join(' · ');
}

/// Renders one merged key row, with export and delete actions. Pure.
export function renderPgpKey(key) {
	const fingerprint = normalizePgpFingerprint(key && key.fingerprint);
	return (
		'<li data-fm="pgp-key" data-fingerprint="' + escapeHtml(fingerprint) + '"'
		+ (key && key.secret ? ' data-secret="1"' : '')
		+ '>'
		+ '<span data-fm="uid">' + escapeHtml(pgpKeyLabel(key)) + '</span>'
		+ '<span data-fm="fingerprint">' + escapeHtml(formatPgpFingerprint(fingerprint)) + '</span>'
		+ '<span data-fm="created">created ' + escapeHtml(formatPgpDate(key && key.created)) + '</span>'
		+ '<span data-fm="expires">expires ' + escapeHtml(formatPgpDate(key && key.expires)) + '</span>'
		+ '<span data-fm="state">' + escapeHtml(pgpKeyState(key)) + '</span>'
		+ ' <button type="button" data-fm="pgp-export" data-fingerprint="'
		+ escapeHtml(fingerprint)
		+ '" data-secret="' + (key && key.secret ? '1' : '0')
		+ '">Export</button>'
		+ ' <button type="button" data-fm="pgp-delete" data-fingerprint="'
		+ escapeHtml(fingerprint) + '">Delete</button>'
		+ '</li>'
	);
}

/// Renders the list for a `GET /pgp/keys` data payload, merging the two
/// keyring views first. Pure.
export function renderPgpKeys(data) {
	const keys = mergePgpKeys(data && data.keys);
	if (!keys.length) {
		return '<p data-fm="empty">No OpenPGP keys yet.</p>';
	}
	return '<ul data-fm="pgp-keys">' + keys.map(renderPgpKey).join('') + '</ul>';
}

/// The merged keys the compose window may sign with. Pure.
export function signingPgpKeys(data) {
	return mergePgpKeys(data && data.keys).filter((key) => key.secret && key.can_sign);
}

/// The merged keys compose may encrypt to: every key with a usable encryption
/// subkey. Pure.
export function encryptablePgpKeys(data) {
	return mergePgpKeys(data && data.keys).filter((key) => {
		if (key.can_encrypt) {
			return true;
		}
		// ed25519 primaries cannot encrypt; the capability sits on a subkey.
		return Array.isArray(key.subkeys)
			&& key.subkeys.some((subkey) => subkey && subkey.can_encrypt);
	});
}

/// Renders the key-management forms: generate, import and export. Pure.
export function renderPgpForms() {
	return (
		'<form data-fm="pgp-generate">'
		+ '<h3 data-fm="subtitle">Generate a key pair</h3>'
		+ '<label>Name <input data-fm="name"></label>'
		+ '<label>Email <input type="email" data-fm="email" required></label>'
		+ '<label>Passphrase (optional) <input type="password" data-fm="generate-passphrase"></label>'
		+ '<button type="submit">Generate key</button>'
		+ '</form>'
		+ '<form data-fm="pgp-import">'
		+ '<h3 data-fm="subtitle">Import a key</h3>'
		+ '<label>Armored key <textarea data-fm="armor"></textarea></label>'
		+ '<label><input type="checkbox" data-fm="backup"> Also store a backup with the account</label>'
		+ '<button type="submit">Import key</button>'
		+ '</form>'
		+ '<form data-fm="pgp-export-form">'
		+ '<h3 data-fm="subtitle">Export a key</h3>'
		+ '<label>Key id or fingerprint <input data-fm="export-key-id"></label>'
		+ '<label><input type="checkbox" data-fm="export-secret"> Include the private key</label>'
		+ '<label>Passphrase <input type="password" data-fm="export-passphrase"></label>'
		+ '<button type="submit">Export key</button>'
		+ '<textarea data-fm="export-output" readonly rows="6"></textarea>'
		+ '</form>'
	);
}

function pgpFormReader(root, formSelector) {
	const form = root.querySelector(formSelector);
	const scope = form || root;
	return (selector) => {
		const field = scope.querySelector(selector);
		return field ? field.value : '';
	};
}

function pgpFormCheckbox(root, formSelector, selector) {
	const form = root.querySelector(formSelector);
	const scope = form || root;
	const field = scope.querySelector(selector);
	return !!(field && field.checked);
}

/// Reads the generate form into a `POST /pgp/keys/generate` payload. Takes a
/// stub-able root like the other collectors. Pure.
export function collectGeneratePayload(root) {
	const read = pgpFormReader(root, '[data-fm="pgp-generate"]');
	const payload = {
		name: read('[data-fm="name"]').trim(),
		email: read('[data-fm="email"]').trim()
	};
	const passphrase = read('[data-fm="generate-passphrase"]');
	if (passphrase) {
		payload.passphrase = passphrase;
	}
	return payload;
}

/// Reads the import form into a `POST /pgp/keys/import` payload. Pure.
export function collectImportPayload(root) {
	const read = pgpFormReader(root, '[data-fm="pgp-import"]');
	return {
		key: read('[data-fm="armor"]').trim(),
		backup: pgpFormCheckbox(root, '[data-fm="pgp-import"]', '[data-fm="backup"]')
	};
}

/// Reads the export form into a `POST /pgp/keys/export` payload. Pure.
export function collectExportPayload(root) {
	const read = pgpFormReader(root, '[data-fm="pgp-export-form"]');
	const payload = {
		key_id: read('[data-fm="export-key-id"]').trim(),
		secret: pgpFormCheckbox(root, '[data-fm="pgp-export-form"]', '[data-fm="export-secret"]')
	};
	const passphrase = read('[data-fm="export-passphrase"]');
	if (payload.secret && passphrase) {
		payload.passphrase = passphrase;
	}
	return payload;
}

/// Which keyring halves a delete has to remove for the key to actually be
/// gone: the secret half first (GnuPG keeps the public half of a secret key
/// behind), then the public half. Pure.
export function pgpKeyRemovalTargets(key) {
	const fingerprint = normalizePgpFingerprint(key && key.fingerprint);
	if (!fingerprint) {
		return [];
	}
	return key.secret
		? [{ key_id: fingerprint, secret: true }, { key_id: fingerprint, secret: false }]
		: [{ key_id: fingerprint, secret: false }];
}

/// Renders the compose OpenPGP block: sign with one of the caller's secret
/// keys, optionally encrypt to any number of recipient keys. Returns an empty
/// string when there is nothing to sign with, so the compose window stays
/// clean for a keyring with no private key.
///
/// The controls live inside a collapsed `<details>`: a recipient multi-select
/// is tall enough to make every compose window jump, so the bar only claims
/// its one summary line until it is actually wanted. The summary doubles as
/// the state readout, which is where a user checks what the mail will be
/// signed/encrypted with. Pure.
export function renderPgpComposeOptions(data) {
	const signing = signingPgpKeys(data);
	const recipients = encryptablePgpKeys(data);
	if (!signing.length && !recipients.length) {
		return '';
	}
	const option = (key) =>
		'<option value="' + escapeHtml(key.fingerprint) + '">'
		+ escapeHtml(pgpKeyLabel(key)) + '</option>';
	const signRow = signing.length
		? '<label><input type="checkbox" data-fm="pgp-sign"> Sign with '
			+ '<select data-fm="pgp-sign-key" data-fm-pgp-disabled="1" disabled>'
			+ signing.map(option).join('')
			+ '</select></label>'
			+ '<label data-fm="pgp-sign-passphrase-row" hidden>Passphrase '
			+ '<input type="password" data-fm="pgp-sign-passphrase"></label>'
		: '';
	const encryptRow = recipients.length
		? '<label><input type="checkbox" data-fm="pgp-encrypt"> Encrypt to '
			+ '<select data-fm="pgp-encrypt-keys" data-fm-pgp-disabled="1" multiple size="3" disabled>'
			+ recipients.map(option).join('')
			+ '</select></label>'
		: '';
	return (
		'<details data-fm="pgp-compose">'
		+ '<summary data-fm="pgp-summary">OpenPGP: '
		+ '<span data-fm="pgp-state">off</span></summary>'
		+ '<div data-fm="pgp-compose-body">'
		+ signRow
		+ encryptRow
		+ '</div>'
		+ '</details>'
	);
}

/// The one-line state readout for the collapsed compose bar, e.g.
/// `signed with V1 PGP · encrypted to 2 recipients`. Pure.
export function pgpComposeState(root) {
	if (!root || !root.querySelector) {
		return 'off';
	}
	const parts = [];
	const signBox = root.querySelector('[data-fm="pgp-sign"]');
	if (signBox && signBox.checked) {
		const key = root.querySelector('[data-fm="pgp-sign-key"]');
		const option = key && key.selectedIndex >= 0 ? key.options[key.selectedIndex] : null;
		parts.push('signed' + (option ? ' with ' + option.textContent : ''));
	}
	const encryptBox = root.querySelector('[data-fm="pgp-encrypt"]');
	if (encryptBox && encryptBox.checked) {
		const select = root.querySelector('[data-fm="pgp-encrypt-keys"]');
		const chosen = select && select.options
			? [...select.options].filter((option) => option.selected).length
			: 0;
		parts.push(chosen ? 'encrypted to ' + chosen : 'encrypted to nobody');
	}
	return parts.length ? parts.join(' · ') : 'off';
}

/// Reads the compose OpenPGP block into the `sign_fingerprint` /
/// `sign_passphrase` / `encrypt_fingerprints` fields of a `POST /send` body.
/// Unchecked options are omitted entirely rather than sent empty, so the
/// server never has to guess. Pure.
export function collectPgpComposeOptions(root) {
	const options = {};
	if (!root || !root.querySelector) {
		return options;
	}
	const signBox = root.querySelector('[data-fm="pgp-sign"]');
	if (signBox && signBox.checked) {
		const key = root.querySelector('[data-fm="pgp-sign-key"]');
		const fingerprint = normalizePgpFingerprint(key && key.value);
		if (fingerprint) {
			options.sign_fingerprint = fingerprint;
			const passphrase =
				root.querySelector('[data-fm="pgp-sign-passphrase"]') || { value: '' };
			if (passphrase.value) {
				options.sign_passphrase = passphrase.value;
			}
		}
	}
	const encryptBox = root.querySelector('[data-fm="pgp-encrypt"]');
	if (encryptBox && encryptBox.checked) {
		const select = root.querySelector('[data-fm="pgp-encrypt-keys"]');
		const options_ = select && select.options ? [...select.options] : [];
		const fingerprints = options_
			.filter((option) => option.selected)
			.map((option) => normalizePgpFingerprint(option.value))
			.filter((fingerprint) => fingerprint);
		if (fingerprints.length) {
			options.encrypt_fingerprints = fingerprints;
		}
	}
	return options;
}

/// Enables the key/recipient selects when their checkbox is ticked, reveals
/// the signing passphrase field, and keeps the collapsed summary in step with
/// what the message will actually be signed/encrypted with. Thin DOM helper,
/// mirroring `wireComposeToggle`. Returns the checkboxes it wired.
export function wirePgpComposeToggle(root) {
	if (!root || !root.querySelector) {
		return [];
	}
	const state = root.querySelector('[data-fm="pgp-state"]');
	const sync = () => {
		const signBox = root.querySelector('[data-fm="pgp-sign"]');
		const signKey = root.querySelector('[data-fm="pgp-sign-key"]');
		if (signBox && signKey) {
			signKey.disabled = !signBox.checked;
		}
		const signPass = root.querySelector('[data-fm="pgp-sign-passphrase"]');
		const passRow = root.querySelector('[data-fm="pgp-sign-passphrase-row"]');
		if (signBox && signPass && passRow) {
			passRow.hidden = !signBox.checked;
		}
		const encryptBox = root.querySelector('[data-fm="pgp-encrypt"]');
		const encryptKeys = root.querySelector('[data-fm="pgp-encrypt-keys"]');
		if (encryptBox && encryptKeys) {
			encryptKeys.disabled = !encryptBox.checked;
		}
		if (state) {
			state.textContent = pgpComposeState(root);
		}
	};
	const wired = [];
	for (const selector of ['[data-fm="pgp-sign"]', '[data-fm="pgp-encrypt"]']) {
		const box = root.querySelector(selector);
		if (box) {
			box.addEventListener('change', sync);
			wired.push(box);
		}
	}
	const signKey = root.querySelector('[data-fm="pgp-sign-key"]');
	if (signKey && typeof signKey.addEventListener === 'function') {
		signKey.addEventListener('change', sync);
	}
	const encryptKeys = root.querySelector('[data-fm="pgp-encrypt-keys"]');
	if (encryptKeys && typeof encryptKeys.addEventListener === 'function') {
		encryptKeys.addEventListener('change', sync);
	}
	sync();
	return wired;
}

/// Loads the keyring through the client. Thin I/O wrapper.
export async function loadPgpKeys(api) {
	return api.request('GET', '/pgp/keys');
}

/// Generates a key pair through the client. Thin I/O wrapper.
export async function generatePgpKey(api, payload) {
	return api.request('POST', '/pgp/keys/generate', { body: payload });
}

/// Imports an armored key through the client. Thin I/O wrapper.
export async function importPgpKey(api, payload) {
	return api.request('POST', '/pgp/keys/import', { body: payload });
}

/// Exports one key through the client. Thin I/O wrapper.
export async function exportPgpKey(api, payload) {
	return api.request('POST', '/pgp/keys/export', { body: payload });
}

/// Deletes one keyring half through the client. Thin I/O wrapper.
export async function deletePgpKey(api, keyId, secret) {
	return api.request('DELETE', '/pgp/keys', {
		query: { key_id: keyId, secret: secret ? 1 : 0 }
	});
}

/// Removes both halves of a merged key, so a delete cannot leave a public key
/// behind. Throws on the first failure, leaving the rest untouched.
export async function removePgpKey(api, key) {
	for (const target of pgpKeyRemovalTargets(key)) {
		await deletePgpKey(api, target.key_id, target.secret);
	}
}
