// Frickmail v1 S/MIME screen (Phase 9).
//
// Pure rendering over the v1 `GET /smime/certs` shape plus thin loaders.
// Certificate metadata (emails, fingerprints, dates) passes through the
// shared `escapeHtml`; key material never appears in these shapes by
// server contract. The import forms post base64 text the user pastes;
// file reading stays with the browser form control. All pure helpers are
// unit-tested.

import { escapeHtml } from './mailbox.js';

/// Renders one certificate row. Pure.
export function renderSmimeRow(cert) {
	const id = Number(cert && cert.id) || 0;
	const email = escapeHtml(cert && cert.email ? cert.email : '(unknown address)');
	const fingerprint = escapeHtml(cert && cert.fingerprint ? cert.fingerprint : '');
	const subject = escapeHtml(cert && cert.subject ? cert.subject : '');
	const notAfter = escapeHtml(cert && cert.not_after ? cert.not_after : '');
	const hasKey = !!(cert && cert.has_key);
	return (
		'<li data-fm="cert" data-id="' + id + '">'
		+ '<span data-fm="email">' + email + '</span>'
		+ '<span data-fm="fingerprint">' + fingerprint + '</span>'
		+ '<span data-fm="subject">' + subject + '</span>'
		+ '<span data-fm="expiry">' + notAfter + '</span>'
		+ '<span data-fm="key">' + (hasKey ? 'has private key' : 'public only') + '</span>'
		+ ' <button type="button" data-fm="delete" data-id="' + id + '">Delete</button>'
		+ '</li>'
	);
}

/// Renders the list for a `GET /smime/certs` data payload. Pure.
export function renderSmimeCerts(data) {
	const certs = data && Array.isArray(data.certs) ? data.certs : [];
	if (!certs.length) {
		return '<p data-fm="empty">No S/MIME certificates.</p>';
	}
	return '<ul data-fm="certs">' + certs.map(renderSmimeRow).join('') + '</ul>';
}

/// Renders the two import forms (PEM certificate, PKCS#12 bundle). Pure.
export function renderSmimeImportForms() {
	return '<form data-fm="import-cert">'
		+ '<h2 data-fm="subtitle">Import certificate</h2>'
		+ '<label>Account ID <input data-fm="account-id" inputmode="numeric"></label>'
		+ '<label>PEM (base64) <textarea data-fm="pem"></textarea></label>'
		+ '<button type="submit">Import certificate</button>'
		+ '</form>'
		+ '<form data-fm="import-p12">'
		+ '<h2 data-fm="subtitle">Import PKCS#12 bundle</h2>'
		+ '<label>Account ID <input data-fm="account-id" inputmode="numeric"></label>'
		+ '<label>PKCS#12 (base64) <textarea data-fm="p12"></textarea></label>'
		+ '<label>Bundle password <input type="password" data-fm="password"></label>'
		+ '<button type="submit">Import bundle</button>'
		+ '</form>';
}

/// Reads the PEM import form into a `POST /smime/certs` payload. Takes a
/// stub-able root like the other collectors. Pure.
export function collectCertImport(root) {
	const form = root.querySelector('[data-fm="import-cert"]');
	const scope = form || root;
	const read = (selector) => {
		const field = scope.querySelector(selector);
		return field ? field.value : '';
	};
	return {
		account_id: Number(read('[data-fm="account-id"]')) || 0,
		pem_b64: read('[data-fm="pem"]')
	};
}

/// Reads the PKCS#12 import form into a `POST /smime/p12` payload. Pure.
export function collectP12Import(root) {
	const form = root.querySelector('[data-fm="import-p12"]');
	const scope = form || root;
	const read = (selector) => {
		const field = scope.querySelector(selector);
		return field ? field.value : '';
	};
	const accountId = Number(read('[data-fm="account-id"]')) || 0;
	return {
		account_id: accountId,
		p12_b64: read('[data-fm="p12"]'),
		password: read('[data-fm="password"]')
	};
}

/// Loads certificates through the client. Thin I/O wrapper.
export async function loadSmimeCerts(api) {
	return api.request('GET', '/smime/certs');
}

/// Imports a PEM certificate through the client. Thin I/O wrapper.
export async function importSmimeCert(api, payload) {
	return api.request('POST', '/smime/certs', { body: payload });
}

/// Imports a PKCS#12 bundle through the client. Thin I/O wrapper.
export async function importSmimeP12(api, payload) {
	return api.request('POST', '/smime/p12', { body: payload });
}

/// Deletes a certificate through the client. Thin I/O wrapper.
export async function deleteSmimeCert(api, id) {
	return api.request('DELETE', '/smime/certs', { query: { id } });
}
