// Frickmail v1 API client (Phase 9).
//
// Framework-free ES module over the versioned `/api/frickmail/v1` JSON API:
// success is `{"version":"v1","data":…}` with HTTP 200, failure is
// `{"version":"v1","error":{"code":…,"message":…}}` with a matching status.
// The connection token bootstrapped from `GET /session` is echoed back as
// the `X-SM-Token` header, exactly like the legacy dispatcher requires.
//
// `fetchImpl` injection keeps every network path unit-testable under plain
// `node --test` with no DOM and no extra dependencies (ES2020 only).

export const API_VERSION = 'v1';
export const API_PREFIX = '/api/frickmail/v1';

export class ApiError extends Error {
	constructor(status, code, message) {
		super(message || 'Request failed');
		this.name = 'ApiError';
		this.status = status;
		this.code = code || 'unknown_error';
	}
}

/// Maps a parsed response body plus HTTP status onto envelope data.
/// Throws ApiError for error envelopes, envelope-less failures, and
/// malformed bodies. Pure: no I/O, fully unit-tested.
export function parseApiBody(body, status) {
	if (body && typeof body === 'object' && 'data' in body && body.data !== undefined) {
		return body.data;
	}
	const error = body && typeof body === 'object' && body.error ? body.error : {};
	throw new ApiError(
		status,
		typeof error.code === 'string' && error.code ? error.code : 'unknown_error',
		typeof error.message === 'string' && error.message ? error.message : 'Request failed'
	);
}

/// Builds the login payload exactly as the v1 route expects. Pure helper so
/// the shape is pinned by tests, not by the DOM layer.
export function loginPayload(username, password, totpCode) {
	const payload = {
		username: String(username || ''),
		password: String(password || '')
	};
	if (totpCode !== undefined && totpCode !== null && String(totpCode) !== '') {
		payload.totp_code = String(totpCode);
	}
	return payload;
}

/// Builds the domain save payload exactly as the v1 admin route expects:
/// trimmed strings, empty optionals omitted, ports as integers when valid.
/// Pure helper so the shape is pinned by tests, not by the DOM layer.
export function domainPayload(input) {
	const source = input && typeof input === 'object' ? input : {};
	const payload = { name: String(source.name || '').trim() };
	const text = (value) => {
		const trimmed = String(value === undefined || value === null ? '' : value).trim();
		return trimmed === '' ? undefined : trimmed;
	};
	const port = (value) => {
		if (value === undefined || value === null || String(value).trim() === '') {
			return undefined;
		}
		const parsed = Number(String(value).trim());
		return Number.isInteger(parsed) && parsed > 0 ? parsed : undefined;
	};
	const fields = [
		['imap_host', text(source.imap_host)],
		['imap_port', port(source.imap_port)],
		['imap_secure', text(source.imap_secure)],
		['smtp_host', text(source.smtp_host)],
		['smtp_port', port(source.smtp_port)],
		['smtp_secure', text(source.smtp_secure)]
	];
	for (const [key, value] of fields) {
		if (value !== undefined) {
			payload[key] = value;
		}
	}
	if (source.disabled !== undefined) {
		payload.disabled = !!source.disabled;
	}
	return payload;
}

export class ApiClient {
	constructor(baseUrl, fetchImpl) {
		// Same-origin path prefix (usually ''). When an absolute origin is
		// given, requests go to it verbatim; otherwise only path+query are
		// sent, keeping the client same-origin by construction.
		this.baseUrl = (baseUrl || '').replace(/\/+$/, '');
		this.fetchImpl = fetchImpl || globalThis.fetch.bind(globalThis);
		this.token = '';
	}

	async request(method, path, options) {
		const settings = options || {};
		const url = new URL(this.baseUrl + API_PREFIX + path, 'http://v1.local');
		if (settings.query) {
			for (const key of Object.keys(settings.query)) {
				const value = settings.query[key];
				if (value !== undefined && value !== null && value !== '') {
					url.searchParams.set(key, String(value));
				}
			}
		}
		const headers = { Accept: 'application/json' };
		if (this.token) {
			headers['X-SM-Token'] = this.token;
		}
		let bodyText;
		if (settings.body !== undefined) {
			headers['Content-Type'] = 'application/json';
			bodyText = JSON.stringify(settings.body);
		}
		const target = this.baseUrl.startsWith('http') ? url.toString() : url.pathname + url.search;
		const response = await this.fetchImpl(target, {
			method,
			credentials: 'same-origin',
			headers,
			body: bodyText
		});
		let parsed = null;
		try {
			parsed = await response.json();
		} catch (error) {
			void error;
		}
		return parseApiBody(parsed, response.status);
	}

	/// Bootstraps an anonymous session: stores the CSRF token the login
	/// route requires and reports whether a session is already authenticated.
	async bootstrap() {
		const data = await this.request('GET', '/session');
		if (data && typeof data.csrf_token === 'string') {
			this.token = data.csrf_token;
		}
		return data;
	}

	/// Authenticates; on TOTP-gated accounts without a valid code the server
	/// answers 200 with `{authenticated:false, requires_totp:true}`.
	async login(username, password, totpCode) {
		const data = await this.request('POST', '/login', {
			body: loginPayload(username, password, totpCode)
		});
		return data;
	}

	/// Ends the session server-side. Idempotent by server contract.
	async logout() {
		const data = await this.request('POST', '/logout');
		this.token = '';
		return data;
	}

	/// Establishes the operator session flag; the session stays anonymous
	/// as a user unless a user login happens too.
	async adminLogin(token) {
		const data = await this.request('POST', '/admin/login', {
			body: { token: String(token || '') }
		});
		return data;
	}

	/// Clears only the operator flag, preserving any user session.
	async adminLogout() {
		const data = await this.request('POST', '/admin/logout');
		return data;
	}

	async listDomains() {
		return this.request('GET', '/admin/domains');
	}

	async getDomain(name) {
		return this.request('GET', '/admin/domains/' + encodeURIComponent(String(name || '')));
	}

	async saveDomain(domain) {
		return this.request('POST', '/admin/domains', { body: domainPayload(domain) });
	}

	async deleteDomain(name) {
		return this.request('DELETE', '/admin/domains/' + encodeURIComponent(String(name || '')));
	}

	async disableDomain(name, disabled) {
		return this.request('POST', '/admin/domains/' + encodeURIComponent(String(name || '')) + '/disable', {
			body: { disabled: !!disabled }
		});
	}

	async saveDomainAlias(name, alias) {
		return this.request('POST', '/admin/domains/aliases', {
			body: { name: String(name || '').trim(), alias: String(alias || '').trim() }
		});
	}

	/// Reads effective values with provenance (`value` + `source` per key).
	async getSettings() {
		return this.request('GET', '/admin/settings');
	}

	/// Saves a `{key: value}` map; the server validates everything before
	/// committing and answers the refreshed settings shape.
	async saveSettings(settings) {
		return this.request('PUT', '/admin/settings', { body: { settings: settings || {} } });
	}

	async resetSetting(name) {
		return this.request('DELETE', '/admin/settings/' + encodeURIComponent(String(name || '')));
	}
}
