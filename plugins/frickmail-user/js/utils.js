// Frickmail shared utilities — loaded before all other plugin JS.
// Centralises functions that were previously duplicated across overlays.

window.FrickmailUtils = {

	/**
	 * Escape a string for safe insertion as HTML text content.
	 * Prevents XSS when building innerHTML from untrusted data.
	 */
	escHtml: function (s) {
		return String(s || '')
			.replace(/&/g, '&amp;')
			.replace(/</g, '&lt;')
			.replace(/>/g, '&gt;')
			.replace(/"/g, '&quot;');
	},

	/**
	 * Return the current CSRF/XToken for JSON plugin calls.
	 * Tries the live rl.settings path first, then the cached login-time token.
	 */
	fmToken: function () {
		return window.rl?.settings?.app?.('token') || window.rl?.__frickmail_token || '';
	},

	/**
	 * Format a date for display.
	 *
	 * Accepts either:
	 *   - a unix timestamp (number, seconds since epoch)
	 *   - an ISO 8601 date/datetime string  (e.g. '2024-03-15' or '2024-03-15T10:30:00Z')
	 *
	 * Output rules (same as UnifiedInbox's original formatDate):
	 *   - Same calendar day  → 'HH:MM'
	 *   - Same calendar year → 'Mon DD'
	 *   - Older             → 'Mon DD YYYY'
	 *
	 * Returns '' for falsy input.
	 */
	formatDate: function (input) {
		if (!input) return '';
		var d;
		if (typeof input === 'number') {
			// Unix timestamp (seconds)
			d = new Date(input * 1000);
		} else {
			var s = String(input);
			// Plain date 'YYYY-MM-DD' — anchor to midnight local time
			if (/^\d{4}-\d{2}-\d{2}$/.test(s)) {
				d = new Date(s + 'T00:00:00');
			} else {
				d = new Date(s);
			}
		}
		if (isNaN(d)) return String(input);

		var now    = new Date();
		var months = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
		var pad    = function (n) { return String(n).padStart(2, '0'); };

		if (d.toDateString() === now.toDateString()) {
			return pad(d.getHours()) + ':' + pad(d.getMinutes());
		}
		if (d.getFullYear() === now.getFullYear()) {
			return months[d.getMonth()] + ' ' + d.getDate();
		}
		return months[d.getMonth()] + ' ' + d.getDate() + ' ' + d.getFullYear();
	},

};
