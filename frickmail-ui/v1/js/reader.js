// Frickmail v1 reading-pane body preparation (Phase 9).
//
// The server hands us sanitized HTML from `GET /messages/{uid}`. Three things
// still have to happen client-side, and all three are pure string functions so
// they are unit-tested without a DOM:
//
//   * `cid:` image sources are rewritten to the inline attachment endpoint, so
//     embedded images (signatures, charts) actually render;
//   * remote (`http`/`https`) images are held back until the reader asks for
//     them, mirroring Thunderbird's "show remote content" bar;
//   * the fragment is wrapped in a small stylesheet so a plain email does not
//     inherit the app chrome and long lines wrap.
//
// The output is what the shell assigns to the sandboxed body frame's
// `srcdoc`. Nothing here trusts the message: URLs are built from our own
// prefix and the attachment metadata, never from the body.

import { API_PREFIX } from './api.js';
import { escapeHtml } from './mailbox.js';

/// Neutral 1x1 transparent GIF used in place of a blocked remote image.
const TRANSPARENT_GIF =
	'data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7';

/// Matches a `src=` attribute in any quoting style, capturing the value.
const SRC_PATTERN = /\bsrc\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/gi;

/// Normalizes a `cid:` reference (or a bare Content-ID) for lookup: strips the
/// scheme, angle brackets and surrounding whitespace, percent-decodes, and
/// lowercases. Pure.
export function normalizeCid(value) {
	let cid = String(value === undefined || value === null ? '' : value).trim();
	if (/^cid:/i.test(cid)) {
		cid = cid.slice(4);
	}
	cid = cid.trim().replace(/^</, '').replace(/>$/, '');
	try {
		cid = decodeURIComponent(cid);
	} catch (error) {
		void error;
	}
	return cid.trim().toLowerCase();
}

/// The MIME index of an attachment in either the camelCase payload shape or
/// the snake_case one. Pure.
function mimeIndexOf(attachment) {
	if (!attachment || typeof attachment !== 'object') {
		return '';
	}
	return String(attachment.mimeIndex || attachment.mime_index || '');
}

/// Builds the URL that streams one attachment part. `inline` selects the
/// inline disposition (for `cid:` images); anything else downloads.
/// Exported so the reader and its tests share one URL shape. Pure.
export function attachmentUrl(attachment, context, options) {
	const settings = options || {};
	const settingsContext = context || {};
	const index = mimeIndexOf(attachment);
	const params = new URLSearchParams();
	params.set('folder', String(settingsContext.folder || ''));
	if (settingsContext.accountId) {
		params.set('account_id', String(settingsContext.accountId));
	}
	const name = attachment && (attachment.fileName || attachment.file_name);
	if (name) {
		params.set('name', String(name));
	}
	const type = attachment && (attachment.mimeType || attachment.mime_type);
	if (type) {
		params.set('type', String(type));
	}
	if (settings.inline) {
		params.set('inline', '1');
	}
	return (
		API_PREFIX
		+ '/messages/'
		+ Number(settingsContext.uid)
		+ '/attachments/'
		+ encodeURIComponent(index)
		+ '?'
		+ params.toString()
	);
}

/// Maps normalized Content-IDs to their attachment. Pure.
export function cidAttachmentMap(attachments) {
	const map = new Map();
	if (!Array.isArray(attachments)) {
		return map;
	}
	for (const attachment of attachments) {
		if (!attachment || typeof attachment !== 'object') {
			continue;
		}
		const cid = normalizeCid(attachment.cId || attachment.c_id);
		if (cid && !map.has(cid)) {
			map.set(cid, attachment);
		}
	}
	return map;
}

/// Applies `mapper` to every `src=` value, leaving the attribute untouched
/// when the mapper returns `null`. Pure.
function replaceSrcAttributes(html, mapper) {
	return String(html || '').replace(SRC_PATTERN, (match, doubleQuoted, singleQuoted, unquoted) => {
		const value = doubleQuoted !== undefined ? doubleQuoted : singleQuoted !== undefined ? singleQuoted : unquoted;
		const replacement = mapper(value);
		if (replacement === null || replacement === undefined || replacement === value) {
			return match;
		}
		const quote = doubleQuoted !== undefined ? '"' : singleQuoted !== undefined ? "'" : '';
		return 'src=' + quote + replacement + quote;
	});
}

/// Rewrites `cid:` image sources to inline attachment URLs. A `cid` with no
/// matching attachment is left alone (the browser simply shows nothing, which
/// is the same as the old behaviour). Pure.
export function rewriteCidSources(html, attachments, context) {
	const map = cidAttachmentMap(attachments);
	if (!map.size) {
		return String(html || '');
	}
	return replaceSrcAttributes(html, (value) => {
		if (!/^\s*cid:/i.test(value)) {
			return null;
		}
		const attachment = map.get(normalizeCid(value));
		if (!attachment) {
			return null;
		}
		return attachmentUrl(attachment, context, { inline: true });
	});
}

/// Counts the distinct remote image sources in the body. Pure.
export function remoteImageCount(html) {
	const seen = new Set();
	replaceSrcAttributes(html, (value) => {
		if (/^\s*(https?:)?\/\//i.test(value)) {
			seen.add(value.trim());
		}
		return null;
	});
	return seen.size;
}

/// Replaces every remote image source with a transparent pixel, stashing the
/// original in `data-fm-remote-src` so it can be restored later. Returns the
/// rewritten HTML. Pure.
export function blockRemoteImages(html) {
	return replaceSrcAttributes(html, (value) => {
		if (!/^\s*(https?:)?\/\//i.test(value)) {
			return null;
		}
		return TRANSPARENT_GIF;
	}).replace(
		/<img\b([^>]*?)src=(["'])(data:image\/gif;base64,[^"']*)\2/gi,
		'<img$1src=$2$3$2 data-fm-remote-src="$3"'
	);
}

/// The reader stylesheet. Kept minimal and defensive: a light canvas (HTML
/// mail is authored for white), wrapped lines, and responsive media so a
/// fixed-width sender layout cannot force a horizontal scrollbar. Pure.
const READER_STYLE = [
	'html{background:#fff}',
	'body{margin:0;padding:14px 16px;font-family:system-ui,-apple-system,"Segoe UI",sans-serif;',
	'font-size:14px;line-height:1.5;color:#1a1c2b;word-wrap:break-word;overflow-wrap:anywhere}',
	'img{max-width:100%;height:auto}',
	'table{max-width:100%!important}',
	'blockquote{margin:0 0 0 1rem;padding-left:0.75rem;border-left:2px solid #c9cde0;color:#555a75}',
	'a{color:#3b6fd4}',
	'pre{white-space:pre-wrap;word-wrap:break-word}'
].join('');

/// Wraps a sanitized fragment into a full document for the body frame,
/// optionally holding back remote images. Returns `{document, blocked}` where
/// `blocked` is the number of distinct remote images withheld. Pure.
export function readerDocument(html, options) {
	const settings = options || {};
	let inner = String(html || '');
	let blocked = 0;
	if (!settings.allowRemote) {
		blocked = remoteImageCount(inner);
		if (blocked > 0) {
			inner = blockRemoteImages(inner);
		}
	}
	const document =
		'<!doctype html><html><head><meta charset="utf-8">'
		+ '<meta name="viewport" content="width=device-width, initial-scale=1">'
		+ '<base target="_blank">'
		+ '<style>' + READER_STYLE + '</style>'
		+ '</head><body>' + inner + '</body></html>';
	return { document, blocked };
}

/// Builds a safe `mailto:` href for the reply buttons. Pure.
export function mailtoHref(address) {
	return 'mailto:' + encodeURIComponent(String(address || ''));
}

/// Escapes an attachment display name for the card. Re-exported so callers do
/// not need two imports. Pure.
export function attachmentName(attachment) {
	const name = attachment && (attachment.fileName || attachment.file_name);
	return escapeHtml(name || 'attachment');
}
