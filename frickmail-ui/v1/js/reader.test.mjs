// Unit tests for the v1 reading-pane body preparation. Run with:
//   node --test "frickmail-ui/v1/js/*.test.mjs"

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import {
	attachmentUrl,
	cidAttachmentMap,
	blockRemoteImages,
	normalizeCid,
	readerDocument,
	remoteImageCount,
	rewriteCidSources
} from './reader.js';

const message = {
	folder: 'INBOX',
	uid: 42,
	accountId: 5
};

const attachments = [
	{ fileName: 'logo.png', mimeIndex: '1.2', mimeType: 'image/png', cId: '<logo@acme>' },
	{ fileName: 'chart.gif', mimeIndex: '3', mimeType: 'image/gif', cId: 'chart@acme' }
];

describe('normalizeCid', () => {
	it('strips the scheme, brackets and whitespace', () => {
		assert.equal(normalizeCid('cid:logo@acme'), 'logo@acme');
		assert.equal(normalizeCid('CID:<Logo@Acme>'), 'logo@acme');
		assert.equal(normalizeCid('  <logo@acme>  '), 'logo@acme');
		assert.equal(normalizeCid(''), '');
	});

	it('percent-decodes', () => {
		assert.equal(normalizeCid('cid:part%40acme'), 'part@acme');
	});
});

describe('attachmentUrl', () => {
	it('points at the attachment endpoint with folder and account', () => {
		const url = attachmentUrl(attachments[0], message, {});
		assert.ok(url.startsWith('/api/frickmail/v1/messages/42/attachments/1.2?'));
		assert.ok(url.includes('folder=INBOX'));
		assert.ok(url.includes('account_id=5'));
		assert.ok(url.includes('name=logo.png'));
		assert.ok(!url.includes('inline=1'));
	});

	it('adds inline=1 for inline rendering', () => {
		assert.ok(attachmentUrl(attachments[0], message, { inline: true }).includes('inline=1'));
	});
});

describe('cidAttachmentMap', () => {
	it('keys normalized Content-IDs', () => {
		const map = cidAttachmentMap(attachments);
		assert.equal(map.size, 2);
		assert.equal(map.get('logo@acme'), attachments[0]);
		assert.equal(map.get('chart@acme'), attachments[1]);
	});

	it('ignores malformed input', () => {
		assert.equal(cidAttachmentMap(null).size, 0);
		assert.equal(cidAttachmentMap([{}, { cId: '' }]).size, 0);
	});
});

describe('rewriteCidSources', () => {
	it('rewrites a matching cid in every quoting style', () => {
		const html = '<img src="cid:logo@acme"><img src=\'cid:chart@acme\'><img src=cid:logo@acme>';
		const out = rewriteCidSources(html, attachments, message);
		assert.ok(!out.includes('cid:logo@acme'));
		assert.ok(!out.includes('cid:chart@acme'));
		assert.ok(out.includes('attachments/1.2?'));
		assert.ok(out.includes('attachments/3?'));
		assert.ok(out.includes('inline=1'));
	});

	it('leaves an unknown cid alone', () => {
		const html = '<img src="cid:nope@x">';
		assert.equal(rewriteCidSources(html, attachments, message), html);
	});

	it('leaves non-cid sources alone', () => {
		const html = '<img src="https://a/b.png">';
		assert.equal(rewriteCidSources(html, attachments, message), html);
	});

	it('is a no-op without attachments', () => {
		const html = '<img src="cid:logo@acme">';
		assert.equal(rewriteCidSources(html, [], message), html);
	});
});

describe('remote images', () => {
	it('counts distinct remote sources, ignoring inline and cid', () => {
		const html =
			'<img src="https://a/1.png"><img src="http://b/2.png">'
			+ '<img src="https://a/1.png"><img src="cid:x"><img src="data:image/png;base64,AAAA">';
		assert.equal(remoteImageCount(html), 2);
	});

	it('blocks remote sources behind a placeholder and stashes the original', () => {
		const html = '<p>hi</p><img src="https://tracker.example/beacon.gif" alt="x">';
		const blocked = blockRemoteImages(html);
		assert.ok(!blocked.includes('tracker.example'));
		assert.ok(blocked.includes('data:image/gif;base64,'));
		assert.ok(blocked.includes('data-fm-remote-src='));
		assert.ok(blocked.includes('alt="x"'));
	});

	it('leaves non-remote images untouched', () => {
		const html = '<img src="cid:x"><img src="data:image/png;base64,AAAA">';
		assert.equal(blockRemoteImages(html), html);
	});
});

describe('readerDocument', () => {
	it('wraps a fragment and holds back remote images by default', () => {
		const html = '<img src="cid:logo@acme"><img src="https://remote/1.png">';
		const result = readerDocument(html, {});
		assert.equal(result.blocked, 1);
		assert.ok(result.document.startsWith('<!doctype html>'));
		assert.ok(result.document.includes('<meta charset="utf-8">'));
		assert.ok(result.document.includes('<style>'));
		assert.ok(!result.document.includes('https://remote/1.png'));
		assert.ok(result.document.includes('cid:logo@acme'));
	});

	it('keeps remote images when allowed', () => {
		const result = readerDocument('<img src="https://remote/1.png">', { allowRemote: true });
		assert.equal(result.blocked, 0);
		assert.ok(result.document.includes('https://remote/1.png'));
	});

	it('reports nothing blocked when there are no remote images', () => {
		const result = readerDocument('<p>plain</p>', {});
		assert.equal(result.blocked, 0);
		assert.ok(result.document.includes('<p>plain</p>'));
	});
});
