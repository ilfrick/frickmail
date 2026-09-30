// Unit tests for the v1 message/folder action module. Run with:
//   node --test "frickmail-ui/v1/js/*.test.mjs"

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import {
	actionErrorMessage,
	buildActionSeed,
	clearFolder,
	copyMessages,
	deleteMessages,
	findSpecialFolder,
	markFolderRead,
	moveMessages,
	renderFolderTargets,
	renderFolderToolbar,
	renderMessageToolbar,
	setMessageFlag
} from './actions.js';

const folders = {
	folders: [
		{ name: 'INBOX', full_name: 'INBOX', unread_emails: 3 },
		{ name: 'Archive', full_name: 'Archive', unread_emails: 0 },
		{ name: 'Junk', full_name: 'Junk', unread_emails: 0 },
		{ name: 'Trash', full_name: 'Trash', unread_emails: 1 },
		{ name: 'Sent', full_name: 'Sent', unread_emails: 0 }
	]
};

describe('findSpecialFolder', () => {
	it('matches a special folder case-insensitively', () => {
		assert.equal(findSpecialFolder(folders, ['junk']), 'Junk');
		assert.equal(findSpecialFolder(folders, ['archive']), 'Archive');
		assert.equal(findSpecialFolder(folders, ['trash']), 'Trash');
	});

	it('sees through a provider prefix such as [Gmail]/Spam', () => {
		const nested = {
			folders: [{ name: 'Spam', full_name: '[Gmail]/Spam' }]
		};
		assert.equal(findSpecialFolder(nested, ['spam']), '[Gmail]/Spam');
	});

	it('returns an empty string when nothing matches', () => {
		assert.equal(findSpecialFolder(folders, ['nowhere']), '');
		assert.equal(findSpecialFolder(undefined, ['junk']), '');
		assert.equal(findSpecialFolder({ folders: [] }, ['junk']), '');
	});
});

describe('renderFolderTargets', () => {
	it('offers every folder except the current one', () => {
		const html = renderFolderTargets(folders, 'INBOX');
		assert.match(html, /<select data-fm="target"/);
		assert.ok(html.includes('value="Archive"'));
		assert.ok(!html.includes('value="INBOX"'));
	});

	it('annotates unread counts', () => {
		assert.ok(renderFolderTargets(folders, 'Archive').includes('INBOX (3)'));
	});

	it('returns an empty string when there is nowhere to go', () => {
		assert.equal(renderFolderTargets({ folders: [{ name: 'INBOX', full_name: 'INBOX' }] }, 'INBOX'), '');
		assert.equal(renderFolderTargets(folders, ''), renderFolderTargets(folders, ''));
	});

	it('escapes folder names', () => {
		const hostile = {
			folders: [{ name: '<img src=x>', full_name: 'Evil"Folder' }]
		};
		const html = renderFolderTargets(hostile, 'INBOX');
		assert.ok(html.includes('value="Evil&quot;Folder"'));
		assert.ok(!html.includes('<img src=x>'));
	});
});

describe('renderMessageToolbar', () => {
	it('offers the core single-message actions', () => {
		const html = renderMessageToolbar({ folder: 'INBOX', folders, message: {} });
		for (const action of ['reply', 'reply-all', 'forward', 'flag', 'unread', 'move', 'copy', 'delete']) {
			assert.ok(html.includes('data-action="' + action + '"'), 'missing ' + action);
		}
	});

	it('reflects the flagged state in the button label', () => {
		const starred = renderMessageToolbar({
			folder: 'INBOX',
			folders,
			message: { flags: ['\\seen', '\\flagged'] }
		});
		assert.ok(starred.includes('>Unstar<'));

		const plain = renderMessageToolbar({
			folder: 'INBOX',
			folders,
			message: { flags: ['\\seen'] }
		});
		assert.ok(plain.includes('>Star<'));
	});

	it('offers Archive and Spam only when such folders exist', () => {
		const withSpecials = renderMessageToolbar({ folder: 'INBOX', folders, message: {} });
		assert.ok(withSpecials.includes('data-action="archive"'));
		assert.ok(withSpecials.includes('data-action="spam"'));

		const plain = renderMessageToolbar({
			folder: 'INBOX',
			folders: { folders: [{ name: 'INBOX', full_name: 'INBOX' }] },
			message: {}
		});
		assert.ok(!plain.includes('data-action="archive"'));
		assert.ok(!plain.includes('data-action="spam"'));
		assert.ok(!plain.includes('data-fm="target"'));
	});

	it('does not offer to move a message into the folder it is in', () => {
		const html = renderMessageToolbar({ folder: 'Archive', folders, message: {} });
		assert.ok(!html.includes('data-action="archive"'));
		assert.ok(html.includes('data-action="spam"'));
	});

	it('escapes the current folder name', () => {
		const hostile = { folder: 'Evil"Folder', folders, message: {} };
		const html = renderMessageToolbar(hostile);
		assert.ok(!html.includes('data-fm="target" aria-label="Destination folder"><option value="Evil"'));
	});
});

describe('renderFolderToolbar', () => {
	it('shows the folder, its unread count and the folder actions', () => {
		const html = renderFolderToolbar({
			folder: 'INBOX',
			folders,
			folderData: { unread_emails: 2 }
		});
		assert.ok(html.includes('>INBOX<'));
		assert.ok(html.includes('2 unread'));
		assert.ok(html.includes('data-action="seen-all"'));
		assert.ok(html.includes('data-action="refresh"'));
		// Emptying a non-trash folder is not offered.
		assert.ok(!html.includes('data-action="empty"'));
	});

	it('offers Empty folder only in the trash', () => {
		const html = renderFolderToolbar({
			folder: 'Trash',
			folders,
			folderData: { unread_emails: 0 }
		});
		assert.ok(html.includes('data-action="empty"'));
		assert.ok(html.includes('>Trash<'));
	});

	it('leaves the unread label empty when the folder is read', () => {
		const html = renderFolderToolbar({ folder: 'Sent', folders, folderData: { unread_emails: 0 } });
		assert.ok(html.includes('<span data-fm="unread-count"></span>'));
	});

	it('escapes the folder name', () => {
		const html = renderFolderToolbar({ folder: '<b>x</b>', folders, folderData: {} });
		assert.ok(html.includes('&lt;b&gt;x&lt;/b&gt;'));
		assert.ok(!html.includes('<b>x</b>'));
	});
});

describe('buildActionSeed', () => {
	const message = {
		subject: 'Invoice for August',
		from: [{ name: 'Giulia Rossi', email: 'giulia@example.com' }],
		cc: [{ name: 'Accounts', email: 'accounts@example.com' }],
		plain: 'Hello,\n\nthe invoice is attached.'
	};

	it('builds a reply to the sender with a quoted body', () => {
		const seed = buildActionSeed(message, 'reply');
		assert.equal(seed.to, 'Giulia Rossi <giulia@example.com>');
		assert.equal(seed.subject, 'Re: Invoice for August');
		assert.ok(seed.body.includes('> the invoice is attached.'));
		assert.ok(!seed.body.includes('accounts@example.com'));
	});

	it('builds a reply-all to sender and cc', () => {
		const seed = buildActionSeed(message, 'reply-all');
		assert.ok(seed.to.includes('giulia@example.com'));
		assert.ok(seed.to.includes('accounts@example.com'));
	});

	it('builds a forward with an empty recipient', () => {
		const seed = buildActionSeed(message, 'forward');
		assert.equal(seed.to, '');
		assert.equal(seed.subject, 'Fwd: Invoice for August');
		assert.equal(seed.body, 'Hello,\n\nthe invoice is attached.');
	});

	it('does not stack Re:/Fwd: prefixes', () => {
		assert.equal(buildActionSeed({ subject: 'Re: Already' }, 'reply').subject, 'Re: Already');
		assert.equal(buildActionSeed({ subject: 'Fwd: Already' }, 'forward').subject, 'Fwd: Already');
		assert.equal(buildActionSeed({ subject: '' }, 'reply').subject, 'Re:');
		assert.equal(buildActionSeed({ subject: '   ' }, 'forward').subject, 'Fwd:');
	});

	it('degrades honestly when there is no plain-text part', () => {
		const seed = buildActionSeed({ subject: 'Html only', html: '<p>hi</p>' }, 'reply');
		assert.ok(seed.body.includes('no plain-text part'));
		assert.ok(!seed.body.includes('<p>hi</p>'));
	});

	it('ignores unknown modes', () => {
		assert.deepEqual(buildActionSeed(message, 'archive'), {});
		assert.deepEqual(buildActionSeed(message, undefined), {});
	});
});

describe('actionErrorMessage', () => {
	it('prefers the real error text', () => {
		assert.equal(actionErrorMessage({ message: 'Mail server rejected the request' }, 'x'), 'Mail server rejected the request');
	});

	it('falls back when the error carries nothing useful', () => {
		assert.equal(actionErrorMessage(null, 'Delete failed.'), 'Delete failed.');
		assert.equal(actionErrorMessage({ message: '   ' }, ''), 'Action failed.');
	});
});

describe('action I/O wrappers', () => {
	function recordingApi() {
		const calls = [];
		return {
			calls,
			async request(method, path, options) {
				calls.push({ method, path, body: options && options.body });
				return { version: 'v1', data: { updated: 1 } };
			}
		};
	}

	it('posts each action to its v1 route', async () => {
		const api = recordingApi();
		await setMessageFlag(api, { folder: 'INBOX', uids: [1], flag: 'seen', set: false });
		await moveMessages(api, { folder: 'INBOX', uids: [1], to_folder: 'Archive' });
		await copyMessages(api, { folder: 'INBOX', uids: [1], to_folder: 'Archive' });
		await deleteMessages(api, { folder: 'INBOX', uids: [1] });
		await markFolderRead(api, { folder: 'INBOX' });
		await clearFolder(api, { folder: 'Trash' });
		assert.deepEqual(
			api.calls.map((call) => call.method + ' ' + call.path),
			[
				'POST /messages/flags',
				'POST /messages/move',
				'POST /messages/copy',
				'POST /messages/delete',
				'POST /messages/seen-all',
				'POST /folders/clear'
			]
		);
		assert.equal(api.calls[0].body.flag, 'seen');
		assert.equal(api.calls[0].body.set, false);
	});
});
