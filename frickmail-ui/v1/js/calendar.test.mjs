// Unit tests for the v1 calendar screen (Phase 9). Run with:
//   node --test "frickmail-ui/v1/js/*.test.mjs"

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import {
	addMonths,
	collectEventPayload,
	deleteEvent,
	formatMonthTitle,
	groupEventsByDate,
	isoDate,
	loadCalendars,
	loadEvents,
	monthGrid,
	renderCalendarList,
	renderEventChip,
	renderEventEditor,
	renderEventList,
	renderMonthGrid,
	saveEvent
} from './calendar.js';

describe('addMonths', () => {
	it('rolls over year boundaries', () => {
		assert.deepEqual(addMonths({ year: 2026, month: 12 }, 1), { year: 2027, month: 1 });
		assert.deepEqual(addMonths({ year: 2026, month: 1 }, -1), { year: 2025, month: 12 });
		assert.deepEqual(addMonths({ year: 2026, month: 9 }, 0), { year: 2026, month: 9 });
	});

	it('falls back on missing input', () => {
		assert.deepEqual(addMonths(null, 1), { year: 1970, month: 2 });
	});
});

describe('formatMonthTitle', () => {
	it('names the month', () => {
		assert.equal(formatMonthTitle({ year: 2026, month: 9 }), 'September 2026');
		assert.equal(formatMonthTitle({ year: 2026, month: 1 }), 'January 2026');
	});
});

describe('isoDate', () => {
	it('zero-pads', () => {
		assert.equal(isoDate(2026, 9, 2), '2026-09-02');
		assert.equal(isoDate(2026, 12, 31), '2026-12-31');
	});
});

describe('monthGrid', () => {
	it('covers September 2026 Monday-first in 42 cells', () => {
		// 2026-09-01 is a Tuesday: one August lead cell, then the 1st.
		const cells = monthGrid(2026, 9);
		assert.equal(cells.length, 42);
		assert.deepEqual(cells[0], { date: '2026-08-31', day: 31, inMonth: false });
		assert.deepEqual(cells[1], { date: '2026-09-01', day: 1, inMonth: true });
		assert.equal(cells.filter((cell) => cell.inMonth).length, 30);
		const last = cells[41];
		assert.equal(last.inMonth, false);
		assert.ok(last.date > '2026-09-30');
	});

	it('starts clean months on Monday without lead cells', () => {
		// 2026-06-01 is a Monday.
		const cells = monthGrid(2026, 6);
		assert.deepEqual(cells[0], { date: '2026-06-01', day: 1, inMonth: true });
	});
});

describe('groupEventsByDate', () => {
	it('groups by start day and skips dateless events', () => {
		const groups = groupEventsByDate([
			{ id: 'a', start: '2026-09-02T09:00:00Z' },
			{ id: 'b', start: '2026-09-02T10:00:00Z' },
			{ id: 'c', start: '2026-09-03' },
			{ id: 'd' }
		]);
		assert.deepEqual(Object.keys(groups).sort(), ['2026-09-02', '2026-09-03']);
		assert.equal(groups['2026-09-02'].length, 2);
	});

	it('tolerates missing input', () => {
		assert.deepEqual(groupEventsByDate(null), {});
	});
});

describe('renderCalendarList', () => {
	it('renders empty payloads as a notice', () => {
		assert.ok(renderCalendarList({ calendars: [] }).includes('data-fm="empty"'));
		assert.ok(renderCalendarList(null).includes('data-fm="empty"'));
	});

	it('renders checkboxes with selection and escaping', () => {
		const html = renderCalendarList(
			{ calendars: [{ id: 'primary', name: 'Main' }, { id: 'work', name: '<b>W</b>' }] },
			['work']
		);
		assert.equal((html.match(/data-fm="calendar"/g) || []).length, 2);
		assert.ok(html.includes('value="work" checked'));
		assert.ok(!html.includes('value="primary" checked'));
		assert.ok(!html.includes('<b>W</b>'));
		assert.ok(html.includes('&lt;b&gt;W&lt;/b&gt;'));
	});
});

describe('renderEventChip', () => {
	it('escapes titles and ids', () => {
		const html = renderEventChip({ id: 'a"b', title: '<Standup>' });
		assert.ok(!html.includes('<Standup>'));
		assert.ok(html.includes('&lt;Standup&gt;'));
		assert.ok(html.includes('data-id="a&quot;b"'));
	});

	it('falls back on missing fields', () => {
		assert.ok(renderEventChip({}).includes('(no title)'));
	});
});

describe('renderMonthGrid', () => {
	it('renders six weeks with chips on event days', () => {
		const html = renderMonthGrid(
			{ year: 2026, month: 9 },
			{ '2026-09-02': [{ id: 'primary:ev-1', title: 'Standup' }] }
		);
		assert.equal((html.match(/<tr>/g) || []).length, 7);
		assert.equal((html.match(/data-fm="day"/g) || []).length, 42);
		assert.ok(html.includes('data-date="2026-09-02"'));
		assert.ok(html.includes('data-id="primary:ev-1"'));
		assert.ok(html.includes('Standup'));
		assert.ok(html.includes('data-outside="1"'));
	});
});

describe('renderEventList', () => {
	it('renders empty payloads as a notice', () => {
		assert.ok(renderEventList({ events: [] }).includes('data-fm="empty"'));
		assert.ok(renderEventList(null).includes('data-fm="empty"'));
	});

	it('renders rows with escaping', () => {
		const html = renderEventList({
			events: [{ id: 'x', title: '<b>Hi</b>', start: '2026-09-02T09:00:00Z' }]
		});
		assert.ok(html.includes('data-id="x"'));
		assert.ok(html.includes('&lt;b&gt;Hi&lt;/b&gt;'));
		assert.ok(html.includes('2026-09-02T09:00:00Z'));
	});
});

describe('renderEventEditor', () => {
	it('creates without an id or delete button', () => {
		const html = renderEventEditor(null, [{ id: 'primary', name: 'Main' }]);
		assert.ok(html.includes('Create event'));
		assert.ok(!html.includes('data-fm="delete"'));
		assert.ok(html.includes('<option value="primary" selected>'));
	});

	it('edits with prefilled values, delete, and escaping', () => {
		const html = renderEventEditor(
		 {
				id: 'primary:ev-1',
				_calendar: 'work',
				title: '<Party>',
				start: '2026-09-02T20:00:00Z',
				end: '2026-09-02T22:00:00Z',
				allDay: true
			},
			[{ id: 'primary', name: 'Main' }, { id: 'work', name: 'Work' }]
		);
		assert.ok(html.includes('Update event'));
		assert.ok(html.includes('data-fm="delete"'));
		assert.ok(html.includes('&lt;Party&gt;'));
		assert.ok(html.includes('<option value="work" selected>'));
		assert.ok(html.includes('data-fm="all-day" checked'));
	});
});

describe('collectEventPayload', () => {
	const stubRoot = (values) => ({
		querySelector: (selector) => {
			if (!(selector in values)) {
				return null;
			}
			const value = values[selector];
			if (typeof value === 'boolean') {
				return { type: 'checkbox', checked: value };
			}
			return { type: 'text', value };
		}
	});

	it('reads the form and post id', () => {
		const payload = collectEventPayload(stubRoot({
			'[data-fm="id"]': 'primary:ev-1',
			'[data-fm="title"]': 'Party',
			'[data-fm="start"]': '2026-09-02T20:00:00Z',
			'[data-fm="end"]': '2026-09-02T22:00:00Z',
			'[data-fm="calendar"]': 'work',
			'[data-fm="description"]': '',
			'[data-fm="location"]': 'Home',
			'[data-fm="all-day"]': true
		}), 7);
		assert.equal(payload.id, 'primary:ev-1');
		assert.equal(payload.title, 'Party');
		assert.equal(payload.calendar, 'work');
		assert.equal(payload.all_day, true);
		assert.equal(payload.account_id, 7);
	});

	it('omits empty id and account', () => {
		const payload = collectEventPayload(stubRoot({
			'[data-fm="id"]': '',
			'[data-fm="title"]': 'New'
		}), '');
		assert.ok(!('id' in payload));
		assert.ok(!('account_id' in payload));
		assert.equal(payload.title, 'New');
	});
});

describe('loaders', () => {
	it('loadCalendars passes the account id', async () => {
		let seen = null;
		const api = { request: async (method, path, options) => { seen = { method, path, options }; return null; } };
		await loadCalendars(api, 9);
		assert.deepEqual(seen, { method: 'GET', path: '/calendars', options: { query: { account_id: 9 } } });
	});

	it('loadEvents joins calendar ids', async () => {
		let seen = null;
		const api = { request: async (method, path, options) => { seen = { method, path, options }; return null; } };
		await loadEvents(api, { accountId: 9, calendarIds: ['primary', 'work'], start: 'a', end: 'b' });
		assert.equal(seen.method, 'GET');
		assert.equal(seen.path, '/calendars/events');
		assert.equal(seen.options.query.calendar_ids, 'primary,work');
		assert.equal(seen.options.query.start, 'a');
	});

	it('saveEvent posts the payload', async () => {
		let seen = null;
		const api = { request: async (method, path, options) => { seen = { method, path, options }; return null; } };
		await saveEvent(api, { title: 'X' });
		assert.deepEqual(seen, { method: 'POST', path: '/calendars/events', options: { body: { title: 'X' } } });
	});

	it('deleteEvent deletes with the id', async () => {
		let seen = null;
		const api = { request: async (method, path, options) => { seen = { method, path, options }; return null; } };
		await deleteEvent(api, { id: 'primary:ev-1', calendar: 'primary' });
		assert.equal(seen.method, 'DELETE');
		assert.equal(seen.path, '/calendars/events');
		assert.equal(seen.options.query.id, 'primary:ev-1');
		assert.equal(seen.options.query.calendar, 'primary');
	});
});
