// Frickmail v1 calendar screen (Phase 9).
//
// Pure rendering over the v1 calendar shapes plus thin loaders. Event and
// calendar objects pass through the shared `escapeHtml`; every string the
// server returns is untrusted provider data. Month math is pure and
// unit-tested; the grid renders Monday-first like the legacy plugin.

import { escapeHtml } from './mailbox.js';

/// Shifts a {year, month} pair (month 1-12) by delta months. Pure.
export function addMonths(view, delta) {
	let year = Number(view && view.year) || 1970;
	let month = Number(view && view.month) || 1;
	const total = (year * 12 + (month - 1)) + (Number(delta) || 0);
	return { year: Math.floor(total / 12), month: (total % 12) + 1 };
}

/// Human month title, e.g. "September 2026". Pure.
export function formatMonthTitle(view) {
	const names = [
		'January', 'February', 'March', 'April', 'May', 'June',
		'July', 'August', 'September', 'October', 'November', 'December'
	];
	const month = Number(view && view.month) || 1;
	return names[month - 1] + ' ' + (Number(view && view.year) || 1970);
}

/// Monday-first week grid covering a month: each cell is
/// {date:'YYYY-MM-DD', day:number, inMonth:boolean}. Pure.
export function monthGrid(year, month) {
	const first = new Date(Date.UTC(year, month - 1, 1));
	// Monday-first offset: Sunday (0) trails the previous week.
	const lead = (first.getUTCDay() + 6) % 7;
	const daysInMonth = new Date(Date.UTC(year, month, 0)).getUTCDate();
	const prevDays = new Date(Date.UTC(year, month - 1, 0)).getUTCDate();
	const cells = [];
	for (let index = 0; index < 42; index++) {
		const dayNumber = index - lead + 1;
		if (dayNumber < 1) {
			const day = prevDays + dayNumber;
			const prior = addMonths({ year, month }, -1);
			cells.push({ date: isoDate(prior.year, prior.month, day), day, inMonth: false });
		} else if (dayNumber > daysInMonth) {
			const day = dayNumber - daysInMonth;
			const next = addMonths({ year, month }, 1);
			cells.push({ date: isoDate(next.year, next.month, day), day, inMonth: false });
		} else {
			cells.push({ date: isoDate(year, month, dayNumber), day: dayNumber, inMonth: true });
		}
	}
	return cells;
}

/// Zero-padded ISO day. Pure.
export function isoDate(year, month, day) {
	const pad = (value) => String(value).padStart(2, '0');
	return year + '-' + pad(month) + '-' + pad(day);
}

/// Groups events by their start day (first 10 chars of `start`). Pure.
export function groupEventsByDate(events) {
	const groups = {};
	for (const event of events || []) {
		const day = String((event && event.start) || '').slice(0, 10);
		if (!day) {
			continue;
		}
		if (!groups[day]) {
			groups[day] = [];
		}
		groups[day].push(event);
	}
	return groups;
}

/// Renders the calendar checkbox list for a `GET /calendars` data payload.
/// Pure.
export function renderCalendarList(data, selectedIds) {
	const calendars = data && Array.isArray(data.calendars) ? data.calendars : [];
	const selected = new Set(selectedIds || []);
	if (!calendars.length) {
		return '<p data-fm="empty">No calendars.</p>';
	}
	return '<ul data-fm="calendars">'
		+ calendars.map((calendar) => {
			const id = String(calendar && calendar.id ? calendar.id : '');
			const name = escapeHtml(calendar && calendar.name ? calendar.name : id || '(unnamed)');
			const checked = selected.has(id) ? ' checked' : '';
			return '<li><label><input type="checkbox" data-fm="calendar" value="'
				+ escapeHtml(id) + '"' + checked + '> ' + name + '</label></li>';
		}).join('')
		+ '</ul>';
}

/// Renders one event chip inside a grid cell. Pure.
export function renderEventChip(event) {
	const title = escapeHtml(event && event.title ? event.title : '(no title)');
	const id = escapeHtml(event && event.id ? String(event.id) : '');
	return '<button type="button" data-fm="event" data-id="' + id + '">' + title + '</button>';
}

/// Renders the Monday-first month grid with event chips. Pure.
export function renderMonthGrid(view, eventsByDate) {
	const cells = monthGrid(view.year, view.month);
	const groups = eventsByDate || {};
	let html = '<table data-fm="grid"><thead><tr>'
		+ ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun']
			.map((day) => '<th scope="col">' + day + '</th>').join('')
		+ '</tr></thead><tbody>';
	for (let week = 0; week < 6; week++) {
		html += '<tr>';
		for (let weekday = 0; weekday < 7; weekday++) {
			const cell = cells[week * 7 + weekday];
			const dayEvents = groups[cell.date] || [];
			html += '<td data-fm="day" data-date="' + cell.date + '"'
				+ (cell.inMonth ? '' : ' data-outside="1"') + '>'
				+ '<span data-fm="day-number">' + cell.day + '</span>'
				+ dayEvents.map(renderEventChip).join('')
				+ '</td>';
		}
		html += '</tr>';
	}
	return html + '</tbody></table>';
}

/// Renders the agenda list for a `GET /calendars/events` data payload.
/// Pure.
export function renderEventList(data) {
	const events = data && Array.isArray(data.events) ? data.events : [];
	if (!events.length) {
		return '<p data-fm="empty">No events in this range.</p>';
	}
	return '<ul data-fm="events">'
		+ events.map((event) => {
			const id = escapeHtml(event && event.id ? String(event.id) : '');
			const title = escapeHtml(event && event.title ? event.title : '(no title)');
			const start = escapeHtml(event && event.start ? String(event.start) : '');
			return '<li data-fm="event-row" data-id="' + id + '">'
				+ '<span data-fm="event-start">' + start + '</span> '
				+ '<span data-fm="event-title">' + title + '</span></li>';
		}).join('')
		+ '</ul>';
}

/// Renders the event editor. Without an event it creates; with one it edits
/// (and offers delete). `calendars` feeds the calendar select. Pure.
export function renderEventEditor(event, calendars) {
	const current = event || {};
	const id = current.id ? String(current.id) : '';
	const title = current.title ? String(current.title) : '';
	const start = current.start ? String(current.start) : '';
	const end = current.end ? String(current.end) : '';
	const calendar = current._calendar ? String(current._calendar) : 'primary';
	const description = current.description ? String(current.description) : '';
	const location = current.location ? String(current.location) : '';
	const allDay = !!current.allDay;
	const options = (calendars || []).map((entry) => {
		const value = escapeHtml(String(entry.id || ''));
		const name = escapeHtml(entry.name ? String(entry.name) : String(entry.id || ''));
		return '<option value="' + value + '"'
			+ (String(entry.id) === calendar ? ' selected' : '') + '>' + name + '</option>';
	}).join('');
	return '<form data-fm="editor">'
		+ '<input type="hidden" data-fm="id" value="' + escapeHtml(id) + '">'
		+ '<label>Title <input data-fm="title" value="' + escapeHtml(title) + '"></label>'
		+ '<label>Start <input data-fm="start" value="' + escapeHtml(start) + '"></label>'
		+ '<label>End <input data-fm="end" value="' + escapeHtml(end) + '"></label>'
		+ '<label>Calendar <select data-fm="calendar">' + options + '</select></label>'
		+ '<label>Description <input data-fm="description" value="' + escapeHtml(description) + '"></label>'
		+ '<label>Location <input data-fm="location" value="' + escapeHtml(location) + '"></label>'
		+ '<label><input type="checkbox" data-fm="all-day"' + (allDay ? ' checked' : '') + '> All day</label>'
		+ '<button type="submit" data-fm="save">' + (id ? 'Update event' : 'Create event') + '</button>'
		+ (id ? ' <button type="button" data-fm="delete">Delete</button>' : '')
		+ '</form>';
}

/// Reads the editor form back into a `POST /calendars/events` payload.
/// Takes a stub-able root like the compose/settings collectors. Pure.
export function collectEventPayload(root, accountId) {
	const read = (selector) => {
		const field = root.querySelector(selector);
		if (!field) {
			return '';
		}
		if (field.type === 'checkbox') {
			return field.checked;
		}
		return field.value;
	};
	const payload = {
		title: read('[data-fm="title"]'),
		start: read('[data-fm="start"]'),
		end: read('[data-fm="end"]'),
		calendar: read('[data-fm="calendar"]'),
		description: read('[data-fm="description"]'),
		location: read('[data-fm="location"]'),
		all_day: !!read('[data-fm="all-day"]')
	};
	const id = read('[data-fm="id"]');
	if (id) {
		payload.id = id;
	}
	if (accountId !== undefined && accountId !== null && accountId !== '') {
		payload.account_id = accountId;
	}
	return payload;
}

/// Loads calendars through the client. Thin I/O wrapper.
export async function loadCalendars(api, accountId) {
	const query = {};
	if (accountId !== undefined && accountId !== null && accountId !== '') {
		query.account_id = accountId;
	}
	return api.request('GET', '/calendars', { query });
}

/// Loads merged events through the client. Thin I/O wrapper.
export async function loadEvents(api, options) {
	const settings = options || {};
	const query = {};
	if (settings.accountId !== undefined && settings.accountId !== null && settings.accountId !== '') {
		query.account_id = settings.accountId;
	}
	if (Array.isArray(settings.calendarIds) && settings.calendarIds.length) {
		query.calendar_ids = settings.calendarIds.join(',');
	}
	if (settings.start) {
		query.start = settings.start;
	}
	if (settings.end) {
		query.end = settings.end;
	}
	return api.request('GET', '/calendars/events', { query });
}

/// Saves (creates or updates) an event through the client. Thin I/O wrapper.
export async function saveEvent(api, payload) {
	return api.request('POST', '/calendars/events', { body: payload });
}

/// Deletes an event through the client. Thin I/O wrapper.
export async function deleteEvent(api, options) {
	const settings = options || {};
	const query = { id: settings.id };
	if (settings.accountId !== undefined && settings.accountId !== null && settings.accountId !== '') {
		query.account_id = settings.accountId;
	}
	if (settings.calendar) {
		query.calendar = settings.calendar;
	}
	return api.request('DELETE', '/calendars/events', { query });
}
