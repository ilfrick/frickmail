// Frickmail v1 tasks screen (Phase 9).
//
// Pure rendering over the v1 `GET /tasks` shape plus thin loaders/actions.
// Task titles pass through the shared `escapeHtml`; notes/due dates are
// accepted by the API shape but intentionally not rendered in this slice.
// The row exposes complete/incomplete and delete buttons wired by the shell;
// the add form collects title only for now. All pure helpers are unit-tested.

import { escapeHtml } from './mailbox.js';

/// Renders one task row. Pure.
export function renderTaskRow(task) {
	const id = Number(task && task.id) || 0;
	const title = escapeHtml(task && task.title ? task.title : '(untitled task)');
	const done = !!(task && task.completed);
	return (
		'<li data-fm="task" data-id="' + id + '"' + (done ? ' data-done="1"' : '') + '>'
		+ '<span data-fm="state">' + (done ? '✓' : '○') + '</span>'
		+ '<span data-fm="title">' + title + '</span>'
		+ '<button type="button" data-fm="toggle" data-id="' + id + '">' + (done ? 'Undo' : 'Done') + '</button>'
		+ '<button type="button" data-fm="delete" data-id="' + id + '">Delete</button>'
		+ '</li>'
	);
}

/// Renders the task list for a `GET /tasks` data payload. Pure.
export function renderTasks(data) {
	const tasks = data && Array.isArray(data.tasks) ? data.tasks : [];
	if (!tasks.length) {
		return '<p data-fm="empty">No tasks.</p>';
	}
	return '<ul data-fm="tasks">' + tasks.map(renderTaskRow).join('') + '</ul>';
}

/// Renders the add-task form. Pure.
export function renderTaskForm() {
	return '<form data-fm="add">'
		+ '<label>New task <input data-fm="title" required></label>'
		+ '<button type="submit">Add</button>'
		+ '</form>';
}

/// Reads the add form into a `POST /tasks` payload. Takes a stub-able
/// root like the other collectors. Pure.
export function collectTaskPayload(root) {
	const field = root && root.querySelector ? root.querySelector('[data-fm="title"]') : null;
	return { title: field ? field.value : '' };
}

/// Renders the pending/completed filter control. Pure.
export function renderTasksFilter(active) {
	const current = active === 'completed' ? 'completed' : active === 'pending' ? 'pending' : 'all';
	const option = (value, label) => '<option value="' + value + '"'
		+ (value === current ? ' selected' : '') + '>' + label + '</option>';
	return (
		'<label data-fm="filter-label">Show '
		+ '<select data-fm="filter">'
		+ option('all', 'All')
		+ option('pending', 'Pending')
		+ option('completed', 'Completed')
		+ '</select></label>'
	);
}

/// Loads tasks through the client. Thin I/O wrapper.
export async function loadTasks(api, filter) {
	const query = {};
	if (filter && filter !== 'all') {
		query.filter = filter;
	}
	return api.request('GET', '/tasks', { query });
}

/// Adds a task through the client. Thin I/O wrapper.
export async function addTask(api, payload) {
	return api.request('POST', '/tasks', { body: payload });
}

/// Sets a task's completed state through the client. Thin I/O wrapper.
export async function setTaskCompleted(api, id, completed) {
	return api.request('POST', '/tasks/' + Number(id) + '/completed', { body: { completed: !!completed } });
}

/// Deletes a task through the client. Thin I/O wrapper.
export async function deleteTask(api, id) {
	return api.request('DELETE', '/tasks/' + Number(id));
}