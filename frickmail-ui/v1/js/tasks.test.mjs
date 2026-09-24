// Unit tests for the v1 tasks screen (Phase 9). Run with:
//   node --test "frickmail-ui/v1/js/*.test.mjs"

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import {
	addTask,
	collectTaskPayload,
	deleteTask,
	loadTasks,
	renderTaskForm,
	renderTasks,
	renderTasksFilter,
	renderTaskRow,
	setTaskCompleted
} from './tasks.js';

describe('renderTaskRow', () => {
	it('escapes titles and marks completion', () => {
		const html = renderTaskRow({ id: 5, title: '<b>Hi</b>', completed: true });
		assert.ok(!html.includes('<b>'));
		assert.ok(html.includes('&lt;b&gt;Hi&lt;/b&gt;'));
		assert.ok(html.includes('data-id="5"'));
		assert.ok(html.includes('data-done="1"'));
		assert.ok(html.includes('✓'));
	});

	it('falls back on missing fields', () => {
		const html = renderTaskRow({});
		assert.ok(html.includes('(untitled task)'));
		assert.ok(html.includes('○'));
	});

	it('renders toggle and delete buttons', () => {
		const html = renderTaskRow({ id: 7, title: 'Write', completed: false });
		assert.ok(html.includes('data-fm="toggle"'));
		assert.ok(html.includes('>Done</button>'));
		assert.ok(html.includes('data-fm="delete"'));
		const done = renderTaskRow({ id: 8, title: 'Done', completed: true });
		assert.ok(done.includes('>Undo</button>'));
	});
});

describe('renderTasks', () => {
	it('renders empty lists as a notice', () => {
		assert.ok(renderTasks({ tasks: [] }).includes('data-fm="empty"'));
		assert.ok(renderTasks(null).includes('data-fm="empty"'));
	});

	it('renders every task exactly once', () => {
		const html = renderTasks({
			tasks: [
				{ id: 1, title: 'One', completed: false },
				{ id: 2, title: 'Two', completed: true }
			]
		});
		assert.equal((html.match(/data-fm="task"/g) || []).length, 2);
	});
});

describe('renderTaskForm', () => {
	it('renders the add form with a title field', () => {
		const html = renderTaskForm();
		assert.ok(html.includes('data-fm="add"'));
		assert.ok(html.includes('data-fm="title"'));
		assert.ok(html.includes('type="submit"'));
	});
});

describe('collectTaskPayload', () => {
	it('reads the title from the form', () => {
		const root = {
			querySelector: () => ({ value: 'Buy milk' })
		};
		assert.deepEqual(collectTaskPayload(root), { title: 'Buy milk' });
	});

	it('returns an empty title when the field is missing', () => {
		assert.deepEqual(collectTaskPayload({ querySelector: () => null }), { title: '' });
		assert.deepEqual(collectTaskPayload(null), { title: '' });
	});
});

describe('renderTasksFilter', () => {
	it('marks the active filter selected', () => {
		const html = renderTasksFilter('pending');
		assert.ok(html.includes('<option value="pending" selected>'));
		assert.ok(!html.includes('<option value="completed" selected>'));
	});

	it('defaults unknown filters to all', () => {
		const html = renderTasksFilter('bogus');
		assert.ok(html.includes('<option value="all" selected>'));
	});
});

describe('loadTasks', () => {
	it('passes the filter as a query parameter', async () => {
		let seen = null;
		const api = {
			request: async (method, path, options) => {
				seen = { method, path, options };
				return { tasks: [] };
			}
		};
		await loadTasks(api, 'pending');
		assert.equal(seen.method, 'GET');
		assert.equal(seen.path, '/tasks');
		assert.deepEqual(seen.options.query, { filter: 'pending' });
	});

	it('omits the filter for the full list', async () => {
		let seen = null;
		const api = {
			request: async (method, path, options) => {
				seen = { method, path, options };
				return { tasks: [] };
			}
		};
		await loadTasks(api);
		assert.deepEqual(seen.options.query, {});
	});
});

describe('task writes', () => {
	it('addTask posts the payload', async () => {
		let seen = null;
		const api = {
			request: async (method, path, options) => {
				seen = { method, path, options };
				return { id: 3 };
			}
		};
		const result = await addTask(api, { title: 'Buy milk' });
		assert.equal(seen.method, 'POST');
		assert.equal(seen.path, '/tasks');
		assert.deepEqual(seen.options.body, { title: 'Buy milk' });
		assert.deepEqual(result, { id: 3 });
	});

	it('setTaskCompleted posts the state to /tasks/{id}/completed', async () => {
		let seen = null;
		const api = {
			request: async (method, path, options) => {
				seen = { method, path, options };
				return { ok: true };
			}
		};
		await setTaskCompleted(api, 9, true);
		assert.equal(seen.method, 'POST');
		assert.equal(seen.path, '/tasks/9/completed');
		assert.deepEqual(seen.options.body, { completed: true });
	});

	it('deleteTask DELETEs /tasks/{id}', async () => {
		let seen = null;
		const api = {
			request: async (method, path, options) => {
				seen = { method, path, options };
				return { ok: true };
			}
		};
		await deleteTask(api, 12);
		assert.equal(seen.method, 'DELETE');
		assert.equal(seen.path, '/tasks/12');
	});
});