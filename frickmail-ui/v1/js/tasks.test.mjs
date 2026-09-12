// Unit tests for the v1 tasks screen (Phase 9). Run with:
//   node --test "frickmail-ui/v1/js/*.test.mjs"

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import { loadTasks, renderTasks, renderTasksFilter, renderTaskRow } from './tasks.js';

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
