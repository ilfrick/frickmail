// Frickmail Tasks — simple to-do list backed by Postgres.
//
// Adds a "✓" nav icon (after the existing icons in ThemeSwitcher's fm-icon-nav).
// Click opens a full-screen overlay with All / Pending / Done tabs, a task list,
// and a quick-add form at the bottom.

(function () {
	'use strict';

	// ── State ─────────────────────────────────────────────────────────────────
	let overlayEl  = null;
	let navItemEl  = null;
	let isOpen     = false;
	let isLoading  = false;
	let tasks      = [];       // current list (filtered or all)
	let activeTab  = 'all';    // 'all' | 'pending' | 'completed'
	let editingId  = null;     // taskId being inline-edited, or null

	// ── Helpers ───────────────────────────────────────────────────────────────

	function escHtml(s) {
		return String(s || '')
			.replace(/&/g, '&amp;')
			.replace(/</g, '&lt;')
			.replace(/>/g, '&gt;')
			.replace(/"/g, '&quot;');
	}

	function fmToken() {
		return window.rl?.__frickmail_token || window.rl?.settings?.app?.('token') || '';
	}

	function formatDueDate(s) {
		if (!s) return '';
		// s is 'YYYY-MM-DD' (or a Postgres date string); keep it simple.
		const d = new Date(s + 'T00:00:00');
		if (isNaN(d)) return s;
		const months = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
		return months[d.getMonth()] + ' ' + d.getDate();
	}

	function isOverdue(dueDate, completed) {
		if (!dueDate || completed) return false;
		const d = new Date(dueDate + 'T00:00:00');
		const today = new Date();
		today.setHours(0, 0, 0, 0);
		return d < today;
	}

	// ── API calls ─────────────────────────────────────────────────────────────

	function apiCall(action, params, cb) {
		const r = window.rl;
		if (!r) { cb(null); return; }
		r.pluginRemoteRequest((iErr, oData) => {
			cb(oData?.Result || null);
		}, action, Object.assign({ XToken: fmToken() }, params), 15000);
	}

	// ── Overlay HTML ─────────────────────────────────────────────────────────

	function createOverlay() {
		const el = document.createElement('div');
		el.id = 'fm-tasks-overlay';
		el.setAttribute('role', 'dialog');
		el.setAttribute('aria-label', 'Tasks');
		el.style.cssText = [
			'position:fixed',
			'top:0','left:0','right:0','bottom:0',
			'z-index:9999',
			'display:flex',
			'flex-direction:column',
			'background:var(--fm-bg-panel,var(--background-color,#1e1e2e))',
			'color:var(--fm-text,var(--text-color,#cdd6f4))',
			'font-family:inherit',
			'overflow:hidden',
		].join(';');

		el.innerHTML = `
<div id="fm-tasks-header" style="display:flex;align-items:center;padding:10px 16px;border-bottom:1px solid rgba(255,255,255,.1);gap:8px;flex-shrink:0;">
	<span style="font-weight:700;font-size:1.05rem;flex:1">Tasks</span>
	<button id="fm-tasks-close" title="Close" style="background:none;border:none;color:inherit;cursor:pointer;font-size:1.3rem;padding:4px 8px;opacity:.8;">&times;</button>
</div>

<div id="fm-tasks-tabs" style="display:flex;gap:0;border-bottom:1px solid rgba(255,255,255,.1);flex-shrink:0;">
	<button class="fm-tasks-tab fm-tasks-tab-active" data-tab="all"       style="${tabStyle(true)}">All</button>
	<button class="fm-tasks-tab"                     data-tab="pending"   style="${tabStyle(false)}">Pending</button>
	<button class="fm-tasks-tab"                     data-tab="completed" style="${tabStyle(false)}">Done</button>
</div>

<div id="fm-tasks-list" style="flex:1;overflow-y:auto;padding:4px 0;"></div>

<div id="fm-tasks-add" style="border-top:1px solid rgba(255,255,255,.1);padding:10px 14px;display:flex;flex-direction:column;gap:8px;flex-shrink:0;">
	<div style="display:flex;gap:8px;align-items:center;">
		<input id="fm-tasks-title-input" type="text" placeholder="New task…"
			style="flex:1;padding:7px 10px;border-radius:6px;border:1px solid rgba(255,255,255,.15);background:rgba(255,255,255,.06);color:inherit;font-size:.9rem;outline:none;">
		<input id="fm-tasks-date-input" type="date"
			style="padding:7px 8px;border-radius:6px;border:1px solid rgba(255,255,255,.15);background:rgba(255,255,255,.06);color:inherit;font-size:.85rem;outline:none;cursor:pointer;">
		<button id="fm-tasks-add-btn"
			style="padding:7px 14px;border-radius:6px;border:none;background:var(--fm-accent,#7aa2f7);color:#fff;font-size:.9rem;cursor:pointer;white-space:nowrap;font-weight:600;">Add</button>
	</div>
	<textarea id="fm-tasks-notes-input" rows="2" placeholder="Notes (optional)…"
		style="resize:vertical;padding:7px 10px;border-radius:6px;border:1px solid rgba(255,255,255,.15);background:rgba(255,255,255,.06);color:inherit;font-size:.85rem;outline:none;display:none;"></textarea>
	<a id="fm-tasks-toggle-notes" href="#" style="font-size:.78rem;opacity:.6;align-self:flex-start;color:inherit;">+ notes</a>
</div>
`;

		document.body.appendChild(el);

		el.querySelector('#fm-tasks-close').addEventListener('click', closeOverlay);

		// Escape key
		el._keyHandler = (e) => { if (e.key === 'Escape') closeOverlay(); };
		document.addEventListener('keydown', el._keyHandler);

		// Tabs
		el.querySelectorAll('.fm-tasks-tab').forEach(btn => {
			btn.addEventListener('click', () => {
				activeTab = btn.dataset.tab;
				el.querySelectorAll('.fm-tasks-tab').forEach(b => {
					b.style.cssText = tabStyle(false);
					b.classList.remove('fm-tasks-tab-active');
				});
				btn.style.cssText = tabStyle(true);
				btn.classList.add('fm-tasks-tab-active');
				loadTasks();
			});
		});

		// Toggle notes
		el.querySelector('#fm-tasks-toggle-notes').addEventListener('click', (e) => {
			e.preventDefault();
			const ta = el.querySelector('#fm-tasks-notes-input');
			const link = el.querySelector('#fm-tasks-toggle-notes');
			if (ta.style.display === 'none') {
				ta.style.display = '';
				link.textContent = '- notes';
			} else {
				ta.style.display = 'none';
				ta.value = '';
				link.textContent = '+ notes';
			}
		});

		// Add button
		el.querySelector('#fm-tasks-add-btn').addEventListener('click', addTask);
		el.querySelector('#fm-tasks-title-input').addEventListener('keydown', (e) => {
			if (e.key === 'Enter') addTask();
		});

		return el;
	}

	function tabStyle(active) {
		return [
			'background:none',
			'border:none',
			'color:inherit',
			'cursor:pointer',
			'padding:9px 20px',
			'font-size:.88rem',
			'font-weight:' + (active ? '700' : '400'),
			'border-bottom:2px solid ' + (active ? 'var(--fm-accent,#7aa2f7)' : 'transparent'),
			'opacity:' + (active ? '1' : '.6'),
			'transition:opacity .15s',
		].join(';');
	}

	// ── Open / close ─────────────────────────────────────────────────────────

	function openOverlay() {
		if (!overlayEl) overlayEl = createOverlay();
		overlayEl.hidden = false;
		isOpen = true;
		if (navItemEl) navItemEl.classList.add('active');
		loadTasks();
	}

	function closeOverlay() {
		if (overlayEl) overlayEl.hidden = true;
		isOpen = false;
		if (navItemEl) navItemEl.classList.remove('active');
	}

	// ── Load tasks ────────────────────────────────────────────────────────────

	function loadTasks() {
		if (isLoading) return;
		isLoading = true;

		const list = overlayEl?.querySelector('#fm-tasks-list');
		if (list) list.innerHTML = '<div style="padding:32px;text-align:center;opacity:.5">Loading…</div>';

		const filter = activeTab === 'all' ? '' : activeTab;
		apiCall('FrickmailListTasks', { filter }, (res) => {
			isLoading = false;
			if (!res?.ok) {
				if (list) list.innerHTML = '<div style="padding:32px;text-align:center;color:#f38ba8">Failed to load tasks: ' + escHtml(res?.error || 'unknown error') + '</div>';
				return;
			}
			tasks = res.tasks || [];
			renderTasks(tasks, list);
		});
	}

	// ── Render ────────────────────────────────────────────────────────────────

	function renderTasks(list, container) {
		if (!container) return;

		if (!list.length) {
			container.innerHTML = '<div style="padding:40px;text-align:center;opacity:.45">No tasks here.</div>';
			return;
		}

		const frag = document.createDocumentFragment();

		list.forEach(task => {
			const row = buildTaskRow(task);
			frag.appendChild(row);
		});

		container.innerHTML = '';
		container.appendChild(frag);
	}

	function buildTaskRow(task) {
		const done     = task.completed === true || task.completed === 't' || task.completed === '1';
		const overdue  = isOverdue(task.due_date, done);
		const row      = document.createElement('div');
		row.dataset.taskId = task.id;
		row.style.cssText = [
			'display:flex',
			'align-items:flex-start',
			'gap:10px',
			'padding:10px 16px',
			'border-bottom:1px solid rgba(255,255,255,.05)',
		].join(';');

		// Checkbox
		const chk = document.createElement('input');
		chk.type = 'checkbox';
		chk.checked = done;
		chk.title = done ? 'Mark pending' : 'Mark complete';
		chk.style.cssText = 'margin-top:3px;width:16px;height:16px;cursor:pointer;accent-color:var(--fm-accent,#7aa2f7);flex-shrink:0;';
		chk.addEventListener('change', () => toggleComplete(task.id, chk.checked, row));

		// Content
		const content = document.createElement('div');
		content.style.cssText = 'flex:1;min-width:0;';

		const titleEl = document.createElement('div');
		titleEl.style.cssText = 'font-size:.92rem;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;'
			+ (done ? 'opacity:.45;text-decoration:line-through;' : '');
		titleEl.textContent = task.title;

		const meta = document.createElement('div');
		meta.style.cssText = 'display:flex;gap:8px;margin-top:3px;font-size:.77rem;opacity:.6;flex-wrap:wrap;';

		if (task.due_date) {
			const due = document.createElement('span');
			due.textContent = '📅 ' + formatDueDate(task.due_date);
			if (overdue) due.style.color = '#f38ba8';
			meta.appendChild(due);
		}

		if (task.notes) {
			const notes = document.createElement('span');
			notes.style.cssText = 'overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:60%;';
			notes.textContent = task.notes;
			meta.appendChild(notes);
		}

		content.appendChild(titleEl);
		if (task.due_date || task.notes) content.appendChild(meta);

		// Delete button
		const del = document.createElement('button');
		del.type = 'button';
		del.title = 'Delete task';
		del.innerHTML = '&times;';
		del.style.cssText = [
			'background:none',
			'border:none',
			'color:inherit',
			'cursor:pointer',
			'opacity:.35',
			'font-size:1.1rem',
			'padding:2px 6px',
			'flex-shrink:0',
			'line-height:1',
		].join(';');
		del.addEventListener('mouseenter', () => { del.style.opacity = '1'; del.style.color = '#f38ba8'; });
		del.addEventListener('mouseleave', () => { del.style.opacity = '.35'; del.style.color = ''; });
		del.addEventListener('click', () => deleteTask(task.id, row));

		row.appendChild(chk);
		row.appendChild(content);
		row.appendChild(del);

		// Hover
		row.addEventListener('mouseenter', () => { row.style.background = 'rgba(255,255,255,.035)'; });
		row.addEventListener('mouseleave', () => { row.style.background = ''; });

		return row;
	}

	// ── Actions ───────────────────────────────────────────────────────────────

	function addTask() {
		const titleInput = overlayEl.querySelector('#fm-tasks-title-input');
		const dateInput  = overlayEl.querySelector('#fm-tasks-date-input');
		const notesInput = overlayEl.querySelector('#fm-tasks-notes-input');

		const title   = titleInput.value.trim();
		const dueDate = dateInput.value  || null;
		const notes   = notesInput.value.trim() || null;

		if (!title) {
			titleInput.focus();
			titleInput.style.borderColor = '#f38ba8';
			setTimeout(() => { titleInput.style.borderColor = ''; }, 1500);
			return;
		}

		const btn = overlayEl.querySelector('#fm-tasks-add-btn');
		btn.disabled = true;
		btn.textContent = '…';

		apiCall('FrickmailAddTask', { title, notes, due_date: dueDate }, (res) => {
			btn.disabled = false;
			btn.textContent = 'Add';
			if (!res?.ok) {
				alert('Frickmail Tasks: ' + (res?.error || 'Failed to add task'));
				return;
			}
			titleInput.value = '';
			dateInput.value  = '';
			notesInput.value = '';
			// hide notes area again
			notesInput.style.display = 'none';
			const link = overlayEl.querySelector('#fm-tasks-toggle-notes');
			if (link) link.textContent = '+ notes';
			loadTasks();
		});
	}

	function toggleComplete(taskId, completed, rowEl) {
		// Optimistic UI: dim row immediately
		rowEl.style.opacity = '0.5';
		apiCall('FrickmailCompleteTask', { id: taskId, completed }, (res) => {
			rowEl.style.opacity = '';
			if (!res?.ok) {
				// Revert checkbox
				const chk = rowEl.querySelector('input[type=checkbox]');
				if (chk) chk.checked = !completed;
				return;
			}
			// If we're on a filtered tab, reload; otherwise just re-render in place.
			if (activeTab !== 'all') {
				loadTasks();
			} else {
				// refresh whole list to re-sort
				loadTasks();
			}
		});
	}

	function deleteTask(taskId, rowEl) {
		rowEl.style.opacity = '0.4';
		apiCall('FrickmailDeleteTask', { id: taskId }, (res) => {
			if (!res?.ok) {
				rowEl.style.opacity = '';
				alert('Frickmail Tasks: Failed to delete task');
				return;
			}
			rowEl.remove();
			// Show empty-state if no rows remain
			const list = overlayEl?.querySelector('#fm-tasks-list');
			if (list && !list.querySelector('[data-task-id]')) {
				list.innerHTML = '<div style="padding:40px;text-align:center;opacity:.45">No tasks here.</div>';
			}
		});
	}

	// ── Inject nav icon ───────────────────────────────────────────────────────

	function injectNavItem() {
		const nav = document.getElementById('fm-icon-nav');
		if (!nav) return;

		// Already injected?
		if (nav.querySelector('[data-nav-id="tasks"]')) return;

		const navItems = nav.querySelector('.fm-nav-items');
		if (!navItems) return;

		navItemEl = document.createElement('a');
		navItemEl.className = 'fm-nav-item';
		navItemEl.dataset.navId = 'tasks';
		navItemEl.dataset.tooltip = 'Tasks';
		navItemEl.textContent = '✓';   // ✓ checkmark
		navItemEl.href = '#';
		navItemEl.addEventListener('click', (e) => {
			e.preventDefault();
			if (isOpen) closeOverlay();
			else openOverlay();
		});

		navItems.appendChild(navItemEl);
	}

	// ── rl-view-model hook ────────────────────────────────────────────────────

	addEventListener('rl-view-model', e => {
		const id = e.detail?.viewModelTemplateID;
		if (!id || id === 'Login') return;

		// Retry a few times in case fm-icon-nav isn't built yet by ThemeSwitcher.
		let tries = 0;
		const tryInject = () => {
			if (document.getElementById('fm-icon-nav')) {
				injectNavItem();
			} else if (tries++ < 10) {
				setTimeout(tryInject, 200);
			}
		};
		setTimeout(tryInject, 100);
	});

	// Also try on DOMContentLoaded / load in case rl-view-model fires before us.
	if (document.readyState === 'loading') {
		document.addEventListener('DOMContentLoaded', () => { setTimeout(injectNavItem, 500); });
	} else {
		setTimeout(injectNavItem, 500);
	}

})();
