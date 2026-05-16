(rl => { if (!rl) return;

	const pad = n => String(n).padStart(2, '0');
	const toIso = d => d.getFullYear() + '-' + pad(d.getMonth() + 1) + '-' + pad(d.getDate());
	const monthName = m => ['January','February','March','April','May','June','July','August','September','October','November','December'][m];

	const CAL_PREF_KEY = 'fm_calendar_ids';

	function loadSelectedIds() {
		try { return JSON.parse(localStorage.getItem(CAL_PREF_KEY) || 'null'); } catch(e) { return null; }
	}
	function saveSelectedIds(ids) {
		try { localStorage.setItem(CAL_PREF_KEY, JSON.stringify(ids)); } catch(e) {}
	}

	class CalendarSettings
	{
		constructor()
		{
			const now = new Date();
			this.year = ko.observable(now.getFullYear());
			this.month = ko.observable(now.getMonth());
			this.title = ko.computed(() => monthName(this.month()) + ' ' + this.year());
			this.events = ko.observableArray([]);
			this.status = ko.observable('');
			this.loading = ko.observable(false);
			this.eventsByDay = {};
			this.calendars = ko.observableArray([]);   // [{id, name, color, primary, selected}]
			this.calLoading = ko.observable(false);
			this.calStatus = ko.observable('');
		}

		onBuild(el)
		{
			this.root = el;
			this.render();
			this.loadCalendars();
		}

		prevMonth() {
			let m = this.month() - 1, y = this.year();
			if (m < 0) { m = 11; y--; }
			this.month(m); this.year(y);
			this.fetch();
		}
		nextMonth() {
			let m = this.month() + 1, y = this.year();
			if (m > 11) { m = 0; y++; }
			this.month(m); this.year(y);
			this.fetch();
		}
		today() {
			const n = new Date();
			this.month(n.getMonth()); this.year(n.getFullYear());
			this.fetch();
		}

		// ── Calendar list ──────────────────────────────────────────────

		loadCalendars() {
			this.calLoading(true);
			this.calStatus('Loading calendars…');
			rl.pluginRemoteRequest((iError, oData) => {
				this.calLoading(false);
				const r = oData?.Result;
				if (iError || r?.error) {
					this.calStatus('Could not load calendars: ' + (r?.error || 'request error'));
					// Still try to fetch events with default calendar
					this.fetch();
					return;
				}
				const savedIds = loadSelectedIds();
				const cals = (r.calendars || []).map(c => ({
					...c,
					selected: ko.observable(savedIds ? savedIds.includes(c.id) : c.primary)
				}));
				this.calendars(cals);
				this.calStatus('');
				this.fetch();
			}, 'JsonCalendarList', {}, 20000);
		}

		selectedCalendarIds() {
			const cals = this.calendars();
			if (!cals.length) return null; // null → server uses primary
			const sel = cals.filter(c => c.selected()).map(c => c.id);
			return sel.length ? sel : [cals.find(c => c.primary)?.id || 'primary'];
		}

		saveCalendarPrefs() {
			const ids = this.selectedCalendarIds();
			saveSelectedIds(ids);
			this.fetch();
		}

		// ── Event fetch ────────────────────────────────────────────────

		fetch() {
			this.loading(true);
			this.status('Loading…');
			const start = new Date(Date.UTC(this.year(), this.month() - 1, 1)).toISOString();
			const end   = new Date(Date.UTC(this.year(), this.month() + 2, 0, 23, 59, 59)).toISOString();
			const ids = this.selectedCalendarIds();
			const params = { start, end };
			if (ids) params.calendar_ids = JSON.stringify(ids);
			rl.pluginRemoteRequest((iError, oData) => {
				this.loading(false);
				if (iError || !oData?.Result) {
					this.status('Failed to load events — check that the Google Calendar API is enabled in your Google Cloud project');
					this.events([]);
					this.render();
					return;
				}
				const r = oData.Result;
				if (r.error) { this.status('Error: ' + r.error); this.events([]); this.render(); return; }
				this.events(r.events || []);
				this.status((r.events?.length || 0) + ' events from ' + (r.provider || 'provider'));
				this.render();
			}, 'JsonCalendarEvents', params, 30000);
		}

		// ── Calendar render ────────────────────────────────────────────

		groupByDay() {
			this.eventsByDay = {};
			(this.events() || []).forEach(ev => {
				const key = (ev.start || '').slice(0, 10);
				if (!key) return;
				(this.eventsByDay[key] = this.eventsByDay[key] || []).push(ev);
			});
		}

		render() {
			if (!this.root) return;
			this.groupByDay();
			const grid = this.root.querySelector('.frickmail-calendar-grid');
			if (!grid) return;
			grid.innerHTML = '';
			['Mon','Tue','Wed','Thu','Fri','Sat','Sun'].forEach(d => {
				const cell = document.createElement('div');
				cell.className = 'dow';
				cell.textContent = d;
				grid.appendChild(cell);
			});
			const first = new Date(this.year(), this.month(), 1);
			let dow = first.getDay() - 1; if (dow < 0) dow = 6;
			const startDate = new Date(this.year(), this.month(), 1 - dow);
			const todayKey = toIso(new Date());
			for (let i = 0; i < 42; i++) {
				const d = new Date(startDate.getFullYear(), startDate.getMonth(), startDate.getDate() + i);
				const key = toIso(d);
				const cell = document.createElement('div');
				cell.className = 'day' + (d.getMonth() !== this.month() ? ' othermonth' : '') + (key === todayKey ? ' today' : '');
				const num = document.createElement('div');
				num.className = 'num';
				num.textContent = d.getDate();
				cell.appendChild(num);
				const evs = this.eventsByDay[key] || [];
				evs.slice(0, 4).forEach(ev => {
					const e = document.createElement('div');
					e.className = 'ev ' + (ev.provider || '');
					e.textContent = ev.title;
					e.title = ev.title + (ev.location ? ' @ ' + ev.location : '');
					e.style.borderLeft = ev._calColor ? '3px solid ' + ev._calColor : '';
					e.onclick = (event) => { event.stopPropagation(); this.openEditPopup(ev); };
					cell.appendChild(e);
				});
				if (evs.length > 4) {
					const more = document.createElement('div');
					more.className = 'ev';
					more.style.background = '#888';
					more.textContent = '+' + (evs.length - 4) + ' more';
					cell.appendChild(more);
				}
				cell.onclick = () => this.openCreatePopup(d);
				grid.appendChild(cell);
			}

			// Render calendar selector panel
			this.renderCalendarPanel();
		}

		renderCalendarPanel() {
			let panel = this.root.querySelector('.fm-calendar-panel');
			if (!panel) return;
			panel.innerHTML = '';

			if (this.calLoading()) {
				panel.textContent = 'Loading calendars…';
				return;
			}
			if (this.calStatus()) {
				const msg = document.createElement('div');
				msg.style.cssText = 'font-size:12px;color:var(--fm-text-secondary);margin-bottom:8px';
				msg.textContent = this.calStatus();
				panel.appendChild(msg);
			}
			const cals = this.calendars();
			if (!cals.length) return;

			const title = document.createElement('div');
			title.style.cssText = 'font-size:12px;font-weight:600;color:var(--fm-text-muted);text-transform:uppercase;letter-spacing:.05em;margin-bottom:8px';
			title.textContent = 'Calendars';
			panel.appendChild(title);

			cals.forEach(c => {
				const row = document.createElement('label');
				row.style.cssText = 'display:flex;align-items:center;gap:7px;padding:4px 0;cursor:pointer;font-size:13px';
				const cb = document.createElement('input');
				cb.type = 'checkbox';
				cb.checked = c.selected();
				cb.style.cssText = 'accent-color:' + (c.color || 'var(--fm-accent)') + ';width:14px;height:14px;flex-shrink:0';
				cb.onchange = () => {
					c.selected(cb.checked);
					saveSelectedIds(this.selectedCalendarIds());
					this.fetch();
				};
				const dot = document.createElement('span');
				dot.style.cssText = 'width:10px;height:10px;border-radius:50%;background:' + (c.color || 'var(--fm-accent)') + ';flex-shrink:0';
				const lbl = document.createElement('span');
				lbl.textContent = c.name + (c.primary ? ' ★' : '');
				lbl.style.color = 'var(--fm-text-primary)';
				row.append(cb, dot, lbl);
				panel.appendChild(row);
			});
		}

		// ── Event popup ────────────────────────────────────────────────

		openCreatePopup(date) {
			const start = new Date(date); start.setHours(9, 0, 0, 0);
			const end = new Date(start); end.setHours(10, 0, 0, 0);
			// Default calendar: first selected one
			const defCal = this.calendars().find(c => c.selected())?.id || 'primary';
			this.openPopup({
				id: '', _raw_id: '', _calendar: defCal,
				title: '', description: '', location: '',
				start: start.toISOString(), end: end.toISOString(), allDay: false
			}, false);
		}

		openEditPopup(ev) {
			this.openPopup({ ...ev }, true);
		}

		openPopup(ev, isEdit) {
			const backdrop = document.createElement('div');
			backdrop.className = 'frickmail-event-popup-backdrop';
			const popup = document.createElement('div');
			popup.className = 'frickmail-event-popup';

			// Calendar selector for new events (when multiple calendars available)
			const cals = this.calendars().filter(c => c.selected());
			const calSelector = (!isEdit && cals.length > 1) ? `
				<label>Calendar</label>
				<select data-f="calendar" style="width:100%;padding:6px;border-radius:6px;border:1px solid var(--fm-border-input);background:var(--fm-bg-input);color:var(--fm-text-primary)">
					${cals.map(c => `<option value="${c.id}" ${c.id === ev._calendar ? 'selected' : ''}>${c.name}</option>`).join('')}
				</select>` : '';

			popup.innerHTML = `
				<h3 style="margin:0 0 .6em">${isEdit ? 'Edit event' : 'New event'}</h3>
				${calSelector}
				<label>Title</label><input data-f="title" type="text" />
				<label>Start (UTC ISO)</label><input data-f="start" type="text" />
				<label>End (UTC ISO)</label><input data-f="end" type="text" />
				<label>Location</label><input data-f="location" type="text" />
				<label>Description</label><textarea data-f="description" rows="3"></textarea>
				<label><input data-f="allDay" type="checkbox" /> All day</label>
				<div class="row">
					${isEdit ? '<button class="btn" data-act="del" style="margin-right:auto;background:#c33;color:white">Delete</button>' : ''}
					<button class="btn" data-act="cancel">Cancel</button>
					<button class="btn" data-act="save" style="background:#4a90e2;color:white">Save</button>
				</div>`;
			['title','start','end','location','description'].forEach(f => {
				const el = popup.querySelector(`[data-f="${f}"]`);
				if (el) el.value = ev[f] || '';
			});
			popup.querySelector('[data-f="allDay"]').checked = !!ev.allDay;

			const close = () => { backdrop.remove(); popup.remove(); };
			backdrop.onclick = close;
			popup.querySelector('[data-act="cancel"]').onclick = close;
			popup.querySelector('[data-act="save"]').onclick = () => {
				const calSel = popup.querySelector('[data-f="calendar"]');
				const data = {
					id:          ev.id || '',
					_raw_id:     ev._raw_id || '',
					_calendar:   calSel ? calSel.value : (ev._calendar || 'primary'),
					title:       popup.querySelector('[data-f="title"]').value.trim(),
					start:       popup.querySelector('[data-f="start"]').value.trim(),
					end:         popup.querySelector('[data-f="end"]').value.trim(),
					location:    popup.querySelector('[data-f="location"]').value.trim(),
					description: popup.querySelector('[data-f="description"]').value.trim(),
					allDay:      popup.querySelector('[data-f="allDay"]').checked
				};
				if (!data.title || !data.start || !data.end) { alert('Title/start/end required'); return; }
				this.status('Saving…');
				rl.pluginRemoteRequest((iError, oData) => {
					if (iError || oData?.Result?.error) {
						this.status('Save failed: ' + (oData?.Result?.error || 'request error'));
						return;
					}
					close();
					this.fetch();
				}, 'JsonCalendarSave', data, 30000);
			};
			const del = popup.querySelector('[data-act="del"]');
			if (del) del.onclick = () => {
				if (!confirm('Delete this event?')) return;
				this.status('Deleting…');
				rl.pluginRemoteRequest((iError, oData) => {
					if (iError || oData?.Result?.error) {
						this.status('Delete failed: ' + (oData?.Result?.error || 'request error'));
						return;
					}
					close();
					this.fetch();
				}, 'JsonCalendarDelete', { id: ev.id, _raw_id: ev._raw_id, _calendar: ev._calendar }, 30000);
			};
			document.body.appendChild(backdrop);
			document.body.appendChild(popup);
		}
	}

	rl.addSettingsViewModel(CalendarSettings, 'CalendarSettingsTab', 'Calendar', 'calendar');

})(window.rl);
