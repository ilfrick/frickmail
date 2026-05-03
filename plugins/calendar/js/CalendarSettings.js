(rl => { if (!rl) return;

	const pad = n => String(n).padStart(2, '0');
	const toIso = d => d.getFullYear() + '-' + pad(d.getMonth() + 1) + '-' + pad(d.getDate());
	const monthName = m => ['January','February','March','April','May','June','July','August','September','October','November','December'][m];

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
		}

		onBuild(el)
		{
			this.root = el;
			this.render();
			this.fetch();
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

		fetch() {
			this.loading(true);
			this.status('Loading…');
			const start = new Date(Date.UTC(this.year(), this.month() - 1, 1)).toISOString();
			const end   = new Date(Date.UTC(this.year(), this.month() + 2, 0, 23, 59, 59)).toISOString();
			rl.pluginRemoteRequest((iError, oData) => {
				this.loading(false);
				if (iError || !oData?.Result) {
					this.status('Failed to load events');
					this.events([]);
					this.render();
					return;
				}
				const r = oData.Result;
				if (r.error) { this.status('Error: ' + r.error); this.events([]); this.render(); return; }
				this.events(r.events || []);
				this.status((r.events?.length || 0) + ' events from ' + (r.provider || 'provider'));
				this.render();
			}, 'JsonCalendarEvents', { start, end }, 30);
		}

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
		}

		openCreatePopup(date) {
			const start = new Date(date); start.setHours(9, 0, 0, 0);
			const end = new Date(start); end.setHours(10, 0, 0, 0);
			this.openPopup({
				id: '', title: '', description: '', location: '',
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
			popup.innerHTML = `
				<h3 style="margin:0 0 .6em">${isEdit ? 'Edit event' : 'New event'}</h3>
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
				const data = {
					id: ev.id || '',
					title: popup.querySelector('[data-f="title"]').value.trim(),
					start: popup.querySelector('[data-f="start"]').value.trim(),
					end:   popup.querySelector('[data-f="end"]').value.trim(),
					location: popup.querySelector('[data-f="location"]').value.trim(),
					description: popup.querySelector('[data-f="description"]').value.trim(),
					allDay: popup.querySelector('[data-f="allDay"]').checked
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
				}, 'JsonCalendarSave', data, 30);
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
				}, 'JsonCalendarDelete', { id: ev.id }, 30);
			};
			document.body.appendChild(backdrop);
			document.body.appendChild(popup);
		}
	}

	rl.addSettingsViewModel(CalendarSettings, 'CalendarSettingsTab', 'Calendar', 'calendar');

})(window.rl);
