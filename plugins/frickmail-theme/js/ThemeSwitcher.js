// Frickmail Theme — ThemeSwitcher
// 1. Applies dark/light/system theme immediately (no flash)
// 2. Injects icon navigation column
// 3. Registers a "Appearance" settings tab for theme/accent/font controls

(function () {
	const THEME_KEY  = 'fm_theme';
	const ACCENT_KEY = 'fm_accent';
	const FONT_KEY   = 'fm_fontsize';
	const DEFAULT    = 'dark';

	const ACCENTS = [
		{ name: 'Blue',   dark: '#7aa2f7', light: '#4166d5' },
		{ name: 'Teal',   dark: '#14b8a6', light: '#0d9488' },
		{ name: 'Purple', dark: '#bb9af7', light: '#6d28d9' },
		{ name: 'Pink',   dark: '#f7768e', light: '#db2777' },
		{ name: 'Peach',  dark: '#ff9e64', light: '#c2410c' },
		{ name: 'Green',  dark: '#9ece6a', light: '#1e7e34' },
	];

	// ── Apply theme immediately ────────────────────────────────────

	function applyTheme(theme, save) {
		document.documentElement.setAttribute('data-fm-theme', theme);
		if (save) try { localStorage.setItem(THEME_KEY, theme); } catch(e) {}
	}

	function applyAccent(idx, save) {
		const theme = document.documentElement.getAttribute('data-fm-theme') || DEFAULT;
		const a = ACCENTS[idx] || ACCENTS[0];
		const hex = theme === 'light' ? a.light : a.dark;
		const r = parseInt(hex.slice(1,3),16), g = parseInt(hex.slice(3,5),16), b = parseInt(hex.slice(5,7),16);
		const root = document.documentElement.style;
		root.setProperty('--fm-accent',         hex);
		root.setProperty('--fm-accent-hover',    hex);
		root.setProperty('--fm-accent-surface',  `rgba(${r},${g},${b},.18)`);
		root.setProperty('--fm-accent-text',     hex);
		if (save) try { localStorage.setItem(ACCENT_KEY, idx); } catch(e) {}
	}

	function applyFontSize(px, save) {
		document.documentElement.style.setProperty('--main-font-size', px + 'px');
		if (save) try { localStorage.setItem(FONT_KEY, px); } catch(e) {}
	}

	function boot() {
		const theme = localStorage.getItem(THEME_KEY) || DEFAULT;
		applyTheme(theme, false);
		const accent = parseInt(localStorage.getItem(ACCENT_KEY) || '0', 10);
		if (accent > 0) applyAccent(accent, false);
		const fs = parseInt(localStorage.getItem(FONT_KEY) || '14', 10);
		if (fs !== 14) applyFontSize(fs, false);
	}
	boot(); // run before anything else to prevent flash

	// ── Icon nav ──────────────────────────────────────────────────

	function buildIconNav() {
		if (document.getElementById('fm-icon-nav')) return;
		const NAV = [
			{ id:'mail',     icon:'✉',  tip:'Mail',     hash:'#/mailbox/INBOX' },
			{ id:'contacts', icon:'👤', tip:'Contacts', action:'contacts' },
			{ id:'calendar', icon:'📅', tip:'Calendar', hash:'#/settings/calendar' },
		];

		const wrap = document.createElement('div');
		wrap.id = 'fm-icon-nav';
		wrap.innerHTML = `<div class="fm-logo" title="Frickmail">M</div><div class="fm-nav-items"></div><div class="fm-nav-spacer"></div>`;

		const items = wrap.querySelector('.fm-nav-items');
		NAV.forEach(n => {
			const a = document.createElement('a');
			a.className = 'fm-nav-item'; a.dataset.navId = n.id; a.dataset.tooltip = n.tip;
			a.textContent = n.icon; a.href = '#';
			a.addEventListener('click', e => { e.preventDefault(); doNav(n); });
			items.appendChild(a);
		});

		// Settings icon at bottom
		const s = document.createElement('a');
		s.className = 'fm-nav-item'; s.dataset.navId = 'settings'; s.dataset.tooltip = 'Settings';
		s.textContent = '⚙'; s.href = '#';
		s.addEventListener('click', e => { e.preventDefault(); location.hash = '#/settings'; });
		wrap.appendChild(s);

		document.body.insertBefore(wrap, document.body.firstChild);
		syncActiveNav();
	}

	function doNav(n) {
		if (n.action === 'contacts') {
			document.querySelector('.buttonContacts')?.click(); return;
		}
		if (n.hash) location.hash = n.hash;
		syncActiveNav();
	}

	function syncActiveNav() {
		const h = location.hash;
		document.querySelectorAll('#fm-icon-nav .fm-nav-item').forEach(el => {
			const id = el.dataset.navId;
			const active =
				(id === 'mail'     && (h.includes('mailbox') || h === '' || h === '#/')) ||
				(id === 'contacts' && h.includes('contacts')) ||
				(id === 'calendar' && h.includes('calendar')) ||
				(id === 'settings' && h.includes('settings') && !h.includes('calendar'));
			el.classList.toggle('active', active);
		});
	}

	window.addEventListener('hashchange', syncActiveNav);

	function setNavVisible(visible) {
		const nav = document.getElementById('fm-icon-nav');
		if (!nav) return;
		nav.style.display = visible ? '' : 'none';
		// Also shift the app padding accordingly
		const app = document.getElementById('rl-app');
		if (app) app.style.paddingLeft = visible ? '56px' : '';
	}

	if (document.readyState === 'loading') {
		document.addEventListener('DOMContentLoaded', buildIconNav);
	} else {
		buildIconNav();
	}

	// ── Hide nav on login screen, show on app screens ─────────────

	addEventListener('rl-view-model', e => {
		const id = e.detail?.viewModelTemplateID;
		if (!id) return;

		if (id === 'Login') {
			// Login screen: hide icon nav and remove app padding
			setNavVisible(false);
		} else {
			// Any other screen (inbox, settings, …): show nav
			buildIconNav();   // no-op if already built
			setNavVisible(true);
			syncActiveNav();
		}
	});

	// Register as a settings view model.
	// Waits until rl.addSettingsViewModel is available.
	function registerSettingsTab() {
		const rl = window.rl;
		if (!rl?.addSettingsViewModel) {
			setTimeout(registerSettingsTab, 200); return;
		}
		if (rl.__fm_theme_registered) return;
		rl.__fm_theme_registered = true;

		class FmAppearanceSettings {
			constructor() {
				this.currentTheme  = ko.observable(localStorage.getItem(THEME_KEY) || DEFAULT);
				this.currentAccent = ko.observable(parseInt(localStorage.getItem(ACCENT_KEY) || '0', 10));
				this.fontSize      = ko.observable(parseInt(localStorage.getItem(FONT_KEY) || '14', 10));
				this.accents       = ACCENTS;
			}

			onBuild(dom) {
				if (!dom) return;
				this._dom = dom;
				this._renderThemePicker(dom);
			}

			setTheme(theme) {
				this.currentTheme(theme);
				applyTheme(theme, true);
				// re-render accent swatches with correct color
				if (this._dom) {
					this._dom.querySelectorAll('.fm-accent-swatch').forEach((sw, i) => {
						const t = theme === 'light' ? ACCENTS[i]?.light : ACCENTS[i]?.dark;
						if (t) sw.style.background = t;
					});
					this._dom.querySelectorAll('.fm-theme-card').forEach(c => {
						c.classList.toggle('active', c.dataset.theme === theme);
					});
				}
			}

			setAccent(idx) {
				this.currentAccent(idx);
				applyAccent(idx, true);
				if (this._dom) {
					this._dom.querySelectorAll('.fm-accent-swatch').forEach((sw, i) => sw.classList.toggle('active', i === idx));
				}
			}

			setFontSize(px) {
				this.fontSize(px);
				applyFontSize(px, true);
			}

			_renderThemePicker(dom) {
				const theme  = this.currentTheme();
				const accent = this.currentAccent();
				const fs     = this.fontSize();

				dom.innerHTML = `
<div class="form-horizontal">
	<div class="legend">Tema</div>
	<p style="color:var(--fm-text-secondary);font-size:13px;margin:0 0 12px">Scegli l'aspetto dell'interfaccia.</p>

	<div class="fm-theme-picker">
		${['dark','light','system'].map(t => `
		<div class="fm-theme-card fm-card-${t} ${theme===t?'active':''}" data-theme="${t}" style="cursor:pointer">
			<div class="fm-card-preview"><div class="col1"></div><div class="col2"></div></div>
			<div class="fm-card-label">${{dark:'Scuro',light:'Chiaro',system:'Sistema'}[t]}</div>
		</div>`).join('')}
	</div>

	<div style="margin-top:1.6em">
		<div class="legend" style="font-size:14px">Colore accento</div>
		<div class="fm-accent-picker">
			${ACCENTS.map((a,i) => `
			<div class="fm-accent-swatch ${i===accent?'active':''}" data-idx="${i}"
				style="background:${theme==='light'?a.light:a.dark}"
				title="${a.name}"></div>`).join('')}
		</div>
	</div>

	<div style="margin-top:1.6em">
		<div class="legend" style="font-size:14px">Dimensione testo</div>
		<div style="display:flex;align-items:center;gap:12px;margin-top:8px">
			<input type="range" id="fm-font-range" min="12" max="18" step="1" value="${fs}"
				style="width:180px;accent-color:var(--fm-accent)">
			<span id="fm-font-label" style="color:var(--fm-text-secondary);font-size:13px;min-width:32px">${fs}px</span>
		</div>
	</div>
</div>`;

				// Theme card clicks
				dom.querySelectorAll('.fm-theme-card').forEach(c => {
					c.addEventListener('click', () => this.setTheme(c.dataset.theme));
				});
				// Accent clicks
				dom.querySelectorAll('.fm-accent-swatch').forEach(sw => {
					sw.addEventListener('click', () => this.setAccent(parseInt(sw.dataset.idx, 10)));
				});
				// Font slider
				const slider = dom.querySelector('#fm-font-range');
				const label  = dom.querySelector('#fm-font-label');
				slider?.addEventListener('input', () => {
					label.textContent = slider.value + 'px';
					this.setFontSize(parseInt(slider.value, 10));
				});
			}
		}

		// Template: minimal placeholder (content is rendered imperatively in onBuild)
		// Register a template so the theme system knows the template ID.
		// We'll create it inline as a <template> tag.
		if (!document.getElementById('FmAppearanceSettings')) {
			const tmpl = document.createElement('template');
			tmpl.id = 'FmAppearanceSettings';
			tmpl.innerHTML = '<div></div>';
			document.body.appendChild(tmpl);
		}

		rl.addSettingsViewModel(FmAppearanceSettings, 'FmAppearanceSettings', 'Aspetto', 'fm-appearance');
	}

	registerSettingsTab();

})();
