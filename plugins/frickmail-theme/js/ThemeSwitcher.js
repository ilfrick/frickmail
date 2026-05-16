// Frickmail Theme — ThemeSwitcher
// Injects icon navigation column, manages dark/light/system theme,
// and adds a theme-picker UI to the Appearance settings tab.

(function () {
	const STORAGE_KEY   = 'frickmail_theme';
	const ACCENT_KEY    = 'frickmail_accent';
	const DEFAULT_THEME = 'dark';

	const ACCENTS = [
		{ name: 'Blue',    dark: '#89b4fa', light: '#4a90e2' },
		{ name: 'Green',   dark: '#a6e3a1', light: '#34a853' },
		{ name: 'Purple',  dark: '#cba6f7', light: '#7c3aed' },
		{ name: 'Pink',    dark: '#f5c2e7', light: '#db2777' },
		{ name: 'Peach',   dark: '#fab387', light: '#ea7d3a' },
		{ name: 'Teal',    dark: '#94e2d5', light: '#0891b2' },
	];

	// ── Theme application ──────────────────────────────────────────

	function applyTheme(theme) {
		const html = document.documentElement;
		html.setAttribute('data-fm-theme', theme);
		try { localStorage.setItem(STORAGE_KEY, theme); } catch (e) {}
	}

	function applyAccent(idx) {
		const html = document.documentElement;
		const theme = html.getAttribute('data-fm-theme') || DEFAULT_THEME;
		const a = ACCENTS[idx] || ACCENTS[0];
		const color = (theme === 'light') ? a.light : a.dark;
		html.style.setProperty('--fm-accent', color);
		// derive hover (~10% lighter) and surface (15% alpha)
		html.style.setProperty('--fm-accent-hover', color);
		html.style.setProperty('--fm-accent-surface', hexToRgba(color, 0.15));
		try { localStorage.setItem(ACCENT_KEY, idx); } catch (e) {}
	}

	function hexToRgba(hex, alpha) {
		const r = parseInt(hex.slice(1,3),16);
		const g = parseInt(hex.slice(3,5),16);
		const b = parseInt(hex.slice(5,7),16);
		return `rgba(${r},${g},${b},${alpha})`;
	}

	function init() {
		const saved = localStorage.getItem(STORAGE_KEY) || DEFAULT_THEME;
		applyTheme(saved);
		const savedAccent = parseInt(localStorage.getItem(ACCENT_KEY) || '0', 10);
		if (savedAccent > 0) applyAccent(savedAccent);
	}

	// Run immediately so there's no flash of wrong theme
	init();

	// ── Icon navigation injection ──────────────────────────────────

	const NAV_ITEMS = [
		{ id: 'mail',      icon: '✉',  label: 'Mail',      hash: '#/mailbox/INBOX' },
		{ id: 'contacts',  icon: '👤', label: 'Contacts',  action: 'contacts'      },
		{ id: 'calendar',  icon: '📅', label: 'Calendar',  hash: '#/settings/calendar' },
		{ id: 'settings',  icon: '⚙',  label: 'Settings',  hash: '#/settings'      },
	];

	function buildIconNav() {
		if (document.getElementById('fm-icon-nav')) return;

		const nav = document.createElement('div');
		nav.id = 'fm-icon-nav';

		// Logo
		const logo = document.createElement('div');
		logo.className = 'fm-logo';
		logo.textContent = 'M';
		logo.title = 'Frickmail';
		nav.appendChild(logo);

		// Nav items
		const items = document.createElement('div');
		items.className = 'fm-nav-items';

		NAV_ITEMS.forEach(item => {
			if (item.id === 'settings') return; // settings goes to bottom
			const a = document.createElement('a');
			a.className = 'fm-nav-item';
			a.dataset.tooltip = item.label;
			a.dataset.navId = item.id;
			a.textContent = item.icon;
			a.href = '#';
			a.addEventListener('click', e => {
				e.preventDefault();
				handleNavClick(item, a);
			});
			items.appendChild(a);
		});

		nav.appendChild(items);

		// Spacer + settings at bottom
		const spacer = document.createElement('div');
		spacer.className = 'fm-nav-spacer';
		nav.appendChild(spacer);

		const settingsItem = NAV_ITEMS.find(i => i.id === 'settings');
		const settingsEl = document.createElement('a');
		settingsEl.className = 'fm-nav-item';
		settingsEl.dataset.tooltip = settingsItem.label;
		settingsEl.dataset.navId = 'settings';
		settingsEl.textContent = settingsItem.icon;
		settingsEl.href = '#';
		settingsEl.addEventListener('click', e => {
			e.preventDefault();
			handleNavClick(settingsItem, settingsEl);
		});
		nav.appendChild(settingsEl);

		document.body.insertBefore(nav, document.body.firstChild);
		updateActiveNavItem();
	}

	function handleNavClick(item, el) {
		if (item.action === 'contacts') {
			// Trigger contacts popup via SnappyMail
			const r = window.rl;
			if (r?.app) {
				const contactsBtn = document.querySelector('.buttonContacts');
				contactsBtn?.click();
			}
			return;
		}
		if (item.hash) location.hash = item.hash;
		updateActiveNavItem();
	}

	function updateActiveNavItem() {
		const hash = location.hash;
		document.querySelectorAll('#fm-icon-nav .fm-nav-item').forEach(el => {
			const id = el.dataset.navId;
			let active = false;
			if (id === 'mail'     && (hash.includes('mailbox') || hash === '' || hash === '#/')) active = true;
			if (id === 'contacts' && hash.includes('contacts')) active = true;
			if (id === 'calendar' && hash.includes('calendar')) active = true;
			if (id === 'settings' && hash.includes('settings') && !hash.includes('calendar')) active = true;
			el.classList.toggle('active', active);
		});
	}

	window.addEventListener('hashchange', updateActiveNavItem);

	// Inject nav after DOM is ready
	if (document.readyState === 'loading') {
		document.addEventListener('DOMContentLoaded', buildIconNav);
	} else {
		buildIconNav();
	}

	// ── Appearance settings tab (theme picker + accent) ────────────

	addEventListener('rl-view-model', e => {
		const id = e.detail?.viewModelTemplateID;
		if (!id) return;

		// Re-check active nav on any view change
		updateActiveNavItem();

		// Inject appearance panel into General settings tab
		if (id === 'UserSettingsGeneral') {
			setTimeout(() => injectAppearancePanel(e.detail.viewModelDom), 150);
		}
	});

	function injectAppearancePanel(dom) {
		if (!dom || dom.querySelector('#fm-appearance-panel')) return;

		const container = dom.querySelector('.form-horizontal') || dom;

		const panel = document.createElement('div');
		panel.id = 'fm-appearance-panel';
		panel.innerHTML = `
			<div style="margin-top:2em">
				<div class="legend" style="font-size:16px;font-weight:500;border-bottom:1px solid var(--fm-border);padding-bottom:10px;margin-bottom:16px">
					Tema
				</div>
				<p style="color:var(--fm-text-secondary);font-size:13px;margin-bottom:12px">Usa tema scuro automatico</p>
				<div class="fm-theme-picker">
					${buildThemeCard('light', 'Light')}
					${buildThemeCard('dark',  'Dark')}
					${buildThemeCard('system','System')}
				</div>

				<div style="margin-top:1.4em">
					<div style="font-size:13px;font-weight:600;color:var(--fm-text-secondary);margin-bottom:8px">Colore Accento</div>
					<div class="fm-accent-picker" id="fm-accent-swatches">
						${ACCENTS.map((a,i) => `
							<div class="fm-accent-swatch ${i===currentAccentIdx()?'active':''}"
								style="background:${currentMode()==='light'?a.light:a.dark}"
								data-accent="${i}" title="${a.name}"></div>
						`).join('')}
					</div>
				</div>

				<div style="margin-top:1.4em">
					<div style="font-size:13px;font-weight:600;color:var(--fm-text-secondary);margin-bottom:8px">Dimensione Testo</div>
					<input type="range" id="fm-font-size" min="12" max="18" step="1"
						value="${currentFontSize()}"
						style="width:200px;accent-color:var(--fm-accent)">
					<span id="fm-font-size-label" style="margin-left:8px;color:var(--fm-text-secondary);font-size:13px">${currentFontSize()}px</span>
				</div>
			</div>`;

		container.appendChild(panel);

		// Theme card clicks
		panel.querySelectorAll('.fm-theme-card').forEach(card => {
			card.addEventListener('click', () => {
				const theme = card.dataset.theme;
				applyTheme(theme);
				panel.querySelectorAll('.fm-theme-card').forEach(c => c.classList.toggle('active', c.dataset.theme === theme));
				// re-render accent swatches with correct color
				panel.querySelectorAll('.fm-accent-swatch').forEach((sw, i) => {
					const a = ACCENTS[i];
					sw.style.background = (theme === 'light') ? a.light : a.dark;
				});
			});
		});

		// Accent swatches
		panel.querySelectorAll('.fm-accent-swatch').forEach(sw => {
			sw.addEventListener('click', () => {
				const idx = parseInt(sw.dataset.accent, 10);
				applyAccent(idx);
				panel.querySelectorAll('.fm-accent-swatch').forEach(s => s.classList.toggle('active', parseInt(s.dataset.accent,10) === idx));
			});
		});

		// Font size slider
		const slider = panel.querySelector('#fm-font-size');
		const label = panel.querySelector('#fm-font-size-label');
		slider?.addEventListener('input', () => {
			const size = slider.value + 'px';
			document.documentElement.style.setProperty('--main-font-size', size);
			label.textContent = slider.value + 'px';
			try { localStorage.setItem('frickmail_fontsize', slider.value); } catch(e) {}
		});
	}

	function buildThemeCard(theme, label) {
		const active = (localStorage.getItem(STORAGE_KEY) || DEFAULT_THEME) === theme;
		return `<div class="fm-theme-card fm-card-${theme} ${active?'active':''}" data-theme="${theme}">
			<div class="fm-card-preview">
				<div class="col1"></div>
				<div class="col2"></div>
			</div>
			<div class="fm-card-label">${label}</div>
		</div>`;
	}

	function currentMode() {
		return localStorage.getItem(STORAGE_KEY) || DEFAULT_THEME;
	}
	function currentAccentIdx() {
		return parseInt(localStorage.getItem(ACCENT_KEY) || '0', 10);
	}
	function currentFontSize() {
		return localStorage.getItem('frickmail_fontsize') || '14';
	}

	// Restore font size on load
	const savedSize = localStorage.getItem('frickmail_fontsize');
	if (savedSize) document.documentElement.style.setProperty('--main-font-size', savedSize + 'px');

})();
