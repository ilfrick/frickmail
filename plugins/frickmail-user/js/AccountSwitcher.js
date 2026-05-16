// Frickmail account switcher — populates SnappyMail's top-right account
// dropdown with all Frickmail mail accounts and handles switching.
//
// Refactored from monkey-patching Remote.request (fragile — breaks if
// SnappyMail replaces r.app.Remote) to overriding vm.accountClick directly
// on the SystemDropDown view model (M2 fix). The VM is stable for the
// lifetime of the page; no dependency on Remote internals.

(function () {
	const STORAGE_KEY = 'frickmail_accounts_cache';
	let emailToId = {};   // email → frickmail DB account id
	let injecting = false;
	let store     = null;
	let dropVm    = null; // SystemDropDown view model reference

	// ── Cache helpers ──────────────────────────────────────────────

	function saveCache(accounts) {
		try { localStorage.setItem(STORAGE_KEY, JSON.stringify(accounts)); } catch (e) {}
	}
	function loadCache() {
		try { return JSON.parse(localStorage.getItem(STORAGE_KEY) || 'null'); } catch (e) { return null; }
	}
	function clearCache() {
		try { localStorage.removeItem(STORAGE_KEY); } catch (e) {}
	}

	// Clear on logout or session loss (M3).
	window.addEventListener('rl-logout', clearCache);
	window.addEventListener('beforeunload', () => {
		if (window._fmSessionLost) clearCache();
	});

	// ── Build fake AccountModel-compatible object ──────────────────

	function buildFakeAccount(acc) {
		return {
			email:        acc.email,
			name:         acc.label || '',
			displayName:  acc.label ? acc.label + ' <' + acc.email + '>' : acc.email,
			label:        () => acc.label || acc.email,
			isAdditional: window.ko?.observable(true),
			unreadEmails: window.ko?.observable(null),
			askDelete:    window.ko?.observable(false),
			count:        () => 0,
			_frickmail:   true,   // marker so accountClick knows this is ours
		};
	}

	// ── Inject accounts into AccountUserStore ──────────────────────

	function injectFromList(accounts) {
		if (!store || !accounts) return;
		const currentEmail = store.email?.() || '';
		injecting = true;
		emailToId = {};
		accounts.forEach(acc => {
			emailToId[acc.email] = acc.id;
			if (acc.email === currentEmail) return;
			if (store().some(a => a.email === acc.email)) return;
			store.push(buildFakeAccount(acc));
		});
		injecting = false;
	}

	// ── Fetch accounts from server + inject ────────────────────────

	function fetchAndInject() {
		const r = window.rl;
		if (!r) return;

		fetch('?/AppData/0/' + Math.random().toString().slice(2) + '/', {
			credentials: 'same-origin', cache: 'no-cache',
			headers: { Accept: 'application/json' }
		})
		.then(res => res.json())
		.then(data => {
			const tok = data?.System?.token;
			if (!tok) return;
			r.__frickmail_token = tok;

			r.pluginRemoteRequest((iErr, oData) => {
				const res = oData?.Result;
				if (!res?.ok || !res.accounts) {
					if (res && !res.ok) window._fmSessionLost = true;
					return;
				}
				window._fmSessionLost = false;
				saveCache(res.accounts);
				injectFromList(res.accounts);
			}, 'FrickmailListAccounts', { XToken: tok }, 10000);
		})
		.catch(() => {});
	}

	// ── Override vm.accountClick (replaces Remote.request monkey-patch) ──
	//
	// The original accountClick calls Remote.request('AccountSwitch', callback, {Email})
	// and on success calls rl.route.reload(). We replace the whole method so we:
	//  • Call FrickmailSwitchAccount for accounts we own (_frickmail: true)
	//  • Delegate to the original handler for SnappyMail's own accounts
	// This is robust: depends only on the VM object existing, not on Remote internals.

	function patchAccountClick(vm) {
		if (vm._frickmail_click_patched) return;
		vm._frickmail_click_patched = true;

		const origClick = vm.accountClick.bind(vm);

		vm.accountClick = function (account, event) {
			// Not our account → let SnappyMail handle it normally.
			if (!account?._frickmail) {
				return origClick(account, event);
			}
			// Our account → must be left-click and not already the active one.
			if (!account?.email || event?.button !== 0) return true;
			if (store?.email?.() === account.email) return true;

			store?.loading?.(true);
			event && typeof event.stopPropagation === 'function' && event.stopPropagation();

			const r = window.rl;
			const tok = r.__frickmail_token || r.settings?.app?.('token');

			r.pluginRemoteRequest((iErr, oData) => {
				const res = oData?.Result;
				if (res?.ok) {
					// Success: SnappyMail will do location.reload() inside route.reload()
					r.route?.reload?.();
				} else {
					store?.loading?.(false);
					const msg = res?.error || 'Switch failed';
					// Show error in the same way the original handler would.
					alert('Account error: ' + msg);
				}
			}, 'FrickmailSwitchAccount',
				{ id: emailToId[account.email], XToken: tok },
				30000
			);
			return true;
		};
	}

	// ── rl-view-model handler ──────────────────────────────────────

	addEventListener('rl-view-model', e => {
		if (e.detail?.viewModelTemplateID !== 'SystemDropDown') return;
		const headerDom = e.detail.viewModelDom;
		if (!headerDom) return;

		setTimeout(() => {
			const vm = window.ko?.dataFor(headerDom);
			if (!vm) return;

			dropVm = vm;
			store  = vm.accounts || null;
			if (!store) return;

			// Patch accountClick on the VM (safe refactor of Remote.request monkey-patch).
			patchAccountClick(vm);

			// Wire "+" button to Frickmail Mail Accounts settings.
			vm.addAccountClick = () => { location.hash = '#/settings/mail-accounts'; };
			const addBtn = headerDom.querySelector('[data-i18n="TOP_TOOLBAR/BUTTON_ADD_ACCOUNT"]')?.closest('li');
			if (addBtn) addBtn.hidden = false;

			// Inject from cache immediately, then refresh from server.
			const cached = loadCache();
			if (cached) injectFromList(cached);
			fetchAndInject();

			// Re-inject after SnappyMail reloads the account list.
			let wasLoading = false;
			store.loading?.subscribe(isLoading => {
				if (injecting) return;
				if (isLoading) {
					wasLoading = true;
				} else if (wasLoading) {
					wasLoading = false;
					const cached2 = loadCache();
					if (cached2) setTimeout(() => injectFromList(cached2), 50);
					setTimeout(fetchAndInject, 200);
				}
			});
		}, 200);
	});
})();
