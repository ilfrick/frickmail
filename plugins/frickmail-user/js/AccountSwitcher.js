// Frickmail account switcher — populates SnappyMail's top-right account
// dropdown with all Frickmail mail accounts and intercepts AccountSwitch.
// Uses localStorage to cache the account list so it survives page reloads.

(function () {
	const STORAGE_KEY = 'frickmail_accounts_cache';
	let emailToId = {};
	let injecting = false;
	let store = null;

	function saveCache(accounts) {
		try { localStorage.setItem(STORAGE_KEY, JSON.stringify(accounts)); } catch (e) {}
	}

	function loadCache() {
		try { return JSON.parse(localStorage.getItem(STORAGE_KEY) || 'null'); } catch (e) { return null; }
	}

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
		};
	}

	function injectFromList(accounts) {
		if (!store || !accounts) return;
		// The current SnappyMail account email — skip this one (it's already the main entry).
		const currentEmail = store.email?.() || '';

		injecting = true;
		emailToId = {};
		accounts.forEach(acc => {
			emailToId[acc.email] = acc.id;
			// Skip the account that SnappyMail is currently logged in as.
			if (acc.email === currentEmail) return;
			if (store().some(a => a.email === acc.email)) return;
			store.push(buildFakeAccount(acc));
		});
		injecting = false;
	}

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
			if (r) r.__frickmail_token = tok;

			r.pluginRemoteRequest((iErr, oData) => {
				const res = oData?.Result;
				if (!res?.ok || !res.accounts) return;
				saveCache(res.accounts);
				injectFromList(res.accounts);
			}, 'FrickmailListAccounts', { XToken: tok }, 10000);
		})
		.catch(() => {});
	}

	function patchRemote(r) {
		if (r.app.Remote._frickmail_patched) return;
		r.app.Remote._frickmail_patched = true;
		const orig = r.app.Remote.request.bind(r.app.Remote);
		r.app.Remote.request = (action, callback, params, ...rest) => {
			if (action === 'AccountSwitch' && params?.Email && emailToId[params.Email]) {
				const tok = r.__frickmail_token || r.settings?.app?.('token');
				r.pluginRemoteRequest((iErr, oData) => {
					callback(oData?.Result?.ok ? 0 : 1, oData);
				}, 'FrickmailSwitchAccount',
					{ id: emailToId[params.Email], XToken: tok },
					30000);
				return;
			}
			return orig(action, callback, params, ...rest);
		};
	}

	addEventListener('rl-view-model', e => {
		if (e.detail?.viewModelTemplateID !== 'SystemDropDown') return;
		const headerDom = e.detail.viewModelDom;
		if (!headerDom) return;

		setTimeout(() => {
			const r = window.rl;
			if (!r?.app?.Remote) return;
			patchRemote(r);

			const vm = window.ko?.dataFor(headerDom);
			store = vm?.accounts || null;
			if (!store) return;

			// 1. Inject immediately from cache (no server round-trip needed).
			const cached = loadCache();
			if (cached) injectFromList(cached);

			// 2. Refresh from server in background to keep cache up to date.
			fetchAndInject();

			// 3. Re-inject after SnappyMail reloads the account list
			//    (loadAccountsAndIdentities sets loading true → false).
			let wasLoading = false;
			store.loading?.subscribe(isLoading => {
				if (injecting) return;
				if (isLoading) { wasLoading = true; }
				else if (wasLoading) {
					wasLoading = false;
					const cached2 = loadCache();
					if (cached2) {
						setTimeout(() => injectFromList(cached2), 50);
					}
					setTimeout(fetchAndInject, 200);
				}
			});
		}, 200);
	});
})();
