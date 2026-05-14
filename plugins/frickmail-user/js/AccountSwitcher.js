// Frickmail account switcher — populates SnappyMail's top-right account
// dropdown with all Frickmail mail accounts and intercepts AccountSwitch.

(function () {
	let emailToId  = {};
	let injecting  = false;
	let store      = null;

	function getToken() {
		const r = window.rl;
		return r?.settings?.app?.('token') || r?.__frickmail_token || null;
	}

	function injectAccounts() {
		if (!store) return;
		const tok = getToken();

		window.rl.pluginRemoteRequest((iErr, oData) => {
			const res = oData?.Result;
			if (!res?.ok || !res.accounts) return;

			emailToId = {};
			injecting = true;
			res.accounts.forEach(acc => {
				emailToId[acc.email] = acc.id;
				if (acc.is_primary) return;
				if (store().some(a => a.email === acc.email)) return;
				store.push({
					email:        acc.email,
					name:         acc.label || '',
					displayName:  acc.label ? acc.label + ' <' + acc.email + '>' : acc.email,
					label:        () => acc.label || acc.email,
					isAdditional: window.ko?.observable(true),
					unreadEmails: window.ko?.observable(null),
					askDelete:    window.ko?.observable(false),
					count:        () => 0,
				});
			});
			injecting = false;
		}, 'FrickmailListAccounts', tok ? {XToken: tok} : {}, 10000);
	}

	// Fetch a fresh AppData token, then inject accounts.
	function injectWithFreshToken() {
		fetch('?/AppData/0/' + Math.random().toString().slice(2) + '/', {
			credentials: 'same-origin', cache: 'no-cache',
			headers: { Accept: 'application/json' }
		})
		.then(r => r.json())
		.then(data => {
			if (data?.System?.token) {
				if (window.rl) window.rl.__frickmail_token = data.System.token;
			}
			injectAccounts();
		})
		.catch(() => injectAccounts()); // fallback — try without fresh token
	}

	function patchRemote(r) {
		if (r.app.Remote._frickmail_patched) return;
		r.app.Remote._frickmail_patched = true;
		const orig = r.app.Remote.request.bind(r.app.Remote);
		r.app.Remote.request = (action, callback, params, ...rest) => {
			if (action === 'AccountSwitch' && params?.Email && emailToId[params.Email]) {
				r.pluginRemoteRequest((iErr, oData) => {
					callback(oData?.Result?.ok ? 0 : 1, oData);
				}, 'FrickmailSwitchAccount',
					{ id: emailToId[params.Email], XToken: getToken() },
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

			// Use fresh AppData token to avoid stale-token aborts on page reload.
			injectWithFreshToken();

			// Re-inject after SnappyMail reloads the account list
			// (loadAccountsAndIdentities sets loading true→false).
			let wasLoading = false;
			store.loading?.subscribe(isLoading => {
				if (injecting) return;
				if (isLoading) {
					wasLoading = true;
				} else if (wasLoading) {
					wasLoading = false;
					setTimeout(injectWithFreshToken, 50);
				}
			});
		}, 300); // give SnappyMail time to finish initialising rl.settings
	});
})();
