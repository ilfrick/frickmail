// Frickmail account switcher — populates SnappyMail's top-right account
// dropdown with all Frickmail mail accounts and intercepts AccountSwitch.

(function () {
	let emailToId = {};   // email → frickmail account id
	let injecting = false;

	function injectAccounts(store) {
		const r = window.rl;
		if (!r) return;
		const tok = r.settings?.app?.('token');

		r.pluginRemoteRequest((iErr, oData) => {
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

	function patchRemote(r) {
		if (r.app.Remote._frickmail_patched) return;
		r.app.Remote._frickmail_patched = true;
		const orig = r.app.Remote.request.bind(r.app.Remote);
		r.app.Remote.request = (action, callback, params, ...rest) => {
			if (action === 'AccountSwitch' && params?.Email && emailToId[params.Email]) {
				r.pluginRemoteRequest((iErr, oData) => {
					callback(oData?.Result?.ok ? 0 : 1, oData);
				}, 'FrickmailSwitchAccount',
					{ id: emailToId[params.Email], XToken: r.settings?.app?.('token') },
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
			const store = vm?.accounts;
			if (!store) return;

			// Inject now.
			injectAccounts(store);

			// Re-inject after every time SnappyMail reloads the account list
			// (loading: true → false means the store was just reset).
			let wasLoading = false;
			store.loading?.subscribe(isLoading => {
				if (!injecting) {
					if (isLoading) {
						wasLoading = true;
					} else if (wasLoading) {
						wasLoading = false;
						setTimeout(() => injectAccounts(store), 50);
					}
				}
			});
		}, 100);
	});
})();
