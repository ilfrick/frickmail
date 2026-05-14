// Frickmail account switcher — populates SnappyMail's top-right account
// dropdown with all Frickmail mail accounts and intercepts AccountSwitch
// to call FrickmailSwitchAccount instead of SnappyMail's native handler.

addEventListener('rl-view-model', e => {
	if (e.detail?.viewModelTemplateID !== 'Header') return;

	const headerDom = e.detail.viewModelDom;
	if (!headerDom) return;

	// Wait one tick so SnappyMail finishes binding the Header VM.
	setTimeout(() => {
		const r = window.rl;
		if (!r?.app?.Remote) return;

		const tok = r.settings?.app?.('token');
		if (!tok) return;

		// Keep a local map email → frickmail account id for the switch handler.
		const emailToId = {};

		// Patch Remote.request ONCE to intercept AccountSwitch.
		if (!r.app.Remote._frickmail_patched) {
			r.app.Remote._frickmail_patched = true;
			const orig = r.app.Remote.request.bind(r.app.Remote);
			r.app.Remote.request = (action, callback, params, ...rest) => {
				if (action === 'AccountSwitch' && params?.Email && emailToId[params.Email]) {
					r.pluginRemoteRequest((iErr, oData) => {
						if (oData?.Result?.ok) {
							callback(0); // success → SnappyMail will call rl.route.reload()
						} else {
							callback(1, oData); // error
						}
					}, 'FrickmailSwitchAccount',
						{ id: emailToId[params.Email], XToken: r.settings?.app?.('token') },
						30000);
					return;
				}
				return orig(action, callback, params, ...rest);
			};
		}

		// Fetch Frickmail accounts and inject into AccountUserStore.
		r.pluginRemoteRequest((iErr, oData) => {
			const res = oData?.Result;
			if (!res?.ok || !res.accounts) return;

			// AccountUserStore is not exported, but the Header VM exposes it
			// as this.accounts — reach it via ko.dataFor on the header root.
			const vm = window.ko?.dataFor(headerDom);
			const store = vm?.accounts;
			if (!store) return;

			res.accounts.forEach(acc => {
				emailToId[acc.email] = acc.id;
				if (acc.is_primary) return; // primary is already the main account in the store

				// Skip if already present (e.g. page refresh).
				if (store().some(a => a.email === acc.email)) return;

				// Create an AccountModel-compatible plain object.
				const fake = {
					email: acc.email,
					name: acc.label || '',
					displayName: acc.label ? acc.label + ' <' + acc.email + '>' : acc.email,
					label:         () => acc.label || acc.email,
					isAdditional:  window.ko?.observable(true),
					unreadEmails:  window.ko?.observable(null),
					askDelete:     window.ko?.observable(false),
					count:         () => 0,
				};
				store.push(fake);
			});
		}, 'FrickmailListAccounts', { XToken: tok }, 10000);
	}, 100);
});
