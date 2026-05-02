(rl => {
	const PLUGIN = 'login-gmail',
		PROVIDER = 'gmail',
		domainsRaw = (rl.pluginSettingsGet(PLUGIN, 'domains') || 'gmail.com googlemail.com'),
		domains = domainsRaw.split(/\s+/).map(d => d.trim().toLowerCase()).filter(Boolean),
		matches = email => {
			email = (email || '').toLowerCase();
			return domains.some(d => email.endsWith('@' + d));
		};

	let popupRef = null,
		pendingResolve = null;

	const startLoginUrl = () => {
		// Hit the server-side launcher; it generates PKCE state and 302s to Google.
		const base = document.location.href.replace(/[#?].*$/, '').replace(/\/+$/, '');
		return base + '/?StartLoginGMail';
	};

	const openPopup = () => {
		const w = 520, h = 640,
			y = (screen.availHeight - h) / 2,
			x = (screen.availWidth - w) / 2;
		try { popupRef && popupRef.close(); } catch (e) {}
		popupRef = window.open(startLoginUrl(), 'frickmail-oauth2-' + PROVIDER,
			`popup=yes,width=${w},height=${h},left=${x},top=${y}`);
		if (!popupRef) {
			// Popup blocked — fall back to full-page redirect.
			document.location = startLoginUrl();
			return null;
		}
		return new Promise(resolve => {
			pendingResolve = resolve;
			const watch = setInterval(() => {
				if (!popupRef || popupRef.closed) {
					clearInterval(watch);
					if (pendingResolve) {
						const r = pendingResolve;
						pendingResolve = null;
						r({ status: 'cancelled' });
					}
				}
			}, 500);
		});
	};

	addEventListener('message', e => {
		if (e.origin !== window.location.origin) return;
		const d = e.data;
		if (!d || d.type !== 'frickmail-oauth2' || d.provider !== PROVIDER) return;
		if (pendingResolve) {
			const r = pendingResolve;
			pendingResolve = null;
			r(d);
		}
		try { popupRef && popupRef.close(); } catch (err) {}
	});

	const launch = async () => {
		const result = await openPopup();
		if (result && result.status === 'ok') {
			// Server has already established the SnappyMail session for this email.
			// Reload to enter the webmail.
			document.location.reload();
		} else if (result && result.status === 'error') {
			alert('Sign-in failed: ' + (result.error || 'unknown error'));
		}
	};

	addEventListener('sm-user-login', e => {
		if (matches(e.detail.get('Email'))) {
			e.preventDefault();
			launch();
		}
	});

	addEventListener('rl-view-model', e => {
		if ('Login' === e.detail.viewModelTemplateID) {
			const
				container = e.detail.viewModelDom.querySelector('#plugin-Login-BottomControlGroup'),
				btn = Element.fromHTML('<button type="button">Sign in with Google</button>'),
				div = Element.fromHTML('<div class="controls"></div>');
			btn.onclick = launch;
			div.append(btn);
			container && container.append(div);
		}
	});

})(window.rl);
