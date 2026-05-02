(rl => {
	const client_id = rl.pluginSettingsGet('login-gmail', 'client_id'),
		domainsRaw = (rl.pluginSettingsGet('login-gmail', 'domains') || 'gmail.com googlemail.com'),
		domains = domainsRaw.split(/\s+/).map(d => d.trim().toLowerCase()).filter(Boolean),
		matches = email => {
			email = (email || '').toLowerCase();
			return domains.some(d => email.endsWith('@' + d));
		},
		login = () => {
			document.location = 'https://accounts.google.com/o/oauth2/auth?' + (new URLSearchParams({
				response_type: 'code',
				client_id: client_id,
				redirect_uri: document.location.href + '?LoginGMail',
				scope: [
					'https://www.googleapis.com/auth/userinfo.email',
					'https://www.googleapis.com/auth/userinfo.profile',
					'openid',
					'https://mail.google.com/'
				].join(' '),
				state: 'gmail',
				access_type: 'offline',
				prompt: 'consent'
			}));
		};

	if (client_id) {
		addEventListener('sm-user-login', e => {
			if (matches(e.detail.get('Email'))) {
				e.preventDefault();
				login();
			}
		});

		addEventListener('rl-view-model', e => {
			if ('Login' === e.detail.viewModelTemplateID) {
				const
					container = e.detail.viewModelDom.querySelector('#plugin-Login-BottomControlGroup'),
					btn = Element.fromHTML('<button type="button">Sign in with Google</button>'),
					div = Element.fromHTML('<div class="controls"></div>');
				btn.onclick = login;
				div.append(btn);
				container && container.append(div);
			}
		});
	}

})(window.rl);
