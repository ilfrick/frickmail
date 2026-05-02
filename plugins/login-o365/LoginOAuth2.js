(rl => {
	const client_id = rl.pluginSettingsGet('login-o365', 'client_id'),
		// https://learn.microsoft.com/en-us/entra/identity-platform/reply-url#query-parameter-support-in-redirect-uris
		query = rl.pluginSettingsGet('login-o365', 'personal') ? '' : '?',
		tenant = rl.pluginSettingsGet('login-o365', 'tenant') || 'common',
		domainsRaw = (rl.pluginSettingsGet('login-o365', 'domains') || 'outlook.com hotmail.com live.com msn.com hotmail.it outlook.it live.it'),
		domains = domainsRaw.split(/\s+/).map(d => d.trim().toLowerCase()).filter(Boolean),
		matches = email => {
			email = (email || '').toLowerCase();
			return domains.some(d => email.endsWith('@' + d));
		},
		login = () => {
			document.location = 'https://login.microsoftonline.com/'+tenant+'/oauth2/v2.0/authorize?' + (new URLSearchParams({
				response_type: 'code',
				client_id: client_id,
				redirect_uri: document.location.href.replace(/\/$/, '') + '/' + query + 'LoginO365',
				scope: [
					'openid',
					'offline_access',
					'email',
					'profile',
					'https://graph.microsoft.com/IMAP.AccessAsUser.All',
					'https://graph.microsoft.com/SMTP.Send'
				].join(' '),
				state: 'o365',
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
					btn = Element.fromHTML('<button type="button">Sign in with Microsoft</button>'),
					div = Element.fromHTML('<div class="controls"></div>');
				btn.onclick = login;
				div.append(btn);
				container && container.append(div);
			}
		});
	}

})(window.rl);
