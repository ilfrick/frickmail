(rl => { if (!rl) return;

	// Replace the default IMAP login form with Frickmail's user-centred form.
	// On submit we hit ?Json/&q[]=/0/Plugin/-/&_action=FrickmailLogin which
	// (server-side) bridges to LoginProcess() once it has retrieved the
	// primary mail account credentials from the user's encrypted record.

	let mode = 'login'; // 'login' | 'register'

	const buildForm = (root, openSignup) => {
		const wrap = document.createElement('div');
		wrap.className = 'frickmail-login compact';
		const _iconSrc = document.querySelector('link[rel="icon"]')?.href || '';
		wrap.innerHTML = `
			${_iconSrc ? `<div style="text-align:center;margin-bottom:.6em"><img src="${_iconSrc}" alt="" style="width:64px;height:64px;border-radius:14px"></div>` : ''}
			<h2 data-fm="title">Sign in to Frickmail</h2>
			<form data-fm="form">
				<label for="fm-username">Username</label>
				<input id="fm-username" data-fm="username" type="text" autocomplete="username" required />
				<div data-fm="email-row" style="display:none">
					<label for="fm-email">Recovery email <span style="font-weight:normal;opacity:.7">(used to reset password)</span></label>
					<input id="fm-email" data-fm="email" type="email" autocomplete="email" />
				</div>
				<label for="fm-password">Password</label>
				<input id="fm-password" data-fm="password" type="password" autocomplete="current-password" required minlength="8" />
				<div data-fm="totp-row" style="display:none">
					<label for="fm-totp">Two-factor code</label>
					<input id="fm-totp" data-fm="totp" type="text" inputmode="numeric" autocomplete="one-time-code" maxlength="8" />
				</div>
				<div class="actions">
					<button class="btn btn-primary" type="submit" data-fm="submit">Sign in</button>
					<button class="switch-mode" type="button" data-fm="switch">Create an account</button>
				</div>
				<div style="margin-top:.6em;font-size:90%">
					<a href="#" data-fm="forgot" style="color:#4a90e2">Forgot password?</a>
				</div>
				<div class="status" data-fm="status"></div>
			</form>`;
		root.replaceChildren(wrap);

		const $f = sel => wrap.querySelector(`[data-fm="${sel}"]`);
		const setStatus = (msg, kind) => {
			const el = $f('status'); el.textContent = msg || ''; el.className = 'status' + (kind ? ' ' + kind : '');
		};

		const switchMode = newMode => {
			mode = newMode;
			$f('title').textContent = 'login' === mode ? 'Sign in to Frickmail' : 'Create your Frickmail account';
			$f('email-row').style.display = 'login' === mode ? 'none' : '';
			$f('email').required = 'register' === mode;
			$f('submit').textContent = 'login' === mode ? 'Sign in' : 'Register';
			$f('switch').textContent = 'login' === mode ? 'Create an account' : 'Already have one — sign in';
			$f('password').autocomplete = 'login' === mode ? 'current-password' : 'new-password';
			setStatus('');
		};

		$f('switch').onclick = () => switchMode('login' === mode ? 'register' : 'login');

		$f('forgot').onclick = e => {
			e.preventDefault();
			showForgotForm(wrap);
		};

		// Always fetch a fresh AppData to bind the CSRF token to the *current*
		// CONNECTION_TOKEN cookie. A cached RL_APP_DATA.System.token can be stale
		// (cookie rotated, container restart, …) → server reports XToken mismatch.
		const refreshCsrfToken = async () => {
			try {
				const r = await fetch('?/AppData/0/' + Math.random().toString().slice(2) + '/', {
					credentials: 'same-origin', cache: 'no-cache',
					headers: { 'Accept': 'application/json' }
				});
				const data = await r.json();
				if (data?.System?.token) {
					rl.__frickmail_token = data.System.token;
					// Best-effort: keep the standard slot in sync too so later code paths agree
					try { rl.settings.set?.('System', data.System); } catch (e) {}
					return data.System.token;
				}
			} catch (e) { /* fall through */ }
			return null;
		};

		$f('form').onsubmit = async e => {
			e.preventDefault();
			const username = $f('username').value.trim();
			const password = $f('password').value;
			const email    = $f('email').value.trim();
			if (!username || !password) { setStatus('Username and password required', 'error'); return; }

			setStatus('login' === mode ? 'Signing in…' : 'Creating account…');
			const fresh = await refreshCsrfToken();
			const action = 'login' === mode ? 'FrickmailLogin' : 'FrickmailRegister';
			const xtoken = fresh || rl.settings?.app?.('token') || rl.__frickmail_token;
			const totpCode = ($f('totp')?.value || '').replace(/\s+/g, '');
			const params = { username, password, email };
			if (totpCode) params.totp_code = totpCode;
			if (xtoken) params.XToken = xtoken;
			rl.pluginRemoteRequest((iError, oData) => {
					if (iError && !oData) { setStatus('Network error (no response)', 'error'); return; }
				const r = oData?.Result;
				if (false === r || null == r) {
					const dump = JSON.stringify(oData).slice(0, 200);
					setStatus('Server says: ' + dump, 'error');
					return;
				}
				if (!r.ok) {
					if (r.requires_totp) {
						$f('totp-row').style.display = '';
						$f('totp').focus();
						setStatus(r.error || 'Two-factor code required', 'error');
						return;
					}
					setStatus(r.error || 'Failed', 'error');
					return;
				}
				if ('FrickmailRegister' === action) {
					setStatus(r.message || 'Account created — now sign in', 'ok');
					switchMode('login');
					return;
				}
				if (r.reauth_required) {
					setStatus(r.message || 'Re-enter the IMAP password.', 'ok');
					showReauthForm(wrap, r.reauth_account_id, r.reauth_account_email, r.reauth_account_type);
					return;
				}
				if (r.no_primary) {
					setStatus('Logged in. Set up your first mail account below.', 'ok');
					showFirstAccountForm(wrap);
					return;
				}
				setStatus('Welcome ' + (r.email || ''), 'ok');
				setTimeout(() => document.location.reload(), 400);
			}, action, params, 30000);
		};
	};

	const callPlugin = (action, params, cb) => {
		const xtoken = rl.settings?.app?.('token') || rl.__frickmail_token;
		if (xtoken) params.XToken = xtoken;
		rl.pluginRemoteRequest(cb, action, params, 30000);
	};

	const showReauthForm = (wrap, accountId, email, type) => {
		wrap.classList.remove('compact');
		const setStatus = (msg, kind) => {
			const el = wrap.querySelector('[data-fm="status"]');
			if (el) { el.textContent = msg || ''; el.className = 'status' + (kind ? ' ' + kind : ''); }
		};
		const setup = document.createElement('div');
		setup.innerHTML = `
			<h3 style="margin-top:1em">Re-authenticate ${email}</h3>
			<p style="color:#888">After a password reset, the encrypted IMAP/OAuth credentials are unrecoverable. Re-enter them here to keep using this mailbox.</p>
			${type === 'imap'
				? `<label for="fm-rf-password">IMAP password</label><input id="fm-rf-password" data-rf="password" type="password" autocomplete="new-password" />`
				: `<p>Click below to re-link via OAuth (${type === 'gmail' ? 'Google' : 'Microsoft'}).</p>`}
			<div style="margin-top:1em;display:flex;gap:.6em;flex-wrap:wrap">
				<button class="btn" type="button" data-rf="save" style="background:#4a90e2;color:white">Save and open mailbox</button>
				${type !== 'imap' ? '<button class="btn" type="button" data-rf="relink" style="background:transparent;border:1px solid #4a90e2;color:#4a90e2">Re-link OAuth (renew)</button>' : ''}
			</div>
			<div class="status" data-fm="status"></div>`;
		wrap.querySelector('form').replaceWith(setup);

		const switchToPrimary = () => {
			callPlugin('FrickmailSwitchAccount', { id: accountId }, (iErr, oData) => {
				const r = oData?.Result;
				if (!r?.ok) { setStatus('Switch failed: ' + (r?.error || 'unknown'), 'error'); return; }
				setTimeout(() => document.location.reload(), 400);
			});
		};

		const openOAuthPopup = () => {
			const path = type === 'gmail' ? 'StartLoginGMail' : 'StartLoginO365';
			const base = document.location.href.replace(/[#?].*$/, '').replace(/\/+$/, '');
			const w = 520, h = 640,
				y = (screen.availHeight - h) / 2,
				x = (screen.availWidth - w) / 2;
			const popup = window.open(base + '/?' + path, 'frickmail-oauth-' + type,
				`popup=yes,width=${w},height=${h},left=${x},top=${y}`);
			if (!popup) { setStatus('Popup blocked — allow popups and retry', 'error'); return; }
			setStatus('Waiting for ' + type + ' consent…', 'ok');
			const onMsg = e => {
				if (e.origin !== window.location.origin) return;
				const d = e.data;
				if (!d || d.type !== 'frickmail-oauth2') return;
				removeEventListener('message', onMsg);
				if (d.status !== 'ok') { setStatus('OAuth failed: ' + (d.error || 'unknown'), 'error'); return; }
				// If the popup couldn't save the token server-side (no session in callback),
				// save it now from the opener window where the Frickmail session is active.
				if (d.pending_refresh_token) {
					setStatus('Saving OAuth token…', 'ok');
					callPlugin('FrickmailSaveOAuthToken',
						{ type: type, email: d.email || email, refresh_token: d.pending_refresh_token },
						(iErr, oData) => {
							if (!oData?.Result?.ok) {
								setStatus('Token save failed: ' + (oData?.Result?.error || 'unknown'), 'error');
								return;
							}
							switchToPrimary();
						}
					);
					return;
				}
				switchToPrimary();
			};
			addEventListener('message', onMsg);
		};

		setup.querySelector('[data-rf="save"]').onclick = () => {
			if ('imap' === type) {
				const pwd = setup.querySelector('[data-rf="password"]').value;
				if (!pwd) { setStatus('Password required', 'error'); return; }
				setStatus('Saving…', 'ok');
				callPlugin('FrickmailSetAccountPassword', { id: accountId, password: pwd }, (iErr, oData) => {
					const r = oData?.Result;
					if (!r?.ok) { setStatus('Save failed: ' + (r?.error || 'unknown'), 'error'); return; }
					switchToPrimary();
				});
				return;
			}
			// OAuth — try the saved token in DB first (no popup needed if still valid).
			setStatus('Trying saved credentials…', 'ok');
			callPlugin('FrickmailSwitchAccount', { id: accountId }, (iErr, oData) => {
				const r = oData?.Result;
				if (r?.ok) { setTimeout(() => document.location.reload(), 400); return; }
				// Saved token missing or expired → fall back to OAuth popup.
				setStatus('Saved token invalid (' + (r?.error || 'unknown') + '). Re-linking…', 'ok');
				setTimeout(openOAuthPopup, 600);
			});
		};

		// Explicit "Re-link OAuth" button forces the popup regardless of DB state.
		setup.querySelector('[data-rf="relink"]')?.addEventListener('click', openOAuthPopup);
	};

	const showFirstAccountForm = (wrap) => {
		// Switch out of compact mode so the host/port/security row has room to breathe.
		wrap.classList.remove('compact');
		const setStatus = (msg, kind) => {
			const el = wrap.querySelector('[data-fm="status"]');
			if (el) { el.textContent = msg || ''; el.className = 'status' + (kind ? ' ' + kind : ''); }
		};
		// Replace the form area with a setup wizard
		const setup = document.createElement('div');
		setup.innerHTML = `
			<h3 style="margin-top:1em">Add your first mail account</h3>
			<label for="fm-fa-type">Type</label>
			<select id="fm-fa-type" data-fa="type">
				<option value="imap">IMAP / SMTP (any provider)</option>
				<option value="gmail">Gmail (OAuth)</option>
				<option value="o365">Office 365 / Outlook (OAuth)</option>
			</select>
			<div data-fa="imap-fields">
				<label for="fm-fa-email">Email</label><input id="fm-fa-email" data-fa="email" type="email" />
				<label for="fm-fa-login">IMAP login (if different)</label><input id="fm-fa-login" data-fa="login" type="text" />
				<label for="fm-fa-password">IMAP password</label><input id="fm-fa-password" data-fa="password" type="password" autocomplete="new-password" />
				<div style="display:flex;gap:.5em">
					<div style="flex:2"><label for="fm-fa-imap_host">IMAP host</label><input id="fm-fa-imap_host" data-fa="imap_host" type="text" placeholder="imap.example.com" /></div>
					<div style="flex:1"><label for="fm-fa-imap_port">Port</label><input id="fm-fa-imap_port" data-fa="imap_port" type="number" value="993" /></div>
					<div style="flex:1"><label for="fm-fa-imap_secure">Sec.</label><select id="fm-fa-imap_secure" data-fa="imap_secure"><option>SSL</option><option>STARTTLS</option><option>NONE</option></select></div>
				</div>
				<div style="display:flex;gap:.5em">
					<div style="flex:2"><label for="fm-fa-smtp_host">SMTP host</label><input id="fm-fa-smtp_host" data-fa="smtp_host" type="text" placeholder="smtp.example.com" /></div>
					<div style="flex:1"><label for="fm-fa-smtp_port">Port</label><input id="fm-fa-smtp_port" data-fa="smtp_port" type="number" value="465" /></div>
					<div style="flex:1"><label for="fm-fa-smtp_secure">Sec.</label><select id="fm-fa-smtp_secure" data-fa="smtp_secure"><option>SSL</option><option>STARTTLS</option><option>NONE</option></select></div>
				</div>
			</div>
			<div data-fa="oauth-fields" style="display:none">
				<label for="fm-fa-oauth_email">Email</label><input id="fm-fa-oauth_email" data-fa="oauth_email" type="email" placeholder="(detected after consent)" />
				<p style="color:#888;margin-top:.6em">Click below; a popup will ask the provider for consent. The refresh token is then linked to your Frickmail account.</p>
			</div>
			<div style="margin-top:1em;display:flex;gap:.6em">
				<button class="btn btn-primary" type="button" data-fa="save" style="background:#4a90e2;color:white">Save and open mailbox</button>
			</div>`;
		wrap.querySelector('form').replaceWith(setup);

		const $a = sel => setup.querySelector(`[data-fa="${sel}"]`);
		const refreshFields = () => {
			const t = $a('type').value;
			$a('imap-fields').style.display = (t === 'imap') ? '' : 'none';
			$a('oauth-fields').style.display = (t === 'imap') ? 'none' : '';
			$a('save').textContent = (t === 'imap') ? 'Save and open mailbox' : ('Sign in with ' + (t === 'gmail' ? 'Google' : 'Microsoft'));
		};
		$a('type').onchange = refreshFields;
		refreshFields();

		const switchToPrimary = () => {
			callPlugin('FrickmailListAccounts', {}, (iErr, oData) => {
				const r = oData?.Result;
				if (!r?.ok) { setStatus('Linked but could not list accounts: ' + (r?.error || 'unknown'), 'error'); return; }
				const primary = (r.accounts || []).find(a => a.is_primary) || r.accounts?.[0];
				if (!primary) { setStatus('Saved, but no primary account found', 'error'); return; }
				setStatus('Switching to ' + primary.email + '…', 'ok');
				callPlugin('FrickmailSwitchAccount', { id: primary.id }, (iErr2, oData2) => {
					const r2 = oData2?.Result;
					if (!r2?.ok) { setStatus('Switch failed: ' + (r2?.error || 'unknown'), 'error'); return; }
					setTimeout(() => document.location.reload(), 400);
				});
			});
		};

		$a('save').onclick = () => {
			const t = $a('type').value;
			if (t === 'imap') {
				const data = {
					type: 'imap',
					label: $a('email').value.trim() || 'Mail',
					email: $a('email').value.trim(),
					login: $a('login').value.trim() || $a('email').value.trim(),
					password: $a('password').value,
					imap_host: $a('imap_host').value.trim(),
					imap_port: parseInt($a('imap_port').value, 10),
					imap_secure: $a('imap_secure').value,
					smtp_host: $a('smtp_host').value.trim(),
					smtp_port: parseInt($a('smtp_port').value, 10),
					smtp_secure: $a('smtp_secure').value,
					is_primary: true
				};
				if (!data.email || !data.password || !data.imap_host) { setStatus('Email, password, IMAP host required', 'error'); return; }
				setStatus('Saving…', 'ok');
				callPlugin('FrickmailAddAccount', data, (iErr, oData) => {
					const r = oData?.Result;
					if (!r?.ok) { setStatus('Save failed: ' + (r?.error || 'unknown'), 'error'); return; }
					switchToPrimary();
				});
				return;
			}
			// OAuth
			const provider = t;
			const path = provider === 'gmail' ? 'StartLoginGMail' : 'StartLoginO365';
			const base = document.location.href.replace(/[#?].*$/, '').replace(/\/+$/, '');
			const w = 520, h = 640,
				y = (screen.availHeight - h) / 2,
				x = (screen.availWidth - w) / 2;
			const popup = window.open(base + '/?' + path, 'frickmail-oauth-' + provider,
				`popup=yes,width=${w},height=${h},left=${x},top=${y}`);
			if (!popup) { setStatus('Popup blocked — allow popups and retry', 'error'); return; }
			setStatus('Waiting for ' + provider + ' consent…', 'ok');
			const onMsg = e => {
				if (e.origin !== window.location.origin) return;
				const d = e.data;
				if (!d || d.type !== 'frickmail-oauth2') return;
				removeEventListener('message', onMsg);
				if (d.status !== 'ok') { setStatus('OAuth failed: ' + (d.error || 'unknown'), 'error'); return; }
				setStatus('Linked ' + (d.email || provider) + '. Switching…', 'ok');
				switchToPrimary();
			};
			addEventListener('message', onMsg);
		};
	};

	const showForgotForm = (wrap) => {
		const setStatus = (msg, kind) => {
			const el = wrap.querySelector('[data-fm="status"]');
			if (el) { el.textContent = msg || ''; el.className = 'status' + (kind ? ' ' + kind : ''); }
		};
		const setup = document.createElement('div');
		setup.innerHTML = `
			<h2>Recupero password</h2>
			<p style="color:#888">Inserisci il tuo username Frickmail. Se esiste e ha una recovery email, ti mandiamo un link per resettare la password.</p>
			<label for="fm-ff-username">Username</label>
			<input id="fm-ff-username" data-ff="username" type="text" autocomplete="username" />
			<div class="actions" style="margin-top:1em">
				<button class="btn btn-primary" type="button" data-ff="send">Send reset link</button>
				<button class="switch-mode" type="button" data-ff="back">Back to sign-in</button>
			</div>
			<div class="status" data-fm="status"></div>`;
		wrap.querySelector('form').replaceWith(setup);

		const $g = sel => setup.querySelector(`[data-ff="${sel}"]`);
		$g('back').onclick = () => document.location.reload();
		$g('send').onclick = async () => {
			const username = $g('username').value.trim();
			if (!username) { setStatus('Username required', 'error'); return; }
			setStatus('Sending…');
			const xtoken = rl.settings?.app?.('token') || rl.__frickmail_token;
			const params = { username };
			if (xtoken) params.XToken = xtoken;
			rl.pluginRemoteRequest((iError, oData) => {
				const r = oData?.Result;
				if (false === r || null == r) { setStatus('Server: ' + JSON.stringify(oData).slice(0, 200), 'error'); return; }
				if (!r.ok) { setStatus(r.error || 'Failed', 'error'); return; }
				setStatus(r.message || 'If the username exists, an email was sent.', 'ok');
			}, 'FrickmailRequestPasswordReset', params, 30000);
		};
	};

	const showResetForm = (host, token) => {
		const wrap = document.createElement('div');
		wrap.className = 'frickmail-login compact';
		wrap.innerHTML = `
			<h2>Imposta una nuova password</h2>
			<p style="color:#888">Le credenziali IMAP/OAuth dei tuoi account email collegati saranno reimpostate (devi reinserirle dal Setup).</p>
			<label for="fm-fr-password">Nuova password (min 8 caratteri)</label>
			<input id="fm-fr-password" data-fr="password" type="password" autocomplete="new-password" minlength="8" />
			<label for="fm-fr-password2">Conferma password</label>
			<input id="fm-fr-password2" data-fr="password2" type="password" autocomplete="new-password" />
			<div class="actions">
				<button class="btn btn-primary" type="button" data-fr="save">Reset password</button>
			</div>
			<div class="status" data-fr="status"></div>`;
		host.replaceChildren(wrap);
		const $r = sel => wrap.querySelector(`[data-fr="${sel}"]`);
		const setStatus = (msg, kind) => {
			$r('status').textContent = msg || '';
			$r('status').className = 'status' + (kind ? ' ' + kind : '');
		};
		$r('save').onclick = () => {
			const p1 = $r('password').value;
			const p2 = $r('password2').value;
			if (p1.length < 8) { setStatus('Password must be at least 8 characters', 'error'); return; }
			if (p1 !== p2)    { setStatus('Passwords do not match', 'error'); return; }
			setStatus('Resetting…');
			const xtoken = rl.settings?.app?.('token') || rl.__frickmail_token;
			const params = { token, password: p1 };
			if (xtoken) params.XToken = xtoken;
			rl.pluginRemoteRequest((iError, oData) => {
				const r = oData?.Result;
				if (false === r || null == r) { setStatus('Server: ' + JSON.stringify(oData).slice(0, 200), 'error'); return; }
				if (!r.ok) { setStatus(r.error || 'Failed', 'error'); return; }
				setStatus(r.message || 'Password reset.', 'ok');
				// Strip the token from the URL and reload into the normal login form.
				const url = new URL(document.location.href);
				url.searchParams.delete('reset_token');
				setTimeout(() => { document.location.href = url.toString(); }, 1200);
			}, 'FrickmailResetPassword', params, 30000);
		};
	};

	addEventListener('rl-view-model', e => {
		if ('Login' !== e.detail.viewModelTemplateID) return;
		const dom = e.detail.viewModelDom;
		// Defer one tick so default bindings finish, then inject Frickmail form.
		setTimeout(() => {
			const host = dom.querySelector('.b-login-content') || dom;
			const resetToken = new URLSearchParams(location.search).get('reset_token');
			if (resetToken) {
				showResetForm(host, resetToken);
				return;
			}
			const openSignup = !!rl.pluginSettingsGet('frickmail-user', 'open_signup');
			buildForm(host, openSignup);
		}, 0);
	});

})(window.rl);
