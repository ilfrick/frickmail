(rl => { if (!rl) return;

	// Replace SnappyMail's IMAP login form with a Frickmail user form.
	// On submit we hit ?Json/&q[]=/0/Plugin/-/&_action=FrickmailLogin which
	// (server-side) bridges to LoginProcess() once it has retrieved the
	// primary mail account credentials from the user's encrypted record.

	let mode = 'login'; // 'login' | 'register'

	const buildForm = (root, openSignup) => {
		const wrap = document.createElement('div');
		wrap.className = 'frickmail-login compact';
		wrap.innerHTML = `
			<style>
				.frickmail-login { max-width: 720px; margin: 4em auto; padding: 1.6em 1.8em; border:1px solid var(--border-color, #ccc); border-radius: 6px; background: var(--main-background, #fff); }
				.frickmail-login.compact { max-width: 380px; }
				.frickmail-login h2 { margin: 0 0 0.6em; font-size: 1.4em; }
				.frickmail-login label { display:block; margin-top: .8em; font-size: 90%; font-weight: 600; }
				.frickmail-login input { width:100%; box-sizing:border-box; padding:.45em .6em; }
				.frickmail-login .actions { margin-top: 1em; display:flex; gap:.6em; align-items:center; }
				.frickmail-login .actions .btn { padding:.5em 1em; }
				.frickmail-login .actions .btn-primary { background:#4a90e2; color:white; border:none; }
				.frickmail-login .switch-mode { margin-left:auto; background:none; border:none; color:#4a90e2; cursor:pointer; padding:0; }
				.frickmail-login .status { margin-top: .8em; min-height: 1em; color:#888; font-size:90%; }
				.frickmail-login .status.error { color:#c33; }
				.frickmail-login .status.ok { color:#2a8; }
			</style>
			<h2 data-fm="title">Sign in to Frickmail</h2>
			<form data-fm="form">
				<label>Username</label>
				<input data-fm="username" type="text" autocomplete="username" required />
				<div data-fm="email-row" style="display:none">
					<label>Recovery email <span style="font-weight:normal;opacity:.7">(used to reset password)</span></label>
					<input data-fm="email" type="email" autocomplete="email" />
				</div>
				<label>Password</label>
				<input data-fm="password" type="password" autocomplete="current-password" required minlength="8" />
				<div class="actions">
					<button class="btn btn-primary" type="submit" data-fm="submit">Sign in</button>
					<button class="switch-mode" type="button" data-fm="switch">Create an account</button>
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
			const params = { username, password, email };
			if (xtoken) params.XToken = xtoken;
			rl.pluginRemoteRequest((iError, oData) => {
				console.log('[frickmail-login] iError=', iError, 'oData=', oData);
				if (iError && !oData) { setStatus('Network error (no response)', 'error'); return; }
				const r = oData?.Result;
				if (false === r || null == r) {
					const dump = JSON.stringify(oData).slice(0, 200);
					setStatus('Server says: ' + dump, 'error');
					return;
				}
				if (!r.ok) { setStatus(r.error || 'Failed', 'error'); return; }
				if ('FrickmailRegister' === action) {
					setStatus(r.message || 'Account created — now sign in', 'ok');
					switchMode('login');
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
			<label>Type</label>
			<select data-fa="type">
				<option value="imap">IMAP / SMTP (any provider)</option>
				<option value="gmail">Gmail (OAuth)</option>
				<option value="o365">Office 365 / Outlook (OAuth)</option>
			</select>
			<div data-fa="imap-fields">
				<label>Email</label><input data-fa="email" type="email" />
				<label>IMAP login (if different)</label><input data-fa="login" type="text" />
				<label>IMAP password</label><input data-fa="password" type="password" autocomplete="new-password" />
				<div style="display:flex;gap:.5em">
					<div style="flex:2"><label>IMAP host</label><input data-fa="imap_host" type="text" placeholder="imap.example.com" /></div>
					<div style="flex:1"><label>Port</label><input data-fa="imap_port" type="number" value="993" /></div>
					<div style="flex:1"><label>Sec.</label><select data-fa="imap_secure"><option>SSL</option><option>STARTTLS</option><option>NONE</option></select></div>
				</div>
				<div style="display:flex;gap:.5em">
					<div style="flex:2"><label>SMTP host</label><input data-fa="smtp_host" type="text" placeholder="smtp.example.com" /></div>
					<div style="flex:1"><label>Port</label><input data-fa="smtp_port" type="number" value="465" /></div>
					<div style="flex:1"><label>Sec.</label><select data-fa="smtp_secure"><option>SSL</option><option>STARTTLS</option><option>NONE</option></select></div>
				</div>
			</div>
			<div data-fa="oauth-fields" style="display:none">
				<label>Email</label><input data-fa="oauth_email" type="email" placeholder="(detected after consent)" />
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

	addEventListener('rl-view-model', e => {
		if ('Login' !== e.detail.viewModelTemplateID) return;
		const dom = e.detail.viewModelDom;
		// Defer one tick so SnappyMail's own bindings finish, then take over.
		setTimeout(() => {
			const openSignup = !!rl.pluginSettingsGet('frickmail-user', 'open_signup');
			const host = dom.querySelector('.b-login-content') || dom;
			buildForm(host, openSignup);
		}, 0);
	});

})(window.rl);
