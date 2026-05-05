(rl => { if (!rl) return;

	// Replace SnappyMail's IMAP login form with a Frickmail user form.
	// On submit we hit ?Json/&q[]=/0/Plugin/-/&_action=FrickmailLogin which
	// (server-side) bridges to LoginProcess() once it has retrieved the
	// primary mail account credentials from the user's encrypted record.

	let mode = 'login'; // 'login' | 'register'

	const buildForm = (root, openSignup) => {
		const wrap = document.createElement('div');
		wrap.className = 'frickmail-login';
		wrap.innerHTML = `
			<style>
				.frickmail-login { max-width: 360px; margin: 4em auto; padding: 1.6em 1.8em; border:1px solid var(--border-color, #ccc); border-radius: 6px; background: var(--main-background, #fff); }
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
					<button class="switch-mode" type="button" data-fm="switch" style="display:${openSignup ? '' : 'none'}">Create an account</button>
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
					setStatus('Logged in. Reload to add a mail account.', 'ok');
					setTimeout(() => document.location.reload(), 800);
					return;
				}
				setStatus('Welcome ' + (r.email || ''), 'ok');
				setTimeout(() => document.location.reload(), 400);
			}, action, params, 30000);
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
