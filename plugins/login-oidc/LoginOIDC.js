(rl => {
	const PLUGIN       = 'login-oidc';
	const providerName = rl.pluginSettingsGet(PLUGIN, 'provider_name') || 'SSO';
	const buttonLabel  = rl.pluginSettingsGet(PLUGIN, 'button_label')  || 'Sign in with SSO';

	let popupRef = null, pendingResolve = null, _bc = null;

	const baseUrl = () =>
		document.location.href.replace(/[#?].*$/, '').replace(/\/+$/, '');

	const resolvePopup = d => {
		if (_bc) { try { _bc.close(); } catch(_) {} _bc = null; }
		if (pendingResolve) { const r = pendingResolve; pendingResolve = null; r(d); }
		try { popupRef && popupRef.close(); } catch (_) {}
	};

	const openPopup = url => {
		const w = 520, h = 640,
			y = Math.round((screen.availHeight - h) / 2),
			x = Math.round((screen.availWidth  - w) / 2);
		try { popupRef && popupRef.close(); } catch (_) {}
		if (_bc) { try { _bc.close(); } catch(_) {} _bc = null; }
		try { localStorage.removeItem('frickmail-oidc-result'); } catch(_) {}
		popupRef = window.open(url, 'frickmail-oidc',
			`popup=yes,width=${w},height=${h},left=${x},top=${y}`);
		if (!popupRef) { document.location = url; return null; }
		return new Promise(resolve => {
			pendingResolve = resolve;
			// BroadcastChannel is same-origin and survives cross-origin popup navigation
			// (unlike postMessage via window.opener which can silently drop after Authentik
			// navigates the popup cross-origin and back).
			try {
				_bc = new BroadcastChannel('frickmail-oidc');
				_bc.onmessage = e => {
					const d = e.data;
					if (!d || d.type !== 'frickmail-oidc') return;
					console.log('[frickmail-oidc] BroadcastChannel received', d);
					resolvePopup(d);
				};
			} catch(_) {}
			const t = setInterval(() => {
				// localStorage is the most reliable channel — immune to cross-origin
				// popup navigation that silently breaks postMessage and BroadcastChannel.
				try {
					const raw = localStorage.getItem('frickmail-oidc-result');
					if (raw) {
						const d = JSON.parse(raw);
						if (d && d.type === 'frickmail-oidc') {
							localStorage.removeItem('frickmail-oidc-result');
							clearInterval(t);
							console.log('[frickmail-oidc] localStorage received', d);
							resolvePopup(d);
							return;
						}
					}
				} catch(_) {}
				if (!popupRef || popupRef.closed) {
					clearInterval(t);
					console.log('[frickmail-oidc] popup closed, waiting for channel message…');
					setTimeout(() => {
						if (pendingResolve) {
							console.log('[frickmail-oidc] no message received — resolving cancelled');
							resolvePopup({ status: 'cancelled' });
						}
					}, 1000);
				}
			}, 500);
		});
	};

	// Keep postMessage listener as fallback for browsers without BroadcastChannel.
	addEventListener('message', e => {
		if (e.origin !== location.origin) return;
		const d = e.data;
		if (!d || d.type !== 'frickmail-oidc') return;
		console.log('[frickmail-oidc] postMessage received', d);
		resolvePopup(d);
	});

	const launch = async mode => {
		const url = baseUrl() + '/?StartLoginOIDC' + (mode === 'link' ? '&mode=link' : '');
		const result = await openPopup(url);
		console.log('[frickmail-oidc] popup result', result);
		if (!result || result.status === 'cancelled') return;
		if (result.status === 'ok') {
			if (mode === 'link') {
				alert(providerName + ' account linked successfully.');
				refreshOidcSection();
			} else if (result.reauth_required) {
				// bridge() failed in the popup (IMAP auth error); use the main-window
				// JSON path to get account details and show the reauth form.
				rl.pluginRemoteRequest((iError, oData) => {
					const r = oData?.Result;
					if (!r) { alert('SSO login failed: network error'); return; }
					if (r.reauth_required) {
						dispatchEvent(new CustomEvent('frickmail-bridge-reauth', { detail: {
							account_id: r.reauth_account_id,
							email:      r.reauth_account_email,
							type:       r.reauth_account_type,
							message:    r.message,
						}}));
						return;
					}
					console.log('[frickmail-oidc] navigating after reauth bridge');
					document.location.href = baseUrl();
				}, 'FrickmailBridgeSession', {});
			} else {
				// bridge() succeeded in the popup — SnappyMail auth cookie is
				// already set in the popup response, navigate to inbox.
				console.log('[frickmail-oidc] navigating after successful bridge');
				document.location.href = baseUrl();
			}
		} else {
			alert((mode === 'link' ? 'Link' : 'Sign-in') + ' failed: ' + (result.error || 'unknown error'));
		}
	};

	// ── Login view: SSO button ────────────────────────────────────────────────

	// frickmail-user/Login.js replaces the entire login form DOM and fires this
	// event afterward so plugins can inject into the actual rendered form.
	addEventListener('frickmail-login-ready', e => {
		const host = e.detail;
		const actions = host.querySelector('.actions');
		if (!actions) return;
		const sep = document.createElement('div');
		sep.style.cssText = 'margin:.7em 0 .3em;text-align:center;font-size:90%;opacity:.6';
		sep.textContent = '— or —';
		const btn = document.createElement('button');
		btn.type = 'button';
		btn.className = 'btn';
		btn.style.cssText = 'width:100%;margin-top:.3em';
		btn.textContent = buttonLabel;
		btn.onclick = () => launch('login');
		actions.after(sep, btn);
	});

	// Fallback for environments without frickmail-user (uses the stock SnappyMail
	// login form which has #plugin-Login-BottomControlGroup).
	addEventListener('rl-view-model', e => {
		if ('Login' === e.detail.viewModelTemplateID) {
			const container = e.detail.viewModelDom.querySelector('#plugin-Login-BottomControlGroup');
			if (!container) return;
			const btn = Element.fromHTML('<button type="button">' + buttonLabel + '</button>');
			btn.onclick = () => launch('login');
			const div = Element.fromHTML('<div class="controls"></div>');
			div.append(btn);
			container.append(div);
		}

		// ── Settings (Preferences tab): OIDC link/unlink section ─────────────

		if ('FrickmailUserPrefsTab' === e.detail.viewModelTemplateID) {
			const form = e.detail.viewModelDom.querySelector('.form-horizontal');
			if (!form) return;
			const section = document.createElement('div');
			section.id = 'fm-oidc-section';
			section.style.cssText = 'margin-top:24px;border-top:1px solid rgba(255,255,255,.1);padding-top:16px;';
			section.innerHTML =
				'<div class="legend">OIDC Authentication — ' + providerName + '</div>' +
				'<div id="fm-oidc-status" style="color:var(--fm-text-secondary,#888);margin-bottom:10px;">Loading…</div>' +
				'<div id="fm-oidc-buttons" class="controls" style="display:flex;gap:8px;flex-wrap:wrap;"></div>' +
				'<p class="help-block">Link your ' + providerName + ' account to sign in with SSO instead of your Frickmail password.</p>';
			form.append(section);
			refreshOidcSection();
		}
	});

	// ── Render / refresh the link/unlink state in settings ───────────────────

	function refreshOidcSection() {
		const statusEl  = document.getElementById('fm-oidc-status');
		const buttonsEl = document.getElementById('fm-oidc-buttons');
		if (!statusEl || !buttonsEl) return;

		statusEl.textContent = 'Loading…';
		buttonsEl.innerHTML  = '';

		rl.pluginRemoteRequest((iError, oData) => {
			const links = oData?.Result?.links || [];

			if (links.length) {
				const raw       = links[0].linked_at;
				const linkedAt  = raw ? new Date(raw).toLocaleDateString() : '';
				statusEl.textContent = providerName + ' linked' + (linkedAt ? ' since ' + linkedAt : '') + '.';

				const unlinkBtn = Element.fromHTML('<button class="btn btn-danger">Unlink ' + providerName + '</button>');
				unlinkBtn.onclick = () => {
					if (!confirm('Remove the ' + providerName + ' link?\nYou will need to use your Frickmail password to sign in.')) return;
					rl.pluginRemoteRequest(() => refreshOidcSection(),
						'FrickmailUnlinkOidc', { provider_hash: links[0].provider_hash });
				};
				buttonsEl.append(unlinkBtn);
			} else {
				statusEl.textContent = 'No ' + providerName + ' identity linked yet.';
				const linkBtn = Element.fromHTML('<button class="btn">Link ' + providerName + ' account</button>');
				linkBtn.onclick = () => launch('link');
				buttonsEl.append(linkBtn);
			}
		}, 'FrickmailListOidcLinks', {});
	}

})(window.rl);
