(rl => {
	const PLUGIN       = 'login-oidc';
	const providerName = rl.pluginSettingsGet(PLUGIN, 'provider_name') || 'SSO';
	const buttonLabel  = rl.pluginSettingsGet(PLUGIN, 'button_label')  || 'Sign in with SSO';

	let popupRef = null, pendingResolve = null;

	const baseUrl = () =>
		document.location.href.replace(/[#?].*$/, '').replace(/\/+$/, '');

	const openPopup = url => {
		const w = 520, h = 640,
			y = Math.round((screen.availHeight - h) / 2),
			x = Math.round((screen.availWidth  - w) / 2);
		try { popupRef && popupRef.close(); } catch (_) {}
		popupRef = window.open(url, 'frickmail-oidc',
			`popup=yes,width=${w},height=${h},left=${x},top=${y}`);
		if (!popupRef) { document.location = url; return null; }
		return new Promise(resolve => {
			pendingResolve = resolve;
			const t = setInterval(() => {
				if (!popupRef || popupRef.closed) {
					clearInterval(t);
					if (pendingResolve) {
						const r = pendingResolve; pendingResolve = null;
						r({ status: 'cancelled' });
					}
				}
			}, 500);
		});
	};

	addEventListener('message', e => {
		if (e.origin !== location.origin) return;
		const d = e.data;
		if (!d || d.type !== 'frickmail-oidc') return;
		if (pendingResolve) { const r = pendingResolve; pendingResolve = null; r(d); }
		try { popupRef && popupRef.close(); } catch (_) {}
	});

	const launch = async mode => {
		const url = baseUrl() + '/?StartLoginOIDC' + (mode === 'link' ? '&mode=link' : '');
		const result = await openPopup(url);
		if (!result || result.status === 'cancelled') return;
		if (result.status === 'ok') {
			if (mode === 'link') {
				alert(providerName + ' account linked successfully.');
				refreshOidcSection();
			} else {
				document.location.reload();
			}
		} else {
			alert((mode === 'link' ? 'Link' : 'Sign-in') + ' failed: ' + (result.error || 'unknown error'));
		}
	};

	// ── Login view: SSO button ────────────────────────────────────────────────

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
