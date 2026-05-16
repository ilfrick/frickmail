// Frickmail contacts quick-add: injects a small "+" button next to each
// sender/recipient address shown in the open message, allowing the user to
// add that address to their address book in one click.

(function () {
	const DONE_ATTR = 'data-fm-cab'; // "contact-add button" sentinel

	function addContactRequest(email, name, btn) {
		btn.disabled = true;
		btn.textContent = '…';
		window.rl.pluginRemoteRequest((iErr, oData) => {
			const r = oData?.Result;
			if (iErr || r?.error) {
				btn.textContent = '!';
				btn.title = r?.error || 'Error';
				btn.disabled = false;
				return;
			}
			btn.textContent = '✓';
			btn.title = (r.name || r.email) + ' saved to contacts';
			btn.style.color = 'var(--fm-accent, #7aa2f7)';
		}, 'JsonAddContact', { email, name }, 15000);
	}

	function makeBtn(email, name) {
		const btn = document.createElement('button');
		btn.type = 'button';
		btn.className = 'fm-quick-add-contact';
		btn.textContent = '+';
		btn.title = 'Add ' + email + ' to contacts';
		btn.style.cssText = [
			'display:inline-flex;align-items:center;justify-content:center',
			'width:16px;height:16px;padding:0;margin-left:4px',
			'border-radius:50%;border:1px solid var(--fm-border,rgba(255,255,255,.2))',
			'background:transparent;color:var(--fm-text-secondary,#9fa3bf)',
			'font-size:11px;line-height:1;cursor:pointer;vertical-align:middle',
			'transition:color .12s,border-color .12s',
		].join(';');
		btn.onmouseenter = () => { btn.style.color = 'var(--fm-accent,#7aa2f7)'; btn.style.borderColor = 'var(--fm-accent,#7aa2f7)'; };
		btn.onmouseleave = () => { btn.style.color = 'var(--fm-text-secondary,#9fa3bf)'; btn.style.borderColor = 'var(--fm-border,rgba(255,255,255,.2))'; };
		btn.onclick = (e) => { e.stopPropagation(); e.preventDefault(); addContactRequest(email, name, btn); };
		return btn;
	}

	function injectButtons(root) {
		// The webmail renders sender/recipient as elements with data-bind containing
		// the email. We look for the rendered <span class="senderParent"> or any
		// element that contains an "mailto:" link or a visible email-like text node
		// wrapped in a span with a title or data attribute carrying the address.

		// Strategy 1: elements with title matching an email pattern (most reliable)
		root.querySelectorAll('[title]').forEach(el => {
			if (el.getAttribute(DONE_ATTR)) return;
			const title = el.getAttribute('title') || '';
			const m = title.match(/[\w.+\-]+@[\w.\-]+\.[a-z]{2,}/i);
			if (!m) return;
			const email = m[0];
			const name  = el.textContent.trim().replace(/<.*>/, '').trim() || email;
			if (name === email || !name) return; // skip bare-email elements
			el.setAttribute(DONE_ATTR, '1');
			el.parentNode?.insertBefore(makeBtn(email, name), el.nextSibling);
		});

		// Strategy 2: mailto: anchors
		root.querySelectorAll('a[href^="mailto:"]').forEach(el => {
			if (el.getAttribute(DONE_ATTR)) return;
			const email = el.href.replace(/^mailto:/, '').split('?')[0];
			if (!email) return;
			const name = el.textContent.trim() || email;
			el.setAttribute(DONE_ATTR, '1');
			el.parentNode?.insertBefore(makeBtn(email, name), el.nextSibling);
		});
	}

	// Watch for the message detail area to be populated / changed
	const observer = new MutationObserver(mutations => {
		for (const m of mutations) {
			for (const node of m.addedNodes) {
				if (!(node instanceof Element)) continue;
				// Message header area identifiers
				const header = node.matches('.messageView,.b-message-view,.senderParent,#V-MailMessage')
					? node
					: node.querySelector?.('.messageView,.b-message-view,.senderParent,#V-MailMessage');
				if (header) injectButtons(header.closest('.messageView,#V-MailMessage') || header);
			}
		}
	});
	observer.observe(document.body, { childList: true, subtree: true });

	// Also handle messages already visible on page load
	addEventListener('DOMContentLoaded', () => {
		const area = document.querySelector('.messageView,#V-MailMessage,.b-message-view');
		if (area) injectButtons(area);
	});

	// Re-run when the message view fires rl-view-model
	addEventListener('rl-view-model', e => {
		const id = e.detail?.viewModelTemplateID;
		if (!id || !id.toLowerCase().includes('message')) return;
		const dom = e.detail?.viewModelDom;
		if (dom) setTimeout(() => injectButtons(dom), 300);
	});
})();
