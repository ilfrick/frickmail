// Frickmail Graph Mailbox — "Graph view" panel for Office 365 accounts.
//
// For each O365 account in the user's account list, adds a "⚡ Graph view" button
// to the MailMessageList toolbar. Clicking it opens a full-screen overlay that:
//   - Lists messages via FrickmailGraphListMessages (fast, no IMAP needed)
//   - Searches via FrickmailGraphSearch (uses Graph $search, much faster on O365)
//   - Shows the full message body in a sandboxed <iframe>
//   - Supports mark-read, move, delete, and incremental delta sync
//
// Hooks into rl-view-model on 'MailMessageList', same pattern as UnifiedInbox.js.
// Delegates to FrickmailUtils (utils.js) for shared helpers.

(function () {
    'use strict';

    // ── State ─────────────────────────────────────────────────────────────────

    var overlayEl    = null;   // The overlay DOM node
    var activeAccount = null;  // { id, email, label } of the account being viewed
    var isOpen       = false;
    var isLoading    = false;
    var deltaToken   = null;   // Opaque delta token from last successful getDelta
    var btnsByAccId  = {};     // accountId → DOM button

    // ── Helpers ───────────────────────────────────────────────────────────────

    function fmToken() {
        return window.FrickmailUtils ? FrickmailUtils.fmToken()
            : (window.rl?.__frickmail_token || window.rl?.settings?.app?.('token') || '');
    }

    function formatDate(v) {
        if (!v) return '';
        if (window.FrickmailUtils) return FrickmailUtils.formatDate(v);
        // Fallback: parse ISO date
        var d = new Date(v);
        if (isNaN(d)) return String(v);
        var pad = function (n) { return String(n).padStart(2, '0'); };
        var now = new Date();
        if (d.toDateString() === now.toDateString()) {
            return pad(d.getHours()) + ':' + pad(d.getMinutes());
        }
        var months = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
        if (d.getFullYear() === now.getFullYear()) {
            return months[d.getMonth()] + ' ' + d.getDate();
        }
        return months[d.getMonth()] + ' ' + d.getDate() + ' ' + d.getFullYear();
    }

    function escHtml(s) {
        return window.FrickmailUtils ? FrickmailUtils.escHtml(s)
            : String(s || '').replace(/&/g,'&amp;').replace(/</g,'&lt;')
                             .replace(/>/g,'&gt;').replace(/"/g,'&quot;');
    }

    function makeCloseButton(id, fn) {
        if (window.FrickmailUtils && FrickmailUtils.makeCloseButton) {
            return FrickmailUtils.makeCloseButton(id, fn);
        }
        var b = document.createElement('button');
        b.id = id; b.type = 'button'; b.innerHTML = '&times;';
        b.style.cssText = 'background:none;border:none;color:inherit;cursor:pointer;font-size:1.4rem;min-width:44px;min-height:44px;display:flex;align-items:center;justify-content:center;opacity:.7;touch-action:manipulation;flex-shrink:0';
        ['pointerdown','click','touchend'].forEach(function (ev) {
            b.addEventListener(ev, function (e) { e.stopPropagation(); e.preventDefault(); fn(); });
        });
        return b;
    }

    function pluginRequest(action, params, cb, timeout) {
        if (!window.rl) { cb(1, null); return; }
        params.XToken = fmToken();
        rl.pluginRemoteRequest(cb, action, params, timeout || 20000);
    }

    // ── Overlay construction ──────────────────────────────────────────────────

    function createOverlay() {
        var el = document.createElement('div');
        el.id = 'fm-graph-mailbox';
        el.setAttribute('role', 'dialog');
        el.setAttribute('aria-label', 'Graph Mailbox');
        el.style.cssText = [
            'position:fixed','top:0','left:0','right:0','bottom:0',
            'z-index:99999','display:flex','flex-direction:column',
            'background:var(--fm-bg-panel,#1a1a2e)',
            'color:var(--fm-text-primary,#e2e4f0)',
            'font-family:inherit','overflow:hidden',
        ].join(';');

        el.innerHTML = [
            '<div id="fm-gm-header" style="display:flex;align-items:center;padding:max(10px,env(safe-area-inset-top)) 16px 10px;border-bottom:1px solid var(--fm-border,rgba(255,255,255,.1));gap:8px;flex-shrink:0;">',
                '<span id="fm-gm-title" style="font-weight:var(--fm-font-weight-semi,600);font-size:var(--fm-font-size-lg,1rem);flex:1">&#9889; Graph Inbox</span>',
                '<span id="fm-gm-status" style="font-size:var(--fm-font-size-sm,.8rem);opacity:.7;white-space:nowrap;"></span>',
                '<span id="fm-gm-delta-slot"></span>',
                '<span id="fm-gm-refresh-slot"></span>',
                '<span id="fm-gm-close-slot"></span>',
            '</div>',
            '<div id="fm-gm-search-bar" style="display:flex;gap:8px;padding:8px 16px;border-bottom:1px solid var(--fm-border,rgba(255,255,255,.06));flex-shrink:0;">',
                '<input id="fm-gm-search" type="search" placeholder="Search messages…"',
                    ' style="flex:1;padding:6px 10px;border-radius:var(--fm-radius-xs,4px);border:1px solid var(--fm-border,rgba(255,255,255,.2));background:var(--fm-bg-input,rgba(255,255,255,.07));color:inherit;font-size:var(--fm-font-size-sm,.85rem);">',
                '<button id="fm-gm-search-btn" type="button"',
                    ' style="padding:6px 14px;border-radius:var(--fm-radius-xs,4px);border:1px solid var(--fm-border,rgba(255,255,255,.2));background:var(--fm-bg-input,rgba(255,255,255,.07));color:inherit;cursor:pointer;font-size:var(--fm-font-size-sm,.85rem);">',
                    'Search</button>',
            '</div>',
            '<div id="fm-gm-body" style="display:flex;flex:1;overflow:hidden;">',
                '<div id="fm-gm-list" style="width:340px;min-width:220px;max-width:48%;overflow-y:auto;border-right:1px solid var(--fm-border,rgba(255,255,255,.06));flex-shrink:0;"></div>',
                '<div id="fm-gm-detail" style="flex:1;overflow:hidden;display:flex;flex-direction:column;"></div>',
            '</div>',
        ].join('');

        document.body.appendChild(el);

        // Close button
        var closeBtn = makeCloseButton('fm-gm-close', closeOverlay);
        el.querySelector('#fm-gm-close-slot').replaceWith(closeBtn);

        // Refresh button
        var refreshBtn = document.createElement('button');
        refreshBtn.id = 'fm-gm-refresh'; refreshBtn.type = 'button'; refreshBtn.title = 'Refresh';
        refreshBtn.innerHTML = '&#8635;';
        refreshBtn.style.cssText = 'background:none;border:none;color:inherit;cursor:pointer;font-size:1.1rem;min-width:44px;min-height:44px;display:flex;align-items:center;justify-content:center;opacity:.7;touch-action:manipulation;flex-shrink:0';
        ['pointerdown','click','touchend'].forEach(function (ev) {
            refreshBtn.addEventListener(ev, function (e) { e.stopPropagation(); e.preventDefault(); loadMessages(); });
        });
        el.querySelector('#fm-gm-refresh-slot').replaceWith(refreshBtn);

        // Delta sync button
        var deltaBtn = document.createElement('button');
        deltaBtn.id = 'fm-gm-delta'; deltaBtn.type = 'button'; deltaBtn.title = 'Delta sync (fetch changes since last sync)';
        deltaBtn.innerHTML = '&#8645; Delta';
        deltaBtn.style.cssText = 'background:none;border:1px solid var(--fm-border,rgba(255,255,255,.2));color:inherit;cursor:pointer;font-size:.75rem;padding:3px 8px;border-radius:4px;opacity:.7;touch-action:manipulation;flex-shrink:0;white-space:nowrap';
        ['pointerdown','click','touchend'].forEach(function (ev) {
            deltaBtn.addEventListener(ev, function (e) { e.stopPropagation(); e.preventDefault(); runDeltaSync(); });
        });
        el.querySelector('#fm-gm-delta-slot').replaceWith(deltaBtn);

        // Search handler
        var searchInput = el.querySelector('#fm-gm-search');
        var searchBtn   = el.querySelector('#fm-gm-search-btn');
        function doSearch() {
            var q = searchInput ? searchInput.value.trim() : '';
            if (q.length < 2) { loadMessages(); return; }
            loadSearchResults(q);
        }
        if (searchBtn)  searchBtn.addEventListener('click', doSearch);
        if (searchInput) {
            searchInput.addEventListener('keydown', function (e) {
                if (e.key === 'Enter') { e.preventDefault(); doSearch(); }
            });
        }

        // Close on Escape
        el._keyHandler = function (e) { if (e.key === 'Escape') closeOverlay(); };
        document.addEventListener('keydown', el._keyHandler);

        return el;
    }

    function setStatus(msg) {
        var s = overlayEl && overlayEl.querySelector('#fm-gm-status');
        if (s) s.textContent = msg || '';
    }

    function getListEl()   { return overlayEl && overlayEl.querySelector('#fm-gm-list');   }
    function getDetailEl() { return overlayEl && overlayEl.querySelector('#fm-gm-detail'); }

    // ── Open / close ──────────────────────────────────────────────────────────

    function openOverlay(account) {
        activeAccount = account;
        deltaToken    = null; // reset delta state when switching account
        if (!overlayEl) overlayEl = createOverlay();

        // Update title
        var titleEl = overlayEl.querySelector('#fm-gm-title');
        if (titleEl) titleEl.textContent = '⚡ Graph — ' + (account.label || account.email);

        // Clear detail pane
        var detail = getDetailEl();
        if (detail) detail.innerHTML = '';

        overlayEl.hidden = false;
        isOpen = true;
        loadMessages();
    }

    function closeOverlay() {
        if (overlayEl) overlayEl.hidden = true;
        isOpen = false;
    }

    // ── Load message list ─────────────────────────────────────────────────────

    function loadMessages(folder) {
        if (!activeAccount || isLoading) return;
        isLoading = true;
        folder = folder || 'inbox';

        var list = getListEl();
        if (list) list.innerHTML = '<div style="padding:32px;text-align:center;opacity:.6">Loading…</div>';
        setStatus('');

        pluginRequest('FrickmailGraphListMessages', {
            account_id: activeAccount.id,
            folder:     folder,
            top:        50,
        }, function (iErr, oData) {
            isLoading = false;
            var res = oData && oData.Result;
            if (!res || !res.ok) {
                var err = (res && res.error) ? res.error : 'Unknown error';
                if (list) list.innerHTML = '<div style="padding:32px;text-align:center;color:#f38ba8">' + escHtml(err) + '</div>';
                return;
            }
            var messages = (res.data && res.data.value) ? res.data.value : [];
            setStatus(messages.length + ' messages');
            renderMessageList(messages, list);
        }, 20000);
    }

    function loadSearchResults(query) {
        if (!activeAccount || isLoading) return;
        isLoading = true;

        var list = getListEl();
        if (list) list.innerHTML = '<div style="padding:32px;text-align:center;opacity:.6">Searching…</div>';
        setStatus('Searching…');

        pluginRequest('FrickmailGraphSearch', {
            account_id: activeAccount.id,
            q:          query,
            top:        50,
        }, function (iErr, oData) {
            isLoading = false;
            var res = oData && oData.Result;
            if (!res || !res.ok) {
                var err = (res && res.error) ? res.error : 'Unknown error';
                if (list) list.innerHTML = '<div style="padding:32px;text-align:center;color:#f38ba8">' + escHtml(err) + '</div>';
                setStatus('');
                return;
            }
            var messages = (res.data && res.data.value) ? res.data.value : [];
            setStatus(messages.length + ' results for: ' + escHtml(query));
            renderMessageList(messages, list);
        }, 25000);
    }

    function runDeltaSync() {
        if (!activeAccount || isLoading) return;
        isLoading = true;
        setStatus('Delta sync…');

        pluginRequest('FrickmailGraphDelta', {
            account_id:  activeAccount.id,
            folder_id:   'inbox',
            delta_token: deltaToken || null,
        }, function (iErr, oData) {
            isLoading = false;
            var res = oData && oData.Result;
            if (!res || !res.ok) {
                setStatus('Delta sync failed: ' + escHtml((res && res.error) || 'unknown'));
                return;
            }
            // Extract new delta token for next sync
            var data = res.data || {};
            var newDeltaLink = data['@odata.deltaLink'] || data['@odata.nextLink'] || null;
            if (newDeltaLink) {
                // Store the full URL as delta token
                deltaToken = newDeltaLink;
            }
            var messages = (data.value) ? data.value : [];
            var removed  = messages.filter(function (m) { return m['@removed']; }).length;
            var changed  = messages.length - removed;
            setStatus('Delta: +' + changed + ' changed, ' + removed + ' removed');
            if (messages.length > 0) {
                // Prepend delta results to the list pane
                var list = getListEl();
                var existing = list ? list.querySelectorAll('.fm-gm-row') : [];
                var newMessages = messages.filter(function (m) { return !m['@removed']; });
                if (newMessages.length > 0 && list) {
                    var frag = buildMessageRows(newMessages);
                    if (existing.length > 0) {
                        list.insertBefore(frag, existing[0]);
                    } else {
                        list.appendChild(frag);
                    }
                }
            }
        }, 25000);
    }

    // ── Message list rendering ────────────────────────────────────────────────

    function renderMessageList(messages, container) {
        if (!container) return;
        if (!messages || !messages.length) {
            container.innerHTML = '<div style="padding:32px;text-align:center;opacity:.6">No messages.</div>';
            return;
        }
        container.innerHTML = '';
        container.appendChild(buildMessageRows(messages));
    }

    function buildMessageRows(messages) {
        var frag = document.createDocumentFragment();
        messages.forEach(function (msg) {
            if (msg['@removed']) return; // skip delta-removed tombstones

            var isRead    = !!msg.isRead;
            var from      = (msg.from && msg.from.emailAddress) ? (msg.from.emailAddress.name || msg.from.emailAddress.address || '') : '';
            var subject   = msg.subject || '(no subject)';
            var preview   = msg.bodyPreview || '';
            var dateStr   = msg.receivedDateTime || '';
            var msgId     = msg.id || '';
            var hasAttach = !!msg.hasAttachments;

            var row = document.createElement('div');
            row.className = 'fm-gm-row';
            row.setAttribute('tabindex', '0');
            row.setAttribute('role', 'button');
            row.setAttribute('aria-label', escHtml(from + ' — ' + subject));
            row.style.cssText = [
                'padding:10px 12px',
                'border-bottom:1px solid var(--fm-border,rgba(255,255,255,.06))',
                'cursor:pointer',
                isRead ? 'opacity:.7' : 'font-weight:var(--fm-font-weight-semi,600)',
            ].join(';');

            var topLine = document.createElement('div');
            topLine.style.cssText = 'display:flex;justify-content:space-between;gap:6px;';

            var fromEl = document.createElement('span');
            fromEl.style.cssText = 'overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:60%;font-size:.9rem;';
            fromEl.textContent = from;

            var metaEl = document.createElement('span');
            metaEl.style.cssText = 'font-size:.72rem;opacity:.6;white-space:nowrap;flex-shrink:0;';
            metaEl.textContent = (hasAttach ? '⊕ ' : '') + formatDate(dateStr);

            topLine.appendChild(fromEl);
            topLine.appendChild(metaEl);

            var subjectEl = document.createElement('div');
            subjectEl.style.cssText = 'font-size:.82rem;opacity:.85;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;margin-top:2px;';
            subjectEl.textContent = subject;

            var previewEl = document.createElement('div');
            previewEl.style.cssText = 'font-size:.75rem;opacity:.5;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;margin-top:1px;font-weight:normal;';
            previewEl.textContent = preview;

            row.appendChild(topLine);
            row.appendChild(subjectEl);
            row.appendChild(previewEl);

            // Hover highlight
            row.addEventListener('mouseenter', function () { row.style.background = 'var(--fm-bg-hover,rgba(255,255,255,.05))'; });
            row.addEventListener('mouseleave', function () { row.style.background = ''; });

            var activate = function () { openMessage(msg, row); };
            row.addEventListener('click', activate);
            row.addEventListener('touchend', function (e) { e.preventDefault(); activate(); });
            row.addEventListener('keydown', function (e) { if (e.key === 'Enter' || e.key === ' ') activate(); });

            frag.appendChild(row);
        });
        return frag;
    }

    // ── Message detail pane ───────────────────────────────────────────────────

    function openMessage(msg, rowEl) {
        var msgId = msg.id;
        if (!msgId) return;

        // Mark as read in the list immediately (optimistic)
        if (rowEl && !msg.isRead) {
            rowEl.style.fontWeight = 'normal';
            rowEl.style.opacity    = '0.7';
        }

        var detail = getDetailEl();
        if (detail) detail.innerHTML = '<div style="padding:32px;text-align:center;opacity:.6">Loading message…</div>';

        pluginRequest('FrickmailGraphGetMessage', {
            account_id: activeAccount.id,
            message_id: msgId,
        }, function (iErr, oData) {
            var res = oData && oData.Result;
            if (!res || !res.ok) {
                if (detail) detail.innerHTML = '<div style="padding:24px;color:#f38ba8">Failed to load message: ' + escHtml((res && res.error) || 'unknown') + '</div>';
                return;
            }
            var m = res.message || {};
            renderDetail(m);

            // Mark as read server-side if it wasn't already
            if (!m.isRead) {
                pluginRequest('FrickmailGraphMarkRead', {
                    account_id: activeAccount.id,
                    message_id: msgId,
                    is_read:    true,
                }, function () {}, 10000);
            }
        }, 20000);
    }

    function renderDetail(m) {
        var detail = getDetailEl();
        if (!detail) return;

        var from    = (m.from && m.from.emailAddress) ? (m.from.emailAddress.name || m.from.emailAddress.address || '') : '';
        var subject = m.subject || '(no subject)';
        var date    = m.receivedDateTime || '';
        var body    = (m.body && m.body.content) ? m.body.content : '';
        var msgId   = m.id || '';

        // Header bar
        var header = document.createElement('div');
        header.style.cssText = 'padding:12px 16px;border-bottom:1px solid var(--fm-border,rgba(255,255,255,.06));flex-shrink:0;';
        header.innerHTML = [
            '<div style="font-weight:var(--fm-font-weight-semi,600);font-size:.95rem;margin-bottom:4px;">' + escHtml(subject) + '</div>',
            '<div style="font-size:.8rem;opacity:.7;">From: ' + escHtml(from) + '</div>',
            '<div style="font-size:.75rem;opacity:.5;margin-top:2px;">' + escHtml(formatDate(date)) + '</div>',
        ].join('');

        // Action toolbar
        var actions = document.createElement('div');
        actions.style.cssText = 'display:flex;gap:8px;padding:8px 16px;border-bottom:1px solid var(--fm-border,rgba(255,255,255,.06));flex-shrink:0;flex-wrap:wrap;';

        function actionBtn(label, title, handler) {
            var b = document.createElement('button');
            b.type = 'button'; b.textContent = label; b.title = title;
            b.style.cssText = 'padding:4px 10px;font-size:.75rem;border-radius:4px;border:1px solid var(--fm-border,rgba(255,255,255,.2));background:var(--fm-bg-input,rgba(255,255,255,.07));color:inherit;cursor:pointer;';
            b.addEventListener('click', handler);
            return b;
        }

        actions.appendChild(actionBtn('Mark unread', 'Mark this message as unread', function () {
            if (!msgId) return;
            pluginRequest('FrickmailGraphMarkRead', { account_id: activeAccount.id, message_id: msgId, is_read: false }, function () {
                setStatus('Marked unread.');
            }, 10000);
        }));

        actions.appendChild(actionBtn('Move to…', 'Move to another folder', function () {
            var folderId = window.prompt('Enter destination folder ID or well-known name (e.g. deleteditems):');
            if (!folderId || !folderId.trim()) return;
            pluginRequest('FrickmailGraphMove', {
                account_id: activeAccount.id, message_id: msgId, target_folder_id: folderId.trim(),
            }, function (iErr, oData) {
                var res = oData && oData.Result;
                setStatus(res && res.ok ? 'Message moved.' : 'Move failed: ' + escHtml((res && res.error) || 'unknown'));
                if (res && res.ok) { detail.innerHTML = '<div style="padding:32px;opacity:.6">Message moved.</div>'; }
            }, 15000);
        }));

        actions.appendChild(actionBtn('Delete', 'Move to Deleted Items', function () {
            if (!msgId) return;
            if (!window.confirm('Move this message to Deleted Items?')) return;
            pluginRequest('FrickmailGraphDelete', { account_id: activeAccount.id, message_id: msgId }, function (iErr, oData) {
                var res = oData && oData.Result;
                setStatus(res && res.ok ? 'Message deleted.' : 'Delete failed: ' + escHtml((res && res.error) || 'unknown'));
                if (res && res.ok) { detail.innerHTML = '<div style="padding:32px;opacity:.6">Message deleted.</div>'; }
            }, 10000);
        }));

        // Body iframe (sandboxed for security)
        var iframe = document.createElement('iframe');
        iframe.setAttribute('sandbox', 'allow-same-origin');
        iframe.style.cssText = 'flex:1;width:100%;border:none;background:#fff;';
        iframe.setAttribute('title', 'Message body');

        detail.innerHTML = '';
        detail.style.display = 'flex';
        detail.style.flexDirection = 'column';
        detail.appendChild(header);
        detail.appendChild(actions);
        detail.appendChild(iframe);

        // Write the HTML body into the iframe after it is attached to the DOM
        try {
            var iDoc = iframe.contentDocument || iframe.contentWindow.document;
            iDoc.open();
            iDoc.write('<!DOCTYPE html><html><head><meta charset="utf-8"><style>body{margin:16px;font-family:sans-serif;font-size:14px;line-height:1.5;}</style></head><body>');
            iDoc.write(body);
            iDoc.write('</body></html>');
            iDoc.close();
        } catch (e) {
            // srcdoc fallback
            iframe.srcdoc = '<!DOCTYPE html><html><head><meta charset="utf-8"><style>body{margin:16px;font-family:sans-serif;}</style></head><body>' + body + '</body></html>';
        }
    }

    // ── Inject "⚡ Graph view" button(s) into the MailMessageList toolbar ──────

    function injectButtons(toolbarEl, accounts) {
        if (!toolbarEl || !accounts || !accounts.length) return;

        // Filter to O365 accounts
        var o365Accounts = accounts.filter(function (a) { return a.type === 'o365'; });
        if (!o365Accounts.length) return;

        o365Accounts.forEach(function (acc) {
            var accId = acc.id;
            if (btnsByAccId[accId] && toolbarEl.contains(btnsByAccId[accId])) return;

            var btn = document.createElement('button');
            btn.type = 'button';
            btn.title = 'Open Graph view for ' + (acc.label || acc.email);
            btn.style.cssText = [
                'margin-left:4px',
                'padding:4px 10px',
                'border-radius:var(--fm-radius-xs,4px)',
                'border:1px solid var(--fm-border,rgba(255,255,255,.2))',
                'background:var(--fm-bg-input,rgba(255,255,255,.07))',
                'color:inherit',
                'font-size:var(--fm-font-size-sm,.8rem)',
                'cursor:pointer',
                'white-space:nowrap',
                'touch-action:manipulation',
            ].join(';');
            btn.textContent = '⚡ ' + (acc.label || acc.email);

            var toggle = function () {
                if (isOpen && activeAccount && activeAccount.id === accId) {
                    closeOverlay();
                } else {
                    openOverlay(acc);
                }
            };
            btn.addEventListener('click', toggle);
            btn.addEventListener('touchend', function (e) { e.preventDefault(); toggle(); });

            // Append after last toolbar button, or at end
            var btns = toolbarEl.querySelectorAll('button, a.button, .toolbar-button');
            if (btns.length) {
                btns[btns.length - 1].after(btn);
            } else {
                toolbarEl.appendChild(btn);
            }
            btnsByAccId[accId] = btn;
        });
    }

    // ── rl-view-model hook ────────────────────────────────────────────────────

    addEventListener('rl-view-model', function (e) {
        if (!e.detail || e.detail.viewModelTemplateID !== 'MailMessageList') return;
        var dom = e.detail.viewModelDom;
        if (!dom) return;

        setTimeout(function () {
            var toolbar = dom.querySelector('.listActions, .toolbar, [class*="toolbar"]') || dom.querySelector('div');
            if (!toolbar) return;

            // Load accounts from local cache (populated by AccountSwitcher.js)
            var accounts = null;
            try {
                accounts = JSON.parse(localStorage.getItem('frickmail_accounts_cache') || 'null');
            } catch (ex) {}

            if (accounts) {
                injectButtons(toolbar, accounts);
            } else {
                // Fetch accounts if cache is missing
                if (!window.rl) return;
                rl.pluginRemoteRequest(function (iErr, oData) {
                    var res = oData && oData.Result;
                    if (res && res.ok && res.accounts) {
                        injectButtons(toolbar, res.accounts);
                    }
                }, 'FrickmailListAccounts', { XToken: fmToken() }, 10000);
            }
        }, 350);
    });

    // ── Public API ────────────────────────────────────────────────────────────

    window.FrickmailGraphMailbox = {
        open:  openOverlay,
        close: closeOverlay,
    };

})();
