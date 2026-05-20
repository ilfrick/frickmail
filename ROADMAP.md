# Frickmail Roadmap

## In progress

| Feature | Branch / PR |
|---|---|
| Unified Inbox | worktree |
| Full-text Search | worktree |
| PWA + Service Worker | `master` (this commit) |

---

## Implemented

- Frickmail user identity (Postgres, Argon2id, xchacha20-poly1305)
- Multi-account IMAP/Gmail/O365
- TOTP 2FA with replay protection
- Password reset via email
- Redis cache layer
- Security headers (CSP, X-Frame-Options, Referrer-Policy, Permissions-Policy)
- Login rate limiting (nginx, per-IP)
- PWA: Service Worker, Web Push skeleton, installable manifest

---

## Gaps vs Thunderbird — priority order

### P1 — High impact, medium effort

**Unified Inbox** _(in progress)_
Show messages from all accounts in a single merged view sorted by date.
Each message carries an account badge. Click navigates into that account.
Backend: direct MailSo connections per account. Frontend: new "All" tab.

**Full-text Search** _(in progress)_
Index message metadata (subject, sender, date) in Postgres `tsvector`.
Populate lazily on message view + bulk on login sync.
Search endpoint returns cross-account results ranked by relevance + date.

**Web Push Notifications**
The Service Worker push handler is already in `sw.js`. Missing:
- VAPID key generation (one-time, store in config)
- `/FrickmailPushSubscribe` endpoint: save `PushSubscription` JSON per user in Postgres
- Trigger: poll for new messages on login, push notification on new arrivals
- Unsubscribe endpoint
Effort: ~1 day. Dependency: rebuild container (SW already ships in next build).

**Multiple identities per account**
Thunderbird lets you send as `alias@domain.com` from a single IMAP account.
SnappyMail has an `Identities` concept — expose it via frickmail-user settings.
Store additional From addresses per mail account in `frickmail_mail_accounts.settings` JSONB.
Effort: ~2 days.

### P2 — Medium impact, medium effort

**Advanced message rules (client-side)**
SnappyMail supports Sieve (server-side) only if the server allows it.
For servers without Sieve: implement a client-side rules engine that runs on
message fetch and performs move/flag/forward actions via IMAP.
Store rules in Postgres JSONB. Evaluate in `frickmail-user` on message list fetch.
Effort: ~3 days. Dependency: unified inbox or per-account hooks.

**S/MIME**
Thunderbird supports both OpenPGP (SnappyMail already has it) and S/MIME (X.509 certs).
Corporate environments often use S/MIME, not PGP.
Required: PHP `openssl_pkcs7_*` functions, certificate import UI, key storage encrypted in Postgres.
Effort: ~5 days. High complexity.

**Import / Export**
- Export: EML download per message (SnappyMail has raw download), MBOX export of folder
- Import: drag-and-drop `.eml` files into a folder via IMAP APPEND
- VCard export/import for contacts
Effort: ~2 days.

**Task management**
Integrate a Tasks tab backed by CalDAV VTODO (same CalDAV plugin already handles events).
Display in a sidebar panel. Create/complete/delete tasks.
Effort: ~3 days. Dependency: CalDAV plugin already works.

### P3 — Lower priority / platform constraints

**True offline reading**
The Service Worker caches static assets and the app shell.
For offline message reading, body content must be cached on open.
Add a `cache-message` strategy to sw.js that stores email HTML in Cache API on view.
Effort: ~1 day, but adds storage management complexity.

**Keyboard shortcuts**
SnappyMail has minimal keyboard nav. Adding Thunderbird-style shortcuts
(j/k navigate, r reply, f forward, / search, e archive) requires hooking into
the SnappyMail keyboard event system or adding a global keydown listener.
Effort: ~2 days.

**Mailto: protocol registration**
```javascript
navigator.registerProtocolHandler('mailto', '/?compose=%s', 'Frickmail');
```
One line. Add to ThemeSwitcher.js with user consent prompt.
Effort: 1 hour.

**Desktop app wrapper (Tauri)**
Tauri wraps the webmail in a native window with OS notifications,
file system access for attachments, and system tray. Frickmail's existing
PWA + backend is a drop-in. Requires a Rust build step.
Effort: ~3 days for a basic wrapper. Lower priority — PWA covers most use cases.

**Spam filtering (client-side)**
Server-side SpamAssassin or rspamd is the right place for this.
Client-side: expose the IMAP `JUNK` flag and a "Mark as Spam" action that
moves to Junk and teaches the server filter via `REPORT` command if supported.
Effort: ~1 day for the UI, server configuration is out of scope.

---

## Upstream SnappyMail integration

Frickmail patches only 3 lines of SnappyMail core (Service.php, ServiceActions.php)
plus static assets (icons, manifest). Upgrade procedure:

```bash
git remote add upstream https://github.com/the-djmaze/snappymail  # once
git fetch upstream
git merge upstream/master
# Resolve conflicts on Service.php (1 line), ServiceActions.php (1 line),
# AdminSettingsAbout.html (remove update links), static assets (re-apply icons)
```
