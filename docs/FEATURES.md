# Frickmail Feature Reference

Frickmail is a SnappyMail fork. This document describes every feature Frickmail adds
on top of stock SnappyMail. It is written for developers onboarding to the project and
for power users who want to understand what is available and how it is configured.

SnappyMail upstream is patched in exactly three places: `Service.php`,
`ServiceActions.php` (one line each, to hook the Frickmail login bridge), and static
assets (icons, PWA manifest). Everything else is delivered through two plugins:
`frickmail-user` and `frickmail-theme`.

---

## Table of Contents

1. [Authentication & Identity](#1-authentication--identity)
2. [Multi-Account Management](#2-multi-account-management)
3. [Unified Inbox](#3-unified-inbox)
4. [Full-Text Search](#4-full-text-search)
5. [Desktop Notifications](#5-desktop-notifications)
6. [Microsoft Graph API (Office 365)](#6-microsoft-graph-api-office-365)
7. [Sender Identities](#7-sender-identities)
8. [Message Filter Rules](#8-message-filter-rules)
9. [S/MIME](#9-smime)
10. [Tasks](#10-tasks)
11. [Import / Export](#11-import--export)
12. [Theme & UI](#12-theme--ui)
13. [PWA & Service Worker](#13-pwa--service-worker)
14. [Security Hardening](#14-security-hardening)
15. [Infrastructure](#15-infrastructure)

---

## 1. Authentication & Identity

### What it does

Frickmail replaces SnappyMail's native per-domain login with a centralised user
identity layer. Users register with a username and password; Frickmail stores the
identity in Postgres and bridges to SnappyMail's IMAP session transparently.

### Cryptography

| Property | Detail |
|---|---|
| Password hashing | Argon2id via `password_hash()` with `PASSWORD_ARGON2ID` |
| Key derivation | Argon2id-KDF applied to the plaintext password + per-user `kdf_salt` (BYTEA) to produce a 32-byte AEAD key used to encrypt credentials at rest |
| Credential encryption | xchacha20-poly1305 AEAD (`Crypto::encrypt` / `Crypto::decrypt`) |
| Salt storage | `frickmail_users.kdf_salt` (BYTEA, random, per user) |
| Timing-safe login | Dummy hash verified even when username does not exist (prevents enumeration) |
| Session fixation | `session_regenerate_id(true)` called on every successful login |

After a password reset, all stored IMAP passwords and OAuth refresh tokens are
irrecoverable (they are encrypted with the old KDF key). The login flow detects this
state (`reauth_required`) and prompts the user to re-enter credentials.

### TOTP 2FA

Two-factor authentication is optional and per-user. Implemented via SnappyMail's
built-in `\SnappyMail\TOTP` class.

**Setup flow:**
1. `FrickmailEnableTotp` — generates a TOTP secret, stores it temporarily in the PHP
   session, returns `otpauth://` URI and a base64 QR code data URL.
2. `FrickmailConfirmTotp` — verifies the first user-supplied code against the pending
   secret; only then writes it to `frickmail_users.totp_secret`.
3. `FrickmailDisableTotp` — requires a valid live code before clearing the secret.

**Replay protection:** `frickmail_totp_used` table records `(user_id, code, window)` as
a primary key. Any code already present for the current 30-second window is rejected
with `totp_replay`.

### Password reset

1. `FrickmailRequestPasswordReset` — looks up the username, generates a
   32-byte random token, stores its SHA-256 hash in `frickmail_password_resets`
   with a 30-minute TTL, and emails a reset link to the user's registered recovery
   email. Always returns HTTP 200 regardless of whether the username exists.
2. `FrickmailResetPassword` — validates the token hash, sets a new Argon2id hash and
   a fresh `kdf_salt`, and marks the reset token consumed. The encrypted credential
   blobs are left intact but are now unreadable (different derived key).

### Registration

Self-signup is controlled by the admin flag `FRICKMAIL_OPEN_SIGNUP`. The first user
to register is always allowed regardless of this flag (bootstraps the system).
Minimum username length: 3 characters. Minimum password length: 8 characters.

### Files

| Layer | File |
|---|---|
| JS (login form) | `plugins/frickmail-user/js/Login.js` |
| JS (2FA settings) | `plugins/frickmail-user/js/TwoFactorSettings.js` |
| PHP | `plugins/frickmail-user/lib/AuthHandler.php` |
| PHP (crypto) | `plugins/frickmail-user/lib/Crypto.php` |

### Admin flags

| Flag | Default | Effect |
|---|---|---|
| `FRICKMAIL_OPEN_SIGNUP` | `false` | Allow public registration |

---

## 2. Multi-Account Management

### What it does

A single Frickmail user can hold multiple mail accounts of three types: `imap`,
`gmail` (Google OAuth2), and `o365` (Microsoft OAuth2 / Office 365). One account is
marked `is_primary`; it is the account SnappyMail bridges to on login. Additional
accounts can be switched to at any time via the account dropdown or the Mail Accounts
settings tab.

### Account types

| Type | Auth mechanism | Notes |
|---|---|---|
| `imap` | IMAP password, encrypted at rest | Any IMAP/SMTP server |
| `gmail` | OAuth2 refresh token (Google) | XOAUTH2 via `login-gmail` plugin |
| `o365` | OAuth2 refresh token (Microsoft) | OAUTHBEARER via `login-o365` plugin; also used for Graph API |

### Provider presets

`MailAccountsSettings.js` detects the email domain on input and auto-fills IMAP/SMTP
host, port, and security settings for 18 known providers including Gmail, Outlook,
Yahoo, iCloud, FastMail, ProtonMail Bridge, and several Italian ISPs.

### Per-account settings editor

Each account in the list can be expanded inline to edit label, IMAP login, IMAP/SMTP
host+port+security, and password (leave blank to keep existing). Changes are sent to
`FrickmailUpdateAccount`. The SSRF guard (see Section 14) applies on both add and
update.

### OAuth2 flow

OAuth consent is opened in a 520×640 popup. On completion the popup posts a
`frickmail-oauth2` `postMessage` to the opener with `{ status, email, pending_refresh_token }`.
The opener calls `FrickmailSaveOAuthToken` to persist the refresh token encrypted under
the session's AEAD key.

### SnappyMail bridge

`MailAccountHandler::bridge()` translates a Frickmail account row into a SnappyMail
`LoginProcess()` call:
- IMAP accounts: decrypts the stored password, calls `LoginProcess(email, password)`.
- OAuth accounts: exchanges the stored refresh token for a fresh access token, injects
  it into the OAuth plugin's static `$auth` slot, then calls
  `LoginProcess(email, email_as_pseudo_password)`. Stale `.cryptkey` files are
  deleted before bridging to avoid `CryptKeyError` after re-authorisation.

### Account switching

`FrickmailSwitchAccount` validates the target account, stores it as the selected
mail account, and triggers `rl.route.reload()` on the client. In the PHP bridge
runtime this still calls `bridge()` for the target account; in the Rust runtime
the selected account is stored in the Rust session and consumed by native
Frickmail-user mailbox routes. The `AccountSwitcher.js` module patches the
`SystemDropDown` view model's `accountClick` handler to intercept Frickmail accounts
and route them through this endpoint instead of SnappyMail's native account-switch
path.

### Service discovery

After adding an account, `FrickmailDiscoverServices` probes for associated CalDAV
contacts and calendar services and presents a dialog to activate them via
`FrickmailActivateService`.

### Files

| Layer | File |
|---|---|
| JS (settings UI) | `plugins/frickmail-user/js/MailAccountsSettings.js` |
| JS (dropdown injection) | `plugins/frickmail-user/js/AccountSwitcher.js` |
| PHP | `plugins/frickmail-user/lib/MailAccountHandler.php` |
| PHP (service discovery) | `plugins/frickmail-user/lib/ServiceDiscoveryHandler.php` |

### Admin flags

| Environment variable | Default | Effect |
|---|---|---|
| `FRICKMAIL_GMAIL_CLIENT_ID` | — | Google OAuth2 client ID (falls back to `login-gmail` plugin config) |
| `FRICKMAIL_GMAIL_CLIENT_SECRET` | — | Google OAuth2 client secret |
| `FRICKMAIL_O365_CLIENT_ID` | — | Azure AD app client ID |
| `FRICKMAIL_O365_CLIENT_SECRET` | — | Azure AD app client secret |

Required Azure AD delegated permissions for full functionality (IMAP + Graph):
`IMAP.AccessAsUser.All`, `SMTP.Send`, `offline_access`, `Mail.Read`,
`Mail.ReadWrite`, `Mail.Send`, `User.Read`.

---

## 3. Unified Inbox

### What it does

Opens a full-screen split-pane overlay showing messages from all IMAP accounts merged
and sorted by date descending. The left pane (280 px) is a scrollable message list;
the right pane shows the full message body fetched inline. On viewports narrower than
600 px the panes stack and a back button navigates between them.

### Implementation

- **PHP backend** (`FrickmailUnifiedInbox`): iterates all `imap`-type accounts, opens
  a direct `MailSo\Imap\ImapClient` connection per account (10 s timeout), fetches
  `ENVELOPE`, `FLAGS`, `INTERNALDATE`, and `UID` for the last N messages from `INBOX`,
  merges and sorts all results by `date_ts` descending, and returns up to `limit`
  messages. Errors from individual accounts are collected and returned separately so
  one failing account does not abort the rest.

- **Rust backend** (`FrickmailUnifiedInbox`): serves the same response envelope from
  `frickmail_message_index` as an indexed snapshot. It returns only `imap` accounts
  with a stored password, filters to `INBOX`, preserves user/account scoping, and
  sorts by indexed `date_ts`. The index does not persist IMAP `FLAGS`, so snapshot
  rows are treated as already seen until native live header fetch or flag indexing is
  added.

- **Message body** (`FrickmailGetMessageBody`): opens a second MailSo connection for
  the owning account and uses `MailSo\Mail\MailClient::Message()` to fetch the decoded
  HTML or plain-text body. HTML is rendered in a sandboxed `<iframe sandbox="allow-same-origin">`
  to isolate untrusted content.

- **Account badges**: each message row shows a colour-coded initial badge (`BADGE_COLORS`
  cycles through 8 colours) with a tooltip showing the account label.

- **"Open in account" button**: calls `FrickmailSwitchAccount` for the owning account
  and reloads the app so the user lands in that account's inbox.

- **Toolbar injection**: `MailMessageList` view model mount event triggers injection
  of an "All accounts" button into the existing toolbar.

### User-configurable limit

`unified_inbox_limit` preference (default 40, range 10–100) controls how many messages
per account are fetched. Configurable in Settings → Frickmail Preferences.

### Files

| Layer | File |
|---|---|
| JS | `plugins/frickmail-user/js/UnifiedInbox.js` |
| PHP | `plugins/frickmail-user/lib/MailAccountHandler.php` — `unifiedInbox()`, `getMessageBody()` |

---

## 4. Full-Text Search

### What it does

Cross-account full-text search over indexed message metadata (subject, sender name,
sender address, snippet). A slide-in panel opens from the right with an input field
and result list; clicking a result switches to the owning account.

### Backend

- **Index table**: `frickmail_message_index` stores one row per message with a
  `tsvector` column (`tsv`) populated from `subject || from_name || from_addr || snippet`.
  A GIN index on `tsv` makes ranked queries fast.

- **Query**: `plainto_tsquery` (handles multi-word, no special syntax required).
  Results are ordered by `ts_rank(tsv, query) DESC, date_ts DESC`.

- **Indexing**: messages are indexed lazily when viewed, and in bulk on account add
  (`indexMessageFromHeader`). The index is deleted when an account is removed
  (`deleteMessageIndex` called before `deleteMailAccount`).

- **Endpoint**: `FrickmailSearch` — accepts `{ q, limit }`, returns up to 50 rows
  with `{ subject, from_name, from_addr, date_ts, snippet, account_email, account_id }`.

### Postgres schema (key columns)

```sql
frickmail_message_index (
    account_id  BIGINT  REFERENCES frickmail_mail_accounts,
    folder      TEXT,
    imap_uid    BIGINT,
    subject     TEXT,
    from_addr   TEXT,
    from_name   TEXT,
    date_ts     TIMESTAMPTZ,
    snippet     TEXT,
    tsv         tsvector,
    UNIQUE(account_id, folder, imap_uid)
)
-- Indexes:
CREATE INDEX idx_fm_msgidx_tsv  ON frickmail_message_index USING GIN(tsv);
CREATE INDEX idx_fm_msgidx_user ON frickmail_message_index(user_id, date_ts DESC);
```

### Files

| Layer | File |
|---|---|
| JS | `plugins/frickmail-user/js/Search.js` |
| PHP | `plugins/frickmail-user/lib/MailAccountHandler.php` — `search()`, `indexMessageFromHeader()` |

---

## 5. Desktop Notifications

### What it does

Notifies the user when new mail arrives in any IMAP account's inbox. Requires the
browser Notifications API. A permission banner is shown the first time if permission
has not been granted.

### Detection strategy: long-poll

The client sends `FrickmailLongPollNewMail` with the last-known UIDNEXT per account.
The server holds the connection for up to 25 seconds, polling each IMAP account's
inbox UIDNEXT every 5 seconds. It returns immediately when any account's UIDNEXT
changes, or after the 25-second timeout with `{ timeout: true }`.

The client:
- On new mail found: dispatches a notification tagged `fm-newmail-{account_id}`, then
  immediately starts the next long-poll cycle (0 ms delay).
- On timeout (no mail): waits `reconnect_delay` seconds (user preference, default 60 s,
  range 30–300 s) then starts the next cycle.
- After 3 consecutive long-poll failures: falls back to one-shot `FrickmailCheckNewMail`
  with the same reconnect delay.

Effective new-mail latency: ≤5 seconds during active polling (server checks every 5 s).

### First-poll baseline

On the first successful poll, UIDNEXT values are recorded as a baseline without
triggering notifications. Only subsequent polls that observe a UIDNEXT increase fire
notifications.

### Notification dispatch

If a Service Worker is active, notifications are issued via
`ServiceWorkerRegistration.showNotification()` (allows rich notifications on mobile).
Otherwise falls back to `new Notification()`.

### User preference

`notifications_poll_interval` (30–300 s, default 60) controls the reconnect delay
between long-poll cycles when no new mail is found. Set in Settings → Frickmail
Preferences.

### Admin flag

Notifications can be disabled entirely at the plugin level (`notifications_enabled`
admin setting). When disabled, `Notifications.js` is not loaded.

### Files

| Layer | File |
|---|---|
| JS | `plugins/frickmail-user/js/Notifications.js` |
| PHP | `plugins/frickmail-user/lib/MailAccountHandler.php` — `checkNewMail()`, `fetchInboxStatus()` |
| PHP (long-poll) | `plugins/frickmail-user/index.php` — `JsonLongPollNewMail()` |

---

## 6. Microsoft Graph API (Office 365)

### What it does

For `o365`-type accounts a "Graph view" button appears in the `MailMessageList` toolbar
(one button per O365 account, labelled with the account label). Clicking it opens a
full-screen overlay that reads mail via the Microsoft Graph REST API rather than IMAP.

This is additive: the user still has standard IMAP access; Graph view is an alternative
path that is faster for search and supports delta sync.

### Overlay features

| Feature | Endpoint called |
|---|---|
| List inbox messages (top 50) | `FrickmailGraphListMessages` |
| Full-text search via Graph `$search` | `FrickmailGraphSearch` |
| Fetch full message body + header | `FrickmailGraphGetMessage` |
| Mark read / unread | `FrickmailGraphMarkRead` |
| Move to folder | `FrickmailGraphMove` |
| Delete (to Deleted Items) | `FrickmailGraphDelete` |
| Incremental delta sync | `FrickmailGraphDelta` |

### Delta sync

The "Delta" button calls `FrickmailGraphDelta` with the stored `@odata.deltaLink` from
the previous sync (or null for a full initial sync). The response contains changed and
removed messages. Removed messages (tombstones with `@removed`) are filtered from the
list; new/changed messages are prepended. The new delta link is retained in JS state
for the next sync.

### Authentication

`MailAccountHandler::graphClientForAccount()` decrypts the stored OAuth refresh token
and passes it to `GraphClient::fromRefreshToken()`. The Graph client exchanges it for
a fresh access token using the Microsoft token endpoint for the account's configured
tenant (default: `common`).

### Files

| Layer | File |
|---|---|
| JS | `plugins/frickmail-user/js/GraphMailbox.js` |
| PHP (handler methods) | `plugins/frickmail-user/lib/MailAccountHandler.php` — `graphListMessages()`, `graphGetMessage()`, `graphSearch()`, `graphDelta()`, etc. |
| PHP (HTTP client) | `plugins/frickmail-user/lib/GraphClient.php` |

---

## 7. Sender Identities

### What it does

Each mail account can have multiple sender identities (aliases). An identity has a
display name, an email address, an optional Reply-To address, and an `is_default` flag.
Only one identity per account can be the default (enforced by a Postgres partial unique
index). The primary identity cannot be deleted (minimum one per account enforced in JS;
`deleteIdentity` requires count > 1).

### Settings UI

Settings → Identities shows all accounts in a collapsible list. Expanding an account
shows its identities with Edit/Delete buttons and a form to add a new one. The `+` to
the right of each account label opens the add form.

### API endpoints

| Action | Endpoint |
|---|---|
| List | `FrickmailListIdentities` |
| Add | `FrickmailAddIdentity` |
| Set default | `FrickmailSetDefaultIdentity` |
| Delete | `FrickmailDeleteIdentity` |

`FrickmailListAccounts` also returns the `identities` array inline for each account,
so the Mail Accounts and Rules panels can display them without a second request.

### Files

| Layer | File |
|---|---|
| JS | `plugins/frickmail-user/js/IdentitySettings.js` |
| PHP | `plugins/frickmail-user/lib/MailAccountHandler.php` — `listIdentities()`, `addIdentity()`, `deleteIdentity()`, `setDefaultIdentity()` |

---

## 8. Message Filter Rules

### What it does

Client-side rules engine for IMAP accounts. Rules are evaluated by the server by
opening a direct IMAP connection and issuing `SEARCH` + `STORE`/`MOVE`/`EXPUNGE`
commands. Rules are stored in Postgres JSONB and are per-account.

### Rule structure

A rule has:
- A **name** (free text).
- One or more **conditions**, each with:
  - `field`: `from` | `subject` | `to`
  - `op`: `contains` | `not_contains` | `equals`
  - `value`: string
- A **conditions_logic**: `all` (AND) or `any` (OR).
- One or more **actions**:
  - `move` — requires `params.folder` (IMAP folder name)
  - `read` — sets `\Seen` flag
  - `flag` — sets `\Flagged` flag
  - `delete` — moves to Trash via `MessageDelete`
- An **enabled** boolean toggle.

### IMAP execution

`applyRules()` in `MailAccountHandler.php` translates conditions to IMAP `SEARCH`
criteria (`FROM`, `SUBJECT`, `TO`, `HEADER`, `NOT`). `any` logic with N > 2 criteria
builds nested binary `OR` expressions (IMAP RFC 3501 requirement). Matched UID sets
are processed by Rust-native IMAP mutation helpers. The legacy webmail routes
`MessageSetSeen`, `MessageSetFlagged`, `MessageSetDeleted`, `MessageCopy`,
`MessageMove`, and `MessageDelete` are also native for the selected IMAP
account during the broader SnappyMail/RainLoop runtime migration.

### UI

Settings → Rules. Accounts are collapsible. "Run now" button calls
`FrickmailApplyRules` and displays a report of matched counts per rule.
Rules can be individually toggled on/off without deleting them.

### Files

| Layer | File |
|---|---|
| JS | `plugins/frickmail-user/js/Rules.js` |
| PHP | `plugins/frickmail-user/lib/MailAccountHandler.php` — `listRules()`, `addRule()`, `deleteRule()`, `toggleRule()`, `applyRules()` |

---

## 9. S/MIME

### What it does

S/MIME certificate management: import personal certificates with private keys for
signing, import public certificates for verifying others, and test-sign messages.

### Certificate import

**PKCS#12 (.p12/.pfx):**
1. Browser reads the file with `FileReader.readAsArrayBuffer` and base64-encodes it.
2. Sends `{ account_id, p12_b64, password }` to `FrickmailSmimeImportP12`.
3. Rust decodes and parses the PKCS#12 bundle with OpenSSL.
4. Extracts `cert` (PEM) and `pkey` (PEM). The private key is encrypted with
   `Crypto::encrypt(keyPem, cryptKey)` before storage.
5. Stores in `frickmail_smime_certs` with `fingerprint` (SHA-1, colon-separated hex),
   `subject`, `not_before`, `not_after`.

**PEM certificate only:**
Sends `{ account_id, pem_b64 }` to `FrickmailSmimeImportCert`. No private key;
`encrypted_key_pem` is NULL. Used for recipient public certificates.

### Signing

`FrickmailSmimeSign` decrypts the private key from storage, signs with OpenSSL
PKCS#7 detached S/MIME support, and returns the signed message base64-encoded.

### Verification

`FrickmailSmimeVerify` calls `openssl_pkcs7_verify()` against the system trust store,
extracts the signer certificate, and parses the signer's email from `subjectAltName`
(email: or rfc822name: fields) or CN fallback.

### Key storage

Private keys are encrypted at rest with the same xchacha20-poly1305 AEAD key used for
IMAP passwords. The key is only available during an authenticated session.

### Expiry warnings

The settings UI (`SmimeSettings.js`) shows a warning badge for certificates expiring
within 30 days and an error badge for already-expired certificates.

### Admin flag

S/MIME can be disabled at the plugin level (`smime_enabled` admin setting). The
Rust compatibility server mirrors that gate with
`FRICKMAIL__FRICKMAIL_USER__SMIME_ENABLED=false`; when disabled, S/MIME hooks
fall back to the compatibility layer instead of running native Rust handlers.
Existing installs that disabled S/MIME in the PHP plugin admin settings should
set the Rust environment variable as well while both compatibility layers exist.

### Files

| Layer | File |
|---|---|
| JS | `plugins/frickmail-user/js/SmimeSettings.js` |
| PHP | `plugins/frickmail-user/lib/SmimeHandler.php` |

---

## 10. Tasks

### What it does

A simple to-do list backed by Postgres. Tasks have a title, optional notes, an optional
due date, and a completed flag. The task list is accessible via a "✓" icon in the icon
nav column.

### UI

Full-screen overlay with three tabs: All, Pending, Done. Each task row has a checkbox
(optimistic toggle), a title with optional due date and notes preview, and a delete
button. Overdue tasks (due date in the past, not completed) have the date highlighted
in red. A quick-add form at the bottom has a title input, an optional date picker, and
an expandable notes textarea.

### API endpoints

| Action | Endpoint | Parameters |
|---|---|---|
| List | `FrickmailListTasks` | `{ filter: '' | 'pending' | 'completed' }` |
| Add | `FrickmailAddTask` | `{ title, notes?, due_date? }` |
| Toggle complete | `FrickmailCompleteTask` | `{ id, completed }` |
| Delete | `FrickmailDeleteTask` | `{ id }` |
| Update | `FrickmailUpdateTask` | `{ id, title, notes?, due_date? }` |

### Schema

```sql
frickmail_tasks (
    id           BIGSERIAL PRIMARY KEY,
    user_id      BIGINT REFERENCES frickmail_users,
    title        TEXT NOT NULL,
    notes        TEXT,
    due_date     DATE,
    completed    BOOLEAN DEFAULT FALSE,
    completed_at TIMESTAMPTZ,
    created_at   TIMESTAMPTZ,
    updated_at   TIMESTAMPTZ
)
CREATE INDEX idx_fm_tasks_user ON frickmail_tasks(user_id, completed, due_date);
```

### Admin flag

Tasks can be disabled at the plugin level (`tasks_enabled` admin setting). When
disabled, `Tasks.js` and task endpoints are not loaded.

### Files

| Layer | File |
|---|---|
| JS | `plugins/frickmail-user/js/Tasks.js` |
| PHP | `plugins/frickmail-user/lib/TaskHandler.php` |

---

## 11. Import / Export

### What it does

| Action | Location | What it does |
|---|---|---|
| Export .eml | **Message view toolbar** | Downloads the open message as an RFC 2822 `.eml` file |
| Export .mbox | **Settings → Import / Export** | Downloads all messages in the chosen folder as an mbox file |
| Import .eml | **Settings → Import / Export** | Opens a file picker; appends the `.eml` to the chosen folder via IMAP APPEND |

Export .mbox and Import .eml were moved from the main toolbar (low-frequency, caused overflow on mobile). The Settings tab provides a folder name field and a status line, accessible on all screen sizes.

### Implementation details

**Export .eml** (`FrickmailExportMessage`): opens an IMAP connection, issues
`BODY.PEEK[]` fetch (does not set `\Seen`), base64-encodes the raw RFC 2822 bytes,
returns `{ content_b64, filename }`. The browser triggers a download via a temporary
object URL.

**Export .mbox** (`FrickmailExportFolder`): fetches messages in batches of 50
using `BODY.PEEK[]`, prepends a `From ` envelope line to each, concatenates them into
mbox format, and returns the result base64-encoded. The Rust backend keeps PHP's
`allow_export` default enabled, can disable these hooks with
`FRICKMAIL__FRICKMAIL_USER__ALLOW_EXPORT=false`, and bounds exports with
`FRICKMAIL__FRICKMAIL_USER__EXPORT_FOLDER_MAX_MESSAGES` plus
`FRICKMAIL__FRICKMAIL_USER__EXPORT_FOLDER_MAX_BYTES`.

**Import .eml** (`FrickmailImportEml`): validates the file starts with a known RFC 2822
header field pattern, then calls `ImapClient::MessageAppendStream()` targeting the
specified folder (default `INBOX`) with the `\Seen` flag set.

### Files

| Layer | File |
|---|---|
| JS | `plugins/frickmail-user/js/ImportExport.js` |
| PHP | `plugins/frickmail-user/lib/MailAccountHandler.php` — `exportMessage()`, `exportFolder()`, `importEml()` |

---

## 12. Theme & UI

### What it does

The `frickmail-theme` plugin applies a Frickmail look-and-feel on top of SnappyMail's
default skin, adds an icon navigation column, and provides a user-facing Appearance
settings tab.

### Dark / light / system theme

Three modes: `dark` (default), `light`, `system` (follows `prefers-color-scheme`).
Applied by setting a `data-fm-theme` attribute on `<html>`. Theme is read from
`localStorage` on every page load before anything else renders, eliminating flash of
unstyled content (FOUC).

### Accent colours

Six accent colour presets (Blue, Teal, Purple, Pink, Peach, Green). Each has separate
dark-mode and light-mode hex values. Applying an accent sets three CSS custom
properties: `--fm-accent`, `--fm-accent-hover`, `--fm-accent-surface`.

### Font size

Adjustable 12–18 px via a range slider in the Appearance settings tab. Stored in
`localStorage` as `fm_fontsize`; applied by setting `--main-font-size` on
`documentElement`.

### Icon navigation column

A 56 px-wide vertical icon nav (`#fm-icon-nav`) is prepended to `document.body`. It
contains:

| Icon | Action |
|---|---|
| App logo | (static) |
| ✉ Mail | Navigate to `#/mailbox/INBOX` |
| 📬 All accounts | Open Unified Inbox overlay |
| 👤 Contacts | Click SnappyMail contacts button |
| 📅 Calendar | Navigate to `#/settings/calendar` |
| ✓ Tasks | Open Tasks overlay (injected by `Tasks.js`) |
| ⚙ Settings | Navigate to `#/settings` |

The nav is hidden on the Login screen and shown on all other screens. Active item is
synced with the URL hash.

### mailto: protocol registration

`navigator.registerProtocolHandler('mailto', location.origin + '/?compose=%s', 'Frickmail')`
is called on every page load (idempotent; browsers ignore repeated registrations).

### Files

| Layer | File |
|---|---|
| JS | `plugins/frickmail-theme/js/ThemeSwitcher.js` |
| CSS | `plugins/frickmail-theme/css/` |

---

## 13. PWA & Service Worker

### What it does

Frickmail is installable as a Progressive Web App and works partially offline.

### Service Worker (`sw.js`)

Registered at scope `/` with `Service-Worker-Allowed: /` header. Cache version: `fm-v4`.

| URL pattern | Strategy | Cache |
|---|---|---|
| `/snappymail/v/<ver>/static/*` | Cache-first | `fm-v4` (versioned, content-addressed) |
| `/?/Css/*` and `/?/Js/*` | Stale-while-revalidate | `fm-v4` |
| `/?Json/…MessageList`, `/?Json/…Message`, `/?Json/…FrickmailUnifiedInbox` | Network-first, offline fallback | `fm-messages-v1` (30-min TTL) |
| Other `/?Json/*` API calls | Network-only | — |
| `/` and `/index.php` | Network-first, offline fallback | `fm-v4` |

Offline fallback for message API calls returns `{ Result: null, ErrorCode: 0, ErrorMessage: 'Offline' }` with a `X-Frickmail-Offline: 1` header, allowing the UI to detect and display offline state rather than a generic error.

Message cache pruning runs best-effort after each network write: entries whose `Date`
response header is older than 30 minutes are deleted.

### Web Push handler

The SW has a `push` event handler that calls `self.registration.showNotification()`.
The `notificationclick` handler focuses an existing Frickmail window or opens a new
one at the URL carried in `notification.data.url`.

The server-side VAPID infrastructure (key generation, `/FrickmailPushSubscribe`
endpoint, trigger on new mail) is listed in the roadmap as the next pending step; the
SW handler is already in place.

### PWA manifest

An installable `manifest.json` is served with the correct `start_url`, `display:
standalone`, icons, and theme colour. This enables "Add to Home Screen" on Android/iOS
and the install prompt on desktop Chrome/Edge.

### Files

| Layer | File |
|---|---|
| SW | `.docker/release/files/snappymail/sw.js` |
| Registration + mailto | `plugins/frickmail-theme/js/ThemeSwitcher.js` (top of file) |

---

## 14. Security Hardening

### HTTP security headers (nginx)

All responses include the following headers (set with `always` so they apply to error
responses too):

| Header | Value |
|---|---|
| `X-Frame-Options` | `DENY` |
| `X-Content-Type-Options` | `nosniff` |
| `Referrer-Policy` | `strict-origin-when-cross-origin` |
| `Permissions-Policy` | `camera=(), microphone=(), geolocation=()` |
| `Content-Security-Policy` | `default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob: https:; font-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self';` |

`'unsafe-inline'` and `'unsafe-eval'` in `script-src` are required by SnappyMail's
KnockoutJS-based UI. `frame-ancestors 'none'` provides clickjacking protection
equivalent to `X-Frame-Options: DENY` for CSP-aware browsers.

### Rate limiting (nginx)

A shared `login` zone of 10 MB is defined with a rate of 10 requests/minute. The zone
key is the real client IP (from `X-Real-IP` if present, otherwise the connection IP).

Rate limiting applies only to:
- `?/Login/` query strings
- `^admin` query strings

All other requests are in the empty-key bucket (no limit). Burst of 5 allowed with
`nodelay`. Excess requests return HTTP 429.

### SSRF guard

`MailAccountHandler::addAccount()` and `updateAccount()` resolve each `imap_host` and
`smtp_host` with `gethostbyname()` and reject any result that falls within private or
reserved IP ranges (`FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE`). This
prevents an authenticated user from using the server as a proxy to scan internal
network services.

### Secure cookies (PHP)

When `SECURE_COOKIES=true` (default), PHP sessions are configured with:
```
session.cookie_httponly = On
session.cookie_secure   = On
session.use_only_cookies = On
```

### Session fixation

`session_regenerate_id(true)` is called on every successful login.

### TOTP replay protection

See Section 1. Prevents reuse of a valid TOTP code within the same 30-second window.

### Iframe sandboxing for email HTML

HTML bodies rendered in the Unified Inbox and Graph Mailbox overlays use
`<iframe sandbox="allow-same-origin">`. This allows the iframe to read its own DOM
(needed for some mail clients' inline CSS) while blocking scripts, form submission,
and navigation from untrusted HTML content.

### Files

| Layer | File |
|---|---|
| nginx config | `.docker/release/files/etc/nginx/nginx.conf` |
| SSRF guard | `plugins/frickmail-user/lib/MailAccountHandler.php` — `addAccount()`, `updateAccount()` |
| Secure cookies | `.docker/release/files/entrypoint.sh` |

---

## 15. Infrastructure

### Docker build

The container runs nginx (port 8888) + php-fpm via supervisord. Both processes are
started by `entrypoint.sh` which handles all first-boot provisioning before exec-ing
supervisord.

### Plugin sync on boot

On every container start, `entrypoint.sh` overwrites the SnappyMail plugin directory
with the image-bundled versions of:
`login-oauth2`, `login-gmail`, `login-o365`, `contacts-sync`, `calendar`,
`frickmail-user`, `frickmail-theme`.

This ensures plugin upgrades are applied on container restart without requiring a
manual admin action. SnappyMail's plugin JS cache (`cache/`) is also cleared on sync.

The enabled plugin list in `application.ini` is written and re-written idempotently
(including a 15-second polling loop after startup to defend against SnappyMail
overwriting it on first request):
```
login-oauth2,login-gmail,login-o365,contacts-sync,calendar,frickmail-user,frickmail-theme,cache-redis
```

### Postgres schema provisioning

`entrypoint.sh` runs a PHP snippet at boot that connects to Postgres (retrying up to
30 times with 1-second delays) and issues idempotent `CREATE TABLE IF NOT EXISTS` /
`CREATE INDEX IF NOT EXISTS` / `ALTER TABLE … ADD COLUMN IF NOT EXISTS` DDL.

Tables provisioned:

| Table | Purpose |
|---|---|
| `frickmail_users` | User accounts (username, Argon2id hash, KDF salt, JSONB settings) |
| `frickmail_mail_accounts` | Mail account rows (type, IMAP/SMTP config, encrypted credential blobs) |
| `frickmail_password_resets` | Time-limited reset tokens (SHA-256 hash, 30-min TTL) |
| `frickmail_totp_used` | TOTP replay prevention (user_id, code, window — composite PK) |
| `frickmail_message_index` | Full-text search index (tsvector, GIN index) |
| `frickmail_identities` | Sender identities per account |
| `frickmail_tasks` | User tasks (title, notes, due_date, completed) |
| `frickmail_rules` | Message filter rules (conditions + actions stored as JSONB) |
| `frickmail_smime_certs` | S/MIME certificates (PEM cert, encrypted private key BYTEA) |

### Redis cache

`entrypoint.sh` writes the `cache-redis` plugin config file pointing at
`FRICKMAIL_REDIS_HOST:FRICKMAIL_REDIS_PORT` (defaults: `redis:6379`). Redis provides
SnappyMail's session and object cache layer.

### Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `FRICKMAIL_DB_HOST` | `db` | Postgres hostname |
| `FRICKMAIL_DB_PORT` | `5432` | Postgres port |
| `FRICKMAIL_DB_NAME` | `frickmail` | Database name |
| `FRICKMAIL_DB_USER` | `frickmail` | Database user |
| `FRICKMAIL_DB_PASSWORD` | `frickmail` | Database password |
| `FRICKMAIL_REDIS_HOST` | `redis` | Redis hostname |
| `FRICKMAIL_REDIS_PORT` | `6379` | Redis port |
| `FRICKMAIL_OPEN_SIGNUP` | `false` | Allow public user registration |
| `FRICKMAIL_GMAIL_CLIENT_ID` | — | Google OAuth2 app client ID |
| `FRICKMAIL_GMAIL_CLIENT_SECRET` | — | Google OAuth2 app client secret |
| `FRICKMAIL_O365_CLIENT_ID` | — | Azure AD app client ID |
| `FRICKMAIL_O365_CLIENT_SECRET` | — | Azure AD app client secret |
| `UPLOAD_MAX_SIZE` | `25M` | Max upload size (nginx + php-fpm) |
| `MEMORY_LIMIT` | `256M` | PHP memory limit |
| `SECURE_COOKIES` | `true` | Enforce httponly/secure PHP session cookies |
| `DEBUG` | — | Set to `true` to enable `set -x` in entrypoint |

### Auth logging

SnappyMail auth logging is enabled unconditionally. Failed login attempts are written
to `auth.log` in the format:
```
[{date}] Auth failed: ip={ip} user={imap:login} host={imap:host} port={imap:port}
```

### Files

| Layer | File |
|---|---|
| Entrypoint | `.docker/release/files/entrypoint.sh` |
| nginx config | `.docker/release/files/etc/nginx/nginx.conf` |

---

## 16. Per-account Settings Editor

Added directly to the Mail Accounts settings page (Settings → Mail Accounts).
Each account row has a **⚙ Edit** button that expands an inline form.

| Account type | Editable fields |
|---|---|
| IMAP | Label, login, password (blank = keep current), IMAP host/port/security, SMTP host/port/security |
| Gmail / O365 | Label only; IMAP/SMTP fields shown read-only with note explaining OAuth2 manages them |

**Implementation:** `FrickmailUpdateAccount` JSON hook → `MailAccountHandler::updateAccount()` → `Db::updateMailAccount()`. SSRF guard applied to host fields. Frontend: `MailAccountsSettings.js` + `FrickmailMailAccountsSettings.html`.

---

## 17. Web Push Notifications (VAPID)

Real push notifications to the browser even when the Frickmail tab is backgrounded.

### Server-side (`lib/VapidPush.php`)

Pure PHP, no external libraries.

- `generateKeys()` — P-256 EC key pair via `openssl_pkey_new`; public key as base64url-encoded uncompressed point (`0x04 ‖ X ‖ Y`, 65 bytes)
- `makeAuthHeader()` — ES256 JWT (ECDSA + SHA-256); DER→raw R‖S conversion for RFC 7515
- `send()` — HTTP POST to push endpoint with `Authorization: vapid ...` + `TTL` headers; JSON payload `{title, body, tag, url}` consumed by existing SW handler

VAPID key pair generated once and stored in plugin config (`vapid_public_b64u`, `vapid_private_pem`).

### Endpoints

| Endpoint | Description |
|---|---|
| `FrickmailGetVapidKey` | Returns the application server public key (generates keys on first call) |
| `FrickmailPushSubscribe` | Stores a `PushSubscription` (endpoint, p256dh, auth) in `frickmail_push_subscriptions` |
| `FrickmailPushUnsubscribe` | Deletes a subscription |

Push is triggered from `JsonLongPollNewMail` when new mail is detected, so it fires even when the tab is in the background. Requires the browser to still be running (SW active). True offline push (browser fully closed) requires the IMAP IDLE worker (not yet implemented).

### Client-side (`js/Notifications.js`)

After notification permission is granted:
1. `registerWebPush()` calls `FrickmailGetVapidKey`, then `pushManager.subscribe({ userVisibleOnly: true, applicationServerKey })`
2. The resulting `PushSubscription` is POSTed to `FrickmailPushSubscribe`
3. The Service Worker's existing `push` event handler shows the notification

---

## 18. New-mail Detection — Long Poll

Replaces the previous fixed 60-second `setInterval` poll.

`FrickmailLongPollNewMail` holds the HTTP connection open for up to 25 s, checking IMAP `UIDNEXT` every 5 s server-side, and returns immediately when new mail arrives. The browser reconnects immediately on a new-mail response, or after a user-configurable delay on timeout.

| Behaviour | Detail |
|---|---|
| Max latency | ≤5 s (server checks every 5 s) |
| Reconnect delay | User preference `notifications_poll_interval` (30–300 s); set in Settings → Frickmail Preferences |
| Fallback | After 3 consecutive errors, falls back to single-shot `FrickmailCheckNewMail` |
| Preference wiring | `Notifications.js` reads `FrickmailGetPrefs` at startup; old 60 s hardcoded constant removed |

---

## 19. Unified Inbox — Split-pane View

The All accounts overlay was redesigned from a simple list into a two-pane inbox.

| Pane | Content |
|---|---|
| Left (280 px, desktop) | Scrollable message list with coloured account badges |
| Right (flex:1) | Message detail: sender header + HTML body in sandboxed `<iframe>` + "Open in account ↗" button |

On narrow screens (<600 px) the panes stack: list → tap → full-screen detail with ← back button.

`FrickmailGetMessageBody` fetches the HTML/plain body by IMAP UID using `MailSo\Mail\MailClient::Message()` (handles MIME, encoding, multipart). The body is rendered in a sandboxed iframe to prevent XSS. Plain-text fallback if no HTML part is available.

The first message is auto-selected on desktop after load.

---

## 20. Contact Deduplication

**Root cause of duplicates:** `contacts-sync` called `ContactSave()` without setting the numeric `id` on the `Contact` object, so every sync run issued `INSERT` instead of `UPDATE`.

**Forward fix:** `savePersonAsContact()` and `saveGraphContact()` now call `GetContactByID($uid, true)` before saving. If a contact with that UID already exists, the existing `id` is copied onto the new object so `ContactSave()` issues `UPDATE`.

**Retroactive fix:** Settings → Contacts Sync → **Remove duplicates** button calls `JsonDeduplicateContacts`, which:
1. Iterates all contacts in pages of 500
2. Groups by `IdContactStr` (provider UID: `gmail:people/...`, `o365:AAMk...`)
3. Keeps the first (lowest numeric id), calls `DeleteContacts()` on all later copies
4. Reports the number removed
