# Frickmail Full Rust Migration Plan

This is the active plan for rewriting the entire Frickmail codebase in Rust.
It covers the Frickmail user features, the legacy SnappyMail/RainLoop runtime,
the legacy PHP plugin host, the webmail core, the admin/settings surface, the
frontend, theming, integrations, packaging, and the final production container.

## Progress Snapshot — 2026-08-30 15:05:00 CEST (UTC+02:00)

The pending OAuth2 provider slice adds native Gmail and O365 part hooks,
replacing the PHP `login-gmail` and `login-o365` plugins in Frickmail mode.
`StartLoginGMail` and `StartLoginO365` redirect to the providers with PKCE and
an encrypted state reusing the shared SnappyMail-compatible `EncryptUrlSafe`
crypto; `LoginGMail` and `LoginO365` exchange the code, fetch userinfo, and
either persist the refresh token with the active session (matching the PHP
bridge `upsertOAuthAccount` path) or pass it to the opener through the
`frickmail-oauth2` popup payload for `FrickmailSaveOAuthToken`. Provider
configuration lives under `FRICKMAIL__OAUTH2__GMAIL__*` /
`FRICKMAIL__OAUTH2__O365__*` with the legacy `FRICKMAIL_GMAIL_*` /
`FRICKMAIL_O365_*` environment variables as fallback. The
`oauth2.o365.personal` option switches O365 to the path-style
`https://host/LoginO365` reply URL served by dedicated routes for personal
Microsoft accounts. The legacy non-Frickmail IMAP-as-identity `LoginProcess`
callback path is intentionally not migrated. The popup renderer posts both
success and error payloads to the opener and deliberately does not persist
the refresh-token-bearing payload to localStorage.

Independent senior review approved the slice after one remediation round. The
first round blocked on a wrong O365 token-endpoint host, popup payload
delivery regressions, a plaintext localStorage credential, and missing
personal-mode redirect parity; all required fixes were applied and the closing
re-review approved with only informational residual risks (unbounded state
replay window inherited from PHP parity, config-drift redirect mismatch
failing safe at the provider).

Docker-only validation passed: `cargo fmt --all -- --check`,
`cargo check --workspace`, `cargo clippy --workspace --all-targets -D
warnings`, and `cargo test --workspace` (664 tests across 22 suites, zero
failures). Production-image validation built `frickmail-rust:oauth2-part-hooks-test`
at image ID `sha256:25dcfd1c3a159f7ef1e9e6ff91fe3c6943d39e78f459305ad26ec22904547a34`;
a read-only container started without a database, `/health` returned `ok`, the
OAuth2 part-hook paths returned the expected popup/redirect behavior
(unconfigured provider error popup, provider error plus `error_description`
forwarding, path-style callback route, missing-code redirect to the webmail
root, configured start-login redirect with PKCE through the legacy
`FRICKMAIL_GMAIL_CLIENT_ID` env fallback), logs showed only expected startup
messages, and it stopped cleanly.

This slice also restores the dual-branch publication policy: the four commits
`c07048e060b6822eaf0e9d5115247c9a4efbf257`..`8f6f22117f657b5916165a8b9fa23be655c4e046`
(a review-findings docs update, the DB schema compatibility integration
tests, the DROP TABLE test-race fix, and the native OIDC
`StartLoginOIDC`/`LoginOIDC` part-hook slice) had been pushed to `master`
only; publishing this slice's commit to `rust-full-migration` on both remotes
fast-forwards that branch to include them.

## Prior Snapshot — 2026-08-25 14:15:00 CEST (UTC+02:00)

The pending `PgpVerifyMessage` IMAP MIME normalization slice completes the
legacy byte-input path for detached and clear-signed verification. The native
handler now fetches bounded part MIME headers, decodes clear-signed bodies when
they use Base64 or quoted-printable transfer encoding like PHP, prepends those
headers plus CRLF to a detached signature before the body, preserves the legacy
GnuPG input order, and continues to ASCII-filter signatures. A regression covers
the PHP-compatible clear-signed decoding rules. Formatting, workspace Clippy
with warnings denied, full workspace tests, production-image build, read-only
startup, `/health`, and in-container GnuPG execution passed. Independent senior
review approved.

Implementation commit `4f0dae58736a1ef801b5aea5d606a8c85413e892` was published
to all four remote tips, with live remote checks confirming identical SHAs.
Exact-SHA GitHub CI passed for that SHA on `master` run
[`32845271725`](https://github.com/ilfrick/frickmail/actions/runs/32845271725)
and `rust-full-migration` run
[`32845271821`](https://github.com/ilfrick/frickmail/actions/runs/32845271821).
This documentation-only amendment records that evidence; those runs remain
authoritative for the implementation.

The pending signed-and-encrypted GnuPG slice removes `--skip-verify` from
native `GnupgDecrypt`, so verification status is emitted while decrypting.
Direct-data and IMAP-part responses now return legacy-compatible multi-signature
objects instead of always claiming an empty list; unsigned encrypted payloads
continue to return an empty signature collection. This intentionally improves on
legacy behavior: a bad or unusable embedded signature can fail decryption rather
than silently returning plaintext as merely unsigned. An isolated end-to-end
regression signs and encrypts with a passphrase-protected key, decrypts through
the native handler, and asserts both recovered plaintext and one valid
signature. Formatting, workspace Clippy with warnings denied, full workspace
tests, production-image build, read-only startup, `/health`, and in-container
GnuPG execution passed. Independent senior review approved.

Implementation commit `9a634c6e82835dddc578107ab7664d57831cafc8` was published
to all four remote tips, with live remote checks confirming identical SHAs.
Exact-SHA GitHub CI passed for that SHA on `master` run
[`32829573724`](https://github.com/ilfrick/frickmail/actions/runs/32829573724)
and `rust-full-migration` run
[`32829573612`](https://github.com/ilfrick/frickmail/actions/runs/32829573612).

The pending GnuPG verification parity slice replaces the early-return verifier
parser with SnappyMail's multi-signature model. Signature status objects are
created for `GOODSIG`, `BADSIG`, `ERRSIG`, `EXPKEYSIG`, `REVKEYSIG`, and
`EXPSIG`; a following `VALIDSIG` updates the same signature with its
fingerprint, timestamp, expiry, version, and valid marker. Percent-encoded UIDs
and PHP-compatible summary messages are preserved, while missing signatures
still return legacy false. Deterministic regressions cover valid, bad,
multiple-signature, and no-signature output. Formatting, workspace Clippy with
warnings denied, full workspace tests, production-image build, read-only
startup, `/health`, and in-container GnuPG execution passed. Independent senior
review approved.

Implementation commit `a198298473fa7b2bbd118c01720a082790ff9f20` was published
to all four remote tips, with live remote checks confirming identical SHAs.
Exact-SHA GitHub CI passed for that SHA on `master` run
[`32823183347`](https://github.com/ilfrick/frickmail/actions/runs/32823183347)
and `rust-full-migration` run
[`32823183689`](https://github.com/ilfrick/frickmail/actions/runs/32823183689).

The pending GnuPG export/decrypt parity slice fixes native `GnupgExportKey` so
private exports use only `--export-secret-keys`, honor the supplied loopback
passphrase under the existing 1,024-byte bound, and return real armored GnuPG
stdout. The shared runner now preserves parsed status lines while returning
actual stdout, correcting public exports and other stdout-consuming crypto
paths. A new isolated end-to-end regression generates a passphrase-protected
key, exports its private armor, encrypts a payload, and decrypts it through the
native handlers. Formatting, workspace Clippy with warnings denied, full
workspace tests, production-image build, read-only startup, `/health`, and
in-container GnuPG execution passed. Independent senior review approved.

Implementation commit `296bbb1dc880de885920666ac93aa991f377b544` includes the
CI-only GnuPG test dependency fix and was published to all four remote tips;
live remote checks confirmed identical SHAs. Exact-SHA GitHub CI passed for
that SHA on `master` run
[`32818414406`](https://github.com/ilfrick/frickmail/actions/runs/32818414406)
and `rust-full-migration` run
[`32818414748`](https://github.com/ilfrick/frickmail/actions/runs/32818414748).

The pending follow-up OpenPGP slice completes `PgpImportKey` parity. Direct
armor remains authoritative; when omitted, the handler can resolve an email via
a bounded HKP index, select the first valid unexpired key, fetch it under the
same response and armor guards, optionally store an encrypted account backup,
and import into GnuPG while returning the legacy `{backup,gnuPG}` booleans.
Focused tests cover PHP-compatible email extraction and HKP record filtering.
Formatting, Clippy with warnings denied, full workspace tests, production-image
build, read-only startup, `/health`, and in-container GnuPG execution passed.
Independent senior review approved this slice.

Implementation commit `00f45c67443cc8202a6e1ffc501c8ae6dc2a3dde` was published
to all four remote tips and live remote checks confirmed identical SHAs.
Exact-SHA GitHub CI passed for that SHA on `master` run
[`32812370738`](https://github.com/ilfrick/frickmail/actions/runs/32812370738)
and `rust-full-migration` run
[`32812373548`](https://github.com/ilfrick/frickmail/actions/runs/32812373548).
This documentation-only amendment records that evidence; those runs remain
authoritative for the implementation.

## Prior Snapshot — 2026-08-25 01:45:00 CEST (UTC+02:00)

The pending OpenPGP slice adds native `PgpSearchKey`, `GetStoredPGPKeys`, and
`StorePGPKey`, and corrects `GetPGPKeys` to merge encrypted account-backup keys
with GnuPG-exported armor as legacy PHP did. New private-key backups use the
existing session credential-key AEAD envelope; public backups remain armored
text. The bounded keyserver lookup is restricted to HTTPS `keys.openpgp.org`.
The production runtime image now includes GnuPG, which the existing native
GnuPG actions require. Focused tests cover encrypted-at-rest storage, private
round-trip classification, and merged legacy key output.

Independent senior review approved the slice after three remediation rounds.
Review confirmed the split `GetPGPKeys`/`GnupgGetKeys` contracts,
GnuPG-unavailable fallback, first-seen global key uniqueness, streamed response
bounds, and strict single-block armor validation. Local validation passed
formatting, workspace Clippy with warnings denied, and all workspace tests;
the final production image was rebuilt after the approved changes for read-only
container startup, `/health`, and in-container GnuPG execution checks before
publication.

Implementation commit `45b4ec31ca0cf29a1aa873b9d3b1317cbf468ddf` was published
to `master` and `rust-full-migration` on both remotes, with live remote tips
verified identical. Exact-SHA GitHub CI passed for that SHA on `master` run
[`32791357229`](https://github.com/ilfrick/frickmail/actions/runs/32791357229)
and `rust-full-migration` run
[`32791361772`](https://github.com/ilfrick/frickmail/actions/runs/32791361772).
This snapshot records that evidence; it intentionally does not alter runtime
code, so those runs remain authoritative for the implementation.

The completed prior slice adds native bundled-plugin backup and restore for
`JsonAdminBackupData` and `JsonAdminRestoreData`, preserving the legacy JSON
response shapes while introducing an explicit Rust admin trust boundary. Both
actions are disabled unless operators configure an Argon2 PHC token hash with
`FRICKMAIL__ADMIN__TOKEN_HASH`; requests must present
`x-frickmail-admin-token`. Backup also requires an absolute
`FRICKMAIL__PRIVATE_DATA_DIR`, which in the compatibility deployment maps to the
existing `/var/lib/snappymail` volume.

The native implementation bounds archives to 256 MiB, uploads to 192 MiB,
entries to 20,000, and work to 120 seconds. It excludes the legacy cache
directory and symlinks, rejects symlinked roots or source paths, uses protected
temporary files, and restores only ZIP entries whose paths remain inside the
configured private-data root. Unlike PHP client-supplied MIME typing, restore
validates the actual ZIP container. That prior image intentionally did not add
GnuPG; the current pending OpenPGP slice changes that runtime dependency.

Commit `188c7cda232bef69e18c6c22f6757dd47d464ae3` is published to `master` and
`rust-full-migration` on both remotes. Live `git ls-remote` checks verified all
four tips resolve to that exact SHA. Local validation passed `cargo fmt --all
-- --check`, `cargo clippy --workspace --all-targets -D warnings`, and full
workspace tests. Exact-SHA GitHub `rust-ci` passed for `master` run
[`32784318378`](https://github.com/ilfrick/frickmail/actions/runs/32784318378)
and `rust-full-migration` run
[`32784321185`](https://github.com/ilfrick/frickmail/actions/runs/32784321185);
both runs included production image build and hardened health smoke validation.

The prior approved-and-published SearchFilters settings-CRUD slice remains
recorded by commit `25479444ee1123ab3f7d0e2617f33b8c66e45c2c`; its exact-SHA
GitHub CI runs `32763194987` (`master`) and `32763194553`
(`rust-full-migration`) passed on both branches.

## Previous Snapshot — 2026-08-24 17:30:00 CEST (UTC+02:00)

The pending slice adds native, opt-in `ChangePassword`. It preserves the legacy
minimum length, strength scoring, optional HIBP check, and error codes; verifies
the current login password; atomically rotates the user password/KDF salt and
every encrypted mail-account password/OAuth refresh token; cycles the session ID;
and removes the stale credential key. Configuration defaults keep the feature
disabled for compatibility with deployments where the legacy plugin is disabled.
HIBP unavailability returns an explicit server error rather than being treated as
a breached or safe password. Unlike legacy PDO/LDAP drivers, this implementation
changes only the native Frickmail account database and does not provision external
directory/database backends, so inventory parity remains partial-native pending a
generic driver decision.

The independent senior review initially blocked the slice on external-driver
parity disclosure, HIBP failure semantics, malformed-salt robustness, SQLite-only
tests, and missing documentation. Required remediation is complete: native-account
scope and intentional HIBP hardening are documented, malformed KDF salt length now
fails safely with a no-rotation regression test, and the action inventory records
partial-native status plus the PDO/LDAP migration boundary. Closing approval is
awaiting re-review of this remediated diff.

Docker-only validation passed after remediation: `cargo fmt --all -- --check`,
`cargo check --workspace`, `cargo clippy --workspace --all-targets -D warnings`,
and `cargo test --workspace` (610 tests total across crates). Production-image
validation built `frickmail-rust:change-password-test` at image ID
`sha256:e8f561072eeacbf5fd13f8eab3a2b727ac07f20faea302284251c55858a74e25`. The
hardened read-only container started without a database, `/health` returned
`ok`, logs showed only expected startup messages, and it stopped cleanly.

After operator publication approval, commit `f93151520b28dcc642c112a38a1437e3b
56ff072` was pushed to `master` and `rust-full-migration` on both `origin`
(GitHub) and `gitea`. Live `git ls-remote` checks verified all four remote tips
resolve to that exact SHA. Exact-SHA GitHub `rust-ci` passed for `master` run
[`32715077552`](https://github.com/ilfrick/frickmail/actions/runs/32715077552)
and `rust-full-migration` run
[`32715080095`](https://github.com/ilfrick/frickmail/actions/runs/32715080095),
including Docker workspace gates and production-image smoke tests. This slice
is now published and verified; only the nonblocking Node.js 20 deprecation
warning was reported by both runs.

### Current Branch And Publication State

Commit `8c05206afda3e00cbfca63635eadf36f225fcd7e` is now published to `master`
and `rust-full-migration` on both `origin` (GitHub) and `gitea`; live
`git ls-remote` checks confirmed all four tips. Exact-SHA GitHub `rust-ci`
passed for `master` run
[`32745096943`](https://github.com/ilfrick/frickmail/actions/runs/32745096943)
and `rust-full-migration` run
[`32745101444`](https://github.com/ilfrick/frickmail/actions/runs/32745101444),
including Docker workspace gates and production-image smoke tests. Only the
known nonblocking Node.js 20 deprecation annotation was reported.

The prior snapshot's completed state remains recorded by commit history:
OpenPGP compose/keyring slice `73c6a429a`, scheduler-test remediation
`af34de649`, and exact-SHA CI runs `32649569879` / `32649569883` passed on both
branches. See git history for that auditable publication record.

### Required Per-Slice Workflow

Every migration slice must record a timestamped update in this file and follow:
implementation, independent senior review, remediation and re-review, Docker
production-image/container/log validation, intentional commit, explicit push of
the same SHA to `master` and `rust-full-migration` on both remotes, then
remote-tip and applicable exact-SHA CI verification. The timestamp, reviewed
scope, image ID (or explicit applicability rationale for non-runtime slices),
commit, remote tips, and CI result are added here before the slice is considered
complete. Publication is not complete until the applicable GitHub Actions run is
polled to a terminal result. On failure, retrieve the failing job logs, reproduce
or diagnose locally, apply a focused correction, revalidate, publish a new SHA,
and repeat CI monitoring until success or an operator decision is required.

### Still Missing Before The Final Rust-Only Goal

The Rust service is usable as a guarded canary for the native routes, but is not
yet a safe drop-in replacement for the PHP production container. The major
remaining gates are:

1. Complete server-side OpenPGP/GnuPG keyring signing/encryption. Client-
   provided OpenPGP MIME, selected-account S/MIME signing/encryption, and
   bounded direct client-supplied S/MIME certificate/private-key signing are
   native.
2. Finish exact legacy action and response parity, then migrate every request
   still dependent on the PHP compatibility bridge.
3. Complete the Rust-only connection-token/CSRF/session contract and port or
   retire outstanding plugin, admin, domain, and settings hooks.
4. Replace the Knockout/SnappyMail frontend and bundle path with the Frickmail
   UI and complete the Frickmail-only theme transition.
5. Validate schema upgrades, deployment rollback, restarts, multi-instance
   sessions, observability, and the full real-service acceptance matrix before
   removing PHP-FPM, nginx, supervisor, MailSo, and SnappyMail/RainLoop.

The production Rust Dockerfile, Compose service, deployment guide, healthcheck,
and canary workflow already exist. Operators should continue to use the canary
procedure in `docs/DEPLOYMENT.md`; promoting the Rust service as the sole
production container remains intentionally blocked by the gates above. This
snapshot is a high-level summary; `docs/DEPLOYMENT.md` is the authoritative,
exhaustive readiness and cutover checklist.

The PHP backend and legacy JavaScript application are temporary compatibility
layers only. They must shrink continuously until no production request depends
on PHP, nginx, PHP-FPM, supervisor, Knockout screens, legacy bundle generation,
or SnappyMail/RainLoop runtime paths.

## Migration Definition Of Done

The migration is complete only when all of these are true:

1. A single Rust runtime owns the production listener, routing, sessions, API,
   static assets, metrics, health checks, and graceful shutdown.
2. No production request is proxied to PHP or handled by the legacy plugin host.
3. The legacy SnappyMail/RainLoop PHP backend, admin controller, plugin runtime,
   theme loader, IMAP/SMTP/MIME wrappers, cache providers, and bootstrap code are
   removed from the production image.
4. The Frickmail UI no longer depends on the legacy Knockout/SnappyMail app
   bundle, except for deliberately archived migration references.
5. Existing databases remain supported. The migration must not replace MySQL,
   PostgreSQL, or SQLite with a custom database.
6. Existing installed SnappyMail plugins remain operational through the Rust
   compatibility contract, a native Rust/WASM port, or an explicitly approved
   deprecation. No enabled plugin may silently stop working at cutover.
7. User-facing product names, Docker metadata, runtime paths, docs, legal pages,
   and public APIs use Frickmail terminology.
8. The only theming system is the Frickmail-user/Frickmail theme model.
9. Docker-only validation, senior Rust review, and GitHub CI pass for every
   merged slice.

## Current System

Frickmail currently combines these layers:

| Area | Current implementation | Rust target |
| --- | --- | --- |
| HTTP entrypoint | nginx + PHP-FPM | `fm-http` Axum server |
| App bootstrap | legacy PHP index/bootstrap | Rust boot/config/runtime |
| Sessions | PHP sessions plus webmail cookie | `fm-session` with Redis or existing DB persistence |
| Existing DB access | PHP PDO helpers | `fm-db`/SQLx using existing DB backends |
| User auth | Frickmail plugin PHP | `fm-user`/`fm-core` |
| Credential crypto | PHP sodium/Argon2id | `fm-core` compatible crypto |
| IMAP core | MailSo/PHP legacy stack | `fm-imap` native async boundary |
| SMTP send | PHP mail bridge and Graph helper | `fm-smtp` native send |
| MIME parse/build | MailSo/PHP libraries | `fm-mime` parse, sanitize, build |
| Contacts/calendar/tasks/rules/search | Frickmail plugins plus legacy hooks | Rust service modules |
| OIDC/Gmail/O365 OAuth | PHP plugin hooks and callback pages | `fm-oidc` plus provider modules |
| Microsoft Graph mailbox | Frickmail JS/PHP plugin calls | Rust Graph client and API |
| S/MIME/OpenPGP/import/export | PHP plugin/core features | Rust crypto and import/export services |
| Plugin system | `RainLoop\Plugins\AbstractPlugin` and JSON/part hooks | Rust compatibility ABI/API |
| Admin/settings/domain config | legacy admin screens and config files | Rust admin API and Frickmail UI |
| Frontend | legacy Knockout/SnappyMail app plus plugins | Frickmail UI consuming Rust APIs |
| Theming | legacy theme loader plus Frickmail theme plugins | Frickmail-user theming only |
| Packaging | PHP/nginx/supervisor container | multi-stage Rust release image |

## Scope

### In Scope

1. All Frickmail-owned plugin endpoints and UI features.
2. All legacy SnappyMail/RainLoop PHP backend request handlers still used by the
   app, including JSON endpoints, admin endpoints, static bootstrap, plugin
   dispatch, and remote/part hooks.
3. The legacy webmail core required for normal mailbox use: domains, folders,
   message lists, message body, compose, send, reply/forward, attachments,
   flags, move/delete, search, filters, identities, contacts, calendars,
   import/export, notifications, and security settings.
4. The plugin compatibility surface for existing SnappyMail plugins: manifests,
   settings, JSON hooks, part hooks, asset injection, permissions, storage, and
   lifecycle behavior. PHP source execution is allowed only during the bridge
   phase; final compatibility is behavior/API compatibility through Rust-native
   implementations, WASM plugins, generated adapters, or approved deprecation.
5. Frickmail naming cleanup in production paths, public docs, container metadata,
   user-visible strings, generated assets, and legal text.
6. Legacy theme removal and Frickmail-user theme consolidation.
7. CI/CD, Docker development, smoke containers, and release packaging.

### Explicit Non-Goals

1. Do not write a custom database engine.
2. Do not force users to migrate away from their existing MySQL, PostgreSQL, or
   SQLite-compatible deployment mode.
3. Do not remove compatibility for an installed/enabled plugin without a
   validated native/WASM migration path, conformance tests, and operator
   approval.
4. Do not break existing account credentials or encrypted user data.

## Strategy

The migration uses a controlled strangler pattern, but the target is the entire
legacy application, not just the Frickmail-user plugin:

1. Rust owns the listener and compatibility dispatcher.
2. Each legacy JSON/part route is inventoried and classified as native,
   bridged, deprecated, or replaced.
3. Rust implementations are added in small, reviewed slices.
4. The PHP bridge is allowed only while a specific production route is not yet
   native.
5. Legacy UI screens are replaced screen-by-screen after their Rust APIs are
   stable.
6. Legacy themes, bundle generation, PHP plugins, nginx/PHP-FPM, and upstream
   names are deleted only after their replacement path is active.

## Frickmail-User Usable Release Gate

Before continuing from the Frickmail-user migration into the broader legacy
SnappyMail/RainLoop runtime rewrite, ship a usable partial Rust version and
pause for operator input.

This gate is reached when the Frickmail-owned user surface is native and usable:

1. Login, registration, password reset, TOTP, preferences, account management,
   account switching, identities, OAuth token persistence, search, unified
   inbox, notifications, tasks, rules, S/MIME metadata, and retained
   Frickmail-user settings are implemented or explicitly deferred with a known
   fallback.
2. The partial build is available as a tested branch/tag or image that can be
   deployed without changing the existing database backend.
3. Docker-only tests, Docker build, temporary container startup, log check,
   senior Rust review, and GitHub CI pass for that release candidate.
4. Release notes list remaining PHP bridge dependencies and any user-visible
   limitations.
5. Work pauses after publishing the usable Frickmail-user release candidate.
   Continue into the full legacy SnappyMail/RainLoop runtime migration only
   after explicit user/operator approval.

## Naming Policy

Frickmail is a complete rewrite, not a forked runtime. The migration rules are:

| Rule | Decision |
| --- | --- |
| Public product name | `Frickmail` only |
| Rust crates | `fm-*` and `frickmail-server` |
| Public Docker image | `frickmail` |
| Runtime data path | Existing configured data path during migration; `/var/lib/frickmail` only after cutover |
| Session cookie | `FrickmailSession` |
| New API routes | `/api/frickmail/*` plus temporary compatibility dispatcher |
| Legacy names | Allowed only inside compatibility shims, archived legal attribution, or migration notes until deleted |

Do not add new user-facing references to old upstream product names. Existing
legacy identifiers may remain internally only where compatibility requires them,
and each remaining reference must have an owner and removal phase.

## Repository State

The Rust workspace currently lives under:

```text
frickmail-server/
  Cargo.toml
  crates/
    frickmail-server/  # binary
    fm-core/           # config, errors, shared API/session types
    fm-db/             # existing database connection adapter
    fm-http/           # Axum router and compatibility dispatcher
    fm-imap/           # IMAP boundary
    fm-mime/           # MIME boundary
    fm-oidc/           # OIDC/PKCE boundary
    fm-plugin-compat/  # compatibility contract for current plugin hooks
    fm-session/        # session layer
    fm-smtp/           # SMTP boundary
    fm-user/           # users, accounts, preferences, Frickmail features
```

All Rust compilation and tests must run through the Docker dev service:

```bash
docker compose -f docker-compose.rust.yml run --rm rust-dev cargo check --workspace
docker compose -f docker-compose.rust.yml run --rm rust-dev cargo test --workspace
docker compose -f docker-compose.rust.yml run --rm rust-dev cargo clippy --workspace -- -D warnings
```

Do not use host Rust tooling for validation.

## Phase 0 - Complete Legacy Inventory

Goal: know every runtime surface that must be migrated, replaced, or removed.

Deliverables:

1. Generated inventory of all legacy PHP route handlers, JSON hooks, part hooks,
   admin endpoints, upload/download endpoints, static bootstrap routes, and
   plugin actions.
2. Generated inventory of all frontend calls into legacy APIs.
3. Generated inventory of all `SnappyMail`, `RainLoop`, `snappymail`, and
   `rainloop` references, classified as remove, replace, compatibility-only, or
   legal attribution.
4. Generated inventory of legacy theme entry points and bundle generation paths.
5. Migration dashboard showing native, bridged, deprecated, and deleted items.

Exit criteria:

1. Every production route is represented in the inventory.
2. Every remaining PHP dependency has an owner, replacement strategy, and phase.
3. The inventory is checked in and kept current by CI.

## Phase 1 - Rust Foundation

Goal: Rust can boot, serve health/static routes, read configuration, and connect
to the existing deployment services.

Deliverables:

1. Rust workspace and crate boundaries.
2. Docker Rust development image and compose service.
3. Axum server with health/version endpoints.
4. Typed config loaded from `FRICKMAIL__*` environment variables.
5. Existing database adapter supporting current DB backends.
6. Session abstraction with Redis or existing-DB persistence.
7. CI-compatible commands for `fmt`, `check`, `test`, `clippy`, Docker build,
   temporary container startup, and log verification.

Exit criteria:

1. Docker `cargo check --workspace` passes.
2. Docker `cargo test --workspace` passes.
3. Docker `cargo clippy --workspace -- -D warnings` passes.
4. Docker build plus temporary container log check passes.

## Phase 2 - Compatibility Router And PHP Bridge Containment

Goal: Rust owns the production listener and all requests pass through Rust.

Deliverables:

1. Compatibility JSON dispatcher for current plugin `_action` calls.
2. Compatibility part-hook dispatcher.
3. Temporary PHP bridge for routes not yet native.
4. SSRF-safe bridge target validation and request-size limits.
5. Golden-response tests comparing bridge and Rust behavior during migration.
6. Route-level metrics showing all PHP bridge hits.

Exit criteria:

1. New native endpoints can be enabled without changing the frontend.
2. PHP bridge usage is observable per route/action.
3. Unknown or double-prefixed plugin actions fail safely.

## Phase 3 - Users, Sessions, Accounts, And Crypto

Goal: Rust owns Frickmail identity and account metadata.

Deliverables:

1. Password login with Argon2id verification against existing data.
2. Per-user credential key derivation.
3. Compatible credential encryption/decryption.
4. Registration, password reset, TOTP, preferences, and session rotation.
5. Account add/update/delete/list/switch/set-primary.
6. Identity add/update/delete/default.
7. Gmail/O365 token persistence and account relinking.

Exit criteria:

1. Existing users can log in and decrypt existing account credentials.
2. Account switching no longer depends on PHP session state.
3. Credential mutation has reviewer-approved tests.

## Phase 4 - Legacy Admin, Domain, Settings, And Config Runtime

Goal: replace the legacy admin panel backend and runtime configuration system.

Deliverables:

1. Rust admin authentication and authorization.
2. Domain configuration management for IMAP/SMTP/Sieve/service discovery.
3. Admin settings currently stored in legacy config files or plugin settings.
4. Backup/restore of Frickmail configuration and user-relevant data.
5. Audit-safe admin APIs and CSRF/session protection.
6. UI replacement for required admin screens.

Exit criteria:

1. Production admin tasks no longer require the legacy PHP admin controller.
2. Runtime config writes are transactional and tested across supported DB modes
   or config stores.

## Phase 5 - OIDC, OAuth, SSO, And Part Hooks

Goal: Rust owns all sign-in flows and external-login hooks.

Deliverables:

1. OIDC discovery, PKCE, callback rendering, link/unlink, and escrow-key recovery.
2. Gmail OAuth with PKCE.
3. O365 OAuth with PKCE, tenant handling, and Graph token refresh.
4. Remote auto-login, cPanel auto-login, proxy auth, external login, external
   SSO, and user-header set compatibility.
5. Popup callback pages preserving current browser behavior.

Exit criteria:

1. All login/SSO part hooks are native Rust or explicitly deprecated with a
   replacement.
2. No login flow requires PHP.

## Phase 6 - IMAP Webmail Core

Goal: Rust replaces the MailSo/PHP mailbox runtime.

Deliverables:

1. Login probe and capability discovery.
2. Folder list, create, rename, delete, subscribe, unsubscribe, and select.
3. Message list with paging, threading where supported, sort, flags, dates,
   sizes, previews, and cache invalidation.
4. Message body fetch with MIME structure, inline images, attachments, safe HTML
   sanitization, and plain-text fallback.
5. Mark read/unread, flag/star, move, copy, delete, expunge, archive, and spam
   actions. The legacy `MessageSetSeen`, `MessageSetFlagged`,
   `MessageSetDeleted`, `MessageCopy`, `MessageMove`, and `MessageDelete`
   routes are now native for the selected IMAP account.
6. IMAP search, server-side search fallback, and indexed search integration.
7. Attachment download and raw message download.
8. Connection pooling, timeout policy, backoff, and per-account isolation.

Exit criteria:

1. Normal inbox usage, message reading, and message operations work without PHP.
2. Unified inbox uses live IMAP flags or persisted flag indexing, not only a
   snapshot fallback.
3. IMAP tests cover injection-resistant command construction and failure modes.

## Phase 7 - SMTP, Compose, MIME, And Import/Export

Goal: Rust sends and imports mail without PHP.

Deliverables:

1. Compose API for draft data, recipients, attachments, reply, reply-all, and
   forward.
2. MIME builder for text, HTML, inline content, attachments, and correct headers.
3. SMTP send for password accounts.
4. OAuth SMTP or provider send for Gmail/O365 where required.
5. Save-to-sent through IMAP append.
6. EML import, message export, folder export, and raw source export.
7. S/MIME sign, verify, public certificate import, PKCS#12 import, and secure key
   storage.

Exit criteria:

1. Sending and import/export features work without PHP.
2. MIME parsing/building has golden fixtures for common real-world messages.

## Phase 8 - Frickmail Features And Legacy Plugin Compatibility

Goal: Rust replaces Frickmail plugins and provides a compatibility path for
existing SnappyMail plugins.

Deliverables:

1. Unified inbox with live or indexed flag parity.
2. Full-text search and message index maintenance.
3. Rules engine and filter application.
4. Tasks.
5. Contacts sync, contact dedupe, add/edit/delete, and suggestions.
6. Calendar list/events/save/delete.
7. Push notifications and VAPID key rotation.
8. Microsoft Graph mailbox operations: list, search, delta, get, mark-read,
   move, and delete.
9. Nextcloud save/attach compatibility.
10. Avatar/BIMI/favicon/gravatar lookup with SSRF-safe HTTP.
11. HIBP and security plugin replacements where retained.
12. Rust plugin compatibility host covering manifests, settings schemas,
    JSON hooks, part hooks, static assets, template injection, permission
    declarations, lifecycle callbacks, plugin storage, and error envelopes.
13. Plugin conformance harness that can replay captured legacy hook requests and
    assert Rust/native/WASM plugin responses.
14. Plugin migration report classifying every installed or bundled plugin as
    native Rust, WASM/native adapter, core feature replacement, bridge-only
    temporary, or approved deprecation.
15. Porting guide and adapter templates for plugin authors.

Exit criteria:

1. All production plugin hooks are native, deprecated, or implemented through the
   Rust compatibility layer.
2. Every installed/enabled plugin in the target deployment has a passing
   conformance result or an operator-approved deprecation record.
3. No PHP plugin is loaded in the production container.

## Phase 9 - Frontend Rewrite

Goal: replace the legacy Knockout/SnappyMail frontend with a Frickmail UI.

Deliverables:

1. Stable Rust-owned API under `/api/frickmail`.
2. New login, account, settings, mailbox, compose, search, unified inbox, tasks,
   contacts, calendar, S/MIME, OIDC, and admin screens.
3. Service worker and offline cache updated for Frickmail APIs.
4. Accessibility, mobile, keyboard navigation, and localization pass.
5. Removal of legacy bundle generation, legacy view models, and compatibility UI
   shims after each screen is replaced.

Exit criteria:

1. The app can run without the legacy `dev/` Knockout application.
2. Compatibility dispatcher remains only for external plugin compatibility, not
   for Frickmail-owned UI screens.

## Phase 10 - Theming Simplification

Goal: remove the legacy theme system and keep only Frickmail-user theming.

Deliverables:

1. Inventory all theme entry points currently exposed to users/admins.
2. Preserve Frickmail user theme preferences.
3. Remove legacy theme selection UI, legacy theme package loading, and legacy
   CSS fetch routes.
4. Keep a migration fallback so existing users land on the Frickmail theme.
5. Add tests or snapshots for Frickmail theme settings and CSS variables.

Exit criteria:

1. No production code path loads a legacy SnappyMail/RainLoop theme package.
2. Frickmail theme settings are the only user/admin theming surface.

## Phase 11 - Naming, Legal, And Integration Cleanup

Goal: remove old product references from production surfaces while retaining
only required attribution.

Deliverables:

1. Replace user-facing SnappyMail/RainLoop names in docs, legal pages, Docker,
   fail2ban, integrations, generated assets, and UI strings.
2. Rename production services, volumes, image names, labels, comments, examples,
   and env vars to Frickmail.
3. Keep legally required upstream attribution in a clearly scoped attribution
   section until the corresponding legacy code is removed.
4. Remove or archive obsolete integrations that cannot be made Frickmail-native.

Exit criteria:

1. A main-tree scan for legacy names has only approved compatibility or legal
   attribution hits.
2. Production packaging exposes only Frickmail names.

## Phase 12 - Final Rust Runtime Image

Goal: ship one Rust production image.

Deliverables:

1. Multi-stage Rust release Dockerfile.
2. Runtime path moved to `/var/lib/frickmail` after data migration is validated.
3. `/metrics` endpoint replaces PHP exporter.
4. Healthcheck uses `/health`.
5. Graceful shutdown and structured logging.
6. No PHP-FPM, nginx, supervisor, PHP bridge, or PHP plugin host.
7. Existing DB backend support retained.
8. Upgrade/migration scripts for existing deployments.

Exit criteria:

1. Production container starts, serves, logs, and shuts down without PHP.
2. End-to-end smoke tests pass against the release image.
3. CI publishes or verifies the release image.

## Phase 13 - Removal And Archival

Goal: delete dead legacy code safely.

Deliverables:

1. Remove legacy PHP backend files no longer used by production.
2. Remove legacy Knockout app files after the Frickmail UI replacement is active.
3. Remove old themes and generated bundles.
4. Archive required attribution, migration notes, and compatibility docs.
5. Lock CI so legacy runtime reintroduction fails.

Exit criteria:

1. No production build artifact contains the legacy runtime.
2. CI prevents new SnappyMail/RainLoop user-facing references unless explicitly
   allowlisted.

## Review Gate

Before each commit, a Senior Rust reviewer agent must inspect the staged diff.
The reviewer profile:

```text
Senior Rust developer with 15+ years of systems and backend experience.
Focus: correctness, async safety, security boundaries, compile-time guarantees,
data migration risk, API compatibility, plugin compatibility, Docker-only
verification, and removal of legacy user-facing naming.
Default stance: block merges for unsafe credential handling, unbounded blocking
inside async paths, missing tests for migrated endpoints, DB compatibility
breakage, plugin compatibility regressions, or user-facing naming regressions.
```

## Required Verification Loop

Every migration slice must follow this loop:

1. Modify.
2. Senior Rust reviewer agent review.
3. Fix every actionable reviewer finding and repeat independent review until
   the slice is approved.
4. Run Docker-only `fmt`, `check`, `test`, and `clippy`.
5. Build the production Docker image, start a temporary test container, exercise
   its health and relevant HTTP paths, and inspect its state and logs for
   startup/runtime errors, OOM events, and restarts.
6. Fix every issue found by Docker validation, then return to step 2 and repeat
   review and verification.
7. Refresh the timestamped progress snapshot near the top of this file before
   the final commit. Preserve the same structure used by the 2026-08-11
   snapshot and record:
   - completed and already pushed commits since the preceding snapshot;
   - the current approved/verified slice as pending in the same commit, without
     falsely claiming it was pushed before remote verification;
   - rejected or uncommitted work separately, including unresolved review
     findings;
   - the major remaining gates toward the final Rust-only goal;
   - exact test/lint results and Docker evidence; and
   - auditable image provenance using an immutable digest plus revision tag or
     OCI revision label when available.
8. Have the senior reviewer inspect the final staged diff, including the
   refreshed snapshot, and fix/re-review any documentation findings.
9. Commit once and, under the operator's explicit dual-branch publication
   policy, push the identical commit to `master` and `rust-full-migration` on
   `origin` (GitHub) and `gitea`. Changing this publication policy requires a
   new operator instruction.
10. Use live `git ls-remote` checks against `origin` and `gitea` to verify all
   four branch tips resolve to that commit, and record the returned SHAs. Confirm
   every applicable CI check passes. When path filters legitimately produce no
   GitHub Actions run (for example, a documentation-only change), explicitly
   record the expected no-run instead of claiming CI success. On the next
   snapshot, move the prior pending slice into the completed-and-pushed section
   with its commit ID.
11. At the Frickmail-user usable release gate, publish the release candidate and
   ask for user/operator input before starting the next migration phase.

The progress snapshot is a concise operational summary, not a replacement for
the detailed route inventory or release checklist. Keep
`docs/LEGACY_ACTION_INVENTORY.md` authoritative for action parity and
`docs/DEPLOYMENT.md` authoritative for production readiness and cutover.

## Immediate Next Work

1. Maintain the production Rust Dockerfile and Compose service now, ahead of
   final cutover, so every migration slice can be exercised in the real release
   container. Keep it canary-only until the UI, session/CSRF, schema migration,
   and action-parity gates in `docs/DEPLOYMENT.md` pass.
2. Keep `docs/LEGACY_ACTION_INVENTORY.md` current as the route/hook/frontend
   source of truth for each migration slice.
3. Complete native parity for legacy `Message` and the remaining mail actions.
   `MessageList`, `FolderInformation`, and `FolderInformationMultiply` dispatch
   are native; `Message` remains partial-native while exact PHP message-model
   parity is completed.
4. Add Docker MySQL/PostgreSQL/SQLite integration tests for existing schema
   compatibility.
5. Inventory the legacy theme loader and plan deletion in favor of Frickmail-user
   theming.
6. Add CI allowlists for temporary legacy names so naming cleanup is measurable.
7. Track the Frickmail-user usable release gate and do not continue into full
   legacy runtime removal until that release is available and operator input is
   received.
