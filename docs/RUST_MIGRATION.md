# Frickmail Full Rust Migration Plan

This is the active plan for rewriting the entire Frickmail codebase in Rust.
It covers the Frickmail user features, the legacy SnappyMail/RainLoop runtime,
the legacy PHP plugin host, the webmail core, the admin/settings surface, the
frontend, theming, integrations, packaging, and the final production container.

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
   actions.
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
3. Fix reviewer findings.
4. Docker-only `fmt`, `check`, `test`, and `clippy`.
5. Docker build.
6. Temporary test container startup and log check.
7. Commit and push to both configured remotes.
8. Confirm GitHub Actions passes.
9. At the Frickmail-user usable release gate, publish the release candidate and
   ask for user/operator input before starting the next migration phase.

## Immediate Next Work

1. Generate and commit the complete legacy route/hook/frontend-call inventory.
2. Complete native mailbox account switching: wire the selected account into
   native folder/message routes, then change `FrickmailBridgeSession` and
   `FrickmailSwitchAccount` from the current safe pending response to real
   success without PHP session state.
3. Add native coverage for `FrickmailApplyRules`, import/export, and remaining
   S/MIME actions.
4. Add the missing Microsoft Graph mailbox actions to the compatibility
   inventory and begin native Graph implementation.
5. Add Docker MySQL/PostgreSQL/SQLite integration tests for existing schema
   compatibility.
6. Inventory the legacy theme loader and plan deletion in favor of Frickmail-user
   theming.
7. Add CI allowlists for temporary legacy names so naming cleanup is measurable.
8. Track the Frickmail-user usable release gate and do not continue into full
   legacy runtime removal until that release is available and operator input is
   received.
