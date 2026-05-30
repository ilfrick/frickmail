# Frickmail Rust Migration Plan

This document is the active migration plan for the full Frickmail rewrite.
The PHP backend is now treated only as a temporary compatibility bridge while
Rust endpoints are implemented and verified. New code, documentation, package
metadata, Docker image names, runtime paths, and public API names must use
Frickmail terminology.

## Current System

Frickmail currently ships as a PHP-FPM plus nginx image with a Knockout-based
web UI and Frickmail plugins layered on top. The main Frickmail-owned backend
surface is the plugin API:

| Area | Current implementation | Rust target |
| --- | --- | --- |
| HTTP routing and static files | PHP/nginx | `fm-http` with Axum |
| Sessions | PHP sessions plus webmail cookie | `fm-session` |
| User/account data | Existing configured DB connection | `fm-db` adapter |
| Password and credential crypto | PHP sodium/Argon2id | `fm-core` crypto module |
| IMAP account access | PHP mail bridge | `fm-imap` |
| SMTP send | PHP mail bridge and Graph helper | `fm-smtp` |
| MIME parse/build | PHP mail libraries | `fm-mime` |
| OIDC/PKCE | Frickmail plugin | `fm-oidc` |
| Gmail/O365 OAuth | Frickmail plugins | provider modules under `fm-oidc` |
| Calendar/contacts/tasks/rules/search | Frickmail plugins | Rust JSON endpoints |
| S/MIME and notifications | Frickmail plugin | Rust service modules |
| UI | KnockoutJS | keep initially, then replace screen by screen |
| Theming | Legacy theme system plus Frickmail user theme plugin | Frickmail-user theming only |

## Optimized Strategy

The previous plan started with generic crate discovery and delayed Frickmail
endpoint migration. That leaves too much risk in the largest unknowns. The
optimized plan starts from the real product boundary: Frickmail-owned JSON and
part hooks. Every migrated endpoint must keep the current response shape until
the UI is rewritten.

The migration uses a strangler pattern:

1. Build the Rust server in parallel.
2. Route implemented Frickmail endpoints to Rust.
3. Proxy only unimplemented endpoints to the temporary PHP bridge.
4. Keep current plugin hooks compatible until their Rust equivalents are live.
5. Remove PHP bridge code once all production endpoint families are in Rust.
6. Rename or delete remaining legacy paths only after they are no longer used.

## Naming Policy

Frickmail is a complete rewrite, not a forked runtime. The migration rules are:

| Rule | Decision |
| --- | --- |
| Public product name | `Frickmail` only |
| Rust crates | `fm-*` and `frickmail-server` |
| Public Docker image | `frickmail` |
| Runtime data path | Existing configured data path during migration; `/var/lib/frickmail` only after cutover |
| Session cookie | `FrickmailSession` |
| New API routes | `/api/frickmail/*` plus compatibility JSON dispatcher |
| Legacy names | Allowed only inside temporary compatibility paths until deleted |

Do not add new user-facing references to old upstream product names. Existing
plugin API identifiers and path fragments may remain internally where required
for compatibility, but new Rust modules must wrap them in Frickmail-named
abstractions and schedule them for removal.

## Repository State

The migration starts with a Rust workspace:

```text
frickmail-server/
  Cargo.toml
  crates/
    frickmail-server/  # binary
    fm-core/           # config, errors, shared API/session types
    fm-db/             # existing database connection adapter
    fm-http/           # Axum router
    fm-imap/           # IMAP boundary
    fm-mime/           # MIME boundary
    fm-oidc/           # OIDC/PKCE boundary
    fm-plugin-compat/  # compatibility contract for current plugin hooks
    fm-session/        # session layer
    fm-smtp/           # SMTP boundary
```

All Rust compilation and tests must run through the Docker dev service:

```bash
docker compose -f docker-compose.rust.yml run --rm rust-dev cargo check --workspace
docker compose -f docker-compose.rust.yml run --rm rust-dev cargo test --workspace
docker compose -f docker-compose.rust.yml run --rm rust-dev cargo clippy --workspace -- -D warnings
```

Do not use host Rust tooling for validation.

## Phase 1 - Rust Foundation

Status: started.

Deliverables:

1. Rust workspace and crate boundaries.
2. Docker Rust development image and compose service.
3. Axum server with health/version endpoints.
4. Typed config loaded from `FRICKMAIL__*` environment variables.
5. Frickmail session layer.
6. Existing-database adapter that supports the current configured DB backend.
7. Compatibility inventory for existing Frickmail plugin hooks.
8. CI-compatible commands for `check`, `test`, and `clippy`.

Exit criteria:

1. `cargo check --workspace` passes in the Docker dev container.
2. `cargo test --workspace` passes in the Docker dev container.
3. `cargo clippy --workspace -- -D warnings` passes in the Docker dev container.

Non-production limits in this phase:

1. Session storage is in-memory until Redis or existing-DB persistence lands.
2. The PHP bridge URL is declared but not active yet.
3. Existing-DB integration is compile-checked only until Docker DB matrix tests land.

## Phase 2 - Compatibility Router

Goal: Rust owns the listening port and routes all Frickmail URLs.

Deliverables:

1. Static file serving under Frickmail-owned routes.
2. Compatibility JSON dispatcher for current `_action` calls.
3. Temporary proxy to PHP for endpoints not yet ported.
4. Endpoint inventory generated from plugin hooks and frontend calls.
5. Plugin compatibility layer for existing Frickmail plugins.
6. Golden-response tests comparing Rust and bridge responses where the bridge
   still exists.

Priority endpoints:

1. `FrickmailMe`
2. `FrickmailLogin`
3. `FrickmailBridgeSession`
4. `FrickmailListAccounts`
5. `FrickmailSwitchAccount`
6. `FrickmailGetPrefs`
7. `FrickmailSetPrefs`

## Phase 3 - Users, Sessions, And Crypto

Goal: Rust owns Frickmail identity.

Deliverables:

1. Password login with Argon2id verification against the existing database.
2. Per-user encryption key derivation.
3. Credential encryption and decryption compatible with existing data.
4. Session storage backed by Redis or the existing configured database.
5. Account switching without PHP.
6. Password reset endpoints.
7. TOTP endpoints.

Risk: credential encryption compatibility is security-critical. The reviewer
must inspect this phase before merge.

## Phase 4 - Accounts And Service Discovery

Goal: Rust manages all account records and connection settings.

Deliverables:

1. Add/update/delete/list account endpoints.
2. Primary account selection.
3. Service discovery with SSRF protection.
4. Gmail and O365 token persistence.
5. Identity management endpoints.

## Phase 5 - OIDC And OAuth Providers

Goal: Rust owns all OAuth/OIDC redirects and callback rendering.

Deliverables:

1. OIDC discovery and PKCE flow.
2. Link/unlink OIDC identity.
3. Escrow-key recovery for passwordless SSO.
4. Gmail OAuth with PKCE.
5. O365 OAuth with PKCE and tenant handling.
6. Popup callback page that preserves current UI behavior.

## Phase 6 - IMAP Core

Goal: Rust can authenticate and read mail without the PHP bridge.

Deliverables:

1. Login probe.
2. Folder list and select.
3. Message list.
4. Message body fetch.
5. Flags, delete, move.
6. Search.
7. Attachment fetch.
8. Connection pooling.

Implementation note: use the smallest IMAP feature set required by the UI
first. Add extension support only when a current Frickmail endpoint needs it.

## Phase 7 - SMTP And MIME

Goal: Rust sends and renders mail.

Deliverables:

1. MIME parsing and sanitization.
2. MIME building with attachments and inline content.
3. SMTP send for password accounts.
4. OAuth SMTP send for Gmail/O365 when supported.
5. Save-to-sent through IMAP append.

## Phase 8 - Frickmail Features And Plugin Compatibility

Goal: Rust replaces all Frickmail plugin modules while preserving compatibility
for current plugin hooks until each hook is ported.

Deliverables:

1. Unified inbox.
2. Full-text search and message index.
3. Rules engine.
4. Tasks.
5. Calendar.
6. Contacts sync.
7. Push notifications.
8. Import/export.
9. S/MIME.
10. Graph mailbox support for O365.
11. Compatibility shim for current JSON and part hooks.

## Phase 9 - Theming Simplification

Goal: remove the legacy theme system and keep only Frickmail-user-controlled
theming.

Deliverables:

1. Inventory all theme entry points currently exposed to users/admins.
2. Preserve Frickmail user theme preferences.
3. Remove legacy theme selection UI.
4. Remove legacy theme package loading after the new Frickmail UI is active.
5. Keep a migration fallback so existing users land on the Frickmail theme.
6. Add tests or snapshots for the Frickmail user theme settings path.

## Phase 10 - Frontend Rewrite

Goal: remove the legacy UI dependency.

Deliverables:

1. Stabilize a Rust-owned JSON API under `/api/frickmail`.
2. Build new Frickmail UI screens incrementally.
3. Keep compatibility dispatcher only for screens not yet rewritten.
4. Remove legacy bundle generation once all screens are migrated.

## Phase 11 - Final Runtime Image

Goal: ship one Frickmail Rust binary.

Deliverables:

1. Multi-stage Rust release Dockerfile.
2. Runtime path moved to `/var/lib/frickmail` only after data migration is validated.
3. `/metrics` endpoint replaces PHP exporter.
4. Healthcheck uses `/health`.
5. Graceful shutdown.
6. No PHP-FPM, nginx, or supervisor.
7. No temporary compatibility bridge.
8. Existing DB backend support retained; no forced database switch.

## Review Gate

Before each commit, a Senior Rust reviewer agent must inspect the staged diff.
The reviewer profile:

```text
Senior Rust developer with 15+ years of systems and backend experience.
Focus: correctness, async safety, security boundaries, compile-time guarantees,
data migration risk, API compatibility, and Docker-only verification.
Default stance: block merges for unsafe credential handling, unbounded blocking
inside async paths, missing tests for migrated endpoints, or user-facing naming
regressions.
```

## Immediate Next Work

1. Add endpoint inventory generation.
2. Implement the compatibility JSON dispatcher.
3. Port `FrickmailMe`, `FrickmailLogin`, and `FrickmailListAccounts`.
4. Add existing-DB integration tests for MySQL, PostgreSQL, and SQLite in Docker where supported by the current deployment mode.
5. Add route tests for health/version and JSON error shape.
6. Inventory legacy theme entry points and route them to Frickmail-user theming.
