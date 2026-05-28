# Frickmail → Rust: Complete Migration Plan

## Scope & Scale Reality Check

| Subsystem | Current | Lines | Rust replacement |
|---|---|---|---|
| HTTP + routing | PHP-FPM + nginx | ~9 | Axum |
| IMAP client | MailSo/Imap (PHP) | 16,170 | async-imap + imap-proto |
| SMTP client | MailSo/Smtp | ~1,200 | lettre |
| MIME parser | MailSo/Mime | ~3,000 | stalwart mail-parser |
| Sieve | MailSo/Sieve | ~600 | sieve-rs (stalwartlabs) |
| OIDC/OAuth2 | login-oidc plugin (PHP+JS) | ~800 | openidconnect crate |
| Session/cookie | RainLoop (PHP) | ~500 | tower-sessions |
| Database | PDO/Postgres | ~200 | sqlx |
| Cache | Redis (PHP ext) | ~100 | deadpool-redis |
| Plugin system | RainLoop/Plugins | ~300 | Rust trait objects |
| CalDAV/CardDAV | Sabre (PHP) | ~4,000 | custom or vdirsyncer bridge |
| Frontend SPA | KnockoutJS (25k LOC) | 25,027 | **keep as-is** (pragmatic) |
| Service worker | sw.js | 167 | keep as-is |
| Tauri shell | tauri.conf.json | ~60 | already Rust — minimal changes |

**Estimated effort**: 12–18 months of focused engineering. The IMAP client is the critical path and hardest piece.

---

## Phase 0 — Documentation Discovery

> Deploy one subagent per subsystem. Do not proceed to Phase 1 until the "Allowed APIs" list is finalized.

### 0A — Axum + tower-sessions (HTTP layer)

**Agent task**: Read the following and extract concrete API signatures:
- `axum` 0.8 routing docs: `Router::new()`, `axum::extract::*`, middleware via `tower::ServiceBuilder`
- `tower-sessions` README and examples: `SessionManagerLayer`, `Session::insert/get`, backend choices (`MemoryStore`, `RedisStore`)
- `axum-extra` cookie jar: `CookieJar`, `Cookie::build()`

**Report must include**: exact `Cargo.toml` dependency version, concrete route + handler signatures, session backend choices

### 0B — async-imap + imap-proto (IMAP client)

**Agent task**: Read:
- `async-imap` crate docs (docs.rs/async-imap) — especially `Client::connect`, `Session::select`, `Session::fetch`, `Session::uid_search`, `Session::idle`
- `imap-proto` crate — response types, how to parse server responses
- Check if `async-imap` supports: IMAP IDLE, CONDSTORE, QRESYNC, NAMESPACE, MOVE, LITERAL+

**Report must note gaps** vs MailSo's feature set (checked via `ls snappymail/v/0.0.0/app/libraries/MailSo/Imap/Commands/`)

### 0C — stalwart mail crates (MIME + Sieve)

**Agent task**: Read:
- `mail-parser` crate (stalwartlabs/mail-parser): `MessageParser::new().parse()`, MIME part access, attachment extraction, header parsing
- `mail-builder` crate: `MessageBuilder`, attachment/inline embedding
- `sieve-rs` crate: `Sieve::compile()`, `Runtime::filter()` — confirm ManageSieve protocol support

### 0D — lettre (SMTP)

**Agent task**: Read:
- `lettre` docs: `AsyncSmtpTransport`, `TlsParameters`, `Message::builder()`, OAuth2 SASL (XOAUTH2 / OAUTHBEARER)
- Confirm: STARTTLS, SMTPS, connection pooling, DKIM signing support

### 0E — openidconnect + oauth2 crates (OIDC/PKCE)

**Agent task**: Read:
- `openidconnect` crate: `CoreClient`, `CoreAuthorizationCode`, PKCE: `PkceCodeChallenge::new_random_sha256()`, `exchange_code()`
- How to: store PKCE verifier in session between redirect and callback, validate ID token, extract claims
- Confirm `DiscoveryDocument` / `ProviderMetadata` for Authentik compatibility

### 0F — sqlx + deadpool-redis (data layer)

**Agent task**: Read:
- `sqlx` 0.8: `PgPool::connect()`, `query!` / `query_as!` macros, `sqlx::migrate!()`, transaction API
- `deadpool-redis`: `Pool::get()`, async command execution
- Note: sqlx requires `DATABASE_URL` at compile time for checked queries; plan for offline mode

### 0G — Existing PHP schema and API surface

**Agent task** (local file read only):
- Read `plugins/login-oidc/index.php` — extract all JSON hook names, their request/response shapes
- Read `plugins/frickmail-user/index.php` — extract all JSON hooks
- Read any SQL in `plugins/` or `snappymail/` — extract table schemas (grep for `CREATE TABLE`)
- List all `?Json/…&_action=X` endpoints by grepping `RainLoop/Actions/`

**Output**: A table of all API endpoints + request/response shapes the JS frontend currently uses

---

## Phase 1 — Rust Workspace Scaffold

**What to implement**: Create a new `frickmail-server/` Rust workspace alongside the existing PHP code. The PHP backend stays running in production throughout the migration; the Rust server runs in parallel.

**Context from Phase 0**: Use the exact crate versions from 0A–0F.

### 1.1 — Workspace layout

```
frickmail-server/
  Cargo.toml          # workspace root
  crates/
    fm-http/          # Axum router, middleware
    fm-imap/          # async-imap client pool
    fm-smtp/          # lettre SMTP
    fm-mime/          # stalwart mail-parser wrappers
    fm-oidc/          # OIDC/PKCE flow
    fm-db/            # sqlx pool + migrations
    fm-session/       # tower-sessions integration
    fm-core/          # shared types (error, config, auth token)
```

### 1.2 — Cargo.toml dependencies

Copy from the "Allowed APIs" list produced in Phase 0. Pin exact versions. Include:
```toml
axum = { version = "0.8", features = ["macros"] }
tokio = { version = "1", features = ["full"] }
tower = { version = "0.5" }
tower-http = { version = "0.6", features = ["fs", "compression-gzip", "cors"] }
tower-sessions = { version = "0.14" }
async-imap = { version = "..." }
imap-proto = { version = "..." }
lettre = { version = "0.11", features = ["tokio1", "smtp-transport", "pool"] }
mail-parser = { version = "0.9" }
mail-builder = { version = "0.3" }
openidconnect = { version = "3" }
sqlx = { version = "0.8", features = ["postgres", "runtime-tokio-rustls", "migrate"] }
deadpool-redis = { version = "0.18" }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
thiserror = "2"
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }
config = "0.15"   # layered config from env vars
```

### 1.3 — Config struct

```rust
// fm-core/src/config.rs
#[derive(serde::Deserialize)]
pub struct Config {
    pub database_url: String,
    pub redis_url: String,
    pub base_url: String,
    pub imap_host: String,
    pub imap_port: u16,
    pub oidc_issuer: String,
    pub oidc_client_id: String,
    pub oidc_client_secret: Option<String>,  // None = PKCE only
    pub smtp_host: String,
    pub smtp_port: u16,
    pub smtp_user: String,
    pub smtp_password: String,
}
```

Load from environment via `config` crate — mirrors the existing `.env` / docker-compose env vars.

### 1.4 — Verification

- `cargo build` compiles clean
- `cargo test` passes (empty tests)
- `cargo clippy -- -D warnings` passes

**Anti-patterns**: Do not import `rocket`, `warp`, or `actix-web` — this plan standardizes on `axum`. Do not use `std::sync::Mutex` for shared state — use `tokio::sync::RwLock` or `Arc<DashMap>`.

---

## Phase 2 — HTTP Layer & Static File Serving

**What to implement** (from Phase 0A axum docs): The main Axum router that serves:
1. Static files under `/snappymail/v/0.0.0/static/` → `tower-http::ServeDir`
2. The SPA shell at `GET /` → return the existing `index.php`-equivalent HTML (initially: reverse-proxy to PHP)
3. JSON API routes: `POST /?Json` (initially: reverse-proxy to PHP)
4. The OIDC callback route: `GET /?LoginOIDC` (Phase 4 will implement; stub 404 for now)

### 2.1 — Router structure

```rust
// fm-http/src/router.rs
// Copy this pattern from axum 0.8 docs (Router::nest, axum::routing::get/post)
pub fn build_router(state: Arc<AppState>) -> Router {
    Router::new()
        .nest_service("/snappymail", ServeDir::new("snappymail"))
        .route("/", get(shell_handler).post(json_api_handler))
        .route("/sw.js", get(sw_handler))
        // Phase 4: .route("/?LoginOIDC", get(oidc_callback_handler))
        .layer(
            ServiceBuilder::new()
                .layer(session_layer)          // Phase 3
                .layer(CompressionLayer::new())
                .layer(TraceLayer::new_for_http())
        )
        .with_state(state)
}
```

### 2.2 — Reverse proxy shim

While PHP backend is still running (port 8888), the Rust server runs on 8889. Proxy unimplemented routes to PHP using `hyper` client. This allows incremental feature cutover without a big-bang switch.

```rust
async fn proxy_to_php(req: Request) -> impl IntoResponse {
    // Forward request to http://localhost:8888 with original headers
    // hyper::Client or reqwest
}
```

### 2.3 — Verification

- `curl http://localhost:8889/snappymail/v/0.0.0/static/images/logo.svg` returns the file
- `curl http://localhost:8889/` proxies to PHP and returns the login page
- Static file headers include `Cache-Control: max-age=31536000, immutable`

---

## Phase 3 — Session & Auth Cookie

**What to implement** (from Phase 0A tower-sessions docs):

SnappyMail sets a `MailSession` cookie via `Cookies::setSecure()`. The Rust layer must:
1. Issue the same cookie name/shape after successful IMAP login
2. Decode the existing cookie format (or replace with a new Rust-native session)

### 3.1 — Session layer

```rust
// fm-session/src/lib.rs
// Pattern from tower-sessions docs: RedisStore + SessionManagerLayer
use tower_sessions::{RedisStore, SessionManagerLayer};
use tower_sessions::cookie::SameSite;

pub fn session_layer(redis_pool: Pool) -> SessionManagerLayer<RedisStore> {
    let store = RedisStore::new(redis_pool);
    SessionManagerLayer::new(store)
        .with_name("MailSession")
        .with_same_site(SameSite::Lax)   // Lax (not Strict) needed for OIDC redirect
        .with_secure(true)
        .with_http_only(true)
}
```

**Note**: The existing PHP sets `SameSite=Strict`. Changing to `Lax` is required for OIDC cross-site redirect to attach the session cookie.

### 3.2 — Auth token struct

```rust
// fm-core/src/auth.rs
#[derive(serde::Serialize, serde::Deserialize)]
pub struct AuthToken {
    pub account_id: i64,
    pub email: String,
    pub imap_host: String,
    pub imap_port: u16,
    pub imap_password_encrypted: String,  // AES-256-GCM with per-install key
}
```

### 3.3 — Login handler (password auth)

```rust
// POST / with action=Login: extract email + password,
// call fm-imap::probe_login(host, port, email, password),
// on success: insert AuthToken into session, return JSON { "Result": true }
```

### 3.4 — Verification

- POST login with valid IMAP credentials → session cookie set → subsequent request has session
- POST login with wrong password → `{ "Result": false, "ErrorCode": 403 }`

---

## Phase 4 — OIDC/PKCE Flow (login-oidc replacement)

**What to implement** (from Phase 0E openidconnect docs): This replaces `plugins/login-oidc/index.php` entirely in Rust.

### 4.1 — OIDC client initialization

```rust
// fm-oidc/src/client.rs
// Pattern: openidconnect::CoreClient::from_provider_metadata()
// Fetch ProviderMetadata from {oidc_issuer}/.well-known/openid-configuration at startup
// Store in Arc<OidcClient> in AppState
```

### 4.2 — Start OIDC login: `GET /?StartLoginOIDC`

```rust
// 1. PkceCodeChallenge::new_random_sha256() → (challenge, verifier)
// 2. Build authorization URL with scopes: openid, email, profile
// 3. Store verifier + state + mode ("login"|"link") in session
// 4. Return 302 redirect to Authentik
```

### 4.3 — OIDC callback: `GET /?LoginOIDC&code=X&state=Y`

```rust
// 1. Retrieve verifier from session
// 2. client.exchange_code(code).set_pkce_verifier(verifier).request_async()
// 3. Validate ID token → extract email claim
// 4. bridge(): IMAP login with fetched credential or SSO token
// 5. renderCallback(): return popup HTML with inline JS
```

### 4.4 — renderCallback() Rust equivalent

```rust
// fm-oidc/src/callback.rs
pub fn render_callback(ok: bool, email: &str, error: &str, mode: &str, reauth_required: bool) -> Html<String> {
    let payload = serde_json::json!({
        "type": "frickmail-oidc",
        "status": if ok { "ok" } else { "error" },
        "mode": mode,
        "email": email,
        "error": error,
        "reauth_required": reauth_required,
    });
    // Inline JS: localStorage.setItem, window.opener.location.reload(),
    // BroadcastChannel, postMessage, setTimeout(window.close, 200)
    Html(format!(r#"<!doctype html>...{payload}...</html>"#))
}
```

### 4.5 — Account linking endpoints

JSON handlers:
- `FrickmailListOidcLinks` → query `oidc_links` table
- `FrickmailUnlinkOidc` → delete from `oidc_links`
- `FrickmailBridgeSession` → re-try IMAP bridge (for `reauth_required` path)

### 4.6 — Postgres schema (migration 001)

```sql
CREATE TABLE oidc_links (
    id           BIGSERIAL PRIMARY KEY,
    account_id   BIGINT NOT NULL,
    provider_hash TEXT NOT NULL,
    email        TEXT NOT NULL,
    linked_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(account_id, provider_hash)
);
```

### 4.7 — Verification

- Full OIDC login flow in browser: popup opens → Authentik → callback → `window.opener.location.reload()` fires → inbox loads
- `frickmail-oidc-result` localStorage key is cleared after delivery
- Account link/unlink works from Settings tab

---

## Phase 5 — IMAP Client (critical path)

**What to implement** (from Phase 0B async-imap docs): This is the largest and hardest phase. MailSo/Imap is 16,170 lines implementing every IMAP extension. The Rust crate `async-imap` provides a lower-level foundation.

**Strategy**: Implement only the operations the frontend actually calls (from Phase 0G API surface survey), not the full MailSo feature set.

### 5.1 — Connection pool

```rust
// fm-imap/src/pool.rs
// Use deadpool pattern: Pool<ImapManager>
// ImapManager implements deadpool::managed::Manager
// Each connection: TcpStream → TLS → async_imap::Client → Session (after LOGIN)
pub struct ImapPool {
    inner: deadpool::managed::Pool<ImapManager>,
}
```

### 5.2 — Core operations (implement in priority order)

| Priority | Operation | async-imap API |
|---|---|---|
| 1 | Probe login | `Client::connect` + `login()` |
| 2 | List folders | `Session::list("", "*")` |
| 3 | Select folder + fetch count | `Session::select(mailbox)` |
| 4 | Fetch message list | `Session::uid_fetch(seq, "(FLAGS ENVELOPE)")` |
| 5 | Fetch message body | `Session::uid_fetch(uid, "BODY[]")` |
| 6 | Set flags (read/unread/starred) | `Session::uid_store(uid, "+FLAGS (\\Seen)")` |
| 7 | Move message | `Session::uid_mv(uid, dest)` — requires IMAP MOVE ext |
| 8 | Delete message | `Session::uid_store` + EXPUNGE |
| 9 | Search messages | `Session::uid_search("SUBJECT x FROM y")` |
| 10 | IDLE (push notifications) | `Session::idle()` |

### 5.3 — IMAP extension gap analysis (from Phase 0B findings)

If `async-imap` doesn't support an extension natively, implement via raw `Session::run_command_and_read_response()`. Document each workaround.

Extensions needed:
- `IMAP4rev2` or `IMAP4rev1` — both crates support
- `MOVE` — check; fallback: COPY + UID STORE \Deleted + EXPUNGE
- `CONDSTORE` / `QRESYNC` — for efficient sync; fallback: re-fetch
- `NAMESPACE` — for multi-account; may need raw command
- `LITERAL+` / `LITERAL-` — for large uploads; check support

### 5.4 — Error mapping

```rust
#[derive(thiserror::Error, Debug)]
pub enum ImapError {
    #[error("auth failed")] AuthFailed,
    #[error("connection refused")] ConnectionRefused,
    #[error("tls error: {0}")] Tls(#[from] native_tls::Error),
    #[error("protocol error: {0}")] Protocol(String),
}
```

Map to existing JSON error codes the frontend expects (from Phase 0G).

### 5.5 — Verification

- `cargo test -p fm-imap` with a test IMAP server (Greenmail or Dovecot in Docker)
- Round-trip: connect → list folders → select INBOX → fetch 10 messages → disconnect
- Connection pool recycles connections correctly (no auth storm on rapid requests)

### 5.6 — Pragmatic shortcut

Consider keeping MailSo as a microservice (PHP → JSON API) called by the Rust server for IMAP operations only. This halves Phase 5's scope and lets the rest of the migration proceed faster, with a full IMAP rewrite deferred to Phase 5B.

---

## Phase 6 — SMTP Client

**What to implement** (from Phase 0D lettre docs):

### 6.1 — Transport setup

```rust
// fm-smtp/src/lib.rs
// Pattern from lettre docs: AsyncSmtpTransport::<Tokio1Executor>::starttls_relay()
pub async fn build_transport(config: &SmtpConfig) -> AsyncSmtpTransport<Tokio1Executor> {
    AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&config.host)
        .unwrap()
        .port(config.port)
        .credentials(Credentials::new(config.user.clone(), config.password.clone()))
        .pool_config(PoolConfig::new().max_size(10))
        .build()
}
```

### 6.2 — Send handler: `POST /?Json&_action=SendMessage`

```rust
// 1. Deserialize request: to[], cc[], subject, html_body, attachments[]
// 2. Build Message with mail-builder (Phase 7.2)
// 3. transport.send(message).await
// 4. If config.save_to_sent: append to IMAP Sent folder via fm-imap
// 5. Return { "Result": true } or error
```

### 6.3 — OAuth2 SMTP (Gmail / O365)

Use `lettre`'s `OAuth2Credentials` if it supports XOAUTH2/OAUTHBEARER (verify in Phase 0D). If not, implement a custom `Mechanism` trait impl following the `lettre` extension guide.

### 6.4 — Verification

- Send to a test mailbox (Mailtrap or local Mailhog in Docker Compose)
- Attachments render correctly in Gmail/Outlook
- Reply-To header propagated correctly

---

## Phase 7 — MIME Parser & Message Rendering

**What to implement** (from Phase 0C stalwart mail-parser):

### 7.1 — Parse incoming messages

```rust
// fm-mime/src/parse.rs
use mail_parser::MessageParser;

pub fn parse_message(raw: &[u8]) -> ParsedMessage {
    let msg = MessageParser::default().parse(raw).unwrap();
    ParsedMessage {
        subject: msg.subject().unwrap_or("").to_string(),
        from: extract_addresses(msg.from()),
        to: extract_addresses(msg.to()),
        date: msg.date().map(|d| d.to_rfc3339()),
        html_body: msg.body_html(0).map(|b| sanitize_html(b)),
        text_body: msg.body_text(0).map(|t| t.to_string()),
        attachments: extract_attachments(&msg),
    }
}
```

### 7.2 — Build outgoing messages

```rust
// fm-mime/src/build.rs
use mail_builder::MessageBuilder;

pub fn build_message(params: &SendParams) -> Vec<u8> {
    let mut builder = MessageBuilder::new()
        .from(params.from.clone())
        .to(params.to.clone())
        .subject(&params.subject)
        .html_body(&params.html_body);
    for att in &params.attachments {
        builder = builder.attachment(att.content_type.clone(), &att.filename, att.data.clone());
    }
    builder.write_to_vec().unwrap()
}
```

### 7.3 — HTML sanitization

Use `ammonia` crate (`ammonia::clean()`) to strip XSS from incoming HTML bodies. Mirror SnappyMail's existing sanitization rules (check `snappymail/v/0.0.0/app/libraries/snappymail/` HTML sanitizer).

### 7.4 — Verification

- Parse a multipart/alternative email with inline image and PDF attachment → all parts extracted correctly
- Build a message with attachment → RFC 5322 valid output (validated with `mail-parser` round-trip)

---

## Phase 8 — Database Layer & Migrations

**What to implement** (from Phase 0F sqlx docs):

### 8.1 — Pool initialization

```rust
// fm-db/src/lib.rs
pub async fn create_pool(database_url: &str) -> PgPool {
    PgPool::connect(database_url).await.expect("DB connect failed")
}
```

### 8.2 — Migration files

```
fm-db/migrations/
  0001_oidc_links.sql          # Phase 4.6 schema
  0002_sessions.sql            # if storing sessions in DB instead of Redis
  0003_accounts.sql            # user accounts table (if replacing PHP file-based storage)
  0004_push_subscriptions.sql  # Web Push subscriptions (existing feature)
```

Run via `sqlx::migrate!()` at server startup.

### 8.3 — Query patterns

Use `sqlx::query!` macros (compile-time checked). Requires `DATABASE_URL` env var at build time — set in `.cargo/config.toml` for dev, CI secret for CI builds. For offline development, generate `sqlx-data.json` via `cargo sqlx prepare`.

### 8.4 — Existing Postgres data

The current Postgres schema is managed by PHP; inspect it before writing migrations:
```bash
docker exec -it frickmail-db-1 psql -U frickmail -c '\dt'
```
Write `0000_existing_schema.sql` to document what already exists before adding new migrations.

---

## Phase 9 — Plugin System Replacement

**What to implement**: Replace the PHP `addJsonHook` / `addPartHook` plugin API with Rust trait objects.

### 9.1 — Plugin trait

```rust
// fm-core/src/plugin.rs
#[async_trait::async_trait]
pub trait FrickmailPlugin: Send + Sync {
    fn name(&self) -> &'static str;
    // JSON API hooks
    async fn handle_json(&self, action: &str, payload: serde_json::Value, ctx: &RequestCtx)
        -> Option<serde_json::Value>;
    // Part hooks (raw HTTP handlers for custom URL routes)
    async fn handle_part(&self, part: &str, ctx: &RequestCtx)
        -> Option<axum::response::Response>;
    // Plugin settings (replaces pluginSettingsGet on the JS side)
    fn settings(&self) -> serde_json::Value { serde_json::Value::Null }
}
```

### 9.2 — Plugin registry

```rust
// fm-core/src/plugin_registry.rs
pub struct PluginRegistry {
    plugins: Vec<Box<dyn FrickmailPlugin>>,
}
impl PluginRegistry {
    pub fn register(&mut self, p: impl FrickmailPlugin + 'static) { ... }
    pub async fn dispatch_json(&self, action: &str, payload: Value, ctx: &RequestCtx) -> Option<Value> { ... }
}
```

### 9.3 — frickmail-user plugin (Rust)

Implement as a `FrickmailPlugin` struct. Port:
- User preferences API (profile, password change)
- Admin branding settings
- Recovery email flow
- Custom login form injection → becomes server-side HTML template rendering

### 9.4 — frickmail-theme

CSS only — copy to `static/` directory. No Rust code needed. Remove from plugin system.

---

## Phase 10 — Frontend Adaptation (minimal changes)

**Strategy**: Keep the existing KnockoutJS SPA. Only adjust the JS that touches PHP-specific quirks.

### 10.1 — JSON API contract verification

From Phase 0G API surface: for each `_action=X` endpoint the JS calls, verify the Rust implementation returns identically-shaped JSON. Any shape mismatch causes silent UI breakage.

Write a regression test suite:
```bash
# For each known action, compare PHP response vs Rust response:
diff <(curl http://localhost:8888/?Json&_action=Folders) \
     <(curl http://localhost:8889/?Json&_action=Folders)
```

### 10.2 — LoginOIDC.js

No changes needed — `window.opener.location.reload()` pattern works regardless of backend language.

### 10.3 — Service worker (sw.js)

No changes — copy from `.docker/release/files/snappymail/sw.js` to new Rust server's static directory.

### 10.4 — Plugin JS loading

The JS side calls `rl.pluginSettingsGet('login-oidc', 'provider_name')`. This is loaded via `/?/Plugins/0/User/…` URL. The Rust server must serve the same URL pattern, returning a JS file that includes `window.rl.pluginSettingsData = {...}`.

Implement a route:
```
GET /?/Plugins/0/User/{hash}/
```
that returns concatenated plugin JS files with settings injected, matching the current PHP behavior.

---

## Phase 11 — Docker & Deployment

**What to implement**: Replace the `nginx + php-fpm + supervisor` stack with a single Rust binary.

### 11.1 — Multi-stage Dockerfile

```dockerfile
# Build stage
FROM rust:1.80-slim AS builder
WORKDIR /build
COPY frickmail-server/ .
RUN cargo build --release

# Runtime stage
FROM gcr.io/distroless/cc-debian12
COPY --from=builder /build/target/release/frickmail-server /usr/local/bin/
COPY snappymail/v/0.0.0/static/ /static/
COPY .docker/release/files/snappymail/sw.js /static/
EXPOSE 8888
CMD ["/usr/local/bin/frickmail-server"]
```

### 11.2 — docker-compose changes

Remove `php-fpm-exporter` (replace with Rust `/metrics` endpoint using `metrics-exporter-prometheus`). Remove the `supervisor.conf` volume mount. Update `healthcheck` URL.

### 11.3 — Signals and graceful shutdown

```rust
// In main(): listen for SIGTERM/SIGINT via tokio::signal
// Give active requests 30s to complete before exit
axum::serve(listener, app)
    .with_graceful_shutdown(shutdown_signal())
    .await?;
```

---

## Phase 12 — Tauri Desktop App

**Changes**: Minimal. The Tauri app (`tauri/`) already wraps a webview pointed at `http://localhost:8888`. It stays the same.

The only change: the Rust server binary can be **embedded** in the Tauri app (spawn as a sidecar). Update `tauri.conf.json`:
```json
"bundle": {
  "externalBin": ["../frickmail-server/target/release/frickmail-server"]
}
```
This makes the Tauri desktop app self-contained with no external PHP/nginx dependency.

---

## Phase 13 — Integration Testing & Cutover

### 13.1 — End-to-end test suite

Using `playwright` or `cargo-nextest` + `reqwest`:
- Login (password + OIDC)
- Read inbox, open message, attachment download
- Compose + send (to local Mailhog)
- Search
- Link/unlink OIDC account
- Settings (change display name, signature)

### 13.2 — Data migration

```bash
# Export existing PHP-managed user config (stored as INI files in /var/lib/snappymail)
# Import into Postgres accounts table
# Migrate oidc_links from existing PHP-managed storage
```

### 13.3 — Cutover checklist

- [ ] All Phase 0G API endpoints return identical JSON shapes
- [ ] OIDC login works end-to-end in production environment
- [ ] `SameSite=Lax` cookie is acceptable to security policy
- [ ] Existing Postgres data migrated successfully
- [ ] Push notification subscriptions preserved
- [ ] Fail2ban rules work against new log format
- [ ] Prometheus metrics endpoint replaces `php-fpm-exporter`

---

## Execution Order & Dependencies

```
Phase 0 (discovery) ─────────────────────────────────────────────┐
  └─► Phase 1 (scaffold)                                         │
        └─► Phase 2 (HTTP layer + proxy shim)                    │
              ├─► Phase 3 (session)                              │
              │     ├─► Phase 4 (OIDC) ◄── Phase 0E+0G ─────────┘
              │     └─► Phase 5 (IMAP) ◄── Phase 0B
              │           └─► Phase 6 (SMTP)
              │                 └─► Phase 7 (MIME)
              ├─► Phase 8 (DB) ◄─────────── Phase 0F
              └─► Phase 9 (plugins)
                    └─► Phase 10 (frontend)
                          └─► Phase 11 (Docker)
                                └─► Phase 12 (Tauri)
                                      └─► Phase 13 (cutover)
```

**Critical path**: Phase 5 (IMAP) is the longest and riskiest. Start it in parallel with Phase 3 once Phase 1 is done. If `async-imap` proves insufficient for SnappyMail's IMAP feature set, Phase 0B will have identified this — the fallback is to write a thin Rust wrapper that shells out to a Dovecot IMAP proxy or keeps MailSo as an internal microservice.
