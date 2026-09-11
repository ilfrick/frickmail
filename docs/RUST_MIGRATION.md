# Frickmail Full Rust Migration Plan

This is the active plan for rewriting the entire Frickmail codebase in Rust.
It covers the Frickmail user features, the legacy SnappyMail/RainLoop runtime,
the legacy PHP plugin host, the webmail core, the admin/settings surface, the
frontend, theming, integrations, packaging, and the final production container.

## Progress Snapshot — 2026-09-11 18:30:00 CEST (UTC+02:00)

The v1 rules slice adds `GET /api/frickmail/v1/rules`, reusing the
exact repository query as legacy `FrickmailListRules`. Unlike identities
(empty list), unknown or foreign accounts surface the repository's
`account_not_found` as 404; the `MailRule` shape carries no secrets.
GET-only, so no CSRF check applies. Two tests cover scoped listing plus
unknown/foreign/malformed/anonymous cases.

Independent senior review approved with no actionables (exact error-string
mapping, secret-free shapes, mirrored guards, non-vacuous tests).

Docker-only validation passed: `cargo fmt --all -- --check`,
`cargo clippy --workspace --all-targets -D warnings`, full workspace suites
(fm-http 439 passed, live-DB suites green).
Production-image validation built `frickmail-rust:api-v1-rules-test` at
image ID `sha256:0bb7023207503dcf5d12d0df93de9282abe389ae7ef9fc428f899259837c2a42`;
a read-only container returned 401 for anonymous `/rules`, logs showed
only expected startup messages, and it stopped cleanly.

This slice is verified but NOT yet committed or pushed. The major remaining
gates toward the final Rust-only goal are unchanged.

## Prior Snapshot — 2026-09-11 17:30:00 CEST (UTC+02:00)

The v1 preferences slice adds `GET`+`PUT
/api/frickmail/v1/preferences`, reusing the exact repository queries as
legacy `FrickmailGetPrefs`/`FrickmailSetPrefs` (merged read, schema-driven
patch cleaning: unknown keys dropped, values clamped/coerced). GET is
read-only; PUT requires the connection token. Two tests cover the
authenticated round-trip (patch applies, unknown keys dropped, values
persist) plus anonymous/tokenless rejection.

Independent senior review approved with no actionables (route isolation,
PUT CSRF ordering, patch cleaning parity, response shapes, non-vacuous
tests using a schema-valid key).

Docker-only validation passed: `cargo fmt --all -- --check`,
`cargo clippy --workspace --all-targets -D warnings`, full workspace suites
(fm-http 437 passed, live-DB suites green).
Production-image validation built `frickmail-rust:api-v1-prefs-test` at
image ID `sha256:6ed73d7db801f9f632188a1fdff839b65356a1ac8e7206ae14d4d509510a23c1`;
a read-only container returned 401 for anonymous `/preferences`, logs showed
only expected startup messages, and it stopped cleanly.

Implementation commit `5337b9d690f0a5f1b9cf2924911a8c8c565c2ac4` was
published to `master` and `rust-full-migration` on both remotes; live
`git ls-remote` checks confirmed all four tips resolve to that SHA.
Exact-SHA GitHub `rust-ci` passed for that SHA on `master` run
[`34611004042`](https://github.com/ilfrick/frickmail/actions/runs/34611004042)
and `rust-full-migration` run
[`34611009904`](https://github.com/ilfrick/frickmail/actions/runs/34611009904),
and the `naming` gate passed on both branches
([`34611004072`](https://github.com/ilfrick/frickmail/actions/runs/34611004072),
[`34611009802`](https://github.com/ilfrick/frickmail/actions/runs/34611009802));
all runs reported only the known nonblocking Node.js 20 deprecation
annotation. This closing documentation-only amendment intentionally matches no
CI path filter and is expected to produce no GitHub Actions run. The major
remaining gates toward the final Rust-only goal are unchanged (more v1
mailbox endpoints, frontend screens, theming removal, cutover validation).

## Prior Snapshot — 2026-09-11 16:30:00 CEST (UTC+02:00)

The v1 messages slice adds `GET /api/frickmail/v1/messages`, the
first mailbox endpoint: explicit-or-selected account resolution, scoped
credential lookup, shared request normalization (limit defaults/clamping,
per-user hide-deleted, domain search settings), and IMAP fetch under the
shared deadline, returning the MailSo-compatible list shape inside the v1
envelope. Thread views, receipt-suppression post-processing, HTTP conditional
caching, and the UID cache stay on the legacy dispatcher for now (noted in
module docs). The fetcher is injectable like the legacy pattern, so tests
run without IMAP. Three tests cover the success path (request mapping,
default limit, response shape) plus bad-request/unknown-account/broken-
credential/anonymous cases.

Independent senior review approved with no blockers; one suggested 502
test was added (upstream failures map to `upstream_error` without leaking
storage text).

Docker-only validation passed: `cargo fmt --all -- --check`,
`cargo clippy --workspace --all-targets -D warnings`, full workspace suites
(fm-http 435 passed, live-DB suites green).
Production-image validation built `frickmail-rust:api-v1-messages-test` at
image ID `sha256:3e837ba4dbf03e52fa5cef46af2cd9ca835a419f7b4868e8002676456a219734`;
a read-only container returned 401 for anonymous `/messages`, logs showed
only expected startup messages, and it stopped cleanly.

Implementation commit `3c0864a23a0d1675b3c5f677b76b7e292edbe0b1` was
published to `master` and `rust-full-migration` on both remotes; live
`git ls-remote` checks confirmed all four tips resolve to that SHA.
Exact-SHA GitHub `rust-ci` passed for that SHA on `master` run
[`34607138927`](https://github.com/ilfrick/frickmail/actions/runs/34607138927)
and `rust-full-migration` run
[`34607145251`](https://github.com/ilfrick/frickmail/actions/runs/34607145251),
and the `naming` gate passed on both branches
([`34607139079`](https://github.com/ilfrick/frickmail/actions/runs/34607139079),
[`34607145304`](https://github.com/ilfrick/frickmail/actions/runs/34607145304));
all runs reported only the known nonblocking Node.js 20 deprecation
annotation. This closing documentation-only amendment intentionally matches no
CI path filter and is expected to produce no GitHub Actions run. The major remaining
gates toward the final Rust-only goal are unchanged (more v1 mailbox
endpoints, frontend screens, theming removal, cutover validation).

## Prior Snapshot — 2026-09-11 15:30:00 CEST (UTC+02:00)

The v1 switch-account slice adds `POST /api/frickmail/v1/switch-account`,
reusing legacy ownership checks (user-scoped account lookup), credential-material
validation without network (decryptable password/OAuth token), session
storage, and the account-scoped connection-token refresh (returned as
`csrf_token`, since switched scopes invalidate the previous token).
Authenticated `GET /session` additionally reports `selected_account_id`.
CSRF runs before identity, mirroring the legacy dispatcher. Intentional
deviation: no live IMAP/OAuth probe — v1 separates session selection from
transport health, which surfaces on first mailbox use. Four tests cover the
switch lifecycle, unknown/foreign/broken accounts, and the auth/token gates.

Independent senior review approved with no blockers; one follow-up parity
note (credential-key length check) was applied, propagating session-store
failures to 500s instead of masking them as 401s.

Docker-only validation passed: `cargo fmt --all -- --check`,
`cargo clippy --workspace --all-targets -D warnings`, full workspace suites
(fm-http 432 passed, live-DB suites green).
Production-image validation built `frickmail-rust:api-v1-switch-test` at
image ID `sha256:c00b608bb3b8d9514bd88ca7aaf2818f562df1f7742f1a6651a11ab3ec15c134`;
a read-only container rejected a tokenless switch with 403 `invalid_token`,
logs showed only expected startup messages, and it stopped cleanly.

Implementation commit `2e13b27d17118c89ac4cee64dc414d4b0bcf9884` was
published to `master` and `rust-full-migration` on both remotes; live
`git ls-remote` checks confirmed all four tips resolve to that SHA.
Exact-SHA GitHub `rust-ci` passed for that SHA on `master` run
[`34602049957`](https://github.com/ilfrick/frickmail/actions/runs/34602049957)
and `rust-full-migration` run
[`34602056944`](https://github.com/ilfrick/frickmail/actions/runs/34602056944),
and the `naming` gate passed on both branches
([`34602049767`](https://github.com/ilfrick/frickmail/actions/runs/34602049767),
[`34602056910`](https://github.com/ilfrick/frickmail/actions/runs/34602056910));
all runs reported only the known nonblocking Node.js 20 deprecation
annotation. This closing documentation-only amendment intentionally matches no
CI path filter and is expected to produce no GitHub Actions run. The major remaining
gates toward the final Rust-only goal are unchanged (v1 mailbox endpoints,
frontend screens, theming removal, cutover validation).

## Prior Snapshot — 2026-09-11 14:30:00 CEST (UTC+02:00)

The v1 identities slice adds `GET /api/frickmail/v1/identities`,
reusing the exact repository query as legacy `FrickmailListIdentities`.
Scoping is strict (`user_id` plus required positive `account_id`, mirroring
legacy): foreign accounts yield an empty list, never foreign rows; the
`MailIdentity` shape carries no secrets. Missing/non-numeric/non-positive
ids are 400s. Two tests cover scoped listing, cross-user isolation plus
input validation and anonymous rejection.

Independent senior review approved with no actionables (IDOR safety,
secret-free shapes, auth/DB guards, and test rigor all verified).

Docker-only validation passed: `cargo fmt --all -- --check`,
`cargo clippy --workspace --all-targets -D warnings`, full workspace suites
(fm-http 429 passed, live-DB suites green).
Production-image validation built `frickmail-rust:api-v1-identities-test` at
image ID `sha256:01d52cfc0143b68d576ac6eda5bc7dcb61b45814eb95943ca730d567f647a91d`;
a read-only container returned 401 for anonymous `/identities` (with and
without `account_id`), logs showed only expected startup messages, and it
stopped cleanly.

Implementation commit `c1c779edf39a7843f7a6c435ef801a34d68d590c` was
published to `master` and `rust-full-migration` on both remotes; live
`git ls-remote` checks confirmed all four tips resolve to that SHA.
Exact-SHA GitHub `rust-ci` passed for that SHA on `master` run
[`34598042210`](https://github.com/ilfrick/frickmail/actions/runs/34598042210)
and `rust-full-migration` run
[`34598048519`](https://github.com/ilfrick/frickmail/actions/runs/34598048519),
and the `naming` gate passed on both branches
([`34598042175`](https://github.com/ilfrick/frickmail/actions/runs/34598042175),
[`34598048531`](https://github.com/ilfrick/frickmail/actions/runs/34598048531));
all runs reported only the known nonblocking Node.js 20 deprecation
annotation. This closing documentation-only amendment intentionally matches no
CI path filter and is expected to produce no GitHub Actions run. The major remaining
gates toward the final Rust-only goal are unchanged (v1 mailbox endpoints,
frontend screens, theming removal, cutover validation).

## Prior Snapshot — 2026-09-11 13:30:00 CEST (UTC+02:00)

The v1 accounts slice adds `GET /api/frickmail/v1/accounts`,
reusing the exact `list_mail_accounts` repository query as legacy
`FrickmailListAccounts` (safe metadata plus inline identities; secrets live
in the never-serialized `MailAccountConnectionSecret` type). GET-only, so no
CSRF check applies. Two tests cover the authenticated listing (shape,
identities, serialized secret-absence) through a real login, plus anonymous
401s.

Independent senior review approved with no actionables (secret-free shapes
verified at the struct, query, and serialization levels; auth paths and
test rigor confirmed).

Docker-only validation passed: `cargo fmt --all -- --check`,
`cargo clippy --workspace --all-targets -D warnings`, full workspace suites
(fm-http 427 passed, live-DB suites green).
Production-image validation built `frickmail-rust:api-v1-accounts-test` at
image ID `sha256:148bd71ab1bc53af9b4e24883f4d0784f058ce74c74c21b60878522eea536e91`;
a read-only container returned 401 for anonymous `/accounts`, logs showed
only expected startup messages, and it stopped cleanly.

Implementation commit `529d5c70a30378a88921878c306dcf3882372caf` was
published to `master` and `rust-full-migration` on both remotes; live
`git ls-remote` checks confirmed all four tips resolve to that SHA.
Exact-SHA GitHub `rust-ci` passed for that SHA on `master` run
[`34594294486`](https://github.com/ilfrick/frickmail/actions/runs/34594294486)
and `rust-full-migration` run
[`34594298275`](https://github.com/ilfrick/frickmail/actions/runs/34594298275),
and the `naming` gate passed on both branches
([`34594294685`](https://github.com/ilfrick/frickmail/actions/runs/34594294685),
[`34594298426`](https://github.com/ilfrick/frickmail/actions/runs/34594298426));
all runs reported only the known nonblocking Node.js 20 deprecation
annotation. This closing documentation-only amendment intentionally matches no
CI path filter and is expected to produce no GitHub Actions run. The major remaining
gates toward the final Rust-only goal are unchanged (v1 mailbox endpoints,
frontend screens, theming removal, cutover validation).

## Prior Snapshot — 2026-09-11 12:30:00 CEST (UTC+02:00)

The v1 login slice adds `POST /api/frickmail/v1/login` through a
shared authentication core extracted from legacy `FrickmailLogin`
(`native_login_authenticate` + `native_login_establish_session`: dummy-hash
no-enumeration, TOTP gating with replay protection, credential-key
derivation, session rotation with rollback — legacy responses byte-identical
per the untouched login tests). v1 maps outcomes to the versioned envelope
(200 authenticated user, 200 `requires_totp`, 401 `invalid_credentials`,
503 without a database) with no mail-account bridge probing by design.
Anonymous `GET /session` now bootstraps and returns the `csrf_token`
(legacy AppData parity) so login always requires the `X-SM-Token` header
when CSRF is enabled; DB/session failures return generic 500s with server
logs instead of storage internals. Ten v1 tests cover bootstrap, the full
login→session lifecycle, identical unknown/wrong-password rejection, TOTP
gating plus valid-code success with replay rejection, and CSRF enforcement —
delivering the deferred authenticated-`GET /session` coverage too.

Independent senior review first blocked on three security findings (login
CSRF fail-open pre-bootstrap, ignored `csrf_enabled` flag, storage error
details in 500 bodies) plus five hardening notes; all were remediated
(anonymous `GET /session` bootstraps and returns the `csrf_token`, login
always requires it when CSRF is enabled, generic 500s with server logs,
redacted credential-key `Debug`, corrected 405 message, documented
header-only/strict-typing deviations, TOTP success+replay test) and the
closing re-review approved with no blockers.

Docker-only validation passed: `cargo fmt --all -- --check`,
`cargo clippy --workspace --all-targets -D warnings`, full workspace suites
(fm-http 425 passed including 10 v1 tests, live-DB suites green).
Production-image validation built `frickmail-rust:api-v1-login-test` at
image ID `sha256:010ac5487dc85282fb87ba61d8111a15dc0b18b62881037fd7cde54f02bbaa88`;
a read-only container verified the live contract (anonymous session
bootstrap with `csrf_token`, login without a database → 503 envelope),
logs showed only expected startup messages, and it stopped cleanly.

Implementation commit `7757e07c655a764b40dc5f1ff7796e4d2582ca66` was
published to `master` and `rust-full-migration` on both remotes; live
`git ls-remote` checks confirmed all four tips resolve to that SHA.
Exact-SHA GitHub `rust-ci` passed for that SHA on `master` run
[`34591799096`](https://github.com/ilfrick/frickmail/actions/runs/34591799096)
and `rust-full-migration` run
[`34591805298`](https://github.com/ilfrick/frickmail/actions/runs/34591805298),
and the `naming` gate passed on both branches
([`34591799124`](https://github.com/ilfrick/frickmail/actions/runs/34591799124),
[`34591805279`](https://github.com/ilfrick/frickmail/actions/runs/34591805279));
all runs reported only the known nonblocking Node.js 20 deprecation
annotation. This closing documentation-only amendment intentionally matches no
CI path filter and is expected to produce no GitHub Actions run. The major remaining
gates toward the final Rust-only goal are unchanged (v1 account/mailbox
endpoints, frontend screens, theming removal, cutover validation).

## Prior Snapshot — 2026-09-11 11:20:00 CEST (UTC+02:00)

The Phase 9 API-foundation slice mounts the stable Rust-owned API at
`/api/frickmail/v1` (new `fm-http/src/router/api_v1.rs`, framework-agnostic
JSON with real HTTP statuses instead of 200 envelopes). Contract:
`{"version":"v1","data":…}` on success, `{"version":"v1","error":{code,
message}}` on failure; additive fields never bump the version. Ships with
`GET /health` (unauthenticated) and `GET /session` (reads the
`FrickmailSession` cookie session only — 401 anonymous, 500 on store
failure, never a login attempt or mutation), plus a JSON 404 fallback (and a JSON 405 for wrong methods) so
unknown v1 paths never leak the HTML shell or axum's default bodies. Only safe methods exist so far,
so no connection-token CSRF check applies; the first state-changing route
must enforce it. Envelope types live in `fm-core` with unit tests; six
tests cover envelopes, health, anonymous 401, JSON 404, and JSON 405.
Authenticated
`GET /session` coverage lands with the login-endpoint slice, which will
exercise session creation end to end.

Independent senior review approved the slice; one contract edge (wrong
methods fell through to axum's default 405 body) was closed with a JSON 405
handler plus test before validation.

Docker-only validation passed: `cargo fmt --all -- --check`,
`cargo clippy --workspace --all-targets -D warnings`, full workspace suites
(fm-http 419 passed, live-DB suites green).
Production-image validation built `frickmail-rust:api-v1-test` at image ID
`sha256:9e193fdec140f5c0269f0a5ff520e4c801f38f5ab0be7b7f76c4b4ebc6385b46`;
a read-only container verified the live contract (`/health` 200 envelope,
`/session` 401 envelope, unknown path 404, POST 405), `/health` returned
`ok`, logs showed only expected startup messages, and it stopped cleanly.

Implementation commit `5f2daeed169df011571245a7f9afeaefb7a279c5` was
published to `master` and `rust-full-migration` on both remotes; live
`git ls-remote` checks confirmed all four tips resolve to that SHA.
Exact-SHA GitHub `rust-ci` passed for that SHA on `master` run
[`34585555724`](https://github.com/ilfrick/frickmail/actions/runs/34585555724)
and `rust-full-migration` run
[`34585560799`](https://github.com/ilfrick/frickmail/actions/runs/34585560799),
and the `naming` gate passed on both branches
([`34585555730`](https://github.com/ilfrick/frickmail/actions/runs/34585555730),
[`34585560775`](https://github.com/ilfrick/frickmail/actions/runs/34585560775));
all runs reported only the known nonblocking Node.js 20 deprecation
annotation. This closing documentation-only amendment intentionally matches no
CI path filter and is expected to produce no GitHub Actions run. The major remaining
gates toward the final Rust-only goal are unchanged (v1 session-authenticated
coverage with the login endpoints, frontend screens, theming removal,
cutover validation).

## Prior Snapshot — 2026-09-11 10:50:00 CEST (UTC+02:00)

The client-PGP compose slice closes the "staged attachments with
client OpenPGP MIME" gap: `SendMessage`/`SaveMessage` now accept staged
attachments alongside Mailvelope-style `signed`/`encrypted` payloads,
nesting the PGP entity as the MIME root under shared MailSo-compatible
related/mixed wrapping (attachments stay siblings, never inside the signed
or encrypted envelope), exactly like PHP appending attachments after its PGP
branch. The attachment wrapping was extracted byte-identically into a shared
helper reused by plain/HTML, signed, and encrypted roots; no-attachment PGP
rendering is unchanged. Three tests cover both builders (markers, byte
parity, sibling ordering, linked `related` branch) plus the full
send-success/save-success staged-capability lifecycle.

Independent senior review approved conditional on strengthened tests, which
were added; the closing re-review found READY-TO-COMMIT with zero residual
references to the old rejection.

Docker-only validation passed: `cargo fmt --all -- --check`,
`cargo clippy --workspace --all-targets -D warnings`, full workspace suites
(fm-http 415 passed, live-DB suites green).
Production-image validation built `frickmail-rust:pgp-attachments-test` at
image ID `sha256:656422dcbcd3b7d587e38e90e442082c4e90e84bdcddc02b3ea840845631351d`;
a read-only container started without a database, `/health` returned `ok`,
logs showed only expected startup messages, and it stopped cleanly.

Implementation commit `cfcf3d196efcd29e4b5a12598a714bb7a5b65c4d` was
published to `master` and `rust-full-migration` on both remotes; live
`git ls-remote` checks confirmed all four tips resolve to that SHA.
Exact-SHA GitHub `rust-ci` passed for that SHA on `master` run
[`34580686016`](https://github.com/ilfrick/frickmail/actions/runs/34580686016)
and `rust-full-migration` run
[`34580690756`](https://github.com/ilfrick/frickmail/actions/runs/34580690756);
both runs reported only the known nonblocking Node.js 20 deprecation
annotation. This closing documentation-only amendment intentionally matches no
CI path filter and is expected to produce no GitHub Actions run. The major remaining
gates toward the final Rust-only goal are unchanged (compose PGP assembly
and OAuth SMTP parity, frontend/theming with the theme deletion plan
recorded, cutover validation).

## Prior Snapshot — 2026-09-11 09:40:00 CEST (UTC+02:00)

The connection-token/CSRF parity slice hardens the Rust-only
contract to PHP `ServiceActions` semantics: every POST except `Logout` now
requires the derived connection token regardless of action-name validity
(previously skipped for unknown names), and any supplied `X-SM-Token` header
on `GET /` must match (AppData, raw downloads, JSON GETs, hooks, index;
headerless requests pass through). Shared `expected_connection_token`
helper keeps POST semantics byte-identical while the GET path stays
read-only (never mints session state; no secret means nothing to compare).
Bridge deployments still defer to PHP tokens; logout stays exempt.
`docs/LEGACY_ACTION_INVENTORY.md` transport shapes record the contract.

Independent senior review approved with no blockers (constant-time compares,
no GET minting, exemption/bridge preservation, root_get placement,
account-switch staleness as parity, identical error mapping, non-vacuous
tests); one wording nit remediated.

Docker-only validation passed: `cargo fmt --all -- --check`,
`cargo clippy --workspace --all-targets -D warnings`, full workspace suites
(fm-http 413 passed including 3 new CSRF tests, live-DB suites green).
Production-image validation built `frickmail-rust:csrf-contract-test` at
image ID `sha256:0f57d194333e42b8183085de17f401344e759bc551ed062d0e5a4a9a50f17972`;
a read-only container returned `/health` ok, rejected an unknown-action POST
without token (`code 102`), passed a headerless AppData GET on a fresh
session, showed only expected startup logs, and stopped cleanly.

Implementation commit `4007939db24488727ad53daa9534e6208be60535` was
published to `master` and `rust-full-migration` on both remotes; live
`git ls-remote` checks confirmed all four tips resolve to that SHA.
Exact-SHA GitHub `rust-ci` passed for that SHA on `master` run
[`34575778869`](https://github.com/ilfrick/frickmail/actions/runs/34575778869)
and `rust-full-migration` run
[`34575787686`](https://github.com/ilfrick/frickmail/actions/runs/34575787686),
and the `naming` gate passed on both branches
([`34575778880`](https://github.com/ilfrick/frickmail/actions/runs/34575778880),
[`34575787641`](https://github.com/ilfrick/frickmail/actions/runs/34575787641));
all runs reported only the known nonblocking Node.js 20 deprecation
annotation. This closing documentation-only amendment intentionally matches no
CI path filter and is expected to produce no GitHub Actions run. The major
remaining gates toward the final Rust-only goal are unchanged (compose PGP
assembly and OAuth SMTP parity, frontend/theming with the theme deletion
plan recorded, cutover validation).

## Prior Snapshot — 2026-09-10 04:00:00 CEST (UTC+02:00)

The CI legacy-name allowlist slice (Immediate Next Work #6) makes
naming cleanup measurable: new workflow `.github/workflows/naming.yml` runs
`.github/scripts/check-legacy-names.sh` against
`.github/naming-allowlist.txt` on push/PR. The gate scans tracked files under
the migration-owned surfaces (`frickmail-server/`, the Rust Dockerfile and
compose files, `frickmail-ui/`, `package.json`) for `snappymail`/`rainloop`
and fails on any unallowlisted hit or any stale entry. The 9-entry baseline
(52 hits) is all compatibility-justified with owners and removal phases:
`SnappyMail\Crypt` parity comments, shared `rainloop_ab_*` schema SQL,
the internal `LEGACY_SNAPPYMAIL_APP_VERSION` digest constant, and
strangler-phase bundle inputs. The legacy PHP/JS runtime stays out of scope
until its removal phases.

Independent senior review approved the slice with no blockers (script safety,
index consistency, coverage spot-check, workflow validity all verified).

Validation: `bash -n` + YAML parse clean; gate passes on the tree (52 hits,
9 entries, none stale); both failure modes demonstrated (synthetic new hit
fails, synthetic stale entry fails; fixtures removed afterwards).

Implementation commit `266f7b13f9d5d26316af77b32b827bad974a6dfe` was
published to `master` and `rust-full-migration` on both remotes; live
`git ls-remote` checks confirmed all four tips resolve to that SHA. The new
`naming` workflow ran on that SHA and passed on `master` run
[`34572762706`](https://github.com/ilfrick/frickmail/actions/runs/34572762706)
and `rust-full-migration` run
[`34572769467`](https://github.com/ilfrick/frickmail/actions/runs/34572769467);
no `rust-ci` run was produced since no Rust paths changed, as expected. This
closing documentation-only amendment intentionally matches no CI path filter
and is expected to produce no GitHub Actions run. The major remaining
gates toward the final Rust-only goal are unchanged (compose PGP assembly
and OAuth SMTP parity, connection-token/CSRF contract, frontend/theming
with the theme deletion plan recorded, cutover validation).

## Prior Snapshot — 2026-09-09 16:00:00 CEST (UTC+02:00)

The theme-loader inventory slice (Phase 0 deliverable, Immediate Next
Work #5) records every legacy SnappyMail theme surface in the
`docs/LEGACY_ACTION_INVENTORY.md` section (T1–T13): 21 bundled theme
directories plus `example.css`, `@custom`/`@nextcloud` roots, the
`Actions/Themes.php` resolution/validation/LESS/background loader, the
`ServiceCss()` route with `CssCache`, bootstrap placeholders, the AppData
theme payload and `Capa::THEMES`/`Capa::USER_BACKGROUND` flags, per-account
`Theme`/font/background settings, admin config, Knockout store/screens, and
the retained Frickmail-theme plugin (localStorage-only). The deletion plan is
ordered freeze → serving paths → sources (including the build-breaking
`COPY snappymail/v/0.0.0/themes` Dockerfile line) → UI, blocked on Phase 9
screens and Phase 4 admin APIs, with Phase 10 exit criteria restated.

Independent senior review first blocked on three omissions (font settings,
`RawUserBackground()`/capability refs, Dockerfile COPY dependency) plus six
precision findings (package count, route shape, admin keys, admin/UI file
names, storage keys, AppData read surface); all were verified against source
and remediated, and the closing re-review approved with no blockers.

Validation is docs-only: every cited path, symbol, and line was verified to
exist; `git diff --stat` shows only `docs/LEGACY_ACTION_INVENTORY.md`, so no
Rust build, test, or image change applies and no `rust-ci` run is expected
before publication.

Implementation commit `5886eee3f8499ab3193021a5ff7e7596508dfc79` was
published to `master` and `rust-full-migration` on both remotes; live
`git ls-remote` checks confirmed all four tips resolve to that SHA. As a
docs-only change it intentionally matches no `rust-ci` path filter, and no
new GitHub Actions runs were produced, as expected. The major remaining
gates toward the final Rust-only goal are unchanged (compose PGP assembly and
OAuth SMTP parity, connection-token/CSRF contract, frontend/theming — now
with the theme deletion plan recorded — cutover validation).

## Prior Snapshot — 2026-09-09 15:30:00 CEST (UTC+02:00)

The `Message` edge-parity slice corrects the stale "Immediate Next
Work" note (`Message` dispatch and response parity are native, including
opaque/detached S/MIME and PGP auto-verification) and pins the `[Preview]`
subject-prefix strip with a single-`Message`-path regression test
(`[Preview] Hello` renders as `Hello`, matching PHP's 10-char strip). A
systematic field-by-field hunt (flags normalization, `hash`/`ETag`,
`[Preview]`/trim subject, all three spam branches with `isSpam ? 100`
serialization, header-vs-internal timestamps, address/attachment/header
collections) plus the frontend consumer check (`smimeSigned.body` feeds
`MimeToMessage`) confirmed parity with the generic
`filter.result-message` plugin-hook boundary as the only remaining carve-out.
`docs/LEGACY_ACTION_INVENTORY.md` already marks `Message` native.

Independent senior review approved the slice with no blockers; its one
non-blocking suggestion (an fm-imap unit case for the spaced `[Preview]`
variant) was already covered by the existing summary test.

Docker-only validation passed: `cargo fmt --all -- --check`,
`cargo clippy --workspace --all-targets -D warnings`, and the fm-http lib
suite (410 passed including the new test).
Production-image validation built `frickmail-rust:message-edge-test` at
image ID `sha256:cf885b83b2ccafc5035fb8d7cb1865e5f31416562838554dcabe88f0f1139352`;
a read-only container started without a database, `/health` returned `ok`,
the legacy `/?/Json/` route shape dispatched `Message` natively (standard
unauthenticated envelope instead of the 501 compatibility fallback), logs
showed only expected startup messages, and it stopped cleanly.
Implementation commit `18ac857e1fbd93947049442a24d8c53383723fba` was
published to `master` and `rust-full-migration` on both remotes; live
`git ls-remote` checks confirmed all four tips resolve to that SHA.
Exact-SHA GitHub `rust-ci` passed for that SHA on `master` run
[`34364923404`](https://github.com/ilfrick/frickmail/actions/runs/34364923404)
and `rust-full-migration` run
[`34364940759`](https://github.com/ilfrick/frickmail/actions/runs/34364940759);
both runs reported only the known nonblocking Node.js 20 deprecation
annotation. This closing documentation-only amendment intentionally matches no
`rust-ci` path filter and is expected to produce no GitHub Actions run. The
major remaining gates toward the final Rust-only goal are unchanged (compose
PGP assembly and OAuth SMTP parity, connection-token/CSRF contract,
frontend/theming, cutover validation).

## Prior Snapshot — 2026-09-09 09:00:00 CEST (UTC+02:00)

The `Message` detached S/MIME + PGP auto-verification slice completes
the PHP `DoMessage()` verification parity behind the
`security.auto_verify_signatures` setting (default `false`, matching PHP).
Detached `smimeSigned` parts verify from the fetched `RawMessage` bytes via
the shared OpenSSL primitive and contribute `success` only; `pgpSigned`
parts verify through the account GnuPG home reusing the exact
`PgpVerifyMessage` fetch contract (`{part}.MIME`, `{part}`, `{sigPart}`
bounds, CRLF/LF and ASCII normalization, clearsigned transfer-decoding) and
are replaced with the PHP `{fingerprint, success}` shape when the first
signature has status 0 with a non-empty fingerprint. The S/MIME and PGP
probes run concurrently under a 30 s outer deadline after the HTTP cache
check; every failure mode falls back to the unverified part metadata with a
warning log. The `PgpVerifyMessage` fetch sequence is reused through the
shared `fetch_pgp_verify_inputs` helper. Seven new
tests cover the fingerprint parser, both JSON shapes, detached gating and
best-effort skips, and the disabled-by-default PGP gating (no extra I/O);
`docs/LEGACY_ACTION_INVENTORY.md` records the new native scope.

Independent senior review approved the slice; the two non-blocking findings
were remediated before validation (corrected `(signature, body)` doc labels
on the extracted helper, 30 s outer deadline on the verify phase).

Docker-only validation passed: `cargo fmt --all -- --check`,
`cargo clippy --workspace --all-targets -D warnings`, full workspace unit
suites (fm-http 409 passed including the new tests), and the live-DB suites
against the compose services (`schema_compatibility` 10 passed,
`address_book_compatibility` 3 passed, fm-db 56 passed).
Production-image validation built
`frickmail-rust:message-auto-verify-test` at image ID
`sha256:8770029e2ea93ddc024de04311852ed84535dc796dee982b97584025fa6b3247`;
a read-only container started without a database, `/health` returned `ok`,
the legacy `/?/Json/` route shape dispatched `Message` natively (standard
unauthenticated envelope instead of the 501 compatibility fallback), logs
showed only expected startup messages, and it stopped cleanly.

Implementation commit `311b091182cb11378c2f30feaf180d6001af8a3d` was
published to `master` and `rust-full-migration` on both remotes; live
`git ls-remote` checks confirmed all four tips resolve to that SHA.
Exact-SHA GitHub `rust-ci` passed for that SHA on `master` run
[`34324087327`](https://github.com/ilfrick/frickmail/actions/runs/34324087327)
and `rust-full-migration` run
[`34324096049`](https://github.com/ilfrick/frickmail/actions/runs/34324096049);
both runs reported only the known nonblocking Node.js 20 deprecation
annotation. This closing documentation-only amendment intentionally matches no
`rust-ci` path filter and is expected to produce no GitHub Actions run. The
major remaining gates toward the final Rust-only goal are unchanged (compose
PGP assembly and OAuth SMTP parity, connection-token/CSRF contract,
frontend/theming, cutover validation).

## Prior Snapshot — 2026-09-09 01:00:00 CEST (UTC+02:00)

The `Message` opaque S/MIME auto-verification slice closes the largest
remaining `Message` response-parity gap against legacy PHP `DoMessage()`: the
native handler now best-effort verifies a non-detached (`opaque`)
`smimeSigned` part from the already-fetched `RawMessage` bytes (blocking pool,
10 s deadline, 2 MiB bound) and emits the PHP-compatible `smimeSigned.body`
plus `smimeSigned.success` fields. Verification failures fall through to the
unsigned metadata, mirroring PHP's logged-and-continued path. Supporting
changes: `security.auto_verify_signatures` setting (default `false`,
`autoVerifySignatures` alias, matching PHP) reserved for the detached/PGP
follow-up, and `SmimeVerifyResult.body` carrying the extracted inner content
for opaque blobs only. `docs/LEGACY_ACTION_INVENTORY.md` records the new
native scope and the remaining detached/PGP boundary.

Independent senior review approved the slice; the three actionable
non-blocking findings were remediated before validation (dead `let _`
binding collapsed to an existence check, new oversize-input regression test,
new `SecurityConfig` default/alias parsing test). The remaining review notes
are accepted follow-up boundaries: stricter Rust chain validation versus
PHP's parse-only `PKCS7_NOVERIFY|NOCHAIN|NOSIGS`, top-level-`RawMessage`
verification for nested opaque parts, and trust-store-change cache staleness
(PHP `DoMessage` has no HTTP caching; the Rust ETag intentionally still
matches PHP's folder/uid/flags/client-hash shape).

Docker-only validation passed: `cargo fmt --all -- --check`, `cargo
clippy --workspace --all-targets -D warnings`, full workspace unit suites
(fm-http 402 passed including 5 new tests, fm-core/fm-user/fm-imap/fm-db unit
suites green), and the live-DB suites against the compose services
(`schema_compatibility` 10 passed, `address_book_compatibility` 3 passed).
Production-image validation built `frickmail-rust:message-smime-test` at
image ID `sha256:6c802161145dd93771840d7463cd392d75b003723eecd97d44a06dc31e7a1109`;
a read-only container started without a database, `/health` returned `ok`,
the legacy `/?/Json/` route shape dispatched `Message` natively (standard
unauthenticated envelope instead of the 501 compatibility fallback), logs
showed only expected startup messages, and it stopped cleanly.

Implementation commit `e76c31ac0ff166fdda8bf19d2918bca955c8fb1c` was
published to `master` and `rust-full-migration` on both remotes; live
`git ls-remote` checks confirmed all four tips resolve to that SHA.
Exact-SHA GitHub `rust-ci` passed for that SHA on `master` run
[`34289667282`](https://github.com/ilfrick/frickmail/actions/runs/34289667282)
and `rust-full-migration` run
[`34289682420`](https://github.com/ilfrick/frickmail/actions/runs/34289682420);
both runs reported only the known nonblocking Node.js 20 deprecation
annotation. This closing documentation-only amendment intentionally matches no
`rust-ci` path filter and is expected to produce no GitHub Actions run. The
major remaining gates toward the final Rust-only goal are unchanged (compose
PGP/detached auto-verify and OAuth SMTP parity, exact `Message` edge parity,
connection-token/CSRF contract, frontend/theming, cutover validation).

## Prior Snapshot — 2026-08-31 15:30:00 CEST (UTC+02:00)

The pending contacts-sync slice makes `JsonContactsSync` native, completing
the contacts-sync plugin migration: the handler proxies Gmail People API
(pageSize 200, fixed personFields, page tokens) and Microsoft Graph contacts
($top=100 following `@odata.nextLink`) with the selected Frickmail mail
account's encrypted OAuth refresh token, refreshing with the Graph contacts
scope and upserting by `gmail:` / `o365:` provider UIDs into the native
address book with the PHP save-count semantics (updates count). Provider
field mapping (names, N order, emails, phones including Graph's string and
array shapes, organizations, addresses, birthdays as jCard `date` values),
person-skipping rules, PHP-style HTTP error messages, and Result envelopes
match the PHP plugin; `@odata.nextLink` is followed only inside the Graph
root (SSRF-safe; PHP followed it blindly), pages are capped at 50 with a
60 s aggregate deadline, and the OAuth token-request builder now takes the
provider scope so calendar (Calendars.ReadWrite) and contacts
(Contacts.Read) refreshes stay exact. The provider-mismatch error uses
PHP's "Unknown provider for {email}" wording for contacts. New unit tests
cover the mappers and DB-backed flows (O365 pagination plus double-run
upsert parity, Gmail page-token encoding, provider mismatch, offsite
next-link rejection, PHP-format HTTP error envelope) were added; all
outbound HTTP goes through the injectable fetcher.

Independent senior review approved the slice; the review's two recommended
pre-commit fixes (removing an unreachable duplicate error branch and adding
regression tests for the next-link SSRF rejection and the PHP-format HTTP
error string) were applied before staging. Docker-only validation passed:
`cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -D
warnings`, and the full workspace suite (706 tests across 23 suites, zero
failures). Production-image validation built `frickmail-rust:sync-test` at
image ID
`sha256:ef35a475d4bc313d1877255e19cefa841addfd6d1d063bb5468da50bc472fd45`;
a read-only container started without a database, `/health` returned `ok`,
and the legacy `/?/Json/` route shape dispatched `JsonContactsSync`
natively (standard unauthenticated envelope instead of the 501
compatibility fallback), with clean logs and no restarts.

Implementation commit `02aa23845348afcfafc6d9ab844495731f230221` was
published to `master` and `rust-full-migration` on both remotes; live
`git ls-remote` checks confirmed all four tips resolve to that SHA.
Exact-SHA GitHub `rust-ci` passed for that SHA on `master` run
[`33400113908`](https://github.com/ilfrick/frickmail/actions/runs/33400113908)
and `rust-full-migration` run
[`33400127955`](https://github.com/ilfrick/frickmail/actions/runs/33400127955).
This closing documentation-only amendment intentionally matches no
`rust-ci` path filter and is expected to produce no GitHub Actions run.

## Prior Snapshot — 2026-08-31 07:25:00 CEST (UTC+02:00)

The contacts slice (published and CI-verified as `eb557a0b3` with
`rust-ci` runs `33389856713` and `33389862089`; its first SHA
`5f38fe7a6` failed on a clippy needless-borrow and was corrected) made
`JsonAddContact` and
`JsonDeduplicateContacts` native and introduced the native Personal Address
Book storage: a new `fm-user::address_book` module creates and shares the
legacy PHP `rainloop_ab_contacts` / `rainloop_ab_properties` schema (jCard
blob under `prop_type = 251`, flattened typed properties, lowercased search
values, email usage-frequency preservation on update, and the soft-delete
`deleted = 1` semantics) so the PHP compatibility runtime reads and writes
the same rows during the strangler phase. `JsonAddContact` reproduces the
PHP plugin's validation, `manual:` UID format (32 random hex characters
instead of `md5(email . microtime)`), name-to-N splitting, property write
order, and response envelopes; `JsonDeduplicateContacts` reproduces the
paged lowest-id-kept deduplication grouped by UID or display name. The
"address book is not active" errors are intentionally absent (native
storage is always available). `JsonContactsSync` (Gmail People API /
Microsoft Graph provider fetching) remains a compatibility fallback for the
follow-up provider-sync slice. The Postgres schema migration runs under a
dedicated advisory lock, guarded by a cheap table probe so request handlers
can call it on every request.

Independent senior review approved the slice after one remediation round.
The first round blocked on two findings — PostgreSQL `?` placeholders
(sqlx's `any` driver passes SQL verbatim, so Postgres requires numbered
`$n` placeholders) and email usage frequencies read after the property
delete (always empty, contradicting PHP's `getContactFreq` order) — plus
minor findings (non-transactional `save_contact`, a wrong JCARD-order
parity claim, dead backend code, and unconditional per-request DDL). The
remediation fixes all of them: backend-aware placeholders throughout,
transactional contact writes, frequency reads before the delete, JCARD
written first like PHP, a probe-guarded schema check, and a new
`fm-user/tests/address_book_compatibility.rs` suite running the full
save/update/dedupe/delete flow against live PostgreSQL, MySQL, and SQLite.
Docker-only validation passed: `cargo fmt --all -- --check`,
`cargo clippy --workspace --all-targets -D warnings`, and the full
workspace suite (698 tests across 23 suites, zero failures).
Production-image validation built `frickmail-rust:contacts-test` at image
ID
`sha256:b22367ac0b7a56dc33e1892584b0fe6f9d10a83a537709c5d92fc3bc9fc2ae0f`;
a read-only container started without a database, `/health` returned `ok`,
and the legacy `/?/Json/` route shape dispatched `JsonAddContact`
natively (standard unauthenticated envelope instead of the 501
compatibility fallback), with clean logs and no restarts.

The first publication SHA `5f38fe7a6c69452a46bbecc32155bb3800cd3ec3`
failed the exact-SHA GitHub `rust-ci` runs (`33389283336` on `master`,
`33389289969` on `rust-full-migration`) on a clippy `needless_borrow`
denied by `-D warnings` in the new compatibility test — a leftover the
local lint run predated the final test edit. The focused correction
(`eb557a0b30cca5a1b457638672b2734612ecd45f`) removed the borrow and was
published to all four tips; exact-SHA GitHub `rust-ci` passed for it on
`master` run
[`33389856713`](https://github.com/ilfrick/frickmail/actions/runs/33389856713)
and `rust-full-migration` run
[`33389862089`](https://github.com/ilfrick/frickmail/actions/runs/33389862089).
This closing documentation-only amendment intentionally matches no
`rust-ci` path filter and is expected to produce no GitHub Actions run.

## Prior Snapshot — 2026-08-30 21:10:00 CEST (UTC+02:00)

The pending calendar slice makes `JsonCalendarList`, `JsonCalendarEvents`,
`JsonCalendarSave`, and `JsonCalendarDelete` native in a new
`fm-http/src/router/calendar.rs` module, replacing the PHP `calendar`
plugin in Frickmail mode. The handlers proxy Google Calendar and Microsoft
Graph with the selected Frickmail mail account's encrypted OAuth refresh
token: the account's `account_type` selects the provider (replacing PHP's
domain-list detection), an explicit `account_id` or the selected-account
session replaces the PHP main-account lookup, and provider credentials come
from `FRICKMAIL__OAUTH2__*` with the legacy `FRICKMAIL_GMAIL_*` /
`FRICKMAIL_O365_*` environment fallback. Request building, event mapping,
composite-id splitting, and provider error strings mirror the PHP plugin;
plugin errors return as `Result.error` inside a 200 envelope like the PHP
catch block. Two intentional deviations are documented: the O365 event
update addresses the raw Graph event id instead of the legacy composite
`calendar:id` URL (which could never match a Graph event id), and resource
use is bounded (50 calendars, 2000 events, 30 s per-request deadline plus a
60 s aggregate action deadline). Missing `start`/`end` bounds reproduce the
PHP default window (first of this month through last of next month, UTC).
The request type implements a redacting `Debug` so OAuth credentials cannot
leak through logs. All outbound HTTP goes through an injectable fetcher; 23
new tests cover the pure builders/mappers and six DB-backed flows against
captured requests.

Independent senior review approved the slice after one remediation round:
the first round approved with three non-blocking findings (missing PHP
`start`/`end` default window, no aggregate deadline across the sequential
events loop, and a credential-bearing `Debug` derive), all of which were
fixed and verified by the closing re-review. Docker-only validation passed:
`cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -D
warnings`, and the full workspace suite (687 tests across 22 suites, zero
failures). Production-image validation built `frickmail-rust:calendar-test`
at image ID
`sha256:d36d41bdb52689b2f16d2c20bc29c0c12128ac1c6983b1b304da44f3e853b3b6`;
a read-only container started without a database, `/health` returned `ok`,
and the legacy `/?/Json/` route shape dispatched `JsonCalendarList` natively
(returning the standard unauthenticated envelope instead of the 501
compatibility fallback), with clean logs and no restarts.

Implementation commit `e8201bd897558b2cb841083690dc4e6508cffca6` was
published to `master` and `rust-full-migration` on both remotes; live
`git ls-remote` checks confirmed all four tips resolve to that SHA.
Exact-SHA GitHub `rust-ci` passed for that SHA on `master` run
[`33343565421`](https://github.com/ilfrick/frickmail/actions/runs/33343565421)
and `rust-full-migration` run
[`33343568730`](https://github.com/ilfrick/frickmail/actions/runs/33343568730).
This closing documentation-only amendment intentionally matches no
`rust-ci` path filter and is expected to produce no GitHub Actions run.

## Prior Snapshot — 2026-08-30 15:05:00 CEST (UTC+02:00)

The OAuth2 provider slice adds native Gmail and O365 part hooks,
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

The first publication SHA `99582cf8e493ca9ada3f5719bbf565670634710b` failed
the exact-SHA GitHub `rust-ci` runs (`33312891712` on `master`,
`33312918887` on `rust-full-migration`) in the pre-existing
`fm-db` schema-compatibility test
`postgres_ensure_runtime_schema_is_idempotent`: concurrent
`ensure_runtime_schema` calls raced on a fresh PostgreSQL database and one
failed with a duplicate key violation on `pg_type_typname_nsp_index`, a
known PostgreSQL concurrency limitation of `CREATE TABLE IF NOT EXISTS`.
That test landed with the previously under-verified DB-slice commits and had
never been exercised by a completed dual-branch CI run. The focused
correction serializes the runtime schema migration with a session-level
PostgreSQL advisory lock inside `ensure_runtime_schema`, releasing it on
both success and failure paths. Revalidation passed `cargo fmt --all
-- --check`, `cargo clippy --workspace --all-targets -D warnings`, and the
full workspace suite, with the schema-compatibility suite (10 tests,
including live MySQL/PostgreSQL) run three consecutive times without
failure against the dev-container databases.

The correction commit `4c9d3b2b5da152e517a2eaad47007ccb4ab00d73` failed the
exact-SHA GitHub `rust-ci` runs (`33313736617` on `master`, `33313743514` on
`rust-full-migration`) one step later, in the production-image smoke test:
the container exited because `main` hard-required a Redis connection at
startup ("connect persistent Redis session store"), a startup-availability
regression introduced by the previously under-verified persistent-session
commit and incompatible with the documented standalone-smoke behavior of
starting and answering `/health` without dependencies. The focused
correction makes `main` fall back to the in-memory session store with a
prominent warning when Redis is unreachable, restoring graceful degradation
while production deployments with a reachable Redis keep persistent shared
sessions unchanged. Revalidation passed `cargo fmt --all -- --check`,
`cargo clippy --workspace --all-targets -D warnings`, and the full
workspace suite (664 tests, 22 suites). Production-image validation
rebuilt `frickmail-rust:oauth2-part-hooks-test` and confirmed both modes:
a read-only standalone container without Redis starts, logs the fallback
warning, and answers `/health`; a container attached to the Redis network
starts with persistent sessions and answers `/health`; neither restarts
nor is OOM-killed.

Implementation commit
`1f72236bd2d7c8a682d9912ab66df5eca2551588` (the fallback correction on top of
`4c9d3b2b5` and `99582cf8e`) was published to `master` and
`rust-full-migration` on both remotes; live `git ls-remote` checks confirmed
all four tips resolve to that SHA. Exact-SHA GitHub `rust-ci` passed for that
SHA on `master` run
[`33315148125`](https://github.com/ilfrick/frickmail/actions/runs/33315148125)
and `rust-full-migration` run
[`33315150467`](https://github.com/ilfrick/frickmail/actions/runs/33315150467).
The intermediate SHAs `99582cf8e` and `4c9d3b2b5` are superseded: their runs
failed as recorded above, and each received the documented focused
correction before the next publication. This closing documentation-only
amendment intentionally matches no `rust-ci` path filter and is expected to
produce no GitHub Actions run.

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

**Secrets policy (unconditional):** never commit, or otherwise share, API keys
or other secrets — tokens, passwords, client secrets, private key material, or
real user data. Credentials come exclusively from the deployment environment
(`.env`, Docker secrets, `FRICKMAIL__*` variables, `~/.netrc` for push
authentication). They must never be copied into commits, documentation, review
reports, CI logs, or error messages; test fixtures use synthetic values only;
and secret-bearing paths (`.env`, `frickmail-data/`, `postgres/`, and similar)
must never enter the repository or any shared artifact.

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
   `MessageList`, `FolderInformation`, `FolderInformationMultiply`, and
   `Message` dispatch are native; `Message` response parity is complete
   including opaque/detached S/MIME and PGP auto-verification, with only the
   generic `filter.result-message` plugin-hook boundary remaining
   (`| Message | ... | native |` — see `docs/LEGACY_ACTION_INVENTORY.md`).
4. Add Docker MySQL/PostgreSQL/SQLite integration tests for existing schema
   compatibility.
5. Inventory the legacy theme loader and plan deletion in favor of Frickmail-user
   theming.
6. CI allowlists for temporary legacy names are now enforced by the `naming`
   workflow (`.github/workflows/naming.yml`), which runs
   `.github/scripts/check-legacy-names.sh` against `.github/naming-allowlist.txt`:
   any unallowlisted `snappymail`/`rainloop` reference in the Rust workspace,
   Rust packaging, or new UI sources fails, as does any stale entry — so
   naming cleanup stays measurable.
7. Track the Frickmail-user usable release gate and do not continue into full
   legacy runtime removal until that release is available and operator input is
   received.
