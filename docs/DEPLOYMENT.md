# Build and deploy Frickmail

## Runtime status

Frickmail now has two production image definitions:

- `.docker/release/Dockerfile` builds the current SnappyMail/PHP compatibility
  runtime.
- `.docker/release/rust/Dockerfile` builds a minimal, non-root Rust runtime with
  an HTTP health check and graceful shutdown support.

The Rust image is packaged for production and can connect to the existing
PostgreSQL and Redis services without mounting PHP application data. It is not
yet a functional replacement for the complete browser application: `/` still
serves the Rust migration shell, some legacy actions remain unmigrated, and
sessions are currently in memory. Use the Rust Compose service as a canary until
the readiness gate below passes. Promoting `master` does not by itself authorize
switching production traffic from the compatibility container.

## Prerequisites

- Docker Engine with the Compose v2 plugin
- A clone of this repository on the `master` branch
- A populated `.env` containing the deployment secrets referenced by
  `docker-compose.frickmail.yml`
- Enough free space for an application-data and PostgreSQL backup

Run all commands from the repository root.

The Rust service expects the existing Compose database and Redis networks. The
compatibility stack must have provisioned the existing database schema at least
once. The Rust binary verifies database connectivity at startup but does not
create or upgrade that schema yet.

## Back up the current deployment

Stop application writes while retaining the database and Redis services:

```bash
docker compose -f docker-compose.frickmail.yml stop frickmail
```

Record the currently deployed image and create a rollback tag:

```bash
FRICKMAIL_ROLLBACK_IMAGE="$(docker inspect frickmail --format '{{.Image}}')"
docker image inspect "$FRICKMAIL_ROLLBACK_IMAGE" --format '{{.Id}}'
docker tag "$FRICKMAIL_ROLLBACK_IMAGE" frickmail:rollback
```

Back up `frickmail-data/`, `postgres/`, and `.env` using the backup mechanism
approved for the host. These paths contain user data and secrets; do not copy
them into the repository or a public artifact.

## Build the updated image

Update the checked-out source and build a versioned image:

```bash
git fetch --all --prune
git switch master
git pull --ff-only
FRICKMAIL_IMAGE_TAG="frickmail:$(git rev-parse --short=12 HEAD)"
docker build --pull -f .docker/release/Dockerfile -t "$FRICKMAIL_IMAGE_TAG" .
docker tag "$FRICKMAIL_IMAGE_TAG" frickmail:latest
```

The release build runs the frontend build-time tests. A successful build must
finish without a failed test or Docker layer.

## Smoke-test the image before rollout

Use an isolated container name, port, and temporary volume:

```bash
docker volume create frickmail-smoke-data
docker run -d --name frickmail-smoke \
  -p 127.0.0.1:18888:8888 \
  -v frickmail-smoke-data:/var/lib/snappymail \
  frickmail:latest
```

The standalone smoke container has no Compose `db` hostname, so its log may
report that PostgreSQL is unreachable and that schema migration was skipped.
It must still become ready and return HTTP 200:

```bash
docker logs --tail=200 frickmail-smoke
for attempt in $(seq 1 60); do
  curl --fail --silent http://127.0.0.1:18888/ >/dev/null && break
  sleep 1
done
curl --fail --show-error http://127.0.0.1:18888/ >/dev/null
docker inspect frickmail-smoke \
  --format 'status={{.State.Status}} oom={{.State.OOMKilled}} restarts={{.RestartCount}}'
docker stop --timeout 20 frickmail-smoke
docker rm -v frickmail-smoke
docker volume rm frickmail-smoke-data
```

Do not continue if HTTP readiness fails, the container is OOM-killed, or the
logs contain an unexpected migration, PHP-FPM, nginx, permission, or plugin
error.

## Deploy with Compose

Start the dependencies, recreate the webmail container from the validated
image, and verify health:

```bash
docker compose -f docker-compose.frickmail.yml up -d db redis
docker compose -f docker-compose.frickmail.yml up -d --no-deps --force-recreate frickmail
docker compose -f docker-compose.frickmail.yml ps
docker compose -f docker-compose.frickmail.yml logs --tail=200 frickmail
curl --fail --show-error http://127.0.0.1:8888/ >/dev/null
```

The existing `./frickmail-data` and `./postgres` bind mounts are preserved by
container recreation. Verify login, account switching, inbox listing, message
view, send, OAuth/OIDC login, contacts, and calendar behavior before declaring
the rollout complete.

## Roll back

If validation fails, restore the previous image and recreate only the webmail
service:

```bash
docker tag frickmail:rollback frickmail:latest
docker compose -f docker-compose.frickmail.yml up -d --no-deps --force-recreate frickmail
docker compose -f docker-compose.frickmail.yml logs --tail=200 frickmail
curl --fail --show-error http://127.0.0.1:8888/ >/dev/null
```

Restore application-data or PostgreSQL backups only when the failed rollout
changed those stores and the rollback procedure for that change requires it.

## Validate the Rust workspace

Rust checks run in the repository's development container:

```bash
docker compose -f docker-compose.rust.yml build rust-dev
docker compose -f docker-compose.rust.yml run --rm rust-dev cargo fmt --all --check
docker compose -f docker-compose.rust.yml run --rm rust-dev cargo test --workspace
docker compose -f docker-compose.rust.yml run --rm rust-dev \
  cargo clippy --workspace --all-targets -- -D warnings
```

## Build the production Rust image

Build an immutable, revision-tagged image and retain `latest` as the local
Compose convenience tag:

```bash
FRICKMAIL_RUST_IMAGE_TAG="frickmail-rust:$(git rev-parse --short=12 HEAD)"
docker build --pull -f .docker/release/rust/Dockerfile \
  -t "$FRICKMAIL_RUST_IMAGE_TAG" .
docker tag "$FRICKMAIL_RUST_IMAGE_TAG" frickmail-rust:latest
docker image inspect "$FRICKMAIL_RUST_IMAGE_TAG" \
  --format 'image={{.Id}} user={{.Config.User}} health={{json .Config.Healthcheck.Test}}'
```

The final image contains the release binary, CA certificates, OpenSSL runtime
libraries, and `curl` for its health check. It does not contain a compiler, the
source tree, PHP, nginx, or PHP-FPM, and it runs as UID/GID `10001` by default.

## Run the Rust production canary

Keep the compatibility stack's `db` and `redis` services running. The default
Rust host port is `18088`, so the existing container can remain live on `8888`:

```bash
docker compose -f docker-compose.frickmail.yml up -d db redis
docker compose -f docker-compose.rust-production.yml config --quiet
docker compose -f docker-compose.rust-production.yml up -d --no-build
```

If the existing stack uses a non-default Compose project name, set
`FRICKMAIL_DB_NETWORK` and `FRICKMAIL_REDIS_NETWORK` to its actual network
names. Inspect them with `docker network ls`.

Set `FRICKMAIL_RUST_BASE_URL` to the externally reachable canary origin whenever
testing generated links or OIDC redirects. It defaults to
`http://localhost:18088`. Compose explicitly forwards the supported Gmail,
Microsoft, generic OIDC, mail, cache, Frickmail-user, and transactional SMTP
settings from `.env`; Compose `.env` values are not otherwise injected into a
container. The separate `egress` network is required for IMAP/SMTP and OAuth
provider access, while PostgreSQL and Redis stay on internal networks.

Wait for health and inspect the complete startup state:

```bash
for attempt in $(seq 1 60); do
  curl --fail --silent http://127.0.0.1:18088/health >/dev/null && break
  sleep 1
done
curl --fail --show-error http://127.0.0.1:18088/health
curl --fail --show-error http://127.0.0.1:18088/version
docker compose -f docker-compose.rust-production.yml ps
docker compose -f docker-compose.rust-production.yml logs --tail=200 frickmail-rust
docker inspect frickmail-rust \
  --format 'status={{.State.Status}} health={{.State.Health.Status}} oom={{.State.OOMKilled}} restarts={{.RestartCount}} user={{.Config.User}} readonly={{.HostConfig.ReadonlyRootfs}}'
```

`/health` and Docker health are process liveness checks, not dependency-aware
readiness checks. The logs must show a verified database connection and the
server listening on `0.0.0.0:8888`; functional canary tests must independently
exercise Redis and external mail/OAuth connectivity. Do not cut over if it
restarts, is OOM-killed, cannot connect to PostgreSQL, or reports configuration
errors.

## Rust replacement readiness gate

Before replacing the compatibility container, all of the following must be
true on the exact image being deployed:

1. The Rust migration inventory has no required browser/API action marked
   `legacy`, `bridge`, or `partial-native`.
2. The full Frickmail UI loads from the Rust service; the migration-shell text
   is absent.
3. Persistent, multi-instance session and CSRF behavior has passed the release
   tests; restarting the canary does not unexpectedly log users out.
4. Existing PostgreSQL data has passed backup/restore and upgrade testing, and
   the Rust-owned schema migration path has been exercised.
5. Login, account switching, inbox listing, message view, attachments, send,
   drafts, search, settings, OAuth/OIDC, contacts, calendar, notifications, and
   S/MIME pass end-to-end tests through the canary URL.
6. The exact image has passed workspace tests, strict Clippy, Docker health and
   log inspection, independent senior review, and the repository CI run.

The current image intentionally does not pass gates 1–4. It is usable for
production-like canary testing, not yet as the sole user-facing webmail service.

## Cut over to the Rust container

Once every readiness gate passes, retain the compatibility image ID for
rollback, stop only the old application container, and bind the validated Rust
image to the production port:

```bash
: "${FRICKMAIL_RUST_IMAGE_TAG:?set this to the revision-tagged image validated by the canary}"
: "${FRICKMAIL_RUST_BASE_URL:?set this to the real externally reachable production origin}"
FRICKMAIL_RUST_IMAGE_ID="$(docker image inspect "$FRICKMAIL_RUST_IMAGE_TAG" --format '{{.Id}}')"
FRICKMAIL_RUST_CANARY_IMAGE_ID="$(docker inspect frickmail-rust --format '{{.Image}}')"
test "$FRICKMAIL_RUST_IMAGE_ID" = "$FRICKMAIL_RUST_CANARY_IMAGE_ID"
FRICKMAIL_COMPAT_IMAGE="$(docker inspect frickmail --format '{{.Image}}')"
docker tag "$FRICKMAIL_COMPAT_IMAGE" frickmail:rollback
docker compose -f docker-compose.rust-production.yml down
docker compose -f docker-compose.frickmail.yml stop frickmail php-fpm-exporter
FRICKMAIL_RUST_PORT=8888 \
FRICKMAIL_RUST_BASE_URL="$FRICKMAIL_RUST_BASE_URL" \
FRICKMAIL_RUST_IMAGE="$FRICKMAIL_RUST_IMAGE_TAG" \
  docker compose -f docker-compose.rust-production.yml up -d --no-build
curl --fail --show-error http://127.0.0.1:8888/health
docker compose -f docker-compose.rust-production.yml logs --tail=200 frickmail-rust
```

Keep `db` and `redis` under `docker-compose.frickmail.yml`; the Rust Compose
file deliberately attaches to their existing internal networks and does not
create a second database.

To roll back the application cutover, stop the Rust service and recreate the
compatibility application without touching PostgreSQL or Redis:

```bash
docker compose -f docker-compose.rust-production.yml down
docker tag frickmail:rollback frickmail:latest
docker compose -f docker-compose.frickmail.yml up -d --no-deps --force-recreate frickmail php-fpm-exporter
curl --fail --show-error http://127.0.0.1:8888/ >/dev/null
docker compose -f docker-compose.frickmail.yml logs --tail=200 frickmail
```
