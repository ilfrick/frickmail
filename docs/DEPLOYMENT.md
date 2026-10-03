# Build and deploy Frickmail

## Runtime status

Frickmail now has two production image definitions:

- `.docker/release/Dockerfile` builds the current SnappyMail/PHP compatibility
  runtime.
- `.docker/release/rust/Dockerfile` builds a minimal, non-root Rust runtime with
  an HTTP health check and graceful shutdown support.

The Rust image is packaged for production and can connect to the existing
PostgreSQL and Redis services without mounting PHP application data. `/` now
serves the Phase 9 v1 web UI (`frickmail-ui/v1`, native screens over
`/api/frickmail/v1`); the previous legacy shell is still built and shipped as
`/static/legacy.html` for reference. Some legacy actions remain unmigrated.
Promoting `master` does not by itself authorize switching production traffic
from the compatibility container.

Rolling back the UI is rolling back the container image: the legacy shell only
boots from `/` (it routes AppData relative to `location.pathname`), so it has
no standalone URL. Re-run the previous image, e.g.
`frickmail-rust:7067ca9b643b` (the last legacy-shell build) or the long-lived
`frickmail-rust:rollback` tag.

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

The `build` step is not optional. `docker compose run` reuses an existing image, so
without it the checks silently run against whatever toolchain the image was last
built with.

`.docker/dev/rust/Dockerfile` and `.docker/release/rust/Dockerfile` pin the **same**
digest, so CI lints with the compiler that builds the shipped binary. Both must be
moved together, deliberately:

```bash
docker compose -f docker-compose.rust.yml run --rm rust-dev rustc --version
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

### Verify the durability invariants after every deploy

Deploy through `docker-compose.rust-production.yml`, not a hand-written
`docker run`. A manual run silently drops hardening the Compose file declares,
and the symptom shows up hours later: the container is stopped cleanly (SIGTERM,
exit 0) and simply never comes back. Check these on **every** deploy, whichever
path produced it:

```bash
docker inspect frickmail-rust --format '
restart={{.HostConfig.RestartPolicy.Name}}
init={{.HostConfig.Init}}
stopTimeout={{.Config.StopTimeout}}
readonly={{.HostConfig.ReadonlyRootfs}}
user={{.Config.User}}'
docker inspect frickmail-rust \
  --format '{{range .Mounts}}{{println .Type .Destination}}{{end}}'
```

| Invariant | Required | Consequence if missing |
| --- | --- | --- |
| `restart` | `unless-stopped` | a stopped container stays down, including across a host reboot |
| `init` | `true` | no zombie reaping, and SIGTERM is not forwarded, so a graceful stop never really exits |
| `stopTimeout` | `30` | in-flight IMAP/SMTP work is killed instead of drained |
| `readonly` | `true` | — |
| tmpfs mounts | `/tmp`, `/tmp/frickmail`, `/tmp/frickmail/attachment-exports`, `/tmp/frickmail/compose-attachments` | the last two carry their own quotas (96 MiB, 72 MiB); without them attachment exports and compose staging land on the 64 MiB `/tmp` and can exhaust it |
| tmpfs ownership | `uid=10001,gid=10001,mode=0700` on `/tmp/frickmail` and both children | see below — this one silently breaks every GnuPG operation |
| `user` | `10001:10001` | — |

Prove the restart policy works by crashing the server process, **not** by
stopping the container: `docker stop` and `docker kill` both count as *manual*
stops, which `unless-stopped` deliberately ignores, so they demonstrate nothing.

```bash
docker exec frickmail-rust sh -c 'kill -9 $(for f in /proc/[0-9]*/comm; do p=${f#/proc/}; p=${p%/comm}; [ "$(cat "$f")" = frickmail-serve ] && echo "$p"; done | head -1)'
# RestartCount must climb by one and /health must recover without intervention.
docker inspect frickmail-rust --format 'restarts={{.RestartCount}} status={{.State.Status}}'
```

The runtime image ships no `pkill`, and `/proc/*/comm` truncates the process
name to 15 characters, hence matching `frickmail-serve`.

### `/tmp/frickmail` must be a mount owned by the application user

`tmp_dir` defaults to `/tmp/frickmail`, and the server creates its own
subdirectories there (`gnupg/user-<hex>` for keyrings, attachment scratch space).
The daemon only creates a directory implicitly when it has to mount something
*inside* it — and it does so **root-owned, mode 0755**. With `--cap-drop ALL` the
process has no `CAP_DAC_OVERRIDE`, so a merely-parent directory is unwritable and
every GnuPG call fails:

```
WARN fm_http::router::api_v1: v1 key listing failed:
     GnuPG home unavailable: Permission denied (os error 13)
```

which surfaces in the UI as Settings → OpenPGP reporting that the section cannot
be loaded. Mount `/tmp/frickmail` itself with `uid=10001,gid=10001,mode=0700` so
the application owns its working directory. Confirm after any deploy:

```bash
docker exec frickmail-rust ls -ldn /tmp/frickmail          # must be 10001 10001
docker exec frickmail-rust mkdir -p /tmp/frickmail/gnupg/probe   # must succeed
docker exec frickmail-rust gpg --homedir /tmp/frickmail/gnupg/probe \
  --with-colons --list-keys; echo "exit=$?"                 # must be 0
docker exec frickmail-rust rm -rf /tmp/frickmail/gnupg/probe
```

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
