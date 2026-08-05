# Build and deploy Frickmail

## Runtime status

The production image built by `.docker/release/Dockerfile` is the current
SnappyMail/PHP compatibility runtime. The Rust backend is being migrated and
validated in `frickmail-server/`, but it is not yet packaged as a standalone
production replacement. Deploying the current `master` image updates the
supported compatibility runtime; it does not remove PHP.

## Prerequisites

- Docker Engine with the Compose v2 plugin
- A clone of this repository on the `master` branch
- A populated `.env` containing the deployment secrets referenced by
  `docker-compose.frickmail.yml`
- Enough free space for an application-data and PostgreSQL backup

Run all commands from the repository root.

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

For local development, the current binary is `frickmail-server`. A production
Rust-only rollout must wait for a dedicated release image, complete action and
session/CSRF parity, persistent-data migration testing, and an exercised
rollback path.
