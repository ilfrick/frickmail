# syntax=docker/dockerfile:1

FROM rust:1.97.1-slim-bookworm@sha256:96c0af8cf054fd006435089f0076729716784ec9be485bd655de59c55df105ce AS builder

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        libssl-dev \
        pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY package.json ./
COPY frickmail-server/ ./frickmail-server/

WORKDIR /build/frickmail-server
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/build/frickmail-server/target,sharing=locked \
    cargo build --locked --release -p frickmail-server \
    && cp target/release/frickmail-server /build/frickmail-server-bin

FROM node:24-bookworm-slim@sha256:e5a8dee7bc1e6a215d224a7ef8206f7e77271bc3cabd5febf2beafac0674f174 AS ui-builder

WORKDIR /build
COPY package.json yarn.lock ./
COPY dev/ ./dev/
COPY vendors/ ./vendors/
COPY gulpfile.js ./
COPY tasks/ ./tasks/
COPY snappymail/v/0.0.0/app/templates ./snappymail/v/0.0.0/app/templates
COPY plugins/frickmail-user ./plugins/frickmail-user
COPY plugins/frickmail-theme ./plugins/frickmail-theme
COPY plugins/login-oidc/LoginOIDC.js ./plugins/login-oidc/LoginOIDC.js
COPY plugins/calendar/js ./plugins/calendar/js
COPY plugins/contacts-sync/js ./plugins/contacts-sync/js
COPY snappymail/v/0.0.0/static ./snappymail/v/0.0.0/static
COPY snappymail/v/0.0.0/themes ./snappymail/v/0.0.0/themes
COPY snappymail/v/0.0.0/app/localization ./snappymail/v/0.0.0/app/localization
COPY frickmail-ui/build.mjs ./frickmail-ui/build.mjs

RUN corepack enable \
    && corepack yarn install --frozen-lockfile --ignore-scripts \
    && yarn gulp js \
    && node frickmail-ui/build.mjs /build/frickmail-static

FROM debian:bookworm-slim@sha256:abd67ffcfa541b485a3dff59865ab629aa048a6c613e639d36e7456b0b229241 AS runtime

ARG FRICKMAIL_UID=10001
ARG FRICKMAIL_GID=10001

LABEL org.opencontainers.image.title="Frickmail Rust server" \
      org.opencontainers.image.description="Production runtime image for the Frickmail Rust migration server" \
      org.opencontainers.image.source="https://github.com/ilfrick/frickmail" \
      org.opencontainers.image.licenses="AGPL-3.0-or-later"

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        gnupg \
        libssl3 \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid "${FRICKMAIL_GID}" frickmail \
    && useradd --uid "${FRICKMAIL_UID}" --gid "${FRICKMAIL_GID}" \
        --home-dir /nonexistent --no-create-home --shell /usr/sbin/nologin frickmail \
    && install -d -o frickmail -g frickmail /usr/share/frickmail/static

COPY --from=builder /build/frickmail-server-bin /usr/local/bin/frickmail-server
COPY --from=ui-builder /build/frickmail-static /usr/share/frickmail/static

ENV FRICKMAIL__BIND_ADDR="0.0.0.0:8888" \
    FRICKMAIL__BASE_URL="http://localhost:8888" \
    FRICKMAIL__STATIC_ROOT="/usr/share/frickmail/static" \
    RUST_LOG="frickmail_server=info,fm_http=info,tower_http=info"

USER frickmail:frickmail
EXPOSE 8888

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["curl", "--fail", "--silent", "--show-error", "http://127.0.0.1:8888/health"]

ENTRYPOINT ["/usr/local/bin/frickmail-server"]
