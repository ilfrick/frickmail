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

ENV FRICKMAIL__BIND_ADDR="0.0.0.0:8888" \
    FRICKMAIL__BASE_URL="http://localhost:8888" \
    FRICKMAIL__STATIC_ROOT="/usr/share/frickmail/static" \
    RUST_LOG="frickmail_server=info,fm_http=info,tower_http=info"

USER frickmail:frickmail
EXPOSE 8888

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["curl", "--fail", "--silent", "--show-error", "http://127.0.0.1:8888/health"]

ENTRYPOINT ["/usr/local/bin/frickmail-server"]
