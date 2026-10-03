# Same pinned toolchain the release image builds with. This tag used to float
# (`rust:1-slim-bookworm`), which made the lint gate unreproducible: a newer
# clippy appeared upstream and failed `cargo clippy --workspace --all-targets
# -- -D warnings` on `clippy::double_must_use`, which `#[async_trait]`'s
# expansion triggers. CI must lint with the compiler that produces the shipped
# binary, so upgrade both Dockerfiles together and deliberately.
FROM rust:1.97.1-slim-bookworm@sha256:96c0af8cf054fd006435089f0076729716784ec9be485bd655de59c55df105ce

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        git \
        gnupg \
        pkg-config \
        libssl-dev \
    && rm -rf /var/lib/apt/lists/*

RUN rustup component add clippy rustfmt

WORKDIR /workspace/frickmail-server

CMD ["cargo", "check", "--workspace"]
