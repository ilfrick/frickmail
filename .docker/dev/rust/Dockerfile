FROM rust:1-slim-bookworm

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        git \
        pkg-config \
        libssl-dev \
    && rm -rf /var/lib/apt/lists/*

RUN rustup component add clippy

WORKDIR /workspace/frickmail-server

CMD ["cargo", "check", "--workspace"]
