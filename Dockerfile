# syntax=docker/dockerfile:1
FROM docker.io/library/rust:1.97.1-bookworm AS paired
RUN apt-get update && apt-get install -y --no-install-recommends pkg-config libssl-dev protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /native
COPY native/ ./
RUN cargo build --locked --release --manifest-path signal/Cargo.toml \
    && cargo build --locked --release --manifest-path whatsapp/Cargo.toml

FROM docker.io/library/ubuntu:24.04 AS builder
# `require linen` builds linen's C shims and links its native libraries as
# part of `lake build` (libpq, OpenSSL, zlib, libsecret; unzip for the DuckDB
# archive its lakefile downloads). Liaison calls Postgres/SQL, crypto/JOSE and
# zlib for bounded native Git packs. The list is linen's own (`ci/native-deps/apt.txt`), read
# at the linen version `lakefile.lean` requires, so it cannot drift.
ARG LINEN_REF=v1.10.0
ADD https://raw.githubusercontent.com/typednotes/linen/${LINEN_REF}/ci/native-deps/apt.txt /tmp/linen-apt.txt
RUN apt-get update && apt-get install -y --no-install-recommends \
      $(sed 's/#.*//' /tmp/linen-apt.txt) \
    && rm -rf /var/lib/apt/lists/*
RUN curl -sSf https://raw.githubusercontent.com/leanprover/elan/master/elan-init.sh | sh -s -- -y --default-toolchain none
ENV PATH="/root/.elan/bin:${PATH}"

WORKDIR /app
COPY . .
RUN lake build liaison

FROM docker.io/library/ubuntu:24.04 AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates libpq5 zlib1g libssl3t64 libsqlite3-0 \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --no-create-home --uid 10001 liaison
# Lean's toolchain links a static OpenSSL whose compile-time OPENSSLDIR is
# the machine that built the toolchain, so `SSL_CTX_set_default_verify_paths`
# (what Linen's TLS client calls) finds no trust store here and every HTTPS
# call — the vault, every provider — fails with "certificate verify failed".
# OpenSSL honours these two variables over the compiled-in paths.
ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt \
    SSL_CERT_DIR=/etc/ssl/certs
WORKDIR /app
COPY --from=builder /app/.lake/build/bin/liaison /usr/local/bin/liaison
COPY --from=paired /native/signal/target/release/libliaison_signal.so /usr/local/lib/libliaison_signal.so
COPY --from=paired /native/whatsapp/target/release/libliaison_whatsapp.so /usr/local/lib/libliaison_whatsapp.so
ENV LIAISON_SIGNAL_LIBRARY=/usr/local/lib/libliaison_signal.so \
    LIAISON_WHATSAPP_LIBRARY=/usr/local/lib/libliaison_whatsapp.so
# LIAISON_PAIRED_DIR is deliberately operator-configured: mount persistent,
# encrypted storage owned by uid 10001 before enabling hosted pairing.
USER liaison
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/liaison"]
