# syntax=docker/dockerfile:1
FROM docker.io/library/ubuntu:24.04 AS builder
# `unzip` is here for `linen`'s own lakefile, not `liaison`'s: `require linen`
# downloads a pinned DuckDB release archive at lakefile-elaboration time
# (i.e. as part of `lake build`, before any of `liaison`'s own code runs) and
# unpacks it by shelling out to `unzip`. `zlib1g-dev`/`libsecret-1-dev` are
# likewise for `linen`'s own FFI (`ffi/zlib.c`, `ffi/keychain.c`) — `liaison`
# only calls into `linen`'s Postgres/SQL and crypto/JOSE modules, but Lake
# still builds every one of `linen`'s `extern_lib` object files as part of
# `lake build`, so all of its native dependencies are needed here too, not
# just libpq's and OpenSSL's. Modeled on `ledger/Dockerfile` (same `linen`
# dependency, same concerns), confirmed by reading it.
RUN apt-get update && apt-get install -y --no-install-recommends \
      curl ca-certificates git libpq-dev libssl-dev pkg-config build-essential unzip \
      zlib1g-dev libsecret-1-dev \
    && rm -rf /var/lib/apt/lists/*
RUN curl -sSf https://raw.githubusercontent.com/leanprover/elan/master/elan-init.sh | sh -s -- -y --default-toolchain none
ENV PATH="/root/.elan/bin:${PATH}"

WORKDIR /app
COPY . .
RUN lake build liaison

FROM docker.io/library/debian:bookworm-slim AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates libpq5 \
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
USER liaison
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/liaison"]
