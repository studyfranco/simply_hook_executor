# Build stage
FROM rust:slim as builder

WORKDIR /app

# Copy the source code
COPY Cargo.toml Cargo.lock* ./
COPY src src
COPY static static

RUN set -x \
    && apt update \
    && DEBIAN_FRONTEND=noninteractive apt install -y build-essential ca-certificates pkg-config libssl-dev git --no-install-recommends \
    && apt clean autoclean -y \
    && rm -rf /var/cache/* /var/lib/apt/lists/* /var/log/* /var/tmp/* /tmp/*

# Build the release binary
RUN cargo build --release

# Runtime stage
FROM ghcr.io/studyfranco/docker-baseimages-debian:testing

RUN set -x \
    && apt update \
    && apt dist-upgrade -y \
    && apt autopurge -yy \
    && apt clean autoclean -y \
    && rm -rf /var/cache/* /var/lib/apt/lists/* /var/log/* /var/tmp/* /tmp/*

# Install required certificates for TLS
RUN set -x \
    && apt update \
    && DEBIAN_FRONTEND=noninteractive apt install -y ca-certificates libsqlite3-0 --no-install-recommends \
    && apt clean autoclean -y \
    && rm -rf /var/cache/* /var/lib/apt/lists/* /var/log/* /var/tmp/* /tmp/* \
    && mkdir /app

WORKDIR /app

# Copy the binary and static files
COPY --from=builder /app/target/release/simply_hook_executor /usr/local/bin/simply_hook_executor
COPY static /app/static

# Expose API/Frontend port
EXPOSE 3000

# Default environment configuration
ENV DATABASE_URL=sqlite://data/simply_hook_executor.db?mode=rwc
ENV RUST_LOG=info
# Environment variables hook sub-processes inherit; everything else is cleared before each spawn.
ENV ALLOWED_ENV_VARS=PATH,LANG,TERM
ENV LOG_RETENTION_DAYS=30

# Define command
CMD ["simply_hook_executor"]
