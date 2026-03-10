# ─────────────────────────────────────────────────────────────
# ZTLP Proto — Rust client binaries
# Multi-stage build: compile in rust:slim, run in debian:slim
#
# Build:       docker build -t ztlp-proto ./proto
# Run tests:   docker build --target test -t ztlp-proto-test ./proto && docker run --rm ztlp-proto-test
# ─────────────────────────────────────────────────────────────

# ── Stage 1: Build ──────────────────────────────────────────
FROM rust:1.78-slim-bookworm AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Cache dependency compilation — copy manifests first
COPY Cargo.toml Cargo.lock* ./

# Create a dummy src so cargo can resolve dependencies
RUN mkdir -p src/bin && \
    echo "fn main() {}" > src/bin/ztlp-node.rs && \
    echo "fn main() {}" > src/bin/ztlp-demo.rs && \
    echo "fn main() {}" > src/bin/ztlp-relay-demo.rs && \
    echo "fn main() {}" > src/bin/ztlp-interop-test.rs && \
    echo "" > src/lib.rs && \
    cargo build --release 2>/dev/null || true && \
    rm -rf src

# Now copy the real source and build
COPY . .

# Touch source files so cargo sees them as newer than the dummy
RUN find src -name '*.rs' -exec touch {} + && \
    cargo build --release

# ── Stage 1b: Test target (optional) ─────────────────────────
FROM builder AS test
RUN cargo test --release --no-run
CMD ["cargo", "test", "--release"]

# ── Stage 2: Runtime ────────────────────────────────────────
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --system --create-home ztlp

COPY --from=builder /build/target/release/ztlp-node /usr/local/bin/
COPY --from=builder /build/target/release/ztlp-demo /usr/local/bin/
COPY --from=builder /build/target/release/ztlp-relay-demo /usr/local/bin/

USER ztlp
WORKDIR /home/ztlp

# Client initiates connections — no ports exposed by default
ENTRYPOINT ["ztlp-node"]
