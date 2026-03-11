# ─────────────────────────────────────────────────────────────
# ZTLP Proto — Rust client binaries (multi-stage)
#
# Build:   docker build -t ztlp-proto ./proto
# Run:     docker run --rm ztlp-proto --help
# Test:    docker build --target test -t ztlp-proto-test ./proto && docker run --rm ztlp-proto-test
# ─────────────────────────────────────────────────────────────

# ── Stage 1: Build ──────────────────────────────────────────
FROM rust:1.78-slim-bookworm AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Cache dependency compilation — copy manifests first
COPY Cargo.toml Cargo.lock* ./

# Create dummy sources so cargo can resolve/compile dependencies
RUN mkdir -p src/bin && \
    echo "fn main() {}" > src/bin/ztlp-cli.rs && \
    echo "fn main() {}" > src/bin/ztlp-inspect.rs && \
    echo "fn main() {}" > src/bin/ztlp-load.rs && \
    echo "fn main() {}" > src/bin/ztlp-fuzz.rs && \
    echo "fn main() {}" > src/bin/ztlp-throughput.rs && \
    echo "fn main() {}" > src/bin/ztlp-node.rs && \
    echo "fn main() {}" > src/bin/ztlp-demo.rs && \
    echo "fn main() {}" > src/bin/ztlp-relay-demo.rs && \
    echo "fn main() {}" > src/bin/ztlp-interop-test.rs && \
    echo "fn main() {}" > src/bin/ztlp-bench.rs && \
    echo "fn main() {}" > src/bin/ztlp-edge-cases.rs && \
    echo "fn main() {}" > src/bin/ztlp-gateway-e2e.rs && \
    echo "fn main() {}" > src/bin/ztlp-handshake-interop.rs && \
    echo "fn main() {}" > src/bin/ztlp-ns-interop.rs && \
    echo "fn main() {}" > src/bin/ztlp-pipeline-interop.rs && \
    echo "fn main() {}" > src/bin/ztlp-rat-interop.rs && \
    echo "" > src/lib.rs && \
    cargo build --release 2>/dev/null || true && \
    rm -rf src

# Copy real source and build
COPY . .
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

# Copy all release binaries
COPY --from=builder /build/target/release/ztlp /usr/local/bin/
COPY --from=builder /build/target/release/ztlp-inspect /usr/local/bin/
COPY --from=builder /build/target/release/ztlp-load /usr/local/bin/
COPY --from=builder /build/target/release/ztlp-fuzz /usr/local/bin/
COPY --from=builder /build/target/release/ztlp-throughput /usr/local/bin/

USER ztlp
WORKDIR /home/ztlp

# Client initiates connections — no ports exposed by default
ENTRYPOINT ["ztlp"]
