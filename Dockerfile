# syntax=docker/dockerfile:1.4

# ── Stage 1: Compute dependency recipe for caching ───────────────────────────
FROM rust:1.85-slim-bookworm AS chef
RUN cargo install cargo-chef --locked
WORKDIR /app

# ── Stage 2: Prepare recipe ───────────────────────────────────────────────────
FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

# ── Stage 3: Build dependencies (heavy, cached layer) ────────────────────────
FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json
# Cook only dependencies first — this layer is cached unless Cargo.toml changes
RUN cargo chef cook --release --recipe-path recipe.json

# Build the actual binary (no github-storage to minimize binary size)
COPY . .
RUN cargo build --release --bin mcp-uor-server

# ── Stage 4: Strip binary ─────────────────────────────────────────────────────
FROM debian:bookworm-slim AS stripper
COPY --from=builder /app/target/release/mcp-uor-server /mcp-uor-server
RUN strip /mcp-uor-server

# ── Stage 5: Distroless runtime (<80 MB target) ───────────────────────────────
FROM gcr.io/distroless/cc-debian12:nonroot AS runtime

# OCI image labels
LABEL org.opencontainers.image.title="UOR Passport MCP Server"
LABEL org.opencontainers.image.description="Canonical reference implementation of the UOR Passport Envelope for MCP"
LABEL org.opencontainers.image.url="https://mcp.uor.foundation"
LABEL org.opencontainers.image.source="https://github.com/humuhumu33/uor-passport"
LABEL org.opencontainers.image.licenses="Apache-2.0"
LABEL org.opencontainers.image.vendor="UOR Foundation"

COPY --from=stripper /mcp-uor-server /mcp-uor-server

# Default configuration — can be overridden at runtime
ENV UOR_TRANSPORT=http
ENV PORT=3000
ENV UOR_PASSPORT_ENABLED=true
ENV UOR_SIGNING=disabled
ENV UOR_USE_JCS=true
ENV RUST_LOG=info

EXPOSE 3000

ENTRYPOINT ["/mcp-uor-server"]
