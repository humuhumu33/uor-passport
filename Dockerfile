# syntax=docker/dockerfile:1.4

# ── Stage 1: Build ────────────────────────────────────────────────────────────
FROM rust:1.88-slim-bookworm AS builder
WORKDIR /app

COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --bin mcp-uor-server && \
    cp /app/target/release/mcp-uor-server /mcp-uor-server

# ── Stage 2: Distroless runtime ───────────────────────────────────────────────
# Binary is stripped at compile time via [profile.release] strip = true
FROM gcr.io/distroless/cc-debian12:nonroot AS runtime

LABEL org.opencontainers.image.title="UOR Passport MCP Server"
LABEL org.opencontainers.image.description="Canonical reference implementation of the UOR Passport Envelope for MCP"
LABEL org.opencontainers.image.url="https://mcp.uor.foundation"
LABEL org.opencontainers.image.source="https://github.com/humuhumu33/uor-passport"
LABEL org.opencontainers.image.licenses="Apache-2.0"
LABEL org.opencontainers.image.vendor="UOR Foundation"

COPY --from=builder /mcp-uor-server /mcp-uor-server

ENV UOR_TRANSPORT=http
ENV PORT=3000
ENV UOR_PASSPORT_ENABLED=true
ENV UOR_USE_JCS=true
ENV RUST_LOG=info

EXPOSE 3000

ENTRYPOINT ["/mcp-uor-server"]
