# UOR Passport MCP Server

The canonical reference implementation of the **UOR Passport Envelope** — a transparent, additive content-fingerprinting layer for every MCP tool response.

Every tool call response gets a permanent, content-derived `uor.passport` envelope containing a 256-bit SHA-256 fingerprint, computed using RFC 8785 JCS canonicalization. Zero changes required for existing MCP clients.

---

## One-Command Deployment

```bash
docker run -p 3000:3000 \
  -e GITHUB_TOKEN=ghp_...        \
  -e UOR_PASSPORT_ENABLED=true   \
  -e UOR_SIGNING=disabled        \
  ghcr.io/humuhumu33/mcp-uor-server:latest
```

Server is immediately available at `http://localhost:3000/mcp`.

**Canonical public endpoint:** `https://mcp.uor.foundation`

---

## Validate in 60 Seconds

**1. Start the server:**
```bash
docker run -p 3000:3000 ghcr.io/humuhumu33/mcp-uor-server:latest
```

**2. Verify health:**
```bash
curl http://localhost:3000/health
# → {"status":"ok","service":"mcp-uor-server","version":"0.1.0"}
```

**3. Connect Claude Desktop** — add to `claude_desktop_config.json`:
```json
{
  "mcpServers": {
    "uor-passport": {
      "url": "http://localhost:3000/mcp"
    }
  }
}
```

**4. Test automatic passport attachment:**
Use the `uor.encode_address` tool with `content = "hello"` in Claude. Every response will include a `uor.passport` envelope in `_meta`.

**5. Verify a passport:**
Use `uor.verify_passport` with the content and envelope returned in step 4.

---

## What Is the UOR Passport Envelope?

The UOR Passport Envelope is a **strictly additive, backward-compatible metadata extension** to MCP tool responses. It is injected into the `_meta` field of every `CallToolResult`:

```json
{
  "content": [{"type": "text", "text": "..."}],
  "_meta": {
    "uor.passport": {
      "version": "uor.passport.v1",
      "fingerprint": "e3b0c44298fc1c149afb...  (64 hex chars)",
      "algorithm": "uor-sha256-v1",
      "content_type": "application/json",
      "length": 42,
      "timestamp": "2026-04-21T17:31:00Z"
    }
  }
}
```

### Fingerprint computation

```
tool response content (Vec<Content>)
  → serialize to JSON
  → JCS-canonicalize (RFC 8785)     ← order-independent
  → SHA-256
  → 64-char lowercase hex string
```

**JCS (RFC 8785)** ensures that `{"a":1,"b":2}` and `{"b":2,"a":1}` produce identical fingerprints. This makes passports stable across serializers, languages, and runtimes.

### What gets fingerprinted

Only the `content` array (the user-visible payload). The `_meta` field is excluded to avoid circularity. This means the fingerprint covers exactly what the client sees and uses.

---

## Built-In Tools

| Tool | Description |
|------|-------------|
| `uor.encode_address` | Compute a UOR content address (SHA-256) for a UTF-8 string (≤ 1000 chars) |
| `uor.verify_passport` | Verify a UOR Passport Envelope against its claimed content |
| `uor.sign` | *(v0.2 placeholder)* Sign content with an Ed25519 identity key |

---

## Configuration Reference

| Environment Variable | Default | Description |
|---|---|---|
| `UOR_PASSPORT_ENABLED` | `true` | Attach passport to every tool response |
| `UOR_SIGNING` | `disabled` | Enable `uor.sign` tool (`true` / `ed25519`) |
| `UOR_USE_JCS` | `true` | Use RFC 8785 JCS canonicalization |
| `UOR_TRANSPORT` | `stdio` | Transport mode: `stdio` or `http` |
| `PORT` | `3000` | HTTP listen port |
| `RATE_LIMIT` | `100` | Requests per second (0 = unlimited) |
| `UOR_MCP_HOST` | `https://mcp.uor.foundation` | Canonical endpoint URL (logged on startup) |
| `GITHUB_TOKEN` | — | GitHub PAT for passport persistence storage |
| `UOR_GITHUB_OWNER` | `humuhumu33` | GitHub repo owner for storage |
| `UOR_GITHUB_REPO` | `uor-passport` | GitHub repo name for storage |
| `RUST_LOG` | `info` | Log level (`trace`, `debug`, `info`, `warn`, `error`) |

---

## MCP Host Integration

### Claude Desktop / Cursor / Windsurf

```json
{
  "mcpServers": {
    "uor-passport": {
      "url": "http://localhost:3000/mcp"
    }
  }
}
```

### Stdio mode (Claude Desktop native)

```json
{
  "mcpServers": {
    "uor-passport": {
      "command": "docker",
      "args": ["run", "-i", "--rm",
               "-e", "UOR_TRANSPORT=stdio",
               "ghcr.io/humuhumu33/mcp-uor-server:latest"]
    }
  }
}
```

### cargo install

```bash
cargo install --git https://github.com/humuhumu33/uor-passport mcp-uor-server
UOR_TRANSPORT=http mcp-uor-server
```

---

## Local Development

```bash
# Clone and build
git clone https://github.com/humuhumu33/uor-passport
cd uor-passport
cargo build

# Run in HTTP mode
UOR_TRANSPORT=http cargo run

# Run in stdio mode (for MCP hosts)
cargo run

# Run tests
cargo test --all-targets

# Lint
cargo clippy --all-targets -- -D warnings
```

### docker-compose (with GITHUB_TOKEN)

```bash
GITHUB_TOKEN=ghp_... docker-compose up
```

---

## Technical Benefits

| Property | Description |
|---|---|
| **Persistent identity** | Same content always produces the same fingerprint across time, machines, and languages |
| **Provenance** | Every response is cryptographically linked to its content |
| **Deduplication** | Fingerprints enable content-addressed caching and deduplication at the agent layer |
| **Auditability** | Timestamps and fingerprints form a replayable audit trail |
| **JCS compatibility** | RFC 8785 canonicalization ensures cross-platform fingerprint stability |
| **Backward compatible** | Non-UOR clients see unmodified MCP behavior; `_meta` is an optional extension |

---

## Architecture

```
MCP Client (Claude, Cursor, Windsurf)
        │  JSON-RPC over stdio or HTTP
        ▼
UorPassportServer (implements ServerHandler)
        │  call_tool() override
        │    1. Route to UorTools via ToolRouter
        │    2. Attach passport envelope (non-failing)
        │    3. Optional: persist to GitHub (background, best-effort)
        ▼
CallToolResult { content, _meta: { "uor.passport": { ... } } }
```

### Dependency stack

| Crate | Role |
|---|---|
| `rmcp 1.5` | Official MCP Rust SDK (server, macros, HTTP transport) |
| `uor-foundation 0.3` | UOR ontology types and content addressing |
| `serde_json_canonicalizer 0.2` | RFC 8785 JCS canonicalization |
| `sha2 0.10` | SHA-256 fingerprint computation |
| `axum 0.8` | HTTP server for streamable HTTP transport |

---

## License

Apache-2.0 — see [LICENSE](LICENSE).

Built on the [UOR Foundation](https://uor.foundation) and the [Model Context Protocol](https://modelcontextprotocol.io).
