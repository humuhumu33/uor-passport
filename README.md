# UOR Passport MCP Server

[UOR (Universal Object Reference)](https://uor.foundation) is an open-source standard for content-addressed, decentralized identity for digital objects. This repository is its MCP application.

Every tool response gets a permanent, content-derived fingerprint that survives re-serialization across languages and runtimes — so the receiver can prove the bytes they're holding match the bytes the sender produced. With one env var, responses are also signed with Ed25519, and verification stays local: no PKI, no network call.

Runs as a Docker image. Works with any MCP client (Claude Desktop, Cursor, Windsurf, the Inspector). Clients that don't read `_meta` see standard MCP behavior — the fingerprint sits in a field they ignore.

Built and published by [GitHub Actions](.github/workflows/docker.yml) on every push to `main`.

---

## Run it

```bash
docker run --rm -p 3000:3000 \
  -e UOR_MCPS_ENABLED=true \
  ghcr.io/humuhumu33/mcp-uor-server:latest
```

On startup you'll see:

```
╔══════════════════════════════════════════════════════╗
║         UOR Passport MCP Server v0.1.0               ║
║  Endpoint : https://mcp.uor.foundation               ║
║  Transport: http                                     ║
║  Passport : enabled (uor-sha256-v1, JCS)             ║
║  MCPS     : enabled (Ed25519 L1) — anchored receipts ║
╚══════════════════════════════════════════════════════╝
INFO mcp_uor_server: MCP server ready — listening on http://0.0.0.0:3000/mcp
```

Health check:

```bash
curl http://localhost:3000/health
# → {"status":"ok","service":"mcp-uor-server","version":"0.1.0"}
```

---

## Try it in the MCP Inspector

```bash
npx @modelcontextprotocol/inspector
```

Transport = **Streamable HTTP**, URL = `http://localhost:3000/mcp`, **Connect**. Call `encode_address` with `{"content":"hello"}`. Expand `_meta` on the response:

```json
{
  "_meta": {
    "uor.passport": {
      "version": "uor.passport.v1",
      "fingerprint": "5c8f96c88a648178c09bd73764639bb2cf4d8d5c8f72f077f0e872cab6a6be6f",
      "algorithm": "uor-sha256-v1",
      "content_type": "application/json",
      "length": 438,
      "timestamp": "2026-04-21T19:59:02.532971200+00:00"
    },
    "uor.mcps.receipt": {
      "passport": { "...": "same fingerprint as above" },
      "signature": "3FB+nfc9Fy2er4ThCaBfXuMoyzahO1ZcZlaftiRp...",
      "public_key": "Y/JdKNj9CIhpSBPBJ0I9oKBXDJnCwZ5/xtvpsjIc8PY=",
      "nonce": "BH25XxMa3ouKPoHHAJKw2Q==",
      "timestamp": "2026-04-21T20:23:24.435930800+00:00",
      "trust_level": "L1",
      "algorithm": "ed25519"
    }
  }
}
```

---

## Background

MCP tool responses don't stay in one place. A Python agent emits JSON, a Rust server receives it, a Node agent re-parses and forwards it. Every re-serialization can change the raw bytes — `1.0` becomes `1`, key order shifts, string escapes get rewritten — so any scheme that hashes the JSON bytes breaks on the first round-trip.

[SEP-2395 (MCPS)](https://github.com/modelcontextprotocol/modelcontextprotocol/pull/2395) proposed signed receipts, replay protection, and agent passports for MCP. It was closed after its canonicalization-sensitive signing scheme was shown to produce different bytes in Node.js and Python — the same reason naïve "hash the JSON" approaches don't work across runtimes.

A [February 2026 audit of 518 public MCP servers](https://tapauth.ai/blog/518-mcp-servers-scanned-41-percent-no-auth) found 41% had no authentication at all, and 156 exposed callable tools to anyone on the internet. It's not that agent developers didn't want integrity — the primitives to get it safely across runtimes didn't exist yet.

### The idea

Fingerprint the **canonical form** of an object — RFC 8785 JCS — not the raw bytes. Same object, same 256-bit hash, in any runtime with a JCS library. A signature over that hash survives re-serialization because the hash does.

The server drops the fingerprint into every tool response at `_meta."uor.passport"`. Set `UOR_MCPS_ENABLED=true` and it also attaches an Ed25519-signed receipt built on top. Verification is local — the receipt carries its own public key.

### The failure mode

| Input                       | Python `json.dumps` | Node `JSON.stringify` | Same bytes? |
|-----------------------------|---------------------|-----------------------|:-----------:|
| `{"value": 1.0}`            | `{"value":1.0}`     | `{"value":1}`         | ❌          |
| `"café"` (default settings) | `"caf\u00e9"`       | `"café"`              | ❌          |

Hash those bytes and sign them, and the signature fails the first time any agent parses, mutates, or forwards the object.

### The resolution

| Issue SEP-2395 hit                                | Resolution in this server                                                |
|---------------------------------------------------|--------------------------------------------------------------------------|
| Canonical JSON diverged across Node.js and Python | JCS normalizes structure; byte-identical fingerprint in every runtime    |
| Signatures broke on floats, key order, escapes    | Signature is over the fingerprint, not the bytes                         |
| PKI / trust anchors were the attack surface       | No PKI — receipt embeds its own public key; verification is local        |
| Downgrade attack on signed-mode fallback          | Fingerprint is the address — there is no unsigned mode to fall back to   |
| Fail-open revocation lists                        | Receipts are content-addressed; nothing to revoke                        |

### JCS normalizes numbers, not just keys

```
server fp of {"x": 1}:   5041bf1f713df204784353e82f6a4a53…
server fp of {"x": 1.0}: 5041bf1f713df204784353e82f6a4a53…
```

Plain JSON serializers in Python, Node, and Go each produce different bytes for these two inputs. JCS fingerprints them to the same 256-bit hash. It's a small property. It's also the reason cross-runtime signed receipts can exist at all.

---

## Verify it yourself

Three scripts, three claims, each self-contained.

### 1. Cross-runtime demo — the SEP-2395 failure mode resolved

```bash
pip install httpx cryptography
python scripts/demo_mcps_cross_runtime.py --url http://localhost:3000/mcp
```

Excerpt from an actual run:

```text
Python json.dumps:   {"value":1.0,"flag":true,"id":42}
                     → SHA-256: a70aa6c8f536c127cf868aec837ce113…
Node JSON.stringify: {"value":1,"flag":true,"id":42}
                     → SHA-256: ad4d0d5642fc54d7fd2456585a49008a…
❌ Plain JSON bytes DIVERGE — signing these hashes is brittle.

Python UOR fingerprint:  d41ea271a46d0b148a3007c01f3c398924c3816ca489c4bacc1b668c4658f82f
Rust server fingerprint: d41ea271a46d0b148a3007c01f3c398924c3816ca489c4bacc1b668c4658f82f
✅ Python ≡ Rust — byte-identical 256-bit fingerprint.

Server verify_receipt:  valid=True
Offline Python verify:  valid=True   ← Ed25519 verified in pure Python using only the receipt's embedded public key
```

The offline line uses only the public key embedded in the receipt itself — `cryptography.hazmat` + 15 lines of Python. No network, no PKI.

### 2. Spec conformance

```bash
python scripts/stress_test.py --url http://localhost:3000/mcp --n 500
```

| # | Property | Verified by | Result |
|---|---|---|---|
| 1 | Every tool response carries `_meta."uor.passport"` | 500 calls | ✅ |
| 2 | Deterministic fingerprinting | 100 identical inputs → 1 unique hash | ✅ |
| 3 | JCS key-order independence | 3 key permutations → 1 fingerprint | ✅ |
| 4 | Tamper-evident | 50 byte mutations, all detected | ✅ |
| 5 | `uor-sha256-v1` ≡ `SHA-256(JCS(payload))` | Independent re-computation matches byte-for-byte | ✅ |
| 6 | 1000-character content limit enforced | 1000 accepted, 1001 rejected | ✅ |
| 7 | Concurrent safety | 50 parallel clients → 1 fingerprint, 0 errors | ✅ |
| 8 | Sub-millisecond fingerprinting | p50 = 0.61 ms, p95 = 0.89 ms, p99 = 1.06 ms | ✅ |

### 3. Article-level conformance

```bash
python scripts/article_conformance.py --url http://localhost:3000/mcp
```

Validates every claim in the UOR Foundation's *A universal data passport for your AI agent* article — 16/16, including the specific SEP-2395 cross-runtime failure mode.

Everything in this README is reproducible by the reader. If a claim doesn't hold, the harness exits non-zero and the README is wrong.

---

## Security model

Two layers. They answer different questions.

**`uor.passport` (always on)** — integrity. Proves the response content is the same content the server produced, regardless of how the JSON is re-serialized in transit. No keys. No PKI.

**`uor.mcps.receipt` (opt-in, `UOR_MCPS_ENABLED=true`)** — authentication. Proves *this server instance* signed the response. Each instance generates a fresh Ed25519 keypair on startup; the public key is embedded in every receipt. Old receipts remain verifiable forever via their embedded key.

**Useful for**: agent-to-agent provenance, audit logs, replay detection (nonce), content-addressed deduplication, cross-session memory.

**Not a substitute for**: binding identity to a known organization (use Sigstore / JWS with an X.509 chain for that). Strong revocation (content-addressed receipts are valid forever; the answer to key compromise is "stop issuing receipts with that key" — rotation is intrinsic, rollback isn't). High-availability key persistence across restarts (out of scope for v0.1).

---

## Built-in tools

| Tool | Description |
|------|-------------|
| `uor.encode_address` | Compute a content address (SHA-256 over JCS) for a UTF-8 string (≤ 1000 chars) |
| `uor.verify_passport` | Re-compute the fingerprint of a content and compare to a claimed passport |
| `uor.verify_receipt` | Verify an Ed25519-signed MCPS receipt. Stateless, local-only — no PKI, no network |

---

## Configuration

| Environment variable | Default | Description |
|---|---|---|
| `UOR_PASSPORT_ENABLED` | `true` | Attach passport to every tool response |
| `UOR_MCPS_ENABLED` | `false` | Attach Ed25519-signed MCPS receipt to every tool response |
| `UOR_MCPS_TRUST_LEVEL` | `L1` | Trust level stamped on issued receipts (informational) |
| `UOR_USE_JCS` | `true` | Use RFC 8785 JCS canonicalization |
| `UOR_TRANSPORT` | `stdio` | `stdio` or `http` |
| `PORT` | `3000` | HTTP listen port |
| `UOR_MCP_HOST` | `https://mcp.uor.foundation` | Endpoint URL logged on startup |
| `RUST_LOG` | `info` | Log level |

---

## Client setup

**Claude Desktop / Cursor / Windsurf** (HTTP):

```json
{
  "mcpServers": {
    "uor-passport": { "url": "http://localhost:3000/mcp" }
  }
}
```

**Stdio** (for hosts that prefer a subprocess):

```json
{
  "mcpServers": {
    "uor-passport": {
      "command": "docker",
      "args": ["run", "-i", "--rm", "-e", "UOR_TRANSPORT=stdio",
               "ghcr.io/humuhumu33/mcp-uor-server:latest"]
    }
  }
}
```

**Build from source**:

```bash
cargo install --git https://github.com/humuhumu33/uor-passport mcp-uor-server
UOR_TRANSPORT=http mcp-uor-server
```

---

## Development

```bash
git clone https://github.com/humuhumu33/uor-passport
cd uor-passport
cargo test --all-targets
cargo clippy --all-targets -- -D warnings
UOR_TRANSPORT=http cargo run
```

---

## Architecture

```
MCP Client (Claude, Cursor, Windsurf)
        │  JSON-RPC over stdio or HTTP
        ▼
UorPassportServer (ServerHandler)
        │  call_tool() override:
        │    1. Route to UorTools via ToolRouter
        │    2. Attach uor.passport envelope  (always when enabled)
        │    3. Attach uor.mcps.receipt       (when UOR_MCPS_ENABLED)
        ▼
CallToolResult {
  content,
  _meta: {
    "uor.passport":     { ... },     // always (when enabled)
    "uor.mcps.receipt": { ... }      // only when UOR_MCPS_ENABLED
  }
}
```

### Dependencies

| Crate | Role |
|---|---|
| `rmcp 1.5` | Official MCP Rust SDK |
| `serde_json_canonicalizer 0.2` | RFC 8785 JCS canonicalization |
| `sha2 0.10` | SHA-256 |
| `ed25519-dalek 2` | Ed25519 signatures (feature-gated) |
| `axum 0.8` | HTTP server for streamable HTTP transport |
| `tokio 1` | Async runtime |

---

## A note on scope

Small on purpose. The server does one thing: attach a fingerprint to every MCP response, and optionally sign it. If you need identity-to-organization binding or a production PKI, build those on top — or reach for Sigstore. Most of what made MCPS compelling turns out to fall out of a stable fingerprint, with almost none of the infrastructure.

MCP is one transport. The broader standard — content-addressed identity for any digital object — is maintained by the [UOR Foundation](https://uor.foundation). This repository is the MCP surface of that standard, nothing more.

The whole repo is about 250 KB of source. Three scripts falsify every claim in this README in under a minute. That's the product.

---

## License

Apache-2.0 — see [LICENSE](LICENSE).

Built on the [Model Context Protocol](https://modelcontextprotocol.io) and the [UOR Foundation](https://uor.foundation).
