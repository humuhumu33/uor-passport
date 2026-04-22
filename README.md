# UOR Passport MCP Server

[UOR (Universal Object Reference)](https://uor.foundation) is an open-source standard for content-addressed, decentralized identity for digital objects. This repository is its MCP application.

Every tool response gets a permanent, content-derived fingerprint that survives re-serialization across languages and runtimes — so the receiver can prove the bytes they're holding match the bytes the sender produced. With one env var, responses are also signed with Ed25519, and verification stays local: no PKI, no network call.

Runs as a Docker image. Works with any MCP client (Claude Desktop, Cursor, Windsurf, the Inspector). Clients that don't read `_meta` see standard MCP behavior — the fingerprint sits in a field they ignore.

Built and published by [GitHub Actions](.github/workflows/docker.yml) on every push to `main`.

---

## Connect to the UOR Passport MCP server

The server is hosted at **`https://mcp.uor.foundation/mcp`**. Any MCP client can point at it directly — nothing to install locally. Responses include `_meta.uor.passport` and `_meta.uor.mcps.receipt` automatically.

<details>
<summary><b>Cursor</b> — one-click install</summary>

<br>

[![Install in Cursor](https://cursor.com/deeplink/mcp-install-dark.svg)](cursor://anysphere.cursor-deeplink/mcp/install?name=uor-passport&config=eyJ1cmwiOiJodHRwczovL21jcC51b3IuZm91bmRhdGlvbi9tY3AifQ)

Click the button to open Cursor and install automatically. Or add to `~/.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "uor-passport": { "url": "https://mcp.uor.foundation/mcp" }
  }
}
```

</details>

<details>
<summary><b>VS Code</b> — one-click install</summary>

<br>

[![Install in VS Code](https://img.shields.io/badge/VS_Code-Install_MCP_Server-0098FF?style=for-the-badge&logo=visualstudiocode&logoColor=white)](vscode:mcp/install?%7B%22name%22%3A%22uor-passport%22%2C%22serverUrl%22%3A%22https%3A//mcp.uor.foundation/mcp%22%7D)

Or run `MCP: Add Server` from the command palette (`Ctrl+Shift+P`), choose **HTTP**, and paste `https://mcp.uor.foundation/mcp`.

</details>

<details>
<summary><b>Claude Code</b> — one command</summary>

<br>

```bash
claude mcp add --transport http uor-passport https://mcp.uor.foundation/mcp
```

Verify with `claude mcp list`. Then in any Claude Code session, ask the agent to use the `uor.encode_address` tool.

</details>

<details>
<summary><b>Claude Desktop</b> — config file</summary>

<br>

Edit your `claude_desktop_config.json`:

- **macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows:** `%APPDATA%\Claude\claude_desktop_config.json`
- **Linux:** `~/.config/Claude/claude_desktop_config.json`

Add:

```json
{
  "mcpServers": {
    "uor-passport": { "url": "https://mcp.uor.foundation/mcp" }
  }
}
```

Restart Claude Desktop.

</details>

<details>
<summary><b>Other clients</b> (Windsurf, Zed, Continue, ChatGPT, agent frameworks)</summary>

<br>

The server speaks the standard MCP Streamable HTTP transport, so any compliant client works.

| Client | Where to add `https://mcp.uor.foundation/mcp` |
|---|---|
| **Windsurf** | Settings → MCP Servers → Add Server → URL |
| **Zed** | `~/.config/zed/settings.json` → `context_servers` |
| **Continue (VS Code / JetBrains)** | `~/.continue/config.json` → `mcpServers` |
| **ChatGPT** | MCP is only available through OpenAI's Deep Research Connectors today; arbitrary MCP URLs aren't user-addable in ChatGPT yet. Use the [OpenAI Agents SDK](https://github.com/openai/openai-agents-python) for MCP in code. |
| **LangChain / LlamaIndex / Agno / CrewAI / OpenAI Agents SDK** | Use each framework's MCP client adapter with the same URL |

</details>

### Verify it worked

In your agent, ask:

> *Use the `uor.encode_address` tool to fingerprint the string "hello", then show me the full response including `_meta`.*

You'll see both a `uor.passport` envelope and a `uor.mcps.receipt`:

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

That envelope is the product. Every future response your agent receives from this server carries one.

### Self-host instead

```bash
docker run --rm -p 3000:3000 \
  -e UOR_ALLOWED_HOSTS=localhost \
  -e UOR_MCPS_ENABLED=true \
  ghcr.io/humuhumu33/mcp-uor-server:latest
```

Then point your client at `http://localhost:3000/mcp` in any of the configs above.

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

**Useful for**: agent-to-agent provenance, audit logs, content-addressed deduplication, cross-session memory, detecting re-serialization drift across runtimes.

### Explicit non-goals

UOR passport delivers **content integrity** — proof that the bytes you hold are the canonical form of the object the producer produced. It is deliberately silent on:

- **Identity binding.** The public key embedded in a receipt proves a keypair signed it; it does not prove *whose* keypair. If you need *"this came from Alice, not Bob,"* layer Sigstore, JWS + X.509, OIDC, or a DID method on top — UOR is complementary to those, not a replacement.
- **Replay protection.** `verify_receipt` is stateless; the same receipt verifies forever. Track nonces or timestamps at the application layer if your protocol cares about freshness.
- **Size of addressable objects.** `encode_address` caps the canonical form at 64 KB as a DoS guard. Chunk larger payloads and fingerprint each chunk.
- **Strong revocation.** Receipts are content-addressed; the answer to key compromise is *"stop issuing receipts with that key."* Rotation is intrinsic (new server instance = new key); rollback of existing receipts isn't.

---

## Built-in tools

| Tool | Description |
|------|-------------|
| `uor.encode_address` | Compute a content address (SHA-256 over RFC 8785 JCS, with NFC normalization) for **any JSON value** — string, number, boolean, null, array, or object. Canonical form capped at 64 KB. |
| `uor.verify_passport` | Re-compute the fingerprint of a content value and compare to a claimed passport. Enforces `algorithm` field — rejects anything other than `uor-sha256-v1`. |
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
| `UOR_ALLOWED_HOSTS` | `localhost,127.0.0.1,::1` | Comma-separated allowlist for the `Host` header (DNS-rebinding defence required by the MCP spec). Public deploys must include their public hostname(s). |
| `RUST_LOG` | `info` | Log level |

---

## Development

Clone, run tests, or build from source:

```bash
git clone https://github.com/humuhumu33/uor-passport
cd uor-passport
cargo test --all-targets
cargo clippy --all-targets -- -D warnings
UOR_TRANSPORT=http cargo run
```

Stdio mode for hosts that prefer a subprocess:

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
