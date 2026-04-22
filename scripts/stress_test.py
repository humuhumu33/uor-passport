#!/usr/bin/env python3
"""
UOR Passport MCP stress / validation harness.

Exercises every promise in the UOR Passport Envelope spec against a running
server. Exits non-zero on any violation.

Usage:
    pip install httpx
    python scripts/stress_test.py [--url http://localhost:8080/mcp] [--n 1000]
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import itertools
import json
import random
import statistics
import string
import sys
import time
import uuid
from dataclasses import dataclass, field
from typing import Any

import httpx


@dataclass
class Stats:
    passed: int = 0
    failed: int = 0
    failures: list[str] = field(default_factory=list)
    latencies_ms: list[float] = field(default_factory=list)

    def ok(self, name: str) -> None:
        self.passed += 1
        print(f"  ✓ {name}")

    def fail(self, name: str, reason: str) -> None:
        self.failed += 1
        self.failures.append(f"{name}: {reason}")
        print(f"  ✗ {name}: {reason}")


class McpClient:
    """Minimal streamable-HTTP MCP client. Handles both JSON and SSE responses."""

    def __init__(self, url: str):
        self.url = url
        self.session_id: str | None = None
        self.client = httpx.AsyncClient(timeout=30.0)
        self._next_id = itertools.count(1)

    async def close(self) -> None:
        await self.client.aclose()

    async def _send(self, method: str, params: dict | None = None) -> dict:
        body = {"jsonrpc": "2.0", "id": next(self._next_id), "method": method}
        if params is not None:
            body["params"] = params
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        }
        if self.session_id:
            headers["Mcp-Session-Id"] = self.session_id

        resp = await self.client.post(self.url, json=body, headers=headers)
        resp.raise_for_status()
        if sid := resp.headers.get("mcp-session-id"):
            self.session_id = sid

        ctype = resp.headers.get("content-type", "")
        if "text/event-stream" in ctype:
            for line in resp.text.splitlines():
                if line.startswith("data:"):
                    payload = line[5:].strip()
                    if not payload:
                        continue
                    try:
                        return json.loads(payload)
                    except json.JSONDecodeError:
                        continue
            raise RuntimeError(f"no data event in SSE response: {resp.text[:500]!r}")
        return resp.json()

    async def initialize(self) -> dict:
        result = await self._send(
            "initialize",
            {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "uor-stress", "version": "0.1"},
            },
        )
        # MCP requires notifications/initialized after init
        body = {"jsonrpc": "2.0", "method": "notifications/initialized"}
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        }
        if self.session_id:
            headers["Mcp-Session-Id"] = self.session_id
        await self.client.post(self.url, json=body, headers=headers)
        return result

    async def list_tools(self) -> dict:
        return await self._send("tools/list")

    async def call_tool(self, name: str, arguments: dict) -> dict:
        return await self._send("tools/call", {"name": name, "arguments": arguments})


async def new_session(url: str) -> McpClient:
    c = McpClient(url)
    await c.initialize()
    return c


def extract_passport(resp: dict) -> dict | None:
    """Return the `_meta.uor.passport` envelope attached to every tool response."""
    result = resp.get("result") or {}
    meta = result.get("_meta") or result.get("meta")
    if not meta:
        return None
    return meta.get("uor.passport")


def extract_structured(resp: dict) -> dict | None:
    """Return the structured JSON payload the tool emits.

    Our tools emit two `text` content items: [0] a human summary, [1] a JSON
    string with the structured result. Parse [1] if it looks like JSON.
    """
    result = resp.get("result") or {}
    for item in result.get("content", []):
        if item.get("type") == "text":
            text = item.get("text", "")
            if text.startswith("{"):
                try:
                    return json.loads(text)
                except json.JSONDecodeError:
                    continue
    return None


def jcs_canonicalize(value: Any) -> bytes:
    """Minimal RFC 8785 JCS canonicalization for validation only.
    Handles the cases this test emits: sorted keys, compact separators."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


# ── Tests ────────────────────────────────────────────────────────────────────


async def test_every_response_has_passport(c: McpClient, s: Stats, n: int) -> None:
    print(f"\n[1/8] Every response carries a passport (n={n})")
    for i in range(n):
        t0 = time.perf_counter()
        resp = await c.call_tool("encode_address", {"content": f"msg-{i}-{uuid.uuid4()}"})
        s.latencies_ms.append((time.perf_counter() - t0) * 1000)
        if not extract_passport(resp):
            s.fail("passport-present", f"missing on call {i}: {resp}")
            return
    s.ok(f"all {n} responses have _meta.uor.passport")


async def test_deterministic(c: McpClient, s: Stats, n: int = 100) -> None:
    print(f"\n[2/8] Deterministic — same input → same fingerprint (n={n})")
    fps = set()
    for _ in range(n):
        r = await c.call_tool("encode_address", {"content": "the quick brown fox"})
        p = extract_passport(r)
        if p:
            fps.add(p["fingerprint"])
    if len(fps) == 1:
        s.ok(f"{n} calls → 1 unique fingerprint: {next(iter(fps))[:16]}…")
    else:
        s.fail("determinism", f"got {len(fps)} distinct fingerprints")


async def test_key_order_independence(c: McpClient, s: Stats) -> None:
    print("\n[3/8] JCS key-order independence")
    # verify_passport accepts arbitrary JSON content; we test that semantically
    # identical objects with different key order produce the same fingerprint
    obj_a = {"type": "text", "text": "hello", "n": 42}
    obj_b = {"text": "hello", "n": 42, "type": "text"}
    obj_c = {"n": 42, "type": "text", "text": "hello"}

    async def fp_of(obj: dict) -> str | None:
        # verify_passport's structured response exposes `computed_fingerprint`
        # even when validation fails — use that to extract the server's hash.
        envelope = {
            "fingerprint": "0" * 64,
            "length": 0,
            "version": "uor.passport.v1",
            "algorithm": "uor-sha256-v1",
        }
        r = await c.call_tool("verify_passport", {"content": obj, "passport": envelope})
        structured = extract_structured(r)
        return structured.get("computed_fingerprint") if structured else None

    fps = [await fp_of(o) for o in (obj_a, obj_b, obj_c)]
    if all(fps) and len(set(fps)) == 1:
        s.ok(f"3 key permutations → 1 fingerprint: {fps[0][:16]}…")
    else:
        s.fail("key-order-independence", f"got {fps}")


async def test_tamper_evident(c: McpClient, s: Stats, mutations: int = 50) -> None:
    print(f"\n[4/8] Tamper-evident (n={mutations} byte-mutations)")
    base = "The UOR passport envelope binds content to a cryptographic fingerprint."
    r = await c.call_tool("encode_address", {"content": base})
    structured = extract_structured(r)
    if not structured:
        s.fail("tamper-setup", f"no structured encode_address response: {r}")
        return

    envelope_in = {
        "fingerprint": structured["fingerprint"],
        "length": structured["length"],
        "version": structured.get("version", "uor.passport.v1"),
        "algorithm": structured.get("algorithm", "uor-sha256-v1"),
    }
    # v0.2.0: encode_address canonicalizes the value directly (no wrapper).
    # To verify, pass the same value back as content.

    ok = await c.call_tool("verify_passport", {"content": base, "passport": envelope_in})
    ok_res = extract_structured(ok)
    if not ok_res or not ok_res.get("valid"):
        s.fail("tamper-baseline", f"original content failed to verify: {ok_res}")
        return

    rng = random.Random(42)
    caught = 0
    for _ in range(mutations):
        idx = rng.randrange(len(base))
        mutated = base[:idx] + chr((ord(base[idx]) + 1) % 128) + base[idx + 1 :]
        r = await c.call_tool(
            "verify_passport",
            {"content": mutated, "passport": envelope_in},
        )
        res = extract_structured(r)
        if res and not res.get("valid"):
            caught += 1
    if caught == mutations:
        s.ok(f"baseline verifies true; all {mutations} byte mutations detected")
    else:
        s.fail("tamper-evident", f"only {caught}/{mutations} mutations detected")


async def test_algorithm_claim_matches(c: McpClient, s: Stats) -> None:
    print("\n[5/8] Algorithm claim — uor-sha256-v1 == SHA-256(JCS(content))")
    content = "verify the hash chain"
    r = await c.call_tool("encode_address", {"content": content})
    structured = extract_structured(r)
    if not structured:
        s.fail("alg-claim", f"no structured response: {r}")
        return

    # v0.2.0: the value is canonicalized directly (no wrapper). For a plain
    # string, JCS canonical form is the JSON-quoted string: '"<content>"'.
    canonical = jcs_canonicalize(content)
    expected_fp = hashlib.sha256(canonical).hexdigest()
    expected_len = len(canonical)

    claimed_fp = structured["fingerprint"]
    claimed_len = structured["length"]

    if claimed_fp == expected_fp and claimed_len == expected_len:
        s.ok(f"address fingerprint matches SHA-256(JCS(...)) independently: {expected_fp[:16]}…")
    else:
        s.fail(
            "alg-claim",
            f"fp claimed={claimed_fp[:16]}… expected={expected_fp[:16]}… "
            f"len claimed={claimed_len} expected={expected_len}",
        )


async def test_canonical_byte_cap(c: McpClient, s: Stats) -> None:
    print("\n[6/8] Canonical-byte size cap (64 KB on canonical form)")

    # Well under the cap: typical agent payload
    small_obj = {"xs": list(range(100))}  # ~600 bytes canonical
    r_ok = await c.call_tool("encode_address", {"content": small_obj})
    if r_ok.get("result") and extract_structured(r_ok):
        s.ok("small structured payload accepted")
    else:
        s.fail("cap-small", f"small payload rejected: {r_ok}")

    # Pushed above 64 KB: should be rejected
    huge_obj = {"xs": list(range(20_000))}  # ~110 KB canonical
    r_bad = await c.call_tool("encode_address", {"content": huge_obj})
    err = r_bad.get("error") or (
        r_bad.get("result", {}).get("isError") and r_bad.get("result")
    )
    if err:
        s.ok("over-cap structured payload rejected with error")
    else:
        s.fail("cap-huge", f"huge payload accepted (should reject): {r_bad}")


async def test_concurrent_safety(url: str, s: Stats, clients: int = 50) -> None:
    print(f"\n[7/8] Concurrent safety ({clients} parallel clients)")

    async def worker(i: int) -> str | None:
        try:
            c = await new_session(url)
            try:
                r = await c.call_tool(
                    "encode_address", {"content": "shared content for concurrency"}
                )
                p = extract_passport(r)
                return p["fingerprint"] if p else None
            finally:
                await c.close()
        except Exception as e:
            return f"ERR:{e}"

    fps = await asyncio.gather(*(worker(i) for i in range(clients)))
    errors = [f for f in fps if f and f.startswith("ERR:")]
    unique = {f for f in fps if f and not f.startswith("ERR:")}
    if errors:
        s.fail("concurrency", f"{len(errors)} errors: {errors[:3]}")
    elif len(unique) == 1:
        s.ok(f"{clients} concurrent clients → 1 consistent fingerprint")
    else:
        s.fail("concurrency", f"{len(unique)} distinct fingerprints across clients")


async def test_performance(s: Stats) -> None:
    print("\n[8/8] Performance (latency percentiles)")
    if not s.latencies_ms:
        s.fail("perf", "no latencies captured")
        return
    ls = sorted(s.latencies_ms)
    p = lambda q: ls[int(len(ls) * q)]
    p50, p95, p99 = p(0.50), p(0.95), p(0.99)
    print(f"  p50={p50:.2f}ms  p95={p95:.2f}ms  p99={p99:.2f}ms  n={len(ls)}")
    # Sub-10ms p95 is a reasonable headroom claim for SHA-256+JCS over tiny payloads
    if p95 < 10.0:
        s.ok(f"p95 < 10ms")
    else:
        s.fail("perf", f"p95={p95:.2f}ms exceeds 10ms target")


# ── Entrypoint ───────────────────────────────────────────────────────────────


async def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="http://localhost:8080/mcp")
    ap.add_argument("--n", type=int, default=500, help="calls for passport-presence test")
    args = ap.parse_args()

    print(f"UOR Passport stress harness → {args.url}")
    s = Stats()
    c = await new_session(args.url)

    try:
        tools = await c.list_tools()
        names = [t["name"] for t in tools.get("result", {}).get("tools", [])]
        print(f"tools advertised: {names}")
        assert "encode_address" in names and "verify_passport" in names

        await test_every_response_has_passport(c, s, args.n)
        await test_deterministic(c, s)
        await test_key_order_independence(c, s)
        await test_tamper_evident(c, s)
        await test_algorithm_claim_matches(c, s)
        await test_canonical_byte_cap(c, s)
    finally:
        await c.close()

    await test_concurrent_safety(args.url, s, clients=50)
    await test_performance(s)

    print("\n" + "=" * 60)
    print(f"PASSED: {s.passed}   FAILED: {s.failed}")
    if s.failures:
        print("Failures:")
        for f in s.failures:
            print(f"  - {f}")
    return 0 if s.failed == 0 else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
