# verify-ghsa-c4j6-fc7j-m34r

In-band verifier for **GHSA-c4j6-fc7j-m34r** / **CVE-2026-44578** — Server-Side
Request Forgery in Next.js via WebSocket upgrade requests.

> ⚠️ For authorized security testing only. You are responsible for ensuring you
> have permission to test every target you pass to this script.

## The vulnerability

| Field | Value |
|---|---|
| CVE | CVE-2026-44578 |
| GHSA | [GHSA-c4j6-fc7j-m34r](https://github.com/advisories/GHSA-c4j6-fc7j-m34r) |
| CWE | CWE-918 (SSRF) |
| CVSS v3.1 | 8.6 (High) — `AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N` |
| Affected | `next >=13.4.13 <15.5.16`, `>=16.0.0 <16.2.5` |
| Patched | `15.5.16`, `16.2.5` |
| Fix commit | [`c4f69086`](https://github.com/vercel/next.js/commit/c4f69086cc8dcbd81b1dbc321c98ea874d90d6f8) |
| Not affected | Vercel-hosted; `output: "export"`; deployments behind a reverse proxy that does not forward `Upgrade` |

### How the bug actually works (verified empirically against 15.5.15 vs 15.5.16)

1. An attacker opens a TCP connection to a self-hosted Next.js process and
   sends an HTTP/1.1 WebSocket upgrade whose request-URI is an absolute URL:

   ```
   GET http://anything/<path> HTTP/1.1
   Host: <target>
   Connection: Upgrade
   Upgrade: websocket
   Sec-WebSocket-Version: 13
   Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
   ```
2. In `resolveRoutes`, the URL contains `//` (every absolute URI does), which
   matches the "normalize repeated slashes" branch. That branch returns early
   with `{ finished: true, statusCode: 308, parsedUrl: <mangled> }`. The
   normalizer collapses `http://host/path` into `http:/host/path` (one slash).
3. In `router-server.ts`, the **pre-patch** upgrade handler ignored
   `finished`/`statusCode` and only checked `parsedUrl.protocol`. Since the
   protocol survives normalization, it called `proxyRequest(...)`.
4. `proxyRequest` runs `url.format(parsedUrl)` on the mangled URL, getting
   `http:/host:port/path`. `http-proxy` parses that target, finds no host
   (`url.parse('http:/...').host === null`), and falls back to its default
   destination: **`localhost:80`** (or `localhost:443` for `https`).
5. So in practice the SSRF lets you make Next open a WebSocket upgrade to
   the **Next.js host's own `localhost:80` / `localhost:443`** with an
   attacker-controlled path.

The **fix** (commit `c4f69086`) made the upgrade handler check
`finished && !statusCode` before proxying. The 308-normalization case now
fails the `!statusCode` check and the socket is closed instead.

### Why a callback-based OOB verifier won't work for this CVE

The proxy never reaches an external host. If you set up an interactsh /
Burp Collaborator / webhook canary and expect the Next process to phone home,
**it will not** — the connection goes to `localhost` on the target machine.
This verifier therefore uses an **in-band signal** read from the upgrade
socket: a vulnerable server returns a recognizable error body, a patched
server returns nothing.

### Practical impact

The SSRF target is restricted but still meaningful in real deployments:

- Sidecar containers / reverse proxies / admin panels co-located on the same
  host that bind `127.0.0.1:80` or `:443` and trust localhost-originated
  requests.
- Docker socket exposed over HTTP on `127.0.0.1:80` (uncommon but seen).
- Path traversal into any localhost HTTP service with attacker-controlled
  URI path and WebSocket upgrade semantics.

AWS / GCP / Azure metadata endpoints (`169.254.169.254`) are *not* directly
reachable because the bug pins the destination to localhost.

## Detection model

For each target, the script opens a raw TCP (or TLS) socket and sends the
crafted upgrade. It then reads the response and classifies:

| Response | Verdict |
|---|---|
| Contains `Internal Server Error` | **`vulnerable`** — Next's `http-proxy` error handler ran, which only the pre-patch path reaches. |
| Starts with `HTTP/1.` | **`vulnerable_proxy_succeeded`** — a service on the target's localhost actually answered the proxied upgrade. |
| Empty / clean close | **`likely_patched`** — also covers "not Next", "reverse proxy stripped the Upgrade", "Vercel". |
| Anything else | **`inconclusive`**. |

## Requirements

- Python 3.10+
- No third-party dependencies (stdlib only)

## Usage

```bash
# single target
python3 verify_ghsa_c4j6.py --target https://app.example.com

# multiple targets via flag repetition
python3 verify_ghsa_c4j6.py \
    --target https://app1.example.com \
    --target app2.example.com:3000 \
    --target 10.0.0.5:80

# from a file (one target per line; '#' for comments)
python3 verify_ghsa_c4j6.py --targets-file targets.txt

# from stdin
cat targets.txt | python3 verify_ghsa_c4j6.py

# JSON Lines output for downstream tooling
python3 verify_ghsa_c4j6.py --targets-file targets.txt --json
```

### Flags

| Flag | Description | Default |
|---|---|---|
| `--target URL` | A single target. Repeat for multiple. | — |
| `--targets-file PATH` | File with one target per line. | — |
| `--probe-path PATH` | Path used in the crafted absolute URI. Reaches the target's localhost service at this path (logged on a per-target token suffix). | `/x` |
| `--timeout SEC` | Per-socket timeout. | `5` |
| `--concurrency N` | Parallel probes. | `10` |
| `--insecure` | Skip TLS certificate verification. | off |
| `--json` | Emit JSON Lines instead of human text. | off |

Targets may be `host`, `host:port`, or full `http(s)://...` URLs.

## Reproducing locally

You can run a vulnerable lab in five commands:

```bash
mkdir vuln-lab && cd vuln-lab
npm init -y && npm i next@15.5.15 react@19 react-dom@19
mkdir pages && echo 'export default () => "ok"' > pages/index.js
npx next build && npx next start -p 3030 &
python3 ../verify_ghsa_c4j6.py --target 127.0.0.1:3030
```

Output:

```
[ VULN] target=127.0.0.1:3030  verdict=vulnerable  snippet='Internal Server Error'
```

Repeat with `next@15.5.16` and you should see `verdict=likely_patched`.

## Caveats

- **False negatives**: any reverse proxy in front of Next that does not
  forward the `Upgrade` header will mask the vulnerability; the script will
  report `likely_patched`. Re-test directly against the Next process if you
  can.
- **False positives**: the literal string `Internal Server Error` could
  theoretically be returned by an upstream proxy on its own. To rule that
  out, re-send the same payload with `Connection: close` instead of
  `Connection: Upgrade` — a real vulnerable Next stops returning the
  Internal Server Error body in that case (different code path).
- **HTTP/2-only targets**: not handled. `next start` defaults to HTTP/1.1.

## Responsible use

Test only systems you own or have explicit, written authorization to assess.

## References

- Advisory: <https://github.com/advisories/GHSA-c4j6-fc7j-m34r>
- Next.js v15.5.16 release: <https://github.com/vercel/next.js/releases/tag/v15.5.16>
- Next.js v16.2.5 release: <https://github.com/vercel/next.js/releases/tag/v16.2.5>
- Fix commit: <https://github.com/vercel/next.js/commit/c4f69086cc8dcbd81b1dbc321c98ea874d90d6f8>

## License

MIT
