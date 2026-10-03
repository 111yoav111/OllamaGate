# OllamaGate

A secure pairing proxy that lets your own devices use the Ollama models on your
home PC over the internet. Knowing the server's address gives no access: a device
has to **pair** first (code, QR or link), then it gets its own revocable token.


## Requirements

- Python 3.11+
- Ollama running on the same machine, bound to loopback (`OLLAMA_HOST=127.0.0.1`)
- To answer several devices at once, let Ollama run requests in parallel
  (`OLLAMA_NUM_PARALLEL=4`, plus `OLLAMA_MAX_LOADED_MODELS=2` if they use different models).
  OllamaGate already forwards up to `server.max_upstream_concurrency` requests at once;
  without this, Ollama answers them one after another.

## Install

```bash
pipx install git+https://github.com/111yoav111/OllamaGate    # or, for development:
python -m venv .venv && .venv/bin/pip install -e ".[dev]"     # Windows: .venv\Scripts\pip
```

## Run

```bash
ollamagate serve                 # server + admin TUI in this terminal
ollamagate serve --no-tui        # headless; manage it with the CLI commands below
```

### Admin TUI

| Tab | Shows |
|---|---|
| **1 Dashboard** | public URL, TLS fingerprint, uptime, devices, active streams, requests/min, Ollama version and loaded models (VRAM), security warnings, recent log |
| **2 Devices** | live table: status dot (🟢 streaming · 🟡 seen < 5 min · ⚪ idle · 🔴 suspended/revoked), name, IP, client/OS, pairing method, last seen, current model, requests today |
| **3 Pairing** | code, QR, link and countdown; a notice when a device pairs |
| **4 Audit log** | filterable security events (pairings, failed logins, admin actions…) |
| **5 Bans** | auto and manual IP bans; `U` lifts one |
| **6 Settings** | runtime-changeable settings (until restart) |

Keys: `P` pair · `Enter` device details · `R` revoke · `T` rotate token ·
`S` suspend/resume · `N` rename · `L` limits (quotas, rate,
models, priority, expiry, model management) · `B` ban the device's IP ·
`O` notes (in details) · `/` search · `Ctrl+L` **LOCKDOWN** · `Q` quit. Destructive actions ask for confirmation.

**Lockdown** rejects all traffic (`503`), cuts every stream and closes pairing,
but keeps all devices; press `Ctrl+L` again (or `ollamagate lockdown off`) to
resume.

### Pairing a device

Press `P` in the TUI or run `ollamagate pair` in another terminal.

`ollamagate pair` shows three ways to pair, valid for 5 minutes and for one
device only:

- a **code** like `8E9T-RDQF` to type in at the printed address (`https://<your-server>:8443/pair`),
- a **QR code** to scan with a phone,
- a **link** to open on the device.

The device names itself and receives its token once. On a phone, tap **Open
chat in this browser** and start chatting: the browser is signed in to the
built-in chat at `/app` with a secure cookie. For other apps, copy the token
and use it as `Authorization: Bearer og_dev_...` with base URL
`https://<your-server>` (Ollama API) or `https://<your-server>/v1` (OpenAI API).

Options: `--method code|qr|link` (repeatable), `--ttl <seconds>`, `--no-wait`,
and `ollamagate pair --cancel` to close an open window. Five wrong codes
disable the code (the QR/link keep working); open a new window with
`ollamagate pair`.

> In `direct` and `letsencrypt` mode, set `server.public_url` and `server.host`
> in `config.toml`; otherwise pairing links point at `127.0.0.1`, which a phone
> can't reach (`ollamagate pair` warns about this). `tailscale` mode fills both in.

### Limits and bans

Every device gets its own limits, copied from `[limits]` in `config.toml` when
it pairs and editable live (TUI `L`, or `ollamagate devices limits`):

| Limit | Effect |
|---|---|
| `tokens_per_day`, `tokens_per_month` | quota on prompt + completion tokens (from Ollama's own counts); `429` once used up |
| `requests_per_minute` | `429` with `Retry-After` when exceeded |
| `max_concurrent` | simultaneous requests for this device |
| `max_num_ctx`, `max_num_predict` | requests asking for more are clamped (also `max_tokens` on `/v1`) |
| `allowed_models` | other models are refused and hidden from model lists |
| `priority` | when Ollama is busy (`server.max_upstream_concurrency`), high goes first |

A stream that is cut off before Ollama reports its token counts is charged an
estimate, so disconnecting early doesn't dodge the quota.

Clients that keep failing to log in or pair (10 times in 10 minutes by default)
are banned for an hour, doubling on repeat offences (`[bans]` in the config).
Manage bans in the TUI's Bans tab or with `ollamagate bans list|add|remove`.

### Managing devices

```bash
ollamagate devices list
ollamagate devices show <id>             # id or its first 8 characters
ollamagate devices rename <id> "Work laptop"
ollamagate devices notes <id> "Anna's phone, replaced 2026-09"
ollamagate devices model-management <id> --allow|--deny   # pull/push/delete/create/copy
ollamagate devices limits <id> [--tokens-per-day N --allowed-models llama3,qwen2 --priority high ...]
ollamagate devices ban-ip <id>            # ban its last IP and suspend it
ollamagate bans list|add <ip>|remove <ip>
ollamagate devices suspend|resume <id>
ollamagate devices revoke <id>           # must pair again
ollamagate devices rotate <id> [--grace 60]   # prints a new token once
ollamagate devices expiry <id> never|1d|7d|30d|<seconds>
ollamagate audit [--event pairing]
ollamagate status                        # the dashboard, for scripts / headless mode
ollamagate lockdown on|off
ollamagate settings list
ollamagate settings set server.public_url https://my-pc.tailnet.ts.net:8443
ollamagate doctor                        # checks Ollama binding, permissions, TLS
```

These commands talk to the running server over a local-only channel (a
`0600` Unix socket, or `127.0.0.1` on Windows, plus a secret in an owner-only
file). Nothing about it is reachable from the network.

On first run a self-signed ECDSA P-256 certificate is created in the config
directory (`tls/cert.pem`, `tls/key.pem`). Its SHA-256 fingerprint is printed at
startup and included in pairing links so clients can pin it.

**All device state is in memory.** Only the config file, the TLS key/cert and,
while running, the admin channel files in `run/` are on disk. Restarting the server forgets every device; they
must pair again.

## Reaching it from the internet

Pick one `network.mode` in `config.toml` (most recommended first):

| Mode | What you need | What OllamaGate does |
|---|---|---|
| `tailscale` | Tailscale on the PC and your devices, *HTTPS certificates* enabled in the Tailscale admin console | listens only on the PC's Tailscale IP, gets a real certificate with `tailscale cert` (renewed and hot-reloaded), and uses `https://<pc>.<tailnet>.ts.net:8443` in pairing links. Devices must be on your tailnet **and** paired. |
| `cloudflare` | a `cloudflared` tunnel pointing at `http://127.0.0.1:8443` (with `[tls] mode = "off"`) | stays on loopback, trusts only the local tunnel for client IPs; set `server.public_url` to the tunnel hostname. No router ports opened. |
| `letsencrypt` | your own domain, certbot, a router port-forward | uses `[tls] mode = "files"` with certbot's certificate (copy it to an owner-only place with a deploy hook); renewals are picked up without a restart. |
| `direct` (default) | `server.host = "0.0.0.0"` (or a LAN IP), a router port-forward for internet access, and `server.public_url` | self-signed certificate: works, but every browser shows a warning. |

```toml
[network]
mode = "tailscale"
```

### Client certificates (mTLS)

For defence in depth, turn on client certificates:

```toml
[tls]
client_certs = true
```

Each device then gets a client certificate at pairing (shown once, next to the
token: a password-protected `.p12` for phones and browsers, and
`client.pem`/`client.key` for apps and scripts). Every request needs **both** the
token and that device's certificate, so a leaked token alone is useless:

```sh
curl --cert client.pem --key client.key -H "Authorization: Bearer og_dev_..." https://<server>:8443/api/tags
```

Outside an open pairing window, connections without a valid certificate are
refused during the TLS handshake, before any HTTP is parsed; while a window is
open, new devices can reach `/pair` without one. With client certificates on,
only TLS 1.3 is accepted (it encrypts the client certificate).

The signing CA lives only in memory and is new on every start, like the device
list, so a restart invalidates all certificates too: remove the old certificate
from the device and pair again. A lost certificate also means revoke + re-pair.
Only use this if all your apps can send a client certificate (browsers, curl,
Python/httpx can; many chat apps can't). Not available with
`network.mode = "cloudflare"` or `tls.mode = "off"` (OllamaGate must terminate
TLS itself).

`ollamagate doctor` checks the whole setup: Ollama running and not exposed,
certificate validity and name, network mode prerequisites, file permissions.

## Notifications

OllamaGate can tell you when a device pairs, a device shows up from a new IP,
a client gets banned, or lockdown changes - via [ntfy](https://ntfy.sh), a
Telegram bot, or a desktop notification. All off by default; see `[notify]`
in `config.example.toml`. Messages never contain tokens or prompts.

## Country filtering (GeoIP)

Point `geoip.database` at a local country database - the free
[DB-IP IP to Country Lite](https://db-ip.com/db/download/ip-to-country-lite)
`.mmdb` (no account needed) or MaxMind GeoLite2-Country - and the audit log,
device details and notifications show each client's country. Lookups are
offline. Then optionally:

```toml
[geoip]
database = "/home/me/.config/ollamagate/dbip-country-lite.mmdb"
allow_countries = ["DE", "AT"]   # refuse everyone else, paired devices included
deny_countries = []
```

Blocked clients get `403` before any routing. Loopback, LAN and Tailscale
addresses are never filtered; an address the database can't place is refused
when an allowlist is set. The databases update monthly: download a fresh one
and restart (`ollamagate doctor` warns when it's over two months old).

## Running as a service

```bash
ollamagate service install     # systemd user unit / macOS LaunchAgent / Windows Startup folder
ollamagate service uninstall
```

The service runs as your normal user, headless; manage it with the CLI
commands above. `serve` refuses to run as root/Administrator unless you pass
`--allow-root`. In Tailscale mode on Linux, allow your user to fetch
certificates once with `sudo tailscale set --operator=$USER`. Restarting it forgets all devices (state is in memory).

## Configuration

Copy `config.example.toml` to your config directory as `config.toml`:

| OS | Config dir |
|---|---|
| Linux | `~/.config/ollamagate/` |
| macOS | `~/Library/Application Support/ollamagate/` |
| Windows | `%APPDATA%\ollamagate\` |

Every value can be overridden with `OLLAMAGATE_<SECTION>__<KEY>` env vars, e.g.
`OLLAMAGATE_SERVER__PORT=9443`. `OLLAMAGATE_CONFIG_DIR` changes the directory.

## What's exposed

| Route | Auth | |
|---|---|---|
| `GET /healthz` | none | returns `ok` |
| `GET /pair` | pairing window open | pairing page (404 otherwise) |
| `POST /pair/claim` | pairing secret | returns the device token once |
| `GET /me` | device token | the device's own name, token prefix, limits |
| `/app` | session cookie | built-in chat for browsers paired via `/pair` |
| `/api/*` | device token | Ollama native API (allowlisted endpoints only) |
| `/v1/*` | device token | OpenAI-compatible API (allowlisted endpoints only) |

Everything else returns `404`. Model management (`pull`, `push`, `delete`,
`create`, `copy`, blobs) is blocked unless granted per device.

## Tests

```bash
.venv/bin/python -m pytest -q
```

