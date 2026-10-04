# OllamaGate

[![CI](https://github.com/111yoav111/OllamaGate/actions/workflows/ci.yml/badge.svg)](https://github.com/111yoav111/OllamaGate/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)

**Secure remote access to your local Ollama models.**

Use the Ollama instance on your home PC from your phone, laptop or anywhere
else, without putting an unauthenticated Ollama server on the internet.

Pair a device with a one-time code, QR code or link. Each device gets its own
revocable token, with its own limits and access controls.

## Contents

- [Why](#why)
- [Features](#features)
- [How it works](#how-it-works)
- [Requirements](#requirements)
- [Quick start](#quick-start)
- [Usage](#usage)
- [Network access](#network-access)
- [Notifications](#notifications)
- [Country filtering (GeoIP)](#country-filtering-geoip)
- [Configuration](#configuration)
- [Running as a service](#running-as-a-service)
- [Updating and uninstalling](#updating-and-uninstalling)
- [Security considerations](#security-considerations)
- [Limitations](#limitations)
- [Troubleshooting](#troubleshooting)
- [Development](#development)
- [License](#license)

## Why

Running models locally means your prompts stay on your own machine, with no
subscription, no per-token bill and any model you like. The catch is that the
models live on one PC, and you want them on your phone and laptop too.

The usual shortcut is to set `OLLAMA_HOST=0.0.0.0` and expose the port. Ollama
has no built-in authentication, so its API is then open to anyone who can reach
it. A joint scan by
[SentinelLABS and Censys](https://www.sentinelone.com/labs/silent-brothers-ollama-hosts-form-anonymous-ai-network-beyond-platform-guardrails/)
found around **175,000 exposed Ollama servers** across 130 countries, with
about 23,000 consistently online. Exposed servers get used for free compute,
spam and phishing, and access to them is resold.

OllamaGate is an authenticated gateway in front of Ollama. Ollama stays bound
to loopback, and devices have to pair and authenticate before they can use the
API, with per-device limits and instant revocation.

## Features

- **Device pairing.** Pair with a one-time code, QR code or link. Each device gets its own revocable credentials.
- **Access controls.** Per-device model allowlists, token quotas, rate limits, concurrency, context limits and priority.
- **Built-in web chat.** Chat with your models from any browser at `/app`; a phone needs nothing else.
- **Live administration.** Monitor, suspend, revoke, rotate and ban devices from an interactive TUI or the CLI, with a one-key lockdown.
- **Flexible remote access.** Tailscale, Cloudflare Tunnel, Let's Encrypt or direct HTTPS, with optional client certificates (mTLS).
- **Automated protection.** Automatic IP bans, optional country filtering and notifications.
- **In-memory state.** Device credentials, usage and logs live in memory and are cleared on restart.

## How it works

```
  Phone ──────┐
  Laptop ─────┼── HTTPS ──>  OllamaGate  ───────>  Ollama
  Browser ────┘              pairing, auth,         127.0.0.1:11434
  (paired devices)           limits, audit          (never exposed)
```

How devices reach OllamaGate depends on the [network mode](#network-access).

## Requirements

- Python 3.11+
- Ollama running on the same machine, bound to loopback (`OLLAMA_HOST=127.0.0.1`, the default)
- To answer several devices at once, let Ollama run requests in parallel
  (`OLLAMA_NUM_PARALLEL=4`, plus `OLLAMA_MAX_LOADED_MODELS=2` if they use different models).
  OllamaGate already forwards up to `server.max_upstream_concurrency` requests at once;
  without this, Ollama answers them one after another.

## Quick start

**1. Install**

```bash
pipx install git+https://github.com/111yoav111/OllamaGate
```

[pipx](https://pipx.pypa.io) puts the `ollamagate` command on your `PATH` in
its own virtual environment. `pip install git+https://...` inside a venv you
manage works too.

**2. Configure**

OllamaGate runs with safe defaults and no config file (HTTPS on
`127.0.0.1:8443`, self-signed certificate). To reach it from other devices,
create a config from the example and pick a [network mode](#network-access).
Tailscale is the easiest: no router ports, and a real certificate.

```bash
mkdir -p ~/.config/ollamagate
curl -o ~/.config/ollamagate/config.toml \
  https://raw.githubusercontent.com/111yoav111/OllamaGate/main/config.example.toml
chmod 600 ~/.config/ollamagate/config.toml   # it may hold notification secrets
```

See [Configuration](#configuration) for the macOS and Windows paths.

**3. Start OllamaGate**

```bash
ollamagate serve                 # server + admin TUI in this terminal
ollamagate serve --no-tui        # headless; manage it with the CLI commands
```

**4. Pair a device**

Press `P` in the TUI, or run `ollamagate pair` in another terminal. Then scan
the QR code, open the link, or type the code on your device.

**5. Check the setup**

```bash
ollamagate doctor
```

This checks that Ollama is running and not exposed, certificate validity and
name, network mode prerequisites and file permissions.

## Usage

### Pairing a device

`ollamagate pair` shows three ways to pair, valid for 5 minutes and for one
device only:

- a **code** like `8E9T-RDQF` to type in at the printed address (`https://<your-server>:8443/pair`),
- a **QR code** to scan with a phone,
- a **link** to open on the device.

The device names itself and receives its token once.

- **In a browser**: tap **Open chat in this browser** and start chatting. The
  browser is signed in to the built-in chat at `/app` with a secure cookie.
- **In other apps**: copy the token and use it as
  `Authorization: Bearer og_dev_...` with base URL `https://<your-server>`
  (Ollama API) or `https://<your-server>/v1` (OpenAI API).

Options: `--method code|qr|link` (repeatable), `--ttl <seconds>`, `--no-wait`,
and `ollamagate pair --cancel` to close an open window. Five wrong codes
disable the code (the QR/link keep working); open a new window with
`ollamagate pair`.

> [!NOTE]
> In `direct` and `letsencrypt` mode, set `server.public_url` and `server.host`
> in `config.toml`; otherwise pairing links point at `127.0.0.1`, which a phone
> can't reach (`ollamagate pair` warns about this). `tailscale` mode fills both in.

### Using the API

Any Ollama or OpenAI client works with the device token. With curl:

```bash
curl https://<your-server>:8443/api/chat \
  -H "Authorization: Bearer og_dev_..." \
  -H "Content-Type: application/json" \
  -d '{"model": "llama3.2", "messages": [{"role": "user", "content": "Hello!"}], "stream": false}'
# add --cacert cert.pem with a self-signed certificate
```

With Python and the OpenAI-compatible endpoint:

```python
import httpx

r = httpx.post(
    "https://<your-server>:8443/v1/chat/completions",
    headers={"Authorization": "Bearer og_dev_..."},
    json={"model": "llama3.2", "messages": [{"role": "user", "content": "Hello!"}]},
    timeout=120,
    # verify="cert.pem",  # with a self-signed certificate
)
print(r.json()["choices"][0]["message"]["content"])
```

Supported endpoints:

| API | Endpoints |
|---|---|
| Ollama | `POST /api/chat`, `/api/generate`, `/api/embed`, `/api/embeddings`, `/api/show`; `GET /api/tags`, `/api/ps`, `/api/version` |
| OpenAI | `POST /v1/chat/completions`, `/v1/completions`, `/v1/embeddings`; `GET /v1/models`, `/v1/models/<name>` |
| Model management | `/api/pull`, `/api/push`, `/api/create`, `/api/copy`, `/api/delete`, blobs: blocked unless granted per device |

### Admin TUI

| Tab | Shows |
|---|---|
| **1 Dashboard** | public URL, TLS fingerprint, uptime, devices, active streams, requests/min, Ollama version and loaded models (VRAM), security warnings, recent log |
| **2 Devices** | live table: status dot, name, IP, client/OS, pairing method, last seen, current model, requests today |
| **3 Pairing** | code, QR, link and countdown; a notice when a device pairs |
| **4 Audit log** | filterable security events (pairings, failed logins, admin actions...) |
| **5 Bans** | auto and manual IP bans; `U` lifts one |
| **6 Settings** | runtime-changeable settings (until restart) |

Device status dots:

| Dot | Meaning |
|---|---|
| green, filled | streaming a response right now |
| yellow, filled | seen in the last 90 seconds (an open `/app` tab checks in every 30 seconds) |
| hollow | idle |
| red, filled | suspended |
| red cross | revoked |

Keys:

| Key | Action |
|---|---|
| `P` | pair a device |
| `Enter` | device details |
| `R` | revoke |
| `T` | rotate token |
| `S` | suspend / resume |
| `N` | rename |
| `L` | limits (quotas, rate, models, priority, expiry, model management) |
| `B` | ban the device's IP |
| `O` | notes (in details) |
| `/` | search |
| `1`-`6` | switch tabs |
| `U` | lift a ban (Bans tab) |
| `Ctrl+L` | **lockdown** |
| `Q` / `Ctrl+Q` | quit |

Destructive actions ask for confirmation.

**Lockdown** answers every request with `503`, cuts every stream and closes pairing,
but keeps all devices; press `Ctrl+L` again (or `ollamagate lockdown off`) to
resume.

### Managing devices from the CLI

```bash
ollamagate devices list
ollamagate devices show <id>             # full id or a unique prefix (4+ characters)
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
estimate, so disconnecting early doesn't dodge the quota. Quotas are checked
when a request starts and charged when it ends, so a device can end up over
its quota: each of its concurrent requests may use up to the remaining output
allowance, plus its prompt (bounded by `max_num_ctx`). Set `max_concurrent`
low for devices whose quota must be close to exact.

Clients that keep failing to log in or pair (10 times in 10 minutes by default)
are banned for an hour, doubling on repeat offenses (`[bans]` in the config).
Manage bans in the TUI's Bans tab or with `ollamagate bans list|add|remove`.

## Network access

Set `network.mode` in `config.toml`. **Tailscale is recommended for most
setups**; use Cloudflare if your devices can't join a tailnet.

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

For an extra layer, turn on client certificates:

```toml
[tls]
client_certs = true
```

Each device then gets a client certificate at pairing (shown once, next to the
token: a password-protected `.p12` for phones and browsers, and
`client.pem`/`client.key` for apps and scripts). Every request needs **both** the
token and that device's certificate, so a token that leaks on its own is not
enough:

```sh
curl --cert client.pem --key client.key -H "Authorization: Bearer og_dev_..." https://<server>:8443/api/tags
```

Outside an open pairing window, connections without a valid certificate are
refused during the TLS handshake, before any HTTP is parsed; while a window is
open, new devices can reach `/pair` without one. With client certificates on,
only TLS 1.3 is accepted (it encrypts the client certificate).

The signing CA lives only in memory and is new on every start, so a restart
invalidates all certificates too: remove the old certificate from the device
and pair again. A lost certificate also means revoke + re-pair.

> [!IMPORTANT]
> Only use this if all your apps can send a client certificate (browsers, curl,
> Python/httpx can; many chat apps can't). Not available with
> `network.mode = "cloudflare"` or `tls.mode = "off"` (OllamaGate must terminate
> TLS itself).

## Notifications

OllamaGate can tell you when a device pairs, a device shows up from a new IP,
a client gets banned, or lockdown changes, via [ntfy](https://ntfy.sh), a
Telegram bot, or a desktop notification. All off by default; see `[notify]`
in `config.example.toml`. Messages never contain tokens or prompts.

## Country filtering (GeoIP)

Point `geoip.database` at a local country database (the free
[DB-IP IP to Country Lite](https://db-ip.com/db/download/ip-to-country-lite)
`.mmdb`, no account needed, or MaxMind GeoLite2-Country) and the audit log,
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

## Configuration

Copy [`config.example.toml`](config.example.toml) to your config directory as
`config.toml`:

| OS | Config dir |
|---|---|
| Linux | `~/.config/ollamagate/` (or `$XDG_CONFIG_HOME/ollamagate/`) |
| macOS | `~/Library/Application Support/ollamagate/` |
| Windows | `%APPDATA%\ollamagate\` |

The example lists every key with its default; all of them are optional, and
unknown keys are rejected. Keep the file owner-readable only (`chmod 600`).
Every value can be overridden with `OLLAMAGATE_<SECTION>__<KEY>` env vars, e.g.
`OLLAMAGATE_SERVER__PORT=9443` (lists are comma-separated). `OLLAMAGATE_CONFIG_DIR`
changes the directory, and most commands take `--config <file>` to use a specific file.

## Running as a service

```bash
ollamagate service install     # systemd user unit / macOS LaunchAgent / Windows Startup folder
ollamagate service uninstall
```

The service runs as your normal user, headless; manage it with the
[CLI commands](#managing-devices-from-the-cli). `serve` refuses to run as
root/Administrator unless you pass `--allow-root`. In Tailscale mode on Linux,
allow your user to fetch certificates once with
`sudo tailscale set --operator=$USER`.

## Updating and uninstalling

Update:

```bash
pipx upgrade ollamagate
```

Uninstall:

```bash
ollamagate service uninstall   # if you installed the service
pipx uninstall ollamagate
rm -rf ~/.config/ollamagate    # config, TLS key/cert (or your OLLAMAGATE_CONFIG_DIR; see Configuration for other OSes)
```

On Windows, stop a running OllamaGate yourself before uninstalling the service.

## Security considerations

OllamaGate adds authentication and access control in front of Ollama. It does
not replace securing the host machine or the devices you pair.

- Keep Ollama bound to loopback (`ollamagate doctor` checks this).
- Treat device tokens and client certificates as passwords. Revoke a device
  as soon as it's lost or compromised.
- Only pair devices you trust. Granting model management gives that device full
  control over Ollama's models, whatever its model allowlist says.
- Anyone who can act as your OS user can administer OllamaGate.
- The self-signed certificate's SHA-256 fingerprint is printed at startup and
  shown after pairing so you can compare them, but the pairing page can't
  detect a man-in-the-middle by itself. A real certificate (Tailscale or
  Let's Encrypt) avoids this.
- Country filtering is not authentication: VPNs and proxies get around it.
- Anyone who knows an ntfy topic name can read its notifications; pick an
  unguessable one.

The full threat model and known limitations are in [SECURITY.md](SECURITY.md).
Please report vulnerabilities privately through
[GitHub's private vulnerability reporting](https://github.com/111yoav111/OllamaGate/security/advisories/new),
not in a public issue.

### What's exposed

| Route | Auth | |
|---|---|---|
| `GET /healthz` | none | returns `ok` |
| `GET /pair` | pairing window open | pairing page (404 otherwise) |
| `POST /pair/claim` | pairing secret | returns the device token once |
| `GET /me` | device token | the device's own name, token prefix, limits |
| `/app`, `/app/*` | session cookie | built-in chat for browsers paired via `/pair` |
| `/api/*` | device token | Ollama native API ([allowlisted endpoints](#using-the-api) only) |
| `/v1/*` | device token | OpenAI-compatible API ([allowlisted endpoints](#using-the-api) only) |

Everything else returns `404`.

### What's stored where

On first run a self-signed ECDSA P-256 certificate is created in the config
directory (`tls/cert.pem`, `tls/key.pem`). Its SHA-256 fingerprint is printed
at startup and included in pairing links so clients can pin it. In `tailscale`
mode the Tailscale certificate is stored next to it (`tls/tailscale.crt`,
`tls/tailscale.key`).

Only the config file, the TLS key/cert and, while running, the admin channel
files in `run/` are on disk. Devices, usage counters, bans, the audit log and
the request log are all in memory.

## Limitations

- **A restart forgets everything.** Every device must pair again, and usage
  counters, bans and the audit log reset. Don't rely on the audit log as a
  durable record.
- With client certificates on, a restart invalidates them too.
- The browser shows a certificate warning in `direct` mode with the
  self-signed certificate.
- Ollama answers one request at a time unless `OLLAMA_NUM_PARALLEL` is set
  (see [Requirements](#requirements)).

## Troubleshooting

Error responses are JSON, e.g. `{"error": "rate limit exceeded"}`.

| Symptom | Cause and fix |
|---|---|
| Pairing link or QR points at `127.0.0.1` | `server.public_url` is not set. Set it (and `server.host`) in `config.toml`, or use `network.mode = "tailscale"`. |
| Browser warns about the certificate | Self-signed certificate in `direct` mode. Compare the fingerprint with the one OllamaGate prints, or switch to Tailscale or Let's Encrypt. |
| `502 upstream unavailable` | Ollama isn't running. Start it (`ollama serve`). |
| `doctor` says Ollama is exposed | Set `OLLAMA_HOST=127.0.0.1` and restart Ollama. |
| `401` or "Not signed in" after a restart | All state is in memory. Open pairing and pair the device again. With mTLS, delete the old "OllamaGate" certificate from the device first. |
| `429 rate limit exceeded` / `daily token quota used up` / `monthly token quota used up` | The device hit its limits. Raise them with `L` in the TUI or `ollamagate devices limits`. |
| `503 server busy, try again shortly` | Ollama was busy for longer than `server.queue_timeout`. See `OLLAMA_NUM_PARALLEL` and `server.max_upstream_concurrency`. |
| `503 server unavailable` | Lockdown is on. Run `ollamagate lockdown off`. |
| `403 forbidden` for a paired device | Its country is blocked (country rules apply to everyone). Check `ollamagate audit --event geo_blocked`. |
| `403 forbidden` before pairing or with a bad token | The IP is banned or its country is blocked. Check `ollamagate bans list` and the audit log. |
| `tailscale cert needs permission` | Run `sudo tailscale set --operator=$USER` once, then start OllamaGate again as your normal user. |
| `tailscale cert failed` | Enable *HTTPS certificates* in the Tailscale admin console. |
| "Refusing to run as root" | Run OllamaGate as a normal user. |

When in doubt, run `ollamagate doctor`: every finding comes with a fix.

## Development

```bash
git clone https://github.com/111yoav111/OllamaGate && cd OllamaGate
python -m venv .venv && .venv/bin/pip install -e ".[dev]"     # Windows: .venv\Scripts\pip
.venv/bin/python -m pytest -q
```

CI installs the exact, hash-pinned versions from `requirements-dev.lock`
(`pip install --require-hashes -r requirements-dev.lock`, then
`pip install --no-deps -e .`); use that to reproduce a CI run.

Built with [FastAPI](https://fastapi.tiangolo.com), [Uvicorn](https://www.uvicorn.org),
[HTTPX](https://www.python-httpx.org), [Textual](https://textual.textualize.io)
and [Typer](https://typer.tiangolo.com).

## License

[MIT](LICENSE)
