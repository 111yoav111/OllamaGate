# OllamaGate

A secure pairing proxy that lets your own devices use the Ollama models on your
home PC over the internet. Knowing the server's address gives no access: a device
has to **pair** first (code, QR or link), then it gets its own revocable token.

> **Status:** Phases 1-3 are done: TLS, a hardened streaming passthrough to
> Ollama, pairing by code / QR / link, and a live admin TUI plus CLI.
> Quotas, rate limits and auto-bans come next (see the roadmap below).

## Requirements

- Python 3.11+
- Ollama running on the same machine, bound to loopback (`OLLAMA_HOST=127.0.0.1`)

## Install (development)

```bash
python -m venv .venv
.venv/bin/pip install -e ".[dev]"      # Windows: .venv\Scripts\pip install -e ".[dev]"
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
| **5 Settings** | runtime-changeable settings (until restart) |

Keys: `P` pair · `Enter` device details · `R` revoke · `T` rotate token ·
`S` suspend/resume · `K` kick · `N` rename · `L` limits (token expiry, model
management) · `O` notes (in details) · `/` search · `Ctrl+L` **LOCKDOWN** ·
`Q` quit. Destructive actions ask for confirmation.

**Lockdown** rejects all traffic (`503`), cuts every stream and closes pairing,
but keeps all devices; press `Ctrl+L` again (or `ollamagate lockdown off`) to
resume.

### Pairing a device

Press `P` in the TUI or run `ollamagate pair` in another terminal.

`ollamagate pair` shows three ways to pair, valid for 5 minutes and for one
device only:

- a **code** like `8E9T-RDQF` to type in at `https://<your-server>/pair`,
- a **QR code** to scan with a phone,
- a **link** to open on the device.

The device names itself and receives its token once. Browsers show a copy
button; use it in any Ollama/OpenAI client as `Authorization: Bearer og_dev_...`
with base URL `https://<your-server>` (Ollama API) or `https://<your-server>/v1`
(OpenAI API).

Options: `--method code|qr|link` (repeatable), `--ttl <seconds>`, `--no-wait`,
and `ollamagate pair --cancel` to close an open window. Five wrong codes
disable the code (the QR/link keep working); open a new window with
`ollamagate pair`.

> Set `server.public_url` (e.g. your Tailscale name) and `server.host` in
> `config.toml`; otherwise pairing links point at `127.0.0.1`, which a phone
> can't reach. `ollamagate pair` warns about this.

### Managing devices

```bash
ollamagate devices list
ollamagate devices show <id>             # id or its first 8 characters
ollamagate devices rename <id> "Work laptop"
ollamagate devices notes <id> "Anna's phone, replaced 2026-09"
ollamagate devices model-management <id> --allow|--deny   # pull/push/delete/create/copy
ollamagate devices suspend|resume <id>
ollamagate devices kick <id>             # end its active requests now
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
| `/api/*` | device token | Ollama native API (allowlisted endpoints only) |
| `/v1/*` | device token | OpenAI-compatible API (allowlisted endpoints only) |

Everything else returns `404`. Model management (`pull`, `push`, `delete`,
`create`, `copy`, blobs) is blocked unless granted per device.

## Tests

```bash
.venv/bin/python -m pytest -q
```

## Roadmap

1. ~~Foundation~~
2. ~~Pairing (code / QR / link) and device management CLI~~
3. ~~Admin TUI~~
4. Quotas, rate limits, auto-bans, lockdown
5. Tailscale / Cloudflare / Let's Encrypt modes, service install, packaging
