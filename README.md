# OllamaGate

A secure pairing proxy that lets your own devices use the Ollama models on your
home PC over the internet. Knowing the server's address gives no access: a device
has to **pair** first (code, QR or link), then it gets its own revocable token.

> **Status:** Phases 1-2 are done: TLS, a hardened streaming passthrough to
> Ollama, pairing by code / QR / link, and device management from the CLI.
> The admin TUI and quotas come next (see the roadmap below).

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
ollamagate serve                 # terminal 1: run the server (headless for now)
ollamagate pair                  # terminal 2: open a pairing window
```

`ollamagate pair` shows three ways to pair, valid for 5 minutes and for one
device only:

- a **code** like `8E9T-RDQF` to type in at `https://<your-server>/pair`,
- a **QR code** to scan with a phone,
- a **link** to open on the device.

The device names itself and receives its token once. Browsers show a copy
button; use it in any Ollama/OpenAI client as `Authorization: Bearer og_dev_...`
with base URL `https://<your-server>` (Ollama API) or `https://<your-server>/v1`
(OpenAI API).

Five wrong codes destroy the window; open a new one with `ollamagate pair`.

### Managing devices

```bash
ollamagate devices list
ollamagate devices show <id>             # id or its first 8 characters
ollamagate devices rename <id> "Work laptop"
ollamagate devices suspend|resume <id>
ollamagate devices kick <id>             # end its active requests now
ollamagate devices revoke <id>           # must pair again
ollamagate devices rotate <id> [--grace 60]   # prints a new token once
ollamagate devices expiry <id> never|1d|7d|30d|<seconds>
ollamagate audit [--event pairing]
ollamagate doctor                        # checks Ollama binding, permissions, TLS
```

These commands talk to the running server over a local-only channel (a
`0600` Unix socket, or `127.0.0.1` on Windows, plus a secret in an owner-only
file). Nothing about it is reachable from the network.

On first run a self-signed ECDSA P-256 certificate is created in the config
directory (`tls/cert.pem`, `tls/key.pem`). Its SHA-256 fingerprint is printed at
startup and included in pairing links so clients can pin it.

**All state is in memory.** Restarting the server forgets every device; they
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
3. Admin TUI
4. Quotas, rate limits, auto-bans, lockdown
5. Tailscale / Cloudflare / Let's Encrypt modes, service install, packaging
