"""Command-line entry point.

``serve`` runs the proxy. Every other command talks to the running server
over the local-only admin channel (see ``admin/ipc.py``), because all state
lives in the server's memory.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import logging
import time
from pathlib import Path
from typing import Any, Optional

import typer

from .config import Config, ConfigError, load_config
from .textsafe import safe

cli = typer.Typer(add_completion=False, no_args_is_help=True, help="OllamaGate - secure pairing proxy for Ollama")
devices_cli = typer.Typer(no_args_is_help=True, help="Manage paired devices")
cli.add_typer(devices_cli, name="devices")

ConfigOption = typer.Option(None, "--config", "-c", help="Path to config.toml", exists=True, dir_okay=False)


def _load(config_path: Optional[Path]) -> Config:
    try:
        return load_config(config_path)
    except ConfigError as exc:
        typer.secho(f"Config error: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(2)


def _call(config_path: Optional[Path], cmd: str, **args: Any) -> Any:
    from .admin.ipc import AdminError, ControlClient, NotRunning

    config = _load(config_path)
    try:
        with ControlClient(config.config_dir) as client:
            return client.call(cmd, **args)
    except NotRunning as exc:
        typer.secho(str(exc), fg=typer.colors.RED, err=True)
        raise typer.Exit(3)
    except AdminError as exc:
        typer.secho(f"Error: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(1)


def _ts(value: float | None) -> str:
    if value is None:
        return "-"
    return dt.datetime.fromtimestamp(value).strftime("%Y-%m-%d %H:%M:%S")


# ----- serve -------------------------------------------------------------------------


@cli.command()
def serve(
    config_path: Optional[Path] = ConfigOption,
    no_tui: bool = typer.Option(False, "--no-tui", help="Run headless (manage it with the CLI commands)"),
) -> None:
    """Run the proxy server with the admin TUI (or headless with --no-tui)."""
    from collections import deque

    from . import doctor
    from .admin.ipc import start_control_server
    from .admin.service import Admin
    from .config import is_loopback_host
    from .server.app import create_app
    from .server.runner import build_server, prepare_tls
    from .server.tls import format_fingerprint
    from .state import State

    config = _load(config_path)
    log_lines: deque[str] = deque(maxlen=200)
    fmt = "%(asctime)s %(levelname)s %(name)s: %(message)s"
    if no_tui:
        logging.basicConfig(level=logging.INFO, format=fmt)
    else:
        # Logging to the terminal would corrupt the TUI; keep recent lines in memory instead.
        handler = _BufferHandler(log_lines)
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s", "%H:%M:%S"))
        logging.basicConfig(level=logging.INFO, handlers=[handler], force=True)

    state = State(config.logging.audit_size, config.logging.request_log_size)
    tls_info = prepare_tls(config)
    fingerprint = tls_info.fingerprint if tls_info else None

    warnings = [f"{f.title}. {f.fix}" for f in doctor.check_ollama_binding(config) if f.level != "ok"]

    app = create_app(config, state, fingerprint=fingerprint)
    server = build_server(config, app, state, tls_info, own_logging=no_tui)
    admin = Admin(state, config, fingerprint)
    # Bind now, so "address in use" is reported before any TUI takes over the terminal.
    sock = server.config.bind_socket()

    if no_tui:
        typer.echo(f"OllamaGate listening on {config.base_url}")
        if tls_info:
            typer.echo(f"TLS certificate SHA-256: {format_fingerprint(tls_info.fingerprint)}")
        from urllib.parse import urlsplit

        if is_loopback_host(urlsplit(config.base_url).hostname or ""):
            warnings.append("server.public_url is not set: pairing links point at loopback; phones can't reach them.")
        for w in warnings:
            typer.secho(f"WARNING: {w}", fg=typer.colors.RED, err=True)
        typer.echo("Pair a device with:  ollamagate pair")

    async def main() -> None:
        try:
            control = await start_control_server(config.config_dir, admin.dispatch)
        except RuntimeError as exc:
            typer.secho(str(exc), fg=typer.colors.RED, err=True)
            raise typer.Exit(1)
        server_task = asyncio.ensure_future(server.serve(sockets=[sock]))
        try:
            if not no_tui:
                from .tui.app import GateTUI

                tui = GateTUI(
                    admin, services=server_task, warnings=warnings, log_lines=log_lines, ollama_url=config.ollama.url
                )
                crashed = None
                try:
                    await tui.run_async()
                except Exception as exc:  # noqa: BLE001
                    crashed = exc
                if tui.quit_confirmed or server_task.done():
                    server.should_exit = True  # the owner quit (or the server already stopped)
                else:
                    # The TUI died on its own. Devices live in memory, so stopping the server
                    # would disconnect everyone: keep serving headless instead.
                    logging.basicConfig(level=logging.INFO, format=fmt, force=True)
                    for line in log_lines:
                        typer.echo(line, err=True)
                    typer.secho(
                        f"The admin TUI stopped unexpectedly ({crashed!r}); the server keeps running headless. "
                        "Use the CLI commands (ollamagate devices ...) or Ctrl+C to stop.",
                        fg=typer.colors.RED,
                        err=True,
                    )
            await server_task
        finally:
            await control.close()

    asyncio.run(main())


class _BufferHandler(logging.Handler):
    def __init__(self, lines: Any) -> None:
        super().__init__()
        self.lines = lines

    def emit(self, record: logging.LogRecord) -> None:
        try:
            self.lines.append(self.format(record))
        except Exception:  # noqa: BLE001 - logging must never raise
            self.handleError(record)


# ----- pairing -------------------------------------------------------------------------


@cli.command()
def pair(
    config_path: Optional[Path] = ConfigOption,
    method: list[str] = typer.Option(
        [], "--method", "-m", help="Pairing method(s) to enable: code, qr, link (default: all)"
    ),
    ttl: Optional[int] = typer.Option(None, "--ttl", help="Window lifetime in seconds (default from config)"),
    wait: bool = typer.Option(True, "--wait/--no-wait", help="Wait until a device pairs or the window closes"),
    cancel: bool = typer.Option(False, "--cancel", help="Close the currently open pairing window"),
) -> None:
    """Open a pairing window and show the code, QR and link."""
    from . import qr

    if cancel:
        result = _call(config_path, "pairing.cancel")
        typer.echo("Pairing window closed." if result["cancelled"] else "No pairing window was open.")
        return
    info = _call(config_path, "pairing.open", methods=method or None, ttl=ttl)
    typer.echo()
    if info.get("warning"):
        typer.secho(f"  WARNING: {info['warning']}\n", fg=typer.colors.YELLOW)
    if info.get("code"):
        typer.secho("  Pairing code:  ", nl=False)
        typer.secho(info["code"], bold=True)
        typer.echo("  Open <server>/pair on the device and type it in.\n")
    if info.get("qr_url"):
        typer.echo(qr.render_text(info["qr_url"]))
        typer.echo("  Scan with the phone's camera.\n")
    if info.get("link_url"):
        typer.echo(f"  Pairing link:  {info['link_url']}\n")
    if info.get("fingerprint"):
        from .server.tls import format_fingerprint

        typer.echo(f"  Certificate SHA-256: {format_fingerprint(info['fingerprint'])}\n")
    if not wait:
        return
    try:
        while True:
            status = _call(config_path, "pairing.status", window_id=info["window_id"])
            if status["state"] != "open":
                break
            left = int(status["expires_at"] - time.time())
            typer.echo(f"\r  Waiting for a device... {left // 60}:{left % 60:02d} left  ", nl=False)
            time.sleep(1)
    except KeyboardInterrupt:
        _call(config_path, "pairing.cancel", window_id=info["window_id"])
        status = _call(config_path, "pairing.status", window_id=info["window_id"])
    typer.echo()
    if status["state"] == "used" and status.get("device"):
        d = status["device"]
        typer.secho(
            f"  Paired: {safe(d['name'])} ({d['id'][:8]}) from {safe(d['last_ip'] or 'unknown address')}",
            fg=typer.colors.GREEN,
        )
    else:
        typer.secho(f"  Pairing window {status['state']}.", fg=typer.colors.YELLOW)
        raise typer.Exit(1)


# ----- devices -------------------------------------------------------------------------


@devices_cli.command("list")
def devices_list(config_path: Optional[Path] = ConfigOption) -> None:
    """List paired devices."""
    devices = _call(config_path, "devices.list")
    if not devices:
        typer.echo("No devices paired. Run `ollamagate pair`.")
        return
    typer.echo(f"{'ID':10} {'NAME':24} {'STATUS':10} {'VIA':5} {'LAST IP':40} LAST SEEN")
    for d in devices:
        typer.echo(
            f"{d['id'][:8]:10} {safe(d['name'])[:24]:24} {d['status']:10} {d['paired_via']:5} "
            f"{safe(d['last_ip'] or '-'):40} {_ts(d['last_seen'])}"
        )


def _print_device(d: dict[str, Any]) -> None:
    rows = [
        ("ID", d["id"]),
        ("Name", safe(d["name"])),
        ("Status", d["status"]),
        ("Paired via", f"{d['paired_via']} at {_ts(d['paired_at'])}"),
        ("Last seen", f"{_ts(d['last_seen'])} from {safe(d['last_ip'] or '-')}"),
        ("User agent", safe(d["user_agent"] or "-")),
        ("Token", d["token_prefix"]),
        ("Token expires", _ts(d["token_expires_at"]) if d["token_expires_at"] else "never"),
        ("Token rotated", _ts(d["token_rotated_at"])),
        ("Model management", "allowed" if d["allow_model_management"] else "blocked"),
        ("Active streams", str(d["active_streams"])),
        ("Notes", safe(d["notes"] or "-")),
    ]
    for label, value in rows:
        typer.echo(f"{label + ':':18} {value}")
    if d["ip_history"]:
        typer.echo("IP history:")
        for h in d["ip_history"]:
            typer.echo(f"  {safe(h['ip']):40} x{h['count']:<5} {_ts(h['first_seen'])} .. {_ts(h['last_seen'])}")


@devices_cli.command("show")
def devices_show(device_id: str, config_path: Optional[Path] = ConfigOption) -> None:
    """Show everything known about a device."""
    _print_device(_call(config_path, "devices.show", ref=device_id))


@devices_cli.command("rename")
def devices_rename(device_id: str, name: str, config_path: Optional[Path] = ConfigOption) -> None:
    """Rename a device."""
    d = _call(config_path, "devices.rename", ref=device_id, name=name)
    typer.echo(f"Renamed to {safe(d['name'])!r}.")


@devices_cli.command("notes")
def devices_notes(device_id: str, notes: str, config_path: Optional[Path] = ConfigOption) -> None:
    """Set free-text notes on a device."""
    _call(config_path, "devices.notes", ref=device_id, notes=notes)
    typer.echo("Notes saved.")


@devices_cli.command("revoke")
def devices_revoke(
    device_id: str,
    config_path: Optional[Path] = ConfigOption,
    yes: bool = typer.Option(False, "--yes", "-y", help="Don't ask for confirmation"),
) -> None:
    """Revoke a device (it must pair again). Cuts its active streams."""
    if not yes:
        typer.confirm(f"Revoke device {device_id}?", abort=True)
    d = _call(config_path, "devices.revoke", ref=device_id)
    typer.echo(f"Revoked {safe(d['name'])!r}.")


@devices_cli.command("rotate")
def devices_rotate(
    device_id: str,
    config_path: Optional[Path] = ConfigOption,
    grace: int = typer.Option(0, "--grace", help="Seconds the old token keeps working"),
) -> None:
    """Issue a new token for a device (shown once)."""
    result = _call(config_path, "devices.rotate", ref=device_id, grace_seconds=grace)
    typer.echo(f"New token for {safe(result['device']['name'])!r} (shown once):")
    typer.secho(result["token"], bold=True)
    if grace:
        typer.echo(f"The old token keeps working for {grace} seconds.")


@devices_cli.command("suspend")
def devices_suspend(device_id: str, config_path: Optional[Path] = ConfigOption) -> None:
    """Temporarily block a device without deleting it."""
    d = _call(config_path, "devices.suspend", ref=device_id)
    typer.echo(f"Suspended {safe(d['name'])!r}.")


@devices_cli.command("resume")
def devices_resume(device_id: str, config_path: Optional[Path] = ConfigOption) -> None:
    """Resume a suspended device."""
    d = _call(config_path, "devices.resume", ref=device_id)
    typer.echo(f"Resumed {safe(d['name'])!r}.")


@devices_cli.command("kick")
def devices_kick(device_id: str, config_path: Optional[Path] = ConfigOption) -> None:
    """Terminate a device's active requests now."""
    result = _call(config_path, "devices.kick", ref=device_id)
    typer.echo(f"Terminated {result['streams_killed']} active request(s).")


@devices_cli.command("expiry")
def devices_expiry(
    device_id: str,
    expiry: str = typer.Argument(..., help="never, 1d, 7d, 30d, or a number of seconds"),
    config_path: Optional[Path] = ConfigOption,
) -> None:
    """Set when a device's token expires."""
    value: Any = int(expiry) if expiry.isascii() and expiry.isdigit() else expiry
    d = _call(config_path, "devices.expiry", ref=device_id, expiry=value)
    typer.echo(f"Token expires: {_ts(d['token_expires_at']) if d['token_expires_at'] else 'never'}")


@devices_cli.command("model-management")
def devices_model_management(
    device_id: str,
    allow: bool = typer.Option(..., "--allow/--deny", help="Allow or deny pull/push/delete/create/copy"),
    config_path: Optional[Path] = ConfigOption,
) -> None:
    """Grant or revoke access to Ollama's model management endpoints."""
    d = _call(config_path, "devices.model_management", ref=device_id, allowed=allow)
    typer.echo(f"Model management for {safe(d['name'])!r}: {'allowed' if d['allow_model_management'] else 'blocked'}")


@cli.command()
def status(config_path: Optional[Path] = ConfigOption) -> None:
    """Show the dashboard: URL, devices, streams, requests, pairing and lockdown state."""
    d = _call(config_path, "dashboard")
    pairing_state = "closed" if d["pairing"] is None else f"open ({int(d['pairing']['expires_at'] - time.time())}s left)"
    rows = [
        ("Public URL", d["base_url"]),
        ("TLS", d["tls_mode"]),
        ("Network mode", d["network_mode"]),
        ("Uptime", f"{int(d['uptime'] // 60)} min"),
        ("Lockdown", "ON" if d["lockdown"] else "off"),
        ("Devices", f"{d['devices_active']} active / {d['devices']} total"),
        ("Active streams", d["active_streams"]),
        ("Requests", f"{d['requests_last_minute']}/min, {d['requests_today']} today"),
        ("Pairing", pairing_state),
    ]
    for label, value in rows:
        typer.echo(f"{label + ':':16} {safe(value)}")


# ----- lockdown / settings -------------------------------------------------------------


@cli.command()
def lockdown(
    state: str = typer.Argument(..., help="on or off"),
    config_path: Optional[Path] = ConfigOption,
) -> None:
    """Reject all traffic and close pairing (on), or resume (off). Devices are kept."""
    if state not in ("on", "off"):
        typer.secho("Use 'on' or 'off'", fg=typer.colors.RED, err=True)
        raise typer.Exit(2)
    result = _call(config_path, "lockdown.set", on=state == "on")
    if result["lockdown"]:
        typer.secho(f"LOCKDOWN on: {result['streams_killed']} stream(s) cut, pairing closed.", fg=typer.colors.RED)
    else:
        typer.echo("Lockdown off.")


settings_cli = typer.Typer(no_args_is_help=True, help="View or change runtime settings (until restart)")
cli.add_typer(settings_cli, name="settings")


@settings_cli.command("list")
def settings_list(config_path: Optional[Path] = ConfigOption) -> None:
    """Show settings that can be changed while running."""
    for key, value in _call(config_path, "settings.get").items():
        typer.echo(f"{key:32} {safe(value)}")


@settings_cli.command("set")
def settings_set(key: str, value: str, config_path: Optional[Path] = ConfigOption) -> None:
    """Change a runtime setting (lasts until restart; edit config.toml to keep it)."""
    _call(config_path, "settings.set", key=key, value=value)
    typer.echo(f"{key} = {value}")


# ----- audit / doctor ------------------------------------------------------------------


@cli.command()
def audit(
    config_path: Optional[Path] = ConfigOption,
    limit: int = typer.Option(50, "--limit", "-n"),
    event: Optional[str] = typer.Option(None, "--event", "-e", help="Filter by event prefix, e.g. pairing"),
) -> None:
    """Show recent audit log entries."""
    for e in _call(config_path, "audit.list", limit=limit, event=event):
        detail = " ".join(f"{safe(k)}={safe(v)}" for k, v in e["detail"].items())
        who = (e["device_id"] or "")[:8]
        typer.echo(f"{_ts(e['ts'])}  {safe(e['event']):22} {safe(e['ip'] or '-'):16} {who:8} {detail}")


@cli.command()
def doctor(config_path: Optional[Path] = ConfigOption) -> None:
    """Check for insecure setups (Ollama exposure, file permissions, TLS)."""
    from . import doctor as doc

    config = _load(config_path)
    colors = {"ok": typer.colors.GREEN, "warn": typer.colors.YELLOW, "error": typer.colors.RED}
    worst = "ok"
    for f in doc.run_all(config):
        typer.secho(f"[{f.level.upper():5}] {f.title}", fg=colors[f.level])
        if f.fix:
            typer.echo(f"        fix: {f.fix}")
        if f.level == "error" or (f.level == "warn" and worst == "ok"):
            worst = f.level
    raise typer.Exit(1 if worst == "error" else 0)


def main() -> None:
    cli()


if __name__ == "__main__":
    main()
