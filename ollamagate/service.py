"""Run OllamaGate in the background as a per-user service.

The service always runs as the logged-in user (never root/SYSTEM), headless
(``serve --no-tui``); manage it with the CLI commands. Remember that state is
in memory: when the service restarts, devices must pair again.

* Linux:   a systemd *user* unit (~/.config/systemd/user/ollamagate.service)
* macOS:   a LaunchAgent (~/Library/LaunchAgents/com.ollamagate.plist)
* Windows: a script in the user's Startup folder (no admin rights needed)
"""

from __future__ import annotations

import getpass
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from xml.sax.saxutils import escape

SERVICE_NAME = "ollamagate"
LAUNCHD_LABEL = "com.ollamagate"


@dataclass
class ServicePlan:
    path: Path | None  # file to write
    content: str
    activate: list[list[str]]  # commands that enable/start it
    deactivate: list[list[str]]


def _config_dir_env() -> str | None:
    """OLLAMAGATE_CONFIG_DIR as an absolute path, so the service uses the same directory as this CLI."""
    value = os.environ.get("OLLAMAGATE_CONFIG_DIR")
    return str(Path(value).resolve()) if value else None


def _serve_command(config_path: Path | None, python: str | None = None) -> list[str]:
    cmd = [python or sys.executable, "-m", "ollamagate", "serve", "--no-tui"]
    if config_path is not None:
        cmd += ["--config", str(config_path.resolve())]
    return cmd


def _check_printable(parts: list[str]) -> None:
    # A newline in a path would start a new directive in the unit file / script.
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for part in parts for ch in part):
        raise ValueError("paths with control characters can't be used in a service definition")


# Arguments made only of these characters need no quoting.
_PLAIN = re.compile(r"[\w@+=:,./-]+", re.ASCII)
# No "=" or ",": cmd.exe treats them as token delimiters.
_PLAIN_WIN = re.compile(r"[\w@+:./\\-]+", re.ASCII)


def _systemd_exec(cmd: list[str]) -> str:
    """Quote for ExecStart. systemd has its own syntax (not a shell's): it expands
    % specifiers and $VARIABLES even inside quotes, and C-unescapes double-quoted words."""

    def quote(arg: str) -> str:
        if _PLAIN.fullmatch(arg):
            return arg
        return '"' + arg.replace("\\", "\\\\").replace('"', '\\"').replace("%", "%%").replace("$", "$$") + '"'

    return " ".join(quote(a) for a in cmd)


def _cmd_quote(arg: str) -> str:
    """Quote for a .cmd script: inside double quotes & | < > ^ are literal, but %
    still expands, so it is doubled. (Windows paths can't contain double quotes.)"""
    if _PLAIN_WIN.fullmatch(arg):
        return arg
    return '"' + arg.replace("%", "%%") + '"'


def _current_user() -> str:
    try:
        return getpass.getuser()
    except (KeyError, OSError):  # no login name and no passwd entry (some containers)
        return ""


def plan(
    config_path: Path | None = None,
    platform: str = sys.platform,
    home: Path | None = None,
    check_paths: bool = True,
) -> ServicePlan:
    """``check_paths=False`` is for uninstall, which only needs the file location."""
    home = home or Path.home()
    cmd = _serve_command(config_path)
    config_dir = _config_dir_env()
    if check_paths:
        _check_printable([*cmd, config_dir or ""])
    if config_dir and platform != "win32":
        cmd = ["/usr/bin/env", f"OLLAMAGATE_CONFIG_DIR={config_dir}", *cmd]
    if platform.startswith("linux"):
        unit = f"""[Unit]
Description=OllamaGate - secure pairing proxy for Ollama
After=network-online.target
Wants=network-online.target

[Service]
ExecStart={_systemd_exec(cmd)}
Restart=on-failure
RestartSec=5
# Hardening (user units can't use every option, but these work unprivileged).
NoNewPrivileges=true
LockPersonality=true
RestrictSUIDSGID=true

[Install]
WantedBy=default.target
"""
        return ServicePlan(
            path=home / ".config" / "systemd" / "user" / f"{SERVICE_NAME}.service",
            content=unit,
            activate=[
                ["systemctl", "--user", "daemon-reload"],
                ["systemctl", "--user", "enable", "--now", SERVICE_NAME],
                # Keep user services running when you're logged out.
                ["loginctl", "enable-linger", _current_user()],
            ],
            deactivate=[["systemctl", "--user", "disable", "--now", SERVICE_NAME]],
        )
    if platform == "darwin":
        args = "\n".join(f"    <string>{escape(a)}</string>" for a in cmd)
        log_dir = home / "Library" / "Logs"
        plist = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>{LAUNCHD_LABEL}</string>
  <key>ProgramArguments</key>
  <array>
{args}
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <dict><key>SuccessfulExit</key><false/></dict>
  <key>StandardOutPath</key>
  <string>{escape(str(log_dir / "ollamagate.log"))}</string>
  <key>StandardErrorPath</key>
  <string>{escape(str(log_dir / "ollamagate.log"))}</string>
</dict>
</plist>
"""
        path = home / "Library" / "LaunchAgents" / f"{LAUNCHD_LABEL}.plist"
        return ServicePlan(
            path=path,
            content=plist,
            activate=[["launchctl", "load", "-w", str(path)]],
            deactivate=[["launchctl", "unload", "-w", str(path)]],
        )
    if platform == "win32":
        # A script in the user's Startup folder: needs no admin rights (logon tasks
        # in Task Scheduler do) and runs with the user's own, limited permissions.
        # pythonw.exe runs without a console window.
        pythonw = Path(sys.executable).with_name("pythonw.exe")
        win_cmd = _serve_command(config_path, str(pythonw) if pythonw.exists() else None)
        appdata = Path(os.environ.get("APPDATA") or home / "AppData" / "Roaming")
        path = appdata / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup" / "OllamaGate.cmd"
        _check_printable(win_cmd)
        env_line = f'set "OLLAMAGATE_CONFIG_DIR={config_dir.replace("%", "%%")}"\r\n' if config_dir else ""
        command = " ".join(_cmd_quote(a) for a in win_cmd)
        script = "@echo off\r\n" + env_line + 'start "OllamaGate" /min ' + command + "\r\n"
        return ServicePlan(
            path=path,
            content=script,
            activate=[["cmd", "/c", str(path)]],
            deactivate=[],  # stop it from Task Manager, or `taskkill /im pythonw.exe` if nothing else uses it
        )
    raise RuntimeError(f"unsupported platform {platform!r}")


def running_as_admin() -> bool:
    if hasattr(os, "geteuid"):
        return os.geteuid() == 0
    try:
        import ctypes

        return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
    except (AttributeError, OSError):
        return False


def write_service_file(p: ServicePlan) -> None:
    if p.path is None:
        return
    # cmd.exe reads batch files in the OEM code page; unit files and plists are UTF-8.
    oem = p.path.suffix == ".cmd" and sys.platform == "win32"
    try:
        data = p.content.encode("oem" if oem else "utf-8")
    except UnicodeEncodeError:
        where = "the Windows console code page" if oem else "UTF-8"
        raise ValueError(f"a path contains characters that can't be written as {where}") from None
    p.path.parent.mkdir(parents=True, exist_ok=True)
    p.path.write_bytes(data)
