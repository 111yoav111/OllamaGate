"""Tiny, dependency-free User-Agent summariser for display ("iPhone · Safari")."""

from __future__ import annotations

import re

_OS = [
    (re.compile(r"iPhone"), "iPhone"),
    (re.compile(r"iPad"), "iPad"),
    (re.compile(r"Android"), "Android"),
    (re.compile(r"Windows"), "Windows"),
    (re.compile(r"Mac OS X|Macintosh|Darwin"), "macOS"),
    (re.compile(r"CrOS"), "ChromeOS"),
    (re.compile(r"Linux"), "Linux"),
]
_CLIENT = [
    (re.compile(r"Edg/"), "Edge"),
    (re.compile(r"Firefox/"), "Firefox"),
    (re.compile(r"Chrome/"), "Chrome"),
    (re.compile(r"Safari/"), "Safari"),
    (re.compile(r"(?i)open-?webui"), "Open WebUI"),
    (re.compile(r"(?i)enchanted"), "Enchanted"),
    (re.compile(r"(?i)^ollama"), "Ollama client"),
    (re.compile(r"(?i)^openai/python|^OpenAI/"), "OpenAI SDK"),
    (re.compile(r"(?i)^python-httpx|^python-requests|^aiohttp"), "Python"),
    (re.compile(r"(?i)^curl/"), "curl"),
    (re.compile(r"(?i)^node|axios"), "Node.js"),
]


def summarize(ua: str) -> str:
    if not ua:
        return "-"
    os_name = next((name for rx, name in _OS if rx.search(ua)), "")
    client = next((name for rx, name in _CLIENT if rx.search(ua)), "")
    parts = [p for p in (os_name, client) if p]
    return " · ".join(parts) if parts else ua[:30]
