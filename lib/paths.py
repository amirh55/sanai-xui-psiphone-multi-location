"""Pick camouflage HTTP paths that look like a normal website."""

from __future__ import annotations

import secrets
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PATHS_FILE = ROOT / "data" / "common-paths.txt"

# Words that would make a path look like a tunnel, not a site.
BANNED = (
    "ws", "wss", "grpc", "vless", "vmess", "trojan", "tuic", "hysteria",
    "hy2", "xhttp", "xray", "v2ray", "psiphon", "vpn", "proxy", "tunnel",
    "socks", "ssr", "shadowsocks", "reality", "outbound", "inbound",
)


def load_pool() -> list[str]:
    rows = []
    for line in PATHS_FILE.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if not line.startswith("/"):
            line = "/" + line
        low = line.lower()
        if any(b in low.split("/") for b in BANNED) or any(b in low for b in ("/ws-", "vless", "vmess")):
            continue
        if line not in rows:
            rows.append(line)
    return rows


def nginx_location(path: str) -> str:
    """Path nginx matches (no query string)."""
    return (path or "/").split("?", 1)[0]


def xray_ws_path(path: str, early_data: int = 2560) -> str:
    base = nginx_location(path)
    if early_data and "ed=" not in base:
        return "%s?ed=%s" % (base, early_data)
    return base


def _extra(used: set[str]) -> str:
    n = secrets.randbelow(900) + 100
    candidates = (
        "/assets/js/chunk-%s.js" % n,
        "/static/js/page-%s.min.js" % n,
        "/cdn/static/js/app-%s.js" % n,
        "/_next/static/chunks/%s.js" % n,
        "/wp-content/uploads/cache/%s.json" % n,
    )
    for c in candidates:
        if c not in used:
            return c
    return "/assets/js/chunk-%s-%s.js" % (n, secrets.randbelow(99) + 1)


def pick_unique(n: int, used: set[str] | None = None) -> list[str]:
    """n unique camouflage paths, random order from the pool."""
    used = set(used or ())
    pool = [p for p in load_pool() if p not in used]
    rng = secrets.SystemRandom()
    rng.shuffle(pool)
    out = []
    for p in pool:
        if len(out) >= n:
            break
        out.append(p)
        used.add(p)
    while len(out) < n:
        p = _extra(used)
        out.append(p)
        used.add(p)
    return out
