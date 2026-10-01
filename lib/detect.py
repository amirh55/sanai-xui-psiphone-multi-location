"""Find 3x-ui (local sqlite/CLI) and TLS certs in common paths."""

from __future__ import annotations

import glob
import sqlite3
import subprocess
from pathlib import Path

from . import ui

XUI_DBS = (
    Path("/etc/x-ui/x-ui.db"),
    Path("/usr/local/x-ui/x-ui.db"),
    Path("/etc/x-ui/bin/x-ui.db"),
)

CERT_FILES = (
    "fullchain.pem",
    "fullchain.crt",
    "cert.pem",
    "certificate.crt",
    "fullchain.cer",
)
KEY_FILES = (
    "privkey.pem",
    "privkey.key",
    "private.key",
    "key.pem",
)


def _sqlite_settings(db: Path) -> dict[str, str]:
    uri = "file:%s?mode=ro" % db.as_posix()
    con = sqlite3.connect(uri, uri=True, timeout=3)
    try:
        out = {}
        for table in ("settings", "setting"):
            try:
                cur = con.execute("SELECT key, value FROM %s" % table)
            except sqlite3.Error:
                continue
            for k, v in cur.fetchall():
                if k is None:
                    continue
                out[str(k)] = "" if v is None else str(v)
            if out:
                return out
        return out
    finally:
        con.close()


def _cli_settings() -> dict[str, str]:
    for bin_name in ("x-ui", "/usr/local/x-ui/x-ui"):
        try:
            p = subprocess.run(
                [bin_name, "setting", "-show"],
                capture_output=True,
                text=True,
                timeout=8,
            )
        except Exception:
            continue
        if p.returncode != 0 or not (p.stdout or "").strip():
            continue
        out: dict[str, str] = {}
        for line in p.stdout.splitlines():
            if ":" not in line:
                continue
            k, v = line.split(":", 1)
            out[k.strip()] = v.strip()
        if out:
            return out
    return {}


def _pick_token(settings: dict[str, str]) -> str:
    for key in ("apiToken", "api_token", "ApiToken", "webServerToken", "secretToken"):
        val = (settings.get(key) or "").strip()
        if val and val.lower() not in ("null", "none", "false"):
            return val
    for k, v in settings.items():
        lk = k.lower()
        if "token" in lk and "tg" not in lk and "telegram" not in lk:
            val = (v or "").strip()
            if val and len(val) >= 16:
                return val
    return ""


def panel_from_local() -> dict:
    """Return {port, path, token, listen, source} or {}."""
    settings: dict[str, str] = {}
    source = ""
    for db in XUI_DBS:
        if not db.is_file():
            continue
        try:
            settings = _sqlite_settings(db)
            source = str(db)
            break
        except Exception as e:
            ui.say("sqlite panel khund nashod (%s): %s" % (db, e))
    if not settings:
        settings = _cli_settings()
        if settings:
            source = "x-ui setting -show"
    if not settings:
        return {}
    port_raw = settings.get("webPort") or settings.get("port") or "2053"
    try:
        port = int(str(port_raw).strip() or "2053")
    except ValueError:
        port = 2053
    path = (settings.get("webBasePath") or settings.get("basePath") or "").strip().strip("/")
    listen = (settings.get("webListen") or "127.0.0.1").strip() or "127.0.0.1"
    token = _pick_token(settings)
    return {
        "port": port,
        "path": path,
        "token": token,
        "listen": listen,
        "source": source,
        "webCert": settings.get("webCertFile") or "",
        "webKey": settings.get("webKeyFile") or "",
    }


def _pair_in_dir(folder: Path) -> tuple[Path, Path] | None:
    if not folder.is_dir():
        return None
    cert = None
    key = None
    for name in CERT_FILES:
        p = folder / name
        if p.is_file():
            cert = p
            break
    for name in KEY_FILES:
        p = folder / name
        if p.is_file():
            key = p
            break
    # acme.sh: domain.key next to fullchain.cer
    if cert and not key:
        for p in folder.glob("*.key"):
            key = p
            break
    if cert and key:
        return cert, key
    return None


def certs_for_domain(domain: str) -> list[dict]:
    domain = (domain or "").strip().lower()
    if not domain:
        return []
    candidates: list[Path] = [
        Path("/root/cert") / domain,
        Path("/root/certs") / domain,
        Path("/etc/letsencrypt/live") / domain,
        Path("/etc/nginx/ssl") / domain,
        Path("/root/.acme.sh") / ("%s_ecc" % domain),
        Path("/root/.acme.sh") / domain,
        Path("/etc/ssl") / domain,
    ]
    found = []
    seen = set()
    for folder in candidates:
        pair = _pair_in_dir(folder)
        if not pair:
            continue
        cert, key = pair
        sig = (str(cert), str(key))
        if sig in seen:
            continue
        seen.add(sig)
        found.append({"domain": domain, "cert": str(cert), "key": str(key), "dir": str(folder)})
    return found


def discover_cert_domains() -> list[dict]:
    """Scan well-known trees; each hit has domain + cert + key."""
    hits: list[dict] = []
    globs = [
        "/root/cert/*/",
        "/root/certs/*/",
        "/etc/letsencrypt/live/*/",
        "/etc/nginx/ssl/*/",
        "/root/.acme.sh/*/",
    ]
    seen = set()
    for pattern in globs:
        for folder_s in glob.glob(pattern):
            folder = Path(folder_s)
            name = folder.name
            if name.endswith("_ecc"):
                name = name[: -len("_ecc")]
            if name in ("README", "accounts", "ca", "renewal"):
                continue
            pair = _pair_in_dir(folder)
            if not pair:
                continue
            cert, key = pair
            sig = (str(cert), str(key))
            if sig in seen:
                continue
            seen.add(sig)
            hits.append({"domain": name.lower(), "cert": str(cert), "key": str(key), "dir": str(folder)})
    return hits


def nginx_server_names() -> list[str]:
    names: list[str] = []
    for path in glob.glob("/etc/nginx/sites-enabled/*") + glob.glob("/etc/nginx/conf.d/*.conf"):
        try:
            text = Path(path).read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        for line in text.splitlines():
            s = line.strip()
            if not s.startswith("server_name"):
                continue
            rest = s[len("server_name") :].strip().rstrip(";").strip()
            for tok in rest.split():
                if tok in ("_", "localhost") or tok.startswith("$"):
                    continue
                names.append(tok.lower())
    # unique, keep order
    out = []
    for n in names:
        if n not in out:
            out.append(n)
    return out


def unique_tls_domains() -> list[dict]:
    """One row per domain (first cert pair wins), plus nginx names that have certs."""
    by: dict[str, dict] = {}
    for h in discover_cert_domains():
        d = h["domain"]
        if d not in by:
            by[d] = h
    for n in nginx_server_names():
        if n in by:
            continue
        local = certs_for_domain(n)
        if local:
            by[n] = local[0]
    return sorted(by.values(), key=lambda x: x["domain"])


def guess_domain(prev: dict | None = None) -> str:
    prev = prev or {}
    if prev.get("domain"):
        return str(prev["domain"]).strip().lower()
    names = nginx_server_names()
    if names:
        return names[0]
    hits = unique_tls_domains()
    if hits:
        return hits[0]["domain"]
    return ""
