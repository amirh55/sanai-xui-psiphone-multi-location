"""VLESS + XHTTP behind Cloudflare CDN: inbound stream, nginx location, client link."""

from __future__ import annotations

import hashlib
import json
import socket
import ssl
import urllib.parse

DEFAULT_PATH = "/api/v1/items"
DEFAULT_PORT = 10088
DEFAULT_PADDING = "100-1000"
DEFAULT_MODE = "auto"
# Client fetches the ECH config of cloudflare-ech.com via DNS 1.1.1.1 (zone needs ECH on).
CF_ECH = "cloudflare-ech.com+udp://1.1.1.1"


def stream_settings(path: str, padding: str = DEFAULT_PADDING, mode: str = DEFAULT_MODE) -> dict:
    """Xray inbound streamSettings. TLS is done by Cloudflare + nginx, so security=none."""
    return {
        "network": "xhttp",
        "security": "none",
        "xhttpSettings": {
            "path": path,
            "host": "",
            "headers": {},
            "mode": mode,
            "xPaddingBytes": padding,
            "scMaxBufferedPosts": 30,
            "scMaxEachPostBytes": "1000000",
            "noSSEHeader": False,
        },
        "sockopt": {
            "tcpFastOpen": True,
            "tcpcongestion": "bbr",
            "trustedXForwardedFor": ["127.0.0.1", "CF-Connecting-IP"],
        },
    }


def client_link(
    uuid: str,
    address: str,
    domain: str,
    path: str,
    padding: str = DEFAULT_PADDING,
    mode: str = DEFAULT_MODE,
    ech: str = "",
    pcs: str = "",
    encryption: str = "none",
    remark: str = "cf-xhttp",
) -> str:
    """vless:// link in the same order v2rayN / v2rayNG export it."""
    extra = json.dumps({"mode": mode, "xPaddingBytes": padding}, separators=(",", ":"))
    q = [
        ("encryption", encryption or "none"),
        ("security", "tls"),
        ("sni", domain),
        ("fp", "chrome"),
        ("alpn", "h2"),
    ]
    if ech:
        q.append(("ech", ech))
    if pcs:
        q.append(("pcs", pcs))
    q += [
        ("type", "xhttp"),
        ("host", domain),
        ("path", path),
        ("mode", mode),
        ("extra", extra),
    ]
    query = "&".join("%s=%s" % (k, urllib.parse.quote(v, safe="")) for k, v in q)
    return "vless://%s@%s:443?%s#%s" % (uuid, address, query, urllib.parse.quote(remark, safe=""))


def cert_sha256(address: str, domain: str, port: int = 443, timeout: int = 10) -> str:
    """SHA256 (hex, upper) of the leaf cert the client sees = pcs value."""
    ctx = ssl.create_default_context()
    with socket.create_connection((address, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=domain) as tls:
            der = tls.getpeercert(binary_form=True)
    return hashlib.sha256(der).hexdigest().upper()


def _server_blocks(conf: str) -> list[tuple[int, int]]:
    """(start, end) of each top-level `server { ... }`; end is the index of its `}`."""
    out = []
    i = 0
    while True:
        start = conf.find("server", i)
        if start < 0:
            return out
        brace = conf.find("{", start)
        if brace < 0 or conf[start + len("server"):brace].strip():
            i = start + len("server")
            continue
        depth = 0
        for j in range(brace, len(conf)):
            if conf[j] == "{":
                depth += 1
            elif conf[j] == "}":
                depth -= 1
                if depth == 0:
                    out.append((start, j))
                    break
        else:
            return out
        i = j + 1


def insert_location(conf: str, block: str, path: str) -> str:
    """Add an nginx location into the `listen 443` server. Unchanged if path already there."""
    for start, end in _server_blocks(conf):
        body = conf[start:end]
        if "listen 443" not in body and "listen [::]:443" not in body:
            continue
        if ("location %s {" % path) in body or ("location %s/ {" % path) in body:
            return conf
        return conf[:end] + block.rstrip() + "\n" + conf[end:]
    raise ValueError("server block ba listen 443 peyda nashod")
