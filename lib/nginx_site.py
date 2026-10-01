"""Install nginx reverse proxy: fake site on / + WS paths + optional xhttp /blog."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

from . import paths as camouflage
from . import ui

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_HTML = ROOT / "templates" / "index.html"


def sh(cmd: str, check: bool = True) -> subprocess.CompletedProcess:
    ui.say("+ " + cmd)
    p = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if p.stdout.strip():
        ui.say(p.stdout.strip()[:1500])
    if p.returncode != 0 and check:
        if p.stderr.strip():
            ui.say(p.stderr.strip()[:1500])
        raise RuntimeError("cmd failed: %s" % cmd)
    return p


def ensure_nginx() -> None:
    if shutil.which("nginx"):
        return
    ui.say("nginx nist, install mikonam...")
    sh("DEBIAN_FRONTEND=noninteractive apt-get update -y")
    sh("DEBIAN_FRONTEND=noninteractive apt-get install -y nginx")


def ws_location(path: str, listen: int) -> str:
    loc = camouflage.nginx_location(path)
    return """
    location = %s {
        proxy_pass http://127.0.0.1:%s;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 1h;
        proxy_send_timeout 1h;
        proxy_buffering off;
        client_max_body_size 0;
    }
""" % (loc, listen)


def xhttp_location(path: str = "/blog", listen: int = 10088) -> str:
    return """
    location %s {
        grpc_pass grpc://127.0.0.1:%s;
        grpc_set_header Host $host;
        grpc_set_header X-Real-IP $remote_addr;
        grpc_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        grpc_read_timeout 1h;
        grpc_send_timeout 1h;
        grpc_socket_keepalive on;
        client_max_body_size 0;
        client_body_timeout 1h;
    }
""" % (path, listen)


def copy_webroot(html_src: Path, webroot: Path) -> None:
    webroot.mkdir(parents=True, exist_ok=True)
    src = Path(html_src)
    if src.is_dir():
        for item in src.iterdir():
            dest = webroot / item.name
            if item.is_dir():
                if dest.exists():
                    shutil.rmtree(dest)
                shutil.copytree(item, dest)
            else:
                shutil.copy2(item, dest)
        ui.say("html folder copy: %s -> %s" % (src, webroot))
        return
    dest = webroot / "index.html"
    shutil.copyfile(src, dest)
    ui.say("html copy: %s -> %s" % (src, dest))


def write_site(domain: str, cert: str, key: str, recs: list[dict], html_src: Path, with_xhttp: bool, xhttp_path: str, xhttp_port: int) -> None:
    webroot = Path("/var/www") / domain
    copy_webroot(html_src, webroot)

    locs = "".join(ws_location(r["path"], r["listen"]) for r in recs)
    if with_xhttp:
        locs += xhttp_location(xhttp_path, xhttp_port)

    conf = """server {
    listen 80;
    listen [::]:80;
    server_name %s;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name %s;

    ssl_certificate     %s;
    ssl_certificate_key %s;
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers off;
    ssl_session_timeout 1d;
    ssl_session_cache   shared:SSL:10m;

    root /var/www/%s;
    index index.html;

    add_header X-Content-Type-Options nosniff always;
    add_header Referrer-Policy strict-origin-when-cross-origin always;

    location / {
        try_files $uri $uri/ =404;
    }
%s
}
""" % (domain, domain, cert, key, domain, locs)

    avail = Path("/etc/nginx/sites-available/%s.conf" % domain)
    enabled = Path("/etc/nginx/sites-enabled/%s.conf" % domain)
    avail.write_text(conf, encoding="utf-8")
    if enabled.exists() or enabled.is_symlink():
        enabled.unlink()
    enabled.symlink_to(avail)
    default = Path("/etc/nginx/sites-enabled/default")
    if default.exists() or default.is_symlink():
        default.unlink()
    sh("nginx -t")
    sh("systemctl enable nginx")
    sh("systemctl reload nginx || systemctl restart nginx")


def check_443() -> str:
    p = sh("ss -lntp | grep ':443 ' || true", check=False)
    return p.stdout.strip()
