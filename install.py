#!/usr/bin/env python3
"""Interactive installer: nginx fake-site + 3x-ui inbounds + one Psiphon per country.

All prompts are finglish (ASCII) so a Linux terminal without Persian fonts still works.
Stdlib only. Run as root on Ubuntu/Debian.
"""

from __future__ import annotations

import json
import os
import shutil
import sys
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from lib import countries as C  # noqa: E402
from lib import detect as D  # noqa: E402
from lib import nginx_site as NG  # noqa: E402
from lib import psiphon as P  # noqa: E402
from lib import state as ST  # noqa: E402
from lib import ui  # noqa: E402
from lib import xui  # noqa: E402

ui.enable_utf8()


def is_root() -> bool:
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False


def parse_panel_url(raw: str) -> tuple[str, int]:
    """Return (webBasePath, port) from a full panel URL or a bare path."""
    raw = (raw or "").strip()
    if not raw:
        return "", 2053
    if "://" not in raw and not raw.startswith("/"):
        return raw.strip("/"), 2053
    if "://" not in raw:
        return raw.strip("/").removesuffix("/panel"), 2053
    u = urlparse(raw)
    port = u.port or (443 if u.scheme == "https" else 80)
    path = u.path.rstrip("/")
    if path.endswith("/panel"):
        path = path[: -len("/panel")]
    return path.strip("/"), port


def pick_html() -> Path:
    ui.say("")
    ui.say("HTML site (safhe-ye fake rooye / ):")
    ui.say("  1) template default (templates/index.html)")
    ui.say("  2) masir file html (masalan /root/mysite.html)")
    ui.say("  3) folder site (index.html + css/js copy mishe)")
    choice = ui.ask("entekhab", "1")
    if choice == "2":
        p = Path(ui.ask("masir file html")).expanduser()
        if not p.is_file():
            raise SystemExit("file nist: %s" % p)
        return p
    if choice == "3":
        p = Path(ui.ask("masir folder")).expanduser()
        idx = p / "index.html"
        if not idx.is_file():
            raise SystemExit("index.html too in folder nist: %s" % p)
        return p
    return NG.DEFAULT_HTML


def pick_countries(rows: list[dict]) -> list[dict]:
    ui.banner("list keshvar haye Psiphon")
    ui.table_countries(rows)
    ui.say("mesal:  7 20 26 28")
    ui.say("ya:     1,2,5")
    ui.say("ya:     7-10")
    ui.say("ya:     DE NL US SG   (code)")
    while True:
        raw = ui.ask("shomare ya code keshvar ha")
        idxs = ui.parse_selection(raw, len(rows))
        codes = []
        if idxs:
            codes = [rows[i - 1]["code"] for i in idxs]
        else:
            by = {r["code"]: r for r in rows}
            for tok in raw.replace(",", " ").split():
                t = tok.strip().upper()
                if t in by and t not in codes:
                    codes.append(t)
        if not codes:
            ui.say("hich keshvar select nashod. dobare bezan.")
            continue
        recs = C.assign_ports(codes)
        ui.say("")
        ui.say("entekhab shode:")
        ui.say("  FLAG  CODE  PATH")
        for r in recs:
            ui.say("  %s   %-4s  %s" % (r.get("flag") or "  ", r["code"], r["path"]))
            ui.say("         listen 127.0.0.1:%s  socks %s" % (r["listen"], r["socks"]))
        if ui.ask_yes("in list ok-e? (n = path jadid random)", True):
            return recs


def pick_tls(prev: dict) -> tuple[str, str, str]:
    """Scan certs, list domains by number, or c = custom."""
    guess = D.guess_domain(prev)
    hits = D.unique_tls_domains()
    ui.say("")
    ui.say("TLS / domain (scan cert folders + nginx):")
    if hits:
        for i, h in enumerate(hits, 1):
            ui.say("  %s) %s" % (i, h["domain"]))
            ui.say("      %s" % h["cert"])
        ui.say("  c) custom")
        raw = ui.ask("kodom domain?", "1")
        if raw.lower() not in ("c", "custom"):
            try:
                idx = int(raw)
            except ValueError:
                idx = 1
            if 1 <= idx <= len(hits):
                h = hits[idx - 1]
                ui.say("ok %s" % h["domain"])
                return h["domain"], h["cert"], h["key"]
    else:
        ui.say("  hich cert default peyda nashod.")
        ui.say("  custom: domain + masir file.")

    domain = ui.ask("domain (SNI / nginx server_name)", guess or prev.get("domain") or "example.com").strip().lower()
    local = D.certs_for_domain(domain)
    default_cert = prev.get("cert") or (local[0]["cert"] if local else "/root/cert/%s/fullchain.pem" % domain)
    default_key = prev.get("key") or (local[0]["key"] if local else "/root/cert/%s/privkey.pem" % domain)
    if local:
        ui.say("  cert in domain: %s" % local[0]["cert"])
    cert = ui.ask("masir fullchain.pem", default_cert)
    key = ui.ask("masir privkey.pem", default_key)
    return domain, cert, key


def connect_panel(prev: dict, dry: bool) -> tuple[xui.Panel | None, dict]:
    """Try local 3x-ui db/CLI first; ask for API token only if needed."""
    info: dict = {
        "token": "",
        "path": "",
        "port": 2053,
        "attach_email": prev.get("attach_email") or "",
        "source_id": 1,
        "auto": False,
    }
    found = D.panel_from_local()
    token = ""
    path = ""
    port = 2053
    if found:
        ui.say("panel local: port=%s path=/%s source=%s" % (found["port"], found.get("path") or "", found.get("source")))
        if found.get("token"):
            ui.say("API token az database/CLI umad.")
            token = found["token"]
            path = found.get("path") or ""
            port = int(found.get("port") or 2053)
            info["auto"] = True
        else:
            ui.say("panel hast vali API token khali-e (Settings > Security).")
    if not token:
        ui.say("API token dasti (khali = panel skip).")
        token = ui.ask("API token", "")
        if not token:
            return None, info
        raw_url = ui.ask(
            "URL panel ya webBasePath (khali = auto)",
            prev.get("panel_url") or (found.get("path") if found else ""),
        )
        if raw_url:
            path, port = parse_panel_url(raw_url)
            if not path and raw_url and "://" not in raw_url:
                path = raw_url.strip("/")
        elif found:
            path = found.get("path") or ""
            port = int(found.get("port") or 2053)
        port = ui.ask_int("port panel (listen local)", port, 1, 65535)

    info.update({"token": token, "path": path, "port": port})
    if dry:
        ui.say("dry-run: panel API skip.")
        return None, info
    base = xui.detect_base(token, path, port)
    panel = xui.Panel(base, token)
    info["source_id"] = pick_source_inbound(panel)
    info["attach_email"] = ui.ask(
        "email/remark client baraye attach (khali = skip)",
        prev.get("attach_email") or "",
    )
    return panel, info


def pick_source_inbound(p: xui.Panel) -> int:
    opts = xui.list_inbounds(p)
    if not opts:
        raise SystemExit("panel inbound nadare. aval yek inbound VLESS+WS besaz.")
    ui.say("")
    ui.say("  ID    PROTO    PORT   REMARK")
    ui.say("  ----  -------  -----  ----------")
    for o in opts:
        ui.say("  %-5s %-8s %-5s %s" % (o.get("id"), o.get("protocol"), o.get("port"), o.get("remark")))
    default = opts[0].get("id")
    return ui.ask_int("id inbound-e source (clone type/encryption az in)", default)


def confirm_443() -> None:
    who = NG.check_443()
    if not who:
        return
    ui.say("")
    ui.say("WARNING: port 443 already listen:")
    ui.say(who[:800])
    ui.say("nginx bayad 443 dashte bashe. Reality/Xray rooye 443 bayad disable she.")
    if not ui.ask_yes("edame bedam? (nginx reload momkene fail she)", False):
        raise SystemExit("cancel. aval inbound 443 panel ro disable kon.")


def write_nginx_preview(domain: str, recs: list[dict], html: Path, with_xhttp: bool, xhttp_path: str, xhttp_port: int) -> Path:
    out = ROOT / "build"
    out.mkdir(exist_ok=True)
    locs = "".join(NG.ws_location(r["path"], r["listen"]) for r in recs)
    if with_xhttp:
        locs += NG.xhttp_location(xhttp_path, xhttp_port)
    conf = """# generated preview — copy to /etc/nginx/sites-available/%s.conf
server {
    listen 80;
    server_name %s;
    return 301 https://$host$request_uri;
}
server {
    listen 443 ssl http2;
    server_name %s;
    ssl_certificate     /root/cert/%s/fullchain.pem;
    ssl_certificate_key /root/cert/%s/privkey.pem;
    root /var/www/%s;
    index index.html;
    location / { try_files $uri $uri/ =404; }
%s
}
""" % (domain, domain, domain, domain, domain, domain, locs)
    p = out / ("%s.nginx.conf" % domain)
    p.write_text(conf, encoding="utf-8")
    if html.is_dir():
        NG.copy_webroot(html, out / "site")
    else:
        shutil.copyfile(html, out / "index.html")
    (out / "selected.json").write_text(json.dumps(recs, indent=2), encoding="utf-8")
    return p


def usage() -> None:
    ui.say("usage: python3 install.py [--dry-run] [--help]")
    ui.say("  --dry-run   file local misaze, VPS ro dast nemizane")
    ui.say("  --help      in matn")
    ui.say("")
    ui.say("root Ubuntu/Debian. panel 3x-ui + certificate domain lazeme.")


def main() -> int:
    if "--help" in sys.argv or "-h" in sys.argv:
        usage()
        return 0
    ui.banner("3x-ui + nginx + Psiphon multi-location")
    ui.say("text ha finglish-an (terminal font Farsi nakhune).")
    ui.say("har keshvar = yek process psiphon-tunnel-core + inbound + path nginx.")
    ui.say("")

    want_dry = "--dry-run" in sys.argv
    if not is_root() and not want_dry:
        ui.say("root nisti. baraye nasb vaghei: sudo python3 install.py")
        if not ui.ask_yes("dry-run (faghat file local)?", True):
            return 1
        want_dry = True
    dry = want_dry
    prev = ST.load(root=is_root() and not dry)

    rows = C.load_countries()
    recs = pick_countries(rows)

    domain, cert, key = pick_tls(prev)
    if not dry:
        if not Path(cert).is_file() or not Path(key).is_file():
            raise SystemExit("cert ya key nist. aval certificate domain ro bezar.")

    html = pick_html()

    ui.say("")
    do_nginx = ui.ask_yes("nginx reverse proxy + fake site rooye 443 nasb she?", True)
    with_xhttp = ui.ask_yes("location xHTTP ezafe she? (masalan /blog)", False)
    xhttp_path = "/blog"
    xhttp_port = 10088
    if with_xhttp:
        xhttp_path = ui.ask("xHTTP path", "/blog")
        if not xhttp_path.startswith("/"):
            xhttp_path = "/" + xhttp_path
        xhttp_port = ui.ask_int("xHTTP listen port (Xray localhost)", 10088, 1, 65535)

    ui.say("")
    do_panel = ui.ask_yes("inbound + outbound + routing + Hosts too panel 3x-ui sakhte she?", True)
    token = ""
    panel_path = ""
    panel_port = 2053
    source_id = 1
    attach_email = ""
    panel = None
    if do_panel:
        panel, pinfo = connect_panel(prev, dry)
        token = pinfo.get("token") or ""
        panel_path = pinfo.get("path") or ""
        panel_port = int(pinfo.get("port") or 2053)
        source_id = int(pinfo.get("source_id") or 1)
        attach_email = pinfo.get("attach_email") or ""
        if not dry and panel is None:
            ui.say("panel skip (token nist). inbound dasti nemisaze.")
            do_panel = False

    ui.say("")
    ui.say("kholase:")
    ui.say("  domain     = %s" % domain)
    ui.say("  countries  = %s" % " ".join(r["code"] for r in recs))
    ui.say("  nginx      = %s" % do_nginx)
    ui.say("  panel      = %s" % do_panel)
    ui.say("  html       = %s" % html)
    ui.say("  xhttp      = %s %s:%s" % (with_xhttp, xhttp_path, xhttp_port))
    if not ui.ask_yes("shoro konam?", True):
        ui.say("cancel.")
        return 1

    ST.save(
        {
            "domain": domain,
            "cert": cert,
            "key": key,
            "panel_url": "https://127.0.0.1:%s/%s" % (panel_port, panel_path),
            "panel_port": panel_port,
            "attach_email": attach_email,
            "countries": [r["code"] for r in recs],
            "recs": recs,
            "xhttp": {"enabled": with_xhttp, "path": xhttp_path, "port": xhttp_port},
        },
        root=is_root() and not dry,
    )

    if dry:
        preview = write_nginx_preview(domain, recs, html, with_xhttp, xhttp_path, xhttp_port)
        ui.say("")
        ui.say("DRY-RUN ok. file ha: %s" % preview.parent)
        ui.say("rooye VPS: git clone + python3 install.py  (root)")
        return 0

    ui.banner("1/4  psiphon processes")
    P.start_instances(recs)
    socks_ok = P.wait_socks(recs, timeout=180)
    bad = [c for c, ok in socks_ok.items() if not ok]
    if bad:
        ui.say("WARNING in keshvar ha SOCKS nadashtan: %s" % " ".join(bad))
        ui.say("edame midam; routing sakhte mishe, tunnel bad-an momkene up she.")

    if do_nginx:
        ui.banner("2/4  nginx")
        confirm_443()
        NG.ensure_nginx()
        NG.write_site(domain, cert, key, recs, html, with_xhttp, xhttp_path, xhttp_port)
    else:
        ui.say("nginx skip shod.")

    if do_panel and panel is not None:
        ui.banner("3/4  3x-ui inbounds + hosts")
        clone = xui.clone_from_inbound(panel, source_id)
        ui.say("clone az inbound %s proto=%s enc=%s" % (source_id, clone["protocol"], (clone["encryption"] or "none")[:40]))
        for rec in recs:
            xui.ensure_inbound(panel, rec, domain, clone, attach_email or None)
            xui.add_host(panel, rec, domain)
        ui.banner("4/4  outbound socks + routing + DNS")
        xui.apply_routing(panel, recs)
        links = xui.client_links(panel, recs, domain, attach_email or None)
        ui.say("")
        ui.say("link haye client (hamishe :443 + tls, path motafavet):")
        for L in links:
            ui.say(L)
    else:
        ui.say("panel skip. inbound-ha ro dasti besaz: listen 127.0.0.1, path /ws-XX, security=none")

    ui.banner("tamoom")
    P.status_line()
    ui.say("")
    ui.say("check site:  curl -I https://%s/" % domain)
    ui.say("status:      python3 status.py")
    ui.say("uninstall:   python3 uninstall.py")
    ui.say("")
    ui.say("yadavari: har process ~40MB RAM. 1 CPU = 4-6 keshvar kafie.")
    ui.say("bandwidth double-e (vorood VPS + khorooj Psiphon).")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        ui.say("\ncancel.")
        raise SystemExit(130)
