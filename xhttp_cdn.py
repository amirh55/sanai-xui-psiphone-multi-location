#!/usr/bin/env python3
"""VLESS + XHTTP + TLS behind Cloudflare CDN (optional WARP exit).

client --TLS h2 (ECH)--> Cloudflare edge --TLS--> nginx :443 --h2c--> Xray xhttp 127.0.0.1
Same prompts style as install.py (finglish / ASCII). Stdlib only.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

import install  # noqa: E402
from lib import nginx_site as NG  # noqa: E402
from lib import state as ST  # noqa: E402
from lib import ui  # noqa: E402
from lib import xhttp as X  # noqa: E402
from lib import xui  # noqa: E402

ui.enable_utf8()

REMARK = "cf-xhttp"


def cloudflare_checklist(domain: str, use_ech: bool) -> None:
    ui.say("")
    ui.say("Cloudflare dashboard (dasti, yek bar):")
    ui.say("  1) DNS: A record %s -> IP VPS, Proxy status = Proxied (abr narenji)" % domain)
    ui.say("  2) SSL/TLS > Overview: mode = Full (strict)")
    ui.say("     cert origin: Let's Encrypt ya Cloudflare Origin CA (hamoon ke nginx dare)")
    ui.say("  3) Network: gRPC = On  (baraye packet-up lazem nist, vali zarar nadare)")
    if use_ech:
        ui.say("  4) SSL/TLS > Edge Certificates: Encrypted ClientHello (ECH) = On")
        ui.say("     age in gozine nist, ech ro az link pak kon.")
    ui.say("  address link: IP tamiz Cloudflare (masalan 172.64.x.x / 104.x) ya khod domain")


def pick_warp(xs: dict) -> str:
    for tag in xui.outbound_tags(xs):
        if "warp" in tag.lower():
            return tag
    return ""


def usage() -> None:
    ui.say("usage: python3 xhttp_cdn.py [--dry-run] [--help]")
    ui.say("  --dry-run   faghat build/ misaze, VPS ro dast nemizane")
    ui.say("")
    ui.say("VLESS + XHTTP + TLS posht-e Cloudflare. nginx + 3x-ui + cert domain lazeme.")


def main() -> int:
    if "--help" in sys.argv or "-h" in sys.argv:
        usage()
        return 0
    ui.banner("VLESS + XHTTP + TLS posht-e Cloudflare CDN")

    dry = "--dry-run" in sys.argv
    if not install.is_root() and not dry:
        ui.say("root nisti. baraye nasb vaghei: sudo python3 xhttp_cdn.py")
        if not ui.ask_yes("dry-run (faghat file local)?", True):
            return 1
        dry = True
    prev = ST.load(root=install.is_root() and not dry)
    cf_prev = prev.get("xhttp_cdn") or {}

    domain, cert, key = install.pick_tls(cf_prev or prev)
    if not dry and (not Path(cert).is_file() or not Path(key).is_file()):
        raise SystemExit("cert ya key nist. aval certificate domain ro bezar.")

    ui.say("")
    path = "/" + ui.ask("xHTTP path", cf_prev.get("path") or X.DEFAULT_PATH).strip().strip("/")
    port = ui.ask_int("xHTTP listen port (Xray localhost)", int(cf_prev.get("port") or X.DEFAULT_PORT), 1, 65535)
    padding = ui.ask("xPaddingBytes", cf_prev.get("padding") or X.DEFAULT_PADDING)
    address = ui.ask("address too link (IP tamiz Cloudflare ya domain)", cf_prev.get("address") or domain)
    use_ech = ui.ask_yes("ECH (cloudflare-ech.com) too link?", True)
    use_pcs = ui.ask_yes("pcs (pin cert Cloudflare) too link? (cert har ~90 rooz avaz mishe)", False)

    ui.say("")
    do_panel = ui.ask_yes("inbound XHTTP too panel 3x-ui sakhte she?", True)
    panel = None
    pinfo: dict = {}
    if do_panel:
        panel, pinfo = install.connect_panel(prev, dry)
        if not dry and panel is None:
            ui.say("panel skip (token nist).")
            do_panel = False
    use_warp = ui.ask_yes("khorooj internet az WARP? (outbound warp too panel lazeme)", False)

    ui.say("")
    ui.say("kholase:")
    ui.say("  domain   = %s" % domain)
    ui.say("  address  = %s:443" % address)
    ui.say("  path     = %s  -> 127.0.0.1:%s" % (path, port))
    ui.say("  padding  = %s   mode = %s" % (padding, X.DEFAULT_MODE))
    ui.say("  ech=%s pcs=%s panel=%s warp=%s" % (use_ech, use_pcs, do_panel, use_warp))
    if not ui.ask_yes("shoro konam?", True):
        ui.say("cancel.")
        return 1

    state = dict(prev)
    state["xhttp_cdn"] = {
        "domain": domain, "cert": cert, "key": key, "path": path, "port": port,
        "padding": padding, "address": address, "warp": use_warp,
    }
    ST.save(state, root=install.is_root() and not dry)
    ech = X.CF_ECH if use_ech else ""
    remark = "cf-edge-warp" if use_warp else "cf-edge-xhttp"

    if dry:
        out = ROOT / "build"
        out.mkdir(exist_ok=True)
        (out / "xhttp-location.conf").write_text(NG.xhttp_location(path, port), encoding="utf-8")
        (out / "xhttp-stream.json").write_text(json.dumps(X.stream_settings(path, padding), indent=2), encoding="utf-8")
        link = X.client_link("UUID", address, domain, path, padding, ech=ech, remark=remark)
        (out / "xhttp-link.txt").write_text(link + "\n", encoding="utf-8")
        ui.say("")
        ui.say("DRY-RUN ok. file ha: %s" % out)
        ui.say(link)
        cloudflare_checklist(domain, use_ech)
        return 0

    ui.banner("1/3  nginx location %s" % path)
    block = NG.xhttp_location(path, port)
    if not NG.add_location(domain, block, path):
        install.confirm_443()
        NG.ensure_nginx()
        NG.write_site(domain, cert, key, [], NG.DEFAULT_HTML, True, path, port)

    uuid, encryption = None, ""
    if do_panel and panel is not None:
        ui.banner("2/3  3x-ui inbound XHTTP")
        clone = xui.clone_from_inbound(panel, int(pinfo.get("source_id") or 1))
        rec = {"remark": REMARK, "listen": port, "tag": "in-%s-xhttp" % port}
        attach = pinfo.get("attach_email") or None
        xui.ensure_inbound(panel, rec, domain, clone, attach, stream=X.stream_settings(path, padding))
        try:
            xui.add_host(panel, rec, domain, alpn=["h2"], address=address)
        except Exception as e:
            ui.say("host add fail (link paeen ro estefade kon): %s" % e)
        if use_warp:
            ui.banner("3/3  routing -> WARP")
            xs = xui.get_xray(panel)
            warp = pick_warp(xs)
            if warp:
                xui.route_inbound(xs, rec["tag"], warp)
                xui.put_xray(panel, xs)
                ui.say("%s -> %s" % (rec["tag"], warp))
            else:
                ui.say("outbound warp peyda nashod.")
                ui.say("panel > Xray Configs > Outbounds > WARP > create, bad dobare in script.")
        uuid, encryption = xui.client_uuid(panel, attach)
    else:
        ui.say("panel skip. inbound dasti: VLESS, listen 127.0.0.1:%s, network xhttp, path %s, security none" % (port, path))

    pcs = ""
    if use_pcs:
        try:
            pcs = X.cert_sha256(address, domain)
        except Exception as e:
            ui.say("pcs hesab nashod (%s). bedoone pcs." % e)

    ui.banner("tamoom")
    if not uuid:
        ui.say("client attach nashode: UUID ro az panel bezar jaye UUID.")
    ui.say(X.client_link(uuid or "UUID", address, domain, path, padding,
                         ech=ech, pcs=pcs, encryption=encryption or "none", remark=remark))
    cloudflare_checklist(domain, use_ech)
    ui.say("")
    ui.say("check:  curl -s -o /dev/null -w '%%{http_code}\\n' https://%s%s" % (domain, path))
    ui.say("        502/504 = nginx be Xray nemirese (inbound/port check kon)")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        ui.say("\ncancel.")
        raise SystemExit(130)
