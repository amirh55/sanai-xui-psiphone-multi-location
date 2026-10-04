#!/usr/bin/env python3
"""Offline checks (no VPS, no root)."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from lib import countries as C
from lib import ui


def test_countries():
    rows = C.load_countries()
    codes = [r["code"] for r in rows]
    assert len(rows) == 28, len(rows)
    for need in ("DE", "NL", "US", "SG", "GB", "FR", "JP"):
        assert need in codes, need
    recs = C.assign_ports(["DE", "NL", "US", "SG", "GB"])
    by = {r["code"]: r for r in recs}
    assert by["DE"]["listen"] == 10102 and by["DE"]["socks"] == 1082
    assert by["US"]["listen"] == 10101
    assert by["GB"]["listen"] >= 10110
    paths = [r["path"] for r in recs]
    assert len(paths) == len(set(paths))
    for p in paths:
        assert p.startswith("/")
        low = p.lower()
        assert "ws-" not in low
        assert "vless" not in low
        assert "psiphon" not in low
    ports = [r["listen"] for r in recs] + [r["socks"] for r in recs] + [r["http"] for r in recs]
    assert len(ports) == len(set(ports)), ports
    assert C.flag_emoji("DE") == "\U0001F1E9\U0001F1EA"
    assert C.flag_emoji("US") == "\U0001F1FA\U0001F1F8"
    assert rows[0]["flag"]
    assert by["DE"]["flag"] == C.flag_emoji("DE")


def test_parse_selection():
    assert ui.parse_selection("7 20 26 28", 28) == [7, 20, 26, 28]
    assert ui.parse_selection("1,2,5", 10) == [1, 2, 5]
    assert ui.parse_selection("7-10", 28) == [7, 8, 9, 10]
    assert ui.parse_selection("3-1", 5) == [1, 2, 3]
    assert ui.parse_selection("99", 5) == []
    assert ui.parse_selection("", 5) == []


def test_psiphon_template():
    tpl = (ROOT / "templates" / "psiphon.config.json.tmpl").read_text(encoding="utf-8")
    filled = (
        tpl.replace("__HTTP_PORT__", "8082")
        .replace("__SOCKS_PORT__", "1082")
        .replace("__REGION__", "DE")
        .replace("__DATA_DIR__", "/opt/psiphon/data-de")
    )
    obj = json.loads(filled)
    assert obj["EgressRegion"] == "DE"
    assert obj["LocalSocksProxyPort"] == 1082
    assert obj["DataStoreDirectory"] == "/opt/psiphon/data-de"


def test_parse_panel_url():
    import install

    path, port = install.parse_panel_url("https://tw.example.com:32904/AbCd/panel")
    assert path == "AbCd", path
    assert port == 32904, port
    path, port = install.parse_panel_url("ZUiAVunpskwMR7ZQ5d")
    assert path == "ZUiAVunpskwMR7ZQ5d"
    assert port == 2053


def test_scoped_dns():
    from lib import xui

    tags = ["in-10102-tcp", "in-10103-tcp"]
    rules = xui.scoped_dns_rules(tags)
    assert rules
    for r in rules:
        assert r["inboundTag"] == tags
        assert r["outboundTag"] == "dns-out"
    assert xui.scoped_dns_rules([]) == []
    stale = {"outboundTag": "dns-out", "port": "53"}
    assert xui._is_stale_psiphon_rule(stale, {"psiphon-de"}, {"in-10102-tcp"}) is True
    keep = {"outboundTag": "direct", "inboundTag": ["in-other"]}
    assert xui._is_stale_psiphon_rule(keep, {"psiphon-de"}, {"in-10102-tcp"}) is False
    scoped = {"outboundTag": "dns-out", "inboundTag": ["in-10102-tcp"]}
    assert xui._is_stale_psiphon_rule(scoped, {"psiphon-de"}, {"in-10102-tcp"}) is True
    other_dns = {"outboundTag": "dns-out", "inboundTag": ["in-999-tcp"]}
    assert xui._is_stale_psiphon_rule(other_dns, {"psiphon-de"}, {"in-10102-tcp"}) is False


def test_camouflage_paths():
    from lib import paths as camouflage
    from lib import nginx_site as NG

    pool = camouflage.load_pool()
    assert len(pool) >= 40
    picked = camouflage.pick_unique(8)
    assert len(picked) == 8
    assert len(set(picked)) == 8
    for p in picked:
        assert p.startswith("/")
        assert "?" not in p
        assert camouflage.nginx_location(p) == p
        ws = camouflage.xray_ws_path(p)
        assert ws.endswith("?ed=2560")
        block = NG.ws_location(p, 10102)
        assert "location = %s" % p in block
        assert "?ed=" not in block
    extra = camouflage.pick_unique(3, used=set(picked))
    assert not set(extra) & set(picked)


def test_xhttp_link():
    from urllib.parse import parse_qs, urlparse
    from lib import xhttp as X

    link = X.client_link(
        "e9e61308-3d59-4399-af0f-d5e074560650", "172.64.230.228", "my.example.com",
        X.DEFAULT_PATH, ech=X.CF_ECH, pcs="AB12", remark="cf-edge-warp-test",
    )
    assert link.startswith("vless://e9e61308-3d59-4399-af0f-d5e074560650@172.64.230.228:443?encryption=none&security=tls&sni=my.example.com")
    assert "&ech=cloudflare-ech.com%2Budp%3A%2F%2F1.1.1.1&pcs=AB12&type=xhttp" in link
    assert "&path=%2Fapi%2Fv1%2Fitems&mode=auto&extra=%7B%22mode%22%3A%22auto%22%2C%22xPaddingBytes%22%3A%22100-1000%22%7D#cf-edge-warp-test" in link
    q = parse_qs(urlparse(link).query)
    assert q["alpn"] == ["h2"] and q["fp"] == ["chrome"] and q["host"] == ["my.example.com"]
    plain = X.client_link("U", "d.com", "d.com", "/x")
    assert "ech=" not in plain and "pcs=" not in plain

    st = X.stream_settings("/api/v1/items")
    assert st["network"] == "xhttp" and st["security"] == "none"
    assert st["xhttpSettings"]["path"] == "/api/v1/items"
    assert st["xhttpSettings"]["xPaddingBytes"] == "100-1000"
    assert st["xhttpSettings"]["mode"] == "auto"


def test_xhttp_nginx_insert():
    from lib import nginx_site as NG
    from lib import xhttp as X

    conf = """server {
    listen 80;
    server_name d.com;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    server_name d.com;
    location / {
        try_files $uri $uri/ =404;
    }
}
"""
    block = NG.xhttp_location("/api/v1/items", 10088)
    out = X.insert_location(conf, block, "/api/v1/items")
    assert out.count("location /api/v1/items {") == 1
    assert out.index("grpc_pass grpc://127.0.0.1:10088") > out.index("listen 443")
    assert out.rstrip().endswith("}")
    assert X.insert_location(out, block, "/api/v1/items") == out
    try:
        X.insert_location("server {\n    listen 80;\n}\n", block, "/api/v1/items")
    except ValueError:
        pass
    else:
        raise AssertionError("no 443 server must fail")


def test_route_inbound():
    from lib import xui

    xs = {
        "outbounds": [{"tag": "direct"}, {"tag": "warp"}],
        "routing": {"rules": [
            {"type": "field", "inboundTag": ["api"], "outboundTag": "api"},
            {"type": "field", "inboundTag": ["in-10088-xhttp"], "outboundTag": "direct"},
            {"type": "field", "ip": ["geoip:private"], "outboundTag": "blocked"},
        ]},
    }
    assert xui.outbound_tags(xs) == ["direct", "warp"]
    xui.route_inbound(xs, "in-10088-xhttp", "warp")
    rules = xs["routing"]["rules"]
    assert rules[0]["outboundTag"] == "api"
    assert rules[1] == {"type": "field", "inboundTag": ["in-10088-xhttp"], "outboundTag": "warp"}
    assert len(rules) == 3


if __name__ == "__main__":
    test_countries()
    test_parse_selection()
    test_psiphon_template()
    test_parse_panel_url()
    test_scoped_dns()
    test_camouflage_paths()
    test_xhttp_link()
    test_xhttp_nginx_insert()
    test_route_inbound()
    print("ok")
