"""3x-ui panel API: inbounds, hosts, routing to psiphon socks."""

from __future__ import annotations

import json
import ssl
import time
import urllib.parse
import urllib.request
from typing import Any

from . import ui
from . import paths as camouflage

CTX = ssl._create_unverified_context()


class Panel:
    def __init__(self, base: str, token: str):
        self.base = base.rstrip("/")
        self.token = token
        self.h = {
            "Authorization": "Bearer " + token,
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

    def req(self, method: str, ep: str, payload: Any = None, timeout: int = 30) -> dict:
        data = None
        if payload is not None or method != "GET":
            data = json.dumps({} if payload is None else payload).encode()
        url = self.base + ep
        r = urllib.request.Request(url, headers=self.h, data=data, method=method)
        with urllib.request.urlopen(r, context=CTX, timeout=timeout) as resp:
            return json.loads(resp.read().decode())

    def form(self, ep: str, fields: dict, timeout: int = 30) -> dict:
        data = urllib.parse.urlencode(fields).encode()
        hh = dict(self.h)
        hh["Content-Type"] = "application/x-www-form-urlencoded"
        r = urllib.request.Request(self.base + ep, headers=hh, data=data, method="POST")
        with urllib.request.urlopen(r, context=CTX, timeout=timeout) as resp:
            return json.loads(resp.read().decode())


def detect_base(token: str, web_base_path: str, port: int) -> str:
    path = web_base_path.strip("/")
    candidates = [
        "https://127.0.0.1:%s/%s" % (port, path),
        "https://127.0.0.1:%s" % port,
    ]
    last = None
    for base in candidates:
        p = Panel(base, token)
        try:
            d = p.req("GET", "/panel/api/server/status")
            if d.get("success"):
                ui.say("panel API ok: %s" % base)
                return base
        except Exception as e:
            last = e
            ui.say("panel try fail %s (%s)" % (base, type(e).__name__))
    raise RuntimeError("panel API nist. token/path/port check kon. last=%s" % last)


def as_obj(v):
    if isinstance(v, str):
        try:
            return json.loads(v)
        except Exception:
            return {}
    return v if isinstance(v, dict) else {}


def list_inbounds(p: Panel) -> list[dict]:
    opts = p.req("GET", "/panel/api/inbounds/options").get("obj") or []
    return opts if isinstance(opts, list) else []


def clone_from_inbound(p: Panel, source_id: int) -> dict:
    ib = p.req("GET", "/panel/api/inbounds/get/%s" % source_id).get("obj") or {}
    settings = as_obj(ib.get("settings"))
    stream = as_obj(ib.get("streamSettings"))
    return {
        "id": ib.get("id") or source_id,
        "protocol": ib.get("protocol") or "vless",
        "decryption": settings.get("decryption") or "none",
        "encryption": settings.get("encryption") or "",
        "ws_host": (stream.get("wsSettings") or {}).get("host") or "",
        "raw": ib,
    }


def ensure_inbound(p: Panel, rec: dict, domain: str, clone: dict, attach_email: str | None) -> int:
    opts = p.req("GET", "/panel/api/inbounds/options").get("obj") or []
    by_remark = {str(x.get("remark")): x for x in opts}
    existing = by_remark.get(rec["remark"])
    settings = {"clients": [], "decryption": clone["decryption"]}
    if clone.get("encryption"):
        settings["encryption"] = clone["encryption"]
    # ML-KEM + fallbacks crash Xray
    stream = {
        "network": "ws",
        "security": "none",
        "wsSettings": {
            "acceptProxyProtocol": False,
            "path": camouflage.xray_ws_path(rec["path"]),
            "host": domain,
            "headers": {},
            "heartbeatPeriod": 0,
        },
        "sockopt": {
            "tcpFastOpen": True,
            "tcpcongestion": "bbr",
            "trustedXForwardedFor": ["127.0.0.1", "CF-Connecting-IP"],
        },
    }
    sniff = {
        "enabled": True,
        "destOverride": ["http", "tls", "quic", "fakedns"],
        "routeOnly": False,
        "metadataOnly": False,
    }
    payload = {
        "enable": True,
        "remark": rec["remark"],
        "listen": "127.0.0.1",
        "port": rec["listen"],
        "protocol": clone["protocol"],
        "shareAddrStrategy": "custom",
        "shareAddr": domain,
        "settings": json.dumps(settings),
        "streamSettings": json.dumps(stream),
        "sniffing": json.dumps(sniff),
    }
    if existing:
        iid = existing["id"]
        full = p.req("GET", "/panel/api/inbounds/get/%s" % iid).get("obj") or {}
        old_settings = as_obj(full.get("settings"))
        settings["clients"] = old_settings.get("clients") or []
        payload["settings"] = json.dumps(settings)
        res = p.req("POST", "/panel/api/inbounds/update/%s" % iid, payload)
        ui.say("inbound update %s id=%s %s" % (rec["remark"], iid, res.get("success")))
        if not res.get("success"):
            raise RuntimeError(res.get("msg"))
        rec["id"] = iid
        rec["tag"] = full.get("tag") or existing.get("tag") or rec["tag"]
        if attach_email:
            att = p.req("POST", "/panel/api/clients/%s/attach" % attach_email, {"inboundIds": [iid]})
            ui.say("attach %s -> %s %s" % (attach_email, rec["remark"], att.get("success")))
        return iid
    res = p.req("POST", "/panel/api/inbounds/add", payload)
    ui.say("inbound add %s %s %s" % (rec["remark"], res.get("success"), res.get("msg")))
    if not res.get("success"):
        raise RuntimeError(res.get("msg") or json.dumps(res)[:400])
    obj = res.get("obj") or {}
    rec["id"] = obj.get("id")
    if rec["id"]:
        fresh = p.req("GET", "/panel/api/inbounds/get/%s" % rec["id"]).get("obj") or {}
        rec["tag"] = fresh.get("tag") or obj.get("tag") or rec["tag"]
    if attach_email and rec["id"]:
        att = p.req("POST", "/panel/api/clients/%s/attach" % attach_email, {"inboundIds": [rec["id"]]})
        ui.say("attach %s -> %s %s" % (attach_email, rec["remark"], att.get("success")))
    return rec["id"]


def add_host(p: Panel, rec: dict, domain: str) -> None:
    groups = p.req("GET", "/panel/api/hosts/list").get("obj") or []
    iid = rec["id"]
    for g in groups:
        if iid in (g.get("inboundIds") or []) and g.get("port") == 443 and domain in str(g.get("hosts")):
            ui.say("host already hast baraye %s" % rec["remark"])
            return
    payload = {
        "inboundIds": [iid],
        "hosts": [domain],
        "port": 443,
        "remark": rec["remark"] + "-443",
        "isDisabled": False,
        "security": "tls",
        "sni": domain,
        "hostHeader": domain,
        "alpn": ["http/1.1"],
        "fingerprint": "chrome",
    }
    res = p.req("POST", "/panel/api/hosts/add", payload)
    ui.say("host add %s %s %s" % (rec["remark"], res.get("success"), res.get("msg")))
    if not res.get("success"):
        raise RuntimeError(res.get("msg") or json.dumps(res)[:400])


def scoped_dns_rules(inbound_tags: list[str]) -> list[dict]:
    """DNS-out only for Psiphon inbounds. Other inbounds keep panel DNS."""
    tags = list(inbound_tags)
    if not tags:
        return []
    return [
        {"type": "field", "inboundTag": tags, "port": "53", "network": "udp,tcp", "outboundTag": "dns-out"},
        {"type": "field", "inboundTag": tags, "protocol": ["dns"], "outboundTag": "dns-out"},
    ]


def _is_stale_psiphon_rule(rule: dict, outbound_tags: set, inbound_tags: set) -> bool:
    ot = rule.get("outboundTag")
    it = set(rule.get("inboundTag") or [])
    if ot == "dns-out":
        if not it:
            return True
        return bool(it & inbound_tags)
    if ot in outbound_tags and it & inbound_tags:
        return True
    if ot in outbound_tags and it and all(str(t).startswith("in-101") for t in it):
        return True
    return False


def apply_routing(p: Panel, recs: list[dict]) -> None:
    raw = p.req("POST", "/panel/api/xray/", {})
    obj = raw.get("obj")
    if isinstance(obj, str):
        obj = json.loads(obj)
    xs = obj.get("xraySetting")
    if isinstance(xs, str):
        xs = json.loads(xs)
    if not isinstance(xs, dict):
        raise RuntimeError("xraySetting nist")

    dns = xs.get("dns") or {}
    if not dns.get("servers"):
        dns["servers"] = ["1.1.1.1", "8.8.8.8"]
    xs["dns"] = dns
    if not xs.get("fakedns"):
        xs["fakedns"] = [{"ipPool": "198.18.0.0/16", "poolSize": 65535}]

    outbounds = xs.get("outbounds") or []
    tags = {o.get("tag") for o in outbounds}
    if "dns-out" not in tags:
        outbounds.append({"protocol": "dns", "tag": "dns-out"})
        tags.add("dns-out")
    for rec in recs:
        tag = rec["outbound"]
        if tag in tags:
            continue
        outbounds.append({
            "protocol": "socks",
            "settings": {"servers": [{"address": "127.0.0.1", "port": rec["socks"]}]},
            "tag": tag,
        })
        tags.add(tag)
    xs["outbounds"] = outbounds

    routing = xs.get("routing") or {"rules": []}
    if not routing.get("domainStrategy"):
        routing["domainStrategy"] = "IPIfNonMatch"
    rules = list(routing.get("rules") or [])
    psiphon_out = {r["outbound"] for r in recs}
    inbound_tags = [r["tag"] for r in recs]
    inbound_set = set(inbound_tags)
    cleaned = [r for r in rules if not _is_stale_psiphon_rule(r, psiphon_out, inbound_set)]
    extra = scoped_dns_rules(inbound_tags) + [
        {"type": "field", "inboundTag": [rec["tag"]], "outboundTag": rec["outbound"]}
        for rec in recs
    ]
    insert_at = 1 if cleaned and "api" in (cleaned[0].get("inboundTag") or []) else 0
    cleaned[insert_at:insert_at] = extra
    routing["rules"] = cleaned
    xs["routing"] = routing

    res = p.form("/panel/api/xray/update", {"xraySetting": json.dumps(xs)})
    ui.say("xray routing update %s %s" % (res.get("success"), str(res.get("msg"))[:180]))
    if not res.get("success"):
        raise RuntimeError(res.get("msg"))
    rst = p.req("POST", "/panel/api/server/restartXrayService", {})
    ui.say("xray restart %s" % rst.get("success"))
    time.sleep(3)
    st = p.req("GET", "/panel/api/server/status")
    x = (st.get("obj") or {}).get("xray") or {}
    ui.say("xray state %s %s" % (x.get("state"), x.get("errorMsg") or ""))
    if x.get("state") != "running":
        raise RuntimeError("xray running nist: %s" % x.get("errorMsg"))


def client_links(p: Panel, recs: list[dict], domain: str, email: str | None) -> list[str]:
    uuid = None
    encryption = ""
    if email:
        try:
            links = p.req("GET", "/panel/api/clients/links/%s" % email).get("obj") or []
            for l in links:
                if l.startswith("vless://"):
                    uuid = l.split("://", 1)[1].split("@", 1)[0]
                    q = urllib.parse.parse_qs(urllib.parse.urlparse(l).query)
                    encryption = (q.get("encryption") or [""])[0]
                    break
        except Exception as e:
            ui.say("links fail: %s" % e)
    out = []
    for rec in recs:
        path_enc = urllib.parse.quote(camouflage.xray_ws_path(rec["path"]), safe="")
        enc = ("&encryption=%s" % urllib.parse.quote(encryption, safe="")) if encryption else "&encryption=none"
        if uuid:
            uri = (
                "vless://%s@%s:443?alpn=http%%2F1.1%s&fp=chrome&host=%s&path=%s&security=tls&sni=%s&type=ws#%s-psiphon-%s"
                % (uuid, domain, enc, domain, path_enc, domain, rec["remark"], rec["code"])
            )
            out.append(uri)
        else:
            out.append("inbound %s path=%s port-public=443 (client attach nashode)" % (rec["remark"], rec["path"]))
    return out
