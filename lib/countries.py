"""Load country table and assign local ports/paths."""

from __future__ import annotations

from pathlib import Path

from . import paths as camouflage

ROOT = Path(__file__).resolve().parent.parent
COUNTRIES_FILE = ROOT / "data" / "countries.tsv"

# Port map: keep DE/NL/US/SG listen/socks compatible with a typical live VPS.
# Paths are NOT in this map — they are random camouflage paths.
PORT_MAP = {
    "US": {"listen": 10101, "socks": 1081, "http": 8081},
    "DE": {"listen": 10102, "socks": 1082, "http": 8082},
    "NL": {"listen": 10103, "socks": 1083, "http": 8083},
    "SG": {"listen": 10104, "socks": 1084, "http": 8084},
}

# Remaining codes get sequential ports starting here.
NEXT_LISTEN = 10110
NEXT_SOCKS = 1090
NEXT_HTTP = 8090


def flag_emoji(code: str) -> str:
    """ISO 3166-1 alpha-2 -> regional-indicator flag (DE -> 🇩🇪)."""
    code = (code or "").strip().upper()
    if len(code) != 2 or not code.isalpha():
        return ""
    return "".join(chr(0x1F1E6 + ord(c) - ord("A")) for c in code)


def load_countries() -> list[dict]:
    rows = []
    for line in COUNTRIES_FILE.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split("\t")
        if len(parts) < 3:
            continue
        code = parts[0].strip().upper()
        rows.append({
            "code": code,
            "name_en": parts[1].strip(),
            "name_finglish": parts[2].strip(),
            "flag": flag_emoji(code),
        })
    return rows


def assign_ports(codes: list[str], used_paths: set[str] | None = None) -> list[dict]:
    used_listen = set()
    used_socks = set()
    used_http = set()
    used_path = set(used_paths or ())
    chosen_paths = camouflage.pick_unique(len(codes), used_path)
    out = []
    listen_n, socks_n, http_n = NEXT_LISTEN, NEXT_SOCKS, NEXT_HTTP
    for i, code in enumerate(codes):
        code = code.upper()
        preset = PORT_MAP.get(code)
        if preset:
            rec = dict(preset)
        else:
            while listen_n in used_listen:
                listen_n += 1
            while socks_n in used_socks:
                socks_n += 1
            while http_n in used_http:
                http_n += 1
            rec = {
                "listen": listen_n,
                "socks": socks_n,
                "http": http_n,
            }
            listen_n += 1
            socks_n += 1
            http_n += 1
        rec["path"] = chosen_paths[i]
        rec["code"] = code
        rec["flag"] = flag_emoji(code)
        rec["remark"] = code.lower()
        rec["tag"] = "in-%s-tcp" % rec["listen"]
        rec["outbound"] = "psiphon-%s" % code.lower()
        used_listen.add(rec["listen"])
        used_socks.add(rec["socks"])
        used_http.add(rec["http"])
        used_path.add(rec["path"])
        out.append(rec)
    return out
