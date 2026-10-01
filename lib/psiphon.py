"""Download and run one psiphon-tunnel-core process per country."""

from __future__ import annotations

import json
import glob
import stat
import subprocess
import time
import urllib.request
from pathlib import Path

from . import ui

BIN_URLS = [
    "https://media.githubusercontent.com/media/Psiphon-Labs/psiphon-tunnel-core-binaries/master/linux/psiphon-tunnel-core-x86_64",
    "https://github.com/Psiphon-Labs/psiphon-tunnel-core-binaries/raw/master/linux/psiphon-tunnel-core-x86_64",
]
ROOT = Path(__file__).resolve().parent.parent
TPL_CFG = ROOT / "templates" / "psiphon.config.json.tmpl"
TPL_UNIT = ROOT / "templates" / "psiphon.service"
OPT = Path("/opt/psiphon")
BIN = OPT / "psiphon-tunnel-core-x86_64"


def sh(cmd: str, check: bool = True) -> subprocess.CompletedProcess:
    ui.say("+ " + cmd)
    p = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if p.stdout.strip():
        ui.say(p.stdout.strip()[:2000])
    if p.stderr.strip() and p.returncode != 0:
        ui.say(p.stderr.strip()[:1000])
    if check and p.returncode != 0:
        raise RuntimeError("cmd failed: %s" % cmd)
    return p


def ensure_bin() -> Path:
    OPT.mkdir(parents=True, exist_ok=True)
    if BIN.is_file() and BIN.stat().st_size > 1_000_000:
        ui.say("psiphon binary already hast: %s" % BIN)
        return BIN
    tmp = OPT / "psiphon-tunnel-core-x86_64.tmp"
    last_err = None
    for url in BIN_URLS:
        ui.say("download psiphon-tunnel-core ...")
        ui.say(url)
        try:
            urllib.request.urlretrieve(url, tmp)
        except Exception as e:
            last_err = e
            ui.say("download fail: %s" % e)
            continue
        head = tmp.read_bytes()[:80]
        if tmp.stat().st_size < 1_000_000 or head.startswith(b"version https://git-lfs"):
            ui.say("file koochik ya git-lfs pointer (%s bytes) - URL badi" % tmp.stat().st_size)
            tmp.unlink(missing_ok=True)
            continue
        tmp.chmod(tmp.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        tmp.replace(BIN)
        ui.say("ok %s (%s bytes)" % (BIN, BIN.stat().st_size))
        return BIN
    raise RuntimeError("psiphon binary download nashod: %s" % last_err)


def write_instance(rec: dict) -> None:
    code = rec["code"].lower()
    data_dir = OPT / ("data-%s" % code)
    data_dir.mkdir(parents=True, exist_ok=True)
    cfg_path = OPT / ("%s.config" % code)
    tpl = TPL_CFG.read_text(encoding="utf-8")
    filled = (
        tpl.replace("__HTTP_PORT__", str(rec["http"]))
        .replace("__SOCKS_PORT__", str(rec["socks"]))
        .replace("__REGION__", rec["code"])
        .replace("__DATA_DIR__", str(data_dir))
    )
    json.loads(filled)  # validate
    cfg_path.write_text(filled, encoding="utf-8")
    unit = (
        TPL_UNIT.read_text(encoding="utf-8")
        .replace("__REGION__", rec["code"])
        .replace("__DATA_DIR__", str(data_dir))
        .replace("__BIN__", str(BIN))
        .replace("__CONFIG__", str(cfg_path))
    )
    unit_path = Path("/etc/systemd/system/psiphon-%s.service" % code)
    unit_path.write_text(unit, encoding="utf-8")


def start_instances(recs: list[dict]) -> None:
    ensure_bin()
    for rec in recs:
        write_instance(rec)
    sh("systemctl daemon-reload")
    for rec in recs:
        name = "psiphon-%s" % rec["code"].lower()
        sh("systemctl reset-failed %s || true" % name, check=False)
        sh("systemctl enable --now %s" % name)


def wait_socks(recs: list[dict], timeout: int = 180) -> dict[str, bool]:
    pending = {r["code"]: r["socks"] for r in recs}
    ok: dict[str, bool] = {c: False for c in pending}
    deadline = time.time() + timeout
    while pending and time.time() < deadline:
        done = []
        for code, port in pending.items():
            p = subprocess.run("ss -lnt | grep -q '127.0.0.1:%s'" % port, shell=True)
            if p.returncode == 0:
                ui.say("SOCKS UP %s :%s" % (code, port))
                ok[code] = True
                done.append(code)
        for code in done:
            pending.pop(code)
        if pending:
            time.sleep(4)
    for code in pending:
        ui.say("WARNING socks nist (%s). tunnel shayad chand daghighe tool bekeshe." % code)
        sh("journalctl -u psiphon-%s --no-pager -n 12 || true" % code.lower(), check=False)
    return ok


def unit_names() -> list[str]:
    names = []
    for path in glob.glob("/etc/systemd/system/psiphon-*.service"):
        names.append(Path(path).stem)
    return sorted(names)


def status_line() -> None:
    names = unit_names()
    if not names:
        ui.say("hich psiphon service nist.")
        return
    for name in names:
        p = subprocess.run(["systemctl", "is-active", name], capture_output=True, text=True)
        ui.say("%-18s %s" % (name, (p.stdout or "").strip() or "unknown"))
    sh("ss -lnt | grep -E '108[0-9]|109[0-9]' || true", check=False)


def stop_units(codes: list[str] | None = None) -> None:
    names = ["psiphon-%s" % c.lower() for c in codes] if codes else unit_names()
    for name in names:
        sh("systemctl disable --now %s || true" % name, check=False)
    sh("systemctl daemon-reload", check=False)
