#!/usr/bin/env python3
"""Show psiphon units, SOCKS ports, nginx, xray."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from lib import psiphon as P  # noqa: E402
from lib import state as ST  # noqa: E402
from lib import ui  # noqa: E402

ui.enable_utf8()


def sh(cmd: str) -> str:
    p = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return (p.stdout or p.stderr or "").strip()


def main() -> int:
    ui.banner("status")
    st = ST.load(root=True) or ST.load(root=False)
    if st:
        ui.say("domain:    %s" % st.get("domain"))
        ui.say("countries: %s" % " ".join(st.get("countries") or []))
        ui.say("")
    P.status_line()
    ui.say("")
    ui.say("--- nginx ---")
    ui.say(sh("systemctl is-active nginx || true"))
    ui.say(sh("ss -lntp | grep -E ':443|:80 ' || true"))
    ui.say("")
    ui.say("--- x-ui / xray ---")
    ui.say(sh("systemctl is-active x-ui || true"))
    cfg = Path("/usr/local/x-ui/bin/config.json")
    if cfg.is_file():
        ui.say("xray config: %s" % cfg)
    ui.say("")
    ui.say("--- RAM ---")
    ui.say(sh("ps -eo rss,pcpu,cmd | grep -E 'psiphon-tunnel|xray-linux|nginx:|x-ui' | grep -v grep || true"))
    ui.say(sh("free -h | head -2"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
