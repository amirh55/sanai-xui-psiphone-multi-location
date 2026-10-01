#!/usr/bin/env python3
"""Stop psiphon units. Does NOT delete 3x-ui inbounds (disable them in panel)."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from lib import psiphon as P  # noqa: E402
from lib import ui  # noqa: E402


def main() -> int:
    ui.banner("uninstall psiphon units")
    names = P.unit_names()
    if not names:
        ui.say("chizi baraye stop nist.")
        return 0
    for n in names:
        ui.say("  " + n)
    if not ui.ask_yes("hame-ye psiphon-*.service disable+stop shan?", False):
        ui.say("cancel.")
        return 1
    P.stop_units()
    ui.say("psiphon stop shod.")
    ui.say("nginx va inbound-haye panel dast nakhordan.")
    ui.say("binary: /opt/psiphon/  (dasti rm -rf /opt/psiphon age khasti)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
