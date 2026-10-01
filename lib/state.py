"""Persist last install (no secrets)."""

from __future__ import annotations

import json
from pathlib import Path

STATE_PATH = Path("/opt/psiphon/install-state.json")
LOCAL_STATE = Path(__file__).resolve().parent.parent / "state.local.json"


def path_for(root: bool) -> Path:
    return STATE_PATH if root else LOCAL_STATE


def save(data: dict, root: bool = True) -> Path:
    p = path_for(root)
    p.parent.mkdir(parents=True, exist_ok=True)
    clean = dict(data)
    clean.pop("token", None)
    p.write_text(json.dumps(clean, indent=2), encoding="utf-8")
    return p


def load(root: bool = True) -> dict:
    p = path_for(root)
    if not p.is_file():
        return {}
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return {}
