"""Terminal UI in finglish (ASCII names). Flag emoji is UTF-8."""

from __future__ import annotations

import sys


def enable_utf8() -> None:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass


def say(msg: str = "") -> None:
    try:
        sys.stdout.write(msg + "\n")
    except UnicodeEncodeError:
        sys.stdout.write(msg.encode("utf-8", "replace").decode("ascii", "replace") + "\n")
    sys.stdout.flush()


def ask(prompt: str, default: str | None = None) -> str:
    suffix = " [%s]: " % default if default not in (None, "") else ": "
    try:
        raw = input(prompt + suffix).strip()
    except EOFError:
        return default or ""
    if raw == "" and default is not None:
        return default
    return raw


def ask_yes(prompt: str, default: bool = True) -> bool:
    hint = "Y/n" if default else "y/N"
    raw = ask("%s (%s)" % (prompt, hint), "")
    if raw == "":
        return default
    return raw.lower() in ("y", "yes", "1", "bale", "are")


def ask_int(prompt: str, default: int | None = None, lo: int | None = None, hi: int | None = None) -> int:
    while True:
        raw = ask(prompt, "" if default is None else str(default))
        try:
            n = int(raw)
        except ValueError:
            say("adad vared kon.")
            continue
        if lo is not None and n < lo:
            say("adad koochik-e. min=%s" % lo)
            continue
        if hi is not None and n > hi:
            say("adad bozorg-e. max=%s" % hi)
            continue
        return n


def banner(title: str) -> None:
    line = "=" * 56
    say(line)
    say(title)
    say(line)


def table_countries(rows: list[dict]) -> None:
    say("")
    say("  #   FLAG  CODE  NAME")
    say("  --  ----  ----  --------------------")
    for i, r in enumerate(rows, 1):
        flag = r.get("flag") or "  "
        say("  %-3s %s   %-5s %s" % (i, flag, r["code"], r["name_finglish"]))
    say("")


def parse_selection(raw: str, n: int) -> list[int]:
    """Parse '1 2 5' or '1,2,5' or '1-3' into 1-based indexes."""
    raw = raw.replace(",", " ").replace(";", " ").strip()
    if not raw:
        return []
    out: list[int] = []
    for tok in raw.split():
        if "-" in tok:
            a, b = tok.split("-", 1)
            try:
                start, end = int(a), int(b)
            except ValueError:
                continue
            if start > end:
                start, end = end, start
            for i in range(start, end + 1):
                if 1 <= i <= n and i not in out:
                    out.append(i)
        else:
            try:
                i = int(tok)
            except ValueError:
                continue
            if 1 <= i <= n and i not in out:
                out.append(i)
    return out
