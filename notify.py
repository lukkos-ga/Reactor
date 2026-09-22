"""Desktop notifications, so the monitor is useful while you are not looking at it.

macOS only (osascript). Silently does nothing anywhere else - a missing notifier
must never break a report run.
"""
import json
import os
import platform
import re
import subprocess

HERE = os.path.dirname(os.path.abspath(__file__))
SEEN = os.path.join(HERE, "reports", ".notified.json")

# Only these transitions are worth interrupting someone for.
WORTH_TELLING = {
    ("live", "blocked"): "is now blocked — visitors get a warning",
    ("live-flagged", "blocked"): "is now blocked — visitors get a warning",
    ("unknown", "blocked"): "is now blocked — visitors get a warning",
    ("live", "live-flagged"): "has been picked up by blocklists",
    ("unknown", "live-flagged"): "has been picked up by blocklists",
    ("live", "suspended"): "has been SUSPENDED by the registrar",
    ("live-flagged", "suspended"): "has been SUSPENDED by the registrar",
    ("blocked", "suspended"): "has been SUSPENDED by the registrar",
    ("offline", "suspended"): "has been SUSPENDED by the registrar",
    ("unknown", "suspended"): "has been SUSPENDED by the registrar",
    ("live", "offline"): "stopped resolving — still registered, could return",
    ("live-flagged", "offline"): "stopped resolving — still registered, could return",
    ("blocked", "offline"): "stopped resolving — still registered, could return",
    ("unknown", "offline"): "stopped resolving — still registered, could return",
    ("offline", "live"): "is resolving again — they moved it to a new host",
    ("offline", "blocked"): "is back, and blocked again",
    ("blocked", "live"): "is live again — the warning is gone",
    ("suspended", "live"): "is back up — the suspension was lifted",
}


def _clean(s):
    # osascript takes an AppleScript string; quotes and backslashes must not escape it
    return re.sub(r'[\\"]', "", str(s))[:230]


def send(title, message, subtitle=""):
    if platform.system() != "Darwin":
        return False
    script = f'display notification "{_clean(message)}" with title "{_clean(title)}"'
    if subtitle:
        script += f' subtitle "{_clean(subtitle)}"'
    try:
        subprocess.run(["osascript", "-e", script], timeout=8,
                       capture_output=True, check=False)
        return True
    except Exception:
        return False


def _load():
    try:
        return json.load(open(SEEN))
    except Exception:
        return {}


def _save(d):
    os.makedirs(os.path.dirname(SEEN), exist_ok=True)
    json.dump(d, open(SEEN, "w"), indent=1)


def transition(host, old, new):
    """Message for a state change, or None if it is not worth a popup."""
    if old == new:
        return None
    return WORTH_TELLING.get((old or "unknown", new))


def on_state(host, url, old, new, enabled=True):
    msg = transition(host, old, new)
    if not msg or not enabled:
        return None
    send("fuckscammer", f"{host} {msg}", url or "")
    return msg


def once(key, title, message, subtitle="", enabled=True):
    """Fire a notification at most once ever for this key."""
    seen = _load()
    if key in seen or not enabled:
        return False
    seen[key] = True
    _save(seen)
    return send(title, message, subtitle)


def selftest():
    assert transition("a", "live", "blocked").startswith("is now blocked")
    assert transition("a", "blocked", "blocked") is None, "no popup when nothing changed"
    assert transition("a", "blocked", "live-flagged") is None, "going backwards is not news"
    assert "SUSPENDED" in transition("a", "live", "suspended")
    assert transition("a", "blocked", "offline").startswith("stopped resolving")
    assert "still registered" in transition("a", "live", "offline"), \
        "going quiet must never be announced as a takedown"
    assert transition("a", "offline", "live").startswith("is resolving again")
    assert transition("a", "blocked", "live").startswith("is live again")
    assert '"' not in _clean('he said "hi" \\ there')
    assert len(_clean("x" * 500)) <= 230
    print("notify selftest OK")


if __name__ == "__main__":
    selftest()
