"""One durable case file per reported page: reports/<host>/case.json

A run is not the useful unit - the target is. You report the same URL over
several sessions, and what you want later is "what did I send about this page,
where, when, and did it come down". Everything merges into one file per host.
"""
import json
import os
from datetime import datetime, timedelta, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
REPORTS = os.path.join(HERE, "reports")
TAKEDOWN_STATES = ("client hold", "server hold", "clienthold", "serverhold",
                   "pending delete", "redemption")
ICANN_WAIT_HOURS = 24   # registrar must act before ICANN will hear a complaint


def now():
    return datetime.now(timezone.utc).isoformat()


def case_path(host):
    return os.path.join(REPORTS, host, "case.json")


def load(host):
    try:
        return json.load(open(case_path(host)))
    except Exception:
        return {}


def save(case):
    p = case_path(case["host"])
    os.makedirs(os.path.dirname(p), exist_ok=True)
    json.dump(case, open(p, "w"), indent=2)
    return case


def touch(host, url=None, **seed):
    """Get the case, creating it on first sight."""
    c = load(host)
    if not c:
        c = {"host": host, "url": url, "first_reported": now(),
             "apis": {}, "emails": {}, "vendors": {}, "takedown": {}}
    if url:
        c["url"] = url
    c.update({k: v for k, v in seed.items() if v})
    c["last_activity"] = now()
    return c


def record_run(host, url, recon, apis, emails, brand=None):
    c = touch(host, url, recon=recon, brand=brand or recon.get("brand"))
    for a in apis:
        prev = c["apis"].get(a["name"], {})
        # never let a later failure erase a confirmed success
        if prev.get("status") == "OK" and a["status"] != "OK":
            continue
        c["apis"][a["name"]] = {"status": a["status"], "detail": a.get("detail", "")[:300],
                                "ts": now()}
    for e in emails:
        prev = c["emails"].get(e["to"], {})
        c["emails"][e["to"]] = {"label": e["label"], "file": e["file"],
                                "sent": prev.get("sent", False),
                                "sent_ts": prev.get("sent_ts"),
                                "mailto": e.get("mailto"), "gmail": e.get("gmail"),
                                "ts": prev.get("ts") or now()}
    return save(c)


def record_vendor(host, entry):
    """Merge one vendor tab outcome. A confirmed submission is never downgraded."""
    c = touch(host, entry.get("reported_url"))
    prev = c["vendors"].get(entry["site"], {})
    if prev.get("verified") and not entry.get("verified"):
        return save(c)
    c["vendors"][entry["site"]] = {
        "name": entry.get("name"), "status": entry.get("status"),
        "submitted": entry.get("submitted", False), "verified": entry.get("verified", False),
        "captcha": entry.get("captcha"), "stage": entry.get("stage", 1),
        "picked": entry.get("picked", []), "flags": entry.get("flags", []),
        "ts": now()}
    return save(c)


def mark_email(host, to, sent):
    c = touch(host)
    if to in c.get("emails", {}):
        c["emails"][to]["sent"] = bool(sent)
        c["emails"][to]["sent_ts"] = now() if sent else None
    return save(c)


def record_takedown(host, status_list, resolves, registry_answered=True):
    """Only call it down on positive evidence: a registry hold, or the hostname no
    longer resolving. A failed lookup means UNKNOWN, never down - telling you a live
    phishing page is gone would stop you chasing it."""
    c = touch(host)
    held = any(any(t in str(s).lower() for t in TAKEDOWN_STATES) for s in status_list)
    down = held or not resolves
    c["takedown"] = {"checked": now(), "status": status_list, "resolves": resolves,
                     "registry_answered": registry_answered, "held": held, "down": down,
                     "note": ("registry reports a hold" if held else
                              "hostname no longer resolves" if not resolves else
                              "still resolving" + ("" if registry_answered
                                                   else "; registry lookup failed"))}
    if down and not c.get("down_at"):
        c["down_at"] = now()
    return save(c)


WEAKER_THAN_BLOCKED = ("live", "live-flagged", "unknown")


def record_check(host, result):
    """Append a full multi-signal check and keep a short timeline.

    A sweep that skipped the page fetch cannot see a host interstitial, so it must
    not be allowed to report a confirmed-blocked site as live again - that made the
    timeline flicker and would have undermined the evidence bundle."""
    c = touch(host)
    prev = (c.get("takedown") or {}).get("state")
    if (prev == "blocked" and result.get("state") in WEAKER_THAN_BLOCKED
            and not result.get("had_http")):
        result = dict(result, state="blocked", inherited=True,
                      why="last confirmed blocked; this sweep did not fetch the page")
    c.setdefault("checks", []).append(result)
    c["checks"] = c["checks"][-20:]
    sig = result.get("signals", {})
    us = sig.get("urlscan") or {}
    if us.get("screenshot") or us.get("report"):
        # a screenshot is what makes a registrar complaint stick, and urlscan took it
        # so you never had to load the page yourself
        ev = c.setdefault("evidence", {})
        ev.update({k: v for k, v in
                   {"screenshot": us.get("screenshot"), "report": us.get("report"),
                    "scanned": us.get("when"), "captured": result["checked"]}.items() if v})
    c["takedown"] = {"checked": result["checked"], "state": result["state"],
                     "why": result["why"],
                     "status": (sig.get("registry") or {}).get("status", []),
                     "resolves": (sig.get("dns") or {}).get("resolves"),
                     "held": (sig.get("registry") or {}).get("held"),
                     "down": result["state"] == "suspended",
                     "offline": result["state"] in ("suspended", "offline"),
                     "note": result["why"]}
    if result["state"] == "suspended" and not c.get("suspended_at"):
        c["suspended_at"] = result["checked"]
    if result["state"] in ("suspended", "offline") and not c.get("offline_at"):
        c["offline_at"] = result["checked"]
    return save(c)


def summary(c):
    v = c.get("vendors", {}).values()
    emails = c.get("emails", {}).values()
    first = c.get("first_reported")
    due = None
    if first:
        try:
            due = (datetime.fromisoformat(first) + timedelta(hours=ICANN_WAIT_HOURS)).isoformat()
        except ValueError:
            pass
    return {
        "host": c.get("host"), "url": c.get("url"), "brand": c.get("brand"),
        "registrar": (c.get("recon") or {}).get("registrar"),
        "first_reported": first, "last_activity": c.get("last_activity"),
        "vendors_total": len(list(v)),
        "vendors_confirmed": sum(1 for x in c.get("vendors", {}).values() if x.get("verified")),
        "vendors_clicked": sum(1 for x in c.get("vendors", {}).values()
                               if x.get("submitted") and not x.get("verified")),
        "apis_ok": [k for k, a in c.get("apis", {}).items() if a.get("status") == "OK"],
        "emails_total": len(list(emails)),
        "emails_sent": sum(1 for e in c.get("emails", {}).values() if e.get("sent")),
        "icann_eligible_at": due,
        "takedown": c.get("takedown", {}),
        "checks": len(c.get("checks", [])),
        "evidence": c.get("evidence", {}),
        "offline_at": c.get("offline_at"),
        "suspended_at": c.get("suspended_at"),
    }


def all_cases():
    out = []
    if not os.path.isdir(REPORTS):
        return out
    for host in os.listdir(REPORTS):
        c = load(host)
        if c.get("host"):
            out.append(c)
    return sorted(out, key=lambda c: c.get("last_activity") or "", reverse=True)


def selftest():
    global REPORTS
    import tempfile
    keep = REPORTS
    REPORTS = tempfile.mkdtemp()
    try:
        record_run("a.top", "https://a.top/", {"registrar": "R", "brand": "telegram"},
                   [{"name": "Netcraft", "status": "OK", "detail": "uuid"}],
                   [{"to": "abuse@x", "label": "host", "file": "f.eml"}])
        # a later failed retry must not erase a confirmed success
        record_run("a.top", "https://a.top/", {"registrar": "R"},
                   [{"name": "Netcraft", "status": "HTTP 400", "detail": ""}], [])
        assert load("a.top")["apis"]["Netcraft"]["status"] == "OK"

        record_vendor("a.top", {"site": "crdf", "name": "CRDF", "status": "SUBMITTED",
                                "submitted": True, "verified": True, "reported_url": "https://a.top/"})
        record_vendor("a.top", {"site": "crdf", "name": "CRDF", "status": "opened",
                                "submitted": False, "verified": False})
        assert load("a.top")["vendors"]["crdf"]["verified"], "confirmation must not be downgraded"

        mark_email("a.top", "abuse@x", True)
        assert load("a.top")["emails"]["abuse@x"]["sent"] is True
        # marking sent must not wipe the draft path
        assert load("a.top")["emails"]["abuse@x"]["file"] == "f.eml"

        record_takedown("a.top", ["client hold"], True)
        assert load("a.top")["takedown"]["down"] is True, "a registry hold means down"
        record_takedown("b.top", [], False)
        assert load("b.top")["takedown"]["down"] is True, "no longer resolving means down"
        record_takedown("c.top", [], True, registry_answered=False)
        assert load("c.top")["takedown"]["down"] is False, \
            "a failed registry lookup must never be reported as a takedown"
        record_takedown("d.top", ["active", "client transfer prohibited"], True)
        assert load("d.top")["takedown"]["down"] is False, "ordinary EPP states are not holds"

        record_check("a.top", {"checked": now(), "state": "blocked", "had_http": True,
                               "why": "host interstitial", "signals": {}})
        # a sweep with no page fetch must not undo a confirmed block
        record_check("a.top", {"checked": now(), "state": "live-flagged", "had_http": False,
                               "why": "blocklists only", "signals": {}})
        assert load("a.top")["takedown"]["state"] == "blocked", "block flickered off"
        assert load("a.top")["checks"][-1].get("inherited") is True
        # but a real fetch showing it live again IS allowed through
        record_check("a.top", {"checked": now(), "state": "live", "had_http": True,
                               "why": "serving the page again", "signals": {}})
        assert load("a.top")["takedown"]["state"] == "live"
        record_check("a.top", {"checked": now(), "state": "live-flagged",
                               "why": "still up", "signals": {"dns": {"resolves": True}}})
        record_check("a.top", {"checked": now(), "state": "suspended", "why": "hold",
                               "signals": {"registry": {"held": True, "status": ["client hold"]},
                                           "urlscan": {"screenshot": "https://s/x.png",
                                                       "report": "https://urlscan.io/result/x/"}}})
        assert load("a.top")["evidence"]["screenshot"] == "https://s/x.png"
        ac = load("a.top")
        assert len(ac["checks"]) == 5 and ac["takedown"]["down"] is True
        assert ac["suspended_at"], "the moment of an actual suspension must be recorded"
        # merely offline must never be recorded as a takedown
        record_check("b2.top", {"checked": now(), "state": "offline",
                                "why": "not resolving", "signals": {}})
        b2 = load("b2.top")
        assert b2["takedown"]["down"] is False and b2["takedown"]["offline"] is True
        assert not b2.get("suspended_at") and b2.get("offline_at")
        assert ac["down_at"], "the moment it went down must be recorded"
        s = summary(load("a.top"))
        assert s["vendors_confirmed"] == 1 and s["emails_sent"] == 1
        assert s["icann_eligible_at"] > s["first_reported"]
        assert len(all_cases()) == 5
        print("casefile selftest OK")
    finally:
        REPORTS = keep


if __name__ == "__main__":
    selftest()
