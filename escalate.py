"""ICANN escalation, built from what actually happened.

ICANN is not a takedown channel. They enforce the registrar's RAA 3.18 duty to
investigate and respond to abuse reports. A complaint is only worth filing once the
registrar has had its 24 hours and done nothing, and it is only persuasive with a
timeline. That is what this assembles.
"""
from datetime import datetime, timedelta, timezone

ICANN_FORM = "https://forms.icann.org/en/resources/compliance/complaints/registrars/abuse-report-form"
WAIT_HOURS = 24


def _dt(s):
    try:
        return datetime.fromisoformat(str(s).replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None


def readiness(case):
    """Can an ICANN complaint be filed yet, and if not, what is missing?"""
    first = _dt(case.get("first_reported"))
    emails = case.get("emails") or {}
    registrar_rows = {a: e for a, e in emails.items() if "registrar" in (e.get("label") or "")}
    sent = [e for e in registrar_rows.values() if e.get("sent")]
    sent_at = min([_dt(e.get("sent_ts")) for e in sent if _dt(e.get("sent_ts"))], default=None)
    state = (case.get("takedown") or {}).get("state")
    now = datetime.now(timezone.utc)

    blockers = []
    if not registrar_rows:
        blockers.append("no registrar abuse address was found for this domain")
    elif not sent:
        blockers.append("you have not ticked the registrar complaint as sent — ICANN needs "
                        "proof the registrar was contacted first")
    due = (sent_at or first)
    due = due + timedelta(hours=WAIT_HOURS) if due else None
    if due and now < due:
        blockers.append(f"the registrar's {WAIT_HOURS}h window is still open "
                        f"(until {due.isoformat(timespec='minutes')})")
    if state == "suspended":
        blockers.append("the domain is already suspended — nothing left to escalate")

    return {"ready": not blockers, "blockers": blockers,
            "eligible_at": due.isoformat() if due else None,
            "registrar_contacted": bool(sent),
            "contacted_at": sent_at.isoformat() if sent_at else None}


def complaint_text(case):
    r = case.get("recon") or {}
    emails = case.get("emails") or {}
    reg_rows = [(a, e) for a, e in emails.items() if "registrar" in (e.get("label") or "")]
    contacted = [f"{a} on {e.get('sent_ts') or 'date not recorded'}"
                 for a, e in reg_rows if e.get("sent")]
    checks = case.get("checks") or []
    td = case.get("takedown") or {}

    lines = [
        f"Domain: {r.get('domain') or case.get('host')}",
        f"Phishing URL: {case.get('url')}",
        f"Registrar: {r.get('registrar') or 'unknown'}",
        f"Domain registered: {(r.get('created') or 'unknown')[:19]}",
        "",
        "Nature of the abuse:",
        f"  A credential-harvesting page impersonating "
        f"{(case.get('brand') or 'a well-known service').title()}, distributed by unsolicited SMS.",
        "",
        "Reports already made:",
        f"  First reported by me: {case.get('first_reported')}",
    ]
    for c in contacted:
        lines.append(f"  Registrar abuse contact emailed: {c}")
    if not contacted:
        lines.append("  Registrar abuse contact: NOT YET EMAILED - do this before filing")

    ok_apis = [k for k, a in (case.get("apis") or {}).items() if a.get("status") == "OK"]
    if ok_apis:
        lines.append(f"  Submitted to blocklists: {', '.join(ok_apis)}")
    confirmed = [v.get("name") for v in (case.get("vendors") or {}).values() if v.get("verified")]
    if confirmed:
        lines.append(f"  Vendor reports confirmed: {', '.join(confirmed)}")

    lines += ["", "Evidence the domain is still active:"]
    for c in checks[-6:]:
        lines.append(f"  {c.get('checked','')[:19]}  {c.get('state')}: {c.get('why')}")
    if not checks:
        lines.append("  (run a status check before filing so the timeline is on record)")

    lines += [
        "",
        f"Current state: {td.get('state', 'unknown')} - {td.get('why', '')}",
        "",
        "Why I am escalating:",
        f"  More than {WAIT_HOURS} hours have passed since the registrar's published abuse",
        "  contact was notified, and the domain remains registered and resolving. RAA 2013",
        "  Section 3.18.1 requires the registrar to take reasonable and prompt steps to",
        "  investigate and respond to reports of abuse. I have received no response and no",
        "  action has been taken.",
        "",
        "Requested outcome:",
        "  ICANN Contractual Compliance to require the registrar to demonstrate it",
        "  investigated and acted on the report.",
    ]
    return "\n".join(lines)


def selftest():
    now = datetime.now(timezone.utc)
    old = (now - timedelta(hours=30)).isoformat()

    # registrar never emailed -> not ready, and the text says so out loud
    c = {"host": "a.top", "url": "https://a.top/", "first_reported": old,
         "recon": {"domain": "a.top", "registrar": "Cheap Reg"},
         "emails": {"abuse@reg": {"label": "registrar Cheap Reg", "sent": False}},
         "takedown": {"state": "live", "why": "still up"}, "checks": []}
    r = readiness(c)
    assert not r["ready"] and any("ticked" in b for b in r["blockers"]), r
    assert "NOT YET EMAILED" in complaint_text(c)

    # emailed 30h ago, still live -> ready
    c["emails"]["abuse@reg"].update(sent=True, sent_ts=old)
    r = readiness(c)
    assert r["ready"], r["blockers"]
    assert r["registrar_contacted"]

    # inside the 24h window -> not ready
    c["emails"]["abuse@reg"]["sent_ts"] = (now - timedelta(hours=2)).isoformat()
    assert not readiness(c)["ready"]

    # already suspended -> nothing to escalate
    c["emails"]["abuse@reg"]["sent_ts"] = old
    c["takedown"] = {"state": "suspended", "why": "client hold"}
    assert not readiness(c)["ready"]
    assert any("already suspended" in b for b in readiness(c)["blockers"])
    # merely offline is still escalatable - the registrar has done nothing and the
    # domain can be pointed at a new host in minutes
    c["takedown"] = {"state": "offline", "why": "not resolving but still registered"}
    assert readiness(c)["ready"], readiness(c)["blockers"]

    c["takedown"] = {"state": "live", "why": "still up"}
    c["checks"] = [{"checked": old, "state": "live", "why": "still resolving"}]
    t = complaint_text(c)
    assert "3.18" in t and "a.top" in t and "still resolving" in t
    print("escalate selftest OK")


if __name__ == "__main__":
    selftest()
