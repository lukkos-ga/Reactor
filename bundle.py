"""Evidence bundle: one zip per reported page, readable by someone who was not here.

Everything the case knows, laid out so a registrar, a bank, or a police report can
use it without you explaining anything: what the page was, when you reported it,
who you told, what they did, and proof it stayed up while nobody acted.
"""
import csv
import html
import io
import json
import os
import ssl
import urllib.request
import zipfile
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
REPORTS = os.path.join(HERE, "reports")
UA = "Mozilla/5.0 (compatible; abuse-reporter/1.0)"

CSS = """body{font:14px/1.6 -apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
color:#111;max-width:820px;margin:32px auto;padding:0 20px}
h1{font-size:22px;margin:0 0 4px} h2{font-size:15px;margin:26px 0 8px;
text-transform:uppercase;letter-spacing:.6px;color:#555;border-bottom:1px solid #ddd;padding-bottom:4px}
table{width:100%;border-collapse:collapse;font-size:13px;margin:6px 0}
th{text-align:left;color:#555;font-weight:600;border-bottom:1px solid #ccc;padding:5px 6px}
td{padding:5px 6px;border-bottom:1px solid #eee;vertical-align:top}
code{background:#f4f4f5;padding:1px 5px;border-radius:3px;font-size:12px}
.sub{color:#666;font-size:12px} .warn{color:#a15c00} .ok{color:#116329} .bad{color:#a40e26}
img{max-width:100%;border:1px solid #ccc;border-radius:4px}
.kv td:first-child{color:#555;width:180px}
@media print{body{margin:0}h2{page-break-after:avoid}}"""


def _get_bytes(url, timeout=30):
    try:
        req = urllib.request.Request(url, headers={"User-Agent": UA})
        with urllib.request.urlopen(req, timeout=timeout,
                                    context=ssl.create_default_context()) as r:
            return r.read()
    except Exception:
        return None


def _rows(pairs):
    return "".join(f"<tr><td>{html.escape(str(k))}</td><td>{v}</td></tr>" for k, v in pairs)


def report_html(case, has_shot):
    e = html.escape
    r = case.get("recon") or {}
    td = case.get("takedown") or {}
    checks = case.get("checks") or []
    first_blocked = next((c for c in checks
                          if c.get("state") in ("blocked", "down", "offline", "suspended")), None)

    parts = [f"<h1>Phishing report: {e(r.get('domain') or case.get('host') or '')}</h1>",
             f"<div class='sub'>Compiled {datetime.now(timezone.utc).isoformat(timespec='seconds')} "
             f"by fuckscammer. All times UTC.</div>"]

    parts += ["<h2>Target</h2><table class='kv'>", _rows([
        ("Phishing URL", f"<code>{e(case.get('url') or '')}</code>"),
        ("Domain", e(r.get("domain") or "")),
        ("Brand impersonated", e((case.get("brand") or "not identified").title())),
        ("Registrar", e(r.get("registrar") or "unknown")),
        ("Domain registered", e((r.get("created") or "unknown")[:19])),
        ("Nameservers", e(", ".join(r.get("ns") or []) or "unknown")),
        ("Resolved IPs", e(", ".join(r.get("ips") or []) or "unknown")),
        ("Hosting network", e(r.get("network") or "unknown")),
        ("Published abuse contacts",
         e(", ".join((r.get("registrar_abuse") or []) + (r.get("ip_abuse") or [])) or "none")),
    ]), "</table>"]

    parts += ["<h2>What was reported, and when</h2><table class='kv'>", _rows([
        ("First reported by me", e((case.get("first_reported") or "")[:19])),
        ("Blocklist submissions", e(", ".join(
            k for k, a in (case.get("apis") or {}).items() if a.get("status") == "OK") or "none confirmed")),
    ]), "</table>"]

    emails = case.get("emails") or {}
    if emails:
        parts += ["<table><tr><th>Abuse contact</th><th>Role</th><th>Sent</th><th>When</th></tr>"]
        for addr, m in emails.items():
            parts.append(f"<tr><td><code>{e(addr)}</code></td><td>{e(m.get('label',''))}</td>"
                         f"<td class='{'ok' if m.get('sent') else 'warn'}'>"
                         f"{'yes' if m.get('sent') else 'not marked sent'}</td>"
                         f"<td>{e((m.get('sent_ts') or '')[:19])}</td></tr>")
        parts.append("</table>")

    vendors = case.get("vendors") or {}
    if vendors:
        parts += ["<h2>Reputation vendors notified</h2>",
                  "<table><tr><th>Vendor</th><th>Outcome</th><th>Detail</th><th>When</th></tr>"]
        for v in vendors.values():
            state = ("confirmed by vendor" if v.get("verified")
                     else "submitted, unconfirmed" if v.get("submitted") else "opened, not submitted")
            parts.append(f"<tr><td>{e(v.get('name',''))}</td>"
                         f"<td class='{'ok' if v.get('verified') else 'warn'}'>{state}</td>"
                         f"<td class='sub'>{e((v.get('status') or '')[:70])}</td>"
                         f"<td>{e((v.get('ts') or '')[:19])}</td></tr>")
        parts.append("</table>")

    parts += ["<h2>Status over time</h2>",
              "<p class='sub'>Independent checks of the registry, DNS, blocklists and the page "
              "itself. This is the record that the site stayed reachable.</p>",
              "<table><tr><th>Checked (UTC)</th><th>State</th><th>Finding</th></tr>"]
    for c in checks:
        tag = " <span class='sub'>(carried over, page not fetched)</span>" if c.get("inherited") else ""
        parts.append(f"<tr><td>{e((c.get('checked') or '')[:19])}</td>"
                     f"<td>{e(c.get('state',''))}{tag}</td><td>{e(c.get('why',''))}</td></tr>")
    parts.append("</table>")

    parts += ["<h2>Current position</h2><table class='kv'>", _rows([
        ("State", f"<b>{e(td.get('state','unknown'))}</b> — {e(td.get('why',''))}"),
        ("Last checked", e((td.get("checked") or "")[:19])),
        ("First seen blocked or offline",
         e((first_blocked or {}).get("checked", "not yet")[:19])),
        ("Registrar suspension", e(case.get("suspended_at") or "none — no hold has been placed")),
        ("Registry status", e(", ".join(td.get("status") or []) or "unknown")),
        ("Domain still resolving", "yes" if td.get("resolves") else "no"),
    ]), "</table>"]

    if td.get("state") == "blocked":
        parts.append("<p class='warn'>Blocked is not removed. The domain remains registered "
                     "and resolving; only the host or a browser blocklist is interrupting "
                     "visitors. Moving hosts restores the page.</p>")
    if td.get("state") == "offline":
        parts.append("<p class='warn'>Offline is not suspended. The domain publishes no "
                     "address right now, but it remains registered, under the same control, "
                     "and carries no registry hold. A new address can be published at any "
                     "time. No registrar or authority action has been recorded.</p>")

    ev = case.get("evidence") or {}
    if has_shot or ev.get("report"):
        parts.append("<h2>Page capture</h2>")
        if has_shot:
            parts.append("<p class='sub'>Captured by urlscan.io. The page was never loaded "
                         "from the reporter's own browser.</p><img src='screenshot.png' alt='captured page'>")
        if ev.get("report"):
            parts.append(f"<p class='sub'>Full scan: <code>{e(ev['report'])}</code></p>")

    parts.append("<h2>Files in this bundle</h2><table>"
                 "<tr><th>File</th><th>What it is</th></tr>"
                 "<tr><td>report.html</td><td>this document</td></tr>"
                 "<tr><td>checks.csv</td><td>every status check, machine readable</td></tr>"
                 "<tr><td>case.json</td><td>complete raw record</td></tr>"
                 "<tr><td>emails/</td><td>the complaints sent to each abuse contact</td></tr>"
                 + ("<tr><td>screenshot.png</td><td>the phishing page as captured</td></tr>"
                    if has_shot else "") + "</table>")

    return (f"<!doctype html><meta charset='utf-8'><title>Phishing report "
            f"{e(r.get('domain') or case.get('host') or '')}</title><style>{CSS}</style>"
            + "".join(parts))


def checks_csv(case):
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["checked_utc", "state", "why", "registry_status", "resolves",
                "safebrowsing", "virustotal", "urlscan", "http", "page_fetched"])
    for c in case.get("checks") or []:
        s = c.get("signals") or {}
        def note(k):
            return (s.get(k) or {}).get("note", "")
        w.writerow([(c.get("checked") or "")[:19], c.get("state", ""), c.get("why", ""),
                    "; ".join((s.get("registry") or {}).get("status") or []),
                    (s.get("dns") or {}).get("resolves", ""),
                    note("safebrowsing"), note("vt"), note("urlscan"), note("http"),
                    "yes" if c.get("had_http") else "no"])
    return buf.getvalue()


def build(host, fetch_screenshot=True):
    """Write reports/<host>/<host>-evidence-<date>.zip. Returns (path, contents)."""
    case_dir = os.path.join(REPORTS, host)
    case_path = os.path.join(case_dir, "case.json")
    if not os.path.exists(case_path):
        raise FileNotFoundError(f"no case for {host}")
    case = json.load(open(case_path))

    shot = None
    url = (case.get("evidence") or {}).get("screenshot")
    if url and fetch_screenshot:
        shot = _get_bytes(url)

    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M")
    name = f"{host}-evidence-{stamp}.zip"
    path = os.path.join(case_dir, name)
    contents = []

    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("report.html", report_html(case, bool(shot)))
        contents.append("report.html")
        z.writestr("checks.csv", checks_csv(case))
        contents.append("checks.csv")
        z.writestr("case.json", json.dumps(case, indent=2))
        contents.append("case.json")
        if shot:
            z.writestr("screenshot.png", shot)
            contents.append("screenshot.png")
        for f in sorted(os.listdir(case_dir)):
            if f.endswith(".eml"):
                z.write(os.path.join(case_dir, f), f"emails/{f}")
                contents.append(f"emails/{f}")
    return path, contents


def selftest():
    import tempfile
    global REPORTS
    keep = REPORTS
    REPORTS = tempfile.mkdtemp()
    try:
        host = "a.top"
        d = os.path.join(REPORTS, host)
        os.makedirs(d)
        case = {
            "host": host, "url": "https://a.top/login", "brand": "telegram",
            "first_reported": "2026-09-05T10:00:00+00:00",
            "recon": {"domain": "a.top", "registrar": "Cheap Reg", "created": "2026-09-03",
                      "ns": ["ns1.x"], "ips": ["1.2.3.4"], "network": "NET",
                      "registrar_abuse": ["abuse@reg"], "ip_abuse": []},
            "apis": {"Netcraft": {"status": "OK"}, "urlscan.io": {"status": "SKIP"}},
            "emails": {"abuse@reg": {"label": "registrar", "sent": True,
                                     "sent_ts": "2026-09-05T10:05:00+00:00"}},
            "vendors": {"crdf": {"name": "CRDF", "verified": True, "submitted": True,
                                 "status": "SUBMITTED", "ts": "2026-09-05T10:20:00+00:00"}},
            "checks": [
                {"checked": "2026-09-05T10:30:00+00:00", "state": "live", "why": "still up",
                 "signals": {"registry": {"status": ["ok"]}, "dns": {"resolves": True},
                             "vt": {"note": "0 engines"}}},
                {"checked": "2026-09-05T11:48:00+00:00", "state": "blocked",
                 "why": "Cloudflare is warning visitors", "signals": {}},
            ],
            "takedown": {"state": "blocked", "why": "Cloudflare is warning visitors",
                         "checked": "2026-09-05T11:48:00+00:00", "status": ["ok"],
                         "resolves": True},
            "evidence": {"report": "https://urlscan.io/result/x/"},
        }
        json.dump(case, open(os.path.join(d, "case.json"), "w"))
        open(os.path.join(d, "abuse_reg.eml"), "w").write("From: me\n\nbody")

        path, contents = build(host, fetch_screenshot=False)
        assert os.path.exists(path)
        for want in ("report.html", "checks.csv", "case.json", "emails/abuse_reg.eml"):
            assert want in contents, (want, contents)

        with zipfile.ZipFile(path) as z:
            rep = z.read("report.html").decode()
            csv_out = z.read("checks.csv").decode()
        # the facts a reader needs must actually be in the document
        assert "a.top" in rep and "Cheap Reg" in rep and "Telegram" in rep
        assert "2026-09-05T11:48:00" in rep, "the timeline must be present"
        assert "Netcraft" in rep and "CRDF" in rep
        # blocked must never be presented as removed
        assert "Blocked is not removed" in rep
        case["takedown"]["state"] = "offline"
        json.dump(case, open(os.path.join(d, "case.json"), "w"))
        p2, _ = build(host, fetch_screenshot=False)
        with zipfile.ZipFile(p2) as z2:
            rep2 = z2.read("report.html").decode()
        assert "Offline is not suspended" in rep2, "offline must never read as a takedown"
        # no screenshot fetched -> the document must not claim one
        assert "screenshot.png" not in rep
        assert csv_out.count("\n") == 3, csv_out   # header + 2 checks
        assert csv_out.splitlines()[0].endswith("page_fetched"), csv_out.splitlines()[0]
        assert "Cloudflare is warning visitors" in csv_out
        print("bundle selftest OK")
    finally:
        REPORTS = keep


if __name__ == "__main__":
    selftest()
