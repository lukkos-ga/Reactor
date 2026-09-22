"""Is the phishing site down yet?

Every signal here is gathered WITHOUT visiting the site, so the scammer never sees
your IP and no beacon fires. The one check that does touch it is off by default and
says so.

Signals, in order of how much they prove:
  registry  - RDAP status. clientHold/serverHold IS the takedown, authoritative.
  dns       - does the hostname still resolve, and have the nameservers moved?
  urlscan   - has anyone scanned it, and what did the scan conclude? (no key needed)
  gsb       - is Google Safe Browsing warning Chrome users? (needs a free Google key)
  vt        - how many engines flag it now (needs your free VirusTotal key)
  http      - opt-in only: fetches the page from YOUR IP.
"""
import base64
import json
import os
import socket
import urllib.parse
from datetime import datetime, timezone

import fuckscammer as fs

HOLD_STATES = ("client hold", "server hold", "clienthold", "serverhold",
               "pending delete", "redemption", "suspended")


def now():
    return datetime.now(timezone.utc).isoformat()


def check_registry(domain):
    d = fs.jget(f"https://rdap.org/domain/{domain}")
    if not d:
        return {"ok": False, "note": "registry lookup failed", "status": [], "held": None}
    st = d.get("status", []) or []
    held = any(any(h in str(x).lower() for h in HOLD_STATES) for x in st)
    return {"ok": True, "status": st, "held": held,
            "note": "registrar has suspended the domain" if held
                    else "registered and not suspended"}


def check_dns(host, domain, known_ns=None):
    ips, resolves = [], False
    for h in (host, domain):
        try:
            ips += [a[4][0] for a in socket.getaddrinfo(h, None)]
            resolves = True
        except Exception:
            pass
    ns = []
    r = fs.jget(f"https://dns.google/resolve?name={domain}&type=NS")
    if r:
        ns = sorted({a.get("data", "").strip(".").lower() for a in r.get("Answer", [])
                     if a.get("data")})
    moved = bool(known_ns and ns and set(ns) != {n.strip(".").lower() for n in known_ns})
    return {"ok": True, "resolves": resolves, "ips": sorted(set(ips)), "ns": ns,
            "ns_changed": moved,
            "note": ("no longer resolves" if not resolves else
                     "nameservers changed since you first reported it" if moved else
                     "still resolving")}


def check_urlscan(domain):
    q = urllib.parse.quote(f'page.domain:"{domain}"')
    s = fs.jget(f"https://urlscan.io/api/v1/search/?q={q}&size=1")
    if not s:
        return {"ok": False, "note": "urlscan lookup failed"}
    results = s.get("results") or []
    if not results:
        return {"ok": True, "scanned": False, "note": "nobody has scanned it yet"}
    top = results[0]
    uuid = top.get("_id") or (top.get("task") or {}).get("uuid")
    verdict, score = None, None
    det = fs.jget(f"https://urlscan.io/api/v1/result/{uuid}/") if uuid else None
    if det:
        v = (det.get("verdicts") or {}).get("overall") or {}
        verdict, score = v.get("malicious"), v.get("score")
    return {"ok": True, "scanned": True, "when": (top.get("task") or {}).get("time"),
            "malicious": verdict, "score": score,
            "screenshot": top.get("screenshot"),
            "report": f"https://urlscan.io/result/{uuid}/" if uuid else None,
            "note": ("scanned and judged malicious" if verdict
                     else "scanned, no malicious verdict" if verdict is False
                     else "scanned")}


def check_virustotal(url):
    key = os.getenv("VT_API_KEY")
    if not key:
        return {"ok": False, "note": "no VirusTotal key set"}
    uid = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    st, raw = fs.http(f"https://www.virustotal.com/api/v3/urls/{uid}", headers={"x-apikey": key})
    if st == 404:
        return {"ok": False, "note": "not in VirusTotal yet — it gets submitted on your next report"}
    if st in (401, 403):
        return {"ok": False, "note": f"VirusTotal rejected the key (HTTP {st})"}
    try:
        d = json.loads(raw)
    except ValueError:
        d = None
    if not d:
        return {"ok": False, "note": f"VirusTotal lookup failed (HTTP {st})"}
    a = ((d.get("data") or {}).get("attributes") or {})
    st = a.get("last_analysis_stats") or {}
    flagged = int(st.get("malicious", 0)) + int(st.get("suspicious", 0))
    return {"ok": True, "malicious": st.get("malicious", 0),
            "suspicious": st.get("suspicious", 0), "harmless": st.get("harmless", 0),
            "flagged": flagged, "reputation": a.get("reputation"),
            "note": (f"{flagged} engines flag it" if flagged else "no engine flags it yet")}


def check_safebrowsing(url):
    """Is Chrome warning people yet? This is the signal that actually protects victims."""
    key = os.getenv("GSB_API_KEY")
    if not key:
        return {"ok": False, "note": "no Google Safe Browsing key set"}
    body = {"client": {"clientId": "fuckscammer", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE",
                                "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"], "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}]}}
    st, raw = fs.http(f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={key}",
                      data=body)
    if st != 200:
        msg = ""
        try:
            msg = (json.loads(raw).get("error") or {}).get("message", "")
        except ValueError:
            pass
        if "referer" in msg.lower():
            msg = ("your API key is restricted to HTTP referrers; a server sends none. "
                   "Google Cloud Console → Credentials → your key → Application "
                   "restrictions → None (or IP addresses)")
        return {"ok": False, "note": f"Safe Browsing rejected the key (HTTP {st}): {msg}"[:300]}
    try:
        matches = (json.loads(raw) or {}).get("matches") or []
    except ValueError:
        return {"ok": False, "note": "Safe Browsing returned junk"}
    kinds = sorted({m.get("threatType", "") for m in matches})
    return {"ok": True, "listed": bool(matches), "threats": kinds,
            "note": ("Chrome is warning visitors: " + ", ".join(kinds)) if matches
                    else "not on Safe Browsing yet"}


def check_http(url):
    """Opt-in. This one DOES reach the site from your IP."""
    st, body = fs.http(url)
    low = (body or "").lower()
    warned = ("suspected phishing" in low or "deceptive site" in low
              or "warning: suspected phishing" in low)
    dead = st in (0, 403, 404, 410, 500, 502, 503, 521, 522, 523, 525, 530)
    return {"ok": True, "code": st, "cloudflare_warning": warned, "looks_dead": dead,
            "note": ("Cloudflare is showing a phishing warning" if warned else
                     f"served HTTP {st}" if st else "no response")}


def verdict(sig):
    """Down only on positive evidence. A failed lookup is never a takedown - being
    told a live phishing page is gone would stop you chasing it."""
    reg, dns = sig.get("registry", {}), sig.get("dns", {})
    if reg.get("held"):
        return "suspended", "the registrar has put the domain on hold — this is a real takedown"
    if dns.get("ok") and not dns.get("resolves"):
        # NOT the same as suspended. The domain is still registered and still theirs;
        # they can publish a new A record and be back in minutes. Calling this a
        # takedown would tell you the fight is over when it is not.
        moved = " and its nameservers have changed" if dns.get("ns_changed") else ""
        return "offline", ("not resolving" + moved +
                           ", but still registered and not suspended — it can return at any time")
    http = sig.get("http") or {}
    if http.get("cloudflare_warning"):
        return "blocked", "Cloudflare is warning visitors"
    if http.get("ok") and http.get("looks_dead"):
        return "blocked", f"origin returned HTTP {http.get('code')}"
    gsb = sig.get("safebrowsing") or {}
    if gsb.get("listed"):
        return "blocked", "Google Safe Browsing is warning visitors"
    vt = sig.get("vt") or {}
    us = sig.get("urlscan") or {}
    if vt.get("flagged") or us.get("malicious"):
        return "live-flagged", "still up, but blocklists have caught it"
    if dns.get("resolves"):
        return "live", "still up and not yet flagged anywhere"
    return "unknown", "not enough evidence"


def check(url, host, domain, known_ns=None, touch_site=False):
    sig = {"registry": check_registry(domain),
           "dns": check_dns(host, domain, known_ns),
           "safebrowsing": check_safebrowsing(url),
           "urlscan": check_urlscan(domain),
           "vt": check_virustotal(url)}
    if touch_site:
        sig["http"] = check_http(url)
    state, why = verdict(sig)
    return {"checked": now(), "state": state, "why": why, "signals": sig,
            "touched_site": bool(touch_site),
            # only a direct fetch can see a host interstitial, so a check without one
            # cannot be used to conclude a site is no longer blocked
            "had_http": bool(sig.get("http", {}).get("ok"))}


def selftest():
    assert verdict({"registry": {"held": True}})[0] == "suspended"
    # no DNS but no registry hold is NOT a takedown
    v, why = verdict({"registry": {"held": False}, "dns": {"ok": True, "resolves": False}})
    assert v == "offline" and "still registered" in why, (v, why)
    v, why = verdict({"registry": {"held": False},
                      "dns": {"ok": True, "resolves": False, "ns_changed": True}})
    assert "nameservers have changed" in why
    # a failed registry lookup on a live site must never read as a takedown
    assert verdict({"registry": {"ok": False, "held": None},
                    "dns": {"ok": True, "resolves": True}})[0] == "live"
    assert verdict({"registry": {"held": False}, "dns": {"ok": True, "resolves": True},
                    "vt": {"flagged": 7}})[0] == "live-flagged"
    assert verdict({"registry": {"held": False}, "dns": {"ok": True, "resolves": True},
                    "safebrowsing": {"listed": True}})[0] == "blocked"
    assert verdict({"registry": {"held": False}, "dns": {"ok": True, "resolves": True},
                    "safebrowsing": {"ok": False}})[0] == "live", \
        "a missing Safe Browsing key must not read as 'not listed' evidence"
    assert verdict({"registry": {"held": False}, "dns": {"ok": True, "resolves": True},
                    "http": {"ok": True, "cloudflare_warning": True}})[0] == "blocked"
    assert verdict({"registry": {"held": False}, "dns": {"ok": True, "resolves": True},
                    "http": {"ok": True, "looks_dead": True, "code": 522}})[0] == "blocked"
    # ordinary EPP states are not holds
    st = ["client transfer prohibited", "add period"]
    assert not any(any(h in s.lower() for h in HOLD_STATES) for s in st)
    assert any(any(h in s.lower() for h in HOLD_STATES) for s in ["clientHold"])
    print("status selftest OK")


if __name__ == "__main__":
    selftest()
