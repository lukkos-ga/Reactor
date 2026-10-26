"""Catch the next phishing domain while it is still being set up.

Every TLS certificate is published to public Certificate Transparency logs within
minutes of issue. A scammer registering wa-verify-login.cyou and putting a cert on
it appears there long before the SMS reaches anyone. This watches crt.sh for new
certs whose names look like a brand impersonation and scores them.

Nothing here contacts the candidate domains. It reads a public log.

Scoring is deliberately strict: `%telegram%` matches thousands of harmless names, so
a bare keyword match scores nothing on its own. A hit needs a keyword AND corroborating
signals - a throwaway TLD, phishing vocabulary, padding characters, fresh issuance.
"""
import json
import os
import re
import time
import urllib.parse
from datetime import datetime, timedelta, timezone

import reactor as fs

HERE = os.path.dirname(os.path.abspath(__file__))
STATE = os.path.join(HERE, "reports", "ctwatch.json")
MIN_SCORE = 4
MAX_HITS = 300

# The brand's real domains. Anything under these is the brand itself, never a hit.
LEGIT = {
    "telegram": ["telegram.org", "telegram.me", "t.me", "telegram.dog", "telesco.pe",
                 "telegram-cdn.org", "tg.dev"],
    "whatsapp": ["whatsapp.com", "whatsapp.net", "wa.me", "fb.com", "facebook.com",
                 "meta.com", "cdn.whatsapp.net"],
    "binance": ["binance.com", "binance.us", "bnbchain.org", "binance.charity"],
    "paypal": ["paypal.com", "paypal.me", "paypalobjects.com", "paypal-corp.com"],
    "apple": ["apple.com", "icloud.com", "apple.news", "me.com", "mzstatic.com"],
    "netflix": ["netflix.com", "nflxext.com", "nflximg.net", "nflxvideo.net"],
    "coinbase": ["coinbase.com", "cbhq.net", "coinbase.dev"],
}

RISKY_TLD = {
    "top", "xyz", "icu", "cyou", "sbs", "cfd", "bond", "buzz", "click", "link", "rest",
    "quest", "autos", "lol", "mom", "shop", "store", "online", "site", "live", "fun",
    "club", "vip", "space", "website", "info", "biz", "tk", "ml", "ga", "cf", "gq",
    "monster", "beauty", "hair", "skin", "makeup", "boats", "christmas", "wiki",
}

# Only words a phishing page uses and a normal project does not. "web", "app",
# "bot", "support" and friends were in here first and matched every legitimate
# Telegram mini-app on free hosting - the list has to earn its false positives.
LURE = re.compile(
    r"verif|login|log-in|signin|sign-in|secure|account|auth(?!or)|confirm|"
    r"recover|unlock|activat|billing|payment|suspend|restrict|validat|"
    r"credential|password|otp|2fa", re.I)


def _labels(name):
    return (name or "").lower().strip().lstrip("*.").split(".")


def registrable(name):
    """What you would actually report. On a hosting platform that is the tenant
    subdomain - reporting the platform's own domain would be nonsense."""
    return fs.registrable_domain((name or "").lower().strip().lstrip("*."))


def is_legit(name, brand):
    dom = (name or "").lower().strip().lstrip("*.")
    return any(dom == g or dom.endswith("." + g) for g in LEGIT.get(brand, []))


def target_for(name, brand=""):
    """What you would actually report.

    On a hosting platform, the FULL hostname - a tenant may sit at any depth, and
    guessing a registrable domain there produced nonsense like `us-east4.hosted.app`.
    Also the full hostname when the brand sits in a subdomain, because the
    registrable domain alone (`code.run`) is not the thing doing the impersonating.
    """
    dom = (name or "").lower().strip().lstrip("*.")
    if fs.platform_suffix(dom):
        return dom
    reg = fs.registrable_domain(dom)
    if brand and brand.lower() in dom and brand.lower() not in reg:
        return dom
    return reg


def brand_label(dom, brand):
    """The single DNS label carrying the brand name, which is where the giveaway
    lives. Scoring the whole hostname let unrelated hyphens elsewhere in a long
    certificate name inflate the score."""
    for label in _labels(dom):
        if brand.lower() in label:
            return label
    return ""


def score(name, brand, issued=None, now=None):
    """Return (score, reasons). Signals are weighted by how much they really mean:
    phishing vocabulary beside the brand is the strong one. Free hosting barely
    counts on its own - legitimate Telegram bots live on workers.dev by the
    thousand, and treating that as evidence buried the real hits."""
    dom = (name or "").lower().strip().lstrip("*.")
    if not dom or "." not in dom or is_legit(dom, brand):
        return 0, []
    label = brand_label(dom, brand)
    if not label:
        return 0, []
    plat = fs.platform_suffix(dom)
    tld = plat or _labels(dom)[-1]
    rest = label.replace(brand.lower(), "")

    pts, why = 0, []
    if LURE.search(rest):
        pts += 3
        why.append("phishing vocabulary beside the brand")
    if tld in RISKY_TLD:
        pts += 2
        why.append(f"throwaway TLD .{tld}")
    elif plat:
        pts += 1
        why.append(f"free hosting on {plat}")
    if rest.count("-") >= 1:
        pts += 1
        why.append("brand hyphenated into the name")
    if re.search(r"\d", rest):
        pts += 1
        why.append("digits padding the brand")
    # Issue age is deliberately NOT scored. Nearly every row crt.sh returns is
    # recent, so it added a constant point to everything and simply moved the
    # scale - it is kept as metadata for sorting, not treated as evidence.
    return pts, why


def fetch(keyword, limit=400, tries=3):
    """Recent crt.sh entries whose names contain the keyword.

    Returns (rows, error). crt.sh rate-limits and times out often, and an empty
    list from a failed query is indistinguishable from a genuinely clean result -
    reporting that as "no phishing found" would be a lie, so failure is explicit.
    """
    q = urllib.parse.quote(f"%{keyword}%")
    last = "no response"
    for attempt in range(tries):
        # crt.sh regularly takes 25-40s for a broad keyword
        st, body = fs.http(f"https://crt.sh/?q={q}&output=json&exclude=expired", timeout=90)
        if st == 200 and body.lstrip().startswith("["):
            try:
                rows = json.loads(body)
                return (rows[:limit] if isinstance(rows, list) else []), None
            except ValueError:
                last = "crt.sh returned malformed JSON"
        elif st == 200:
            last = "crt.sh returned an empty or HTML response (usually rate limiting)"
        else:
            last = f"crt.sh HTTP {st}"
        if attempt < tries - 1:
            time.sleep(6 * (attempt + 1))
    return [], last


def scan(keywords, min_score=MIN_SCORE, limit=400):
    st = load_state()
    seen = set(st.get("seen", []))
    now = datetime.now(timezone.utc)
    fresh, errors, searched = [], {}, []
    for kw in keywords:
        rows, err = fetch(kw, limit)
        if err:
            errors[kw] = err
            continue
        searched.append(kw)
        for row in rows:
            cid = str(row.get("id") or "")
            for name in str(row.get("name_value") or "").splitlines():
                dom = target_for(name, kw)
                key = f"{kw}:{dom}"
                if not dom or key in seen:
                    continue
                pts, why = score(name, kw, row.get("entry_timestamp"), now)
                if pts < min_score:
                    continue
                seen.add(key)
                fresh.append({
                    "domain": dom, "name": name.lower().strip().lstrip("*."),
                    "brand": kw, "score": pts, "why": why,
                    "issuer": (row.get("issuer_name") or "")[:80],
                    "issued": row.get("entry_timestamp"),
                    "found": now.isoformat(), "cert_id": cid,
                    "url": f"https://{dom}/",
                })
    st["seen"] = sorted(seen)[-20000:]
    st["hits"] = (fresh + st.get("hits", []))[:MAX_HITS]
    st["last_scan"] = now.isoformat()
    st["last_errors"] = errors
    st["last_searched"] = searched
    save_state(st)
    return {"new": fresh, "errors": errors, "searched": searched,
            "hits": st["hits"], "last_scan": st["last_scan"]}


def load_state():
    try:
        return json.load(open(STATE))
    except Exception:
        return {"seen": [], "hits": [], "last_scan": None}


def save_state(st):
    os.makedirs(os.path.dirname(STATE), exist_ok=True)
    json.dump(st, open(STATE, "w"), indent=1)


def dismiss(domain):
    st = load_state()
    st["hits"] = [h for h in st["hits"] if h["domain"] != domain]
    save_state(st)
    return st


def selftest():
    now = datetime.now(timezone.utc)

    # the brand's own domains must never be flagged, subdomains included
    for good in ("telegram.org", "web.telegram.org", "*.telegram.org", "t.me"):
        assert score(good, "telegram", None, now)[0] == 0, good
    assert score("whatsapp.com", "whatsapp", None, now)[0] == 0

    # a real impersonation clears the bar
    pts, why = score("tg-telegram-verify.cyou", "telegram", now.isoformat(), now)
    assert pts >= MIN_SCORE, (pts, why)
    assert any("throwaway TLD" in w for w in why) and any("vocabulary" in w for w in why)

    pts, _ = score("whatsapp-secure-login24.top", "whatsapp", now.isoformat(), now)
    assert pts >= MIN_SCORE, pts

    # a keyword alone on a normal TLD is not enough - this is the false-positive guard
    assert score("telegramnews.com", "telegram", None, now)[0] < MIN_SCORE
    assert score("mytelegram.org", "telegram", None, now)[0] < MIN_SCORE
    # keyword must be in the name at all
    assert score("randomsite.top", "telegram", None, now)[0] == 0
    # issue age must not change the score - it is metadata, not evidence
    old = (now - timedelta(days=30)).isoformat()
    assert score("telegram-verify.cyou", "telegram", now.isoformat(), now)[0] == \
           score("telegram-verify.cyou", "telegram", old, now)[0]

    assert target_for("*.a.b.evil.co.uk") == "evil.co.uk"
    # brand in a subdomain: report the hostname, not the innocent parent domain
    assert target_for("telegram-login.2myco.com", "telegram") == "telegram-login.2myco.com"
    assert target_for("shop.2myco.com", "telegram") == "2myco.com"
    # on a platform the whole hostname is the target, at whatever depth
    assert target_for("*.tg-verify.us-east4.hosted.app") == "tg-verify.us-east4.hosted.app"
    assert target_for("*.telegram-verify.workers.dev") == "telegram-verify.workers.dev"
    pts, why = score("telegram-verify-login.pages.dev", "telegram", now.isoformat(), now)
    assert pts >= MIN_SCORE, (pts, why)
    assert any("vocabulary" in w for w in why), why
    assert score("pages.dev", "telegram", None, now)[0] == 0, "the platform itself is not a hit"

    # the noise that swamped the first live run must stay below the bar
    for quiet in ("rayleigh.workers.dev", "mint14.workers.dev",
                  "us-east4.hosted.app", "gotip77433.workers.dev"):
        assert score(quiet, "telegram", now.isoformat(), now)[0] < MIN_SCORE, quiet
    # a long certificate name must not score on hyphens that are nowhere near the brand
    noisy = "*.telegram----cassiusvpn----64616489484.gotip77433.workers.dev"
    pts_noisy, _ = score(noisy, "telegram", now.isoformat(), now)
    assert pts_noisy < MIN_SCORE, pts_noisy
    # ...while a genuine lure on free hosting still clears it
    assert score("telegram-account-verify.workers.dev", "telegram",
                 now.isoformat(), now)[0] >= MIN_SCORE
    # legitimate developer projects on free hosting must stay quiet
    for ok in ("telegram-bot--web-monopoly-f8bc3.europe-west4.hosted.app",
               "lumi-telegram-mini-app--lumi-a25e1.europe-west4.hosted.app",
               "telegram-webapp--hadith-api-dev.us-east4.hosted.app",
               "whatsapp-website-for-my-shop.pages.dev"):
        assert score(ok, ok.split("-")[0] if "telegram" in ok else "whatsapp",
                     now.isoformat(), now)[0] < MIN_SCORE, ok
    # a failed source must be reported as a failure, never as "nothing found"
    import unittest.mock as _m
    with _m.patch.object(fs, "http", return_value=(503, "")):
        rows, err = fetch("telegram", tries=1)
        assert rows == [] and err and "503" in err, (rows, err)
        r = scan(["telegram"], limit=5)
        assert r["new"] == [] and r["errors"].get("telegram"), r
        assert r["searched"] == [], "a keyword that failed must not count as searched"
    print("ctwatch selftest OK")


if __name__ == "__main__":
    selftest()
