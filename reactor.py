#!/usr/bin/env python3
"""fuckscammer - one-shot phishing URL abuse reporter.

Paste a phishing URL, it does recon (RDAP/DNS), submits to every abuse API it
can reach, writes ready-to-send .eml complaints for the ones that are email-only,
and prints the human-only web forms with the URL pre-filled.

Stdlib only. No pip install.

Usage:
    python3 fuckscammer.py https://www.example.top/          # dry run, recon only
    python3 fuckscammer.py https://www.example.top/ --send   # actually report
    python3 fuckscammer.py --selftest

Env (all optional, unlocks more targets):
    REPORTER_EMAIL   your email - required by Netcraft + used as From: in .eml
    URLSCAN_API_KEY  urlscan.io (free key)
    VT_API_KEY       VirusTotal (free key)
    SMTP_HOST SMTP_PORT SMTP_USER SMTP_PASS   send the .eml complaints for real
"""
import argparse
import json
import os
import re
import smtplib
import socket
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

import channels
from email.message import EmailMessage

UA = "Mozilla/5.0 (compatible; abuse-reporter/1.0)"
TIMEOUT = 25

# Brand keyword -> that brand's own abuse mailbox. Impersonated brands want to know.
BRAND_ABUSE = {
    "telegram": "abuse@telegram.org",
    "whatsapp": "abuse@support.whatsapp.com",
    "binance": "phishing@binance.com",
    "coinbase": "security@coinbase.com",
    "paypal": "phishing@paypal.com",
    "apple": "reportphishing@apple.com",
    "microsoft": "phish@office365.microsoft.com",
    "amazon": "stop-spoofing@amazon.com",
    "google": "phishing-report@google.com",
    "netflix": "phishing@netflix.com",
    "meta": "phish@fb.com",
    "facebook": "phish@fb.com",
    "instagram": "phish@fb.com",
}

# Always-on email clearinghouses.
CLEARINGHOUSES = [
    ("APWG", "reportphishing@apwg.org"),
    ("Netcraft (email fallback)", "scam@netcraft.com"),
]


# ---------------------------------------------------------------- http helpers

def http(url, data=None, headers=None, method=None, timeout=None):
    """Returns (status, body_text). Never raises on HTTP error status."""
    hdrs = {"User-Agent": UA}
    if headers:
        hdrs.update(headers)
    body = None
    if data is not None:
        body = json.dumps(data).encode()
        hdrs.setdefault("Content-Type", "application/json")
    req = urllib.request.Request(url, data=body, headers=hdrs, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout or TIMEOUT,
                                    context=ssl.create_default_context()) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except Exception as e:  # DNS death, timeout, TLS, whatever
        return 0, f"{type(e).__name__}: {e}"


def jget(url, headers=None, timeout=None):
    st, body = http(url, headers=headers, timeout=timeout)
    if st != 200:
        return None
    try:
        return json.loads(body)
    except ValueError:
        return None


# --------------------------------------------------------------------- recon

# Hosting platforms where each customer gets a subdomain. The tenant label IS the
# site: treating these as ordinary domains would have us reporting Cloudflare or
# Google to their own registrar instead of reporting the scammer.
PLATFORM_SUFFIXES = {
    "pages.dev", "workers.dev", "r2.dev", "vercel.app", "netlify.app", "netlify.com",
    "github.io", "gitlab.io", "web.app", "firebaseapp.com", "hosted.app", "run.app",
    "appspot.com", "herokuapp.com", "onrender.com", "fly.dev", "surge.sh", "glitch.me",
    "repl.co", "replit.app", "000webhostapp.com", "wixsite.com", "weeblysite.com",
    "blogspot.com", "square.site", "myshopify.com", "webflow.io", "framer.app",
    "bubbleapps.io", "notion.site", "canva.site", "durable.co", "trycloudflare.com",
    "ngrok.io", "ngrok-free.app", "serveo.net", "loca.lt", "codeanyapp.com",
}

TWO_LABEL_SUFFIXES = {"co.uk", "org.uk", "ac.uk", "gov.uk", "co.jp", "com.cn",
                      "com.br", "com.au", "co.nz", "co.za", "com.tw", "com.hk",
                      "com.sg", "co.kr", "com.mx", "co.in", "com.tr"}


def platform_suffix(host):
    """The hosting platform this host sits on, or None."""
    h = (host or "").lower().strip(".")
    for suf in PLATFORM_SUFFIXES:
        if h == suf or h.endswith("." + suf):
            return suf
    return None


def registrable_domain(host):
    """Good-enough eTLD+1, with hosting platforms treated as public suffixes."""
    host = (host or "").lower().strip(".")
    parts = [p for p in host.split(".") if p]
    if len(parts) <= 2:
        return host
    suf = platform_suffix(host)
    if suf:
        # keep the tenant label: evil.pages.dev, not pages.dev
        depth = len(suf.split(".")) + 1
        return ".".join(parts[-depth:]) if len(parts) >= depth else host
    if ".".join(parts[-2:]) in TWO_LABEL_SUFFIXES:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def rdap_emails(obj):
    """Pull every abuse-ish email out of an RDAP entity tree (vCard jCard)."""
    found = []

    def walk(node, in_abuse):
        if isinstance(node, dict):
            roles = node.get("roles") or []
            abuse = in_abuse or ("abuse" in [r.lower() for r in roles])
            vc = node.get("vcardArray")
            if vc and len(vc) > 1:
                for entry in vc[1]:
                    if isinstance(entry, list) and len(entry) >= 4 and entry[0] == "email":
                        found.append((abuse, str(entry[3])))
            for v in node.values():
                walk(v, abuse)
        elif isinstance(node, list):
            for v in node:
                walk(v, in_abuse)

    walk(obj, False)
    # ponytail: if RDAP labelled anything abuse-role, trust only those - the rest
    # is noc@/rir@/registrant noise that gets your mail ignored.
    abuse_first = [e for a, e in found if a] or [e for _, e in found]
    seen, out = set(), []
    for e in abuse_first:
        if e.lower() not in seen and "@" in e:
            seen.add(e.lower())
            out.append(e)
    return out


def recon(url):
    p = urllib.parse.urlparse(url)
    host = p.hostname or ""
    dom = registrable_domain(host)
    info = {"url": url, "host": host, "domain": dom, "ips": [], "registrar": None,
            "registrar_abuse": [], "created": None, "ns": [], "ip_abuse": [],
            "network": None, "cloudflare": False, "brand": None}

    try:
        info["ips"] = sorted({ai[4][0] for ai in socket.getaddrinfo(host, None)})
    except Exception:
        pass

    d = jget(f"https://rdap.org/domain/{dom}") or jget(f"https://rdap.zdnsgtld.com/{dom.rsplit('.',1)[-1]}/domain/{dom}")
    if d:
        info["registrar_abuse"] = rdap_emails(d)
        for ent in d.get("entities", []):
            if "registrar" in [r.lower() for r in ent.get("roles", [])]:
                vc = ent.get("vcardArray")
                if vc and len(vc) > 1:
                    for e in vc[1]:
                        if isinstance(e, list) and e[0] == "fn":
                            info["registrar"] = str(e[3])
        for ev in d.get("events", []):
            if ev.get("eventAction") == "registration":
                info["created"] = ev.get("eventDate")
        info["ns"] = [n.get("ldhName", "") for n in d.get("nameservers", [])]

    if not info["ns"]:
        st, body = http(f"https://dns.google/resolve?name={dom}&type=NS")
        if st == 200:
            try:
                info["ns"] = [a["data"].strip(".") for a in json.loads(body).get("Answer", [])]
            except Exception:
                pass

    info["cloudflare"] = any("cloudflare" in n.lower() for n in info["ns"])

    for ip in info["ips"][:2]:
        ipd = jget(f"https://rdap.org/ip/{ip}")
        if ipd:
            info["network"] = ipd.get("name") or info["network"]
            info["ip_abuse"] += [e for e in rdap_emails(ipd) if e not in info["ip_abuse"]]
    return info


def guess_brand(info):
    forced = (info.get("brand") or "").lower()
    if forced:
        return forced, BRAND_ABUSE.get(forced, "")
    hay = (info["url"] + " " + info["host"]).lower()
    for k, mail in BRAND_ABUSE.items():
        if k in hay:
            return k, mail
    return None, None


# ------------------------------------------------------------------ API submits

def submit_netcraft(url, reporter):
    if not reporter:
        return "SKIP", "set REPORTER_EMAIL"
    payload = {"email": reporter, "urls": [{"url": url, "country": "US"}],
               "reason": "Phishing site impersonating a brand login page."}
    for attempt in (1, 2):   # their API 400s intermittently on a first, valid POST
        st, body = http("https://report.netcraft.com/api/v3/report/urls", data=payload)
        if st in (200, 201):
            return "OK", body[:300]
        if attempt == 1:
            import time as _t
            _t.sleep(2)
    return f"HTTP {st}", body[:300]


def submit_urlscan(url):
    key = os.getenv("URLSCAN_API_KEY")
    if not key:
        return "SKIP", "set URLSCAN_API_KEY (free at urlscan.io/user/signup)"
    st, body = http("https://urlscan.io/api/v1/scan/", data={"url": url, "visibility": "public",
                                                            "tags": ["phishing"]},
                    headers={"API-Key": key})
    return ("OK" if st == 200 else f"HTTP {st}"), body[:300]


def submit_virustotal(url):
    key = os.getenv("VT_API_KEY")
    if not key:
        return "SKIP", "set VT_API_KEY (free at virustotal.com)"
    data = urllib.parse.urlencode({"url": url}).encode()
    req = urllib.request.Request("https://www.virustotal.com/api/v3/urls", data=data,
                                 headers={"x-apikey": key, "User-Agent": UA,
                                          "Content-Type": "application/x-www-form-urlencoded"})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            return "OK", r.read().decode()[:300]
    except urllib.error.HTTPError as e:
        return f"HTTP {e.code}", e.read().decode()[:300]
    except Exception as e:
        return "ERR", str(e)


API_TARGETS = [
    ("Netcraft", submit_netcraft, True),      # True = needs reporter email arg
    ("urlscan.io", submit_urlscan, False),
    ("VirusTotal", submit_virustotal, False),
]


# ------------------------------------------------------------------- email side

def complaint_body(info, recipient_label):
    b = guess_brand(info)[0]
    brand = f" impersonating {b.title()}" if b else ""
    return f"""To whom it may concern ({recipient_label}),

I am reporting an active phishing website{brand} for immediate takedown.

  Phishing URL : {info['url']}
  Domain       : {info['domain']}
  Resolved IPs : {', '.join(info['ips']) or 'n/a'}
  Nameservers  : {', '.join(info['ns']) or 'n/a'}
  Registrar    : {info['registrar'] or 'n/a'}
  Registered   : {info['created'] or 'n/a'}
  Network      : {info['network'] or 'n/a'}
  Reported at  : {datetime.now(timezone.utc).isoformat()}

The site is designed to harvest credentials from victims who believe they are
using a legitimate service. This violates your acceptable use policy and, for
the registrar, the ICANN RAA 2013 Section 3.18 obligation to investigate and
respond to reports of abuse.

Please suspend the domain / disable the hosting account and confirm the action
taken. I am available for any further evidence you require.

Regards,
{os.getenv('REPORTER_NAME', 'A concerned internet user')}
"""


def base_mailbox(addr):
    """you+abuse@gmail.com -> you@gmail.com. Gmail selects accounts by the real
    mailbox, not by a plus-alias, and a +tag sends as the base account anyway."""
    local, _, dom = str(addr or "").lower().partition("@")
    return f"{local.split('+')[0]}@{dom}" if dom else ""


def compose_links(to, subject, body, reporter="", gmail_index=None):
    """Hand-off links so you can send from your own mail client instead of letting
    this tool touch SMTP. mailto: is fully local - nothing leaves the machine until
    you press Send in your own app.

    The Gmail link picks the sending account by ADDRESS (`authuser=`), not by the
    /u/N/ slot. A slot is a position in one browser's session list: if that position
    is empty Gmail silently drops you back to /u/0/ and sends from the wrong account.
    An address cannot be wrong. gmail_index stays available as an override for anyone
    who wants to pin the path, but it is not needed and defaults to off."""
    q = urllib.parse.urlencode({"subject": subject, "body": body}, quote_via=urllib.parse.quote)
    gp = {"view": "cm", "fs": "1", "to": to, "su": subject, "body": body}
    who = base_mailbox(reporter)
    if who:
        gp["authuser"] = who
    gq = urllib.parse.urlencode(gp, quote_via=urllib.parse.quote)
    path = f"u/{int(gmail_index)}/" if gmail_index not in (None, "", -1) else ""
    return {"mailto": f"mailto:{urllib.parse.quote(to)}?{q}",
            "gmail": f"https://mail.google.com/mail/{path}?{gq}"}


def build_emls(info, outdir):
    """Write one .eml per recipient. Returns list of (path, to_addr, label)."""
    os.makedirs(outdir, exist_ok=True)
    reporter = os.getenv("REPORTER_EMAIL", "")
    targets = []
    for e in info["registrar_abuse"]:
        targets.append((e, f"registrar {info['registrar'] or ''}".strip()))
    for e in info["ip_abuse"]:
        targets.append((e, f"network {info['network'] or ''}".strip()))
    bk, bmail = guess_brand(info)
    if bmail:
        targets.append((bmail, f"{bk} brand protection"))
    elif bk:
        print(f"  (no known abuse mailbox for brand '{bk}' - add one to BRAND_ABUSE)")
    targets += [(m, lbl) for lbl, m in CLEARINGHOUSES]
    # your own country's CERT, which can lean on the host and registrar in ways
    # an individual reporter cannot
    targets += channels.emails(os.getenv("REPORTER_COUNTRY", ""))

    seen, out = set(), []
    for addr, label in targets:
        if addr.lower() in seen:
            continue
        seen.add(addr.lower())
        m = EmailMessage()
        m["Subject"] = f"Phishing site takedown request: {info['domain']}"
        m["To"] = addr
        if reporter:
            m["From"] = reporter
        m.set_content(complaint_body(info, label))
        path = os.path.join(outdir, re.sub(r"[^a-z0-9]+", "_", addr.lower()) + ".eml")
        with open(path, "wb") as f:
            f.write(bytes(m))
        out.append((path, addr, label, m["Subject"], m.get_content()))
    return out


def smtp_send(emls):
    host = os.getenv("SMTP_HOST")
    if not host:
        return None
    port = int(os.getenv("SMTP_PORT", "587"))
    user, pw = os.getenv("SMTP_USER"), os.getenv("SMTP_PASS")
    results = []
    with smtplib.SMTP(host, port, timeout=30) as s:
        s.starttls(context=ssl.create_default_context())
        if user:
            s.login(user, pw)
        for path, addr, *_ in emls:
            try:
                with open(path, "rb") as f:
                    s.sendmail(os.getenv("REPORTER_EMAIL", user), [addr], f.read())
                results.append((addr, "SENT"))
            except Exception as e:
                results.append((addr, f"FAIL {e}"))
    return results


# --------------------------------------------------------------- manual forms

def manual_forms(info):
    u = urllib.parse.quote(info["url"], safe="")
    forms = list(channels.forms(os.getenv("REPORTER_COUNTRY", "")))
    forms += [
        ("Google Safe Browsing", f"https://safebrowsing.google.com/safebrowsing/report_phish/?url={u}"),
        ("Microsoft SmartScreen", f"https://www.microsoft.com/en-us/wdsi/support/report-unsafe-site-guest?url={u}"),
        ("PhishTank (submit)", "https://phishtank.org/add_web_phish.php"),
        ("Spamhaus DBL removal/report", "https://www.spamhaus.org/report-spam/"),
        ("APWG eCrime portal", "https://apwg.org/reportphishing/"),
    ]
    if info["cloudflare"]:
        forms.insert(0, ("Cloudflare abuse (phishing) - REQUIRED, they front this site",
                         "https://abuse.cloudflare.com/phishing"))
    forms.append(("ICANN complaint - ONLY after registrar ignores you 24h+",
                  "https://forms.icann.org/en/resources/compliance/complaints/registrars/abuse-report-form"))
    return forms


# --------------------------------------------------------------------- output

def run(url, send, outdir, brand=None):
    print(f"\n=== RECON  {url} ===")
    info = recon(url)
    info["brand"] = brand
    for k in ("domain", "ips", "registrar", "created", "ns", "network"):
        print(f"  {k:<10}: {info[k]}")
    print(f"  {'abuse':<10}: registrar={info['registrar_abuse']} network={info['ip_abuse']}")
    if info["created"] and info["created"][:4] >= "2024":
        print("  NOTE      : freshly registered domain - strong phishing signal, say so in reports")

    print("\n=== API SUBMISSIONS ===")
    reporter = os.getenv("REPORTER_EMAIL")
    for name, fn, needs_email in API_TARGETS:
        if not send:
            print(f"  [dry-run] {name}")
            continue
        status, detail = fn(url, reporter) if needs_email else fn(url)
        print(f"  {name:<14} {status:<10} {detail[:120]}")

    print("\n=== EMAIL COMPLAINTS ===")
    emls = build_emls(info, outdir)
    for path, addr, label in emls:
        print(f"  {addr:<38} ({label})  -> {path}")
    if send and os.getenv("SMTP_HOST"):
        print("  sending via SMTP...")
        for addr, res in smtp_send(emls) or []:
            print(f"    {addr:<38} {res}")
    elif send:
        print("  SMTP_HOST not set - .eml files written, open them in your mail client to send")

    print("\n=== MANUAL FORMS (CAPTCHA / human-only, open these) ===")
    for name, link in manual_forms(info):
        print(f"  {name}\n    {link}")
    print()
    return info


# -------------------------------------------------------------------- selftest

def selftest():
    assert registrable_domain("www.tegexyy.top") == "tegexyy.top"
    assert registrable_domain("a.b.c.co.uk") == "c.co.uk"
    assert registrable_domain("example.com") == "example.com"
    # a hosting platform's own domain must never become the report target
    assert registrable_domain("evil-login.pages.dev") == "evil-login.pages.dev"
    assert registrable_domain("x.y.scam.workers.dev") == "scam.workers.dev"
    assert registrable_domain("phish.github.io") == "phish.github.io"
    assert platform_suffix("scam.workers.dev") == "workers.dev"
    assert platform_suffix("tegexyy.top") is None
    fake = {"entities": [
        {"roles": ["registrar"], "entities": [
            {"roles": ["abuse"], "vcardArray": ["vcard", [["email", {}, "text", "abuse@reg.test"]]]}]},
        {"roles": ["registrant"], "vcardArray": ["vcard", [["email", {}, "text", "someone@else.test"]]]},
    ]}
    assert rdap_emails(fake)[0] == "abuse@reg.test", rdap_emails(fake)
    noisy = {"entities": [{"roles": ["technical"], "vcardArray": ["vcard", [["email", {}, "text", "noc@net.test"]]]},
                          {"roles": ["abuse"], "vcardArray": ["vcard", [["email", {}, "text", "abuse@net.test"]]]}]}
    assert rdap_emails(noisy) == ["abuse@net.test"], rdap_emails(noisy)
    assert guess_brand({"url": "https://x.top/", "host": "x.top", "brand": "telegram"}) == ("telegram", "abuse@telegram.org")
    os.environ["REPORTER_COUNTRY"] = "MY"
    my_forms = [u for _, u in manual_forms({"url": "https://x.top/", "cloudflare": False})]
    assert "https://aduan.mcmc.gov.my/" in my_forms, "country channels must lead the list"
    os.environ["REPORTER_COUNTRY"] = ""
    assert "https://aduan.mcmc.gov.my/" not in [
        u for _, u in manual_forms({"url": "https://x.top/", "cloudflare": False})]
    info = {"url": "https://x.top/telegram-login", "host": "x.top", "domain": "x.top",
            "ips": [], "ns": [], "registrar": None, "created": None, "network": None,
            "registrar_abuse": [], "ip_abuse": [], "cloudflare": True, "brand": None}
    assert guess_brand(info) == ("telegram", "abuse@telegram.org")
    assert "abuse.cloudflare.com" in manual_forms(info)[0][1]
    assert "x.top" in complaint_body(info, "registrar")
    print("selftest OK")


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Report a phishing URL everywhere at once.")
    ap.add_argument("url", nargs="?", help="the phishing URL")
    ap.add_argument("--send", action="store_true", help="actually submit (default is dry run)")
    ap.add_argument("--out", default="reports", help="directory for .eml complaint drafts")
    ap.add_argument("--brand", help="impersonated brand, e.g. telegram - CCs their abuse desk")
    ap.add_argument("--compose", action="store_true",
                    help="open every complaint as a prefilled draft in your own mail app "
                         "(sends nothing - you press Send yourself)")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        selftest()
        sys.exit(0)
    if not a.url:
        ap.error("give a URL, or --selftest")
    out = os.path.join(a.out, urllib.parse.urlparse(a.url).hostname or "target")
    info = run(a.url, a.send, out, a.brand)
    if a.compose:
        import subprocess
        info["brand"] = a.brand
        drafts = build_emls(info, out)
        for _path, addr, _label, subj, body in drafts:
            subprocess.Popen(["open", compose_links(addr, subj, body)["mailto"]])
        print(f"Opened {len(drafts)} prefilled drafts in your mail app. "
              f"Read each one and press Send yourself — this tool sent nothing.")
