"""Turn a pasted scam message into reportable targets.

You get the SMS, you copy the whole thing, you paste it here. This pulls the URLs
out - including the obfuscated ones - works out which brand is being spoofed from
the wording rather than the domain, expands shortened links, and drops anything you
have already reported.
"""
import re
import urllib.parse

import fuckscammer as fs

# Scam texts mangle links to dodge filters: hxxps, [.], (dot), spaces.
DEOBF = [
    (re.compile(r"\bh(?:xx|XX)(ps?)\b", re.I), r"htt\1"),
    # (.) [.] {.} and the spelled-out (dot) [dot] {dot}, spaces around them eaten
    (re.compile(r"\s*[\(\[\{]\s*\.\s*[\)\]\}]\s*"), "."),
    (re.compile(r"\s*[\(\[\{]\s*dot\s*[\)\]\}]\s*", re.I), "."),
    (re.compile(r"\s+dot\s+", re.I), "."),
    (re.compile(r"\[\s*:\s*\]"), ":"),
    (re.compile(r"\bhttps?\s*:\s*/\s*/", re.I), lambda m: m.group(0).replace(" ", "")),
]

URL_RE = re.compile(r"""(?xi)
    \b(?:https?://)?                      # optional scheme
    (?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+   # labels
    (?:com|net|org|top|xyz|icu|cyou|shop|store|online|site|club|live|vip|cc|co|io|me|
       info|biz|link|click|fun|life|world|today|app|dev|pro|asia|sg|my|hk|tw|cn|id|ph|
       th|vn|in|uk|ru|tk|ml|ga|cf|gq|buzz|rest|autos|bond|cfd|sbs|lol|mom|quest)
    \b(?:/[^\s<>"'()\[\]]*)?              # optional path
""")

SHORTENERS = {
    "bit.ly", "t.co", "tinyurl.com", "is.gd", "goo.gl", "ow.ly", "buff.ly", "cutt.ly",
    "rb.gy", "rebrand.ly", "shorturl.at", "s.id", "lnkd.in", "t.ly", "tiny.cc", "v.gd",
    "shorte.st", "bl.ink", "trib.al", "u.to", "clck.ru", "qr.ae", "wa.link", "chl.li",
}

# Words a spoofed message uses, mapped to the brand whose abuse desk should hear about it.
BRAND_HINTS = {
    "telegram": ["telegram", "t.me", "telegram support", "telegram security"],
    "whatsapp": ["whatsapp", "whats app", "wa business", "whatsapp support"],
    "apple": ["apple", "icloud", "apple id"],
    "google": ["google", "gmail account"],
    "microsoft": ["microsoft", "outlook", "office 365"],
    "meta": ["meta", "facebook", "instagram", "fb support"],
    "amazon": ["amazon", "prime delivery"],
    "netflix": ["netflix"],
    "paypal": ["paypal"],
    "binance": ["binance"],
    "coinbase": ["coinbase"],
}

# Phrases that mark the message as a scam - shown back so you can paste them into a report.
LURES = [
    (r"verif(y|ication)", "asks you to verify"),
    (r"suspend|deactivat|blocked|locked", "threatens account suspension"),
    (r"unusual (login|activity)|new device|logged in from", "fake security alert"),
    (r"within \d+ ?(hours?|hrs?|minutes?|mins?)|immediately|urgent", "manufactured urgency"),
    (r"click (the )?link|tap (the )?link|follow the link", "pushes a link"),
    (r"one[- ]?time|otp|code|password|pin", "fishing for a code or password"),
    (r"prize|reward|refund|claim|won", "bait offer"),
    (r"deliver|parcel|package|customs|shipping", "fake delivery"),
]


def deobfuscate(text):
    out = text or ""
    for pat, rep in DEOBF:
        out = pat.sub(rep, out)
    return out


def extract_urls(text):
    clean = deobfuscate(text or "")
    seen, out = set(), []
    for m in URL_RE.finditer(clean):
        raw = m.group(0).rstrip(".,;:)]}’\"'")
        url = raw if raw.lower().startswith(("http://", "https://")) else "https://" + raw
        host = (urllib.parse.urlparse(url).hostname or "").lower()
        if not host or host in seen:
            continue
        # an email address is not a link
        start = m.start()
        if start and clean[start - 1] == "@":
            continue
        seen.add(host)
        out.append(url)
    return out


def guess_brand(text, url=""):
    hay = f"{text or ''} {url or ''}".lower()
    best, best_at = None, len(hay) + 1
    for brand, words in BRAND_HINTS.items():
        for w in words:
            at = hay.find(w)
            if at >= 0 and at < best_at:
                best, best_at = brand, at
    return best


def lures(text):
    low = (text or "").lower()
    return [label for pat, label in LURES if re.search(pat, low)]


def is_shortener(url):
    return (urllib.parse.urlparse(url).hostname or "").lower().lstrip("www.") in SHORTENERS


def expand(url, allow_touch=True):
    """Follow a shortener to its real destination.

    Only runs for known shortener hosts, so an ordinary phishing link is never
    fetched here. Returns (final_url, note)."""
    if not is_shortener(url):
        return url, ""
    if not allow_touch:
        return url, "shortened link — expansion skipped"
    st, _ = fs.http(url, method="HEAD")
    # fs.http follows redirects; on failure fall back to the original
    try:
        req = __import__("urllib.request", fromlist=["request"]).Request(
            url, headers={"User-Agent": fs.UA}, method="HEAD")
        with __import__("urllib.request", fromlist=["request"]).urlopen(req, timeout=20) as r:
            final = r.geturl()
        return final, (f"expanded from {urllib.parse.urlparse(url).hostname}"
                       if final != url else "shortener did not redirect")
    except Exception as e:
        return url, f"could not expand ({type(e).__name__})"


def parse(text, known_hosts=(), allow_touch=True):
    """The whole intake step: text in, reportable targets out."""
    urls = extract_urls(text)
    hint = lures(text)
    out = []
    for u in urls:
        final, note = expand(u, allow_touch)
        host = (urllib.parse.urlparse(final).hostname or "").lower()
        out.append({
            "url": final, "host": host,
            "domain": fs.registrable_domain(host) if host else "",
            "original": u if final != u else None,
            "brand": guess_brand(text, final),
            "note": note,
            "already_reported": host in set(known_hosts),
        })
    return {"targets": out, "lures": hint,
            "summary": (f"{len(out)} link(s)" + (f", {len(hint)} scam signal(s)" if hint else ""))}


def selftest():
    sms = ("WhatsApp Security: Unusual login detected. Your account will be suspended "
           "within 24 hours. Verify now: hxxps://wa-verify-login[.]top/auth?id=99 "
           "Do not share your OTP code.")
    got = extract_urls(sms)
    assert got == ["https://wa-verify-login.top/auth?id=99"], got
    assert guess_brand(sms) == "whatsapp"
    L = lures(sms)
    for expect in ("threatens account suspension", "fake security alert",
                   "manufactured urgency", "asks you to verify"):
        assert expect in L, (expect, L)

    # brand comes from the wording, because the domain is deliberately meaningless
    tg = "Telegram: confirm your number at https://xk28fj.icu/login"
    assert guess_brand(tg) == "telegram"
    assert extract_urls(tg) == ["https://xk28fj.icu/login"]

    # obfuscation styles
    for variant in ("go to evil (dot) com now", "go to evil[dot]com now",
                    "go to evil dot com now", "go to evil[.]com now"):
        assert extract_urls(variant) == ["https://evil.com"], variant
    assert deobfuscate("hxxp://a") == "http://a" and deobfuscate("hxxps://a") == "https://a"
    assert extract_urls("hxxp://bad{.}xyz/a") == ["http://bad.xyz/a"]
    # an email address must not be mistaken for a link
    assert extract_urls("mail me at someone@gmail.com") == []
    # duplicates on the same host collapse
    assert len(extract_urls("a.top/1 and a.top/2")) == 1

    assert is_shortener("https://bit.ly/abc") and not is_shortener("https://evil.top/x")
    # a plain phishing link is never fetched during expansion
    assert expand("https://evil.top/x", allow_touch=True) == ("https://evil.top/x", "")

    p = parse(sms, known_hosts=["wa-verify-login.top"], allow_touch=False)
    assert p["targets"][0]["already_reported"] is True
    assert p["targets"][0]["brand"] == "whatsapp"
    assert p["targets"][0]["domain"] == "wa-verify-login.top"
    print("intake selftest OK")


if __name__ == "__main__":
    selftest()
