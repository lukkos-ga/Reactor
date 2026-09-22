"""National reporting channels.

Country-specific, because who you tell about a phishing site depends on where you
are. Each entry records how it was checked, so a dead link is visible rather than
silently useless - government portals move often.

kind:
  email   - added to the complaint drafts automatically
  form    - a web form you fill in; shown as a link with the URL to hand it
  hotline - a phone number; shown, never dialled
"""
CHANNELS = {
    "MY": {
        "name": "Malaysia",
        "entries": [
            dict(id="mycert", kind="form", org="MyCERT Cyber999 (CyberSecurity Malaysia)",
                 target="https://www.mycert.org.my/cyber999",
                 when="always — this is the national CERT and it coordinates takedowns",
                 note="The technical channel. They contact the host and registrar on your "
                      "behalf and have standing with them that an individual does not.",
                 verified="HTTP 200"),
            dict(id="mycert_mail", kind="email", org="MyCERT Cyber999", target="cyber999@cybersecurity.my",
                 when="always — same team as the form, by email",
                 note="Mail domain confirmed to accept mail; the mailbox name itself is "
                      "Cyber999's long-published address but was not readable on their page. "
                      "If it bounces, use the form instead.",
                 verified="MX present for cybersecurity.my"),
            dict(id="mcmc", kind="form", org="MCMC (Malaysian Communications and Multimedia Commission)",
                 target="https://aduan.mcmc.gov.my/",
                 when="always for a phishing site, and for the spoofed SMS itself",
                 note="The regulator. They handle site blocking within Malaysia and are the "
                      "right channel for the SMS spoofing, which no registrar will act on.",
                 verified="HTTP 200 (aduan.skmm.gov.my redirects here)"),
            dict(id="semakmule", kind="form", org="PDRM Semak Mule",
                 target="https://semakmule.rmp.gov.my/",
                 when="when the scam gave you a bank account or phone number",
                 note="Police database of mule accounts and numbers. Check the account or "
                      "number, and report it if it is not already listed.",
                 verified="HTTP 200"),
            dict(id="nsrc", kind="hotline", org="National Scam Response Centre",
                 target="997",
                 when="ONLY if money has actually been transferred — call immediately",
                 note="Funds can sometimes be frozen if you call within the first hours. "
                      "Nothing else in this tool is urgent in that way.",
                 verified="hotline, not checkable from here"),
            dict(id="cyber999_phone", kind="hotline", org="Cyber999 hotline",
                 target="1-300-88-2999",
                 when="if you want to talk it through rather than fill a form",
                 note="Published on the Cyber999 page.",
                 verified="read from mycert.org.my/cyber999"),
        ],
    },
}


def get(code):
    return CHANNELS.get((code or "").upper())


def countries():
    return sorted([(k, v["name"]) for k, v in CHANNELS.items()], key=lambda x: x[1])


def emails(code):
    """(address, label) pairs to add to the complaint drafts."""
    c = get(code)
    if not c:
        return []
    return [(e["target"], f"{e['org']} ({c['name']})")
            for e in c["entries"] if e["kind"] == "email"]


def forms(code):
    """(label, url) pairs for the manual-forms list."""
    c = get(code)
    if not c:
        return []
    return [(f"{e['org']} — {e['when']}", e["target"])
            for e in c["entries"] if e["kind"] == "form"]


def all_entries(code):
    c = get(code)
    return c["entries"] if c else []


def selftest():
    assert get("my")["name"] == "Malaysia"
    assert get("MY") is get("my"), "country code must be case-insensitive"
    assert get("ZZ") is None and emails("ZZ") == [] and forms("ZZ") == []

    addrs = [a for a, _ in emails("MY")]
    assert "cyber999@cybersecurity.my" in addrs
    # only email entries become drafts; forms and hotlines must never be mailed
    assert all("@" in a for a in addrs)
    assert not any(t.startswith("http") or t.isdigit() for t in addrs)

    urls = [u for _, u in forms("MY")]
    assert "https://aduan.mcmc.gov.my/" in urls
    assert all(u.startswith("https://") for u in urls), urls
    # the emergency channel must be a hotline, never something we auto-submit
    nsrc = [e for e in all_entries("MY") if e["id"] == "nsrc"][0]
    assert nsrc["kind"] == "hotline" and "ONLY if money" in nsrc["when"]
    # every entry records how it was checked
    assert all(e.get("verified") for e in all_entries("MY"))
    assert ("MY", "Malaysia") in countries()
    print("channels selftest OK")


if __name__ == "__main__":
    selftest()
