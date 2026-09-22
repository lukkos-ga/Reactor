"""The vendor blocklist / reputation sites, and how to reach their report form.

kind:
  report  - the page is an actual "report a bad URL" form
  lookup  - the page is a reputation lookup; you look the URL up first, then
            click their dispute / request-change / feedback control
prefill:
  template with {url}, {qurl} (percent-encoded), {domain}. Loads the page with
  the URL already in it - zero typing needed.
note:
  what YOU still have to click after the tool parks the tab. Shown in the GUI.
"""

SITES = [
    dict(id="google", name="Google Safe Browsing", kind="report",
         url="https://safebrowsing.google.com/safebrowsing/report_phish/",
         prefill="https://safebrowsing.google.com/safebrowsing/report_phish/?url={qurl}",
         note="URL is pre-filled. Tick the CAPTCHA, click Submit Report."),

    dict(id="microsoft", name="Microsoft SmartScreen", kind="report",
         url="https://www.microsoft.com/en-us/wdsi/support/report-unsafe-site-guest",
         prefill="https://www.microsoft.com/en-us/wdsi/support/report-unsafe-site-guest?url={qurl}",
         note="Pick threat type 'Phishing', tick CAPTCHA, Submit."),

    dict(id="fortiguard", name="Fortiguard (Fortinet)", kind="lookup",
         url="https://www.fortiguard.com/webfilter", prefill=None,
         note="After the rating loads, click the pencil / 'Request Reclassification', "
              "pick Phishing, enter your email, Submit."),

    dict(id="brightcloud", name="BrightCloud (Webroot)", kind="lookup",
         url="https://www.brightcloud.com/tools/url-ip-lookup.php", prefill=None,
         note="Click 'Check URL', then 'Request a Reclassification' -> Phishing."),

    dict(id="crdf", name="CRDF Threat Center", kind="report",
         url="https://threatcenter.crdf.fr/submit_url.html", prefill=None,
         note="URL box is filled. Solve CAPTCHA, click Submit."),

    dict(id="netcraft", name="Netcraft", kind="report",
         url="https://report.netcraft.com/report", prefill=None,
         note="Already sent via their API by this tool - only use this tab if the API said SKIP/FAIL."),

    dict(id="paloalto", name="Palo Alto Networks URL Filtering", kind="lookup",
         url="https://urlfiltering.paloaltonetworks.com/", prefill=None,
         note="Search the URL, then 'Request Change' -> suggest category Phishing."),

    dict(id="eset", name="ESET", kind="report",
         url="https://phishing.eset.com/en-us/report", prefill=None,
         note="URL + your email filled. Tick CAPTCHA, Submit."),

    dict(id="trendmicro", name="Trend Micro Site Safety", kind="lookup",
         url="https://global.sitesafety.trendmicro.com/", prefill=None,
         note="Click Check, then 'Give Feedback' -> request category Disease Vector / Phishing."),

    dict(id="bitdefender", name="Bitdefender", kind="lookup",
         url="https://www.bitdefender.com/consumer/support/answer/29358/", prefill=None,
         note="This is Bitdefender's instructions page - no direct form. "
              "Follow it, or mail the URL to submit@bitdefender.com."),

    dict(id="mcafee", name="McAfee / Trellix SiteLookup", kind="lookup",
         url="https://sitelookup.mcafee.com/", prefill=None,
         note="Enter URL, Check URL, then 'Submit URL for review' with category Phishing."),

    dict(id="forcepoint", name="Forcepoint CSI", kind="lookup",
         url="https://csi.forcepoint.com/", prefill=None, skip=True,
         note="csi.forcepoint.com currently fails to resolve (broken DNS on Forcepoint's side, "
              "verified 2026-09-05). Off by default. Re-enable here if it comes back, or mail "
              "the URL to their support."),

    dict(id="symantec", name="Symantec / Broadcom Site Review", kind="lookup",
         url="https://sitereview.symantec.com/", prefill="https://sitereview.symantec.com/#/?search={qurl}",
         note="Accept their terms, look up, then 'Submit a Dispute' -> Phishing + your email."),

    dict(id="spam404", name="Spam404", kind="report",
         url="https://www.spam404.com/report.html", prefill=None,
         note="URL + email filled. Solve CAPTCHA, Submit."),

    dict(id="kaspersky", name="Kaspersky OpenTIP", kind="lookup",
         url="https://opentip.kaspersky.com/", prefill="https://opentip.kaspersky.com/{qurl}/?tab=lookup",
         note="Lookup is free; submitting a verdict needs a free Kaspersky account. "
              "Otherwise mail the URL to newvirus@kaspersky.com."),

    dict(id="talos", name="Cisco Talos", kind="lookup",
         url="https://talosintelligence.com/reputation_center/",
         prefill="https://talosintelligence.com/reputation_center/lookup?search={domain}",
         note="Check the reputation, then use the 'Submit a Dispute' / support link "
              "at talosintelligence.com/reputation_center/support."),
]

for _s in SITES:
    _s.setdefault("skip", False)   # skip=True: known broken, unchecked by default

BY_ID = {s["id"]: s for s in SITES}
