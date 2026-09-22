# fuckscammer

Paste one phishing URL. It notifies every abuse desk that matters.

```bash
./run.sh
```

Opens the GUI at http://127.0.0.1:8420 (localhost only, never exposed to the network).

## Install

Requires Python 3 and Chromium via Playwright.

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
playwright install chromium
cp config.example.json config.json
./run.sh
```

Add your own API credentials in `config.json` or through the local Settings UI. `config.json` is ignored by Git. Never commit API keys, SMTP credentials, browser profiles, or generated reports.

## Paste the message, not the URL

Step 1 on the Report tab is a box you paste the whole scam SMS into. It:

- pulls out every link, including `hxxps://`, `[.]`, `(dot)`, `{.}` and spaced-out forms
- works out the spoofed brand from the **wording**, not the domain — scam domains are
  deliberately meaningless, but the text always says "WhatsApp" or "Telegram"
- names the scam signals it recognises (urgency, suspension threat, OTP fishing) so you can
  quote them in a report
- expands known shorteners only — an ordinary phishing link is never fetched
- greys out anything already in your history

Then check the ones you want and **Report all checked**: recon, blocklist APIs and complaint
drafts for each. Vendor forms stay one page at a time — use **Use as single target**.

## What one click does

| Stage | What happens | Automatic? |
|---|---|---|
| Recon | RDAP + DNS: registrar, registration date, hosting network, published abuse contacts | yes |
| Blocklist APIs | Netcraft, urlscan.io, VirusTotal | yes |
| Email complaints | Registrar, hosting/network, impersonated brand, APWG | drafts always; auto-sent if SMTP configured |
| Vendor forms | 15 vendors opened **in parallel** (5 at a time, ~16s), text filled, threat type/category selected, learned steps replayed | filled + classified; **Submit all** fires every CAPTCHA-free form |
| History | One case file per target — evidence for the ICANN follow-up | yes |

## Learning

While the tabs are open it records what you click and choose, per site, into
`recipes/<site>.json`. Next run replays those steps before handing the tab back to you,
so a form you drove by hand once is driven for you afterwards.

Recording is armed **only while a tab is yours**. The driver disarms it while it fills
forms itself, otherwise it learns its own autofill and the recipes fill with noise.

### It has to survive a change of victim brand

A recipe learned reporting a fake Telegram page gets replayed on a fake WhatsApp page.
Anything target-specific must therefore be re-derived, not replayed. Every recorded step
is tagged at save time:

| Tag | Example | On the next report |
|---|---|---|
| `threat` | "Phishing", "Malicious site" | replayed as-is — means the same thing every time |
| `brand` | "Telegram" | **re-picked** — the dropdown is searched for the new brand |
| `target` | "tegexyy.top" | re-derived from the new URL |
| `sticky` | "Financial services" | replayed, but flagged in the *Check these* column |

Free text is tokenized at substring level, so `Fake Telegram login at tegexyy.top` is stored
as `Fake {{brand}} login at {{domain}}` and re-renders as `Fake whatsapp login at fake-wa.xyz`.
A recipe that still contains the brand or domain it was learned on fails the selftest.

- Passwords are never recorded.
- Long unrecognised prose (>120 chars) is stored as `{{typed}}` — the field is remembered,
  the words are not. Short generic answers ("Credential harvesting") are kept, since they
  are what makes replay useful and contain nothing about you.
- A recorded Submit click is deliberately never replayed. Submitting stays an explicit press.
- History tab lists what's been learned, with a Forget button per site.

## Two-stage forms

Most vendors look the URL up first and only then show the threat-category form. One press
of **Submit all** advances one stage: the tool clicks, sees the new form, fills and classifies
it, and asks for another press. You watch each stage rather than blind-clicking a flow.

## Ground rules baked in

- **Never navigates to the phishing site.** The URL is only ever typed into other people's forms as text. Don't open it yourself either.
- **Never solves a CAPTCHA.** Sites guarded by one are detected at runtime and can only be submitted by your hand.
- **Nothing is submitted until you press Submit all**, behind a confirm dialog.
- **Never claims a report was filed unless the site confirmed it.** A confirmation phrase alone isn't enough — the submit control must also be gone. Anything less is logged as `verify it`, not `confirmed`.
- **Never accepts terms on your behalf** (Symantec gates on a ToS click — that one is yours).
- Browser runs in `.browser-profile/`, a throwaway profile. None of your real logins, cookies or history are visible to these sites.
- `config.json` holds API keys and the SMTP password, chmod 600.

## Vendor form status, measured 2026-09-05

Autofilled and parked: Google Safe Browsing, Microsoft SmartScreen, Fortiguard, BrightCloud,
CRDF, Netcraft, Palo Alto, ESET, Trend Micro, McAfee/Trellix, Spam404.

Opens but cannot be autofilled, for reasons the GUI spells out per tab:
- **Symantec** — blocks on a Terms of Service click first
- **Cisco Talos** — Cloudflare bot check
- **Kaspersky OpenTIP** — lookup is pre-filled by URL; submitting a verdict needs a free account
- **Bitdefender** — publishes instructions, not a form (mail `submit@bitdefender.com`)
- **Forcepoint CSI** — off by default, `csi.forcepoint.com` fails to resolve; re-enable in `sites.py` if it returns

## Reporting accounts

Settings holds a list of addresses you report from; the Report tab has a switcher. The
active one drives the vendor form fields, the `From:` on the complaint drafts, and which
Gmail composes the message.

The Gmail link picks the sending account by **address**, not by position:
`https://mail.google.com/mail/?authuser=<your address>&view=cm&...`

The `/u/N/` slot is a position in one browser's session list. If that position is empty,
Gmail silently drops you to `/u/0/` and you send from the wrong account — which is exactly
what happened here. An address cannot be wrong, so leave **Gmail slot** blank.

A plus-alias is reduced to its real mailbox for `authuser`, since `you+abuse@gmail.com` is
delivered by the `you@gmail.com` session and sends as it anyway.

**Gmail slot** remains as an optional override if you want to pin the `/u/N/` path. Blank
means select by address, which is what you want. **Detect slots from Gmail** still exists
for that case; it is no longer needed for normal use.

A page served from localhost cannot read your Gmail to work slots out on its own —
cross-origin isolation forbids it, which is why detection has to drive a separate browser.
Selecting by address sidesteps the whole problem.

SMTP stays global. If you set it and then switch identity, the GUI warns you that the SMTP
user no longer matches the From address — use the compose links rather than SMTP in that case.

## History

One case file per reported page: `reports/<host>/case.json`. The target is the useful
unit, not the run — you report the same URL over several sessions and later need to know
what went where, when, and whether it came down. Everything merges into that one file:
recon, blocklist API results, email drafts and whether you sent them, every vendor form
outcome, and takedown checks.

Written **as each result lands**, not at session end, so killing the browser or the server
loses nothing.

The History tab shows, per page: which APIs confirmed, how many vendor forms are confirmed
vs merely clicked, which emails you have ticked as sent, when the ICANN complaint window
opens (24h after first report), and a **Check if it is down** button.

### Status checks

**Check status** gathers five signals and never contacts the phishing site:

| Source | What it proves |
|---|---|
| Registry (RDAP) | `clientHold`/`serverHold` **is** the takedown — authoritative |
| DNS | still resolving? have the nameservers moved to a sinkhole? |
| urlscan.io | has anyone scanned it, and did the scan call it malicious (no key needed) |
| VirusTotal | how many engines flag it now (needs your free key) |

**Check + fetch the page** adds a sixth that *does* reach the site from your IP, behind a
confirm dialog. It is the only way to see a Cloudflare phishing interstitial or a dead
origin, and is off by default.

Verdicts:

- `down` — registry hold, or the hostname stopped resolving
- `blocked` — Cloudflare is warning visitors, or the origin is returning errors
- `live-flagged` — still up, but blocklists have caught it (victims now get warnings)
- `live` — up and not yet flagged anywhere
- `unknown` — not enough evidence

*Down* is only ever claimed on positive evidence. A failed lookup reads as unknown, never
as a takedown: being told a live phishing page is gone would stop you chasing it. Ordinary
EPP states like `clientTransferProhibited` are not holds.

Every check appends to the case file, so the History tab shows the state over time and the
moment it first went down.

### Live monitor

The Report tab carries a live status strip, refreshed every 10s. Turn on **keep checking
automatically** and the server re-checks every open case on a timer (default 15 min).
Cases that have gone `down` stop being polled — nothing left to learn.

**include a page fetch** adds the direct request that catches a Cloudflare interstitial or
a dead origin. It is the most useful signal and the only one that reaches the site from
your IP, on every sweep. Uncheck it if you would rather stay invisible.

The monitor restarts with the server when it is left on.

### How long a takedown takes

| Channel | Typical | Notes |
|---|---|---|
| Blocklists (Netcraft, Safe Browsing, SmartScreen) | hours to ~2 days | browser warnings; the site stays up but stops converting |
| Cloudflare | ~1–3 days | they do not host it; they forward to the origin and often add a phishing interstitial |
| Registrar suspension | days to weeks, sometimes never | ICANN RAA requires investigation within 24h of a report, but sets no removal deadline |

Median credential-phishing lifetime is a couple of days, with a long tail. The blocklists
are the leverage, not the registrar.

## Campaigns

History groups pages that look like one operator. Naive clustering would be worse than
none — nearly every phishing site is behind Cloudflare, so "shared nameserver" would put
every case in one bucket. Signals from shared infrastructure (Cloudflare, AWS, the big
registrars' DNS) are discounted, and every link shows the evidence that drew it so you can
throw it out. A group yields one combined registrar complaint: a pattern of abuse across
several domains is far stronger than the same report filed separately.

## Certificate transparency watch

Every TLS certificate is published to public CT logs within minutes of issue, so a
lookalike domain appears there while the scammer is still setting it up — before any SMS
goes out. The Report tab watches crt.sh for the brands you list.

Scoring is deliberately strict, because `%telegram%` matches thousands of harmless names.
A bare keyword scores **zero**. Points come from phishing vocabulary sitting in the same
DNS label as the brand (the strong signal), a throwaway TLD, hyphens and digits padding
the brand, and free hosting. Three earlier versions of this scoring were thrown out:

- weighting free hosting heavily buried real hits under every legitimate Telegram bot on
  `workers.dev`
- treating `web`, `app` and `support` as phishing words matched every legitimate mini-app
- scoring the whole certificate name let hyphens far from the brand inflate the score
- issue age is **not** scored: nearly every row crt.sh returns is recent, so it added a
  constant point to everything and just moved the scale

Free-hosting tenants (`*.workers.dev`, `*.pages.dev`, `*.hosted.app`) report as the full
hostname. An earlier version reduced them to a registrable domain and would have had you
reporting `pages.dev` — Cloudflare's own domain — instead of the scammer. That fix landed
in the core `registrable_domain`, so it applies to the whole tool, not just this watch.

crt.sh rate-limits and returns 502s often. A failed query is reported as a failed query,
never as "nothing found".

## Desktop notifications

macOS notifications when something actually changes: a site becomes blocked, gets picked up
by blocklists, goes down, comes back up, or a new lookalike certificate appears. Also once,
when a case's ICANN window closes and the complaint becomes fileable. No notification for
"still the same" — only transitions worth interrupting you for.

## Clipboard watch

Toggle on the Report tab. Copy a link out of Messages and a chip appears with the target
already parsed. Off by default and explicitly opt-in — it reads your clipboard while on.
Only extracted URLs are kept; the clipboard text is never stored, logged, or sent anywhere.

## Evidence

When urlscan has a scan on file, its screenshot and report land in the case file
automatically. That gives a registrar complaint a picture of the page without you ever
loading it.

## ICANN escalation

Each case has an **ICANN escalation** button that assembles the complaint from what
actually happened: when you first reported, when the registrar's abuse address was
emailed, every blocklist and vendor confirmation, and the check-by-check timeline proving
the domain stayed up.

It refuses to pretend you are ready when you are not, and says exactly what is missing:

- the registrar was never emailed, or you have not ticked it as sent
- the registrar's 24h window is still open
- the domain is already suspended, so there is nothing to escalate

ICANN enforces the registrar's RAA 3.18 duty to investigate; without a documented,
ignored report there is nothing for them to act on.

## Evidence bundle

Each case has an **Evidence bundle** button that writes
`reports/<host>/<host>-evidence-<timestamp>.zip`:

| File | What it is |
|---|---|
| `report.html` | printable summary — target, who was told and when, vendor outcomes, full timeline, current position |
| `checks.csv` | every status check, machine readable, including whether the page itself was fetched |
| `case.json` | complete raw record |
| `screenshot.png` | the phishing page as urlscan captured it — you never loaded it |
| `emails/*.eml` | the complaints sent to each abuse contact |

The report never presents *blocked* as *removed*: when the host is merely warning
visitors it says so explicitly, because a registrar reading it needs to know the domain is
still registered and resolving.

Downloads are served only from `reports/`, only for `.zip` files, with path traversal
rejected.

## Local reporting channels

Set your country in Settings and its national channels join every report. Malaysia is
wired in, each entry recording how it was checked, because government portals move:

| Channel | How | When |
|---|---|---|
| MyCERT Cyber999 — `mycert.org.my/cyber999` | web form + `cyber999@cybersecurity.my` | always — the national CERT, and it coordinates takedowns |
| MCMC — `aduan.mcmc.gov.my` | web form | always, and it is the only channel for the spoofed SMS itself |
| PDRM Semak Mule — `semakmule.rmp.gov.my` | web form | when the scam gave you an account or phone number |
| NSRC — `997` | phone | **only if money was actually transferred** — call at once |
| Cyber999 hotline — `1-300-88-2999` | phone | if you would rather talk than fill a form |

Verified live: the MyCERT, MCMC and Semak Mule pages all return HTTP 200, and
`cybersecurity.my` accepts mail. `aduan.skmm.gov.my` redirects to the MCMC portal.
`nsrc.gov.my`, `ecrs.rmp.gov.my` and `aduan.cybersecurity.my` did **not** resolve, so
they are deliberately not listed.

The CERT matters more than it looks: it can lean on a host and a registrar with standing
an individual reporter does not have.

Adding another country means one entry in `channels.py` — nothing else is country-aware.

## Order of attack

1. **Cloudflare / the host first** if the site is proxied — they reach the real origin fastest.
2. **Registrar** second (`complaint@...`), citing ICANN RAA 2013 §3.18.
3. **ICANN last, and only after 24h of registrar silence.** ICANN is not a takedown channel; they enforce the registrar's duty to respond. The History tab is your evidence.

## Files

- `server.py` — GUI + local API
- `ui.html` — the interface
- `fuckscammer.py` — recon, blocklist APIs, complaint emails (also usable standalone: `python3 fuckscammer.py <url> --send`)
- `automate.py` — Playwright driver, field classifier
- `sites.py` — the vendor list and what you must click on each
- `reports/` — `.eml` drafts, `runs.jsonl`, `log.jsonl`

Self-checks: `python3 fuckscammer.py --selftest` and `python3 automate.py`.
