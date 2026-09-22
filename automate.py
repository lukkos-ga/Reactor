"""Playwright driver.

Per site, in parallel (5 at a time):
  1. open the report page, decline cookies
  2. fill text fields (URL / email / name / comment)
  3. pick threat-type dropdowns and radios ("Phishing", "Fraud", "Malicious"...)
  4. replay anything you taught it on a previous run (recipes/<site>.json)
  5. detect whether a CAPTCHA guards the form
  6. STOP. Nothing is submitted until you press Submit all.

While tabs are open it records what you click and choose, so next run does it
for you. Passwords are never recorded; your text is stored as {{url}}-style
tokens, never raw.

It never navigates to the phishing site. Runs in a throwaway profile.
"""
import asyncio
import json
import os
import re
from datetime import datetime, timezone

from sites import SITES

HERE = os.path.dirname(os.path.abspath(__file__))
PROFILE_DIR = os.path.join(HERE, ".browser-profile")
RECIPES_DIR = os.path.join(HERE, "recipes")
LOG_PATH = os.path.join(HERE, "reports", "log.jsonl")
RECORDER_JS = os.path.join(HERE, "recorder.js")
MAX_PARALLEL = 5

# ---- field classification -------------------------------------------------
PATTERNS = [
    ("email",   re.compile(r"e-?mail|contact", re.I)),
    ("url",     re.compile(r"\burl\b|website|web site|\bsite\b|address|domain|link|search|query|\bq\b", re.I)),
    ("comment", re.compile(r"comment|descri|detail|message|reason|note|additional|explain|remark", re.I)),
    ("name",    re.compile(r"(^|[^a-z])name([^a-z]|$)|full.?name|your.?name", re.I)),
]
SKIP_PAT = re.compile(r"captcha|password|card|phone|subscribe|newsletter", re.I)

# ---- threat type / category, best choice first ----------------------------
THREAT_WORDS = [
    r"phish", r"credential.?(theft|harvest)", r"deceptive", r"fraud", r"scam",
    r"spoof", r"impersonat", r"malicious", r"\bmalware\b", r"security risk",
    r"suspicious", r"spam", r"compromis",
]
THREAT_RE = [re.compile(w, re.I) for w in THREAT_WORDS]
NEGATIVE_RE = re.compile(r"not |false positive|clean|safe|benign|remove|unblock|legitimate|dispute this", re.I)

CAPTCHA_JS = """
() => {
  const sels = ['iframe[src*="recaptcha"]','iframe[src*="hcaptcha"]','iframe[src*="turnstile"]',
                'iframe[title*="captcha" i]','.g-recaptcha','.h-captcha','[data-sitekey]','#captcha',
                'img[src*="captcha" i]','input[name*="captcha" i]'];
  return sels.some(s => { const e = document.querySelector(s);
    return e && (e.offsetParent !== null || e.tagName === 'IFRAME'); });
}
"""

COLLECT_JS = """
() => Array.from(document.querySelectorAll('input, textarea')).map((el, i) => {
  const r = el.getBoundingClientRect();
  let label = '';
  if (el.labels) for (const l of el.labels) label += ' ' + (l.innerText || '');
  if (el.id) { const fl = document.querySelector(`label[for="${CSS.escape(el.id)}"]`);
               if (fl) label += ' ' + (fl.innerText || ''); }
  const p = el.closest('label, .form-group, .field, td, li, div');
  return { i, type: (el.type || el.tagName).toLowerCase(),
    visible: r.width > 0 && r.height > 0 && el.offsetParent !== null,
    disabled: el.disabled || el.readOnly, filled: !!el.value,
    sig: [el.name, el.id, el.placeholder, el.getAttribute('aria-label'),
          el.getAttribute('title'), label, p ? (p.innerText||'').slice(0,120) : ''
         ].filter(Boolean).join(' ') };
})
"""

# Every <select> with its option texts, and every radio with its label.
CHOICES_JS = """
() => {
  const out = {selects: [], radios: []};
  document.querySelectorAll('select').forEach((el, i) => {
    const r = el.getBoundingClientRect();
    if (!(r.width > 0 && r.height > 0) || el.disabled) return;
    out.selects.push({ i, name: el.name || el.id || '',
      chosen: el.selectedIndex,
      options: Array.from(el.options).map(o => ({v: o.value, t: (o.text||'').trim()})) });
  });
  document.querySelectorAll('input[type=radio]').forEach((el, i) => {
    const r = el.getBoundingClientRect();
    if (!(r.width > 0 && r.height > 0) || el.disabled) return;
    let label = '';
    if (el.labels) for (const l of el.labels) label += ' ' + (l.innerText || '');
    const p = el.closest('label, .form-check, .radio, li, td, div');
    out.radios.push({ i, group: el.name || '', checked: el.checked,
      text: [label, el.value, el.getAttribute('aria-label'),
             p ? (p.innerText||'').slice(0,80) : ''].filter(Boolean).join(' ').trim() });
  });
  return out;
}
"""

HARVEST_JS = "() => { try { return JSON.parse(sessionStorage.getItem('__fsrec') || '[]'); } catch(e) { return []; } }"

SUBMIT_SELECTORS = [
    "button[type=submit]", "input[type=submit]",
    "button:has-text('Submit Report')", "button:has-text('Send Report')",
    "button:has-text('Submit')", "button:has-text('Send')",
    "button:has-text('Report')",
    # lookup-first vendors: the first button advances to the report form
    "button:has-text('Check')", "button:has-text('Look up')", "button:has-text('Lookup')",
    "button:has-text('Search')", "a[role=button]:has-text('Submit')",
]

DECLINE_COOKIES = [
    "button:has-text('Reject all')", "button:has-text('Reject All')",
    "button:has-text('Decline')", "button:has-text('Only necessary')",
    "button:has-text('Necessary only')", "button:has-text('Deny')",
    "#onetrust-reject-all-handler", ".ot-pc-refuse-all-handler",
]


def classify(field):
    if field["disabled"] or not field["visible"] or field["filled"]:
        return None
    if field["type"] in ("hidden", "submit", "button", "checkbox", "radio", "file", "password"):
        return None
    sig = field["sig"]
    if SKIP_PAT.search(sig):
        return None
    if field["type"] == "email":
        return "email"
    if field["type"] == "textarea" and not sig.strip():
        return "comment"
    for kind, pat in PATTERNS:
        if pat.search(sig):
            return kind
    return "comment" if field["type"] == "textarea" else None


def best_threat_option(texts):
    """Index of the option that best means 'this is phishing'. None if no match."""
    best, best_rank = None, len(THREAT_RE)
    for idx, t in enumerate(texts):
        if not t or NEGATIVE_RE.search(t):
            continue
        for rank, pat in enumerate(THREAT_RE):
            if pat.search(t) and rank < best_rank:
                best, best_rank = idx, rank
                break
    return best


# ---- recipes --------------------------------------------------------------

def recipe_path(site_id):
    return os.path.join(RECIPES_DIR, f"{site_id}.json")


def load_recipe(site_id):
    p = recipe_path(site_id)
    if not os.path.exists(p):
        return []
    try:
        return json.load(open(p)).get("steps", [])
    except Exception:
        return []


def tokenize(value, values):
    """Strip anything target-specific out of recorded text and leave a token.

    Substring-level, not whole-value: a free-text answer like
    "Fake Telegram login at tegexyy.top" becomes
    "Fake {{brand}} login at {{domain}}" so it re-renders correctly for the next
    victim brand instead of naming the wrong company."""
    if not isinstance(value, str) or not value.strip():
        return value
    out = value
    if values.get("comment") and out.strip() == str(values["comment"]).strip():
        return "{{comment}}"
    # Longest actual value first, so the URL is tokenized before its own domain.
    for kind in sorted(("url", "email", "comment", "name", "brand", "domain"),
                       key=lambda k: -len(str(values.get(k) or ""))):
        actual = str(values.get(kind) or "")
        if len(actual) >= 3:
            out = re.sub(re.escape(actual), "{{%s}}" % kind, out, flags=re.I)
    if "{{" not in out and len(out) > 120:
        return "{{typed}}"   # long unrecognised prose: remember the field, forget the words
    return out


def detokenize(value, values):
    if not isinstance(value, str):
        return value
    if value == "{{typed}}":
        return values.get("comment", "")
    for kind in ("url", "email", "comment", "name", "brand", "domain"):
        value = value.replace("{{%s}}" % kind, str(values.get(kind) or ""))
    return value


def generalizes_as(text, values):
    """How should a recorded menu/radio choice carry over to the NEXT report?

    threat  - "Phishing", "Malicious" - means the same thing every time, replay it
    brand   - names the impersonated company - must be re-picked for the new brand
    target  - names this URL/domain - must be re-derived
    sticky  - unrecognised - replay it, but flag it for your glance
    """
    t = (text or "").strip()
    if not t:
        return "sticky"
    low = t.lower()
    for kind in ("url", "domain", "email"):
        v = str(values.get(kind) or "")
        if len(v) >= 4 and v.lower() in low:
            return "target"
    brand = str(values.get("brand") or "")
    if len(brand) >= 3 and brand.lower() in low:
        return "brand"
    if not NEGATIVE_RE.search(t) and any(p.search(t) for p in THREAT_RE):
        return "threat"
    return "sticky"


def save_recipe(site_id, steps, values):
    if not steps:
        return 0
    os.makedirs(RECIPES_DIR, exist_ok=True)
    clean, seen = [], set()
    for s in steps:
        act = s.get("act")
        if act == "fill":
            s = {**s, "value": tokenize(s.get("value"), values),
                 "gen": generalizes_as(s.get("value"), values)}
        elif act in ("select", "check"):
            s = {**s, "gen": generalizes_as(s.get("text"), values),
                 "text": tokenize(s.get("text"), values)}
        key = (act, s.get("sel"), str(s.get("value")), str(s.get("checked")))
        if key in seen:
            continue
        seen.add(key)
        clean.append(s)
    json.dump({"site": site_id, "updated": datetime.now(timezone.utc).isoformat(),
               "learned_from_brand": values.get("brand") or None,
               "steps": clean}, open(recipe_path(site_id), "w"), indent=2)
    return len(clean)


async def pick_option_matching(loc, wanted):
    """Choose the <select> option whose visible text mentions `wanted`."""
    try:
        opts = await loc.evaluate("el => Array.from(el.options).map(o => [o.value, o.text])")
    except Exception:
        return None
    for value, text in opts:
        if wanted.lower() in (text or "").lower():
            await loc.select_option(value=value, timeout=2500)
            return text
    return None


async def replay(page, steps, values):
    """Replay learned steps, but re-derive anything that was specific to the last
    target. Returns (steps_applied, flags) - flags are things you should eyeball."""
    done, flags = 0, []
    for st in steps:
        gen = st.get("gen", "sticky")
        try:
            loc = page.locator(st["sel"]).first
            if not await loc.is_visible(timeout=1200):
                continue
            act = st.get("act")

            if act == "fill":
                await loc.fill(detokenize(st.get("value", ""), values), timeout=2500)

            elif act == "select":
                if gen == "threat":
                    await loc.select_option(value=st.get("value"), timeout=2500)
                elif gen in ("brand", "target"):
                    wanted = values.get("brand" if gen == "brand" else "domain") or ""
                    hit = await pick_option_matching(loc, wanted) if wanted else None
                    if not hit:
                        flags.append(f"{gen} dropdown: no option for '{wanted}', left untouched")
                        continue
                else:
                    await loc.select_option(value=st.get("value"), timeout=2500)
                    flags.append(f"reused your old answer '{(st.get('text') or '')[:32]}' - check it")

            elif act == "check":
                if gen in ("brand", "target"):
                    flags.append(f"skipped a {gen}-specific choice you made last time - set it yourself")
                    continue
                if st.get("checked", True):
                    await loc.check(timeout=2500)
                if gen == "sticky":
                    flags.append(f"reused your old choice '{(st.get('text') or '')[:32]}' - check it")

            elif act == "click":
                if re.search(r"submit|send|report now", st.get("text", ""), re.I):
                    continue  # replaying a submit is the one thing we never do here
                await loc.click(timeout=2500)
            else:
                continue

            done += 1
            await page.wait_for_timeout(250)
        except Exception:
            continue
    return done, flags


# ---- page work ------------------------------------------------------------

async def recording(page, on):
    """Recorder is armed only while the tab belongs to you."""
    try:
        await page.evaluate(f"() => {{ window.__fsrec_on = {'true' if on else 'false'}; }}")
    except Exception:
        pass


async def decline_cookies(page):
    for sel in DECLINE_COOKIES:
        try:
            btn = page.locator(sel).first
            if await btn.is_visible(timeout=350):
                await btn.click(timeout=1500)
                return
        except Exception:
            pass


async def fill_text(page, values):
    try:
        fields = await page.evaluate(COLLECT_JS)
    except Exception:
        return []
    boxes = page.locator("input, textarea")
    done, used = [], set()
    for f in fields:
        kind = classify(f)
        if not kind or kind in used or not values.get(kind):
            continue
        try:
            await boxes.nth(f["i"]).fill(values[kind], timeout=3000)
            used.add(kind)
            done.append(kind)
        except Exception:
            continue
    return done


async def pick_threats(page):
    """Set every dropdown / radio group that looks like a threat classifier."""
    picked = []
    try:
        ch = await page.evaluate(CHOICES_JS)
    except Exception:
        return picked
    selects = page.locator("select")
    for s in ch["selects"]:
        idx = best_threat_option([o["t"] for o in s["options"]])
        if idx is None or idx == s["chosen"]:
            continue
        try:
            await selects.nth(s["i"]).select_option(value=s["options"][idx]["v"], timeout=2500)
            picked.append(f"{s['name'] or 'dropdown'}={s['options'][idx]['t']}")
        except Exception:
            continue
    radios = page.locator("input[type=radio]")
    by_group, seen_groups = {}, set()
    for r in ch["radios"]:
        by_group.setdefault(r["group"], []).append(r)
    for group, members in by_group.items():
        if group in seen_groups or any(m["checked"] for m in members):
            continue
        idx = best_threat_option([m["text"] for m in members])
        if idx is None:
            continue
        try:
            await radios.nth(members[idx]["i"]).check(timeout=2500)
            picked.append(f"{group or 'radio'}={members[idx]['text'][:32]}")
            seen_groups.add(group)
        except Exception:
            continue
    return picked


async def has_captcha(page):
    try:
        return bool(await page.evaluate(CAPTCHA_JS))
    except Exception:
        return True  # can't tell -> assume yes, never auto-submit blind


async def find_submit(page):
    """A backgrounded tab reports differently than a fronted one, so anything that
    is about to be clicked gets fronted first."""
    for sel in SUBMIT_SELECTORS:
        try:
            loc = page.locator(sel).first
            if await loc.count() and await loc.is_visible(timeout=800):
                return loc
        except Exception:
            continue
    return None


def expand(template, url):
    import urllib.parse
    p = urllib.parse.urlparse(url)
    return template.format(url=url, qurl=urllib.parse.quote(url, safe=""),
                           domain=p.hostname or url)


async def prepare(ctx, site, url, values, recorder_src, sem, entry_cb):
    entry = {"site": site["id"], "name": site["name"], "kind": site["kind"],
             "filled": [], "picked": [], "replayed": 0, "captcha": None,
             "can_autosubmit": False, "submitted": False, "verified": False,
             "stage": 1, "flags": [], "status": "opening",
             "note": site["note"], "ts": datetime.now(timezone.utc).isoformat(),
             "reported_url": url, "recipe_steps": len(load_recipe(site["id"]))}
    page = None
    async with sem:
        try:
            page = await ctx.new_page()
            await page.add_init_script(recorder_src)
            target = expand(site["prefill"], url) if site["prefill"] else site["url"]
            entry["opened"] = target
            await page.goto(target, wait_until="domcontentloaded", timeout=45000)
            await recording(page, False)
            await decline_cookies(page)
            await page.wait_for_timeout(1500)

            entry["filled"] = await fill_text(page, values)
            if not entry["filled"]:
                # SPA sites paint their inputs late. One patient rescan.
                await page.wait_for_timeout(4000)
                await decline_cookies(page)
                entry["filled"] = await fill_text(page, values)

            entry["picked"] = await pick_threats(page)
            entry["replayed"], entry["flags"] = await replay(page, load_recipe(site["id"]), values)
            if entry["replayed"]:
                entry["picked"] += await pick_threats(page)   # recipe may reveal new fields
                if not entry["filled"]:
                    entry["filled"] = await fill_text(page, values)

            entry["captcha"] = await has_captcha(page)
            entry["can_autosubmit"] = (not entry["captcha"]) and bool(await find_submit(page))
            bits = []
            if entry["filled"]:
                bits.append("filled " + "+".join(entry["filled"]))
            if entry["picked"]:
                bits.append(f"{len(entry['picked'])} choice(s)")
            if entry["replayed"]:
                bits.append(f"{entry['replayed']} learned step(s)")
            if entry["flags"]:
                bits.append(f"{len(entry['flags'])} need your eye")
            entry["status"] = ", ".join(bits) or "opened, nothing to autofill"
            await recording(page, True)   # tab is yours from here; watch and learn
            if entry["captcha"]:
                entry["status"] += " — CAPTCHA, you must submit"
            elif entry["can_autosubmit"]:
                entry["status"] += " — ready to auto-submit"
        except Exception as e:
            entry["status"] = f"FAILED: {type(e).__name__}: {str(e)[:110]}"
    entry_cb(entry)
    return page, entry


# Deliberately narrow. A loose pattern matched Symantec's boilerplate and claimed a
# report was filed when none was - a false "submitted" poisons the evidence log, so a
# phrase alone is never enough: the submit control must also be gone.
DONE_RE = re.compile(r"thank you for (your |the )?(report|submission|feedback)|"
                     r"(report|submission|request|url)[^.]{0,40}(has been|was) (received|submitted|sent)|"
                     r"we have received your|successfully submitted|submission (was )?successful",
                     re.I)


async def submit_one(page, entry, values):
    """One click per press. Many vendors are two-stage (look up, THEN classify and
    report), so if the click reveals a fresh form we fill that too and ask for
    another press rather than blind-clicking through a flow we cannot see."""
    if entry["captcha"]:
        entry["status"] = "skipped — CAPTCHA needs you"
        return entry
    try:
        await page.bring_to_front()
        await page.wait_for_timeout(300)
    except Exception:
        pass
    btn = await find_submit(page)
    if not btn:
        entry["status"] = "skipped — no submit button found, do it by hand"
        return entry
    before = page.url
    try:
        await recording(page, False)
        await btn.click(timeout=6000)
        await page.wait_for_timeout(4000)
        await recording(page, False)   # navigation re-armed it; this is still our turn
        body = ""
        try:
            body = (await page.inner_text("body"))[:2500]
        except Exception:
            pass

        gone = await find_submit(page) is None
        if gone:
            await recording(page, True)
        if DONE_RE.search(body) and gone:
            entry["submitted"] = entry["verified"] = True
            entry["status"] = f"SUBMITTED — confirmed by the site (stage {entry['stage']})"
            return entry
        if gone and page.url != before:
            entry["submitted"] = True
            entry["status"] = "clicked, form closed and page moved — probably filed, verify in the tab"
            return entry

        # No confirmation. Did a new stage of the form appear?
        entry["stage"] += 1
        entry["filled"] = await fill_text(page, values) or entry["filled"]
        newly = await pick_threats(page)
        entry["picked"] = list(dict.fromkeys(entry["picked"] + newly))
        entry["captcha"] = await has_captcha(page)
        entry["can_autosubmit"] = (not entry["captcha"]) and bool(await find_submit(page))
        await recording(page, True)

        if entry["can_autosubmit"] and (newly or page.url != before):
            bits = f"stage {entry['stage']} ready"
            if newly:
                bits += " — picked " + "; ".join(newly)
            entry["status"] = bits + " — press Submit all again"
        elif entry["captcha"]:
            entry["status"] = f"stage {entry['stage']} — CAPTCHA appeared, finish it yourself"
        else:
            entry["submitted"] = True
            entry["status"] = ("clicked, page advanced but no confirmation — verify in the tab"
                               if page.url != before else
                               "clicked, nothing visibly changed — verify in the tab")
    except Exception as e:
        entry["status"] = f"submit failed: {type(e).__name__}: {str(e)[:80]}"
    return entry


async def open_all(url, values, site_ids=None, headless=False,
                   stop_event=None, submit_event=None, on_result=None, learn=True):
    from playwright.async_api import async_playwright

    chosen = [s for s in SITES if (s["id"] in site_ids if site_ids else not s.get("skip"))]
    recorder_src = open(RECORDER_JS).read() if learn and os.path.exists(RECORDER_JS) else ""
    os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
    entries, pages = {}, {}

    def publish(e):
        entries[e["site"]] = e
        # ponytail: append-on-change, not a bulk write at the end. A killed session
        # used to lose every result it had already produced.
        try:
            with open(LOG_PATH, "a") as f:
                f.write(json.dumps(e) + "\n")
        except Exception:
            pass
        if on_result:
            on_result(dict(e))

    async with async_playwright() as pw:
        async def launch():
            return await pw.chromium.launch_persistent_context(
                PROFILE_DIR, headless=headless, viewport={"width": 1280, "height": 900},
                args=["--disable-blink-features=AutomationControlled"])
        try:
            ctx = await launch()
        except Exception:
            # ponytail: a crashed run leaves Singleton* lock files that make the next
            # launch fail with a useless "already in use". Clear them and try once more.
            for f in ("SingletonLock", "SingletonCookie", "SingletonSocket"):
                try:
                    os.unlink(os.path.join(PROFILE_DIR, f))
                except OSError:
                    pass
            ctx = await launch()
        sem = asyncio.Semaphore(MAX_PARALLEL)
        done = await asyncio.gather(*[
            prepare(ctx, s, url, values, recorder_src, sem, publish) for s in chosen],
            return_exceptions=True)
        for res in done:
            if isinstance(res, tuple):
                page, entry = res
                if page:
                    pages[entry["site"]] = page

        ready = [e for e in entries.values() if e["can_autosubmit"]]
        print(f"\n{len(entries)} tabs prepared in parallel. "
              f"{len(ready)} can be auto-submitted, the rest need your hands.")
        for e in entries.values():
            print(f"  [{e['status'][:52]:<52}] {e['name']}")

        async def harvest():
            saved = 0
            for sid, page in list(pages.items()):
                try:
                    steps = await page.evaluate(HARVEST_JS)
                except Exception:
                    continue
                n = save_recipe(sid, steps, values)
                if n and entries.get(sid, {}).get("learned") != n:
                    entries[sid]["learned"] = n
                    publish(entries[sid])
                    saved += n
            return saved

        if stop_event is not None:
            ticks = 0
            while not stop_event.is_set():
                ticks += 1
                if learn and ticks % 40 == 0:      # ~every 16s, so a kill loses little
                    await harvest()
                if submit_event is not None and submit_event.is_set():
                    submit_event.clear()
                    for sid, page in list(pages.items()):
                        e = entries.get(sid)
                        if not e or e.get("submitted"):
                            continue
                        publish(await submit_one(page, e, values))
                await asyncio.sleep(0.4)
        else:
            input("\nPress Enter to submit every CAPTCHA-free tab, or Ctrl-C to bail: ")
            for sid, page in list(pages.items()):
                publish(await submit_one(page, entries[sid], values))
            input("Finish the CAPTCHA tabs by hand, then press Enter to close: ")

        if learn:
            await harvest()

        await ctx.close()
    return list(entries.values())


def run(url, values, site_ids=None, headless=False, stop_event=None,
        submit_event=None, on_result=None, learn=True):
    return asyncio.run(open_all(url, values, site_ids, headless, stop_event,
                                submit_event, on_result, learn))


def selftest():
    assert classify({"type": "text", "visible": True, "disabled": False, "filled": False,
                     "sig": "Enter the phishing URL", "i": 0}) == "url"
    assert classify({"type": "text", "visible": True, "disabled": False, "filled": True,
                     "sig": "url", "i": 0}) is None
    assert classify({"type": "text", "visible": True, "disabled": False, "filled": False,
                     "sig": "captcha code", "i": 0}) is None
    # threat picking: phishing beats generic, negatives never win
    assert best_threat_option(["Select one", "Spam", "Phishing", "Malware"]) == 2
    assert best_threat_option(["Select", "This is NOT phishing", "Fraud"]) == 2
    assert best_threat_option(["Blue", "Green"]) is None
    assert best_threat_option(["Select a category", "Malicious Site"]) == 1
    assert DONE_RE.search("Thank you for your submission")
    assert DONE_RE.search("Your report has been received")
    assert not DONE_RE.search("Please complete the form below")
    assert not DONE_RE.search("Terms of Service. Categories submitted by users are reviewed."), \
        "boilerplate containing 'submitted' must not read as a confirmation"
    # --- cross-brand transfer: what is learned on Telegram must not misfire on WhatsApp
    tg = {"url": "https://www.tegexyy.top/", "domain": "tegexyy.top", "brand": "telegram",
          "email": "me@x.com", "name": "Reporter", "comment": "Phishing site."}
    wa = {"url": "https://fake-wa.xyz/login", "domain": "fake-wa.xyz", "brand": "whatsapp",
          "email": "me@x.com", "name": "Reporter", "comment": "Phishing site."}

    assert tokenize("https://www.tegexyy.top/", tg) == "{{url}}"
    got = tokenize("Fake Telegram login at tegexyy.top", tg)
    assert got == "Fake {{brand}} login at {{domain}}", got
    out = detokenize(got, wa)
    assert out == "Fake whatsapp login at fake-wa.xyz", out
    assert "telegram" not in out.lower() and "tegexyy" not in out.lower(), \
        "last target's brand/domain leaked into the next report"
    assert tokenize("x" * 130, tg) == "{{typed}}", "long unrecognised prose must not be stored raw"
    assert tokenize("Credential harvesting", tg) == "Credential harvesting", \
        "short generic answers stay usable"

    assert generalizes_as("Phishing", tg) == "threat"
    assert generalizes_as("Telegram", tg) == "brand"
    assert generalizes_as("tegexyy.top", tg) == "target"
    assert generalizes_as("Financial services", tg) == "sticky"
    assert generalizes_as("This is not phishing", tg) == "sticky", "negatives are never a threat pick"

    import tempfile
    global RECIPES_DIR
    keep = RECIPES_DIR
    RECIPES_DIR = tempfile.mkdtemp()
    try:
        save_recipe("t", [
            {"act": "fill", "sel": "#u", "value": "https://www.tegexyy.top/"},
            {"act": "fill", "sel": "#c", "value": "Fake Telegram login at tegexyy.top"},
            {"act": "select", "sel": "#cat", "value": "ph", "text": "Phishing"},
            {"act": "select", "sel": "#brand", "value": "tg", "text": "Telegram"},
            {"act": "check", "sel": "#r1", "checked": True, "text": "Credential phishing"},
        ], tg)
        steps = load_recipe("t")
        by = {x["sel"]: x for x in steps}
        assert by["#u"]["value"] == "{{url}}"
        assert by["#c"]["value"] == "Fake {{brand}} login at {{domain}}"
        assert by["#cat"]["gen"] == "threat",  "threat category must replay verbatim"
        assert by["#brand"]["gen"] == "brand", "brand dropdown must be re-picked, not replayed"
        assert by["#r1"]["gen"] == "threat"
        blob = json.dumps(steps).lower()
        assert "telegram" not in blob and "tegexyy" not in blob, \
            "recipe still hard-codes the brand/domain it was learned on: " + blob
    finally:
        RECIPES_DIR = keep
    assert expand("https://x/?u={qurl}&d={domain}", "https://www.bad.top/a?b=1") == \
        "https://x/?u=https%3A%2F%2Fwww.bad.top%2Fa%3Fb%3D1&d=www.bad.top"
    print("automate selftest OK")


if __name__ == "__main__":
    selftest()
