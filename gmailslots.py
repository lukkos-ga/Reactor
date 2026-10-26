"""Work out which Gmail account sits in which /u/N/ slot.

There is no way to read this without Google cookies, so detection runs in
reactor's own persistent browser profile. You sign into your Google accounts
in that window once, by hand - this tool never types a credential - and every
later detection reuses the session.

Everything it finds stays editable in Settings; detection is a starting point,
not an authority.
"""
import asyncio
import re
import os

from automate import PROFILE_DIR

MAX_SLOTS = 6
CLOSED_MSG = ("The browser window was closed before detection finished. Reopen it with "
              "Detect slots from Gmail, sign in, and leave the window alone until it "
              "reports the slots — or just type the numbers in by hand.")
EMAIL_RE = re.compile(r"[\w.+-]+@[\w.-]+\.\w+")

# Gmail publishes the signed-in address in a few places; try each.
READ_EMAIL_JS = """
() => {
  const out = [];
  if (document.title) out.push(document.title);
  const a = document.querySelector('a[aria-label*="Google Account"], [aria-label*="Google Account"]');
  if (a) out.push(a.getAttribute('aria-label') || '');
  const m = document.querySelector('meta[name="og-profile-acct"]');
  if (m) out.push(m.content || '');
  return out.join(' | ');
}
"""


def _pick(blob):
    hits = EMAIL_RE.findall(blob or "")
    return hits[0].lower() if hits else None


async def _detect(max_slots, on_status):
    from playwright.async_api import async_playwright

    found, seen = [], set()
    async with async_playwright() as pw:
        for f in ("SingletonLock", "SingletonCookie", "SingletonSocket"):
            try:
                os.unlink(os.path.join(PROFILE_DIR, f))
            except OSError:
                pass
        ctx = await pw.chromium.launch_persistent_context(
            PROFILE_DIR, headless=False, viewport={"width": 1180, "height": 860})
        page = await ctx.new_page()
        try:
            on_status("opening Gmail…")
            await page.goto("https://mail.google.com/mail/u/0/",
                            wait_until="domcontentloaded", timeout=60000)

            # Wait for a signed-in session. If they need to log in, that is their
            # keyboard, not ours - just keep waiting until an address shows up.
            on_status("waiting for you to be signed in to Google (sign in in the window)…")
            signed_in = False
            for _ in range(120):                      # up to ~4 minutes
                if page.is_closed():
                    return [], CLOSED_MSG
                try:
                    if _pick(await page.evaluate(READ_EMAIL_JS)):
                        signed_in = True
                        break
                    await page.wait_for_timeout(2000)
                except Exception:
                    return [], CLOSED_MSG
            if not signed_in:
                return [], ("Never saw a signed-in Gmail. Sign in inside that window and "
                            "run detection again, or just type the slot numbers by hand.")

            for n in range(max_slots):
                if page.is_closed():
                    break
                on_status(f"reading slot /u/{n}/…")
                try:
                    await page.goto(f"https://mail.google.com/mail/u/{n}/",
                                    wait_until="domcontentloaded", timeout=45000)
                except Exception:
                    break
                email = None
                for _ in range(15):                   # title settles a beat after load
                    email = _pick(await page.evaluate(READ_EMAIL_JS))
                    if email:
                        break
                    await page.wait_for_timeout(1000)
                if not email:
                    break
                if email in seen:
                    # Google bounced us to an existing account: this slot is empty,
                    # and every slot above it will be too.
                    break
                seen.add(email)
                found.append({"index": n, "email": email})
            return found, f"found {len(found)} account(s)"
        finally:
            try:
                await ctx.close()
            except Exception:
                pass


def detect(max_slots=MAX_SLOTS, on_status=lambda m: None):
    return asyncio.run(_detect(max_slots, on_status))


def merge(identities, detected):
    """Fold detected slots into the saved identities.

    Matching is on the base mailbox, so a +tag alias keeps the slot of the account
    that actually sends it - alice+abuse@gmail.com is delivered by the
    alice@gmail.com session. Anything not already saved is added.
    """
    from reactor import base_mailbox as base

    by_base = {base(d["email"]): d["index"] for d in detected}
    out, have = [], set()
    for i in identities:
        idx = by_base.get(base(i.get("email")))
        out.append({**i, "gmail_index": idx if idx is not None else i.get("gmail_index", 0),
                    "detected": idx is not None})
        have.add(base(i.get("email")))
    for d in detected:
        if base(d["email"]) not in have:
            out.append({"email": d["email"], "name": "A concerned internet user",
                        "gmail_index": d["index"], "detected": True})
    return out


def selftest():
    assert _pick("Inbox (3) - someone@gmail.com - Gmail") == "someone@gmail.com"
    assert _pick("Google Account: Bob (bob@gmail.com)") == "bob@gmail.com"
    assert _pick("Gmail") is None
    assert "closed" in CLOSED_MSG.lower()

    ids = [{"email": "bob+abuse@gmail.com", "gmail_index": 0, "name": "n"},
           {"email": "alice+abuse@gmail.com", "gmail_index": 1, "name": "n"}]
    det = [{"index": 0, "email": "alice@gmail.com"},
           {"index": 2, "email": "bob@gmail.com"},
           {"index": 3, "email": "someoneelse@gmail.com"}]
    m = merge(ids, det)
    got = {i["email"]: i["gmail_index"] for i in m}
    assert got["bob+abuse@gmail.com"] == 2, got
    assert got["alice+abuse@gmail.com"] == 0, got
    assert got["someoneelse@gmail.com"] == 3, "an account not saved yet should be offered"
    assert all(i["name"] for i in m), "existing names must survive a detection"

    # an account detection cannot see keeps whatever you typed, and says so
    m2 = merge([{"email": "work@corp.com", "gmail_index": 4, "name": "n"}], det)
    assert m2[0]["gmail_index"] == 4 and m2[0]["detected"] is False
    print("gmailslots selftest OK")


if __name__ == "__main__":
    selftest()
