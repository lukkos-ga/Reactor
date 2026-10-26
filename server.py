#!/usr/bin/env python3
"""Local GUI for reactor. Serves http://127.0.0.1:8420 - localhost only,
nothing is exposed to the network.

    ./run.sh          (or:  .venv/bin/python server.py)

Pipeline the GUI drives, in order:
  1. recon      - RDAP + DNS, finds registrar / host abuse contacts
  2. APIs       - Netcraft, urlscan, VirusTotal, PhishStats (no browser needed)
  3. emails     - writes .eml complaints, optionally sends them over SMTP
  4. browser    - opens the 16 vendor forms in tabs, pre-filled, parked at the
                  CAPTCHA for you to submit
"""
import json
import os
import socket
import threading
import urllib.parse
import webbrowser
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import automate
import bundle
import campaigns
import casefile
import channels
import ctwatch
import escalate
import gmailslots
import intake
import notify
import status
import reactor as fs
from sites import SITES

HERE = os.path.dirname(os.path.abspath(__file__))
CONFIG = os.path.join(HERE, "config.json")
REPORTS = os.path.join(HERE, "reports")
RUNS_LOG = os.path.join(REPORTS, "runs.jsonl")
PORT = 8420

DEFAULT_CONFIG = {
    "reporter_email": "you+abuse@example.com",
    "reporter_name": "A concerned internet user",
    "urlscan_key": "", "vt_key": "",
    "smtp_host": "", "smtp_port": "587", "smtp_user": "", "smtp_pass": "", "gsb_key": "",
    "monitor": "off", "monitor_minutes": "15", "monitor_touch": "off", "clipboard": "off",
    "notify": "on", "ct": "off", "ct_minutes": "60", "country": "",
    "ct_keywords": "telegram, whatsapp",
    # Reporting identities you can switch between. gmail_index is the /u/N/ slot in
    # your browser: whichever account you signed into first is 0, next is 1, and so on.
    "identities": [], "active": 0,
}
LIST_KEYS = ("identities",)

STATE = {"browser_thread": None, "stop": None, "submit": None, "live": {}, "host": "",
         "detect": {"running": False, "status": "", "result": [], "error": ""},
         "monitor_stop": threading.Event(), "monitor_now": "", "monitor_last": "",
         "clip_stop": threading.Event(), "clip_hits": None,
         "ct_stop": threading.Event(), "ct_running": False, "ct_last": None}


def run_detection():
    d = STATE["detect"]
    d.update(running=True, status="starting browser…", result=[], error="")
    try:
        found, msg = gmailslots.detect(on_status=lambda m: d.update(status=m))
        d["result"], d["status"] = found, msg
        if found:
            cfg = load_config()
            cfg["identities"] = gmailslots.merge(cfg["identities"], found)
            save_config(cfg)
    except Exception as e:
        d["error"] = (gmailslots.CLOSED_MSG if "TargetClosed" in type(e).__name__
                      or "closed" in str(e).lower() else f"{type(e).__name__}: {e}")
    finally:
        d["running"] = False


def load_config():
    cfg = dict(DEFAULT_CONFIG)
    if os.path.exists(CONFIG):
        try:
            cfg.update(json.load(open(CONFIG)))
        except Exception:
            pass
    if not cfg.get("identities"):          # migrate the single reporter into slot 0
        cfg["identities"] = [{"email": cfg.get("reporter_email", ""),
                              "name": cfg.get("reporter_name", ""), "gmail_index": ""}]
        cfg["active"] = 0
    cfg["active"] = max(0, min(int(cfg.get("active") or 0), len(cfg["identities"]) - 1))
    who = cfg["identities"][cfg["active"]]
    cfg["reporter_email"] = who.get("email", "")
    cfg["reporter_name"] = who.get("name", "")
    gi = who.get("gmail_index")
    cfg["gmail_index"] = "" if gi in (None, "", -1) else int(gi)
    return cfg


def clean_identities(raw):
    out = []
    for i in (raw or []):
        email = str(i.get("email", "")).strip()
        if not email or "@" not in email:
            continue
        gi = i.get("gmail_index")
        gi = "" if gi in (None, "", -1) or not str(gi).strip().isdigit() else int(gi)
        out.append({"email": email,
                    "name": str(i.get("name", "")).strip() or "A concerned internet user",
                    "gmail_index": gi})
    return out


def save_config(cfg):
    clean = {k: (v if k in LIST_KEYS else str(v))
             for k, v in cfg.items() if k in DEFAULT_CONFIG}
    if "identities" in clean:
        clean["identities"] = clean_identities(clean["identities"])
    if "active" in clean:
        clean["active"] = int(clean["active"] or 0)
    with open(CONFIG, "w") as f:
        json.dump(clean, f, indent=2)
    os.chmod(CONFIG, 0o600)  # has SMTP password + API keys in it
    return clean


def apply_env(cfg):
    """The engine reads credentials from env; the GUI owns them. Bridge here."""
    os.environ["REPORTER_EMAIL"] = cfg.get("reporter_email", "")
    os.environ["REPORTER_NAME"] = cfg.get("reporter_name", "")
    os.environ["GMAIL_INDEX"] = str(cfg.get("gmail_index", ""))
    os.environ["REPORTER_COUNTRY"] = str(cfg.get("country", ""))
    for env, key in [("URLSCAN_API_KEY", "urlscan_key"), ("VT_API_KEY", "vt_key"),
                     ("GSB_API_KEY", "gsb_key"),
                     ("SMTP_HOST", "smtp_host"), ("SMTP_PORT", "smtp_port"),
                     ("SMTP_USER", "smtp_user"), ("SMTP_PASS", "smtp_pass")]:
        if cfg.get(key):
            os.environ[env] = str(cfg[key])
        else:
            os.environ.pop(env, None)


# ------------------------------------------------------------------- pipeline

def do_recon(url, brand):
    info = fs.recon(url)
    info["brand"] = brand or None
    info["brand_guess"] = fs.guess_brand(info)[0]
    return info


def do_apis(url, submit):
    out = []
    reporter = os.getenv("REPORTER_EMAIL")
    for name, fn, needs_email in fs.API_TARGETS:
        if not submit:
            out.append({"name": name, "status": "not sent (preview mode)", "detail": ""})
            continue
        status, detail = fn(url, reporter) if needs_email else fn(url)
        out.append({"name": name, "status": status, "detail": detail[:400]})
    return out


def do_emails(info, send):
    outdir = os.path.join(REPORTS, info["host"] or "target")
    # RDAP is flaky. A failed network lookup silently dropped abuse@cloudflare.com -
    # the single most effective recipient - from a whole run. Contacts we have already
    # established for this host are carried forward instead of being lost.
    prior = casefile.load(info["host"] or "")
    known = {a for a, e in (prior.get("emails") or {}).items()
             if any(w in (e.get("label") or "") for w in ("registrar", "network"))}
    for addr in sorted(known):
        label = (prior["emails"][addr].get("label") or "")
        bucket = "registrar_abuse" if "registrar" in label else "ip_abuse"
        if addr not in info.get(bucket, []):
            info.setdefault(bucket, []).append(addr)
            info.setdefault("recovered_contacts", []).append(addr)
    emls = fs.build_emls(info, outdir)
    raw = os.environ.get("GMAIL_INDEX", "")
    gi = int(raw) if str(raw).strip().isdigit() else None
    rows = [{"to": a, "label": l, "file": os.path.relpath(p, HERE), "status": "draft written",
             **fs.compose_links(a, subj, body,
                                reporter=os.environ.get("REPORTER_EMAIL", ""), gmail_index=gi)}
            for p, a, l, subj, body in emls]
    if send and os.getenv("SMTP_HOST"):
        for addr, res in (fs.smtp_send(emls) or []):
            for r in rows:
                if r["to"] == addr:
                    r["status"] = res
    return rows


def start_browser(url, values, site_ids, host):
    STATE["host"] = host
    if STATE["browser_thread"] and STATE["browser_thread"].is_alive():
        return {"error": "A browser session is already open. Close it first."}
    STATE["stop"] = threading.Event()
    STATE["submit"] = threading.Event()
    STATE["live"] = {}
    t = threading.Thread(target=automate.run, kwargs=dict(
        url=url, values=values, site_ids=site_ids, stop_event=STATE["stop"],
        submit_event=STATE["submit"],
        on_result=lambda e: (STATE["live"].__setitem__(e["site"], e),
                             casefile.record_vendor(STATE["host"], e))), daemon=True)
    t.start()
    STATE["browser_thread"] = t
    return {"started": True, "count": len(site_ids or SITES)}


# ---------------------------------------------------------------- live monitor

def check_one(host, touch=False):
    c = casefile.load(host)
    if not c.get("host"):
        return None
    recon = c.get("recon") or {}
    apply_env(load_config())
    res = status.check(c.get("url") or f"https://{host}/", host,
                       recon.get("domain") or fs.registrable_domain(host),
                       known_ns=recon.get("ns"), touch_site=touch)
    casefile.record_check(host, res)
    return res


def monitor_loop():
    """Re-check every case that is not already down, on the configured interval.
    A case that has gone down stops being polled - nothing left to learn."""
    while not STATE["monitor_stop"].is_set():
        cfg = load_config()
        if cfg.get("monitor") == "on":
            touch = cfg.get("monitor_touch") == "on"
            for c in casefile.all_cases():
                if STATE["monitor_stop"].is_set():
                    break
                if (c.get("takedown") or {}).get("state") == "down":
                    continue
                try:
                    STATE["monitor_now"] = c["host"]
                    before = (c.get("takedown") or {}).get("state")
                    res = check_one(c["host"], touch)
                    if res:
                        notify.on_state(c["host"], c.get("url"), before, res["state"],
                                        enabled=cfg.get("notify") == "on")
                except Exception:
                    pass
            for c in casefile.all_cases():
                if escalate.readiness(c).get("ready"):
                    notify.once(f"icann:{c['host']}", "reactor",
                                f"{c['host']}: the registrar's 24h window has closed — "
                                f"the ICANN complaint is ready to file",
                                enabled=cfg.get("notify") == "on")
            STATE["monitor_now"] = ""
            STATE["monitor_last"] = datetime.now(timezone.utc).isoformat()
        try:
            mins = max(2, int(load_config().get("monitor_minutes") or 15))
        except ValueError:
            mins = 15
        STATE["monitor_stop"].wait(mins * 60)


def clipboard_loop():
    """Watch the clipboard for phishing links so you never have to paste by hand.

    Off by default and explicitly toggled: this reads your clipboard continuously.
    Only extracted URLs are kept - the clipboard text itself is never stored, never
    logged and never leaves the machine."""
    import subprocess
    last = None
    while not STATE["clip_stop"].is_set():
        if load_config().get("clipboard") == "on":
            try:
                txt = subprocess.run(["pbpaste"], capture_output=True, text=True,
                                     timeout=5).stdout
            except Exception:
                txt = ""
            if txt and txt != last:
                last = txt
                known = [c.get("host") for c in casefile.all_cases()]
                found = intake.parse(txt[:4000], known, allow_touch=False)
                fresh = [t for t in found["targets"] if not t["already_reported"]]
                if fresh:
                    STATE["clip_hits"] = {"targets": fresh, "lures": found["lures"],
                                          "seen": datetime.now(timezone.utc).isoformat()}
        STATE["clip_stop"].wait(2)


def ct_keywords(cfg):
    return [k.strip().lower() for k in str(cfg.get("ct_keywords", "")).split(",") if k.strip()]


def ct_loop():
    """Watch Certificate Transparency for the next domain in the campaign."""
    while not STATE["ct_stop"].is_set():
        cfg = load_config()
        if cfg.get("ct") == "on":
            kws = ct_keywords(cfg)
            if kws:
                try:
                    STATE["ct_running"] = True
                    r = ctwatch.scan(kws)
                    STATE["ct_last"] = r
                    if r["new"] and cfg.get("notify") == "on":
                        top = max(r["new"], key=lambda h: h["score"])
                        notify.send("reactor — new lookalike certificate",
                                    f"{len(r['new'])} new candidate(s), top: {top['domain']}",
                                    "; ".join(top["why"])[:80])
                except Exception as e:
                    STATE["ct_last"] = {"new": [], "errors": {"scan": str(e)[:120]},
                                        "searched": [], "hits": ctwatch.load_state().get("hits", [])}
                finally:
                    STATE["ct_running"] = False
        try:
            mins = max(15, int(load_config().get("ct_minutes") or 60))
        except ValueError:
            mins = 60
        STATE["ct_stop"].wait(mins * 60)


def read_runs(limit=50):
    runs = []
    for path in (RUNS_LOG,):
        if os.path.exists(path):
            for line in open(path):
                try:
                    runs.append(json.loads(line))
                except ValueError:
                    pass
    return list(reversed(runs))[:limit]


# --------------------------------------------------------------------- server

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass  # quiet

    def _send(self, code, body, ctype="application/json"):
        data = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Content-Type-Options", "nosniff")
        # The page and its data change constantly while a case is live. Without this
        # the browser happily serves a cached dashboard and you read stale state.
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
        self.send_header("Pragma", "no-cache")
        self.send_header("Expires", "0")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        route = urllib.parse.urlparse(self.path).path
        if route in ("/", "/index.html"):
            html = open(os.path.join(HERE, "ui.html"), "rb").read()
            stamp = str(int(os.path.getmtime(os.path.join(HERE, "ui.html"))))
            html = html.replace(b"__BUILD__", stamp.encode())
            return self._send(200, html, "text/html; charset=utf-8")
        if route.startswith("/download/"):
            rel = urllib.parse.unquote(route[len("/download/"):])
            full = os.path.realpath(os.path.join(REPORTS, rel))
            # never serve outside reports/, and only the bundles we make
            if not full.startswith(os.path.realpath(REPORTS) + os.sep) \
                    or not full.endswith(".zip") or not os.path.isfile(full):
                return self._send(404, {"error": "not found"})
            data = open(full, "rb").read()
            self.send_response(200)
            self.send_header("Content-Type", "application/zip")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Content-Disposition",
                             f'attachment; filename="{os.path.basename(full)}"')
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)
            return

        if route == "/api/bootstrap":
            return self._send(200, {"config": load_config(), "sites": SITES,
                                    "countries": channels.countries(),
                                    "channels": channels.all_entries(
                                        load_config().get("country", "")),
                                    "build": str(int(os.path.getmtime(
                                        os.path.join(HERE, "ui.html"))))})
        if route == "/api/runs":
            return self._send(200, {"runs": read_runs()})
        if route == "/api/detect-status":
            return self._send(200, {**STATE["detect"], "config": load_config()})

        if route == "/api/ct-status":
            cfg = load_config()
            st = ctwatch.load_state()
            return self._send(200, {
                "on": cfg.get("ct") == "on", "minutes": cfg.get("ct_minutes"),
                "keywords": cfg.get("ct_keywords"), "running": STATE["ct_running"],
                "last_scan": st.get("last_scan"), "errors": st.get("last_errors") or {},
                "searched": st.get("last_searched") or [],
                "hits": st.get("hits", [])[:60], "notify": cfg.get("notify") == "on"})

        if route == "/api/clipboard":
            return self._send(200, {"on": load_config().get("clipboard") == "on",
                                    "hit": STATE["clip_hits"]})

        if route == "/api/monitor-status":
            cfg = load_config()
            return self._send(200, {
                "on": cfg.get("monitor") == "on",
                "minutes": cfg.get("monitor_minutes"), "touch": cfg.get("monitor_touch") == "on",
                "checking": STATE["monitor_now"], "last_sweep": STATE["monitor_last"],
                "cases": [casefile.summary(c) for c in casefile.all_cases()]})

        if route == "/api/browser-status":
            alive = bool(STATE["browser_thread"] and STATE["browser_thread"].is_alive())
            tabs = list(STATE["live"].values())
            return self._send(200, {"open": alive, "tabs": tabs,
                                    "ready": sum(1 for t in tabs if t.get("can_autosubmit")
                                                 and not t.get("submitted"))})
        return self._send(404, {"error": "not found"})

    def do_POST(self):
        route = urllib.parse.urlparse(self.path).path
        length = int(self.headers.get("Content-Length", 0))
        try:
            payload = json.loads(self.rfile.read(length) or b"{}")
        except ValueError:
            return self._send(400, {"error": "bad json"})

        if route == "/api/intake":
            known = [c.get("host") for c in casefile.all_cases()]
            return self._send(200, intake.parse(payload.get("text", ""), known,
                                                allow_touch=payload.get("expand", True)))

        if route == "/api/report-batch":
            cfg = load_config()
            apply_env(cfg)
            out = []
            for t in payload.get("targets", [])[:25]:
                url = (t.get("url") or "").strip()
                if not url.lower().startswith(("http://", "https://")):
                    out.append({"url": url, "error": "not a http(s) URL"})
                    continue
                try:
                    info = do_recon(url, t.get("brand"))
                    apis = do_apis(url, True)
                    emails = do_emails(info, True)
                    casefile.record_run(info["host"] or "target", url, info, apis, emails,
                                        t.get("brand"))
                    out.append({"url": url, "host": info["host"], "brand": info.get("brand"),
                                "registrar": info.get("registrar"), "created": info.get("created"),
                                "apis": apis, "emails": emails,
                                "cloudflare": info.get("cloudflare")})
                except Exception as e:
                    out.append({"url": url, "error": f"{type(e).__name__}: {e}"})
            return self._send(200, {"results": out})

        if route == "/api/clipboard-set":
            cfg = load_config()
            cfg["clipboard"] = "on" if payload.get("on") else "off"
            save_config(cfg)
            if cfg["clipboard"] == "on":
                if not STATE.get("clip_thread") or not STATE["clip_thread"].is_alive():
                    STATE["clip_thread"] = threading.Thread(target=clipboard_loop, daemon=True)
                    STATE["clip_thread"].start()
            else:
                STATE["clip_hits"] = None
            return self._send(200, {"on": cfg["clipboard"] == "on"})

        if route == "/api/clipboard-clear":
            STATE["clip_hits"] = None
            return self._send(200, {"cleared": True})

        if route == "/api/ct-set":
            cfg = load_config()
            for k in ("ct", "ct_minutes", "ct_keywords", "notify"):
                if k in payload:
                    cfg[k] = payload[k]
            save_config(cfg)
            if cfg.get("ct") == "on":
                STATE["ct_stop"].set()
                STATE["ct_stop"] = threading.Event()
                if not STATE.get("ct_thread") or not STATE["ct_thread"].is_alive():
                    STATE["ct_thread"] = threading.Thread(target=ct_loop, daemon=True)
                    STATE["ct_thread"].start()
            return self._send(200, {"config": load_config()})

        if route == "/api/ct-scan":
            cfg = load_config()
            r = ctwatch.scan(ct_keywords(cfg))
            STATE["ct_last"] = r
            return self._send(200, r)

        if route == "/api/ct-dismiss":
            return self._send(200, {"state": ctwatch.dismiss(payload.get("domain", ""))})

        if route == "/api/notify-test":
            ok = notify.send("reactor", "Notifications are working", "test")
            return self._send(200, {"sent": ok})

        if route == "/api/bundle":
            host = payload.get("host", "")
            try:
                path, contents = bundle.build(host)
            except FileNotFoundError as e:
                return self._send(404, {"error": str(e)})
            return self._send(200, {"file": os.path.basename(path),
                                    "path": os.path.relpath(path, HERE),
                                    "contents": contents,
                                    "download": "/download/" + urllib.parse.quote(
                                        os.path.relpath(path, REPORTS))})

        if route == "/api/campaigns":
            cases = casefile.all_cases()
            groups = campaigns.build(cases)
            by_host = {c["host"]: c for c in cases}
            for g in groups:
                g["complaint"] = campaigns.complaint(g, by_host)
            return self._send(200, {"groups": groups, "cases": len(cases)})

        if route == "/api/escalation":
            c = casefile.load(payload.get("host", ""))
            if not c.get("host"):
                return self._send(404, {"error": "no such case"})
            r = escalate.readiness(c)
            return self._send(200, {**r, "form": escalate.ICANN_FORM,
                                    "text": escalate.complaint_text(c)})

        if route == "/api/wiring":
            cfg = load_config()
            def item(name, ok, unlocks, how):
                return {"name": name, "ok": bool(ok), "unlocks": unlocks, "how": how}
            return self._send(200, {"items": [
                item("Reporting address", cfg.get("reporter_email"),
                     "vendor forms, complaint From:, Gmail compose", "Settings → accounts"),
                item("Netcraft", True, "automatic blocklist submission",
                     "no key needed, already working"),
                item("urlscan.io key", cfg.get("urlscan_key"),
                     "auto-submits a public scan, and community verdicts in status checks",
                     "free at urlscan.io/user/signup → Settings"),
                item("VirusTotal key", cfg.get("vt_key"),
                     "submits the URL, and engine counts in status checks",
                     "free at virustotal.com → your profile → API key"),
                item("Google Safe Browsing key", cfg.get("gsb_key"),
                     "tells you whether Chrome is warning victims yet",
                     "console.cloud.google.com → enable Safe Browsing API → create API key"),
                item("SMTP", cfg.get("smtp_host"),
                     "sends the complaint emails automatically",
                     "optional — the Gmail/mail-app compose links do this by hand"),
                item("Live monitor", cfg.get("monitor") == "on",
                     "re-checks every open case on a timer",
                     "toggle it on below"),
                item("Local reporting channels",
                     bool(channels.get(cfg.get("country", ""))),
                     "adds your country's CERT, regulator and police channels",
                     "pick your country in Settings"),
                item("Desktop notifications", cfg.get("notify") == "on",
                     "tells you when a site is blocked, taken down, or ICANN-ready",
                     "macOS only; toggle on the Report tab"),
                item("CT watch", cfg.get("ct") == "on",
                     "spots lookalike domains from public certificate logs, before the SMS arrives",
                     "toggle on the Report tab and set the brands you get spoofed"),
                item("Clipboard watch", cfg.get("clipboard") == "on",
                     "spots a phishing link the moment you copy it",
                     "toggle on the Report tab; reads your clipboard, keeps only URLs"),
            ]})

        if route == "/api/monitor":
            cfg = load_config()
            for k in ("monitor", "monitor_minutes", "monitor_touch"):
                if k in payload:
                    cfg[k] = payload[k]
            save_config(cfg)
            if cfg.get("monitor") == "on":
                STATE["monitor_stop"].set()      # wake the sleeper so it starts now
                STATE["monitor_stop"] = threading.Event()
                if not STATE.get("monitor_thread") or not STATE["monitor_thread"].is_alive():
                    STATE["monitor_thread"] = threading.Thread(target=monitor_loop, daemon=True)
                    STATE["monitor_thread"].start()
            return self._send(200, {"config": load_config()})

        if route == "/api/config":
            save_config({**load_config(), **payload})
            return self._send(200, {"config": load_config()})

        if route == "/api/switch":
            cfg = load_config()
            cfg["active"] = int(payload.get("active", 0))
            save_config(cfg)
            return self._send(200, {"config": load_config()})

        if route == "/api/submit-all":
            if not (STATE["browser_thread"] and STATE["browser_thread"].is_alive()):
                return self._send(400, {"error": "no browser session open"})
            STATE["submit"].set()
            return self._send(200, {"submitting": True})

        if route == "/api/recipes":
            out = []
            for s_ in SITES:
                p_ = automate.recipe_path(s_["id"])
                out.append({"id": s_["id"], "name": s_["name"],
                            "steps": len(automate.load_recipe(s_["id"])),
                            "updated": (json.load(open(p_)).get("updated")
                                        if os.path.exists(p_) else None)})
            return self._send(200, {"recipes": out})

        if route == "/api/forget":
            p_ = automate.recipe_path(payload.get("id", ""))
            if os.path.exists(p_):
                os.remove(p_)
            return self._send(200, {"forgotten": payload.get("id")})

        if route == "/api/detect-slots":
            if STATE["detect"]["running"]:
                return self._send(400, {"error": "detection already running"})
            if STATE["browser_thread"] and STATE["browser_thread"].is_alive():
                return self._send(400, {"error": "close the vendor browser session first — "
                                                 "detection needs the same browser profile"})
            threading.Thread(target=run_detection, daemon=True).start()
            return self._send(200, {"started": True})

        if route == "/api/history":
            return self._send(200, {"cases": [casefile.summary(c) for c in casefile.all_cases()]})

        if route == "/api/case":
            return self._send(200, {"case": casefile.load(payload.get("host", ""))})

        if route == "/api/mark-sent":
            return self._send(200, {"case": casefile.mark_email(
                payload["host"], payload["to"], payload.get("sent", True))})

        if route == "/api/recheck":
            host = payload.get("host", "")
            c = casefile.load(host)
            recon = c.get("recon") or {}
            apply_env(load_config())          # VirusTotal key
            res = status.check(c.get("url") or f"https://{host}/", host,
                               recon.get("domain") or fs.registrable_domain(host),
                               known_ns=recon.get("ns"),
                               touch_site=bool(payload.get("touch_site")))
            return self._send(200, {"case": casefile.record_check(host, res), "check": res})

        if route == "/api/open-mail":
            # hands the prefilled draft to the user's own mail client; sends nothing
            import subprocess
            for link in payload.get("links", [])[:10]:
                if link.startswith("mailto:"):
                    subprocess.Popen(["open", link])
            return self._send(200, {"opened": len(payload.get("links", []))})

        if route == "/api/close-browser":
            if STATE["stop"]:
                STATE["stop"].set()
            return self._send(200, {"closed": True})

        if route == "/api/report":
            url = (payload.get("url") or "").strip()
            if not url.lower().startswith(("http://", "https://")):
                return self._send(400, {"error": "URL must start with http:// or https://"})
            save_config({**load_config(), **payload.get("config", {})})
            cfg = load_config()      # re-read: active identity derives reporter_* + gmail slot
            apply_env(cfg)
            submit = bool(payload.get("submit"))

            info = do_recon(url, payload.get("brand"))
            apis = do_apis(url, submit) if payload.get("do_apis", True) else []
            emails = do_emails(info, submit) if payload.get("do_emails", True) else []

            browser = {"started": False}
            if payload.get("do_browser", True) and submit:
                values = {"url": url, "email": cfg["reporter_email"],
                          "name": cfg["reporter_name"],
                          "brand": info.get("brand") or info.get("brand_guess") or "",
                          "domain": info.get("domain") or "",
                          "comment": payload.get("comment") or
                          f"Phishing site{' impersonating ' + info['brand'].title() if info.get('brand') else ''}. "
                          f"Domain {info['domain']} registered {info.get('created') or 'recently'}. "
                          f"Harvests credentials from victims. Please block/blacklist."}
                browser = start_browser(url, values, payload.get("site_ids"),
                                        info["host"] or "target")

            casefile.record_run(info["host"] or "target", url, info, apis, emails,
                                payload.get("brand"))
            record = {"ts": datetime.now(timezone.utc).isoformat(), "url": url,
                      "submitted": submit, "recon": info, "apis": apis,
                      "emails": emails, "browser": browser,
                      "manual": fs.manual_forms(info)}
            os.makedirs(REPORTS, exist_ok=True)
            with open(RUNS_LOG, "a") as f:
                f.write(json.dumps(record) + "\n")
            return self._send(200, record)

        return self._send(404, {"error": "not found"})


if __name__ == "__main__":
    os.makedirs(REPORTS, exist_ok=True)
    if load_config().get("monitor") == "on":
        STATE["monitor_thread"] = threading.Thread(target=monitor_loop, daemon=True)
        STATE["monitor_thread"].start()
    if load_config().get("clipboard") == "on":
        STATE["clip_thread"] = threading.Thread(target=clipboard_loop, daemon=True)
        STATE["clip_thread"].start()
    if load_config().get("ct") == "on":
        STATE["ct_thread"] = threading.Thread(target=ct_loop, daemon=True)
        STATE["ct_thread"].start()
    srv = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    print(f"reactor GUI -> http://127.0.0.1:{PORT}   (localhost only, Ctrl-C to stop)")
    try:
        webbrowser.open(f"http://127.0.0.1:{PORT}")
    except Exception:
        pass
    srv.serve_forever()
