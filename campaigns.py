"""Group reported pages that look like the same operator.

Naive clustering is worse than none here: nearly every phishing site sits behind
Cloudflare, so "shared nameserver" would put every case you own in one bucket and
tell you nothing. Signals from shared infrastructure are therefore discounted, and
every link carries the reason it was drawn so you can throw it out.
"""
import re
from datetime import datetime

# Infrastructure so widely used that sharing it means nothing.
COMMON_NS = re.compile(r"cloudflare|amazonaws|azure|godaddy|namecheap|dnspod|alidns|"
                       r"google|hostinger|namesilo|porkbun|digitalocean|vercel|netlify",
                       re.I)
COMMON_NET = re.compile(r"cloudflare|amazon|google|microsoft|akamai|fastly|digitalocean|"
                        r"hetzner|ovh|linode", re.I)


def _sig(case):
    r = case.get("recon") or {}
    return {
        "host": case.get("host"),
        "domain": r.get("domain") or "",
        "brand": (case.get("brand") or r.get("brand") or "").lower(),
        "registrar": (r.get("registrar") or "").lower(),
        "ns": {n.strip(".").lower() for n in (r.get("ns") or [])},
        "ips": set(r.get("ips") or []),
        "network": (r.get("network") or "").lower(),
        "created": (r.get("created") or "")[:10],
        "first": (case.get("first_reported") or "")[:10],
    }


def link_reasons(a, b):
    """Why these two might be the same operator. Empty list means no evidence."""
    out = []
    shared_ns = a["ns"] & b["ns"]
    if shared_ns and not any(COMMON_NS.search(n) for n in shared_ns):
        out.append(("nameservers", f"both on {', '.join(sorted(shared_ns))}", 3))
    shared_ip = a["ips"] & b["ips"]
    if shared_ip and not COMMON_NET.search(a["network"] + b["network"]):
        out.append(("hosting", f"same IP {', '.join(sorted(shared_ip))}", 3))
    if a["registrar"] and a["registrar"] == b["registrar"]:
        weight = 2 if a["created"] and a["created"] == b["created"] else 1
        extra = " and registered the same day" if weight == 2 else ""
        out.append(("registrar", f"both at {a['registrar']}{extra}", weight))
    if a["brand"] and a["brand"] == b["brand"] and a["first"] == b["first"]:
        out.append(("pattern", f"same brand ({a['brand']}) reported the same day", 1))
    return out


def build(cases, threshold=2):
    """Union cases whose evidence clears the threshold. Returns groups of 2+."""
    sigs = [_sig(c) for c in cases if c.get("host")]
    parent = list(range(len(sigs)))

    def find(i):
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    edges = []
    for i in range(len(sigs)):
        for j in range(i + 1, len(sigs)):
            reasons = link_reasons(sigs[i], sigs[j])
            score = sum(w for _, _, w in reasons)
            if score >= threshold:
                edges.append((sigs[i]["host"], sigs[j]["host"],
                              [f"{k}: {why}" for k, why, _ in reasons], score))
                parent[find(i)] = find(j)

    groups = {}
    for idx, sig in enumerate(sigs):
        groups.setdefault(find(idx), []).append(sig)

    out = []
    for members in groups.values():
        if len(members) < 2:
            continue
        hosts = {m["host"] for m in members}
        out.append({
            "hosts": sorted(hosts),
            "brands": sorted({m["brand"] for m in members if m["brand"]}),
            "registrars": sorted({m["registrar"] for m in members if m["registrar"]}),
            "links": [e for e in edges if e[0] in hosts and e[1] in hosts],
            "size": len(hosts),
        })
    return sorted(out, key=lambda g: -g["size"])


def complaint(group, cases_by_host):
    """One registrar complaint covering the whole cluster. A pattern of abuse across
    several domains is a far stronger case than any single report."""
    lines = [f"{len(group['hosts'])} domains registered through the same channel are running "
             f"the same phishing operation:", ""]
    for h in group["hosts"]:
        c = cases_by_host.get(h, {})
        r = c.get("recon") or {}
        lines.append(f"  {c.get('url') or h}")
        lines.append(f"    registered {(r.get('created') or 'unknown')[:10]} "
                     f"via {r.get('registrar') or 'unknown'}; "
                     f"nameservers {', '.join(r.get('ns') or ['unknown'])}")
    lines += ["", "Evidence that these are one operation:"]
    for a, b, reasons, _ in group["links"]:
        for reason in reasons:
            lines.append(f"  {a} <-> {b}: {reason}")
    lines += ["", "This is a pattern of abuse, not an isolated report. Please suspend all of "
                  "the above and review other registrations from the same customer."]
    return "\n".join(lines)


def selftest():
    cf = {"host": "a.top", "recon": {"domain": "a.top", "registrar": "Cheap Reg",
          "ns": ["alex.ns.cloudflare.com"], "ips": ["104.21.1.1"], "network": "CLOUDFLARENET",
          "created": "2026-09-03"}, "first_reported": "2026-09-05", "brand": "telegram"}
    cf2 = {"host": "b.top", "recon": {"domain": "b.top", "registrar": "Cheap Reg",
           "ns": ["deb.ns.cloudflare.com"], "ips": ["104.21.2.2"], "network": "CLOUDFLARENET",
           "created": "2026-09-03"}, "first_reported": "2026-09-05", "brand": "telegram"}
    # Cloudflare in common proves nothing on its own...
    a, b = _sig(cf), _sig(cf2)
    kinds = {k for k, _, _ in link_reasons(a, b)}
    assert "nameservers" not in kinds, "shared Cloudflare must never count as a link"
    assert "hosting" not in kinds, "Cloudflare IPs must never count as a link"
    # ...but same registrar on the same day, same brand, same day reported, does
    assert sum(w for _, _, w in link_reasons(a, b)) >= 2
    assert len(build([cf, cf2])) == 1

    # an obscure shared nameserver is strong on its own
    x = {"host": "x.top", "recon": {"ns": ["ns1.bulletproof-xyz.ru"], "registrar": "R1",
         "ips": [], "network": "SOMEISP", "created": "2026-01-01"}, "first_reported": "2026-09-05"}
    y = {"host": "y.top", "recon": {"ns": ["ns1.bulletproof-xyz.ru"], "registrar": "R2",
         "ips": [], "network": "SOMEISP", "created": "2026-05-05"}, "first_reported": "2026-09-06"}
    assert len(build([x, y])) == 1
    # unrelated cases must not be grouped
    z = {"host": "z.top", "recon": {"ns": ["ns.other.net"], "registrar": "R3", "ips": [],
         "network": "N", "created": "2020-01-01"}, "first_reported": "2026-09-07"}
    assert build([x, z]) == []
    g = build([x, y])[0]
    assert "bulletproof-xyz.ru" in complaint(g, {"x.top": x, "y.top": y})
    print("campaigns selftest OK")


if __name__ == "__main__":
    selftest()
