#!/usr/bin/env python3
"""Custom attack/test builder — you pick target, layer, checks. Still capped safe.

Two target kinds (the wizard asks; flags accept both):
  URL mode    custom HTTP test (method/probes/headers/stop-on-429)
              + optional bypass evasions (25 techniques) on the same URL
  IP:port     layer checks on YOUR port: tcp-connect rate, banner grab,
              TLS handshakes, UDP datagrams, ping — plus an optional
              1-datagram sweep of 14 common UDP ports to find responders.

Safety: probes<=1000, delay>=0.1s, workers<=8, per-variant<=50, read-only
methods. Plans over ~200 requests or under 0.5s delay are 'aggressive' and
ask a y/n confirmation before anything is sent. No floods, no spoofing,
no brute force.

Run:  python3 custom_rate_test.py                      # wizard: asks everything
      python3 custom_rate_test.py https://t/path --evasions
      python3 custom_rate_test.py --ip 10.0.0.5 --port 443 --tls
      python3 custom_rate_test.py --ip 10.0.0.5 --port 53 --layer-checks udp,ping --udp-sweep

#custom #rate-limit #evasions #tcp #udp #tls #wizard #no-flooding
"""
import argparse
import json
import os
import random
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from safe_rate_limit_catalog import (  # noqa: E402
    HEADERS, SERVICE_NAMES, TLS_CANDIDATES, UDP_RECON_PORTS, clamp,
    ensure_parent, finish_http_records, jitter_sleep, probe_icmp, probe_tcp_banner,
    probe_tcp_connect, probe_tls_handshake, probe_udp_port, recon_udp,
    rl_headers_of,
)
from attack_bypass import (  # noqa: E402
    run_variant, technique_names, variants_for, verdict_for,
)

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

READ_ONLY_METHODS = ("GET", "HEAD", "OPTIONS")
LAYER_CHECKS = ("tcp", "banner", "tls", "udp", "ping")

# Custom builder limits — deliberately roomier than the base catalog because
# threshold-mapping needs volume (e.g. "limit kicks in at request ~300").
# Still bounded: unbounded count + zero delay + wide workers = a flooder,
# which this tool refuses to be. Anything aggressive needs a y/n confirmation.
CUSTOM_HARD_PROBES = 1000
CUSTOM_MIN_DELAY = 0.1
CUSTOM_MAX_WORKERS = 8
CUSTOM_MAX_PER_VARIANT = 50
BLAST_REQUESTS = 200   # above this many total requests => aggressive
BLAST_DELAY = 0.5      # below this delay => aggressive


def custom_clamp(probes, delay, workers):
    probes = max(1, min(int(probes), CUSTOM_HARD_PROBES))
    delay = max(float(delay), CUSTOM_MIN_DELAY)
    workers = max(1, min(int(workers), CUSTOM_MAX_WORKERS))
    return probes, delay, workers


def is_aggressive(total_requests, delay):
    return total_requests > BLAST_REQUESTS or delay < BLAST_DELAY


def aggressive_confirm(total_requests, delay):
    """y/n gate before aggressive plans. Returns True to proceed."""
    if not is_aggressive(total_requests, delay):
        return True
    print(f"  !! aggressive plan: ~{total_requests} requests @ {delay}s delay — "
          f"real load on a live target.")
    return ask_yes_no("proceed", "n")


def ev_count(only):
    """Estimated technique count for blast math (selected or all)."""
    if not (only or "").strip():
        return len(technique_names())
    o = {v.strip() for v in only.split(",") if v.strip()}
    n = len([t for t in technique_names()
             if t in o or (t.startswith("xff-") and "xff" in o)])
    return n or len(technique_names())


def fire(method, url, headers, data, timeout=5):
    start = time.perf_counter()
    try:
        r = requests.request(method, url, headers=headers, data=data,
                             timeout=timeout, verify=False)
        return {"status": r.status_code, "time": time.perf_counter() - start,
                "size": len(r.content),
                "retry_after": r.headers.get("Retry-After"),
                "ratelimit": rl_headers_of(r.headers)}
    except Exception as e:
        return {"status": "ERR", "time": time.perf_counter() - start,
                "error": str(e)}


def run_custom(url, method, probes, delay, workers, extra_headers, data,
               stop_on_429, rng, timeout=5):
    from concurrent.futures import ThreadPoolExecutor, as_completed
    headers = dict(HEADERS)
    headers.update(extra_headers)
    records, stopped = [], False

    def one(i):
        rec = {"i": i}
        rec.update(fire(method, url, headers, data, timeout))
        return rec

    print(f"  [custom {method} {url}] reqs={probes} workers={workers} "
          f"stop_on_429={stop_on_429}", flush=True)
    if workers == 1:
        for i in range(1, probes + 1):
            rec = one(i)
            records.append(rec)
            print(f"  [custom] {rec['i']} status={rec['status']} "
                  f"time={rec['time']:.3f}s size={rec.get('size', '-')}", flush=True)
            if stop_on_429 and rec["status"] == 429:
                print("  [custom] 429 hit — stopping early (--stop-on-429)")
                stopped = True
                break
            jitter_sleep(delay, rng)
    else:
        with ThreadPoolExecutor(max_workers=workers) as ex:
            futs = [ex.submit(one, i) for i in range(1, probes + 1)]
            for fut in as_completed(futs):
                rec = fut.result()
                records.append(rec)
                print(f"  [custom] {rec['i']} status={rec['status']} "
                      f"time={rec['time']:.3f}s", flush=True)
                if stop_on_429 and rec["status"] == 429:
                    print("  [custom] 429 hit — draining, no new requests")
                    break  # in-flight only; pool closes after
                jitter_sleep(delay, rng)
    res = finish_http_records(url, "custom-rate", "L7/HTTP", records)
    res["summary"]["stopped_early"] = stopped
    counts = {}
    for rec in records:
        counts[str(rec["status"])] = counts.get(str(rec["status"]), 0) + 1
    res["summary"]["status_counts"] = counts
    print(f"  [custom] status histogram: {counts}", flush=True)
    return res


def run_evasions(url, per_variant, only, delay, rng):
    """All 17 bypass techniques on a URL. Returns findings dict."""
    only = {v.strip() for v in (only or "").split(",") if v.strip()} or None
    techs = [(n, m, u, h) for n, m, u, h in variants_for(url)
             if only is None or n in only or (n.startswith("xff-") and "xff" in only)]
    if not techs:
        print(f"  [evasions] no techniques match {sorted(only or [])}")
        return {"url": url, "bypassed": [], "results": []}
    per_variant = max(1, min(int(per_variant), CUSTOM_MAX_PER_VARIANT))
    print(f"  [evasions] {len(techs)} techniques x{per_variant} on {url}", flush=True)
    res = [run_variant(n, m, u, h, per_variant, delay, rng) for n, m, u, h in techs]
    base_rows = [r["limited"] for r in res if r["variant"] == "baseline"]
    base_lim = base_rows[0] if base_rows else None
    for r in res:
        r["verdict"] = verdict_for(base_lim, r["limited"], r["statuses"])
        print(f"  {r['variant']:<14} {r['verdict']}")
    byp = [r["variant"] for r in res if r["verdict"].startswith("BYPASSED")]
    print(f"  => evasions: {'BYPASSED via ' + ','.join(byp) if byp else 'held / no limiter'}")
    return {"url": url, "baseline_limited": base_lim, "bypassed": byp, "results": res}


def run_ip_mode(target, port, checks, probes, delay, use_tls, udp_sweep, rng):
    """Your IP:port, your layer checks, your probe counts."""
    import socket as _s
    try:
        ip = _s.gethostbyname(target)
    except Exception as e:
        print(f"cannot resolve {target}: {e}", file=sys.stderr)
        return None
    print(f"  [ip-mode] {target} ({ip}:{port}) checks={checks} "
          f"tls={use_tls} udp_sweep={udp_sweep}", flush=True)
    answering = []
    if udp_sweep:
        umap = recon_udp(ip, UDP_RECON_PORTS)
        answering = sorted(p for p, v in umap.items() if v.startswith("OPEN"))
        print(f"  [ip-mode] answering UDP ports: {answering or 'none'}")
    results = []
    if "tcp" in checks:
        results.append(probe_tcp_connect(ip, port, probes, delay, rng))
    if "banner" in checks:
        results.append(probe_tcp_banner(ip, port, SERVICE_NAMES.get(port, "unknown"),
                                        use_tls, delay, rng))
    if "tls" in checks:
        results.append(probe_tls_handshake(ip, port, probes, delay, rng))
    if "udp" in checks:
        results.append(probe_udp_port(ip, port, probes, delay, rng))
        for p in answering:
            if p != port:
                results.append(probe_udp_port(ip, p, probes, delay, rng))
    if "ping" in checks:
        results.append(probe_icmp(ip, probes, delay, rng))
    for r in results:
        print(f"  => [{r['check']}] {r['target']}: {r['verdict']}")
    return {"target": target, "ip": ip, "port": port, "results": results}


def parse_header(h):
    name, _, val = h.partition(":")
    if not val.strip():
        raise ValueError(f"bad header (need 'Name: value'): {h}")
    return name.strip(), val.strip()


def parse_layer_checks(s):
    if not s or s.strip() == "all":
        return list(LAYER_CHECKS)
    checks = [c.strip() for c in s.split(",") if c.strip()]
    unknown = [c for c in checks if c not in LAYER_CHECKS]
    if unknown:
        raise ValueError(f"unknown layer check(s): {unknown} — valid: {LAYER_CHECKS}")
    return checks


def ask(prompt, default=None, cast=str, valid=None):
    """One friendly prompt with default, type check, and allowed values."""
    while True:
        try:
            suffix = f" [{default}]" if default is not None else ""
            raw = input(f"  {prompt}{suffix}: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nwizard cancelled — nothing was sent.")
            sys.exit(1)
        if not raw:
            if default is not None:
                return default
            print("  a value is required here.")
            continue
        try:
            val = cast(raw)
        except ValueError:
            print(f"  invalid — enter a {cast.__name__}.")
            continue
        if valid is not None and val not in valid:
            print(f"  pick one of: {valid}.")
            continue
        return val


def ask_yes_no(prompt, default="n"):
    return ask(prompt + " (y/n)", default, str.lower, ("y", "n")) == "y"


def ask_headers():
    print("  extra headers, one per line like  Name: value  (blank line = done)")
    extra = {}
    while True:
        try:
            raw = input("  header: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nwizard cancelled — nothing was sent.")
            sys.exit(1)
        if not raw:
            return extra
        try:
            k, v = parse_header(raw)
            extra[k] = v
        except ValueError as e:
            print(f"  {e}")


def wizard_url(rng):
    while True:
        url = ask("target URL (full, e.g. https://site/path)")
        if url.lower().startswith(("http://", "https://")):
            break
        print("  URL must start with http:// or https://")
    method = ask("HTTP method", "GET", str.upper,
                 list(READ_ONLY_METHODS) + ["POST"]).upper()
    data = ask("POST body (single static string)", "") if method == "POST" else None
    probes = ask("how many requests (max 1000)", 10, int)
    delay = ask("delay between requests, seconds (min 0.1)", 1.0, float)
    workers = ask("parallel workers, 1 = sequential polite (max 8)", 1, int)
    extra = ask_headers()
    stop = ask_yes_no("stop early at first 429", "n")
    evasions = ask_yes_no(f"also run the {len(technique_names())} bypass evasions on this URL", "n")
    per_variant, only = 3, ""
    if evasions:
        per_variant = ask("requests per evasion technique (max 50)", 3, int)
        print("  evasion menu — pick any, comma-separated "
              f"(blank/all = all {len(technique_names())}):")
        for i, n in enumerate(technique_names(), 1):
            print(f"    {i:>2}. {n}")
        only = ask("your pick", "")
        if only.strip().lower() == "all":
            only = ""
    timeout = ask("per-request timeout, seconds", 5.0, float)
    json_path = ask("save evidence JSON to file (blank = skip)", "")
    probes, delay, workers = custom_clamp(probes, delay, workers)
    total = probes + (per_variant * ev_count(only) if evasions else 0)
    print(f"\n  plan: {probes}x {method} {url} @ >={delay}s, workers={workers}, "
          f"headers={extra or 'none'}, stop_on_429={stop}"
          + (f" + {per_variant}x evasions (~{per_variant * ev_count(only) if evasions else 0} extra)" if evasions else "")
          + f"  [~{total} requests total]")
    if not aggressive_confirm(total, delay):
        print("cancelled — nothing was sent.")
        return 1
    if not ask_yes_no("run this test", "y"):
        print("cancelled — nothing was sent.")
        return 1
    res = run_custom(url, method, probes, delay, workers, extra,
                     data, stop, rng, timeout)
    print(f"=> {res['verdict']}")
    out = {"mode": "url", "http": res}
    if evasions:
        out["evasions"] = run_evasions(url, per_variant, only, delay, rng)
    if json_path:
        ensure_parent(json_path)
        with open(json_path, "w") as f:
            json.dump(out, f, indent=2, default=str)
        print(f"Evidence written: {json_path}")
    return 0


def wizard_ip(rng):
    target = ask("target IP or hostname")
    while True:
        port = ask("port to test", 80, int)
        if 1 <= port <= 65535:
            break
        print("  port must be 1-65535.")
    checks = ask("layer checks, comma of tcp,banner,tls,udp,ping (blank = all)", "")
    try:
        checks = parse_layer_checks(checks)
    except ValueError as e:
        print(f"  {e} — using all.")
        checks = list(LAYER_CHECKS)
    use_tls = ask_yes_no("use TLS for banner/handshake",
                         "y" if port in TLS_CANDIDATES else "n")
    udp_sweep = ask_yes_no("first sweep 14 common UDP ports (1 datagram each)", "n")
    probes = ask("probes per check (max 1000)", 10, int)
    delay = ask("delay between probes, seconds (min 0.1)", 1.0, float)
    json_path = ask("save evidence JSON to file (blank = skip)", "")
    probes, delay, _ = custom_clamp(probes, delay, 1)
    total = probes * (len(checks) + (14 if udp_sweep else 0))
    print(f"\n  plan: {target}:{port} checks={checks} x{probes} @ >={delay}s "
          f"tls={use_tls} udp_sweep={udp_sweep}  [~{total} requests total]")
    if not aggressive_confirm(total, delay):
        print("cancelled — nothing was sent.")
        return 1
    if not ask_yes_no("run this test", "y"):
        print("cancelled — nothing was sent.")
        return 1
    out = run_ip_mode(target, port, checks, probes, delay, use_tls, udp_sweep, rng)
    if out is None:
        return 2
    out["mode"] = "ip"
    if json_path:
        ensure_parent(json_path)
        with open(json_path, "w") as f:
            json.dump(out, f, indent=2, default=str)
        print(f"Evidence written: {json_path}")
    return 0


def wizard(rng):
    print("Custom test wizard — answer each question (Enter = default).")
    kind = ask("target kind", "url", str.lower, ("url", "ip"))
    return wizard_url(rng) if kind == "url" else wizard_ip(rng)


def main():
    ap = argparse.ArgumentParser(description="Custom attack/test builder (capped, safe)")
    ap.add_argument("url", nargs="?", default=None,
                    help="full URL to test (omit for interactive wizard)")
    ap.add_argument("--wizard", action="store_true",
                    help="interactive setup: asks target, layer, checks, everything")
    ap.add_argument("--method", default="GET",
                    help="GET/HEAD/OPTIONS (read-only) or POST with --data")
    ap.add_argument("--probes", type=int, default=10, help="request count (cap 1000)")
    ap.add_argument("--delay", type=float, default=1.0, help="delay seconds (min 0.1)")
    ap.add_argument("--workers", type=int, default=1, help="parallel workers (cap 8)")
    ap.add_argument("-H", "--header", action="append", default=[],
                    help="extra header 'Name: value' (repeatable)")
    ap.add_argument("--data", default=None, help="static POST body (implies --method POST)")
    ap.add_argument("--stop-on-429", action="store_true", help="stop at first 429")
    ap.add_argument("--evasions", action="store_true",
                    help="also run the 17 bypass evasions on the URL")
    ap.add_argument("--per-variant", type=int, default=3,
                    help="requests per evasion technique (cap 50)")
    ap.add_argument("--only", default="",
                    help="evasion subset, comma list (blank = all)")
    ap.add_argument("--ip", default=None, help="IP/host target for layer checks")
    ap.add_argument("--port", type=int, default=None, help="port for --ip mode")
    ap.add_argument("--layer-checks", default="all",
                    help=f"comma of: {','.join(LAYER_CHECKS)} (default all)")
    ap.add_argument("--tls", action="store_true", help="TLS for banner/handshake")
    ap.add_argument("--udp-sweep", action="store_true",
                    help="sweep 14 common UDP ports first (1 datagram each)")
    ap.add_argument("--timeout", type=float, default=5.0, help="per-request timeout")
    ap.add_argument("--dry-run", action="store_true", help="print plan, send nothing")
    ap.add_argument("--json", default="", help="write result JSON here")
    args = ap.parse_args()
    rng = random.Random()

    if args.wizard or (not args.url and not args.ip):
        return wizard(rng)

    if args.ip:  # ---------------- IP:port mode ----------------
        if not args.port or not 1 <= args.port <= 65535:
            print("--ip needs --port 1-65535.", file=sys.stderr)
            return 2
        try:
            checks = parse_layer_checks(args.layer_checks)
        except ValueError as e:
            print(e, file=sys.stderr)
            return 2
        probes, delay, _ = custom_clamp(args.probes, args.delay, 1)
        total = probes * (len(checks) + (14 if args.udp_sweep else 0))
        print(f"Custom layer test — {args.ip}:{args.port} — checks={checks} "
              f"x{probes} @ >={delay}s tls={args.tls}  [~{total} requests]")
        if is_aggressive(total, delay):
            print(f"  !! aggressive plan: ~{total} requests @ {delay}s — "
                  f"real load on a live target.")
            if not ask_yes_no("proceed", "n"):
                print("cancelled — nothing was sent.")
                return 1
        if args.dry_run:
            print(f"  PLAN {checks} on {args.ip}:{args.port}")
            return 0
        out = run_ip_mode(args.ip, args.port, checks, probes, delay,
                          args.tls, args.udp_sweep, rng)
        if out is None:
            return 2
        out["mode"] = "ip"
        if args.json:
            ensure_parent(args.json)
            with open(args.json, "w") as f:
                json.dump(out, f, indent=2, default=str)
            print(f"Evidence written: {args.json}")
        return 0

    # ---------------- URL mode ----------------
    method = (args.method or ("POST" if args.data else "GET")).upper()
    if method == "POST" and args.data is None:
        print("POST needs --data (single static body; no wordlists).", file=sys.stderr)
        return 2
    if method not in READ_ONLY_METHODS + ("POST",):
        print(f"method {method} refused (read-only + plain POST only).", file=sys.stderr)
        return 2
    try:
        extra = dict(parse_header(h) for h in args.header)
    except ValueError as e:
        print(e, file=sys.stderr)
        return 2

    probes, delay, workers = custom_clamp(args.probes, args.delay, args.workers)
    total = probes + (args.per_variant * ev_count(args.only) if args.evasions else 0)
    print(f"Custom rate test — {method} {args.url} — probes={probes} "
          f"delay>={delay}s workers={workers} headers={extra or 'none'}"
          + (" +evasions" if args.evasions else "")
          + f"  [~{total} requests]")
    if is_aggressive(total, delay):
        print(f"  !! aggressive plan: ~{total} requests @ {delay}s — "
              f"real load on a live target.")
        if not ask_yes_no("proceed", "n"):
            print("cancelled — nothing was sent.")
            return 1
    if args.dry_run:
        print(f"  PLAN {probes}x {method} {args.url}")
        if args.evasions:
            print(f"  PLAN {args.per_variant}x evasions")
        return 0
    res = run_custom(args.url, method, probes, delay, workers, extra,
                     args.data, args.stop_on_429, rng, args.timeout)
    print(f"=> {res['verdict']}")
    out = {"mode": "url", "http": res}
    if args.evasions:
        out["evasions"] = run_evasions(args.url, args.per_variant, args.only,
                                       delay, rng)
    if args.json:
        ensure_parent(args.json)
        with open(args.json, "w") as f:
            json.dump(out, f, indent=2, default=str)
        print(f"Evidence written: {args.json}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
