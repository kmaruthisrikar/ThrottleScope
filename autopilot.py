#!/usr/bin/env python3
"""AUTOPILOT — full rate-limit + resilience engagement in one command.

Chain (all capped, non-destructive, no flooding):
  1 recon        1 connect/datagram per common port -> open lists
  2 safe-catalog http-seq/parallel, tcp-connect, banners, tls, udp, icmp
  3 bypass       every http endpoint (NO-LIMITER baseline where unprotected)
  4 resilience   slow-read + idle-timeout + conn-ceiling on open 80/443
  5 findings     safe PoCs (cors, wp enum/version, sec-headers, xmlrpc,
                 dir-listing, http-trace, server-banner; --base overridable)
  6 report       evidence.json + report.md

Live runs need --yes (scope confirmation). --dry-run plans everything first.

Run:  python3 autopilot.py example.com --dry-run
      python3 autopilot.py example.com --yes --json ev.json --report rep.md
      python3 autopilot.py 10.0.0.5 --yes --skip resilience,bypass --probes 5

#autopilot #engagement #rate-limit #resilience #report
"""
import argparse
import json
import os
import random
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import safe_rate_limit_catalog as C  # noqa: E402
from attack_bypass import run_variant, verdict_for, variants_for  # noqa: E402
from dos_resilience import conn_ceiling, idle_timeout, slow_read  # noqa: E402
from finding_exploits import POCS  # noqa: E402

PHASES = ("recon", "catalog", "bypass", "resilience", "findings", "report")
SCOPE_TEXT = "I confirm this target is in my authorized test scope"


def phase_recon(ip, delay, rng):
    print("\n[1/6] recon — 1 connect/datagram per port")
    open_map = C.recon_tcp(ip, C.COMMON_TCP_PORTS)
    udp_map = C.recon_udp(ip, C.UDP_RECON_PORTS)
    open_tcp = sorted(open_map)
    udp_ok = sorted(p for p, v in udp_map.items() if v.startswith("OPEN"))
    print(f"  => open TCP: {open_tcp or 'none'} | answering UDP: {udp_ok or 'none'}")
    return open_tcp, udp_ok


def phase_catalog(host, ip, open_tcp, udp_ok, probes, delay, workers, rng):
    print("\n[2/6] safe rate-limit catalog")
    urls = [f"https://{host}/"]
    for p in sorted(set(open_tcp) & C.HTTP_CANDIDATES):
        scheme = "https" if p in C.TLS_CANDIDATES else "http"
        urls.append(f"{scheme}://{ip}:{p}/")
    banners = [(p, C.SERVICE_NAMES.get(p, "unknown"), p in C.TLS_CANDIDATES)
               for p in open_tcp]
    tls_ports = sorted(set(open_tcp) & C.TLS_CANDIDATES)
    cat = C.build_catalog(probes, delay, workers, rng, host, ip, urls,
                          host, open_tcp, banners, tls_ports, udp_ok)
    results = []
    for cid, lbl, fn in cat:
        print(f"Check: {lbl}", flush=True)
        for res in fn():
            print(f"  => {res['verdict']}")
            results.append(res)
    return results


def phase_bypass(catalog_results, per_variant, delay, rng):
    print("\n[3/6] bypass attacks on EVERY http endpoint probed in phase 2")
    targets = sorted({r["target"] for r in catalog_results
                      if r["check"].startswith("http")})
    if not targets:
        print("  no http targets in phase 2 — skipping")
        return []
    limited_any = {r["target"] for r in catalog_results
                   if r["check"].startswith("http") and r["summary"].get("first_429")}
    print(f"  ({len(limited_any)} of {len(targets)} endpoints 429-limited; "
          f"the rest get NO-LIMITER baselines — still tested)")
    out = []
    for url in targets:
        techs = list(variants_for(url))
        print(f"  target {url} ({len(techs)} techniques x{per_variant})")
        res = [run_variant(n, m, u, h, per_variant, delay, rng) for n, m, u, h in techs]
        base_rows = [r["limited"] for r in res if r["variant"] == "baseline"]
        base_lim = base_rows[0] if base_rows else None
        for r in res:
            r["verdict"] = verdict_for(base_lim, r["limited"], r["statuses"])
            print(f"  {r['variant']:<14} {r['verdict']}")
        out.append({"url": url, "bypassed": [r["variant"] for r in res
                                             if r["verdict"].startswith("BYPASSED")],
                    "results": res})
    return out


def phase_resilience(host, ip, open_tcp):
    print("\n[4/6] DoS-resilience probes")
    out = []
    ports = [(80, False), (443, True)]
    for p in sorted(set(open_tcp) & (C.HTTP_CANDIDATES | C.TLS_CANDIDATES)):
        if p not in (80, 443):
            ports.append((p, p in C.TLS_CANDIDATES))
    for port, tls in ports:
        if port not in open_tcp:
            print(f"  port {port} closed — skipping")
            continue
        out.append({"port": port, **slow_read(host, ip, port, tls)})
        out.append({"port": port, **idle_timeout(host, ip, port, tls)})
        out.append({"port": port, **conn_ceiling(ip, port, tls, 8)})
    return out


def phase_findings(base):
    print("\n[5/6] finding PoCs")
    out = []
    for name, fn in POCS.items():
        try:
            out.append(fn(base))
        except Exception as e:
            out.append({"check": name, "verdict": f"PoC failed: {e}"})
    return out


def write_report(path, host, ip, ev):
    lines = [f"# Rate-limit engagement — {host} ({ip})",
             f"_UTC {time.strftime('%Y-%m-%dT%H:%M:%S')} — capped probes, no flooding_\n",
             "## Verdicts"]
    for r in ev.get("catalog", []):
        lines.append(f"- [{r['check']}] {r['target']}: {r['verdict']}")
    for b in ev.get("bypass", []):
        lines.append(f"- [bypass] {b['url']}: "
                     f"{'BYPASSED via ' + ','.join(b['bypassed']) if b['bypassed'] else 'limiter held'}")
    for r in ev.get("resilience", []):
        lines.append(f"- [{r['check']}:{r.get('port')}] {r['verdict']}")
    for r in ev.get("findings", []):
        lines.append(f"- [{r['check']}] {r['verdict']}")
    with open(path, "w") as f:
        f.write("\n".join(lines) + "\n")
    print(f"Report written: {path}")


def main():
    ap = argparse.ArgumentParser(description="Autopilot rate-limit engagement")
    ap.add_argument("target", nargs="?", default=C.HOST, help="IP or hostname")
    ap.add_argument("--yes", action="store_true", help=f"scope gate: '{SCOPE_TEXT}'")
    ap.add_argument("--probes", type=int, default=5, help="probes per check (cap 100)")
    ap.add_argument("--delay", type=float, default=1.0, help="delay seconds (min 0.5)")
    ap.add_argument("--workers", type=int, default=2, help="parallel workers (cap 4)")
    ap.add_argument("--skip", default="", help="comma phases to skip: " + ",".join(PHASES))
    ap.add_argument("--base", default="",
                    help="override PoC base URL (default https://<target>/); "
                         "use http://… when 443 is closed, or a loopback port in lab")
    ap.add_argument("--dry-run", action="store_true", help="plan only, touch nothing")
    ap.add_argument("--json", default="evidence.json", help="evidence output path")
    ap.add_argument("--report", default="report.md", help="markdown report path")
    args = ap.parse_args()

    skip = {s.strip() for s in args.skip.split(",") if s.strip()}
    if skip - set(PHASES):
        print(f"unknown phase(s): {sorted(skip)}", file=sys.stderr)
        return 2
    if not args.dry_run and not args.yes:
        print(f"refusing live run without --yes ('{SCOPE_TEXT}'). "
              f"Use --dry-run to plan.", file=sys.stderr)
        return 2
    probes, delay, workers = C.clamp(args.probes, args.delay, args.workers)
    host, ip = C.resolve_target(args.target, None, None)
    rng = random.Random()
    print(f"Autopilot — {host} ({ip}) — probes={probes} delay>={delay}s "
          f"workers={workers} skip={sorted(skip) or 'none'}"
          f"{' DRY-RUN' if args.dry_run else ''}")
    if args.dry_run:
        for ph in PHASES:
            if ph not in skip:
                print(f"  PLAN phase: {ph}")
        return 0

    ev = {"target": host, "ip": ip, "started": time.strftime("%Y-%m-%dT%H:%M:%S"),
          "probes": probes, "delay": delay}
    open_tcp, udp_ok = ([], [])
    if "recon" not in skip:
        open_tcp, udp_ok = phase_recon(ip, delay, rng)
    ev["catalog"] = [] if "catalog" in skip else phase_catalog(
        host, ip, open_tcp, udp_ok, probes, delay, workers, rng)
    ev["bypass"] = [] if "bypass" in skip else phase_bypass(
        ev["catalog"], min(probes, 5), delay, rng)
    ev["resilience"] = [] if "resilience" in skip else phase_resilience(host, ip, open_tcp)
    base = args.base.rstrip("/") + "/" if args.base else f"https://{host}/"
    ev["findings"] = [] if "findings" in skip else phase_findings(base)

    if "report" not in skip:
        print("\n[6/6] report")
        for path in (args.json, args.report):
            C.ensure_parent(path)
        with open(args.json, "w") as f:
            json.dump(ev, f, indent=2, default=str)
        print(f"Evidence written: {args.json}")
        write_report(args.report, host, ip, ev)
    print("\nAutopilot complete.")


if __name__ == "__main__":
    sys.exit(main())
