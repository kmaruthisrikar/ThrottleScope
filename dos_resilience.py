#!/usr/bin/env python3
"""DoS-RESILIENCE probes — single slow connection + small connection ceiling.

Three read-only, low-impact tests (NOT a flood):
  slow-read   ONE connection, partial GET, 1 byte/sec read for <=20s.
              Measures server patience/timeout — a long patient window is the
              Slowloris exposure signal. One socket only.
  idle-timeout ONE keep-alive connection: full valid GET, then sit idle
              <=15s and watch for the server closing us. A server that lets
              idle sessions linger is tying up a slot per trickle — same
              Slowloris family, measured from the other end. One socket only.
  conn-ceil   up to --max-conns (cap 10) parallel idle connections, opened with
              a 1s stagger, held 5s, then all closed. Reports accept vs
              refuse/reset — the per-IP connection ceiling estimate.

Run:  python3 dos_resilience.py example.com --port 443 --tls
      python3 dos_resilience.py example.com --port 80 --checks slow-read
      python3 dos_resilience.py example.com --port 443 --tls --dry-run

#slowloris-check #conn-ceiling #resilience #capped #no-flooding
"""
import argparse
import contextlib
import json
import os
import socket
import ssl
import sys
import time
from concurrent.futures import ThreadPoolExecutor

from safe_rate_limit_catalog import ensure_parent  # noqa: E402

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

MAX_CONNS_CAP = 10
SLOW_READ_SECS = 20
IDLE_TIMEOUT_SECS = 15
VALID_CHECKS = ("slow-read", "idle-timeout", "conn-ceil")


def open_conn(ip, port, use_tls, timeout=5):
    raw = socket.create_connection((ip, port), timeout=timeout)
    if use_tls:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx.wrap_socket(raw, server_hostname=ip)
    return raw


def slow_read(host, ip, port, use_tls, secs=SLOW_READ_SECS):
    """One partial request, trickle-read. Returns patience verdict."""
    print(f"  [slow-read] 1 connection to {ip}:{port}, {secs}s trickle", flush=True)
    t0 = time.perf_counter()
    held, got, verdict = 0, 0, ""
    try:
        with contextlib.closing(open_conn(ip, port, use_tls)) as s:
            s.settimeout(2)  # short reads: the 1s sleep paces the trickle
            s.sendall(f"GET / HTTP/1.1\r\nHost: {host}\r\n".encode())
            deadline = time.perf_counter() + secs
            while time.perf_counter() < deadline:
                try:
                    chunk = s.recv(1)  # 1 byte at a time — slowest polite read
                    if not chunk:
                        break  # server closed — only this means 'cut'
                    got += len(chunk)
                except (socket.timeout, ssl.SSLError):
                    pass  # silence is patience, not a close — keep trickling
                time.sleep(1.0)
            held = time.perf_counter() - t0
    except Exception as e:
        held = time.perf_counter() - t0
        verdict = f"connection failed ({e}) — cannot assess"
    if not verdict:
        if held >= secs - 1:
            verdict = (f"PATIENT SERVER: held our 1B/s connection {held:.0f}s "
                       f"({got}B) — slow-read exposure, confirm timeout config")
        else:
            verdict = (f"server cut the slow connection after {held:.1f}s "
                       f"({got}B) — slow-read mitigated at this layer")
    print(f"  [slow-read] held={held:.1f}s bytes={got}", flush=True)
    return {"check": "slow-read", "held_s": round(held, 1), "bytes": got,
            "verdict": verdict}


def idle_timeout(host, ip, port, use_tls, idle_secs=IDLE_TIMEOUT_SECS):
    """One keep-alive conn, full GET, then idle. Returns close patience."""
    print(f"  [idle-timeout] 1 keep-alive conn to {ip}:{port}, "
          f"idle {idle_secs}s", flush=True)
    t0 = time.perf_counter()
    held, got, closed_at, verdict = 0, 0, None, ""
    try:
        with contextlib.closing(open_conn(ip, port, use_tls)) as s:
            s.sendall(f"GET / HTTP/1.1\r\nHost: {host}\r\n"
                      f"Connection: keep-alive\r\n\r\n".encode())
            s.settimeout(3)  # drain window: headers arrive fast or not at all
            try:  # drain the response, whatever it is
                while True:
                    chunk = s.recv(4096)
                    if not chunk:
                        closed_at = time.perf_counter() - t0
                        break
                    got += len(chunk)
            except (socket.timeout, ssl.SSLError):
                pass
            if closed_at is None:  # response done, socket open — now sit idle
                s.settimeout(1.0)
                deadline = time.perf_counter() + idle_secs
                while time.perf_counter() < deadline:
                    try:
                        chunk = s.recv(1024)
                        if not chunk:
                            closed_at = time.perf_counter() - t0
                            break
                        got += len(chunk)
                    except (socket.timeout, ssl.SSLError):
                        pass
            held = time.perf_counter() - t0
    except Exception as e:
        held = time.perf_counter() - t0
        verdict = f"connection failed ({e}) — cannot assess"
    if not verdict:
        if closed_at is not None and closed_at < idle_secs:
            verdict = (f"server closed our idle keep-alive after {closed_at:.1f}s "
                       f"— idle-session exposure mitigated at this layer")
        else:
            verdict = (f"PATIENT SERVER: idle keep-alive survived {held:.0f}s "
                       f"({got}B) — idle slots linger, confirm keep-alive timeout")
    print(f"  [idle-timeout] held={held:.1f}s bytes={got}", flush=True)
    return {"check": "idle-timeout", "held_s": round(held, 1), "bytes": got,
            "verdict": verdict}


def conn_ceiling(ip, port, use_tls, max_conns):
    """Small parallel idle-connection set. Returns accept/refuse counts."""
    max_conns = max(1, min(int(max_conns), MAX_CONNS_CAP))
    print(f"  [conn-ceil] opening {max_conns} staggered idle connections", flush=True)
    conns, accepted, refused = [], 0, 0

    def one(_):
        try:
            s = open_conn(ip, port, use_tls)
            return s, True
        except Exception:
            return None, False

    with ThreadPoolExecutor(max_workers=max_conns) as ex:
        futs = []
        for i in range(max_conns):
            futs.append(ex.submit(one, i))
            time.sleep(1.0)  # 1s stagger — the opposite of a flood
        for fut in futs:
            s, ok = fut.result()
            if ok:
                accepted += 1
                conns.append(s)
            else:
                refused += 1
    print(f"  [conn-ceil] holding {accepted} for 5s, then closing all", flush=True)
    try:
        time.sleep(5)
    finally:
        for s in conns:
            try:
                s.close()
            except Exception:
                pass
    if refused == 0:
        verdict = (f"all {accepted} idle connections accepted — per-IP ceiling "
                   f"above {accepted} (raise max-conns only in lab)")
    else:
        verdict = (f"ceiling signal: {accepted} accepted / {refused} refused — "
                   f"connection limiting present around ~{accepted}")
    print(f"  [conn-ceil] accepted={accepted} refused={refused}", flush=True)
    return {"check": "conn-ceil", "accepted": accepted, "refused": refused,
            "verdict": verdict}


def main():
    ap = argparse.ArgumentParser(description="DoS-resilience probes (capped, safe)")
    ap.add_argument("host", help="hostname (Host header + display)")
    ap.add_argument("--ip", default=None, help="override IP (skip resolve)")
    ap.add_argument("--port", type=int, default=443)
    ap.add_argument("--tls", action="store_true", help="wrap in TLS")
    ap.add_argument("--checks", default=",".join(VALID_CHECKS),
                    help=f"comma list: {','.join(VALID_CHECKS)}")
    ap.add_argument("--max-conns", type=int, default=8,
                    help=f"idle connections for conn-ceil (cap {MAX_CONNS_CAP})")
    ap.add_argument("--dry-run", action="store_true", help="print plan, open nothing")
    ap.add_argument("--json", default="", help="write results JSON here")
    args = ap.parse_args()

    wanted = {c.strip() for c in args.checks.split(",")}
    if wanted - set(VALID_CHECKS):
        print(f"unknown checks ({','.join(VALID_CHECKS)}): {sorted(wanted)}",
              file=sys.stderr)
        return 2
    ip = args.ip or socket.gethostbyname(args.host)
    print(f"DoS-resilience — {args.host} ({ip}:{args.port}{' tls' if args.tls else ''})")
    if args.dry_run:
        if "slow-read" in wanted:
            print(f"  PLAN slow-read: 1 conn, {SLOW_READ_SECS}s trickle")
        if "idle-timeout" in wanted:
            print(f"  PLAN idle-timeout: 1 keep-alive conn, {IDLE_TIMEOUT_SECS}s idle")
        if "conn-ceil" in wanted:
            print(f"  PLAN conn-ceil: {min(args.max_conns, MAX_CONNS_CAP)} conns, 5s hold")
        return 0
    results = []
    if "slow-read" in wanted:
        results.append(slow_read(args.host, ip, args.port, args.tls))
    if "idle-timeout" in wanted:
        results.append(idle_timeout(args.host, ip, args.port, args.tls))
    if "conn-ceil" in wanted:
        results.append(conn_ceiling(ip, args.port, args.tls, args.max_conns))
    print("\n=== RESILIENCE VERDICTS ===")
    for r in results:
        print(f"{r['check']:<12} {r['verdict']}")
    if args.json:
        ensure_parent(args.json)
        with open(args.json, "w") as f:
            json.dump({"target": args.host, "ip": ip, "results": results},
                      f, indent=2, default=str)
        print(f"Evidence written: {args.json}")


if __name__ == "__main__":
    sys.exit(main())
