#!/usr/bin/env python3
"""Safe rate-limit + recon catalog — point at ANY ip/host, discover, then test.

Two phases, non-destructive probes only:
  PHASE 1 recon (skip with --no-recon): one connect per common TCP port,
            one datagram per common UDP port -> open/answering port lists
  PHASE 2 rate-limit catalog, per discovered port (+ any explicit --*-ports):
    http-seq / http-parallel, tcp-connect, tcp-banner, tls-handshake,
    udp-dns, udp-port, icmp  (same signals as before, now per-port)

One catalog, every reachable layer — non-destructive probes only:
  http-seq        L7  https   sequential GETs, 429 / Retry-After / rate-limit header hunt
  http-parallel   L7  https   low-concurrency GETs (workers<=4), same signals
  tcp-connect     L4  TCP     connect/close cycle rate per open port (all 19 known-open)
  tcp-banner      L4  TCP     connect + passive banner read (plain + TLS-wrapped services)
  tls-handshake   L4  TLS     repeated TLS handshakes + cert fingerprint rate (443, 2083)
  udp-dns         L4  UDP    minimal A-record queries, RCODE / drop / ICMP-unreachable
  udp-port        L4  UDP    single small datagrams per UDP port, response classification
  icmp            L3  ICMP   echo-request rate via system ping, loss/latency signal

Safety policy (webapp-hacking SKILL §13: single/low-digit probes, never flooding):
  - default PROBES=10, hard cap 100; default DELAY>=0.5s with +/-20% jitter
  - GET-only, no auth attempts, no writes, no credentials, no payloads
  - deliberately NOT implemented: SYN floods, ICMP floods, spoofed sources,
    NTP monlist / amplification payloads, application-layer floods

Run:  python3 safe_rate_limit_catalog.py 1.2.3.4        # any IP: recon + per-port rate tests
      python3 safe_rate_limit_catalog.py example.com      # any hostname (resolves first)
      python3 safe_rate_limit_catalog.py --checks tcp-connect,icmp 10.0.0.5
      python3 safe_rate_limit_catalog.py --no-recon       # static known-port lists only
      python3 safe_rate_limit_catalog.py --dry-run        # catalog plan only
      python3 safe_rate_limit_catalog.py --json out.json  # + evidence dump

#rate-limit-check #safe-verification #no-flooding #catalog #tcp #udp #icmp #tls
"""
import argparse
import ipaddress
import json
import os
import random
import socket
import ssl
import subprocess
import sys
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def ensure_parent(path):
    """Create the parent directory for an output file (no-op if none)."""
    parent = os.path.dirname(path or "")
    if parent:
        os.makedirs(parent, exist_ok=True)

# ---------------------------------------------------------------- targets --
# Default target (documentation placeholder — always pass your authorized
# target explicitly, or override via CLI args / --host / --ip).
HOST = "example.com"
IP = "93.184.216.34"
URLS = [
    "https://example.com",
    "https://example.com/api/items",
    "https://example.com/login",
]
# Commonly assessed TCP ports (recon discovers the live set on any target;
# --no-recon falls back to this static list):
# 21,80,110,143,443,465,587,993,995,3306 + cPanel 2077/2078/2080/2082/2083/2086/2087/2095/2096
TCP_PORTS = [21, 80, 110, 143, 443, 465, 587, 993, 995, 3306,
             2077, 2078, 2080, 2082, 2083, 2086, 2087, 2095, 2096]
# port -> (service, tls_wrapped)
BANNER_PORTS = {
    21: ("ftp", False), 110: ("pop3", False), 143: ("imap", False),
    587: ("smtp", False), 3306: ("mysql", False),
    465: ("smtps", True), 993: ("imaps", True), 995: ("pop3s", True),
}
TLS_PORTS = [443, 2083]                     # repeated TLS-handshake rate surfaces
UDP_PORTS = [53, 123]                       # dns, ntp
DNS_QNAME = HOST
RL_HEADER_TOKENS = ("rate", "limit", "throttl", "quota", "retry")

# ------------------------------------------------------- recon port lists --
# Common TCP ports swept once each during discovery (1 connect per port).
COMMON_TCP_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
                    465, 587, 631, 993, 995, 1433, 1521, 1723, 2049, 2077, 2078,
                    2080, 2082, 2083, 2086, 2087, 2095, 2096, 2181, 2375, 2376,
                    3000, 3306, 3389, 4000, 4443, 4567, 5000, 5432, 5631, 5900,
                    5985, 5986, 6379, 6443, 6666, 8000, 8008, 8009, 8010, 8022,
                    8040, 8080, 8081, 8083, 8088, 8089, 8090, 8181, 8443, 8834,
                    8888, 9000, 9001, 9042, 9080, 9090, 9100, 9200, 9300, 9443,
                    10000, 11211, 27017]
# Small UDP set: one datagram each (full UDP sweeps are slow/noisy — opt out).
UDP_RECON_PORTS = [53, 67, 68, 69, 123, 137, 138, 161, 162, 500, 514, 1900, 4500, 5353]
SERVICE_NAMES = {21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
                 80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios",
                 143: "imap", 443: "https", 445: "smb", 465: "smtps", 587: "smtp",
                 631: "ipp", 993: "imaps", 995: "pop3s", 1433: "mssql", 1521: "oracle",
                 3306: "mysql", 3389: "rdp", 5432: "postgres", 5900: "vnc",
                 6379: "redis", 27017: "mongodb", 11211: "memcached",
                 2082: "cpanel", 2083: "cpanel-tls", 2086: "whm", 2087: "whm-tls",
                 2095: "webmail", 2096: "webmail-tls", 2077: "webdav", 2078: "webdav-tls",
                 2080: "cpanel-cal", 8443: "https-alt", 9443: "https-alt"}
TLS_CANDIDATES = {443, 465, 993, 995, 2083, 2087, 2096, 2078, 8443, 9443}
HTTP_CANDIDATES = {80, 8000, 8008, 8080, 8081, 8083, 8088, 8089, 8090, 8181,
                   8888, 9000, 2082, 2086, 2095, 3000, 5000, 8443, 9443}

# ------------------------------------------------------------- safety caps --
HARD_PROBE_CAP = 100
MIN_DELAY = 0.5
MAX_PARALLEL_WORKERS = 4

HEADERS = {"User-Agent": "SafeVerificationBot/1.0", "Accept": "*/*"}

DNS_RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 5: "REFUSED"}


def clamp(probes, delay, workers):
    probes = max(1, min(int(probes), HARD_PROBE_CAP))
    delay = max(float(delay), MIN_DELAY)
    workers = max(1, min(int(workers), MAX_PARALLEL_WORKERS))
    return probes, delay, workers


def jitter_sleep(delay, rng):
    time.sleep(delay * rng.uniform(0.8, 1.2))


def path_of(url):
    try:
        return urlparse(url).path or "/"
    except Exception:
        return url


def rl_headers_of(headers):
    return {k: v for k, v in headers.items()
            if any(t in k.lower() for t in RL_HEADER_TOKENS)}


def parse_ports(s):
    if not s:
        return set()
    return {int(p) for p in s.split(",") if p.strip()}


def is_ip(s):
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def resolve_target(target, host_ov, ip_ov):
    """Any input -> (host, ip). IP stays as-is; hostname resolves via DNS."""
    host = host_ov or (target if target and not is_ip(target) else HOST)
    if ip_ov:
        return host, ip_ov
    if target and is_ip(target):
        return target, target
    return host, socket.gethostbyname(host)


# ------------------------------------------------------------- recon phase --
def recon_tcp(ip, ports, timeout=1.5, workers=20):
    """One connect per port. Returns {port: connect_seconds} for open ports."""
    def knock(p):
        start = time.perf_counter()
        try:
            s = socket.create_connection((ip, p), timeout=timeout)
            s.close()
            return p, time.perf_counter() - start
        except Exception:
            return p, None

    open_ports = {}
    with ThreadPoolExecutor(max_workers=workers) as ex:
        for p, dt in ex.map(knock, ports):
            if dt is not None:
                open_ports[p] = dt
                print(f"  [recon-tcp] OPEN {ip}:{p} ({dt * 1000:.0f}ms)", flush=True)
    return open_ports


def recon_udp(ip, ports, timeout=1.5):
    """One datagram per port. Returns {port: classification}."""
    verdict = {}
    for p in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(timeout)
                s.connect((ip, p))  # connected socket surfaces ICMP unreachable
                s.send(b"\x00" * 8)
                try:
                    data = s.recv(64)
                    verdict[p] = f"OPEN ({len(data)}B reply)"
                except socket.timeout:
                    verdict[p] = "FILTERED (no reply)"
        except ConnectionRefusedError:
            verdict[p] = "CLOSED (icmp unreachable)"
        except Exception as e:
            verdict[p] = f"ERR:{type(e).__name__}"
        print(f"  [recon-udp] {ip}:{p} {verdict[p]}", flush=True)
    return verdict


# ------------------------------------------------------------------ checks --
def probe_http_seq(url, probes, delay, rng):
    records = []
    for i in range(1, probes + 1):
        start = time.perf_counter()
        try:
            r = requests.get(url, headers=HEADERS, timeout=5, verify=False)
            rec = {
                "i": i, "status": r.status_code, "time": time.perf_counter() - start,
                "size": len(r.content),
                "retry_after": r.headers.get("Retry-After"),
                "ratelimit": rl_headers_of(r.headers),
            }
        except Exception as e:
            rec = {"i": i, "status": "ERR", "time": time.perf_counter() - start, "error": str(e)}
        records.append(rec)
        print(f"  [{path_of(url)}] {i} status={rec['status']} "
              f"time={rec['time']:.3f}s size={rec.get('size', '-')} retry_after={rec.get('retry_after')}", flush=True)
        jitter_sleep(delay, rng)
    return finish_http_records(url, "http-seq", "L7/HTTPS", records)


def probe_http_parallel(url, probes, delay, workers, rng):
    def one(i):
        start = time.perf_counter()
        try:
            r = requests.get(url, headers=HEADERS, timeout=5, verify=False)
            return {"i": i, "status": r.status_code, "time": time.perf_counter() - start,
                    "size": len(r.content),
                    "retry_after": r.headers.get("Retry-After"),
                    "ratelimit": rl_headers_of(r.headers)}
        except Exception as e:
            return {"i": i, "status": "ERR", "time": time.perf_counter() - start, "error": str(e)}

    records = []
    print(f"  [{path_of(url)}] workers={workers} reqs={probes}")
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futs = [ex.submit(one, i) for i in range(1, probes + 1)]
        for fut in as_completed(futs):
            rec = fut.result()
            records.append(rec)
            print(f"  [{path_of(url)}] {rec['i']} "
                  f"status={rec['status']} time={rec['time']:.3f}s size={rec.get('size', '-')}", flush=True)
            jitter_sleep(delay, rng)
    return finish_http_records(url, "http-parallel", "L7/HTTPS", records)


def finish_http_records(url, cid, layer, records):
    statuses = Counter(r["status"] for r in records)
    first_429 = next((r["i"] for r in records if r["status"] == 429), None)
    retry_after = [r for r in records if r.get("retry_after")]
    rl_headers = {k for r in records for k in (r.get("ratelimit") or {})}
    if first_429:
        verdict = f"THROTTLED: HTTP 429 first seen at request {first_429}"
    elif retry_after:
        verdict = f"RATE-LIMIT SIGNAL: Retry-After present ({retry_after[0]['retry_after']}) without 429"
    elif rl_headers:
        verdict = f"DECLARED LIMIT: rate headers {sorted(rl_headers)} advertised"
    else:
        verdict = "no rate limiting observed (no 429, no Retry-After, no rate headers)"
    return {"check": cid, "layer": layer, "target": url, "records": records,
            "summary": {"status_counts": dict(statuses), "first_429": first_429,
                        "any_retry_after": bool(retry_after),
                        "rate_headers": sorted(rl_headers)},
            "verdict": verdict}


def probe_tcp_connect(ip, port, probes, delay, rng):
    records = []
    for i in range(1, probes + 1):
        start = time.perf_counter()
        try:
            s = socket.create_connection((ip, port), timeout=3)
            s.close()
            rec = {"i": i, "status": "OPEN", "time": time.perf_counter() - start}
        except Exception as e:
            rec = {"i": i, "status": f"ERR:{type(e).__name__}", "time": time.perf_counter() - start}
        records.append(rec)
        print(f"  [tcp/{port}] {i} {rec['status']} time={rec['time']:.3f}s", flush=True)
        jitter_sleep(delay, rng)
    counts = Counter(r["status"] for r in records)
    onset = next((r["i"] for i, r in enumerate(records)
                  if r["status"] != "OPEN" and any(x["status"] == "OPEN" for x in records[:i])), None)
    if counts.get("OPEN", 0) == probes:
        verdict = "no TCP-level restriction (all connects accepted)"
    elif counts.get("OPEN", 0) == 0:
        verdict = "port unreachable from here (all connects failed)"
    else:
        verdict = f"TCP-LEVEL RESTRICTION: connects failing from request {onset}"
    return {"check": "tcp-connect", "layer": "L4/TCP", "target": f"{ip}:{port}",
            "records": records,
            "summary": {"counts": dict(counts), "failure_onset": onset}, "verdict": verdict}


def probe_tcp_banner(ip, port, service, use_tls, delay, rng):
    tag = f"{service}{'/tls' if use_tls else ''}"
    banner = b""
    try:
        raw = socket.create_connection((ip, port), timeout=3)
        s = raw
        if use_tls:  # one normal handshake, verify off, then read-only
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            s = ctx.wrap_socket(raw, server_hostname=ip)
        s.settimeout(3)
        try:
            banner = s.recv(200)
        except (socket.timeout, ssl.SSLError):
            banner = b""
        s.close()
        status = "BANNER" if banner else "NO-BANNER"
        print(f"  [tcp-banner/{port} {tag}] {status} banner={banner[:80]!r}", flush=True)
        verdict = (f"banner serviced normally ({len(banner)} bytes read)" if banner
                   else "port connected; no server banner within 3s")
    except Exception as e:
        status = f"ERR:{type(e).__name__}"
        verdict = f"unreachable: {e}"
        print(f"  [tcp-banner/{port} {tag}] {status} {e}", flush=True)
    jitter_sleep(delay, rng)
    return {"check": "tcp-banner", "layer": "L4/TCP", "target": f"{ip}:{port} ({tag})",
            "records": [{"port": port, "service": tag, "status": status,
                         "banner": banner[:120].decode("utf-8", "replace")}],
            "summary": {"status": status}, "verdict": verdict}


def probe_tls_handshake(ip, port, probes, delay, rng):
    import hashlib
    records = []
    for i in range(1, probes + 1):
        start = time.perf_counter()
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            raw = socket.create_connection((ip, port), timeout=3)
            s = ctx.wrap_socket(raw, server_hostname=ip)
            der = s.getpeercert(binary_form=True) or b""
            s.close()
            rec = {"i": i, "status": "HANDSHAKE", "time": time.perf_counter() - start,
                   "cert_sha256": hashlib.sha256(der).hexdigest()[:16] if der else "-"}
        except Exception as e:
            rec = {"i": i, "status": f"ERR:{type(e).__name__}", "time": time.perf_counter() - start}
        records.append(rec)
        print(f"  [tls/{port}] {i} {rec['status']} time={rec['time']:.3f}s "
              f"cert={rec.get('cert_sha256', '-')}", flush=True)
        jitter_sleep(delay, rng)
    counts = Counter(r["status"] for r in records)
    onset = next((r["i"] for i, r in enumerate(records)
                  if r["status"] != "HANDSHAKE" and any(x["status"] == "HANDSHAKE" for x in records[:i])), None)
    if counts.get("HANDSHAKE", 0) == probes:
        verdict = "no TLS-level restriction (all handshakes completed)"
    elif counts.get("HANDSHAKE", 0) == 0:
        verdict = "TLS unreachable from here (all handshakes failed)"
    else:
        verdict = f"TLS-LEVEL RESTRICTION: handshakes failing from request {onset}"
    return {"check": "tls-handshake", "layer": "L4/TLS", "target": f"{ip}:{port}",
            "records": records,
            "summary": {"counts": dict(counts), "failure_onset": onset}, "verdict": verdict}


def dns_query(name):
    qname = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"
    return b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + qname + b"\x00\x01\x00\x01"


def dns_rcode(resp):
    return resp[3] & 0x0F if len(resp) >= 4 else None


def probe_udp_dns(ip, qname, probes, delay, rng):
    records = []
    for i in range(1, probes + 1):
        start = time.perf_counter()
        rec = {"i": i}
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(3)
                s.connect((ip, 53))
                s.send(dns_query(qname))
                resp = s.recv(512)
            rc = dns_rcode(resp)
            rec.update(status=DNS_RCODES.get(rc, f"RCODE{rc}"), answers=len(resp),
                       time=time.perf_counter() - start)
        except ConnectionRefusedError:
            rec.update(status="ICMP-UNREACHABLE", time=time.perf_counter() - start)
        except socket.timeout:
            rec.update(status="TIMEOUT", time=time.perf_counter() - start)
        except Exception as e:
            rec.update(status=f"ERR:{type(e).__name__}", time=time.perf_counter() - start)
        records.append(rec)
        print(f"  [udp/53 dns] {i} {rec['status']} time={rec.get('time', 0):.3f}s", flush=True)
        jitter_sleep(delay, rng)
    counts = Counter(r["status"] for r in records)
    onset = next((r["i"] for i, r in enumerate(records)
                  if r["status"] in ("REFUSED", "SERVFAIL")
                  and not any(x["status"] in ("REFUSED", "SERVFAIL") for x in records[:i])), None)
    if counts.get("REFUSED") or counts.get("SERVFAIL"):
        verdict = f"DNS-LEVEL RESTRICTION: REFUSED/SERVFAIL from query {onset} ({dict(counts)})"
    elif counts.get("TIMEOUT", 0) == probes:
        verdict = "no DNS service reachable on udp/53 (all queries timed out)"
    elif counts.get("ICMP-UNREACHABLE", 0):
        verdict = "udp/53 closed (ICMP port unreachable)"
    else:
        verdict = "no DNS rate limiting observed"
    return {"check": "udp-dns", "layer": "L4/UDP", "target": f"{ip}:53 ({qname} A)",
            "records": records, "summary": {"counts": dict(counts), "refusal_onset": onset},
            "verdict": verdict}


def probe_udp_port(ip, port, probes, delay, rng):
    records = []
    for i in range(1, probes + 1):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(3)
                s.connect((ip, port))
                s.send(b"\x00" * 8)  # 8 zero bytes, no protocol payload
                try:
                    resp = s.recv(64)
                    status = "RESPONSE"
                except socket.timeout:
                    resp, status = b"", "TIMEOUT"
        except ConnectionRefusedError:
            resp, status = b"", "ICMP-UNREACHABLE"
        except Exception as e:
            resp, status = b"", f"ERR:{type(e).__name__}"
        records.append({"i": i, "status": status, "resp_len": len(resp)})
        print(f"  [udp/{port}] {i} {status} resp={len(resp)}B", flush=True)
        jitter_sleep(delay, rng)
    counts = Counter(r["status"] for r in records)
    verdict = {"RESPONSE": f"udp/{port} answers (no UDP rate limiting observed)",
               "TIMEOUT": f"udp/{port} filtered or rate-limited (all datagrams unanswered)",
               "ICMP-UNREACHABLE": f"udp/{port} closed (ICMP port unreachable)"}.get(
        counts.most_common(1)[0][0], f"mixed: {dict(counts)}")
    return {"check": "udp-port", "layer": "L4/UDP", "target": f"{ip}:{port}",
            "records": records, "summary": {"counts": dict(counts)}, "verdict": verdict}


def probe_icmp(host, probes, delay, rng):
    interval = max(1.0, delay)
    try:
        out = subprocess.run(["ping", "-c", str(probes), "-i", f"{interval:.2f}", "-W", "2", host],
                             capture_output=True, text=True, timeout=probes * (interval + 3))
        line = next((l for l in out.stdout.splitlines() if "packet loss" in l or "received" in l), "")
        times = [float(l.split("time=")[1].split()[0])
                 for l in out.stdout.splitlines() if "time=" in l]
        print(f"  [icmp] {line.strip() or 'no reply line'}", flush=True)
        if not times:
            verdict = "no ICMP echo replies (filtered or ICMP rate-limited)"
        elif len(times) < probes:
            verdict = f"ICMP PARTIAL: {len(times)}/{probes} replies — rate limiting/filtering likely"
        else:
            verdict = f"no ICMP rate limiting observed ({len(times)}/{probes} replies)"
    except Exception as e:
        line, times, verdict = f"ERROR {e}", [], f"probe failed: {e}"
        print(f"  [icmp] {line}", flush=True)
    return {"check": "icmp", "layer": "L3/ICMP", "target": host,
            "records": [{"replies": len(times), "rtt_ms": times}],
            "summary": {"loss_line": line, "replies": len(times), "probes": probes},
            "verdict": verdict}


# ----------------------------------------------------------------- catalog --
CHECK_IDS = ("http-seq", "http-parallel", "tcp-connect", "tcp-banner",
             "tls-handshake", "udp-dns", "udp-port", "icmp")


def build_catalog(probes, delay, workers, rng, host, ip, urls, qname,
                  tcp_ports, banner_jobs, tls_ports, udp_ports):
    """Single catalog of every safe rate-limit probe. Each entry: (id, label, runnable).

    tcp_ports:  ports for the tcp-connect rate check
    banner_jobs: [(port, service, use_tls)] for the banner check
    tls_ports:  ports for the TLS-handshake rate check
    udp_ports:  ANSWERING udp ports (53 -> dns query-rate check, rest -> datagram rate)
    """
    cat = []
    for u in urls:
        cat.append(("http-seq", f"http-seq -> {u}",
                    lambda u=u: [probe_http_seq(u, probes, delay, rng)]))
    for u in urls[:1]:  # parallel on the primary URL only
        cat.append(("http-parallel", f"http-parallel -> {u}",
                    lambda u=u: [probe_http_parallel(u, probes, delay, workers, rng)]))
    for p in tcp_ports:
        cat.append(("tcp-connect", f"tcp-connect -> {ip}:{p}",
                    lambda p=p: [probe_tcp_connect(ip, p, probes, delay, rng)]))
    for p, svc, use_tls in banner_jobs:
        cat.append(("tcp-banner", f"tcp-banner -> {ip}:{p}",
                    lambda p=p, svc=svc, use_tls=use_tls:
                        [probe_tcp_banner(ip, p, svc, use_tls, delay, rng)]))
    for p in tls_ports:
        cat.append(("tls-handshake", f"tls-handshake -> {ip}:{p}",
                    lambda p=p: [probe_tls_handshake(ip, p, probes, delay, rng)]))
    if 53 in udp_ports:
        cat.append(("udp-dns", f"udp-dns -> {ip}:53",
                    lambda: [probe_udp_dns(ip, qname, probes, delay, rng)]))
    for p in udp_ports:
        if p == 53:
            continue  # covered by udp-dns
        cat.append(("udp-port", f"udp-port -> {ip}:{p}",
                    lambda p=p: [probe_udp_port(ip, p, probes, delay, rng)]))
    cat.append(("icmp", f"icmp -> {host}",
                lambda: [probe_icmp(host, probes, delay, rng)]))
    return cat


# -------------------------------------------------------------------- main --
def main():
    ap = argparse.ArgumentParser(description="Safe rate-limit catalog (HTTP/TCP/UDP/ICMP) — "
                                             "non-destructive, low probe counts, no flooding")
    ap.add_argument("target", nargs="?", default=None,
                    help="IP or hostname to test (default: example.com)")
    ap.add_argument("--host", default=None, help="override display hostname / DNS qname")
    ap.add_argument("--ip", default=None, help="override target IP (skip DNS resolve)")
    ap.add_argument("--no-recon", action="store_true",
                    help="skip discovery; use static known-port lists")
    ap.add_argument("--probes", type=int, default=10, help=f"probes per check (cap {HARD_PROBE_CAP})")
    ap.add_argument("--delay", type=float, default=1.0, help=f"delay seconds (min {MIN_DELAY})")
    ap.add_argument("--workers", type=int, default=3, help=f"parallel workers (cap {MAX_PARALLEL_WORKERS})")
    ap.add_argument("--checks", default="all",
                    help=f"comma list of: {','.join(CHECK_IDS)},all")
    ap.add_argument("--tcp-ports", default="",
                    help="extra TCP ports, comma list (union with discovered)")
    ap.add_argument("--tls-ports", default="",
                    help="extra TLS ports, comma list (union with discovered)")
    ap.add_argument("--udp-ports", default="",
                    help="extra UDP ports, comma list (union with discovered)")
    ap.add_argument("--dry-run", action="store_true", help="print catalog plan, touch nothing")
    ap.add_argument("--json", default="", help="write full results to this JSON file")
    args = ap.parse_args()

    probes, delay, workers = clamp(args.probes, args.delay, args.workers)
    wanted = {c.strip() for c in args.checks.split(",")} if args.checks != "all" else None
    if wanted:
        unknown = wanted - set(CHECK_IDS) - {"all"}
        if unknown:
            print(f"Unknown check id(s): {sorted(unknown)} — valid: {','.join(CHECK_IDS)}",
                  file=sys.stderr)
            return 2
    rng = random.Random()  # nondeterministic jitter
    try:
        host, ip = resolve_target(args.target, args.host, args.ip)
    except Exception as e:
        print(f"Cannot resolve target {args.target or args.host or HOST}: {e}", file=sys.stderr)
        return 2
    print(f"Safe rate-limit catalog — target {host} ({ip}) — "
          f"probes={probes} delay>={delay}s workers={workers} (non-destructive, no flooding)")

    urls = [u.replace(HOST, host) for u in URLS]
    extra_tcp, extra_tls, extra_udp = (parse_ports(args.tcp_ports), parse_ports(args.tls_ports),
                                       parse_ports(args.udp_ports))

    if args.no_recon:
        print("(recon skipped — static known-port lists)")
        open_tcp = sorted(set(TCP_PORTS) | extra_tcp)
        udp_answering = sorted(set(UDP_PORTS) | extra_udp)
    else:
        print(f"\nPhase 1: recon on {ip} (1 connect/datagram per port — discovery only)")
        if args.dry_run:
            print(f"  PLAN tcp-sweep: {len(COMMON_TCP_PORTS)} ports")
            print(f"  PLAN udp-sweep: {len(UDP_RECON_PORTS)} ports")
            open_tcp, udp_answering = sorted(extra_tcp), sorted(extra_udp)
        else:
            open_map = recon_tcp(ip, COMMON_TCP_PORTS)
            udp_map = recon_udp(ip, UDP_RECON_PORTS)
            open_tcp = sorted(set(open_map) | extra_tcp)
            udp_answering = sorted({p for p, v in udp_map.items() if v.startswith("OPEN")}
                                   | extra_udp)
        print(f"  => open TCP: {open_tcp or 'none found'}")
        print(f"  => answering UDP: {udp_answering or 'none found'}")

    # plain-HTTP rate surface on every open web-candidate port (443 stays https)
    for p in sorted(set(open_tcp) & HTTP_CANDIDATES):
        urls.append(f"http://{ip}:{p}/")
    banner_jobs = [(p, SERVICE_NAMES.get(p, "unknown"), p in TLS_CANDIDATES)
                   for p in open_tcp]
    tls_ports = sorted(extra_tls | (set(open_tcp) & TLS_CANDIDATES))
    catalog = build_catalog(probes, delay, workers, rng, host, ip, urls,
                            host, open_tcp, banner_jobs, tls_ports, udp_answering)
    selected = [(cid, lbl, fn) for cid, lbl, fn in catalog if wanted is None or cid in wanted]
    if wanted:
        for c in sorted(wanted - {"all"} - {cid for cid, _, _ in selected}):
            print(f"  SKIP {c} — no live target for it on {ip}")

    if args.dry_run:
        for cid, lbl in ((c, l) for c, l, _ in selected):
            print(f"  PLAN {lbl}  x{probes} @ >= {delay}s")
        return

    all_results = []
    started = time.strftime("%Y-%m-%dT%H:%M:%S")
    for cid, lbl, fn in selected:
        print(f"\nCheck: {lbl}", flush=True)
        for res in fn():
            print(f"  => {res['verdict']}")
            all_results.append(res)

    print("\n=== SUMMARY ===")
    agg = Counter()
    for r in all_results:
        s = r["summary"].get("counts") or r["summary"].get("status_counts") or {}
        if not s and r["summary"].get("status"):
            s = {r["summary"]["status"]: 1}
        agg.update(s)
        print(f"{r['check']:<14} {r['target']:<55} {r['verdict']}")
    print("\nAggregate status/counts:", dict(agg))
    print("Any 429:", any(r["summary"].get("first_429") for r in all_results))
    print("Any Retry-After:", any(r["summary"].get("any_retry_after") for r in all_results))

    if args.json:
        ensure_parent(args.json)
        with open(args.json, "w") as f:
            json.dump({"target": host, "ip": ip, "started": started,
                       "probes": probes, "delay": delay, "results": all_results},
                      f, indent=2, default=str)
        print(f"Evidence written: {args.json}")


if __name__ == "__main__":
    sys.exit(main())
