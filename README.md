# rate_attack_kit

Rate-limit verification, limiter-bypass testing, DoS-resilience probing,
finding verification PoCs, and a single-command engagement orchestrator —
in one directory, with machine-enforced safety caps throughout.

## 1. Overview

| Component | File | Purpose |
|---|---|---|
| Rate-limit catalog | `safe_rate_limit_catalog.py` | Base library and CLI. Phase-1 reconnaissance (77 TCP + 14 UDP ports, one probe each) and 8 rate-limit checks: `http-seq`, `http-parallel`, `tcp-connect`, `tcp-banner`, `tls-handshake`, `udp-dns`, `udp-port`, `icmp`. Imported by all other modules. |
| Custom test builder | `custom_rate_test.py` | Ad-hoc tests. URL mode (method, probe count, headers, stop-on-429, optional bypass evasions) or IP:port mode (TCP/banner/TLS/UDP/ping, optional UDP sweep). Interactive wizard when run without arguments. |
| Bypass attacks | `attack_bypass.py` | 25 limiter-evasion techniques across IP-override headers, methods, path mutations, and header/identity variations. |
| DoS resilience | `dos_resilience.py` | Slow-read patience, idle keep-alive timeout, and idle connection ceiling — one connection at a time, except the capped ceiling check. |
| Finding verification | `finding_exploits.py` | 8 read-only proof-of-concept checks (CORS, WordPress, security headers, xmlrpc, directory listing, HTTP TRACE, server banner). Maximum 2 requests per PoC. |
| Engagement orchestrator | `autopilot.py` | Six-phase chain: recon → catalog → bypass → resilience → findings → report (`evidence.json` + `report.md`). Live execution requires `--yes`. |
| Test lab | `tests/stubs.py` | Loopback fixtures for offline verification (Section 6). |

Requirements: `python3`, `requests`, `urllib3`, `openssl` CLI (used once, to
mint the throwaway self-signed certificate for the TLS stub), `curl`
(optional, for manual cross-checks).

## 2. Safety enforcement

Caps are applied in code; every run prints its request budget before sending.

| Limit | Value | Enforcement |
|---|---|---|
| Probes per check | ≤ 1000 (base catalog ≤ 100) | `custom_clamp` / `clamp` |
| Delay between requests | ≥ 0.1 s (base catalog ≥ 0.5 s), plus ±20% jitter | same |
| Parallel workers | ≤ 8 (base catalog ≤ 4) | same |
| Requests per bypass technique | ≤ 50 | `--per-variant` clamp |
| Idle connections (ceiling check) | ≤ 10, opened 1 s apart, held 5 s | `dos_resilience.py` |
| Slow/idle connections | exactly 1 at a time | `slow_read` / `idle_timeout` |
| Aggressive plans (> ~200 requests or < 0.5 s delay) | explicit y/n confirmation, default **n** (declining exits 1, nothing sent) | `aggressive_confirm`, identical in wizard and flag mode |

Explicitly out of scope by design: traffic floods of any kind, SYN floods,
UDP amplification, spoofed source addresses, credential brute force or
password spraying, and state-changing methods beyond a single static-body
POST. Bypass tests use GET/HEAD/OPTIONS only; login and authentication
endpoints are excluded.

## 3. Quick start

```bash
cd rate_attack_kit   # run everything from the project folder

# 1. Prove the tooling offline first (Section 6)
python3 tests/stubs.py        # READY http=8080 tls=8443 banner=12525 udp=15353

# 2. Plan before sending anything
python3 autopilot.py example.com --dry-run

# 3. Full engagement (--yes is the scope confirmation gate for live runs)
python3 autopilot.py example.com --yes --json ev.json --report rep.md

# 4. Interactive custom test (asks for every parameter, then confirms)
python3 custom_rate_test.py

# 5. Individual modules
python3 attack_bypass.py https://example.com/throttled-ep --per-variant 3
python3 dos_resilience.py example.com --port 443 --tls
python3 finding_exploits.py https://example.com/ --checks cors-origin,wp-users
```

## 4. Module reference

### 4.1 `custom_rate_test.py` — custom test builder

URL mode (`custom_rate_test.py https://target/path [flags]`):

| Flag | Effect |
|---|---|
| `--method` | GET/HEAD/OPTIONS, or POST with `--data` (one static body; no wordlists) |
| `--probes` / `--delay` / `--workers` | probe count / inter-request delay / parallelism (caps: 1000 / 0.1 s / 8) |
| `-H 'Name: value'` | additional header; repeatable |
| `--stop-on-429` | halt at the first 429 instead of mapping the full curve |
| `--evasions` | run bypass techniques against the same URL after the baseline |
| `--per-variant` / `--only` | requests per technique (cap 50) / technique subset, e.g. `--only xff-1,method-head`. Excluding `baseline` yields SKIPPED verdicts, since bypass cannot be judged without the control. |
| `--timeout` / `--dry-run` / `--json` | per-request timeout / print plan only / write evidence file |

Each run prints a per-request line, a status histogram (e.g.
`{'200': 2, '429': 1}`), and a verdict (`THROTTLED: HTTP 429 first seen at
request N`, `RATE-HEADERS: …`, or no-limiting-observed).

IP:port mode (`custom_rate_test.py --ip 10.0.0.5 --port 443 [flags]`):

| Flag | Effect |
|---|---|
| `--layer-checks` | comma-separated subset of `tcp,banner,tls,udp,ping` (default `all`; unknown names are rejected) |
| `--tls` | TLS-wrapped banner grab and handshake check (suggested by default in the wizard for TLS-candidate ports) |
| `--udp-sweep` | sweep 14 common UDP ports with one datagram each, then rate-test responders |
| `--dry-run` / `--json` | as above |

Wizard (no arguments, or `--wizard`): prompts for target kind (`url`/`ip`)
and every applicable parameter with defaults (Enter accepts), presents the
numbered evasion menu with `all` support, prints a recap plan with
total-request math, applies the aggressive-plan gate when triggered, and
requires a final run/cancel confirmation. EOF or Ctrl-C cancels with
"nothing was sent".

### 4.2 `attack_bypass.py` — 25 techniques, 5 verdicts

```bash
python3 attack_bypass.py https://target/throttled-endpoint --per-variant 3
python3 attack_bypass.py https://target/ --only baseline,xff-1,method-head --json out.json
python3 attack_bypass.py https://target/ --dry-run
```

| Group | Techniques |
|---|---|
| Baseline (control) | `baseline` — unmodified GET |
| IP-override headers | `xff-1`–`xff-5` (rotating X-Forwarded-For), `x-real-ip`, `x-orig-ip`, `x-client-ip`, `cf-ip`, `xff-host` |
| Methods | `method-head`, `method-options` |
| Path mutations | `trail-slash`, `dbl-slash`, `dot-seg`, `query-junk`, `cache-bust`, `case-path` |
| Header/identity | `referer-evil`, `via-evil`, `accept-json`, `cookie-junk`, `ua-mobile`, `ua-curl` |

| Verdict | Criterion |
|---|---|
| `HELD` | baseline rate-limited and the variant is also rate-limited — limiter applies uniformly |
| `BYPASSED` | baseline rate-limited but the variant returns clean 2xx/3xx — **finding** |
| `NO-LIMITER` | baseline never rate-limited — nothing to bypass |
| `INEFFECTIVE` | baseline rate-limited but the variant only errors or 404s — no signal, not a bypass |
| `SKIPPED` | `--only` excluded `baseline` — re-run including it before drawing conclusions |

A `FINDING: rate limit bypassed via: [...]` line is printed when any
technique bypasses.

### 4.3 `dos_resilience.py` — 3 probes

```bash
python3 dos_resilience.py example.com --port 443 --tls
python3 dos_resilience.py example.com --port 80 --checks slow-read
python3 dos_resilience.py example.com --port 443 --tls --dry-run --json out.json
```

| Check | Procedure | Interpretation |
|---|---|---|
| `slow-read` | 1 connection, partial GET, 1-byte reads, ≤ 20 s | Server holds the trickle connection → Slowloris exposure (`PATIENT SERVER`); early close → mitigated |
| `idle-timeout` | 1 keep-alive connection, full GET, then idle ≤ 15 s | Lingering idle slot → keep-alive-timeout finding; prompt close → mitigated |
| `conn-ceil` | ≤ `--max-conns` (cap 10) idle connections, 1 s stagger, 5 s hold | Accepted/refused split approximates the per-IP ceiling; all-accepted → ceiling above N |

`--checks` accepts any comma-separated subset (unknown names exit 2). All
sockets close via context managers or `finally` paths, so an interrupted run
still releases its connections.

### 4.4 `finding_exploits.py` — 8 verification PoCs

```bash
python3 finding_exploits.py https://target/
python3 finding_exploits.py https://target/ --checks cors-origin,wp-users
python3 finding_exploits.py https://target/ --dry-run --json out.json
```

| PoC | Confirmed when |
|---|---|
| `cors-origin` | `Access-Control-Allow-Origin: *`, or reflection of a hostile Origin (escalated by `Allow-Credentials: true`) |
| `wp-users` | `/wp-json/wp/v2/users` returns a user list unauthenticated (slugs sampled, maximum 10) |
| `wp-version` | generator meta tag or `readme.html` discloses the WordPress version |
| `sec-headers` | any of CSP / X-Frame-Options / HSTS / X-Content-Type-Options / Referrer-Policy missing |
| `xmlrpc` | `xmlrpc.php` responds (pingback / brute-force surface) |
| `dir-listing` | `/wp-content/uploads/` returns `Index of /` |
| `http-trace` | TRACE echoes the request (XST surface); 405/501 means disabled |
| `server-banner` | version-numbered `Server` / `X-Powered-By` (versionless banner is acceptable, absent is clean) |

Non-confirming statuses (401/403/404) are reported as not-exposed rather
than as failures. Each PoC is exception-isolated so one target's behavior
cannot abort the remainder.

### 4.5 `autopilot.py` — engagement orchestrator

```bash
python3 autopilot.py example.com --dry-run
python3 autopilot.py example.com --yes --json ev.json --report rep.md
python3 autopilot.py 10.0.0.5 --yes --skip resilience,bypass --probes 5
python3 autopilot.py 127.0.0.1 --yes --base http://127.0.0.1:8080/   # lab run
```

Phases (selectable via `--skip`; unknown phase names exit 2):

1. **recon** — one connect per common TCP port, one datagram per common UDP port.
2. **catalog** — base rate checks against the site root and every open web port (`https://` for TLS-candidate ports, `http://` otherwise), plus TCP/banner/TLS/UDP/ICMP checks on open ports.
3. **bypass** — all 25 techniques against every HTTP endpoint from phase 2. Unprotected endpoints yield NO-LIMITER baselines; they are still tested and reported.
4. **resilience** — slow-read, idle-timeout, and connection-ceiling checks against ports 80/443 and any other open web port (TLS ports wrapped accordingly).
5. **findings** — all 8 PoCs against `--base` (default `https://<target>/`; override with `http://…` when 443 is closed, or a loopback port in the lab).
6. **report** — `evidence.json` (every record) and `report.md` (verdict lines). Output parent directories are created automatically.

Live runs are refused without `--yes`, which constitutes the scope
confirmation. `--dry-run` lists all six phases without transmitting
anything. `--probes`/`--delay`/`--workers` pass through the base-catalog
clamp (100 / 0.5 s / 4); bypass uses `min(probes, 5)` per variant.

## 5. Rules of engagement

1. Run `--dry-run` against any new target first, and read the plan line (it shows total request math) before anything is sent.
2. Live autopilot runs require `--yes` — that flag is the scope confirmation.
3. If a check returns 429, back off; `--stop-on-429` exists for this purpose.
4. A bypass finding means limiter logic is keyed on something spoofable — report the technique list verbatim rather than escalating into the bypassed endpoint.
5. Never retarget this tooling outside written authorization, and never "confirm" a finding by testing harder against production.

## 6. Verification

### 6.1 Loopback test lab (`tests/stubs.py`)

Four fixtures on 127.0.0.1; every example in this document runs against them:

| Port | Fixture | Coverage |
|---|---|---|
| 8080 (HTTP) | `/app` limiter (3×200 then 429 + Retry-After; IP-override headers always 200; HEAD/OPTIONS always 200; unknown paths 404), fake WordPress surface (`/`, users REST, readme, xmlrpc, uploads listing, CORS `*`, versioned banner, absent security headers), `/open` (always 200) | THROTTLED, BYPASSED / HELD / INEFFECTIVE / NO-LIMITER, all 8 PoCs |
| 8443 (HTTPS) | identical fixture over TLS (self-signed `tests/test-cert.pem`, auto-minted) | tls-handshake, TLS resilience, `--tls` IP mode |
| 12525 (TCP) | serves `SSH-2.0-TestStub` on connect | banner-grab verdict path |
| 15353 (UDP) | echoes `echo:<payload>` | udp-port and sweep-responder path |

```bash
python3 tests/stubs.py            # foreground; READY line when up; Ctrl-C stops
kill $(cat tests/stubs.pid)       # stop a backgrounded instance
```

Verified matrix (2026-10-11, loopback, all passing): full 25-technique
bypass run (all 5 verdict classes, including 11 BYPASSED and a case-path
INEFFECTIVE), 8/8 PoCs CONFIRMED, custom URL + IP + UDP-sweep + TLS + ping
modes, both wizards end to end, all three resilience checks, both answers of
the aggressive gate, and a complete 6-phase autopilot (10 catalog checks,
3 bypass targets, 6 resilience results, 8 findings — see `tests/out/`).

### 6.2 Production verification

Beyond the loopback lab, the full suite has been executed against an
authorized production target with light probing only (≤ 3 requests per
check, ≥ 1.0 s delay; bypass 1 request × a 3-technique subset; resilience
as single-connection probes plus a capped 8-connection ceiling). Results:
no HTTP/TCP/TLS/ICMP limiting observed on the assessed endpoints, bypass
correctly reporting NO-LIMITER where nothing was throttled, all three
resilience checks returning clean verdicts (including one slow-read
patience finding for timeout-config review), and finding PoCs confirming
the expected subset.

Target-specific evidence (hostnames, addresses, banners, finding details)
is engagement-confidential and intentionally excluded from this repository
— see `.gitignore` (`out-live*`, `*.log`). Keep production evidence in
private engagement storage, never in git.
