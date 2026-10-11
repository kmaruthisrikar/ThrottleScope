# Rate-limit engagement — 127.0.0.1 (127.0.0.1)
_UTC 2026-10-11T12:19:24 — capped probes, no flooding_

## Verdicts
- [http-seq] https://127.0.0.1/: no rate limiting observed (no 429, no Retry-After, no rate headers)
- [http-seq] http://127.0.0.1:8080/: no rate limiting observed (no 429, no Retry-After, no rate headers)
- [http-seq] https://127.0.0.1:8443/: no rate limiting observed (no 429, no Retry-After, no rate headers)
- [http-parallel] https://127.0.0.1/: no rate limiting observed (no 429, no Retry-After, no rate headers)
- [tcp-connect] 127.0.0.1:8080: no TCP-level restriction (all connects accepted)
- [tcp-connect] 127.0.0.1:8443: no TCP-level restriction (all connects accepted)
- [tcp-banner] 127.0.0.1:8080 (unknown): port connected; no server banner within 3s
- [tcp-banner] 127.0.0.1:8443 (https-alt/tls): port connected; no server banner within 3s
- [tls-handshake] 127.0.0.1:8443: no TLS-level restriction (all handshakes completed)
- [icmp] 127.0.0.1: no ICMP rate limiting observed (3/3 replies)
- [bypass] http://127.0.0.1:8080/: limiter held
- [bypass] https://127.0.0.1/: limiter held
- [bypass] https://127.0.0.1:8443/: limiter held
- [slow-read:8080] PATIENT SERVER: held our 1B/s connection 21s (0B) — slow-read exposure, confirm timeout config
- [idle-timeout:8080] PATIENT SERVER: idle keep-alive survived 18s (304B) — idle slots linger, confirm keep-alive timeout
- [conn-ceil:8080] all 8 idle connections accepted — per-IP ceiling above 8 (raise max-conns only in lab)
- [slow-read:8443] PATIENT SERVER: held our 1B/s connection 21s (0B) — slow-read exposure, confirm timeout config
- [idle-timeout:8443] PATIENT SERVER: idle keep-alive survived 18s (304B) — idle slots linger, confirm keep-alive timeout
- [conn-ceil:8443] all 8 idle connections accepted — per-IP ceiling above 8 (raise max-conns only in lab)
- [cors-origin] CONFIRMED: ACAO '*' — any site can read responses (anonymous impact; worse with credentials)
- [wp-users] CONFIRMED: 2 WP users disclosed (['admin', 'editor']) — feeds password-spray targeting
- [wp-version] CONFIRMED version leak: {'generator': '<meta name="generator" content="WordPress 6.4.1" />', 'readme': 'exposed'}
- [sec-headers] CONFIRMED missing: ['Content-Security-Policy', 'X-Frame-Options', 'Strict-Transport-Security', 'X-Content-Type-Options', 'Referrer-Policy']
- [xmlrpc] CONFIRMED: xmlrpc.php responds (status=200) — pingback/brute-force surface, recommend disabling if unused
- [dir-listing] CONFIRMED: directory listing on /wp-content/uploads/ — file disclosure, disable auto-index
- [http-trace] CONFIRMED: TRACE echoes requests (XST surface) — disable TRACE/TRACK
- [server-banner] CONFIRMED versioned banner: {'Server': 'Apache/2.4.41 , Apache/2.4.41', 'X-Powered-By': 'PHP/7.4.3'} — aids targeted CVE mapping, strip versions
