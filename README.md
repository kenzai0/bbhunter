# bbhunter

A scope-first bug bounty recon & automation framework. Pure Python, minimal
dependencies. It combines subdomain enumeration, live-host detection, technology
fingerprinting, content discovery, archive/JS analysis and template-based
vulnerability scanning into a single pipeline.

> **Authorization notice.** This tool is intended **only** for targets you are
> authorized to test: assets within the scope of a bug bounty program (VDP /
> HackerOne / Bugcrowd / Intigriti / `security.txt`), or systems you own. The
> scope engine enforces this technically — but legal responsibility rests with
> the user. Sending requests to out-of-scope targets both violates the program
> and creates legal risk.

## Why "scope-first"?

Every request is validated against the **scope engine** inside `HttpClient`. If a
request is attempted against an out-of-scope host, an `OutOfScopeError` is raised.
Passive data sources (crt.sh, Wayback) are limited by a separate allowlist and do
not touch the target. As a result, it is hard to touch an unauthorized asset even
by accident. The scope is **fail-closed**: if the in-scope list is empty, nothing
is in scope.

## Installation

As a package (recommended) — adds the `bbhunter` command to PATH:

```bash
pip install -e .            # core (requests)
pip install -e ".[full]"    # + dnspython + pyyaml (full features)
```

After that `bbhunter ...` works directly (you can write `bbhunter` instead of
`python -m bbhunter` in the examples below).

Alternative (without packaging):

```bash
pip install -r requirements.txt
python -m bbhunter ...
```

`dnspython` and `pyyaml` are optional: without `dnspython`, DNS resolution falls
back to `socket`; without `pyyaml`, Nuclei import falls back to a built-in
mini-parser.

## Quick start

```bash
# 1) Validate scope (sends no requests)
python -m bbhunter scope --scope example.scope --test example.com evil.com sub.example.com

# 2) Recon only
python -m bbhunter recon example.com --scope example.scope

# 3) Full pipeline (recon + discovery + probe + vuln + report)
python -m bbhunter full example.com --scope example.scope --ports --min-severity low

# 4) Regenerate the report
python -m bbhunter report --out bbhunter_out
```

If you do not pass a scope file, the domains on the command line are treated as
in-scope:

```bash
python -m bbhunter full example.com --exclude blog.example.com
```

## Commands

| Command | What it does |
|---|---|
| `scope` | Loads, summarizes and tests the scope against targets (sends no requests) |
| `recon` | Subdomains (crt.sh + DNS brute) → live hosts → fingerprint (+ `--ports`) |
| `discover` | Wayback URLs → parameter discovery → JS analysis → directory fuzzing |
| `takeover` | Detects subdomain-takeover candidates (CNAME + signature) |
| `probe` | Reflected-parameter probes: XSS candidate, open-redirect, SSRF candidate (non-destructive) |
| `vuln` | Template-based, non-destructive vulnerability scan |
| `nuclei-import` | Converts Nuclei YAML templates into the engine's JSON format |
| `full` | Runs everything in order and produces a report |
| `report` | Regenerates `report.md` + `report.json` from the SQLite store |

## Key flags

- `--rate` : max requests per second (default 10). For politeness + rate limiting.
- `--threads` : number of parallel worker threads.
- `--jitter` : random delay between requests (seconds).
- `--timeout` : request timeout.
- `--sub-wordlist` : external wordlist for subdomain brute (otherwise a small built-in list).
- `--templates` : additional JSON vulnerability templates (directory or file).
- `--min-severity` : minimum severity to include in the report.
- `--header` : custom header added to all requests (repeatable), e.g.
  `--header 'X-HackerOne-Research:username'`.

## Output

Under `bbhunter_out/`:
- `bbhunter.db` — SQLite store (assets + findings, deduplicated, persists across scans)
- `report.md` — human-readable Markdown report
- `report.json` — machine-readable report
- `report.html` — self-contained HTML report (inline SVG charts, severity filter,
  no external dependencies, opens offline)

## Architecture

```
bbhunter/
  scope.py          Scope engine (in/out, wildcard, CIDR, fail-closed)
  http_client.py    Scope-aware, rate-limited HTTP client
  sources.py        Passive data sources (crt.sh, Wayback) - allowlisted
  config.py         Runtime configuration
  util.py           Logging, parallel execution
  recon/
    dns.py          DNS resolution (dnspython optional) + wildcard detection
    subdomains.py   crt.sh passive + DNS brute
    ports.py        TCP connect port scanner
    livehosts.py    HTTP(S) live-host detection
    fingerprint.py  Technology fingerprinting
    takeover.py     Subdomain takeover detection (CNAME + dangling-resource signature)
  discovery/
    wayback.py      Archive URL collection
    params.py       Parameter discovery
    jsanalyze.py    Endpoint + possible-secret extraction from JS
    content.py      Directory/endpoint fuzzing (soft-404 filtered)
  probe/
    reflected.py    Reflected-parameter probes: XSS candidate (canary + special-char
                    survival), open-redirect candidate, SSRF candidate classification
  vuln/
    engine.py       Template engine (matchers: status/word/regex/header)
    templates.py    Built-in non-destructive signatures
    nuclei.py       Nuclei YAML template -> engine format converter
  report/
    store.py        SQLite asset/finding store (dedup)
    report.py       Markdown + JSON report
    html.py         Self-contained HTML report + inline SVG charts
  pipeline.py       Orchestration
  cli.py            Command-line interface
```

## Writing templates

Templates are JSON. Example:

```json
{
  "id": "example-open-file",
  "name": "Example open file",
  "severity": "medium",
  "requests": [{
    "method": "GET",
    "path": "/example.bak",
    "matchers_condition": "and",
    "matchers": [
      {"type": "status", "values": [200]},
      {"type": "word", "part": "body", "words": ["secret"], "condition": "or"}
    ]
  }]
}
```

Matcher types: `status`, `word` (part: body/header/status/all),
`regex` (patterns + condition), `header` (name + regex/value).
Any matcher can be negated with `"negative": true`.

> The engine rejects destructive methods (DELETE/PUT, etc.); it only performs
> detection, not exploitation.

## Subdomain takeover (`takeover`)

Resolves each subdomain's CNAME; catches those that point to a known service
(GitHub Pages, S3, Heroku, Azure, Shopify, Fastly, Pantheon, Tumblr, Ghost, Surge,
Bitbucket, Zendesk...) but are **dangling/unclaimed**, via the service's
"no resource here" signature. It runs automatically as part of recon, and also
standalone:

```bash
python -m bbhunter takeover --scope example.scope          # subdomains in the store
python -m bbhunter takeover sub.example.com --scope example.scope
```

- **high** — CNAME points to a service **and** the dangling-resource signature matched.
- **medium** — only the signature matched (CNAME not confirmed) or the CNAME is dangling.

> This module does NOT actually take over the subdomain; it only gathers evidence.
> The claim step is done MANUALLY per the program's rules. `dnspython` is
> recommended for CNAME detection. Every candidate must be verified manually
> (services change over time).

## Reflected-parameter probe (`probe`)

Non-destructive probes over discovered parameters. It does **candidate detection**;
it does not produce a working exploit — verification is left to the researcher.

- **XSS candidate** — injects a harmless canary and measures whether the reflection
  and special characters like `< > " ' ...` come back un-encoded.
- **Open-redirect candidate** — places a harmless, non-resolving `.example` host in
  `url/next/redirect/...` parameters; checks Location / meta-refresh / JS redirect.
- **SSRF candidate** — flags parameters that appear to take a URL/host for **manual
  review** only; it does not perform active SSRF (OOB) testing.

```bash
# over parameterized URLs in the store, after discover
python -m bbhunter probe --scope example.scope

# on specific URLs
python -m bbhunter probe 'https://app.example.com/?next=x' --scope example.scope
```

## License

MIT — see [LICENSE](LICENSE).
