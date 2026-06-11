# osint-recon

A **local-first, professional-grade OSINT investigation framework**. It keeps the
original overriding goal — **the fewest possible false positives** (soft-404s
where a site returns `200 OK` for *any* profile URL are rejected, not reported) —
and builds a full investigation platform around it: a **probabilistic correlation
engine + identity graph**, **durable persistence**, **long-term monitoring with
change detection**, and a **pluggable scale-out** path.

Inspired by [Specter](https://github.com/gahitchi/osint): deterministic (no LLM),
local-only, SSE-streamed, with identity clustering and exportable reports.

## What this is — and isn't

OSINT automation does **not** produce a finished "target profile". This tool is a
*discovery + verification + correlation* aid that is explicit about uncertainty:

- It separates **discovery** (broad, noisy candidates) from **verification**
  (strict, calibrated) and labels which phase produced each hit.
- Every result is one of **FOUND / UNCERTAIN / UNVERIFIABLE / NOT_FOUND** with an
  explainable `reasons[]` trail — **a bare `200 OK` never becomes a confident
  FOUND**, and a bot-wall/CAPTCHA becomes **UNVERIFIABLE**, never a guess.
- Correlation is **probabilistic**: ambiguous matches are surfaced for REVIEW, not
  silently merged.

It does not replace human analysis, and it cannot defeat platform anti-bot
defenses — it reports honestly when it is blocked. **Authorized / educational use
only.**

## How it answers the common failure modes of recon wrappers

| Common flaw | How osint-recon addresses it |
|---|---|
| **1. False sense of accuracy** (treats tool output as truth) | Multi-layer verify engine: control-probe baseline + site rule + content-similarity → FOUND/UNCERTAIN/NOT_FOUND; never "200 = found" (`verify/`) |
| **2. No normalization** | One normalization layer for usernames/emails/domains/URLs/platforms, used by both queries and correlation (`normalize.py`) |
| **3. No confidence scoring** | Per-finding confidence + per-source reliability + reliability-weighted entity confidence + **conflict resolution** picking canonical values by trust (`correlate/confidence.py`, `graph.py`) |
| **4. Brittle scraping** | Per-site detection rules + **soft-404 baseline**; circuit breakers + result cache so site changes/outages degrade gracefully (`connectors/`) |
| **5. No adversarial-defense handling** | Detects Cloudflare/Akamai/DataDome/PerimeterX/Imperva/CAPTCHA/JS-gate/rate-limit → **UNVERIFIABLE** instead of a false verdict (`verify/defenses.py`) |
| **6. recon vs verification mixed** | Explicit **phase** label (`discovery` vs `verified`) on every hit |
| **7. Hard dependency chains** | Pure-Python; shells out to **no** external CLI tools (no Sherlock/social-analyzer subprocesses), so nothing breaks on rolling distros |
| **8. No reproducibility** | Deterministic seeded probe mode (`RECON_DETERMINISTIC=1`), pinned `requirements.lock`, and provenance (tool/dataset hash/dep versions/thresholds) stamped into every report (`provenance.py`) |
| **9. Output not intelligence-ready** | Persistent identity graph: clustering, de-duplication, relationship edges, confidence (`correlate/`, `store/`) |
| **10. "run this → full profile" misconception** | The framing above; honest UNVERIFIABLE/REVIEW states; disclaimers on every export |

## What's new in v0.2 (framework upgrade)

| Capability | Where |
|---|---|
| **Durable storage** (targets, runs, observations, entities, jobs) — SQLite by default, Postgres by DSN | `src/recon/store/` |
| **Connector framework**: result cache, **circuit breakers**, per-source **reliability** scoring → re-runs don't depend on live APIs and a dead source can't stall a scan | `src/recon/connectors/` |
| **Probabilistic correlation + identity graph**: blocking → Fellegi–Sunter-style weighted matching (Jaro-Winkler names) → MERGE/REVIEW/DISTINCT, with coherence/contradiction checks and confidence propagation | `src/recon/correlate/` |
| **Long-term monitoring**: cron **scheduler** + run-over-run **change detection** (appeared/disappeared/changed via content fingerprint) | `src/recon/monitor/` |
| **Scalability**: scans become **durable jobs**; in-process worker pool by default, optional Redis/arq workers + cross-process rate limiting | `src/recon/jobs/`, `ratelimit.py` |
| **Dashboard + API**: investigations, timeline, identity graph, **interactive discovery map**, source-health, and **modules/keys** tabs | `src/recon/server.py`, `web/` |

These directly address the prior limitations: immature correlation, hard
dependence on live APIs/scrapers, limited scalability, and source-driven output
quality (now weighted by tracked reliability + contradiction checks).

## What's new in v0.3 — the recursive engine

A scan is no longer a single pass over the seed identifiers. It is now an
**event-driven graph traversal**: seeds become typed **artifacts**, each artifact
is dispatched to every **module** that consumes its type, and modules emit *new*
artifacts that are fed back into the frontier until it drains. This is the
auto-pivoting behavior that defines tools like SpiderFoot — but kept honest with
hard ceilings and a scope policy, and feeding the same low-false-positive verify
engine.

| Capability | Where |
|---|---|
| **Recursive traversal**: `domain → subdomains → IPs → ASN/netblock`, `email → domain + username pivot`, `username → profile → cross-linked handles/emails` | `src/recon/engine.py`, `src/recon/modules/` |
| **Typed artifact graph** (nodes + provenance edges), distinct from the identity-cluster graph | `src/recon/graph_models.py`, `store/models_db.py` (`artifacts`, `artifact_edges`) |
| **Bounded & scoped**: `max_depth` / `max_artifacts` / `max_requests` ceilings + `strict`/`aggressive` scope so recursion never runs away or wanders off-target | `config.py`, `engine.ScopePolicy` |
| **Keyless recursive modules**: DNS resolution, **Team Cymru** IP→ASN (DNS whois, no key), profile-link enrichment, Wayback CDX | `src/recon/modules/{resolve,asn,profile_links,wayback}.py` |
| **Keyless-first, keys optional**: a module declares `requires_keys`; the engine skips it when keys are absent, so commercial sources (Shodan/HIBP/VT) can plug in later | `src/recon/keys.py` |

```bash
recon scan --domain example.com --max-depth 2 --scope strict
recon graph --run 1          # depth-indented artifact tree (the pivot chain)
recon serve                  # dashboard: interactive force-directed Discovery map,
                             # plus a Modules & keys tab to manage optional API keys
```

### Source catalogue (v0.3 modules)

18 modules feed the engine; new sources are cheap to add (one `Module` in
`src/recon/modules/`, registered in `registry.py`). All flow through the same
verify/reliability/scope machinery, so breadth arrives without the usual noise.

| Family | Modules (keyless unless noted) |
|---|---|
| Accounts | `username` (curated seed **or full WhatsMyName 600+**), `github` (profile + **commit-email harvest**; key-enhanced), `profile_links` (cross-linked handles/emails) |
| Email / breach | `email` (Gravatar/MX), `breach` (XposedOrNot; HIBP if keyed) |
| Domain / DNS | `domain` (DNS/RDAP/crt.sh), `dns_intel` (SPF/DMARC/CAA + SPF-derived infra), `wayback`, `commoncrawl` |
| Network | `resolve` (→IP), `asn` (Team Cymru), `ripestat` (RIR prefixes + abuse contact), `ip_geo` (ip-api) |
| People | `phone` (offline libphonenumber), `name` (ORCID/OpenAlex) |
| Keyed, optional | `shodan`, `virustotal`, `abuseipdb` — auto-skipped unless the key is set |

```bash
# Broaden username coverage to the full WhatsMyName dataset (opt-in):
python scripts/fetch_wmn.py
RECON_SITES_FILE=data/wmn-data.json recon scan --username torvalds

# Optional keys: env (RECON_KEY_SHODAN=...) or ~/.config/osint-recon/keys.toml
#   [keys]
#   shodan = "..."   # also: virustotal, abuseipdb, github, hibp
```

## What's new in v0.4 — the dashboard, made interactive

The recursive engine of v0.3 produced a rich artifact graph but only exposed it as
JSON. v0.4 makes it (and the keyless-first key model) **visible and operable from
the browser** — no new dependencies, no CDN, no build step.

| Capability | Where |
|---|---|
| **Discovery map**: a self-contained **force-directed** render of a run's artifact graph on `<canvas>` — drag nodes, scroll to zoom, pan, hover for type/value, click for provenance (depth · module · confidence). Nodes colored by artifact type. | `web/app.js` (`startSim`), `web/index.html` |
| **Module catalogue**: every module the engine can dispatch — what it consumes/produces, keyless vs keyed, and whether it's currently **enabled** (keyless, or key present) | `GET /api/modules`, `web/` Modules & keys tab |
| **API-key management**: set/clear the optional keys from the UI; stored locally in `keys.toml` (0600). Values are **never** returned by the API — only configured/source status. | `GET/POST /api/keys`, `keys.KeyVault` |

```bash
recon serve     # open http://127.0.0.1:8000 → Discovery map · Modules & keys tabs
```

## What it does

Give it any of: **username, email, phone, domain, real name.** It runs every
relevant collector concurrently with no further interaction and streams verdicts
as they resolve, then clusters them into candidate identities.

| Input | Sources |
|-------|---------|
| username | site fanout across `data/sites.json`, each run through the FP engine |
| email | Gravatar existence (+hash signal), MX/deliverability, username pivot |
| phone | offline libphonenumber: validity, region, carrier, line type, timezones |
| domain | DNS (A/AAAA/MX/NS/TXT), RDAP registration, crt.sh subdomains |
| name | ORCID & OpenAlex structured author records (fuzzy-gated) |

## The false-positive engine (`src/recon/verify/`)

Every candidate URL passes a layered, **explainable** verdict pipeline. A site is
`FOUND` only after surviving all applicable layers; ambiguous cases become
`UNCERTAIN` (shown, flagged) — never a silent false `FOUND`.

- **Layer 0 — control-probe baseline** (`baseline.py`): probe each site with a
  random *known-absent* username, learn its "no such user" status / redirect /
  body fingerprint, cache per host. Everything is judged relative to this.
- **Layer 1 — site rule** (`rules.py`): WhatsMyName-style `status_code` /
  `message` / `response_url` detection from `data/sites.json`.
- **Layer 2 — redirect / final-URL** vs the absent baseline.
- **Layer 3 — content fingerprint diff** (`similarity.py`): SimHash similarity to
  the absent baseline; high similarity ⇒ soft-404 ⇒ rejected. Plus positive
  signals (queried term in body/title).
- **Layer 4 — verdict** (`verdict.py`): combine into `FOUND/NOT_FOUND/UNCERTAIN`
  with a confidence score and a `reasons[]` trail. **A bare 200 never becomes a
  confident FOUND on its own.** Thresholds live in `config.py`.

## Install

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"          # add ,pdf for PDF export: ".[dev,pdf]"
```

### One-word launch: `specter`

Install a terminal command that wakes the **whole stack** (dashboard server +
background worker + monitoring scheduler) and opens the dashboard in a **Firefox**
tab:

```bash
./scripts/install-specter.sh      # installs `specter` into ~/.local/bin
specter                           # boots everything + opens Firefox
```

`specter` is idempotent: if the stack is already running it just opens the tab.
Flags: `--no-browser` (headless), `--no-workers` (server only), `--port N`.
Ctrl-C shuts the stack down cleanly.

## Use

```bash
# Durable, correlated, persisted scan (full automation)
recon scan --username torvalds --email someone@example.com
recon scan --domain example.com --format json
recon scan --username alice --all                 # also show NOT_FOUND/ERROR

# Long-term monitoring: watch a target on a cron, then run the scheduler + a worker
recon scan --username torvalds --watch "0 */6 * * *"
recon monitor        # fires schedules -> enqueues jobs
recon worker         # processes queued scan jobs (run several to scale out)

# Inspect stored investigation data
recon targets | recon runs | recon changes | recon sources

# Web dashboard + API on http://127.0.0.1:8000
recon serve
```

Back-compat: `recon --username x` (bare flags) still works and maps to `scan`.
Reports (`--format json|csv|pdf`) land in `reports/` with full provenance, the
verdict reason-trail, and a legal disclaimer.

## Scaling out (optional)

Everything defaults to local-first (SQLite + in-process workers). To scale:

```bash
pip install -e ".[postgres,distributed]"
export RECON_DB_DSN="postgresql+psycopg://user:pass@host/recon"
export RECON_REDIS_DSN="redis://localhost:6379"
# set queue_backend = "arq" in config; run many `recon worker` processes
```

No code changes — same `JobQueue`/`Store` interfaces, shared cross-process rate
limiting keeps a fleet polite.

## Tuning precision vs recall

Edit `src/recon/config.py`:
- `baseline_similarity_reject` (default 0.92) — higher = stricter soft-404 culling.
- `found_confidence` / `uncertain_confidence` — verdict thresholds.

We deliberately prefer marking a real-but-ambiguous hit `UNCERTAIN` over emitting
a wrong `FOUND`.

## Refreshing the site list

`data/sites.json` is a small curated seed using the WhatsMyName `wmn-data.json`
schema. Drop in more entries (or the full WhatsMyName dataset) to broaden
coverage; auth-walled / ToS-restricted sites are excluded by default via
`config.excluded_site_tags`.

## Ethics & legal

For **authorized research and educational use only.** Local-first (binds
`127.0.0.1`), respects `robots.txt`, rate-limits per host, and sends an
identifying User-Agent. Auth-walled platforms (Instagram, Discord, Facebook,
X/Twitter, LinkedIn, Snapchat) are excluded by default. You are responsible for
complying with applicable law and each site's terms.

## Tests

```bash
pytest -q
```

The acceptance gate is `tests/test_verify_verdict.py`: soft-404s (200 + generic
not-found body) must resolve to `NOT_FOUND`, genuine profiles to `FOUND`.
