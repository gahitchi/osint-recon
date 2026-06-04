# osint-recon

A **local-first, fully-automated OSINT research tool** with one overriding design
goal: **the fewest possible false positives.** Account-enumeration tools fail
when a site returns `200 OK` for *any* profile URL ("soft 404"); a naive
`200 == found` check is wrong on a large fraction of sites. osint-recon treats
that problem as the core of the system.

Inspired by [Specter](https://github.com/gahitchi/osint): deterministic (no LLM),
local-only, SSE-streamed, with identity clustering and exportable reports.

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

## Use

```bash
# CLI (scriptable, full automation)
recon --username torvalds
recon --email someone@example.com --domain example.com --format json
recon --username alice --all          # also print NOT_FOUND/ERROR rows

# Web UI (SSE live results) on http://127.0.0.1:8000
recon --serve
```

Reports (`--format json|csv|pdf`) land in `reports/` with full provenance, the
verdict reason-trail, and a legal disclaimer.

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
