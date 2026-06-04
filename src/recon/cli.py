"""Command-line entry point — scriptable full-automation runs.

  recon --username torvalds --email x@y.com --format json
  recon --domain example.com --serve   # launch the web UI instead
"""

from __future__ import annotations

import argparse
import asyncio
import sys

from .models import Finding, Query, Verdict
from .orchestrator import run_stream
from . import reporting

_COLORS = {
    Verdict.FOUND: "\033[92m", Verdict.UNCERTAIN: "\033[93m",
    Verdict.NOT_FOUND: "\033[90m", Verdict.ERROR: "\033[91m",
}
_RESET = "\033[0m"


def _line(f: Finding) -> str:
    c = _COLORS.get(f.verdict, "")
    why = f"  ({f.reasons[0]})" if f.reasons else ""
    url = f"  {f.url}" if f.url else ""
    return f"{c}{f.verdict.value:<10}{_RESET} {f.confidence:>4.2f}  {f.source:<24} {f.label}{url}{why}"


async def _run(args) -> int:
    query = Query(username=args.username, email=args.email, phone=args.phone,
                  domain=args.domain, name=args.name)
    findings: list[Finding] = []
    summary: dict = {}
    show_all = args.all

    async for ev in run_stream(query):
        if ev["type"] == "finding":
            f = Finding(**ev["finding"])
            findings.append(f)
            if show_all or f.is_hit:
                print(_line(f))
        elif ev["type"] == "summary":
            summary = ev["summary"]
        elif ev["type"] == "done":
            print(f"\n{ev['hits']} hit(s) of {ev['total']} checks.", file=sys.stderr)
        elif ev["type"] == "error":
            print(f"error: {ev['message']}", file=sys.stderr)
            return 2

    if summary.get("clusters"):
        print("\nIdentity clusters:", file=sys.stderr)
        for c in summary["clusters"]:
            print(f"  cluster {c['id']}: score {c['score']} "
                  f"({c['found']} found / {c['uncertain']} uncertain) {c['signals']}",
                  file=sys.stderr)

    if args.format:
        path = reporting.save(query.normalized(), findings, summary, args.format, args.out)
        print(f"\nreport written: {path}", file=sys.stderr)
    return 0


def main() -> None:
    p = argparse.ArgumentParser(prog="recon", description="Automated low-FP OSINT research.")
    p.add_argument("--username")
    p.add_argument("--email")
    p.add_argument("--phone")
    p.add_argument("--domain")
    p.add_argument("--name")
    p.add_argument("--all", action="store_true", help="also print NOT_FOUND/ERROR rows")
    p.add_argument("--format", choices=["json", "csv", "pdf"], help="write a report file")
    p.add_argument("--out", help="explicit output path for the report")
    p.add_argument("--serve", action="store_true", help="launch the local web UI instead")
    args = p.parse_args()

    if args.serve:
        from .server import main as serve_main
        serve_main()
        return

    if not any([args.username, args.email, args.phone, args.domain, args.name]):
        p.error("provide at least one of --username/--email/--phone/--domain/--name (or --serve)")

    raise SystemExit(asyncio.run(_run(args)))


if __name__ == "__main__":
    main()
