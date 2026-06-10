"""Command-line entry point.

  recon scan --username torvalds [--email x@y.com] [--format json] [--watch "0 */6 * * *"]
  recon serve            # local web dashboard + API
  recon worker           # process queued scan jobs (run N of these to scale)
  recon monitor          # run the cron scheduler for watch-listed targets
  recon targets|runs|changes|sources   # inspect stored investigation data

Back-compat: `recon --username x` (no subcommand) defaults to `scan`.
"""

from __future__ import annotations

import argparse
import asyncio
import sys

from .models import Finding, Query, Verdict

_COLORS = {
    Verdict.FOUND: "\033[92m", Verdict.UNCERTAIN: "\033[93m",
    Verdict.UNVERIFIABLE: "\033[95m",  # magenta — bot-wall/WAF/etc.
    Verdict.NOT_FOUND: "\033[90m", Verdict.ERROR: "\033[91m",
}
_RESET = "\033[0m"


def _line(f: Finding) -> str:
    c = _COLORS.get(f.verdict, "")
    why = f"  ({f.reasons[0]})" if f.reasons else ""
    url = f"  {f.url}" if f.url else ""
    return f"{c}{f.verdict.value:<10}{_RESET} {f.confidence:>4.2f}  {f.source:<26} {f.label}{url}{why}"


def _add_identifier_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--username")
    p.add_argument("--email")
    p.add_argument("--phone")
    p.add_argument("--domain")
    p.add_argument("--name")


# --- scan ------------------------------------------------------------------

async def _cmd_scan(args) -> int:
    import dataclasses

    from .orchestrator import scan
    from .config import SETTINGS
    from . import reporting

    query = Query(username=args.username, email=args.email, phone=args.phone,
                  domain=args.domain, name=args.name)
    if query.normalized().is_empty():
        print("provide at least one identifier", file=sys.stderr)
        return 2

    overrides: dict = {}
    if args.max_depth is not None:
        overrides["max_depth"] = args.max_depth
    if args.scope:
        overrides["scope_mode"] = args.scope
    if args.passive is not None:
        overrides["passive_only"] = args.passive
    settings = dataclasses.replace(SETTINGS, **overrides) if overrides else SETTINGS

    watch = bool(args.watch)
    result = await scan(query, label=args.label, watchlist=watch, settings=settings)

    findings = result["findings"]
    for f in findings:
        if args.all or f.is_notable:
            print(_line(f))

    summary = result["summary"]
    if summary.get("clusters"):
        print("\nIdentities (correlated):", file=sys.stderr)
        for c in summary["clusters"]:
            flag = f" [{','.join(c['flags'])}]" if c.get("flags") else ""
            print(f"  #{c['id']} {c['label']}: score {c['score']} "
                  f"({c['found']} found/{c['uncertain']} uncertain){flag}", file=sys.stderr)

    if result["changes"]:
        print("\nChanges since last run:", file=sys.stderr)
        for ch in result["changes"]:
            print(f"  {ch['kind']:<11} {ch['source']} {ch['label']}", file=sys.stderr)

    stop = f"  (stopped: {result['stop_reason']})" if result.get("stop_reason") else ""
    print(f"\nrun #{result['run_id']} — {sum(1 for f in findings if f.is_hit)} hit(s) "
          f"of {len(findings)} checks; {len(result.get('artifacts', []))} artifact(s) "
          f"discovered.{stop}", file=sys.stderr)

    if watch and args.watch:
        from .store import get_db, repo
        from .monitor.scheduler import validate_cron
        if not validate_cron(args.watch):
            print(f"warning: invalid cron '{args.watch}', schedule not created", file=sys.stderr)
        else:
            db = get_db()
            with db.session() as s:
                repo.create_schedule(s, result["target_id"], args.watch)
            print(f"watch scheduled: '{args.watch}' (run `recon monitor`)", file=sys.stderr)

    if args.format:
        path = reporting.save(query.normalized(), findings, summary, args.format, args.out)
        print(f"report written: {path}", file=sys.stderr)
    return 0


# --- inspect ---------------------------------------------------------------

def _cmd_list(args) -> int:
    from .store import get_db, repo

    db = get_db()
    with db.session() as s:
        if args.what == "targets":
            for t in repo.list_targets(s):
                w = " (watch)" if t.watchlist else ""
                print(f"#{t.id}  {t.label}{w}  {t.query}")
        elif args.what == "runs":
            for r in repo.list_runs(s, target_id=args.target):
                print(f"#{r.id}  target={r.target_id}  {r.status}  {r.stats}")
        elif args.what == "changes":
            for c in repo.list_changes(s, target_id=args.target):
                print(f"{c.created_at:%Y-%m-%d %H:%M}  {c.kind:<11} {c.source} {c.label}")
        elif args.what == "sources":
            for src in repo.list_sources(s):
                print(f"{src.name:<14} rel={src.reliability:.2f}  "
                      f"ok={src.successes} fail={src.failures}  breaker={src.breaker_state}")
    return 0


# --- graph -----------------------------------------------------------------

def _cmd_graph(args) -> int:
    """Print the discovery graph of a run as a depth-indented artifact tree."""
    from .store import get_db, repo

    db = get_db()
    with db.session() as s:
        run_id = args.run
        if run_id is None:
            runs = repo.list_runs(s, limit=1)
            if not runs:
                print("no runs yet", file=sys.stderr)
                return 1
            run_id = runs[0].id
        arts = repo.list_artifacts(s, run_id)
        edges = repo.list_artifact_edges(s, run_id)

    if not arts:
        print(f"run #{run_id}: no artifacts recorded", file=sys.stderr)
        return 0

    children: dict[int, list] = {}
    has_parent: set[int] = set()
    by_id = {a.id: a for a in arts}
    for e in edges:
        if e.src_artifact_id in by_id and e.dst_artifact_id in by_id:
            children.setdefault(e.src_artifact_id, []).append(e.dst_artifact_id)
            has_parent.add(e.dst_artifact_id)

    print(f"run #{run_id} — {len(arts)} artifact(s), {len(edges)} edge(s)")
    seen: set[int] = set()

    def walk(aid: int, indent: int) -> None:
        if aid in seen:  # an artifact can be reached by multiple parents
            a = by_id[aid]
            print(f"{'  ' * indent}↳ {a.type}:{a.value}  (↑ shared)")
            return
        seen.add(aid)
        a = by_id[aid]
        via = f"  via {a.source_module}" if a.source_module != "seed" else ""
        print(f"{'  ' * indent}• {a.type:<16} {a.value}{via}")
        for cid in children.get(aid, []):
            walk(cid, indent + 1)

    for a in arts:
        if a.id not in has_parent:  # roots (seeds)
            walk(a.id, 0)
    return 0


# --- main ------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="recon", description="Professional-grade OSINT framework.")
    sub = p.add_subparsers(dest="cmd")

    sc = sub.add_parser("scan", help="run a durable, correlated, persisted scan")
    _add_identifier_args(sc)
    sc.add_argument("--label")
    sc.add_argument("--all", action="store_true", help="also print NOT_FOUND/ERROR")
    sc.add_argument("--watch", metavar="CRON", help="add target to watchlist on this cron")
    sc.add_argument("--format", choices=["json", "csv", "pdf"])
    sc.add_argument("--out")
    # Recursive-engine controls (override config defaults for this run).
    sc.add_argument("--max-depth", type=int, dest="max_depth",
                    help="how many pivots deep the recursive engine may go")
    sc.add_argument("--scope", choices=["strict", "aggressive"],
                    help="strict: only expand artifacts tied to the seed; aggressive: follow external pivots")
    pg = sc.add_mutually_exclusive_group()
    pg.add_argument("--passive", dest="passive", action="store_true", default=None,
                    help="passive modules only (default)")
    pg.add_argument("--active", dest="passive", action="store_false",
                    help="also run active modules")

    gr = sub.add_parser("graph", help="print the discovery graph (artifact tree) of a run")
    gr.add_argument("--run", type=int, help="run id (defaults to the latest run)")

    sub.add_parser("serve", help="launch the local web dashboard + API")
    wk = sub.add_parser("worker", help="process queued scan jobs")
    wk.add_argument("--once", action="store_true", help="drain the queue then exit")
    sub.add_parser("monitor", help="run the cron scheduler for watch-listed targets")

    ls = sub.add_parser("targets"); ls.add_argument("--target", type=int)
    rn = sub.add_parser("runs"); rn.add_argument("--target", type=int)
    chg = sub.add_parser("changes"); chg.add_argument("--target", type=int)
    sub.add_parser("sources")
    return p


def main() -> None:
    argv = sys.argv[1:]
    # Back-compat: bare flags -> scan.
    if argv and argv[0].startswith("-") and argv[0] not in ("-h", "--help"):
        argv = ["scan", *argv]

    parser = build_parser()
    args = parser.parse_args(argv)
    cmd = args.cmd or "scan"

    if cmd == "scan":
        raise SystemExit(asyncio.run(_cmd_scan(args)))
    if cmd == "graph":
        raise SystemExit(_cmd_graph(args))
    if cmd == "serve":
        from .server import main as serve_main
        serve_main()
        return
    if cmd == "worker":
        from .jobs.worker import run_worker
        n = asyncio.run(run_worker(once=getattr(args, "once", False)))
        print(f"processed {n} job(s)", file=sys.stderr)
        return
    if cmd == "monitor":
        from .monitor.scheduler import MonitorScheduler
        sched = MonitorScheduler()
        loaded = sched.load()
        print(f"scheduler running with {loaded} schedule(s); Ctrl-C to stop", file=sys.stderr)
        loop = asyncio.new_event_loop()
        sched.sched.start()
        try:
            loop.run_forever()
        except KeyboardInterrupt:
            sched.shutdown()
        return
    if cmd in ("targets", "runs", "changes", "sources"):
        args.what = cmd
        raise SystemExit(_cmd_list(args))

    parser.print_help()


if __name__ == "__main__":
    main()
