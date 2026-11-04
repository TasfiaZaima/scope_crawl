import argparse
import json
import sys

from .collectors import collect_crtsh, collect_live, collect_metadata, collect_wayback
from .prioritize import prioritize
from .report import write_reports
from .runner import run
from .scope import load_scope
from .storage import URLStore
from .validate import validate


BANNER = r"""
 ╔══════════════════════════════════════════════╗
 ║                  SCOPECRAWL                   ║
 ╚══════════════════════════════════════════════╝

 Scope-aware URL intelligence for authorized security research
""".strip("\n")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="scopecrawl", description="Scope-aware, low-impact URL intelligence for authorized security research")
    sub = parser.add_subparsers(dest="command", required=True)
    verify = sub.add_parser("verify-scope", help="Validate a scope file")
    verify.add_argument("scope")
    scan = sub.add_parser("scan", help="Run safe checks against explicit scope")
    scan.add_argument("scope")
    scan.add_argument("--execute", action="store_true", help="Allow low-impact network requests")
    scan.add_argument("--dry-run", action="store_true", help="Show targets without network requests")
    scan.add_argument("--output", default="reports/latest")
    collect = sub.add_parser("collect", help="Collect scoped URLs from passive sources and an optional low-impact crawl")
    collect.add_argument("scope")
    collect.add_argument("--db", default="data/scopecrawl.sqlite")
    collect.add_argument("--execute", action="store_true", help="Allow network requests")
    collect.add_argument("--sources", default="crtsh,wayback,metadata", help="Comma-separated: crtsh,wayback,metadata,live")
    collect.add_argument("--max-pages", type=int, default=25)
    priority = sub.add_parser("prioritize", help="Score URLs in the SQLite database")
    priority.add_argument("--db", default="data/scopecrawl.sqlite")
    validate_cmd = sub.add_parser("validate-urls", help="Check DNS and HTTP liveness for collected URLs")
    validate_cmd.add_argument("scope")
    validate_cmd.add_argument("--db", default="data/scopecrawl.sqlite")
    validate_cmd.add_argument("--execute", action="store_true", help="Allow DNS and HTTP requests")
    validate_cmd.add_argument("--limit", type=int, default=100)
    validate_cmd.add_argument("--rate-limit", type=float, default=1.0)
    report = sub.add_parser("url-report", help="Write a prioritized URL report")
    report.add_argument("--db", default="data/scopecrawl.sqlite")
    report.add_argument("--output", default="reports/urls.md")
    report.add_argument("--minimum-score", type=int, default=0)
    report.add_argument("--include-unvalidated", action="store_true", help="Include historical URLs that have not passed live validation")
    report.add_argument("--show", action="store_true", help="Print the generated Markdown report in the terminal")
    domains = sub.add_parser("subdomain-report", help="List every discovered in-scope hostname")
    domains.add_argument("--db", default="data/scopecrawl.sqlite")
    domains.add_argument("--output", default="reports/subdomains.md")
    domains.add_argument("--show", action="store_true", help="Print the hostname inventory in the terminal")
    return parser


def main(argv: list[str] | None = None) -> int:
    print(BANNER)
    print()
    parser = build_parser()
    command_args = sys.argv[1:] if argv is None else argv
    if not command_args:
        parser.print_help()
        print("\nQuick start:")
        print("  1. Create a scope file:  mkdir -p scopes && nano scopes/my-program.yaml")
        print("  2. Validate scope:       scopecrawl verify-scope scopes/my-program.yaml")
        print("  3. Dry-run first:        scopecrawl scan scopes/my-program.yaml --dry-run")
        print("  4. Collect URLs:         scopecrawl collect scopes/my-program.yaml --execute")
        print("  5. Validate liveness:    scopecrawl validate-urls scopes/my-program.yaml --execute")
        print("  6. Prioritize URLs:      scopecrawl prioritize")
        print("  7. Write a report:       scopecrawl url-report --output reports/urls.md")
        print("  8. List subdomains:       scopecrawl subdomain-report --show")
        print("\nUse --help with any command for more options.")
        return 0
    args = parser.parse_args(command_args)
    scope = None
    if args.command in {"verify-scope", "scan", "collect", "validate-urls"}:
        try:
            scope = load_scope(args.scope)
        except (OSError, ValueError) as exc:
            print(f"Scope error: {exc}", file=sys.stderr)
            return 2
    if args.command == "verify-scope":
        print(json.dumps({"program": scope.program, "in_scope": scope.in_scope, "out_of_scope": scope.out_of_scope, "rate_limit": scope.rate_limit, "max_concurrency": scope.max_concurrency}, indent=2))
        return 0
    if args.command == "prioritize":
        store = URLStore(args.db)
        count = prioritize(store)
        store.close()
        print(f"Scored {count} URLs")
        return 0
    if args.command == "validate-urls":
        if not args.execute:
            print("URL validation makes network requests. Re-run with --execute after verifying authorization and scope.", file=sys.stderr)
            return 2
        store = URLStore(args.db)
        counts = validate(store, scope, limit=max(1, min(args.limit, 500)), rate_limit=args.rate_limit)
        store.close()
        print("Validation complete:", ", ".join(f"{key}={value}" for key, value in counts.items()))
        return 0
    if args.command == "url-report":
        store = URLStore(args.db)
        rows = store.rows_for_report(args.minimum_score, live_only=not args.include_unvalidated)
        lines = ["# Prioritized URL report", "", f"URLs: {len(rows)}", ""]
        for row in rows:
            lines += [f"## {row['score']}/100 — {row['url']}", "", f"- Source: `{row['source']}`", f"- Status: `{row['status']}`", f"- Reasons: {row['reasons'] or 'none'}", ""]
        if not rows:
            lines += ["No live URLs matched the minimum score.", "", "Run `scopecrawl validate-urls <scope-file> --execute` first, then run `scopecrawl prioritize` again.", "", "Use `--minimum-score 0` after validation to inspect every live URL.", ""]
        from pathlib import Path
        path = Path(args.output)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("\n".join(lines), encoding="utf-8")
        store.close()
        print(f"Wrote {path}")
        if args.show:
            print()
            print(path.read_text(encoding="utf-8"))
        return 0
    if args.command == "subdomain-report":
        store = URLStore(args.db)
        rows = store.host_inventory()
        lines = ["# ScopeCrawl subdomain inventory", "", f"Hostnames: {len(rows)}", ""]
        for row in rows:
            validation = row["validation_status"] or "not validated"
            http_status = row["http_status"] or "-"
            lines += [f"## {row['host']}", "", f"- URLs: {row['url_count']}", f"- Sources: {row['sources'] or 'unknown'}", f"- Validation: {validation}", f"- HTTP status: {http_status}", ""]
        from pathlib import Path
        path = Path(args.output)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("\n".join(lines), encoding="utf-8")
        store.close()
        print(f"Wrote {path} ({len(rows)} hostnames)")
        if args.show:
            print()
            print(path.read_text(encoding="utf-8"))
        return 0
    if args.command == "collect":
        if not args.execute:
            print("Collection is network-enabled. Re-run with --execute after verifying authorization and scope.", file=sys.stderr)
            return 2
        store = URLStore(args.db)
        sources = {source.strip() for source in args.sources.split(",") if source.strip()}
        added = 0
        if "crtsh" in sources:
            added += collect_crtsh(scope, store)
        if "wayback" in sources:
            added += collect_wayback(scope, store)
        if "metadata" in sources:
            added += collect_metadata(scope, store, delay=1 / scope.rate_limit)
        if "live" in sources:
            added += collect_live(scope, store, max_pages=max(1, min(args.max_pages, 100)), delay=1 / scope.rate_limit)
        total = len(store.rows())
        source_summary = ", ".join(f"{row['source']}={row['count']}" for row in store.source_counts())
        store.close()
        print(f"New URLs: {added}; total URLs: {total}; database: {args.db}")
        print(f"Sources: {source_summary or 'none'}")
        return 0
    if args.execute and args.dry_run:
        print("Choose either --execute or --dry-run, not both.", file=sys.stderr)
        return 2
    results = run(scope, execute=args.execute)
    json_path, md_path = write_reports(args.output, scope.program, results)
    print(f"Targets: {len(results)}")
    print(f"Reports: {json_path} and {md_path}")
    if not args.execute:
        print("Dry-run only. Use --execute after verifying authorization and scope.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
