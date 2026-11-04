# ScopeCrawl

Scope-aware, evidence-driven reconnaissance for authorized bug-bounty testing.

This MVP deliberately focuses on safe, low-impact checks. It does not brute-force, exploit, spray credentials, bypass authentication, or scan hosts outside an explicit scope file.

## Why use ScopeCrawl?

ScopeCrawl helps bug-bounty researchers turn large authorized scopes into a smaller list of live, interesting URLs. It collects historical and certificate-based URLs, removes stale targets, prioritizes API and security-relevant endpoints, and creates reports for manual verification.

## Quick start

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'

scopecrawl verify-scope examples/scope.yaml
scopecrawl scan examples/scope.yaml --dry-run
scopecrawl scan examples/scope.yaml --execute --output reports/example
scopecrawl collect examples/scope.yaml --execute --sources crtsh,wayback,metadata
scopecrawl validate-urls examples/scope.yaml --execute
scopecrawl prioritize --db data/scopecrawl.sqlite
scopecrawl url-report --db data/scopecrawl.sqlite --output reports/urls.md --minimum-score 20
scopecrawl subdomain-report --db data/scopecrawl.sqlite --show
```

The default is dry-run. Network requests require `--execute` and are limited to the exact hosts allowed by the scope file.

## Start from a Kali Linux or Ubuntu terminal

You do not need VS Code to run ScopeCrawl.

Install the required packages:

```bash
sudo apt update
sudo apt install -y python3 python3-venv git
```

Clone the repository and enter the project directory:

```bash
git clone https://github.com/<your-username>/ScopeCrawl.git
cd ScopeCrawl
```

Create the virtual environment and install the tool:

```bash
cd ScopeCrawl
python3 -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
```

### Re-entering the tool later

Whenever you open a new terminal, activate the existing environment again:

```bash
cd ScopeCrawl
source .venv/bin/activate
```

After activation, verify the installation:

```bash
scopecrawl --help
python -m pytest -q
```

Every ScopeCrawl command starts with the ScopeCrawl terminal banner, followed by the command output.

Running `scopecrawl` without arguments displays the available commands and a quick-start checklist for creating a scope, validating it, collecting URLs, prioritizing results, and generating a report.

## Give the tool a bug-bounty scope

Create a scope directory and a YAML file:

```bash
mkdir -p scopes
nano scopes/my-program.yaml
```

Example scope file:

```yaml
program: my-authorized-program

in_scope:
  - example.com
  - api.example.com
  - '*.staging.example.com'

out_of_scope:
  - admin.example.com
  - payments.example.com

rate_limit: 2
max_concurrency: 2
```

Scope rules:

- Add only domains explicitly allowed by the bug-bounty program.
- `*.example.com` matches `example.com` and its subdomains.
- `out_of_scope` always overrides `in_scope`.
- Do not add third-party providers unless the program explicitly authorizes them.
- Follow the program's automation restrictions, rate limits, and exclusions.

Save the file in nano with `Ctrl+O`, press `Enter`, then exit with `Ctrl+X`.

Validate the scope before making requests:

```bash
scopecrawl verify-scope scopes/my-program.yaml
```

Run a dry-run first:

```bash
scopecrawl scan \
  scopes/my-program.yaml \
  --dry-run \
  --output reports/my-program
```

After confirming authorization, collect URLs from passive sources:

```bash
scopecrawl collect \
  scopes/my-program.yaml \
  --execute \
  --sources crtsh,wayback,metadata
```

To include the small same-origin live crawl:

```bash
scopecrawl collect \
  scopes/my-program.yaml \
  --execute \
  --sources crtsh,wayback,metadata,live \
  --max-pages 10
```

Validate that collected URLs still exist before prioritizing them. This removes stale certificate and archive results from the live report:

```bash
scopecrawl validate-urls \
  scopes/my-program.yaml \
  --db data/scopecrawl.sqlite \
  --execute \
  --limit 100 \
  --rate-limit 1
```

Validation classifies each URL as `live`, `dns_only`, or `dead`. Only `live` URLs appear in the prioritized report by default.

To see every discovered hostname, including historical and unvalidated subdomains:

```bash
scopecrawl subdomain-report \
  --db data/scopecrawl.sqlite \
  --output reports/subdomains.md \
  --show
```

To inspect collected URLs before live validation:

```bash
scopecrawl url-report \
  --db data/scopecrawl.sqlite \
  --output reports/all-collected-urls.md \
  --minimum-score 0 \
  --include-unvalidated \
  --show
```

Prioritize the collected URLs and create a review report:

```bash
scopecrawl prioritize \
  --db data/scopecrawl.sqlite

scopecrawl url-report \
  --db data/scopecrawl.sqlite \
  --output reports/my-program-urls.md \
  --minimum-score 20
```

To print the report directly in the terminal:

```bash
scopecrawl url-report \
  --db data/scopecrawl.sqlite \
  --output reports/my-program-urls.md \
  --minimum-score 20 \
  --show
```

To open the saved report in a scrollable terminal viewer:

```bash
less reports/my-program-urls.md
```

Press `q` to exit `less`. You can also print the file with `cat`:

```bash
cat reports/my-program-urls.md
```

The tool stores the URL database in `data/scopecrawl.sqlite` and the review report in `reports/`. Findings and scores are research leads for manual verification, not proof that a target is vulnerable.

## URL intelligence workflow

The `collect` command stores normalized, in-scope URLs in SQLite. Sources include certificate transparency, Wayback history, robots/sitemap references, and (when selected) a small same-origin live crawl. Run `prioritize` to score endpoints likely to deserve manual review, then generate a Markdown triage report with `url-report`.

The collector does not claim to prove severe vulnerabilities. It reduces a large authorized attack surface to a smaller, evidence-backed review queue.

## Scope format

```yaml
program: example-program
in_scope:
  - example.com
  - '*.example.com'
out_of_scope:
  - admin.example.com
rate_limit: 2
max_concurrency: 2
```

Wildcard entries match the base domain and its subdomains only when written as `*.example.com`. Out-of-scope rules always win.

## Current checks

- Scope validation and wildcard boundary handling
- DNS resolution and HTTP/HTTPS reachability
- Security headers
- Cookie flags
- CORS response behavior
- `security.txt`, `robots.txt`, and sitemap references
- Certificate Transparency and Wayback URL collection
- Same-origin live crawling when explicitly selected
- URL normalization, deduplication, and SQLite storage
- Endpoint prioritization for API, auth, admin, upload, export, webhook, redirect, and identifier patterns
- Redacted JSON and Markdown evidence reports

Findings are hypotheses for manual verification, not proof of a vulnerability. Only test targets you are explicitly authorized to assess and follow each program's rate limits and exclusions.
