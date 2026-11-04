import time
from urllib.parse import urlparse

from .checks import inspect_cookies, inspect_cors, inspect_headers
from .http import fetch, resolve
from .models import Scope, TargetResult
from .scope import in_scope, normalize_host


def seed_hosts(scope: Scope) -> list[str]:
    hosts = []
    for rule in scope.in_scope:
        host = normalize_host(rule[2:] if rule.startswith("*.") else rule)
        if host and in_scope(scope, host) and host not in hosts:
            hosts.append(host)
    return hosts


def run(scope: Scope, execute: bool = False) -> list[TargetResult]:
    results = []
    delay = 1 / scope.rate_limit
    for host in seed_hosts(scope):
        result = TargetResult(host)
        result.resolved_ips = resolve(host) if execute else []
        if not execute:
            result.observations["dry_run"] = True
            result.urls = [f"https://{host}/", f"http://{host}/"]
            results.append(result)
            continue
        for scheme in ("https", "http"):
            url = f"{scheme}://{host}/"
            response = fetch(url)
            result.urls.append(url)
            if response.error and not response.status:
                result.errors.append(f"{url}: {response.error}")
                time.sleep(delay)
                continue
            result.observations[url] = {"status": response.status, "elapsed_ms": response.elapsed_ms, "headers": sorted(response.headers)}
            result.findings.extend(inspect_headers(response))
            result.findings.extend(inspect_cors(response))
            result.findings.extend(inspect_cookies(response))
            time.sleep(delay)
        for path in ("/.well-known/security.txt", "/robots.txt", "/sitemap.xml"):
            response = fetch(f"https://{host}{path}")
            if response.status:
                result.observations[f"https://{host}{path}"] = {"status": response.status, "length": len(response.body_sample)}
            time.sleep(delay)
        results.append(result)
    return results
