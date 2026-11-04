import json
import re
import time
from urllib.parse import quote, urlparse
from urllib.request import Request, urlopen

from .http import fetch
from .scope import in_scope, normalize_host
from .urlintel import add_url, extract_links


def get_text(url: str, timeout: float = 15) -> str:
    request = Request(url, headers={"User-Agent": "ScopeCrawl/0.1 (authorized-security-research)"})
    with urlopen(request, timeout=timeout) as response:  # nosec B310 - collector URLs are fixed public services
        return response.read(2_000_000).decode("utf-8", errors="replace")


def collect_crtsh(scope, store, delay: float = 0.5) -> int:
    count = 0
    for rule in scope.in_scope:
        base = normalize_host(rule[2:] if rule.startswith("*.") else rule)
        try:
            data = json.loads(get_text(f"https://crt.sh/?q=%25.{quote(base)}&output=json"))
        except Exception:
            continue
        for item in data:
            for name in str(item.get("name_value", "")).splitlines():
                host = normalize_host(name.lstrip("*."))
                if in_scope(scope, host):
                    count += int(add_url(store, scope, f"https://{host}/", "crt.sh", "subdomain"))
        time.sleep(delay)
    return count


def collect_wayback(scope, store, delay: float = 0.5) -> int:
    count = 0
    for rule in scope.in_scope:
        base = normalize_host(rule[2:] if rule.startswith("*.") else rule)
        endpoint = f"https://web.archive.org/cdx/search/cdx?url={quote(base)}/*&output=json&fl=original&filter=statuscode:200&collapse=urlkey"
        try:
            data = json.loads(get_text(endpoint))
        except Exception:
            continue
        for row in data[1:] if data and isinstance(data[0], list) else data:
            value = row[0] if isinstance(row, list) else row
            count += int(add_url(store, scope, value, "wayback", "historical"))
        time.sleep(delay)
    return count


def collect_live(scope, store, max_pages: int = 25, delay: float = 0.5) -> int:
    count = 0
    for rule in scope.in_scope:
        host = normalize_host(rule[2:] if rule.startswith("*.") else rule)
        for scheme in ("https", "http"):
            root = f"{scheme}://{host}/"
            response = fetch(root)
            if not response.status:
                continue
            count += int(add_url(store, scope, root, "live-root", "live"))
            for link in extract_links(response.body_sample, root)[:max_pages]:
                count += int(add_url(store, scope, link, "live-crawl", "live"))
            time.sleep(delay)
            break
    return count


def collect_metadata(scope, store, delay: float = 0.5) -> int:
    count = 0
    for rule in scope.in_scope:
        host = normalize_host(rule[2:] if rule.startswith("*.") else rule)
        for path in ("/robots.txt", "/sitemap.xml", "/.well-known/security.txt"):
            url = f"https://{host}{path}"
            response = fetch(url)
            if not response.status:
                continue
            count += int(add_url(store, scope, url, "metadata", "live"))
            for candidate in re.findall(r'https?://[^\s<>" ]+', response.body_sample):
                count += int(add_url(store, scope, candidate.rstrip("),.;"), "metadata-reference", "discovered"))
            time.sleep(delay)
    return count
