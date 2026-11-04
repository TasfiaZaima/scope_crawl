import time
from datetime import datetime, timezone
from urllib.parse import urlparse

from .http import fetch, resolve
from .scope import in_scope
from .storage import URLStore


def validate(store: URLStore, scope, limit: int = 100, rate_limit: float = 1.0) -> dict[str, int]:
    counts = {"live": 0, "dns_only": 0, "dead": 0}
    rows = store.rows()[:limit]
    delay = 1 / max(rate_limit, 0.1)
    for row in rows:
        host = urlparse(row["url"]).hostname or ""
        if not in_scope(scope, host):
            continue
        ips = resolve(host)
        if not ips:
            status, http_status, error = "dead", 0, "DNS did not resolve"
        else:
            response = fetch(row["url"])
            if response.status:
                status, http_status, error = "live", response.status, response.error
            else:
                status, http_status, error = "dns_only", 0, response.error or "DNS resolved but HTTP did not respond"
        store.save_check(row["url"], status, http_status, datetime.now(timezone.utc).isoformat(), error)
        counts[status] += 1
        time.sleep(delay)
    return counts
