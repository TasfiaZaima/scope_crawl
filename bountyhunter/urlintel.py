import re
from datetime import datetime, timezone
from html.parser import HTMLParser
from urllib.parse import parse_qsl, urldefrag, urljoin, urlparse, urlunparse

from .scope import in_scope, normalize_host
from .storage import URLStore


STATIC_EXTENSIONS = {".css", ".gif", ".ico", ".jpeg", ".jpg", ".mp3", ".mp4", ".png", ".svg", ".woff", ".woff2", ".ttf", ".webp"}
HIGH_VALUE_WORDS = {"admin": 25, "login": 18, "auth": 18, "oauth": 18, "graphql": 18, "upload": 20, "download": 15, "export": 20, "webhook": 20, "debug": 20, "internal": 15, "backup": 18, "reset": 18, "api": 12, "staging": 10, "sandbox": 10, "dev": 10, "test": 8}
HIGH_VALUE_PARAMS = {"id", "user_id", "account_id", "redirect", "url", "next", "return", "file", "path", "token", "dest", "callback", "query"}


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def normalize_url(value: str) -> str | None:
    value = value.strip()
    if not value or value.startswith(("mailto:", "javascript:", "data:", "tel:")):
        return None
    if not value.lower().startswith(("http://", "https://")):
        return None
    value, _ = urldefrag(value)
    parsed = urlparse(value)
    if parsed.hostname is None:
        return None
    path = parsed.path or "/"
    query = "&".join(f"{k}={v}" for k, v in sorted(parse_qsl(parsed.query, keep_blank_values=True)))
    return urlunparse((parsed.scheme.lower(), parsed.netloc.lower(), path, "", query, ""))


def is_static(url: str) -> bool:
    return any(urlparse(url).path.lower().endswith(ext) for ext in STATIC_EXTENSIONS)


def add_url(store: URLStore, scope, value: str, source: str, status: str = "discovered") -> bool:
    url = normalize_url(value)
    if not url:
        return False
    host = normalize_host(urlparse(url).hostname or "")
    if not in_scope(scope, host):
        return False
    return store.add(url, host, source, now(), status)


class LinkParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links: list[str] = []
        self.scripts: list[str] = []

    def handle_starttag(self, tag, attrs):
        values = dict(attrs)
        if tag == "a" and values.get("href"):
            self.links.append(values["href"])
        if tag == "script" and values.get("src"):
            self.scripts.append(values["src"])


def extract_links(body: str, base_url: str) -> list[str]:
    parser = LinkParser()
    try:
        parser.feed(body[:1_000_000])
    except Exception:
        return []
    return [urljoin(base_url, link) for link in parser.links + parser.scripts]


def score_url(url: str) -> tuple[int, list[str]]:
    parsed = urlparse(url)
    text = f"{parsed.netloc} {parsed.path} {parsed.query}".lower()
    score = 0
    reasons = []
    for word, points in HIGH_VALUE_WORDS.items():
        if re.search(rf"(?:^|[/_.=-]){re.escape(word)}(?:[/_.=-]|$)", text):
            score += points
            reasons.append(f"contains {word}")
    params = {key.lower() for key, _ in parse_qsl(parsed.query, keep_blank_values=True)}
    valuable = sorted(params & HIGH_VALUE_PARAMS)
    if valuable:
        score += min(30, 10 * len(valuable))
        reasons.append("interesting parameters: " + ", ".join(valuable))
    if parsed.query:
        score += 8
        reasons.append("has query parameters")
    if is_static(url):
        score = max(0, score - 30)
        reasons.append("static asset penalty")
    return min(score, 100), reasons
