import ipaddress
import re
from pathlib import Path
from urllib.parse import urlparse

from .models import Scope


def _parse_simple_yaml(path: Path) -> dict:
    """Parse the deliberately small scope format without requiring PyYAML."""
    data: dict = {"in_scope": [], "out_of_scope": []}
    current = None
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].rstrip()
        if not line.strip():
            continue
        stripped = line.strip()
        if stripped.endswith(":") and not stripped.startswith("-"):
            current = stripped[:-1]
            if current in {"in_scope", "out_of_scope"}:
                data[current] = []
            continue
        if stripped.startswith("-"):
            if current not in {"in_scope", "out_of_scope"}:
                raise ValueError(f"List item outside a scope list: {raw}")
            value = stripped[1:].strip().strip("'\"")
            data[current].append(value)
            continue
        if ":" in stripped:
            key, value = stripped.split(":", 1)
            value = value.strip().strip("'\"")
            if value.isdigit():
                value = int(value)
            elif re.fullmatch(r"\d+\.\d+", value):
                value = float(value)
            data[key.strip()] = value
            current = None
    return data


def load_scope(path: str | Path) -> Scope:
    data = _parse_simple_yaml(Path(path))
    scope = Scope(
        program=str(data.get("program", "unnamed-program")),
        in_scope=list(data.get("in_scope", [])),
        out_of_scope=list(data.get("out_of_scope", [])),
        rate_limit=float(data.get("rate_limit", 2)),
        max_concurrency=int(data.get("max_concurrency", 2)),
    )
    validate_scope(scope)
    return scope


def normalize_host(value: str) -> str:
    value = value.strip().lower()
    if "://" in value:
        value = urlparse(value).hostname or ""
    return value.rstrip(".")


def _matches(rule: str, host: str) -> bool:
    rule = normalize_host(rule)
    host = normalize_host(host)
    if not rule or not host:
        return False
    if rule.startswith("*."):
        base = rule[2:]
        return host == base or host.endswith("." + base)
    return host == rule


def in_scope(scope: Scope, host: str) -> bool:
    host = normalize_host(host)
    try:
        ipaddress.ip_address(host)
        return False
    except ValueError:
        pass
    return any(_matches(rule, host) for rule in scope.in_scope) and not any(
        _matches(rule, host) for rule in scope.out_of_scope
    )


def validate_scope(scope: Scope) -> None:
    if not scope.in_scope:
        raise ValueError("in_scope must contain at least one hostname")
    if scope.rate_limit <= 0 or scope.rate_limit > 20:
        raise ValueError("rate_limit must be between 0 and 20 requests/second")
    if scope.max_concurrency < 1 or scope.max_concurrency > 10:
        raise ValueError("max_concurrency must be between 1 and 10")
    for item in scope.in_scope + scope.out_of_scope:
        host = normalize_host(item[2:] if item.startswith("*.") else item)
        if not host or "." not in host or any(ch in host for ch in "/?&#"):
            raise ValueError(f"Invalid hostname rule: {item}")
