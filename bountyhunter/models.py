from dataclasses import dataclass, field
from typing import Any


@dataclass
class Scope:
    program: str
    in_scope: list[str]
    out_of_scope: list[str] = field(default_factory=list)
    rate_limit: float = 2.0
    max_concurrency: int = 2


@dataclass
class Finding:
    check: str
    severity: str
    title: str
    target: str
    evidence: dict[str, Any]
    confidence: str = "medium"
    remediation: str = ""
    manual_verification: str = ""


@dataclass
class TargetResult:
    target: str
    urls: list[str] = field(default_factory=list)
    resolved_ips: list[str] = field(default_factory=list)
    observations: dict[str, Any] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
