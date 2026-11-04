from .http import Response
from .models import Finding


def inspect_headers(response: Response) -> list[Finding]:
    headers = {k.lower(): v for k, v in response.headers.items()}
    findings: list[Finding] = []
    recommended = {
        "content-security-policy": "Define a restrictive Content-Security-Policy.",
        "x-content-type-options": "Set X-Content-Type-Options: nosniff.",
        "referrer-policy": "Set an explicit restrictive Referrer-Policy.",
    }
    for name, fix in recommended.items():
        if name not in headers:
            findings.append(Finding("security-headers", "low", f"Missing {name}", response.url, {"status": response.status}, "high", fix))
    if response.url.startswith("https://") and "strict-transport-security" not in headers:
        findings.append(Finding("security-headers", "medium", "Missing strict-transport-security", response.url, {"status": response.status}, "high", "Set HSTS after confirming HTTPS is enforced."))
    return findings


def inspect_cors(response: Response) -> list[Finding]:
    headers = {k.lower(): v for k, v in response.headers.items()}
    value = headers.get("access-control-allow-origin", "")
    credentials = headers.get("access-control-allow-credentials", "").lower() == "true"
    if value == "*" and credentials:
        return [Finding("cors", "high", "Wildcard CORS with credentials enabled", response.url, {"allow_origin": value, "allow_credentials": credentials}, "high", "Allow only trusted origins and avoid credentialed wildcard CORS.", "Confirm behavior with an authorized browser flow.")]
    return []


def inspect_cookies(response: Response) -> list[Finding]:
    findings = []
    for key, value in response.headers.items():
        if key.lower() != "set-cookie":
            continue
        lowered = value.lower()
        missing = [flag for flag in ("secure", "httponly", "samesite") if flag not in lowered]
        if missing:
            findings.append(Finding("cookies", "low", "Cookie missing security attributes", response.url, {"missing": missing, "cookie": "[REDACTED]"}, "high", "Set Secure, HttpOnly, and an appropriate SameSite attribute where applicable."))
    return findings


def inspect_metadata(response: Response, path: str) -> list[Finding]:
    if response.status == 200 and path == "/security.txt" and len(response.body_sample.strip()) < 20:
        return []
    if response.status == 200 and path == "/.well-known/security.txt":
        return []
    return []
