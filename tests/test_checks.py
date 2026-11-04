from bountyhunter.checks import inspect_cors, inspect_headers
from bountyhunter.http import Response


def test_cors_credentials_wildcard_is_high_confidence():
    response = Response("https://example.com", 200, {"Access-Control-Allow-Origin": "*", "Access-Control-Allow-Credentials": "true"}, "", 10)
    findings = inspect_cors(response)
    assert findings and findings[0].severity == "high"


def test_missing_headers_are_reported():
    response = Response("https://example.com", 200, {}, "", 10)
    assert len(inspect_headers(response)) >= 3
