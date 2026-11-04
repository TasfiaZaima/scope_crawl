from bountyhunter.models import Scope
from bountyhunter.scope import in_scope, load_scope


def test_wildcard_scope_matches_subdomains_but_not_sibling_domains():
    scope = Scope("demo", ["*.example.com"], ["admin.example.com"])
    assert in_scope(scope, "api.example.com")
    assert in_scope(scope, "example.com")
    assert not in_scope(scope, "admin.example.com")
    assert not in_scope(scope, "example.com.attacker.test")


def test_scope_file(tmp_path):
    path = tmp_path / "scope.yaml"
    path.write_text("program: demo\nin_scope:\n  - example.com\nrate_limit: 3\n")
    scope = load_scope(path)
    assert scope.program == "demo"
    assert scope.rate_limit == 3
