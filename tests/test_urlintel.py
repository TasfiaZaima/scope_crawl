from bountyhunter.models import Scope
from bountyhunter.storage import URLStore
from bountyhunter.urlintel import add_url, normalize_url, score_url


def test_normalize_url_sorts_query_parameters_and_removes_fragment():
    assert normalize_url("HTTPS://Example.COM/a?z=2&a=1#frag") == "https://example.com/a?a=1&z=2"


def test_add_url_rejects_out_of_scope_host(tmp_path):
    scope = Scope("demo", ["*.example.com"], ["admin.example.com"])
    store = URLStore(tmp_path / "urls.sqlite")
    assert add_url(store, scope, "https://api.example.com/admin?user_id=1", "test")
    assert not add_url(store, scope, "https://admin.example.com/", "test")
    assert len(store.rows()) == 1
    store.close()


def test_score_prioritizes_sensitive_endpoint_and_parameter():
    score, reasons = score_url("https://api.example.com/api/export?user_id=1")
    assert score >= 30
    assert any("interesting parameters" in reason for reason in reasons)


def test_score_uses_hostname_signals_for_root_urls():
    score, reasons = score_url("https://api-staging.example.com/")
    assert score >= 20
    assert any("contains api" in reason for reason in reasons)
