import json
import os
import pytest
from pathlib import Path
from collections import namedtuple
import keytruth
from keytruth import run_scan, run_probe, extract_keys, find_env_files, mask_key, CACHE_FILE

@pytest.fixture
def test_dir(tmp_path):
    fake_openai = "sk-" + "proj-" + "A" * 48
    fake_stripe = "sk_" + "live_" + "B" * 24
    fake_stripe_test = "sk_" + "test_" + "C" * 24
    
    mock_env = tmp_path / ".env.mock"
    mock_env.write_text(f"""# Valid OpenAI
OPENAI_API_KEY={fake_openai}
# Placeholder
STRIPE_SECRET_KEY=replace-with-your-key
# Invalid Replicate
REPLICATE_API_TOKEN=r8_
# Reused Stripe live
STRIPE_LIVE_KEY_1={fake_stripe}
""")

    another_env = tmp_path / ".env.another"
    another_env.write_text(f"""# Same reused Stripe live
STRIPE_LIVE_KEY={fake_stripe}
""")
    
    return tmp_path

class DummyArgs:
    def __init__(self, paths, unknown=False, group_by_variable=False, reused=False, verbose=False, financial=False, experimental=False, debug=False, yes=True, all=False):
        self.paths = paths
        self.unknown = unknown
        self.group_by_variable = group_by_variable
        self.reused = reused
        self.verbose = verbose
        self.financial = financial
        self.yes = yes
        self.all = all
        self.experimental = experimental
        self.debug = debug

def test_scan_is_offline(monkeypatch, test_dir):
    def network_forbidden(*args, **kwargs):
        raise AssertionError("scan attempted network access")

    monkeypatch.setattr("urllib.request.urlopen", network_forbidden)
    args = DummyArgs(paths=[str(test_dir)])
    
    # We must mock CACHE_FILE to avoid overwriting real cache
    mock_cache = test_dir / ".api_keys_cache.json"
    monkeypatch.setattr(keytruth, "CACHE_FILE", mock_cache)
    
    run_scan(args)
    
    assert mock_cache.exists()
    cache_data = json.loads(mock_cache.read_text())
    assert cache_data["schema_version"] == 3
    assert len(cache_data["scan"]["inventory"]) > 0

def test_cache_contains_no_raw_keys(monkeypatch, test_dir):
    mock_cache = test_dir / ".api_keys_cache.json"
    monkeypatch.setattr(keytruth, "CACHE_FILE", mock_cache)
    
    args = DummyArgs(paths=[str(test_dir)])
    run_scan(args)
    
    cache_text = mock_cache.read_text()
    # The synthetic keys
    fake_openai = "sk-" + "proj-" + "A" * 48
    fake_stripe = "sk_" + "live_" + "B" * 24
    assert fake_openai not in cache_text
    assert fake_stripe not in cache_text

def test_probe_no_cache(capsys, monkeypatch, test_dir):
    mock_cache = test_dir / ".api_keys_cache.json"
    monkeypatch.setattr(keytruth, "CACHE_FILE", mock_cache)
    
    args = DummyArgs(paths=[str(test_dir)])
    run_probe(args)
    captured = capsys.readouterr()
    assert "No cache found" in captured.out

def test_probe_bypasses_openai_experimental(monkeypatch, test_dir):
    # Setup scan
    mock_cache = test_dir / ".api_keys_cache.json"
    monkeypatch.setattr(keytruth, "CACHE_FILE", mock_cache)
    run_scan(DummyArgs(paths=[str(test_dir)]))
    
    urls_hit = []
    
    def mock_make_request(url, **kwargs):
        urls_hit.append(url)
        return 401, '{"error": {"message": "invalid_api_key"}}', 10
        
    monkeypatch.setattr(keytruth, "make_request", mock_make_request)
    
    args = DummyArgs(paths=[], experimental=False)
    run_probe(args)
    
    assert "https://api.openai.com/v1/dashboard/billing/credit_grants" not in urls_hit
    
    # Run with experimental
    urls_hit.clear()
    args = DummyArgs(paths=[], experimental=True)
    run_probe(args)
    assert "https://api.openai.com/v1/dashboard/billing/credit_grants" in urls_hit

def test_probe_missing_file_discards_stale_results(monkeypatch, test_dir):
    mock_cache = test_dir / ".api_keys_cache.json"
    monkeypatch.setattr(keytruth, "CACHE_FILE", mock_cache)
    
    run_scan(DummyArgs(paths=[str(test_dir)]))
    
    def mock_make_request(url, **kwargs):
        return 401, '{"error": "invalid"}', 10
    monkeypatch.setattr(keytruth, "make_request", mock_make_request)
    
    # Delete the mock env
    for f in test_dir.glob("*.mock"):
        f.unlink()
        
    run_probe(DummyArgs(paths=[]))
    
    cache_data = json.loads(mock_cache.read_text())
    probe_results = cache_data.get("probe", {}).get("results", [])
    
    # The openai key shouldn't be probed since the file is missing
    # But wait, probe rescans the folder. So if the file is missing, it won't find the key.
    # Therefore, results won't include it.
    found_openai = any(d['provider'] == 'OPENAI' for d in probe_results)
    assert not found_openai

def test_stripe_live_reuse(monkeypatch, test_dir):
    mock_cache = test_dir / ".api_keys_cache.json"
    monkeypatch.setattr(keytruth, "CACHE_FILE", mock_cache)
    
    run_scan(DummyArgs(paths=[str(test_dir)]))
    
    def mock_make_request(url, **kwargs):
        if "stripe" in url:
            return 200, '{"available": [{"amount": 500, "currency": "eur"}], "pending": [{"amount": 100, "currency": "eur"}]}', 10
        return 401, '{}', 10
    monkeypatch.setattr(keytruth, "make_request", mock_make_request)
    
    run_probe(DummyArgs(paths=[], financial=True))
    
    cache_data = json.loads(mock_cache.read_text())
    probe_results = cache_data.get("probe", {}).get("results", [])
    
    stripe_entries = [d for d in probe_results if d['provider'] == 'STRIPE' and d['masked_key'].startswith('sk_live_')]
    assert len(stripe_entries) == 1
    stripe = stripe_entries[0]
    assert stripe['status']['risk'] == "Critical: Live key reuse across projects"
    
    # Verify amounts didn't leak into cache
    cache_text = mock_cache.read_text()
    assert "500" not in cache_text
    assert "100" not in cache_text
