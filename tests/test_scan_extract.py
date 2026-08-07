import json
import stat

import pytest

import keytruth
from keytruth import find_env_files, extract_keys, run_scan, run_probe, run_show
from conftest import Args


def test_find_env_skips_node_modules_and_symlinks(fixture_tree):
    root = fixture_tree["root"]
    target = root / "proj-a" / ".env"
    link = root / "proj-a" / ".env.symlink"
    try:
        link.symlink_to(target)
    except OSError:
        pass

    files = find_env_files([str(root)])
    assert any(p.endswith(".env") for p in files)
    assert any(".env.local" in p for p in files)
    assert not any("node_modules" in p for p in files)
    assert not any(p.endswith(".env.symlink") for p in files)


def test_extract_detects_reuse_and_providers(fixture_tree):
    root = fixture_tree["root"]
    files = find_env_files([str(root)])
    inv = extract_keys(files, capture_unknown=True)

    by_prov = {}
    for _h, d in inv.items():
        by_prov.setdefault(d["provider"], []).append(d)

    assert {
        "OPENAI", "STRIPE", "ANTHROPIC", "OPENROUTER", "REPLICATE", "RESEND", "UNKNOWN"
    } <= set(by_prov)

    openai = by_prov["OPENAI"][0]
    assert len(openai["files"]) == 2
    assert openai["key"] == fixture_tree["openai"]


def test_scan_cache_permissions_and_schema(cache_file, fixture_tree):
    run_scan(Args(paths=[str(fixture_tree["root"])]))
    assert cache_file.exists()
    mode = stat.S_IMODE(cache_file.stat().st_mode)
    assert mode == 0o600

    data = json.loads(cache_file.read_text())
    assert data["schema_version"] == 3
    assert data["scan"]["inventory"]
    text = cache_file.read_text()
    assert fixture_tree["openai"] not in text
    assert fixture_tree["stripe_live"] not in text

    openai = next(d for d in data["scan"]["inventory"] if d["provider"] == "OPENAI")
    # Unprobed reuse is soft — CRITICAL only after probe proves live.
    assert openai["status"]["risk"].startswith("Review")


def test_probe_pipeline_end_to_end(cache_file, fixture_tree, monkeypatch, capsys):
    run_scan(Args(paths=[str(fixture_tree["root"])]))

    def mock_request(url, method="GET", headers=None, data=None):
        if "openai.com" in url and "moderations" in url:
            return 200, "{}", 5
        if "openai.com" in url:
            return 200, '{"data":[{"id":"gpt-4o"}]}', 5
        if "anthropic.com" in url and "count_tokens" in url:
            return 200, '{"input_tokens":1}', 5
        if "anthropic.com" in url:
            return 200, '{"data":[{"id":"claude-3-haiku-20240307"}]}', 5
        if "openrouter.ai" in url:
            return 200, '{"data":{"usage":0.1,"limit":null}}', 5
        if "replicate.com" in url:
            return 200, '{"username":"tester"}', 5
        if "resend.com" in url:
            return 200, '{"data":[{"id":"k1"}]}', 5
        if "stripe.com" in url:
            return 200, (
                '{"available":[{"amount":250,"currency":"usd"}],'
                '"pending":[{"amount":0,"currency":"usd"}]}'
            ), 5
        return 401, "{}", 5

    monkeypatch.setattr(keytruth, "make_request", mock_request)
    run_probe(Args(paths=[], financial=True, debug=False, yes=True))

    out = capsys.readouterr().out
    assert "PROVIDER" in out
    assert "CRITICAL" in out or "REVIEW" in out
    assert "OPENAI" in out

    data = json.loads(cache_file.read_text())
    results = data["probe"]["results"]
    providers = {d["provider"] for d in results}
    assert {"OPENAI", "STRIPE", "ANTHROPIC", "OPENROUTER", "REPLICATE", "RESEND"} <= providers

    openai = next(d for d in results if d["provider"] == "OPENAI")
    assert openai["status"]["auth"] == "Valid"
    assert openai["status"]["access"] == "Working"
    assert openai["status"]["risk"].startswith("Critical")

    assert "250" not in cache_file.read_text()
    stripe = next(
        d for d in results
        if d["provider"] == "STRIPE" and d["masked_key"].startswith("sk_live_")
    )
    assert stripe["status"]["metric_type"] == "NONE"

    run_show(Args(paths=[], key_id=openai["hash"][:8]))
    show_out = capsys.readouterr().out
    assert "CRITICAL" in show_out
    assert "action:" in show_out


def test_probe_requires_yes_when_noninteractive(cache_file, fixture_tree, monkeypatch):
    run_scan(Args(paths=[str(fixture_tree["root"])]))
    monkeypatch.setattr(keytruth.sys.stdin, "isatty", lambda: False)

    with pytest.raises(SystemExit) as ei:
        run_probe(Args(paths=[], yes=False))
    assert ei.value.code == 1


def test_show_recomputes_risk_ignoring_stale_cache(cache_file, fixture_tree, capsys):
    run_scan(Args(paths=[str(fixture_tree["root"])]))
    data = json.loads(cache_file.read_text())
    openai = next(d for d in data["scan"]["inventory"] if d["provider"] == "OPENAI")
    # Poison the cache the way a bug would — show recomputes from files + liveness.
    openai["status"]["risk"] = "Low"
    openai["status"]["auth"] = "Valid"
    openai["status"]["access"] = "Working"
    openai["status"]["metric_value"] = "No balance authority"
    cache_file.write_text(json.dumps(data))

    run_show(Args(paths=[], key_id=openai["hash"][:8]))
    out = capsys.readouterr().out
    assert "risk=CRITICAL" in out
    assert "action: Stop sharing" in out
