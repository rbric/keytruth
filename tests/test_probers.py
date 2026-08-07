"""Cassette-style prober tests: frozen HTTP → expected classification."""

import json
import keytruth
from keytruth import (
    probe_openai,
    probe_anthropic,
    probe_deepseek,
    probe_openrouter,
    probe_fal,
    probe_elevenlabs,
    probe_mistral,
    probe_huggingface,
    probe_resend,
    probe_stripe,
    probe_replicate,
)


def _route(monkeypatch, routes):
    """routes: list of (url_substr, status, body) matched in order, first hit wins."""

    def mock_request(url, method="GET", headers=None, data=None):
        for substr, code, body in routes:
            if substr in url:
                if not isinstance(body, str):
                    body = json.dumps(body)
                return code, body, 11
        return 404, '{"error":"unmocked " + url}', 11

    monkeypatch.setattr(keytruth, "make_request", mock_request)


def test_openai_valid_working(monkeypatch):
    _route(monkeypatch, [
        ("/v1/models", 200, {"data": [{"id": "gpt-4o"}]}),
        ("/v1/moderations", 200, {"results": []}),
    ])
    s = probe_openai("sk-test")
    assert s.auth == "Valid"
    assert s.access == "Working"
    assert any("/v1/models" in line for line in s.debug_logs)


def test_openai_invalid(monkeypatch):
    _route(monkeypatch, [
        ("/v1/models", 401, {"error": {"message": "Incorrect API key"}}),
    ])
    s = probe_openai("sk-bad")
    assert s.auth == "Invalid"
    assert s.access == "None"


def test_openai_experimental_balance(monkeypatch):
    _route(monkeypatch, [
        ("/credit_grants", 200, {"total_available": 12.5}),
        ("/v1/moderations", 200, {}),
    ])
    s = probe_openai("sk-test", is_experimental=True)
    assert s.auth == "Valid"
    assert s.metric_type == "BALANCE"
    assert s.metric_value == 12.5
    assert s.funding == "Funded"


def test_anthropic_valid(monkeypatch):
    _route(monkeypatch, [
        ("/v1/models", 200, {"data": [{"id": "claude-3-haiku-20240307"}]}),
        ("/count_tokens", 200, {"input_tokens": 1}),
    ])
    s = probe_anthropic("sk-ant-x")
    assert s.auth == "Valid"
    assert s.access == "Working"


def test_anthropic_depleted(monkeypatch):
    _route(monkeypatch, [
        ("/v1/models", 200, {"data": [{"id": "claude-3-haiku-20240307"}]}),
        ("/count_tokens", 400, {"error": {"message": "credit balance too low"}}),
    ])
    s = probe_anthropic("sk-ant-x")
    assert s.auth == "Valid"
    assert s.funding == "Depleted"
    assert s.access == "Restricted"


def test_anthropic_count_tokens_glitch_still_working(monkeypatch):
    _route(monkeypatch, [
        ("/v1/models", 200, {"data": [{"id": "claude-3-haiku-20240307"}]}),
        ("/count_tokens", 400, {"error": {"message": "weird"}}),
    ])
    s = probe_anthropic("sk-ant-x")
    assert s.auth == "Valid"
    assert s.access == "Working"
    assert s.access != "Unknown"


def test_deepseek_balance(monkeypatch):
    _route(monkeypatch, [
        ("/user/balance", 200, {
            "balance_infos": [{"total_balance": "3.14", "currency": "USD"}]
        }),
    ])
    s = probe_deepseek("sk-x")
    assert s.auth == "Valid"
    assert s.access == "Working"
    assert s.metric_type == "BALANCE"
    assert s.metric_value == 3.14


def test_openrouter_usage(monkeypatch):
    _route(monkeypatch, [
        ("/auth/key", 200, {"data": {"usage": 1.5, "limit": 10}}),
    ])
    s = probe_openrouter("sk-or-x")
    assert s.auth == "Valid"
    assert s.metric_type == "USAGE"
    assert s.funding == "Funded"


def test_fal_billing_then_models_fallback(monkeypatch):
    _route(monkeypatch, [
        ("/billing", 401, {}),
        ("/v1/models", 200, {"data": []}),
    ])
    s = probe_fal("fal-x")
    # 401 on billing returns Invalid immediately in current code
    assert s.auth == "Invalid"

    _route(monkeypatch, [
        ("/billing", 403, {}),
        ("/v1/models", 200, {"data": []}),
    ])
    s = probe_fal("fal-x")
    assert s.auth == "Valid"
    assert s.access == "Working"
    assert s.metric_value == "No billing authority"


def test_elevenlabs_quota(monkeypatch):
    _route(monkeypatch, [
        ("/subscription", 200, {
            "tier": "starter",
            "character_count": 100,
            "character_limit": 10000,
        }),
    ])
    s = probe_elevenlabs("el-x")
    assert s.auth == "Valid"
    assert s.metric_type == "QUOTA"
    assert s.identity == "starter"


def test_mistral_valid(monkeypatch):
    _route(monkeypatch, [("/v1/models", 200, {"data": []})])
    s = probe_mistral("m-x")
    assert s.auth == "Valid"
    assert s.access == "Working"


def test_huggingface_identity(monkeypatch):
    _route(monkeypatch, [
        ("/whoami-v2", 200, {
            "name": "geohot",
            "auth": {"accessToken": {"role": "write"}},
        }),
    ])
    s = probe_huggingface("hf-x")
    assert s.auth == "Valid"
    assert s.identity == "geohot"
    assert s.access == "Write"


def test_resend_full_access(monkeypatch):
    _route(monkeypatch, [
        ("/api-keys", 200, {"data": [{"id": "1"}, {"id": "2"}]}),
    ])
    s = probe_resend("re_x")
    assert s.auth == "Valid"
    assert s.access == "Full"
    assert "2 API keys" in str(s.metric_value)


def test_stripe_opt_in_gate():
    live = "sk_live_" + ("B" * 24)
    s = probe_stripe(live, is_financial=False)
    assert s.auth == "Detected"
    assert s.access == "Not probed"
    assert "opt-in" in str(s.metric_value).lower()


def test_stripe_financial(monkeypatch):
    _route(monkeypatch, [
        ("/v1/balance", 200, {
            "available": [{"amount": 500, "currency": "eur"}],
            "pending": [{"amount": 100, "currency": "eur"}],
        }),
    ])
    s = probe_stripe("sk_live_x", is_financial=True)
    assert s.auth == "Valid"
    assert s.metric_type == "ACCOUNT_BALANCE"
    assert s.metric_value == 5.0
    assert "<REDACTED" in s.debug_logs[0]


def test_replicate_account(monkeypatch):
    _route(monkeypatch, [
        ("/v1/account", 200, {"username": "geohot"}),
    ])
    s = probe_replicate("r8_x")
    assert s.auth == "Valid"
    assert s.identity == "geohot"
