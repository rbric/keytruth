import sys
import io
import json
from keytruth import print_table, setup_colors
from argparse import Namespace


def _sample_cache():
    return [{
        'provider': 'OPENAI', 'var_name': 'OPENAI_API_KEY',
        'masked_key': 'sk-proj-1234', 'hash': 'abcdef12aaaa', 'files': ['a.env'],
        'status': {
            'provider': 'OPENAI', 'category': 'CANDIDATE', 'auth': 'Valid',
            'funding': 'Unknown', 'access': 'Working', 'metric_type': 'NONE',
            'metric_value': 'Format OK', 'metric_limit': None, 'metric_unit': '',
            'identity': None, 'risk': 'Low', 'checked_at': '', 'http_status': 200,
            'debug_logs': []
        }
    }, {
        'provider': 'STRIPE', 'var_name': 'STRIPE_SECRET_KEY',
        'masked_key': 'sk_live_xxxx', 'hash': 'bbbbbbbbbbbb', 'files': ['a.env', 'b.env'],
        'status': {
            'provider': 'STRIPE', 'category': 'CANDIDATE', 'auth': 'Detected',
            'funding': 'Unknown', 'access': 'Not probed', 'metric_type': 'NONE',
            'metric_value': 'Live key — opt-in required', 'metric_limit': None, 'metric_unit': '',
            'identity': None, 'risk': 'Critical: reused in 2 files', 'checked_at': '',
            'http_status': None, 'debug_logs': []
        }
    }]


def test_fact_table_no_ansi():
    args = Namespace(no_color=True, placeholders=False, reused=False, json=False)
    setup_colors(args)

    stdout = io.StringIO()
    sys.stdout = stdout
    try:
        print_table(_sample_cache(), args=args, is_scan=False, files_count=2)
    finally:
        sys.stdout = sys.__stdout__

    out = stdout.getvalue()
    assert "\x1b" not in out
    assert "PROVIDER" in out
    assert "CRITICAL" in out
    assert "OPENAI" in out
    assert "STRIPE" in out
    assert "critical" in out
    assert "invalid" in out
    assert "╭─" not in out
    assert "ACTION REQUIRED" not in out
    # Invalid/critical before Working-ish noise; Stripe CRITICAL before OPENAI NONE... 
    # Sort: CRITICAL first — STRIPE (critical) appears before non-critical OPENAI? 
    # OPENAI is Valid/Working risk NONE → tier 3; STRIPE CRITICAL → tier 0
    assert out.index("STRIPE") < out.index("OPENAI")


def test_scan_facts():
    args = Namespace(no_color=True, placeholders=True, reused=False, json=False)
    setup_colors(args)

    cache = [{
        'provider': 'OPENAI', 'var_name': 'OPENAI_API_KEY',
        'masked_key': 'sk-proj-1234', 'hash': 'abcdef12aaaa', 'files': ['a.env'],
        'status': {
            'provider': 'OPENAI', 'category': 'CANDIDATE', 'auth': 'Unknown',
            'funding': 'Unknown', 'access': 'Unknown', 'metric_type': 'NONE',
            'metric_value': 'Unprobed', 'metric_limit': None, 'metric_unit': '',
            'identity': None, 'risk': 'Low', 'checked_at': '', 'http_status': None,
            'debug_logs': []
        }
    }, {
        'provider': 'STRIPE', 'var_name': 'STRIPE_SECRET_KEY',
        'masked_key': 'replace-me', 'hash': 'fedcba21bbbb', 'files': ['b.env'],
        'status': {
            'provider': 'STRIPE', 'category': 'PLACEHOLDER', 'auth': 'Not tested',
            'funding': 'Unknown', 'access': 'None', 'metric_type': 'NONE',
            'metric_value': 'Placeholder', 'metric_limit': None, 'metric_unit': '',
            'identity': None, 'risk': 'Low', 'checked_at': '', 'http_status': None,
            'debug_logs': []
        }
    }]

    stdout = io.StringIO()
    sys.stdout = stdout
    try:
        print_table(cache, args=args, is_scan=True, files_count=2)
    finally:
        sys.stdout = sys.__stdout__

    out = stdout.getvalue()
    assert "scan" in out
    assert "OPENAI" in out
    assert "1 keys" in out
    assert "1 skipped" in out
    assert "AUTH" not in out  # scan drops dead columns
    assert "Unprobed" not in out


def test_working_metric_is_dash_not_noise():
    from keytruth import ProbeResult, display_metric
    s = ProbeResult(
        provider="OPENAI", auth="Valid", access="Working",
        metric_type="NONE", metric_value="No balance authority",
    )
    assert display_metric(s) == "-"


def test_json_output():
    args = Namespace(no_color=True, placeholders=False, reused=False, json=True)
    setup_colors(args)

    stdout = io.StringIO()
    sys.stdout = stdout
    try:
        print_table(_sample_cache(), args=args, is_scan=False)
    finally:
        sys.stdout = sys.__stdout__

    data = json.loads(stdout.getvalue())
    assert isinstance(data, list)
    assert {d["provider"] for d in data} >= {"OPENAI", "STRIPE"}
    stripe = next(d for d in data if d["provider"] == "STRIPE")
    assert stripe["risk"] == "CRITICAL"
