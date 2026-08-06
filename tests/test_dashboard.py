import sys
import io
from pathlib import Path
from keytruth import (
    print_table, ProbeResult,
    setup_colors, ANSI_RE
)
from argparse import Namespace

def test_dashboard_ansi_disabled():
    # Setup mock data
    args = Namespace(no_color=True, all=False, placeholders=False, reused=False)
    setup_colors(args)
    
    cache = [{
        'provider': 'OPENAI', 'var_name': 'OPENAI_API_KEY',
        'masked_key': 'sk-proj-1234', 'hash': 'abcdef12', 'files': ['a.env'],
        'status': {
            'provider': 'OPENAI', 'category': 'CANDIDATE', 'auth': 'Valid',
            'funding': 'Unknown', 'access': 'Working', 'metric_type': 'NONE',
            'metric_value': 'Format OK', 'metric_limit': None, 'metric_unit': '',
            'identity': None, 'risk': 'Low', 'checked_at': '', 'http_status': 200,
            'debug_logs': []
        }
    }]
    
    stdout = io.StringIO()
    sys.stdout = stdout
    try:
        print_table(cache, args=args, is_scan=False, files_count=1)
    finally:
        sys.stdout = sys.__stdout__
        
    out = stdout.getvalue()
    # Ensure no ANSI
    assert "\x1b" not in out
    
    # Ensure dashboard boxes are drawn
    assert "╭─ ACTION REQUIRED" in out
    assert "╭─ PROVIDERS" in out
    assert "● OPENAI" in out # no emoji, reliable char

def test_scan_unprobed():
    args = Namespace(no_color=True, all=False, placeholders=False, reused=False)
    setup_colors(args)
    
    cache = [{
        'provider': 'OPENAI', 'var_name': 'OPENAI_API_KEY',
        'masked_key': 'sk-proj-1234', 'hash': 'abcdef12', 'files': ['a.env'],
        'status': {
            'provider': 'OPENAI', 'category': 'CANDIDATE', 'auth': 'Unknown',
            'funding': 'Unknown', 'access': 'Unknown', 'metric_type': 'NONE',
            'metric_value': 'Unprobed', 'metric_limit': None, 'metric_unit': '',
            'identity': None, 'risk': 'Low', 'checked_at': '', 'http_status': None,
            'debug_logs': []
        }
    }, {
        'provider': 'STRIPE', 'var_name': 'STRIPE_SECRET_KEY',
        'masked_key': 'replace-me', 'hash': 'fedcba21', 'files': ['b.env'],
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
    assert "LOCAL INVENTORY" in out
    assert "1 credentials · 1 skipped · 1 providers" in out

def test_long_provider_metric_truncated():
    args = Namespace(no_color=True, all=False, placeholders=False, reused=False)
    setup_colors(args)
    
    cache = [{
        'provider': 'LONGPROV', 'var_name': 'LONG_KEY',
        'masked_key': '...', 'hash': 'abcdef12', 'files': ['a.env'],
        'status': {
            'provider': 'LONGPROV', 'category': 'CANDIDATE', 'auth': 'Valid',
            'funding': 'Unknown', 'access': 'Working', 'metric_type': 'NONE',
            'metric_value': 'A very long string that should get truncated because it exceeds the terminal width allowed for this column definitely yes it should',
            'metric_limit': None, 'metric_unit': '', 'identity': None, 'risk': 'Low',
            'checked_at': '', 'http_status': 200, 'debug_logs': []
        }
    }]
    
    stdout = io.StringIO()
    sys.stdout = stdout
    try:
        print_table(cache, args=args, is_scan=False, files_count=1)
    finally:
        sys.stdout = sys.__stdout__
        
    out = stdout.getvalue()
    assert "…" in out # Should contain truncation
    
    # Verify no line exceeds roughly 150 chars
    for line in out.splitlines():
        assert len(line) < 150
