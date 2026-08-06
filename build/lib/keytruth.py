#!/usr/bin/env python3
import os
import shutil
import re
import json
import hashlib
import argparse

import sys
USE_COLOR = (
    sys.stdout.isatty()
    and os.getenv("NO_COLOR") is None
    and os.getenv("TERM") != "dumb"
)
import urllib.request
import urllib.error
import time
import tempfile
import datetime
from pathlib import Path
from dataclasses import dataclass, field, asdict


GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"

def setup_colors(args):
    global GREEN, YELLOW, RED, CYAN, BOLD, RESET
    if getattr(args, 'no_color', False) or not USE_COLOR:
        GREEN = YELLOW = RED = CYAN = BOLD = RESET = ""

def color_status(value):
    base_val = value.split(":")[0]
    color = {
        "Valid": GREEN,
        "Working": GREEN,
        "Funded": GREEN,
        "Normal": GREEN,
        "Unknown": YELLOW,
        "Shared": YELLOW,
        "Review": YELLOW,
        "Critical": RED,
    }.get(base_val, "")
    return f"{color}{value}{RESET}"

CACHE_FILE = Path.home() / ".api_keys_cache.json"
SECRET_WORDS = ("API_KEY", "TOKEN", "SECRET", "ACCESS_KEY", "AUTH_KEY", "CREDENTIAL")

UNKNOWN_RECOMMENDATIONS = {
    "MISTRAL_API_KEY": "Supported: add Mistral mapping",
    "ELEVENLABS_API_KEY": "Supported: add ElevenLabs mapping",
    "HF_TOKEN": "Supported: add Hugging Face mapping",
    "RESEND_API_KEY": "Supported: add Resend mapping",
    "STRIPE_SECRET_KEY": "Financial: opt-in only",
    "REPLICATE_API_TOKEN": "Supported when detected",
}

@dataclass
class ProbeResult:
    provider: str
    category: str = "UNKNOWN"
    auth: str = "Unknown"
    funding: str = "Unknown"
    access: str = "Unknown"
    metric_type: str = "NONE" # BALANCE, USAGE, QUOTA, IDENTITY, ACCOUNT_BALANCE, NONE
    metric_value: float | str | None = None
    metric_limit: float | None = None
    metric_unit: str = ""
    identity: str | None = None
    risk: str = "Low"
    checked_at: str = ""
    http_status: int | None = None
    debug_logs: list[str] = field(default_factory=list)

VARIABLE_PROVIDERS = {
    "OPENAI_API_KEY": "OPENAI",
    "ANTHROPIC_API_KEY": "ANTHROPIC",
    "DEEPSEEK_API_KEY": "DEEPSEEK",
    "OPENROUTER_API_KEY": "OPENROUTER",
    "FAL_KEY": "FAL",
    "FAL_API_KEY": "FAL",
    "ELEVENLABS_API_KEY": "ELEVENLABS",
    "MISTRAL_API_KEY": "MISTRAL",
    "HF_TOKEN": "HUGGINGFACE",
    "HUGGINGFACE_TOKEN": "HUGGINGFACE",
    "HUGGING_FACE_HUB_TOKEN": "HUGGINGFACE",
    "RESEND_API_KEY": "RESEND",
    "STRIPE_SECRET_KEY": "STRIPE",
    "REPLICATE_API_TOKEN": "REPLICATE",
}

PROVIDERS = {
    'OPENAI': {'key_patterns': [r'\b(sk-proj-[a-zA-Z0-9_-]{20,})\b', r'\b(sk-[a-zA-Z0-9]{32,})\b']},
    'DEEPSEEK': {'key_patterns': [r'\b(sk-[a-zA-Z0-9]{32,})\b']},
    'OPENROUTER': {'key_patterns': [r'\b(sk-or-v1-[a-zA-Z0-9_-]{20,})\b']},
    'ANTHROPIC': {'key_patterns': [r'\b(sk-ant-[a-zA-Z0-9_-]{20,})\b']},
    'FAL': {},
    'ELEVENLABS': {},
    'MISTRAL': {},
    'HUGGINGFACE': {},
    'RESEND': {'key_patterns': [r'\b(re_[a-zA-Z0-9]{24,})\b']},
    'STRIPE': {'key_patterns': [r'\b(sk_(test|live)_[a-zA-Z0-9]+)\b']},
    'REPLICATE': {'key_patterns': [r'\b(r8_[a-zA-Z0-9]{37})\b']}
}

def log_debug(status, msg):
    status.debug_logs.append(msg)

def make_request(url, method="GET", headers=None, data=None):
    if headers is None: headers = {}
    if "Accept" not in headers: headers["Accept"] = "application/json"
    
    req_data = None
    if data:
        req_data = json.dumps(data).encode('utf-8')
        if "Content-Type" not in headers:
            headers["Content-Type"] = "application/json"
            
    req = urllib.request.Request(url, headers=headers, data=req_data, method=method)
    start_t = time.time()
    try:
        with urllib.request.urlopen(req, timeout=10) as res:
            body = res.read().decode('utf-8')
            latency = int((time.time() - start_t) * 1000)
            return res.status, body, latency
    except urllib.error.HTTPError as e:
        body = e.read().decode('utf-8', errors='ignore')
        latency = int((time.time() - start_t) * 1000)
        return e.code, body, latency
    except Exception as e:
        latency = int((time.time() - start_t) * 1000)
        return 0, str(e), latency

def probe_openai(key, is_financial=False, is_experimental=False):
    status = ProbeResult(provider="OPENAI", metric_value="Valid Format")
    
    headers = {"Authorization": f"Bearer {key}"}
    if is_experimental:
        code, body, lat = make_request("https://api.openai.com/v1/dashboard/billing/credit_grants", headers=headers)
        log_debug(status, f"[/v1/dashboard/billing/credit_grants] {code} {lat}ms: {body[:200]}")
        
        if code == 200:
            try:
                data = json.loads(body)
                status.auth = "Valid"
                status.metric_type = "BALANCE"
                status.metric_value = float(data.get('total_available', 0))
                status.metric_unit = "USD"
                status.funding = "Funded" if status.metric_value > 0 else "Depleted"
            except Exception:
                pass
        elif code == 401:
            if "invalid_api_key" in body or "Incorrect API key" in body or "must be made with a session key" not in body:
                status.auth = "Invalid"
                status.access = "None"
                status.metric_type = "NONE"
                status.metric_value = "Invalid Key"
                return status
                
    if status.auth == "Unknown":
        code, body, lat = make_request("https://api.openai.com/v1/models", headers=headers)
        log_debug(status, f"[/v1/models] {code} {lat}ms: {body[:200]}")
        if code == 200:
            status.auth = "Valid"
            status.http_status = code
        elif code == 401:
            status.auth = "Invalid"
            status.access = "None"
            status.metric_type = "NONE"
            status.metric_value = "Invalid Key"
            status.http_status = code
            return status
            
    if status.auth == "Valid":
        mod_data = {"input": "hello"}
        code, body, lat = make_request("https://api.openai.com/v1/moderations", method="POST", headers=headers, data=mod_data)
        log_debug(status, f"[/v1/moderations] {code} {lat}ms: {body[:200]}")
        if code == 200:
            status.access = "Working"
        elif code == 429:
            status.access = "Rate-limited"
            if "insufficient_quota" in body:
                status.funding = "Depleted"
                status.access = "Restricted"
        else:
            status.access = f"Error {code}"
            
    if status.metric_type == "NONE":
        status.metric_value = "No balance authority"
        
    return status

def probe_anthropic(key, is_financial=False):
    status = ProbeResult(provider="ANTHROPIC", category="AI Compute", checked_at=datetime.datetime.now().isoformat())
    headers = {"x-api-key": key, "anthropic-version": "2023-06-01"}
    
    code, body, lat = make_request("https://api.anthropic.com/v1/models", headers=headers)
    log_debug(status, f"[/v1/models] {code} {lat}ms: {body[:200]}")
    status.http_status = code
    
    probe_model = "claude-3-haiku-20240307"
    if code == 200:
        status.auth = "Valid"
        try:
            models_data = json.loads(body)
            models = [m["id"] for m in models_data.get("data", []) if "id" in m]
            if models:
                probe_model = models[0]
        except Exception:
            pass
    elif code == 401:
        status.auth = "Invalid"
        status.access = "None"
        status.metric_value = "Invalid Key"
        return status
    elif code == 403: 
        status.auth = "Valid"
        status.access = "Restricted"
        status.metric_value = "No balance endpoint"
        return status
        
    if status.auth == "Valid":
        ct_data = {"model": probe_model, "messages": [{"role": "user", "content": "hello"}]}
        code, body, lat = make_request("https://api.anthropic.com/v1/messages/count_tokens", method="POST", headers=headers, data=ct_data)
        log_debug(status, f"[count_tokens] {code} {lat}ms: {body[:200]}")
        
        if code == 200:
            status.access = "Working"
        elif code == 429:
            status.access = "Rate-limited"
        elif code == 400 and "credit balance too low" in body.lower():
            status.funding = "Depleted"
            status.access = "Restricted"
        elif code == 400: 
            status.access = "Unknown"
            status.metric_value = "count_tokens error"
        elif code == 403:
            status.access = "Restricted"
            
    if not status.metric_value:
        status.metric_value = "No balance endpoint"
    return status

def probe_deepseek(key, is_financial=False):
    status = ProbeResult(provider="DEEPSEEK", category="AI Compute", checked_at=datetime.datetime.now().isoformat())
    headers = {"Authorization": f"Bearer {key}"}
    code, body, lat = make_request("https://api.deepseek.com/user/balance", headers=headers)
    log_debug(status, f"[/user/balance] {code} {lat}ms: {body[:200]}")
    status.http_status = code
    
    if code == 200:
        status.auth = "Valid"
        status.access = "Working"
        try:
            data = json.loads(body)
            bal = float(data['balance_infos'][0]['total_balance'])
            status.metric_type = "BALANCE"
            status.metric_value = bal
            status.metric_unit = data['balance_infos'][0].get('currency', 'USD')
            status.funding = "Funded" if bal > 0 else "Depleted"
        except Exception:
            status.metric_value = "Balance Parse Error"
    elif code == 401:
        status.auth = "Invalid"
        status.access = "None"
        status.metric_value = "Invalid Key"
    elif code == 403:
        status.auth = "Valid"
        status.access = "Restricted"
        status.metric_value = "Forbidden"
    return status

def probe_openrouter(key, is_financial=False):
    status = ProbeResult(provider="OPENROUTER", category="AI Compute", checked_at=datetime.datetime.now().isoformat())
    headers = {"Authorization": f"Bearer {key}"}
    code, body, lat = make_request("https://openrouter.ai/api/v1/auth/key", headers=headers)
    log_debug(status, f"[/auth/key] {code} {lat}ms: {body[:200]}")
    status.http_status = code
    
    if code == 200:
        status.auth = "Valid"
        status.access = "Working"
        try:
            data = json.loads(body)
            status.metric_type = "USAGE"
            status.metric_value = float(data['data'].get('usage', 0))
            status.metric_unit = "USD"
            limit = data['data'].get('limit')
            if limit is not None:
                status.metric_limit = float(limit)
                status.funding = "Capped" if status.metric_value >= status.metric_limit else "Funded"
            else:
                status.funding = "Unknown"
        except Exception:
            status.metric_value = "Usage Parse Error"
    elif code == 401:
        status.auth = "Invalid"
        status.access = "None"
        status.metric_value = "Invalid Key"
    elif code == 403:
        status.auth = "Valid"
        status.access = "Restricted"
        status.metric_value = "Forbidden"
    return status

def probe_fal(key, is_financial=False):
    status = ProbeResult(provider="FAL", category="AI Compute", checked_at=datetime.datetime.now().isoformat())
    headers = {"Authorization": f"Key {key}"}
    
    code, body, latency = make_request("https://api.fal.ai/v1/account/billing?expand=credits", headers=headers)
    log_debug(status, f"[/billing] {code} {latency}ms: {body[:200]}")
    status.http_status = code
    
    if code == 200:
        try:
            data = json.loads(body)
            credits = data.get("credits") or {}
            balance = credits.get("current_balance")
            currency = credits.get("currency", "USD")
            status.auth = "Valid"
            status.access = "Working"
            if balance is not None:
                status.metric_type = "BALANCE"
                status.metric_value = float(balance)
                status.metric_unit = currency
                status.funding = "Funded" if float(balance) > 0 else "Depleted"
            else:
                status.metric_value = "Balance unavailable"
        except Exception:
            status.metric_value = "Balance Parse Error"
        return status
        
    if code == 401:
        status.auth = "Invalid"
        status.access = "None"
        status.metric_value = "Invalid Key"
        return status
        
    # Billing may require Admin scope, test /v1/models
    code, body, latency = make_request("https://api.fal.ai/v1/models?limit=1", headers=headers)
    log_debug(status, f"[/v1/models] {code} {latency}ms: {body[:200]}")
    if code == 200:
        status.auth = "Valid"
        status.access = "Working"
        status.metric_value = "No billing authority"
    elif code == 401:
        status.auth = "Invalid"
        status.access = "None"
        status.metric_value = "Invalid Key"
    elif code == 403:
        status.auth = "Valid"
        status.access = "Restricted"
        status.metric_value = "Insufficient scope"
    elif code == 429:
        status.auth = "Valid"
        status.access = "Rate-limited"
        status.metric_value = "Balance unknown"
        
    return status

def probe_elevenlabs(key, is_financial=False):
    status = ProbeResult(provider="ELEVENLABS", category="SaaS Quota", checked_at=datetime.datetime.now().isoformat())
    headers = {"xi-api-key": key}
    code, body, latency = make_request("https://api.elevenlabs.io/v1/user/subscription", headers=headers)
    log_debug(status, f"[/user/subscription] {code} {latency}ms: {body[:200]}")
    status.http_status = code
    
    if code == 200:
        try:
            data = json.loads(body)
            status.auth = "Valid"
            status.access = "Working"
            status.identity = data.get('tier', 'Unknown Tier')
            status.metric_type = "QUOTA"
            status.metric_value = data.get('character_count', 0)
            status.metric_limit = data.get('character_limit', 0)
            status.metric_unit = "characters"
        except Exception:
            status.metric_value = "Subscription Parse Error"
    elif code == 401:
        status.auth = "Invalid"
        status.access = "None"
        status.metric_value = "Invalid/Missing Key"
    elif code == 403:
        status.auth = "Valid"
        status.access = "Restricted"
        status.metric_value = "IP Blocked or Restricted"
    return status

def probe_mistral(key, is_financial=False):
    status = ProbeResult(provider="MISTRAL", category="AI Compute", checked_at=datetime.datetime.now().isoformat())
    headers = {"Authorization": f"Bearer {key}"}
    code, body, latency = make_request("https://api.mistral.ai/v1/models", headers=headers)
    log_debug(status, f"[/v1/models] {code} {latency}ms: {body[:200]}")
    status.http_status = code
    
    if code == 200:
        status.auth = "Valid"
        status.access = "Working"
        status.metric_value = "No balance authority"
    elif code == 401:
        status.auth = "Invalid"
        status.access = "None"
        status.metric_value = "Invalid Key"
    elif code == 402:
        status.auth = "Valid"
        status.access = "Restricted"
        status.metric_value = "No payment method"
    elif code == 429:
        status.auth = "Valid"
        status.access = "Rate-limited"
        status.metric_value = "Balance unknown"
    return status

def probe_huggingface(key, is_financial=False):
    status = ProbeResult(provider="HUGGINGFACE", category="AI Platform", checked_at=datetime.datetime.now().isoformat())
    headers = {"Authorization": f"Bearer {key}"}
    code, body, latency = make_request("https://huggingface.co/api/whoami-v2", headers=headers)
    log_debug(status, f"[/api/whoami-v2] {code} {latency}ms: {body[:200]}")
    status.http_status = code
    
    if code == 200:
        status.auth = "Valid"
        try:
            data = json.loads(body)
            status.identity = data.get('name')
            role = "Unknown"
            if "auth" in data and "accessToken" in data["auth"]:
                role = data["auth"]["accessToken"].get("role", "Unknown")
            status.access = role.capitalize()
            status.metric_type = "IDENTITY"
            status.metric_value = "No simple credit endpoint"
        except Exception:
            status.metric_value = "Identity Parse Error"
    elif code == 401:
        status.auth = "Invalid"
        status.access = "None"
        status.metric_value = "Invalid Key"
    return status

def probe_resend(key, is_financial=False):
    status = ProbeResult(provider="RESEND", category="SaaS Quota", checked_at=datetime.datetime.now().isoformat())
    headers = {"Authorization": f"Bearer {key}", "User-Agent": "keys-cli/1.0"}
    code, body, latency = make_request("https://api.resend.com/api-keys", headers=headers)
    log_debug(status, f"[/api-keys] {code} {latency}ms: {body[:200]}")
    status.http_status = code
    
    if code == 200:
        status.auth = "Valid"
        status.access = "Full"
        try:
            data = json.loads(body)
            keys = data.get("data", [])
            status.metric_type = "KEY_COUNT"
            if keys:
                status.metric_value = f"Full access · {len(keys)} API keys visible"
                status.metric_unit = ""
            else:
                status.metric_value = "Full access · 0 API keys visible"
                status.metric_unit = ""
        except Exception:
            status.metric_value = "Parse Error"
    elif code == 401:
        status.auth = "Invalid"
        status.access = "None"
        status.metric_value = "Invalid Key"
    elif code == 403:
        status.auth = "Unknown"
        status.access = "Restricted"
        status.metric_value = "Sending-only or Missing Scope"
    elif code == 429:
        status.auth = "Valid"
        status.access = "Rate-limited"
        status.metric_value = "Balance unknown"
    return status

def probe_stripe(key, is_financial=False):
    status = ProbeResult(provider="STRIPE", category="Financial", checked_at=datetime.datetime.now().isoformat())
    status.identity = "Live mode" if key.startswith("sk_live_") else "Test mode"
    
    if not is_financial:
        status.auth = "Detected"
        status.access = "Not probed"
        status.metric_value = "Live key — opt-in required" if key.startswith("sk_live_") else "Test key"
        return status
        
    headers = {"Authorization": f"Bearer {key}"}
    code, body, latency = make_request("https://api.stripe.com/v1/balance", headers=headers)
    
    # Do not log raw response body for Stripe in debug logs!
    log_debug(status, f"[/v1/balance] {code} {latency}ms: <REDACTED FINANCIAL DATA>")
    status.http_status = code
    
    if code == 200:
        status.auth = "Valid"
        status.access = "Working"
        try:
            data = json.loads(body)
            # Find primary currency available/pending (Stripe amounts are in cents)
            available = sum(b.get("amount", 0) for b in data.get("available", [])) / 100
            pending = sum(b.get("amount", 0) for b in data.get("pending", [])) / 100
            
            # Use the first currency if available
            currency = "USD"
            if data.get("available") and len(data["available"]) > 0:
                currency = data["available"][0].get("currency", "usd").upper()
                
            status.metric_type = "ACCOUNT_BALANCE"
            status.metric_value = available
            status.metric_limit = pending
            status.metric_unit = currency
        except Exception:
            status.metric_value = "Balance Parse Error"
    elif code == 401:
        status.auth = "Invalid"
        status.access = "None"
        status.metric_value = "Invalid Key"
    elif code == 403:
        status.auth = "Valid"
        status.access = "Restricted"
        status.metric_value = "Restricted key"
        
    return status

def probe_replicate(key, is_financial=False):
    status = ProbeResult(provider="REPLICATE", category="AI Compute", checked_at=datetime.datetime.now().isoformat())
    headers = {"Authorization": f"Bearer {key}"}
    
    code, body, latency = make_request("https://api.replicate.com/v1/account", headers=headers)
    log_debug(status, f"[/v1/account] {code} {latency}ms: {body[:200]}")
    status.http_status = code
    
    if code == 200:
        try:
            data = json.loads(body)
            status.auth = "Valid"
            status.access = "Working"
            status.funding = "Unknown"
            status.metric_type = "IDENTITY"
            status.identity = str(data.get("username") or data.get("name") or "confirmed")
            status.metric_value = "Account confirmed"
        except Exception:
            status.metric_value = "Account Parse Error"
    elif code == 401:
        status.auth = "Invalid"
        status.access = "None"
        status.metric_value = "Invalid Key"
    elif code == 403:
        status.auth = "Unknown"
        status.access = "Restricted"
        status.metric_value = "Account access refused"
    elif code == 429:
        status.auth = "Valid"
        status.access = "Rate-limited"
        status.metric_value = "Balance unknown"
        
    return status

PROBERS = {
    'OPENAI': probe_openai,
    'ANTHROPIC': probe_anthropic,
    'DEEPSEEK': probe_deepseek,
    'OPENROUTER': probe_openrouter,
    'FAL': probe_fal,
    'REPLICATE': probe_replicate,
    'ELEVENLABS': probe_elevenlabs,
    'MISTRAL': probe_mistral,
    'HUGGINGFACE': probe_huggingface,
    'RESEND': probe_resend,
    'STRIPE': probe_stripe,
}

def mask_key(key):
    if len(key) <= 12:
        return "****"
    return f"{key[:8]}...{key[-4:]}"

def hash_key(key):
    return hashlib.sha256(key.encode()).hexdigest()[:12]

def classify_key(key):
    k_lower = key.lower()
    if not key or key == '****': return "Empty"
    if 'replace' in k_lower or 'your' in k_lower or 'here' in k_lower or 'provided' in k_lower:
        return "Placeholder"
    if '...' in key or '<' in key or '{' in key:
        return "Placeholder"
    if len(key) < 15 and not key.startswith('sk-') and not key.startswith('r8_'):
        return "Malformed"
    if ' ' in key or '=' in key:
        return "Malformed"
    return "Candidate"

def classify_assignment(name, value):
    is_ph = (classify_key(value) != "Candidate")
    
    provider = VARIABLE_PROVIDERS.get(name)
    if provider:
        return provider, is_ph
        
    for provider, config in PROVIDERS.items():
        for pattern_str in config.get('key_patterns', []):
            if re.match(pattern_str, value):
                return provider, is_ph
                
    if any(word in name.upper() for word in SECRET_WORDS):
        if is_ph:
            return "IGNORE", True
        return "UNKNOWN", False
        
    return "IGNORE", is_ph

def find_env_files(scan_paths, verbose=False):
    exclude_dirs = {'node_modules', '.git', 'Library', 'Applications', 'Downloads', 'Pictures', 'Music', 'Movies', '.venv', 'venv'}
    files = []
    
    for base_path in scan_paths:
        base_dir = Path(base_path).resolve()
        if not base_dir.is_dir():
            if base_dir.is_file() and '.env' in base_dir.name:
                files.append(str(base_dir))
            continue
            
        for root, dirs, filenames in os.walk(base_dir):
            dirs[:] = [d for d in dirs if d not in exclude_dirs and not d.startswith('.Trash')]
            # strict dir skipping for symlinks
            dirs[:] = [d for d in dirs if not os.path.islink(os.path.join(root, d))]
            
            for name in filenames:
                if '.env' in name:
                    full_path = os.path.join(root, name)
                    if os.path.islink(full_path):
                        continue
                    try:
                        if os.path.getsize(full_path) > 1024 * 1024:
                            if verbose: print(f"Skipping {full_path} (too large)")
                            continue
                        files.append(full_path)
                    except OSError as e:
                        if verbose: print(f"Cannot read {full_path}: {e}")
    return list(set(files))

def extract_keys(files, capture_unknown=False):
    found_keys = {}
    
    for f in files:
        if not os.path.isfile(f): continue
        try:
            with open(f, 'r', encoding='utf-8', errors='ignore') as file:
                content = file.read()
                
                for line in content.splitlines():
                    line = line.strip()
                    if line.startswith('#'): continue
                    
                    match = re.match(r'^(?:export\s+)?([A-Z0-9_]+)\s*=\s*(.*)$', line, re.IGNORECASE)
                    if match:
                        var_name, val = match.groups()
                        val = val.strip('\'" ')
                        
                        provider, is_ph = classify_assignment(var_name, val)
                        if provider == "IGNORE":
                            continue
                            
                        if provider == "UNKNOWN" and not capture_unknown:
                            continue
                            
                        key_hash = hash_key(val)
                        if key_hash not in found_keys:
                            found_keys[key_hash] = {
                                'provider': provider,
                                'var_name': var_name,
                                'key': val,
                                'masked': mask_key(val),
                                'files': set()
                            }
                        found_keys[key_hash]['files'].add(f)
                        
                for provider, config in PROVIDERS.items():
                    for pattern_str in config.get('key_patterns', []):
                        for key in re.findall(pattern_str, content):
                            if classify_key(key) != "Candidate":
                                continue
                            key_hash = hash_key(key)
                            if key_hash not in found_keys:
                                found_keys[key_hash] = {
                                    'provider': provider,
                                    'var_name': '',
                                    'key': key,
                                    'masked': mask_key(key),
                                    'files': set()
                                }
                            found_keys[key_hash]['files'].add(f)
        except Exception:
            pass
            
    for k in found_keys:
        found_keys[k]['files'] = list(found_keys[k]['files'])
    return found_keys

def display_status(result):
    if result.metric_type == "PLACEHOLDER" or result.metric_value == "Placeholder":
        return "Placeholder"
    if result.auth == "Invalid":
        return "Invalid"
    if result.access in {"Full", "Write", "Read"}:
        return result.access
    if result.access == "Working":
        return "Working"
    if result.access == "Restricted":
        return "Restricted" if result.auth == "Valid" else "Unverified"
    if result.access == "Rate-limited":
        return "Rate limited"
    if result.auth == "Valid":
        return "Valid"
    return "Unknown"

def format_metric_compact(status) -> str:
    if status.metric_type == "BALANCE":
        sym = "$" if status.metric_unit == "USD" else status.metric_unit + " "
        return f"Balance {sym}{status.metric_value:.2f}"
    elif status.metric_type == "USAGE":
        if status.metric_limit is not None:
            return f"Usage {status.metric_value} / {status.metric_limit} {status.metric_unit}".strip()
        else:
            return f"Usage {status.metric_value} {status.metric_unit}".strip()
    elif status.metric_type == "QUOTA":
        try:
            val = float(status.metric_value)
            if status.metric_limit is not None:
                lim = float(status.metric_limit)
                return f"{val:,.0f} / {lim:,.0f} {status.metric_unit}".strip()
            else:
                return f"{val:,.0f} {status.metric_unit}".strip()
        except:
            return str(status.metric_value)
    elif status.metric_type == "ACCOUNT_BALANCE":
        try:
            val = float(status.metric_value)
            lim = float(status.metric_limit)
            sym = "€" if status.metric_unit == "EUR" else "$" if status.metric_unit == "USD" else status.metric_unit + " "
            return f"{sym}{val:g} avail • {sym}{lim:g} pending"
        except:
            return str(status.metric_value)
    elif status.metric_type == "IDENTITY":
        if status.identity:
            return f"User: {status.identity}"
        return str(status.metric_value)
    else:
        return str(status.metric_value)

def format_metric(status: ProbeResult) -> str:
    if status.metric_type == "BALANCE":
        sym = "$" if status.metric_unit == "USD" else status.metric_unit + " "
        return f"Balance {sym}{status.metric_value:.2f}"
    elif status.metric_type == "USAGE":
        if status.metric_limit is not None:
            return f"Usage {status.metric_value} / {status.metric_limit} {status.metric_unit}".strip()
        else:
            return f"Usage {status.metric_value} {status.metric_unit}".strip()
    elif status.metric_type == "QUOTA":
        try:
            val = float(status.metric_value)
            if status.metric_limit is not None:
                lim = float(status.metric_limit)
                return f"{val:,.0f} / {lim:,.0f} {status.metric_unit}".strip()
            else:
                return f"{val:,.0f} {status.metric_unit}".strip()
        except:
            return str(status.metric_value)
    elif status.metric_type == "ACCOUNT_BALANCE":
        try:
            val = float(status.metric_value)
            lim = float(status.metric_limit)
            return f"{status.metric_unit} {val:,.2f} available / {status.metric_unit} {lim:,.2f} pending"
        except:
            return str(status.metric_value)
    elif status.metric_type == "IDENTITY":
        if status.identity:
            return f"User: {status.identity}"
        return str(status.metric_value)
    else:
        return str(status.metric_value)

ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")

def visible_len(text):
    return len(ANSI_RE.sub("", text))

def fit(text, width):
    plain = ANSI_RE.sub("", text)
    if len(plain) <= width:
        return text + " " * (width - len(plain))
    return plain[:max(0, width - 1)] + "…"

def panel_lines(title, lines, width) -> list[str]:
    title_text = f" {title} "
    top = f"╭─{title_text}{'─' * max(0, width - 3 - visible_len(title_text))}╮"
    bottom = f"╰{'─' * max(0, width - 2)}╯"
    out = [top]
    for line in lines:
        out.append(f"│ {fit(line, width - 4)} │")
    out.append(bottom)
    return out

def join_panels(left, right, gap=2) -> list[str]:
    out = []
    max_len = max(len(left), len(right))
    left_width = visible_len(left[0]) if left else 0
    right_width = visible_len(right[0]) if right else 0
    
    for i in range(max_len):
        l_line = left[i] if i < len(left) else " " * left_width
        r_line = right[i] if i < len(right) else ""
        out.append(f"{l_line}{' ' * gap}{r_line}")
    return out

def print_header_dashboard(known, candidates, non_candidates, critical_alerts, invalid_keys, probe_issues, providers, is_scan, term_width):
    # For probe view header
    width = term_width if term_width < 80 else 80
    
    w_count = 0
    for d in known:
        if d.get('_display_status') in ("Working", "Full", "Read", "Write") and not (d.get('_metric_str') in ("Placeholder", "Empty", "Malformed")):
            w_count += 1
            
    c_prov = len(set(d['provider'] for d in candidates))
    l1 = f"{len(candidates)} credentials    {len(non_candidates)} skipped    {c_prov} providers    local-only"
    l2 = f"✓ {w_count} working      ! {len(probe_issues)} probe issues   ✕ {len(invalid_keys)} invalid      ! {len(critical_alerts)} critical"
    
    for line in panel_lines("KeyTruth v0.1.0", [l1, l2], width):
        print(line)
    print()

def print_local_inventory_panel(files_count, known, candidates, non_candidates, critical_alerts, review_shared, term_width):
    width = term_width if term_width < 80 else 80
    c_prov = len(set(d['provider'] for d in candidates))
    
    lines = [
        f"{files_count} .env files scanned",
        f"{len(candidates)} credentials · {len(non_candidates)} skipped · {c_prov} providers",
        f"{len(critical_alerts)} critical reuse risks · {len(review_shared)} shared credentials",
        f"Cache: ~/.api_keys_cache.json · permissions 600"
    ]
    for line in panel_lines("LOCAL INVENTORY", lines, width):
        print(line)
    print()
    print("Next: keytruth probe")

def print_action_panel(critical_alerts, probe_issues, invalid_keys, review_shared, term_width):
    width = term_width if term_width < 80 else 80
    lines = []
    
    if critical_alerts:
        for d in critical_alerts:
            msg = d['status']['risk'].split(":", 1)[1].strip() if ":" in d['status']['risk'] else "Critical risk"
            lines.append(f"{RED}!{RESET} {d['provider']:<10} {d['hash'][:8]}   {msg}")
            
    if probe_issues:
        for d in probe_issues:
            lines.append(f"{YELLOW}!{RESET} {d['provider']:<10} {d['hash'][:8]}   {d['_metric_compact']}")
            
    if invalid_keys:
        inv_by_prov = {}
        for d in invalid_keys:
            inv_by_prov[d['provider']] = inv_by_prov.get(d['provider'], 0) + 1
            
        if lines:
            lines.append("") # spacer
            
        inv_str = " · ".join(f"{p} {c}" for p, c in sorted(inv_by_prov.items(), key=lambda x: x[1], reverse=True))
        lines.append(f"✕  {len(invalid_keys)} invalid keys: {inv_str}")
        
    if review_shared:
        if lines:
            lines.append("")
        for d in review_shared:
            msg = f"appears in {len(d['files'])} files" if d['_risk_label'] == "Shared" else d['status']['risk']
            lines.append(f"{YELLOW}!{RESET} {d['provider']:<10} {d['hash'][:8]}   {msg}")
            
    if not lines:
        lines = ["No action required"]
        
    for line in panel_lines("ACTION REQUIRED", lines, width):
        print(line)
    print()

def print_metric_panels(known, term_width):
    money_lines = []
    access_lines = []
    
    for d in known:
        if d.get('_metric_str') in ("Placeholder", "Empty", "Malformed"): continue
        if d['_display_status'] == "Invalid": continue
        
        status = ProbeResult(**d['status'])
        if status.metric_type in ("BALANCE", "ACCOUNT_BALANCE", "USAGE"):
            money_lines.append(f"{d['provider']:<14} {d['_metric_compact']}")
        elif status.metric_type == "IDENTITY" or status.access in ("Full", "Write", "Read"):
            access_lines.append(f"{d['provider']:<14} {d['_metric_compact']}")
            
    if not money_lines and not access_lines:
        return
        
    side_by_side = term_width >= 110
    half_width = (term_width - 4) // 2 if side_by_side else (term_width if term_width < 80 else 80)
    if half_width > 50: half_width = 50
    
    p_money = panel_lines("MONEY & QUOTA", money_lines if money_lines else ["No financial capabilities"], half_width)
    p_access = panel_lines("ACCESS", access_lines if access_lines else ["No identity capabilities"], half_width)
    
    if side_by_side:
        for line in join_panels(p_money, p_access):
            print(line)
        print()
    else:
        for line in p_money:
            print(line)
        print()
        for line in p_access:
            print(line)
        print()

def print_provider_panel(known, invalid_keys, probe_issues, term_width):
    width = term_width if term_width < 80 else 80
    providers = sorted(set(d['provider'] for d in known))
    
    prov_stats = {}
    for d in known:
        p = d['provider']
        if p not in prov_stats:
            prov_stats[p] = {'working': 0, 'issues': 0, 'metrics': [], 'critical': 0}
        
        if d['_display_status'] == "Invalid" or d['_risk_label'] == "Critical" or d in probe_issues:
            prov_stats[p]['issues'] += 1
            if d['_risk_label'] == "Critical":
                prov_stats[p]['critical'] += 1
            
        if d['_display_status'] in ("Working", "Full", "Read", "Write"):
            prov_stats[p]['working'] += 1
            if d['_metric_compact'] not in ("Placeholder", "Empty", "Malformed"):
                prov_stats[p]['metrics'].append(d['_metric_compact'])
                
    lines = []
    for p in providers:
        w = prov_stats[p]['working']
        i = prov_stats[p]['issues']
        c = prov_stats[p]['critical']
        metrics = prov_stats[p]['metrics']
        
        unique = sorted(set(metrics))
        
        if c > 0:
            m_str = f"{RED}{c} critical reuse alerts{RESET}"
        elif not unique:
            if any(d['provider'] == p and d['_display_status'] == "Invalid" for d in invalid_keys):
                m_str = "Invalid/missing key"
            else:
                m_str = "No healthy keys"
        elif len(unique) == 1:
            m_str = unique[0]
        else:
            has_balance = any(
                ProbeResult(**d['status']).metric_type in {"BALANCE", "ACCOUNT_BALANCE"} 
                for d in known 
                if d['provider'] == p and d['_display_status'] in {"Working", "Full", "Read", "Write"}
            )
            if has_balance:
                m_str = f"{len(metrics)} balance-bearing keys"
            else:
                m_str = f"{len(metrics)} active keys"
                
        if w > 0 and i > 0:
            bullet = f"{YELLOW}◐{RESET}"
        elif w > 0:
            bullet = f"{GREEN}●{RESET}"
        elif i > 0:
            bullet = f"{RED}○{RESET}"
        else:
            bullet = "○"
            
        lines.append(f"{bullet} {p:<12} {w} working   {i} issues      {m_str}")
        
    if not lines:
        lines = ["No providers found"]
        
    for line in panel_lines("PROVIDERS", lines, width):
        print(line)
    print()

def print_table(results_cache, args=None, is_scan=False, files_count=0):
    show_all = getattr(args, 'all', False) if args else False
    show_placeholders = getattr(args, 'placeholders', False) if args else False
    reused_only = getattr(args, 'reused', False) if args else False
    
    known = [d for d in results_cache if d['provider'] != 'UNKNOWN']
    if reused_only:
        known = [d for d in known if len(d['files']) > 1]
    
    candidates = [d for d in known if d.get('status', {}).get('metric_value') not in ("Placeholder", "Empty", "Malformed")]
    non_candidates = [d for d in known if d.get('status', {}).get('metric_value') in ("Placeholder", "Empty", "Malformed")]
    
    term_width = shutil.get_terminal_size((80, 20)).columns
    is_narrow = term_width < 95
    
    critical_alerts = []
    probe_issues = []
    invalid_keys = []
    review_shared = []
    
    for data in known:
        status = ProbeResult(**data['status'])
        raw_risk = status.risk
        
        if raw_risk == "Low":
            risk_label = "Normal"
        elif ":" in raw_risk:
            risk_label = raw_risk.split(":")[0]
        elif len(data['files']) > 1:
            risk_label = "Shared"
        else:
            risk_label = "Normal"
            
        data['_risk_label'] = risk_label
        data['_metric_str'] = format_metric(status)
        data['_metric_compact'] = format_metric_compact(status)
        data['_display_status'] = display_status(status)
        
        is_placeholder = data['_metric_str'] in ("Placeholder", "Empty", "Malformed")
        if not is_placeholder:
            st = data['_display_status']
            if risk_label == "Critical":
                critical_alerts.append(data)
            elif st in ("Restricted", "Unverified") or ("error" in data['_metric_str'].lower()) or ("refused" in data['_metric_str'].lower()) or ("failed" in data['_metric_str'].lower()):
                probe_issues.append(data)
            elif st == "Invalid" or st == "Placeholder":
                invalid_keys.append(data)
            elif risk_label in ("Review", "Shared"):
                review_shared.append(data)

    def sort_weight(data):
        st = data['_display_status']
        risk = data['_risk_label']
        is_ph = data['_metric_str'] in ("Placeholder", "Empty", "Malformed")
        
        if risk == "Critical": return 1
        if st in ("Restricted", "Unverified") or ("error" in data['_metric_str'].lower()) or ("refused" in data['_metric_str'].lower()) or ("failed" in data['_metric_str'].lower()): return 2
        if st == "Invalid": return 3
        if risk in ("Review", "Shared"): return 4
        if not is_ph: return 5
        return 6
        
    known.sort(key=sort_weight)

    if not known:
        print(f"{GREEN}KeyTruth v0.1.0{RESET}")
        print("0 credentials • 0 placeholders • 0 providers")
        print(f"Privacy: local-only • no plaintext keys cached\n")
        return

    if not show_all:
        if is_scan:
            print_local_inventory_panel(files_count, known, candidates, non_candidates, critical_alerts, review_shared, term_width)
        else:
            print_header_dashboard(known, candidates, non_candidates, critical_alerts, invalid_keys, probe_issues, set(d['provider'] for d in known), is_scan, term_width)
            print_action_panel(critical_alerts, probe_issues, invalid_keys, review_shared, term_width)
            print_metric_panels(known, term_width)
            print_provider_panel(known, invalid_keys, probe_issues, term_width)
            
            print(f"Details: keytruth probe --all")
            print(f"Reuse:   keytruth probe --reused")
    else:
        # Detailed UI view
        to_show = known
        if not show_placeholders:
            to_show = [d for d in known if d['_metric_str'] not in ("Placeholder", "Empty", "Malformed")]
            
        print(f"{GREEN}KeyTruth v0.1.0{RESET}")
        c_providers = set(d['provider'] for d in candidates)
        print(f"{len(candidates)} credentials • {len(non_candidates)} placeholders • {len(c_providers)} providers")
        if critical_alerts or invalid_keys or probe_issues or review_shared:
            print(f"{len(critical_alerts)} critical • {len(probe_issues)} probe issues • {len(invalid_keys)} invalid • {len(review_shared)} shared")
        print(f"Privacy: local-only • no plaintext keys cached\n")

        if is_narrow:
            for data in to_show:
                risk_label = data['_risk_label']
                print(f"{CYAN}⚠ {data['provider']} {data['hash'][:8]}{RESET}")
                
                disp = data['_display_status']
                if risk_label == "Normal":
                    risk_str = ""
                else:
                    risk_str = f"  Risk:   {color_status(risk_label)}\n"
                    
                print(f"  Status: {color_status(disp)}")
                print(f"  Metric: {data['_metric_str']}")
                if risk_str:
                    print(risk_str, end="")
                else:
                    print()
        else:
            print("┌──────────┬──────────────┬────────────┬──────────────────────────────────────┬──────────┐")
            print("│ KEY ID   │ PROVIDER     │ STATUS     │ METRIC                               │ RISK     │")
            print("├──────────┼──────────────┼────────────┼──────────────────────────────────────┼──────────┤")
            for data in to_show:
                risk_label = data['_risk_label']
                risk_str = "" if risk_label == "Normal" else risk_label
                
                metric_str = data['_metric_str']
                if len(metric_str) > 36:
                    metric_str = metric_str[:33] + "..."
                    
                disp = data['_display_status']
                c_status = color_status(disp)
                c_risk = color_status(risk_str) if risk_str else ""
                
                pad_status = 10 - len(disp)
                pad_risk = 8 - len(risk_str)
                
                print(f"│ {data['hash'][:8]:<8} │ {data['provider']:<12} │ {c_status}{' '*pad_status} │ {metric_str:<36} │ {c_risk}{' '*pad_risk} │")
            print("└──────────┴──────────────┴────────────┴──────────────────────────────────────┴──────────┘")

        # Reuse Alerts are shown at bottom of table for scan
        if (critical_alerts or review_shared) and is_scan:
            alerts = [(d['_risk_label'], d['provider'], d['hash'][:8], d['status']['risk'] if 'risk' in d['status'] and ":" in d['status']['risk'] else "") for d in critical_alerts + review_shared]
            print()
            print(f"{CYAN}Reuse Alerts{RESET}")
            for r_label, prov, k_id, msg in alerts:
                if ":" in msg: msg = msg.split(":", 1)[1].strip()
                if not msg and r_label == "Shared": msg = "appears in multiple files"
                color = RED if r_label == "Critical" else YELLOW
                print(f"{color}●{RESET} {prov} key {k_id} {msg} ({color_status(r_label)})")

def print_discovery_report(results_cache):
    unknowns = [d for d in results_cache if d['provider'] == 'UNKNOWN']
    if not unknowns:
        print()
        print("No UNKNOWN assignments found.")
        return
        
    summary = {}
    for d in unknowns:
        var_name = d['var_name']
        if var_name not in summary:
            summary[var_name] = {'assignments': 0, 'files': set()}
        summary[var_name]['assignments'] += 1
        summary[var_name]['files'].update(d['files'])
        
    print()
    print(f"{CYAN}Unknown Discovery Report{RESET}")
    print("┌───────────────────────────┬────────┬────────┬──────────────────┐")
    print("│ VARIABLE                  │ VALUES │ FILES  │ RECOMMENDATION   │")
    print("├───────────────────────────┼────────┼────────┼──────────────────┤")
    for var_name, stats in sorted(summary.items(), key=lambda x: x[1]['assignments'], reverse=True):
        vals = stats['assignments']
        files = len(stats['files'])
        rec = "Inventory only" if files > 2 else "Inspect manually"
        vname = var_name[:25]
        print(f"│ {vname:<25} │ {vals:<6} │ {files:<6} │ {rec:<16} │")
    print("└───────────────────────────┴────────┴────────┴──────────────────┘")

def print_unknowns(results_cache):
    print_discovery_report(results_cache)

def main():
    parser = argparse.ArgumentParser(description="KeyTruth: Discover and evaluate API credentials.")
    subparsers = parser.add_subparsers(dest="command", required=True)
    
    scan_parser = subparsers.add_parser('scan', help="Scan directories for API keys locally (no network requests)")
    scan_parser.add_argument('paths', nargs='*', default=['.'], help="Paths to scan (default: current directory)")
    scan_parser.add_argument('--unknown', action='store_true', help="Output unknown variable names that look like secrets")
    scan_parser.add_argument('--group-by-variable', action='store_true', help="Summarize unknown variables")
    scan_parser.add_argument('--reused', action='store_true', help="Only show credentials reused across multiple files")
    scan_parser.add_argument('--all', action='store_true', help="Show the complete detailed credential table")
    scan_parser.add_argument('--no-color', action='store_true', help="Disable ANSI color output")
    
    probe_parser = subparsers.add_parser('probe', help="Probe discovered keys against provider networks")
    probe_parser.add_argument('paths', nargs='*', help="Paths to scan and probe (default: uses last scanned paths from cache)")
    probe_parser.add_argument('--financial', action='store_true', help="Opt-in to querying sensitive financial credentials like Stripe")
    probe_parser.add_argument('--experimental', action='store_true', help="Enable undocumented/fragile endpoints (like OpenAI credit_grants)")
    probe_parser.add_argument('--debug', action='store_true', help="Print complete network trace and classification logs")
    probe_parser.add_argument('--all', action='store_true', help="Show the complete detailed credential table")
    probe_parser.add_argument('--placeholders', action='store_true', help="Include placeholders in the detailed table (implies --all)")
    probe_parser.add_argument('--reused', action='store_true', help="Only show credentials reused across multiple files")
    probe_parser.add_argument('--no-color', action='store_true', help="Disable ANSI color output")
    
    args = parser.parse_args()
    setup_colors(args)

    if getattr(args, 'placeholders', False):
        args.all = True

    if args.command == 'scan':
        run_scan(args)
    elif args.command == 'probe':
        run_probe(args)

def run_scan(args):
    print(f"Scanning {', '.join(args.paths)} for .env files (local only)...")
    files = find_env_files(args.paths, verbose=False)
    print(f"Found {len(files)} .env files. Extracting and classifying keys...")
    
    inventory = extract_keys(files, capture_unknown=args.unknown)
    results_cache = []
    
    for key_hash, data in inventory.items():
        provider = data['provider']
        
        category = classify_key(data['key'])
        
        if category != "Candidate":
            status = ProbeResult(provider=provider, metric_value=category, auth="Not tested", access="None")
        else:
            status = ProbeResult(provider=provider, metric_value="Unprobed" if provider != "UNKNOWN" else "Unknown Provider")
        
        results_cache.append({
            'provider': provider,
            'var_name': data['var_name'],
            'masked_key': data['masked'],
            'hash': key_hash,
            'status': asdict(status),
            'files': data['files']
        })
        
    cache_payload = {
        "schema_version": 3,
        "scan": {
            "roots": [str(Path(p).resolve()) for p in args.paths],
            "scanned_at": datetime.datetime.now().isoformat(),
            "inventory": results_cache
        },
        "probe": {}
    }
    
    write_cache(cache_payload)
    print(f"\nLocal inventory saved securely to {CACHE_FILE}")
    print_table(results_cache, args=args, is_scan=True, files_count=len(files))
    if args.unknown:
        if args.group_by_variable:
            print_discovery_report(results_cache)
        else:
            print_unknowns(results_cache)

def write_cache(cache_payload):
    CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(mode="w", dir=CACHE_FILE.parent, delete=False, encoding="utf-8") as tmp:
        json.dump(cache_payload, tmp, indent=2)
        tmp_path = Path(tmp.name)
        
    os.chmod(tmp_path, 0o600)
    os.replace(tmp_path, CACHE_FILE)

def run_probe(args):
    if not CACHE_FILE.exists():
        print("No cache found. Run `keytruth scan .` first.")
        return
        
    try:
        with open(CACHE_FILE, 'r') as f:
            cache_data = json.load(f)
    except Exception:
        print("Cache format invalid. Run `keytruth scan .` again.")
        return
        
    if cache_data.get("schema_version") != 3:
        print("Cache format changed (schema v3 required). Run `keytruth scan .` first.")
        return
        
    scan_data = cache_data.get("scan", {})
    roots = args.paths if args.paths else scan_data.get("roots", ["."])
    
    if not args.debug:
        print(f"Rescanning {', '.join(roots)} to find raw keys...")
    files = find_env_files(roots, verbose=False)
    inventory = extract_keys(files, capture_unknown=False)
    
    if not args.debug:
        print("Probing networks...")
        
    results_cache = []
    
    for key_hash, data in inventory.items():
        provider = data['provider']
        raw_key = data['key']
        
        if provider == "UNKNOWN":
            continue
            
        category = classify_key(raw_key)
        if category != "Candidate":
            status = ProbeResult(provider=provider, metric_value=category, auth="Not tested", access="None")
        else:
            prober = PROBERS.get(provider)
            if prober:
                if provider == 'OPENAI':
                    status = prober(raw_key, is_financial=args.financial, is_experimental=args.experimental)
                else:
                    status = prober(raw_key, is_financial=args.financial)
            else:
                status = ProbeResult(provider=provider, metric_value="No Prober")
            
        results_cache.append({
            'provider': provider,
            'masked_key': data['masked'],
            'hash': key_hash,
            'status': asdict(status),
            'files': data['files']
        })
        
    # Check for live Stripe key reuse
    stripe_live_keys = {}
    for d in results_cache:
        if d['provider'] == 'STRIPE' and d['masked_key'].startswith('sk_live_'):
            k_hash = d['hash']
            stripe_live_keys[k_hash] = len(d['files'])
            
    for d in results_cache:
        if d['provider'] == 'STRIPE' and d['masked_key'].startswith('sk_live_'):
            if stripe_live_keys[d['hash']] > 1:
                d['status']['risk'] = "Critical: Live key reuse across projects"

    if args.debug:
        print_debug(results_cache)
        
    print_table(results_cache, args=args, is_scan=False)
    
    cache_to_save = []
    for rc in results_cache:
        safe_rc = dict(rc)
        safe_status = dict(rc['status'])
        safe_status['debug_logs'] = []
        if rc['provider'] == 'STRIPE':
            safe_status['metric_type'] = "NONE"
            is_live = rc.get('masked_key', '').startswith('sk_live_')
            safe_status['metric_value'] = "Live key — opt-in required" if is_live else "Test key"
            safe_status['metric_limit'] = None
            
        safe_rc['status'] = safe_status
        cache_to_save.append(safe_rc)
        
    cache_data['probe'] = {
        "probed_at": datetime.datetime.now().isoformat(),
        "results": cache_to_save
    }
    
    write_cache(cache_data)

if __name__ == "__main__":
    main()
