#!/usr/bin/env python3
import os
import re
import json
import hashlib
import argparse
import sys
import urllib.request
import urllib.error
import time
import tempfile
import datetime
from pathlib import Path
from dataclasses import dataclass, field, asdict

USE_COLOR = (
    sys.stdout.isatty()
    and os.getenv("NO_COLOR") is None
    and os.getenv("TERM") != "dumb"
)

GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
CYAN = "\033[96m"
RESET = "\033[0m"

def setup_colors(args):
    global GREEN, YELLOW, RED, CYAN, RESET
    if getattr(args, 'no_color', False) or not USE_COLOR:
        GREEN = YELLOW = RED = CYAN = RESET = ""

CACHE_FILE = Path.home() / ".api_keys_cache.json"
SECRET_WORDS = ("API_KEY", "TOKEN", "SECRET", "ACCESS_KEY", "AUTH_KEY", "CREDENTIAL")

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
            # /v1/models already proved the key. count_tokens glitch ≠ unknown access.
            status.access = "Working"
            status.metric_value = "No balance endpoint"
        elif code == 403:
            status.access = "Restricted"
        else:
            status.access = "Working"

    if status.auth == "Valid" and status.access == "Unknown":
        status.access = "Working"
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

NON_CANDIDATE = {"Placeholder", "Empty", "Malformed"}
# Metric strings that mean "probe worked, billing unknown" — not failures.
METRIC_NOISE = {
    "No balance authority",
    "No balance endpoint",
    "count_tokens error",
    "Format OK",
    "Valid Format",
    "No billing authority",
    "Balance unavailable",
    "Balance unknown",
    "No simple credit endpoint",
    "Account confirmed",
}

def is_backup_path(path: str) -> bool:
    name = Path(path).name.lower()
    return (
        name.endswith(".backup")
        or name.endswith(".bak")
        or name.endswith("~")
        or ".backup." in name
        or name.endswith(".old")
    )

def active_files(files) -> list:
    """Files that count for reuse risk (.env.backup etc. excluded)."""
    return [f for f in (files or []) if not is_backup_path(f)]

def format_metric(status: ProbeResult) -> str:
    if status.metric_type == "BALANCE":
        sym = "$" if status.metric_unit == "USD" else status.metric_unit + " "
        try:
            return f"Balance {sym}{float(status.metric_value):.2f}"
        except (TypeError, ValueError):
            return f"Balance {status.metric_value}"
    if status.metric_type == "USAGE":
        if status.metric_limit is not None:
            return f"Usage {status.metric_value} / {status.metric_limit} {status.metric_unit}".strip()
        return f"Usage {status.metric_value} {status.metric_unit}".strip()
    if status.metric_type == "QUOTA":
        try:
            val = float(status.metric_value)
            if status.metric_limit is not None:
                return f"{val:,.0f} / {float(status.metric_limit):,.0f} {status.metric_unit}".strip()
            return f"{val:,.0f} {status.metric_unit}".strip()
        except (TypeError, ValueError):
            return str(status.metric_value)
    if status.metric_type == "ACCOUNT_BALANCE":
        try:
            return (
                f"{status.metric_unit} {float(status.metric_value):,.2f} available / "
                f"{status.metric_unit} {float(status.metric_limit):,.2f} pending"
            )
        except (TypeError, ValueError):
            return str(status.metric_value)
    if status.metric_type == "IDENTITY":
        if status.identity:
            return f"User: {status.identity}"
        return str(status.metric_value)
    return str(status.metric_value)

def display_metric(status: ProbeResult) -> str:
    """Human metric: real numbers stay; 'working but no billing' becomes '-'."""
    raw = format_metric(status)
    if status.metric_value in NON_CANDIDATE:
        return raw
    if status.auth == "Invalid":
        return raw if raw and raw != "None" else "Invalid Key"
    if status.metric_type in {"BALANCE", "USAGE", "QUOTA", "ACCOUNT_BALANCE", "IDENTITY", "KEY_COUNT"}:
        return raw
    if status.access in {"Working", "Full", "Read", "Write"} and (
        raw in METRIC_NOISE or status.metric_type == "NONE"
    ):
        return "-"
    if status.auth == "Valid" and raw in METRIC_NOISE:
        return "-"
    if raw in METRIC_NOISE:
        return "-"
    return raw

def is_stripe_test(data) -> bool:
    masked = data.get("masked_key") or ""
    return data.get("provider") == "STRIPE" and masked.startswith("sk_test_")

def compute_risk(data) -> str:
    """Derive risk from files + key kind. Never trust cached status.risk."""
    mv = (data.get("status") or {}).get("metric_value")
    live = active_files(data.get("files", []))
    if mv in NON_CANDIDATE or len(live) <= 1:
        return "Low"
    auth = (data.get("status") or {}).get("auth", "")
    # Test Stripe / dead keys: inventory noise, not fire.
    if is_stripe_test(data):
        return f"Review: test key reused in {len(live)} files"
    if auth == "Invalid":
        return f"Review: dead key reused in {len(live)} files"
    return f"Critical: reused in {len(live)} files"

def risk_label(risk_or_status) -> str:
    """Accept a risk string or ProbeResult (legacy). Prefer compute_risk(data)."""
    if isinstance(risk_or_status, ProbeResult):
        text = risk_or_status.risk
    else:
        text = risk_or_status or ""
    if text.startswith("Critical"):
        return "CRITICAL"
    if text.startswith("Review"):
        return "REVIEW"
    return "NONE"

def apply_reuse_risk(results_cache):
    """Write derived risk into cache rows so disk matches reality."""
    for d in results_cache:
        d.setdefault("status", {})["risk"] = compute_risk(d)

def row_sort_key(data):
    """Live CRITICAL → dead/test REVIEW → Invalid → Restricted → Working → other."""
    status = ProbeResult(**data["status"])
    label = risk_label(compute_risk(data))
    if label == "CRITICAL":
        tier = 0
    elif label == "REVIEW":
        tier = 1
    elif status.auth == "Invalid":
        tier = 2
    elif status.access in ("Restricted", "Rate-limited"):
        tier = 3
    elif status.access in ("Working", "Full", "Read", "Write") or (
        status.auth == "Valid" and status.access not in ("None",)
    ):
        tier = 4
    elif status.auth == "Detected":
        tier = 5
    elif status.metric_value in NON_CANDIDATE:
        tier = 7
    else:
        tier = 6
    return (tier, data["provider"], data["hash"])

def enrich_rows(results_cache, reused_only=False, show_placeholders=False):
    rows = [d for d in results_cache if d["provider"] != "UNKNOWN"]
    if reused_only:
        rows = [d for d in rows if len(active_files(d.get("files", []))) > 1]
    if not show_placeholders:
        rows = [
            d for d in rows
            if d.get("status", {}).get("metric_value") not in NON_CANDIDATE
        ]
    # Always re-derive risk before sort/print.
    apply_reuse_risk(rows)
    rows = sorted(rows, key=row_sort_key)
    for d in rows:
        status = ProbeResult(**d["status"])
        d["_risk"] = risk_label(compute_risk(d))
        d["_metric"] = display_metric(status)
        d["_auth"] = status.auth
        d["_access"] = status.access
        # FILES column = all locations; risk uses active_files() (no backups).
        d["_nfiles"] = len(d.get("files", []))
        d["_nactive"] = len(active_files(d.get("files", [])))
    return rows

def print_json(results_cache, args=None):
    reused_only = getattr(args, "reused", False) if args else False
    # JSON always includes placeholders so machines see everything
    rows = enrich_rows(results_cache, reused_only=reused_only, show_placeholders=True)
    out = []
    for d in rows:
        out.append({
            "provider": d["provider"],
            "hash": d["hash"],
            "auth": d["_auth"],
            "access": d["_access"],
            "metric": d["_metric"],
            "risk": d["_risk"],
            "files": d.get("files", []),
            "active_files": active_files(d.get("files", [])),
            "var_name": d.get("var_name", ""),
            "masked_key": d.get("masked_key", ""),
        })
    print(json.dumps(out, indent=2))

def print_debug(results_cache):
    """Print the wire. This is the product."""
    for d in sorted(results_cache, key=lambda x: (x["provider"], x["hash"])):
        if d["provider"] == "UNKNOWN":
            continue
        status = ProbeResult(**d["status"])
        live = active_files(d.get("files", []))
        print(f"=== {d['provider']} {d['hash'][:8]} ===")
        print(f"auth={status.auth} access={status.access} funding={status.funding}")
        derived = compute_risk(d)
        print(f"metric_type={status.metric_type} metric={display_metric(status)} raw={format_metric(status)}")
        print(f"risk={risk_label(derived)} ({derived}) active_files={len(live)} files={len(d.get('files', []))}")
        print(f"http_status={status.http_status}")
        if status.debug_logs:
            for line in status.debug_logs:
                print(f"  {line}")
        else:
            print("  (no network trace — unscanned / not probed / placeholder)")
        for f in d.get("files", []):
            tag = " (backup)" if is_backup_path(f) else ""
            print(f"  file: {f}{tag}")
        print()

def _color_risk(risk: str) -> str:
    if risk == "CRITICAL":
        return f"{RED}{risk}{RESET}"
    if risk == "REVIEW":
        return f"{YELLOW}{risk}{RESET}"
    return risk

def print_facts(results_cache, args=None, is_scan=False, files_count=0):
    reused_only = getattr(args, "reused", False) if args else False
    show_placeholders = getattr(args, "placeholders", False) if args else False
    as_json = getattr(args, "json", False) if args else False

    if as_json:
        print_json(results_cache, args=args)
        return

    # Derive risk on the full known set so header counts match the table.
    known = [d for d in results_cache if d["provider"] != "UNKNOWN"]
    apply_reuse_risk(known)

    rows = enrich_rows(results_cache, reused_only=reused_only, show_placeholders=show_placeholders)
    n_keys = sum(1 for d in known if d.get("status", {}).get("metric_value") not in NON_CANDIDATE)
    n_skipped = sum(1 for d in known if d.get("status", {}).get("metric_value") in NON_CANDIDATE)
    n_crit = sum(
        1 for d in known
        if risk_label(compute_risk(d)) == "CRITICAL"
        and d.get("status", {}).get("metric_value") not in NON_CANDIDATE
    )
    n_review = sum(
        1 for d in known
        if risk_label(compute_risk(d)) == "REVIEW"
        and d.get("status", {}).get("metric_value") not in NON_CANDIDATE
    )
    n_invalid = sum(1 for d in known if d.get("status", {}).get("auth") == "Invalid")

    mode = "scan" if is_scan else "probe"
    parts = [
        f"keytruth 0.1.0  {mode}",
        f"{files_count} files",
        f"{n_keys} keys",
        f"{n_skipped} skipped",
        f"{n_crit} critical",
        f"{n_review} review",
    ]
    if not is_scan:
        parts.append(f"{n_invalid} invalid")
    print(" · ".join(parts))
    if not rows:
        print("(empty)")
        return

    if is_scan:
        hdr = f"{'PROVIDER':<12} {'KEY':<8} {'RISK':<8} {'FILES':>5}"
        print(hdr)
        print("-" * 40)
        for d in rows:
            risk = d["_risk"]
            risk_s = _color_risk(risk)
            risk_pad = 8 + (len(risk_s) - len(risk))
            print(f"{d['provider']:<12} {d['hash'][:8]:<8} {risk_s:<{risk_pad}} {d['_nfiles']:>5}")
        return

    hdr = f"{'PROVIDER':<12} {'KEY':<8} {'AUTH':<10} {'ACCESS':<12} {'RISK':<8} {'FILES':>5}  METRIC"
    print(hdr)
    print("-" * min(100, max(len(hdr), 72)))
    for d in rows:
        risk = d["_risk"]
        risk_s = _color_risk(risk)
        auth = d["_auth"]
        if auth == "Invalid":
            auth_s = f"{RED}{auth}{RESET}"
        elif auth == "Valid":
            auth_s = f"{GREEN}{auth}{RESET}"
        else:
            auth_s = f"{YELLOW}{auth}{RESET}" if auth not in ("", "Unknown") else auth
        metric = d["_metric"]
        if len(metric) > 40:
            metric = metric[:39] + "…"
        auth_pad = 10 + (len(auth_s) - len(auth))
        risk_pad = 8 + (len(risk_s) - len(risk))
        print(
            f"{d['provider']:<12} {d['hash'][:8]:<8} {auth_s:<{auth_pad}} {d['_access']:<12} "
            f"{risk_s:<{risk_pad}} {d['_nfiles']:>5}  {metric}"
        )

def print_table(results_cache, args=None, is_scan=False, files_count=0, prev_state=None):
    # prev_state kept only so old call sites don't break; intentionally unused.
    print_facts(results_cache, args=args, is_scan=is_scan, files_count=files_count)

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
    scan_parser.add_argument('--placeholders', action='store_true', help="Include placeholders / malformed values")
    scan_parser.add_argument('--json', action='store_true', help="Machine-readable JSON")
    scan_parser.add_argument('--no-color', action='store_true', help="Disable ANSI color output")
    
    probe_parser = subparsers.add_parser('probe', help="Probe discovered keys against provider networks")
    probe_parser.add_argument('paths', nargs='*', help="Paths to scan and probe (default: uses last scanned paths from cache)")
    probe_parser.add_argument('--financial', action='store_true', help="Opt-in to querying sensitive financial credentials like Stripe")
    probe_parser.add_argument('--experimental', action='store_true', help="Enable undocumented/fragile endpoints (like OpenAI credit_grants)")
    probe_parser.add_argument('--debug', action='store_true', help="Print the wire: URL, status, body slice, classification")
    probe_parser.add_argument('--placeholders', action='store_true', help="Include placeholders / malformed values")
    probe_parser.add_argument('--reused', action='store_true', help="Only show credentials reused across multiple files")
    probe_parser.add_argument('--json', action='store_true', help="Machine-readable JSON")
    probe_parser.add_argument('--no-color', action='store_true', help="Disable ANSI color output")
    probe_parser.add_argument('--yes', action='store_true', help="Skip interactive trust prompt on first probe")
    
    show_parser = subparsers.add_parser('show', help="Show details and recommendations for a specific key")
    show_parser.add_argument('key_id', help="The hash ID prefix of the key to inspect")
    show_parser.add_argument('--no-color', action='store_true', help="Disable ANSI color output")
    
    args = parser.parse_args()
    setup_colors(args)

    if args.command == 'scan':
        run_scan(args)
    elif args.command == 'probe':
        run_probe(args)
    elif args.command == 'show':
        run_show(args)

def run_scan(args):
    files = find_env_files(args.paths, verbose=False)
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

    apply_reuse_risk(results_cache)
        
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
    if not getattr(args, "json", False):
        print(f"cache -> {CACHE_FILE} (0600)")
    print_table(results_cache, args=args, is_scan=True, files_count=len(files))
    if args.unknown and not getattr(args, "json", False):
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
    
    probe_data = cache_data.get("probe", {})
    first_probe = not probe_data or not probe_data.get("results")
    
    if first_probe and not getattr(args, 'yes', False):
        if not sys.stdin.isatty():
            print("First network probe requires --yes in non-interactive mode.", file=sys.stderr)
            sys.exit(1)
        prompt = (
            "\nKeyTruth will send each credential directly to its provider\n"
            "using read-only or free verification endpoints.\n\n"
            "Nothing is uploaded to KeyTruth.\n"
            "No plaintext keys are cached.\n\n"
            "Continue? [y/N] "
        )
        try:
            if input(prompt).strip().lower() not in {"y", "yes"}:
                print("Probe cancelled. No network requests were made.")
                sys.exit(0)
        except EOFError:
            print("Probe cancelled. No network requests were made.")
            sys.exit(0)
            
    files = find_env_files(roots, verbose=False)
    inventory = extract_keys(files, capture_unknown=False)
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
            'var_name': data.get('var_name', ''),
            'masked_key': data['masked'],
            'hash': key_hash,
            'status': asdict(status),
            'files': data['files']
        })

    apply_reuse_risk(results_cache)

    if args.debug:
        print_debug(results_cache)
        if not getattr(args, "json", False):
            print("--- facts ---")
        
    print_table(results_cache, args=args, is_scan=False, files_count=len(files))
    
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


def run_show(args):
    if not CACHE_FILE.exists():
        print("No cache found. Run `keytruth scan .` first.")
        return
        
    with open(CACHE_FILE, 'r') as f:
        cache_data = json.load(f)
        
    pool = cache_data.get("probe", {}).get("results", [])
    if not pool:
        pool = cache_data.get("scan", {}).get("inventory", [])
        
    matches = [d for d in pool if d['hash'].startswith(args.key_id)]
    if len(matches) == 0:
        print(f"Key ID {args.key_id} not found in cache.")
        return
    if len(matches) > 1:
        print(f"Key ID \"{args.key_id}\" matches {len(matches)} credentials. Provide more characters.")
        return
        
    data = matches[0]
    status = ProbeResult(**data['status'])
    derived = compute_risk(data)
    risk = risk_label(derived)

    live = active_files(data.get("files", []))
    if risk == "CRITICAL":
        rec = "Stop sharing this key across projects. Rotate after you split them."
    elif risk == "REVIEW" and is_stripe_test(data):
        rec = "Test key reused — fine for local, don't ship it."
    elif risk == "REVIEW":
        rec = "Dead key still copied around — delete the leftovers."
    elif status.auth == "Invalid":
        rec = "Delete or replace it."
    elif status.access in ("Restricted", "Rate-limited"):
        rec = "Check provider permissions / quota."
    elif status.auth == "Detected":
        rec = "Probed only with --financial if you want Stripe balance."
    else:
        rec = "None."

    print(f"{data['provider']} {data['hash'][:8]}")
    print(f"auth={status.auth}  access={status.access}  risk={risk}")
    print(f"metric={display_metric(status)}")
    print(f"files: {len(live)} active · {len(data.get('files', []))} total")
    for f in data['files']:
        tag = " (backup)" if is_backup_path(f) else ""
        print(f"  {f}{tag}")
    print(f"action: {rec}")
if __name__ == "__main__":
    main()
