#!/usr/bin/env python3
import os
import shutil
import re
import json
import hashlib
import argparse
import urllib.request
import urllib.error
import time
import tempfile
import datetime
from pathlib import Path
from dataclasses import dataclass, field, asdict


GREEN = "[92m"
YELLOW = "[93m"
RED = "[91m"
CYAN = "[96m"
BOLD = "[1m"
RESET = "[0m"

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

def print_table(results_cache, reused_only=False):
    known = [d for d in results_cache if d['provider'] != 'UNKNOWN']
    if reused_only:
        known = [d for d in known if len(d['files']) > 1]
    
    candidates = [d for d in known if format_metric(ProbeResult(**d['status'])) not in ("Placeholder", "Empty", "Malformed")]
    non_candidates = [d for d in known if format_metric(ProbeResult(**d['status'])) in ("Placeholder", "Empty", "Malformed")]
    
    term_width = shutil.get_terminal_size((80, 20)).columns
    is_narrow = term_width < 95
    
    print(f"{GREEN}KeyTruth v0.1.0{RESET}")
    print(f"Credentials: {len(known)} found • {len(candidates)} plausible • {len(non_candidates)} placeholders")
    print(f"Privacy: local-only • no plaintext keys cached")
    print()

    if not known:
        return

    # Process risks and alerts
    alerts = []
    for data in known:
        status = ProbeResult(**data['status'])
        raw_risk = status.risk
        if raw_risk == "Low":
            risk_label = "Normal"
        elif ":" in raw_risk:
            risk_label = raw_risk.split(":")[0]
            alerts.append((risk_label, data['provider'], data['hash'][:8], raw_risk.split(":", 1)[1].strip()))
        elif len(data['files']) > 1:
            risk_label = "Shared"
            alerts.append((risk_label, data['provider'], data['hash'][:8], f"appears in {len(data['files'])} files"))
        else:
            risk_label = "Normal"
            
        data['_risk_label'] = risk_label
        data['_metric_str'] = format_metric(status)

    if is_narrow:
        for data in known:
            status = ProbeResult(**data['status'])
            risk_label = data['_risk_label']
            print(f"{CYAN}⚠ {data['provider']} {data['hash'][:8]}{RESET}")
            print(f"  Auth:   {color_status(status.auth)}")
            print(f"  Access: {color_status(status.access)}")
            print(f"  Metric: {data['_metric_str']}")
            print(f"  Risk:   {color_status(risk_label)}")
            print()
    else:
        print("┌──────────┬──────────────┬────────────┬────────────┬──────────────────────────────────────┬──────────┐")
        print("│ KEY ID   │ PROVIDER     │ AUTH       │ ACCESS     │ METRIC                               │ RISK     │")
        print("├──────────┼──────────────┼────────────┼────────────┼──────────────────────────────────────┼──────────┤")
        for data in known:
            status = ProbeResult(**data['status'])
            risk_label = data['_risk_label']
            metric_str = data['_metric_str']
            # truncate metric if too long
            if len(metric_str) > 36:
                metric_str = metric_str[:33] + "..."
                
            c_auth = color_status(status.auth)
            c_acc = color_status(status.access)
            c_risk = color_status(risk_label)
            
            # calculate visible padding
            pad_auth = 10 - len(status.auth)
            pad_acc = 10 - len(status.access)
            pad_risk = 8 - len(risk_label)
            
            print(f"│ {data['hash'][:8]:<8} │ {data['provider']:<12} │ {c_auth}{' '*pad_auth} │ {c_acc}{' '*pad_acc} │ {metric_str:<36} │ {c_risk}{' '*pad_risk} │")
        print("└──────────┴──────────────┴────────────┴────────────┴──────────────────────────────────────┴──────────┘")

    if alerts:
        print()
        print(f"{CYAN}Reuse Alerts{RESET}")
        for r_label, prov, k_id, msg in alerts:
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
    scan_parser.add_argument('--verbose', action='store_true', help="Show verbose local scanning logs")
    
    probe_parser = subparsers.add_parser('probe', help="Probe discovered keys against provider networks")
    probe_parser.add_argument('paths', nargs='*', help="Paths to scan and probe (default: uses last scanned paths from cache)")
    probe_parser.add_argument('--financial', action='store_true', help="Opt-in to querying sensitive financial credentials like Stripe")
    probe_parser.add_argument('--experimental', action='store_true', help="Enable undocumented/fragile endpoints (like OpenAI credit_grants)")
    probe_parser.add_argument('--debug', action='store_true', help="Print complete network trace and classification logs")
    
    args = parser.parse_args()

    if args.command == 'scan':
        run_scan(args)
    elif args.command == 'probe':
        run_probe(args)

def run_scan(args):
    print(f"Scanning {', '.join(args.paths)} for .env files (local only)...")
    files = find_env_files(args.paths, verbose=args.verbose)
    print(f"Found {len(files)} .env files. Extracting and classifying keys...")
    
    inventory = extract_keys(files, capture_unknown=args.unknown)
    results_cache = []
    
    for key_hash, data in inventory.items():
        provider = data['provider']
        
        status = ProbeResult(provider=provider, metric_value="Pending Probe" if provider != "UNKNOWN" else "Unknown Provider")
        
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
    print_table(results_cache, reused_only=args.reused)
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
        
    print_table(results_cache, reused_only=False)
    
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
