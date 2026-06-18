from flask import Flask, render_template, request, redirect, url_for, jsonify, send_file, session, Response, abort
import sqlite3
import os
import pandas as pd
import json
import xml.etree.ElementTree as ET
from werkzeug.utils import secure_filename
import tempfile
import csv
from collections import defaultdict
from urllib.parse import quote
import io
import requests
import time
from functools import lru_cache
import hashlib
import re
import secrets
from datetime import timedelta

# ── LOAD .env FILE (if present) ─────────────────────────────────────────
# pip install python-dotenv
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass  # dotenv optional — use real env vars in production

# ── ENVIRONMENT-DRIVEN CONFIGURATION ────────────────────────────────────
# All secrets come from environment variables or a .env file.
# NEVER hardcode secrets in this file — keep .env out of git (.gitignore).

_IS_PRODUCTION = os.environ.get("FLASK_ENV", "development").lower() == "production"

app = Flask(__name__)

# Database path — override via env var for portability
# DB path: env var → ./data/nvd_database.db → legacy absolute path
_DEFAULT_DB = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           "data", "nvd_database.db")
DB = os.environ.get("CVE_DB_PATH") or _DEFAULT_DB

def _download_db_from_github():
    """
    Download nvd_database.db from GitHub Releases if it does not exist locally.
    Set env vars:
      GITHUB_REPO  = solomon042/TML-CVE-Dashboard
      GITHUB_TAG   = v1.0.0  (or latest)
      GITHUB_ASSET = nvd_database.db
      GITHUB_TOKEN = (optional, for private repos)
    """
    if os.path.exists(DB):
        size_mb = os.path.getsize(DB) / 1024 / 1024
        print(f"✅ DB already exists ({size_mb:.0f} MB) — skipping download")
        return True

    repo  = os.environ.get("GITHUB_REPO",  "")
    tag   = os.environ.get("GITHUB_TAG",   "v1.0.0")
    asset = os.environ.get("GITHUB_ASSET", "nvd_database.db")
    token = os.environ.get("GITHUB_TOKEN", "")

    if not repo:
        print("⚠️  GITHUB_REPO not set — cannot download DB. Set CVE_DB_PATH or GITHUB_REPO.")
        return False

    url = f"https://github.com/{repo}/releases/download/{tag}/{asset}"
    print(f"📥 Downloading CVE DB from GitHub: {url}")
    print(f"   GITHUB_REPO={repo}  TAG={tag}  ASSET={asset}")

    os.makedirs(os.path.dirname(DB), exist_ok=True)

    headers = {}
    if token:
        headers["Authorization"] = f"token {token}"

    for attempt in range(1, 4):
        try:
            print(f"   Attempt {attempt}/3…")
            resp = requests.get(url, headers=headers, stream=True, timeout=300)
            if resp.status_code == 404:
                print(f"❌ Release asset not found: {url}")
                print("   → Upload your DB as a GitHub Release asset first.")
                return False
            if resp.status_code != 200:
                print(f"❌ HTTP {resp.status_code} — retrying…")
                time.sleep(10)
                continue

            total = int(resp.headers.get("content-length", 0))
            downloaded = 0
            tmp_path = DB + ".tmp"

            with open(tmp_path, "wb") as f:
                for chunk in resp.iter_content(chunk_size=1024 * 1024):
                    if chunk:
                        f.write(chunk)
                        downloaded += len(chunk)
                        if total:
                            pct = int(downloaded / total * 100)
                            if pct % 10 == 0:
                                print(f"   {pct}% — {downloaded/1024/1024:.1f} MB downloaded")

            os.rename(tmp_path, DB)
            size_mb = os.path.getsize(DB) / 1024 / 1024
            print(f"✅ DB ready — {size_mb:.1f} MB")

            # Quick sanity check
            import sqlite3 as _sq
            conn = _sq.connect(DB)
            count = conn.execute("SELECT COUNT(*) FROM cves").fetchone()[0]
            conn.close()
            print(f"✅ Validated — {count:,} CVEs in downloaded DB")
            return True

        except Exception as e:
            print(f"   Download error: {e}")
            if os.path.exists(DB + ".tmp"):
                os.remove(DB + ".tmp")
            time.sleep(15)

    print("❌ DB download failed after 3 attempts")
    return False

# Attempt download on startup (only runs if DB missing)
_download_db_from_github()

app.config['UPLOAD_FOLDER'] = tempfile.gettempdir()
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

# SECRET_KEY — MUST be set as env var in production; stable across restarts
_secret = os.environ.get('FLASK_SECRET_KEY', '')
if not _secret:
    if _IS_PRODUCTION:
                raise RuntimeError(
            "FLASK_SECRET_KEY is not set. "
            "Generate one and add to .env: "
            "python -c 'import secrets; print(secrets.token_hex(32))'"
        )
    # Dev-only: generate ephemeral key (sessions reset on restart — OK for dev)
    _secret = secrets.token_hex(32)
    print("⚠️  DEV MODE: No FLASK_SECRET_KEY set — sessions will reset on restart.")
    print("   Add FLASK_SECRET_KEY=<value> to your .env file to persist sessions.")

app.config['SECRET_KEY'] = _secret
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE']   = _IS_PRODUCTION  # HTTPS only in production
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=8)

ALLOWED_EXTENSIONS = {'txt', 'csv', 'json', 'xml', 'xlsx', 'xls'}

# ── RATE LIMITING (simple in-memory) ────────────────────────────────────
import threading
from collections import deque

_rate_lock = threading.Lock()
_request_log: dict[str, deque] = {}

def _is_rate_limited(ip: str, max_req: int = 60, window: int = 60) -> bool:
    """Allow max_req requests per window seconds per IP."""
    now = time.time()
    with _rate_lock:
        if ip not in _request_log:
            _request_log[ip] = deque()
        dq = _request_log[ip]
        while dq and dq[0] < now - window:
            dq.popleft()
        if len(dq) >= max_req:
            return True
        dq.append(now)
        return False

@app.before_request
def security_checks():
    """Global security middleware — runs before every request."""
    ip = request.remote_addr or "unknown"

    # Skip rate limiting for long-running streaming endpoints
    if request.path in ('/api/nvd-update', '/api/nvd-status', '/admin/update-db'):
        return  # These are long-running — rate limiting doesn't apply

    # Rate limits by endpoint type
    if request.path.startswith('/admin'):
        limit = 20
    elif request.path.startswith('/api/ai-analyze'):
        limit = 120   # batch AI calls — needs higher limit
    elif request.path.startswith('/api/'):
        limit = 2000
    else:
        limit = 80

    if _is_rate_limited(ip, max_req=limit, window=60):
        return jsonify({"error": "Too many requests. Please slow down."}), 429

    # Block obviously malicious paths
    bad_patterns = ['../', '.env', 'wp-admin', 'phpmyadmin', '.git', 'etc/passwd']
    path_lower = request.path.lower()
    if any(p in path_lower for p in bad_patterns):
        abort(404)

@app.after_request
def add_security_headers(response):
    """Add security headers to every response."""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    # Skip CSP for NVD update page and its API endpoints — XHR needs full access
    skip_csp = request.path in ('/update-cve', '/api/nvd-update', '/api/nvd-status')
    if not skip_csp:
        response.headers['Content-Security-Policy'] = (
            "default-src 'self' cdn.jsdelivr.net fonts.googleapis.com fonts.gstatic.com; "
            "script-src 'self' 'unsafe-inline' cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline' cdn.jsdelivr.net fonts.googleapis.com; "
            "img-src 'self' data:; connect-src 'self';"
        )
    return response

# ============================================================
# ADMIN CREDENTIALS — set via environment variables / .env
# ============================================================
ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "")

if not ADMIN_PASSWORD:
    if _IS_PRODUCTION:
        raise RuntimeError(
            "ADMIN_PASSWORD environment variable is not set. "
            "Add ADMIN_PASSWORD=<strong-password> to your .env file."
        )
    ADMIN_PASSWORD = "cve@admin2024"   # dev fallback only
    print("⚠️  DEV MODE: Using default admin password. Set ADMIN_PASSWORD in .env for production.")

# ============================================================
# URL SECURITY — Keyword obfuscation & CSRF token
# ============================================================

def _obfuscate(text: str) -> str:
    """Base64-encode keywords so they are not plain in URLs."""
    import base64
    return base64.urlsafe_b64encode(text.encode()).decode().rstrip("=")

def _deobfuscate(token: str) -> str:
    """Decode obfuscated keyword string."""
    import base64
    padding = 4 - len(token) % 4
    if padding != 4:
        token += "=" * padding
    try:
        return base64.urlsafe_b64decode(token).decode()
    except Exception:
        return token

def generate_csrf_token() -> str:
    """Generate a per-session CSRF token."""
    from flask import session as fs
    if "csrf_token" not in fs:
        fs["csrf_token"] = secrets.token_hex(24)
    return fs["csrf_token"]

def validate_csrf(token: str) -> bool:
    from flask import session as fs
    return secrets.compare_digest(fs.get("csrf_token", ""), token or "")

# Make csrf token available in all templates
@app.context_processor
def inject_csrf():
    return {"csrf_token": generate_csrf_token()}

# ============================================================
# AI CONFIGURATION  — Multi-Provider Support
# ============================================================
# Supported providers: "deepseek" | "openai" | "claude" | "ollama"
# Users can change provider + API key at runtime via /settings page.
# These are the SERVER-SIDE defaults (used when no session setting found).

DEFAULT_AI_PROVIDER = "deepseek"   # default provider on first launch

# DeepSeek
DEEPSEEK_API_URL = "https://api.deepseek.com/v1/chat/completions"
DEEPSEEK_MODEL   = "deepseek-chat"

# OpenAI / ChatGPT
OPENAI_API_URL   = "https://api.openai.com/v1/chat/completions"
OPENAI_MODEL     = "gpt-4o-mini"    # cheapest capable model

# Anthropic / Claude
CLAUDE_API_URL   = "https://api.anthropic.com/v1/messages"
CLAUDE_MODEL     = "claude-3-haiku-20240307"   # fast + affordable

# Ollama (local, no API key needed)
OLLAMA_URL       = "http://localhost:11434/api/generate"
OLLAMA_MODEL     = "llama3.2"

USE_AI       = True
USE_AI_CACHE = True   # True=reuse DB results | False=always call fresh

# NVD Update config
NVD_API_URL      = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY      = os.environ.get("NVD_API_KEY", "")   # optional, raises rate limit
DB_UPDATE_DAYS   = 180    # how many days back to fetch on update

# Global variable for date column
DATE_COLUMN = "published"


# ============================================================
# AI PROVIDER HELPERS
# ============================================================

def get_ai_config():
    """
    Return (provider, api_key, model) from Flask session (user-set at runtime),
    falling back to server defaults. Called per-request so each user can have
    their own provider/key without restarting the server.
    """
    from flask import session as fsession
    provider = fsession.get("ai_provider", DEFAULT_AI_PROVIDER)
    api_key  = fsession.get("ai_api_key",  "")
    model    = fsession.get("ai_model",    "")

    # Fall back to env / hardcoded defaults if session not set
    if provider == "deepseek":
        api_key = api_key or os.environ.get("DEEPSEEK_API_KEY", "")
        model   = model   or DEEPSEEK_MODEL
    elif provider == "openai":
        api_key = api_key or os.environ.get("OPENAI_API_KEY", "")
        model   = model   or OPENAI_MODEL
    elif provider == "claude":
        api_key = api_key or os.environ.get("ANTHROPIC_API_KEY", "")
        model   = model   or CLAUDE_MODEL
    elif provider == "ollama":
        api_key = "ollama"   # no key needed
        model   = model or OLLAMA_MODEL

    # ── KEY MISSING? Give a clear hint ──────────────────────────
    if not api_key and provider != "ollama":
        # Check if we're inside a request context — safe to check session
        try:
            from flask import has_request_context
            if has_request_context():
                pass  # already reading from session above
        except Exception:
            pass

    return provider, api_key, model


PROVIDER_INFO = {
    "deepseek": {
        "name":        "DeepSeek",
        "placeholder": "sk-...",
        "models":      ["deepseek-chat", "deepseek-reasoner"],
        "free_tier":   True,
        "url":         "https://platform.deepseek.com/api_keys",
    },
    "openai": {
        "name":        "OpenAI / ChatGPT",
        "placeholder": "sk-proj-...",
        "models":      ["gpt-4o-mini", "gpt-4o", "gpt-3.5-turbo"],
        "free_tier":   False,
        "url":         "https://platform.openai.com/api-keys",
    },
    "claude": {
        "name":        "Anthropic Claude",
        "placeholder": "sk-ant-...",
        "models":      ["claude-3-haiku-20240307", "claude-3-5-sonnet-20241022"],
        "free_tier":   False,
        "url":         "https://console.anthropic.com/settings/keys",
    },
    "ollama": {
        "name":        "Ollama (Local)",
        "placeholder": "No API key needed",
        "models":      ["llama3.2", "llama3.1", "mistral", "phi3", "gemma2"],
        "free_tier":   True,
        "url":         "https://ollama.com/download",
    },
}


# ============================================================
# DATABASE INITIALIZATION
# ============================================================

def init_database():
    conn = sqlite3.connect(DB)
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS cve_ai_analysis (
        cve_id TEXT PRIMARY KEY,
        summary TEXT,
        affected_companies TEXT,
        remediation TEXT,
        affected_version TEXT,
        fixed_version TEXT,
        fix_status TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (cve_id) REFERENCES cves(cve_id)
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS ai_cache (
        cache_key TEXT PRIMARY KEY,
        response TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    # Transparent usage analytics — stores provider/model only, NEVER API keys
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS usage_analytics (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        event TEXT NOT NULL,
        provider TEXT,
        model TEXT,
        ip_hash TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    try:
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_cves_published ON cves(published DESC)")
    except: pass
    try:
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_cves_cvss_score ON cves(cvss_score)")
    except: pass
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_ai_analysis_fix_status ON cve_ai_analysis(fix_status)")

    conn.commit()
    conn.close()
    print("✅ Database initialized successfully")


def ensure_ai_table_columns():
    conn = sqlite3.connect(DB)
    cursor = conn.cursor()

    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='cve_ai_analysis'")
    if not cursor.fetchone():
        cursor.execute("""
        CREATE TABLE cve_ai_analysis (
            cve_id TEXT PRIMARY KEY,
            summary TEXT,
            affected_companies TEXT,
            remediation TEXT,
            affected_version TEXT,
            fixed_version TEXT,
            fix_status TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (cve_id) REFERENCES cves(cve_id)
        )
        """)
        print("✅ Created cve_ai_analysis table")
    else:
        cursor.execute("PRAGMA table_info(cve_ai_analysis)")
        columns = [col[1] for col in cursor.fetchall()]
        required = ['summary', 'affected_companies', 'remediation',
                    'affected_version', 'fixed_version', 'fix_status']
        for col in required:
            if col not in columns:
                try:
                    cursor.execute(f"ALTER TABLE cve_ai_analysis ADD COLUMN {col} TEXT")
                    print(f"✅ Added {col} column")
                except Exception as e:
                    print(f"⚠️ Could not add {col}: {e}")

    conn.commit()
    conn.close()


# ============================================================
# AI CACHE HELPERS
# ============================================================

def get_cache_key(text, task_type):
    return hashlib.md5(f"{task_type}:{text}".encode()).hexdigest()


def get_cached_ai_response(cache_key):
    try:
        conn = sqlite3.connect(DB)
        cursor = conn.cursor()
        cursor.execute("SELECT response FROM ai_cache WHERE cache_key = ?", (cache_key,))
        row = cursor.fetchone()
        conn.close()
        return row[0] if row else None
    except Exception:
        return None


def cache_ai_response(cache_key, response):
    try:
        conn = sqlite3.connect(DB)
        cursor = conn.cursor()
        cursor.execute(
            "INSERT OR REPLACE INTO ai_cache (cache_key, response) VALUES (?, ?)",
            (cache_key, response)
        )
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"⚠️ Cache write error: {e}")


# ============================================================
# UNIFIED AI CALLER  — works with DeepSeek / OpenAI / Claude / Ollama
# ============================================================

def _build_prompt_messages(system_prompt: str, user_prompt: str) -> list:
    return [
        {"role": "system", "content": system_prompt},
        {"role": "user",   "content": user_prompt},
    ]


def call_ai_provider(prompt_text: str, max_tokens: int = 200,
                     provider: str = None, api_key: str = None,
                     model: str = None) -> str | None:
    """Simple text call — returns raw string or None."""
    if not provider:
        provider, api_key, model = get_ai_config()

    try:
        if provider == "ollama":
            payload = {"model": model, "prompt": prompt_text, "stream": False}
            resp = requests.post(OLLAMA_URL, json=payload, timeout=60)
            if resp.status_code == 200:
                return resp.json().get("response", "").strip()
            return None

        if provider == "claude":
            headers = {
                "x-api-key":         api_key,
                "anthropic-version": "2023-06-01",
                "content-type":      "application/json",
            }
            payload = {
                "model":      model,
                "max_tokens": max_tokens,
                "messages":   [{"role": "user", "content": prompt_text}],
            }
            resp = requests.post(CLAUDE_API_URL, json=payload, headers=headers, timeout=30)
            if resp.status_code == 200:
                return resp.json()["content"][0]["text"].strip()
            print(f"Claude error {resp.status_code}: {resp.text[:200]}")
            return None

        # OpenAI-compatible (DeepSeek + OpenAI share same format)
        url = DEEPSEEK_API_URL if provider == "deepseek" else OPENAI_API_URL
        headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
        payload = {
            "model":      model,
            "messages":   [{"role": "user", "content": prompt_text}],
            "max_tokens": max_tokens,
            "temperature": 0.1,
        }
        resp = requests.post(url, json=payload, headers=headers, timeout=30)
        if resp.status_code == 200:
            return resp.json()["choices"][0]["message"]["content"].strip()
        print(f"{provider} error {resp.status_code}: {resp.text[:200]}")
        return None

    except Exception as e:
        print(f"AI call exception ({provider}): {e}")
        return None


def call_deepseek(prompt, max_tokens=200):
    """Kept for /test-ai backward compat."""
    return call_ai_provider(prompt, max_tokens)


def call_ai_json(cve_id: str, description: str,
                 provider: str = None, api_key: str = None,
                 model: str = None) -> dict | None:
    """
    Call AI provider with structured JSON prompt.
    Returns parsed dict with 7 keys, or None on failure.
    Works with DeepSeek / OpenAI / Claude / Ollama.
    """
    if not provider:
        provider, api_key, model = get_ai_config()

    if not api_key and provider != "ollama":
        print(f"⚠️ No API key for provider '{provider}'")
        return None

    short_desc = description[:1200]

    system_prompt = (
        "You are a senior cybersecurity analyst. "
        "Respond ONLY with a valid JSON object — no markdown, no code fences, no extra text. "
        "JSON keys required:\n\n"
        "  summary - 2-3 sentences: (1) what the vulnerability is and which component is "
        "affected, (2) exactly how an attacker exploits it — state the attack vector "
        "(network/local/physical), privileges required, and whether user interaction is needed, "
        "(3) worst-case impact: RCE, privilege escalation, data exfiltration, persistent XSS, "
        "DoS, etc. Mention the CVE class (buffer overflow, SQL injection, etc). Be precise.\n\n"
        "  affected_vendor  - vendor/company name only, or 'Unknown'\n\n"
        "  affected_product - exact product name, or 'Unknown'\n\n"
        "  affected_version - exact version range from description (e.g. '< 2026.2.0'), "
        "or 'Unknown'\n\n"
        "  fixed_version - specific version that fixes the issue. Extract from description. "
        "Only use Unknown if truly no version is stated.\n\n"
        "  fix_status - MUST be exactly one of: 'Fix Available', 'Not Fixed', "
        "'Workaround Available', 'Unknown'\n\n"
        "  remediation - 2-3 sentences of SPECIFIC technical actions:\n"
        "  (1) If fixed version known: 'Upgrade <product> to <version> or later immediately.'\n"
        "  (2) If no patch: disable the specific endpoint/feature, block port X, "
        "restrict to trusted IPs, apply WAF rule for specific payload.\n"
        "  (3) Monitoring tip: specific log entry, Windows Event ID, or network pattern to alert on.\n"
        "  NEVER write 'review vendor advisory' or 'apply recommended mitigations'.\n"
    )

    user_prompt = (
        f"CVE ID: {cve_id}\nDescription: {short_desc}\n\n"
        "Return the JSON object only. No markdown fences."
    )

    try:
        if provider == "ollama":
            full_prompt = f"{system_prompt}\n\n{user_prompt}"
            payload = {"model": model, "prompt": full_prompt, "stream": False}
            resp = requests.post(OLLAMA_URL, json=payload, timeout=120)
            if resp.status_code != 200:
                return None
            raw = resp.json().get("response", "").strip()

        elif provider == "claude":
            headers = {
                "x-api-key":         api_key,
                "anthropic-version": "2023-06-01",
                "content-type":      "application/json",
            }
            payload = {
                "model":      model,
                "max_tokens": 700,
                "system":     system_prompt,
                "messages":   [{"role": "user", "content": user_prompt}],
            }
            resp = requests.post(CLAUDE_API_URL, json=payload, headers=headers, timeout=60)
            if resp.status_code != 200:
                print(f"Claude error {resp.status_code}: {resp.text[:200]}")
                return None
            raw = resp.json()["content"][0]["text"].strip()

        else:
            # OpenAI-compatible (DeepSeek + OpenAI)
            url     = DEEPSEEK_API_URL if provider == "deepseek" else OPENAI_API_URL
            headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
            payload = {
                "model":    model,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user",   "content": user_prompt},
                ],
                "max_tokens":  700,
                "temperature": 0.1,
            }
            resp = requests.post(url, json=payload, headers=headers, timeout=45)
            if resp.status_code != 200:
                print(f"⚠️ {provider} HTTP {resp.status_code}: {resp.text[:300]}")
                return None
            # Check for empty body BEFORE parsing
            body = resp.text.strip()
            if not body:
                print(f"⚠️ {provider} returned empty body for {cve_id} — likely bad/missing API key")
                print(f"   API key present: {'YES (len=' + str(len(api_key)) + ')' if api_key else 'NO — KEY IS EMPTY!'}")
                return None
            resp_json = resp.json()
            # Check for API-level errors (e.g. DeepSeek returns {"error": {...}})
            if "error" in resp_json:
                err = resp_json["error"]
                print(f"⚠️ {provider} API error for {cve_id}: {err.get('message', err)}")
                return None
            choices = resp_json.get("choices", [])
            if not choices:
                print(f"⚠️ {provider} returned no choices for {cve_id}: {body[:200]}")
                return None

            msg = choices[0].get("message", {})
            raw = (msg.get("content") or "").strip()
            if not raw:
                # deepseek-reasoner returns empty content + reasoning_content (chain-of-thought)
                # reasoning_content is NOT JSON — never try to parse it
                reasoning = (msg.get("reasoning_content") or "").strip()
                if reasoning:
                    print(f"⚠️ {provider}/{model} returned empty content for {cve_id}.")
                    print(f"   Model is deepseek-reasoner which does not return JSON reliably.")
                    print(f"   → FIX: Go to /settings and switch model to 'deepseek-chat'")
                else:
                    print(f"⚠️ {provider} returned empty content for {cve_id}. Model: {model}")
                return None
            print(f"✅ {provider} response received for {cve_id} ({len(raw)} chars)")

        # Strip markdown fences if model added them despite instructions
        if raw.startswith("```"):
            parts = raw.split("```")
            raw = parts[1] if len(parts) > 1 else raw
            if raw.startswith("json"):
                raw = raw[4:]
            raw = raw.strip()

        return json.loads(raw)

    except json.JSONDecodeError as e:
        print(f"⚠️ JSON parse error ({provider}) for {cve_id}: {e}")
        return None
    except Exception as e:
        print(f"⚠️ AI JSON call exception ({provider}) for {cve_id}: {e}")
        return None


# Alias for backward compat
def call_deepseek_json(cve_id, description):
    return call_ai_json(cve_id, description)


# ============================================================
# RULE-BASED FALLBACKS
# ============================================================

STALE_PLACEHOLDERS = {
    "no ai summary available",
    "information not available",
    "ai analysis unavailable",
    "ai analysis unavailable — review description manually.",
    "no patch info in cve description — restrict access to the affected component and monitor vendor advisories.",
    "",
}

KNOWN_VENDORS = [
    "Microsoft", "Apple", "Google", "Amazon", "Meta", "Facebook", "Twitter",
    "Linux", "Windows", "Adobe", "Oracle", "IBM", "Intel", "AMD", "NVIDIA",
    "Cisco", "Dell", "HP", "Lenovo", "Samsung", "Sony", "Tenda", "TP-Link",
    "D-Link", "Netgear", "Asus", "Linksys", "Bosch", "Alps Alpine", "Harman",
    "Nissan", "Tesla", "Ford", "Toyota", "Honda", "Volkswagen", "BMW", "Mercedes",
    "Qualcomm", "MediaTek", "Broadcom", "Texas Instruments", "Infineon",
    "STMicroelectronics", "Renesas", "NXP", "Microchip", "Analog Devices",
    "Apache", "Nginx", "Red Hat", "Canonical", "Ubuntu", "Debian", "Fedora",
    "SUSE", "VMware", "Docker", "Kubernetes", "GitHub", "GitLab", "Atlassian",
    "WordPress", "Drupal", "Joomla", "Magento", "Shopify", "WooCommerce",
    "Siemens", "Schneider", "Rockwell", "Honeywell", "ABB", "Mitsubishi",
]


def extract_affected_companies(description: str) -> list:
    found = []
    dl = description.lower()
    for v in KNOWN_VENDORS:
        if v.lower() in dl:
            found.append(v)
    return found


def _rule_based_fix_status(description: str) -> str:
    d = description.lower()
    if any(t in d for t in [
        "fixed in", "patched in", "update to", "upgrade to", "patch available",
        "has been fixed", "addressed in", "resolved in", "users should update",
        "users are advised to upgrade", "update available", "new version",
        "later version", "this issue is fixed",
    ]):
        return "Fix Available"
    if any(t in d for t in [
        "no fix", "unpatched", "no patch", "no update available",
        "not yet fixed", "still vulnerable", "vendor has not",
    ]):
        return "Not Fixed"
    if any(t in d for t in [
        "workaround", "as a mitigation", "can be mitigated",
        "disable the", "restrict access",
    ]):
        return "Workaround Available"
    return "Unknown"


def _rule_based_remediation(description: str, cve_id: str = "") -> str:
    """Extract specific remediation from description, or return a CVE-linked advisory."""
    d = description.lower()

    # Try to pull a specific version number from the description
    version_match = re.search(
        r'(?:prior to|before|below|less than|up to|through|fixed in|patched in|update to|upgrade to)\s+([\d][.\d]+)',
        d
    )
    version_str = version_match.group(1) if version_match else None

    # Also look for product name at start of description
    product_match = re.match(r'^([A-Za-z0-9][A-Za-z0-9 \-_]{2,40}?)\s+(?:version|v[\d]|[\d])', description)
    product_str = product_match.group(1).strip() if product_match else None

    if "update" in d or "upgrade" in d:
        if version_str and product_str:
            return (f"Upgrade {product_str} to version {version_str} or later immediately. "
                    f"Until patched, restrict network access to the affected component.")
        if version_str:
            return (f"Upgrade to version {version_str} or later to remediate this vulnerability. "
                    f"Restrict access to the affected service until the update is applied.")
        return "Upgrade to the latest patched version provided by the vendor immediately."

    if "workaround" in d or "disable" in d:
        return ("Apply the vendor-recommended workaround or disable the affected feature "
                "until a patch is available. Monitor vendor advisories for a permanent fix.")

    if "patch" in d or "fix" in d:
        if version_str:
            return (f"Apply the security patch that addresses this issue (fixed in version {version_str}). "
                    f"Verify installed version and update if below the fixed release.")
        return "Apply the available security patch from the vendor as soon as possible."

    # No patch info in description — give a CVE-specific advisory link
    nvd_link = f"https://nvd.nist.gov/vuln/detail/{cve_id}" if cve_id else "the NVD entry"
    return (f"No patch details found in CVE description. "
            f"Check {nvd_link} for vendor advisories and references. "
            f"In the meantime, restrict access to the affected component and monitor for vendor patches.")


def _store_analysis_to_db(cve_id: str, result: dict):
    try:
        conn = sqlite3.connect(DB)
        cursor = conn.cursor()
        cursor.execute("""
            INSERT OR REPLACE INTO cve_ai_analysis
                (cve_id, summary, affected_companies, remediation,
                 affected_version, fixed_version, fix_status)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            cve_id,
            result.get("summary", ""),
            json.dumps(result.get("affected_companies", [])),
            result.get("remediation", ""),
            result.get("affected_version", "Unknown"),
            result.get("fixed_version", "Unknown"),
            result.get("fix_status", "Unknown"),
        ))
        conn.commit()
        conn.close()
        print(f"✅ Stored analysis to DB for {cve_id}")
    except Exception as e:
        print(f"⚠️ Could not store analysis for {cve_id}: {e}")


# ============================================================
# MAIN AI ANALYSIS FUNCTION
# ============================================================

def analyze_cve_with_ai(cve_id: str, description: str) -> dict:
    """
    Return AI analysis for a CVE. Flow:
      1. USE_AI_CACHE=True → check DB cache → return if valid
      2. USE_AI_CACHE=True → check response cache → return if valid
      3. Call DeepSeek API → validate → store → return
      4. Rule-based fallback if API fails
    Always returns a fully-populated dict, never None.
    """

    # Step 1: DB cache
    if USE_AI_CACHE:
        try:
            conn = sqlite3.connect(DB)
            cur = conn.cursor()
            cur.execute(
                "SELECT summary, affected_companies, remediation, "
                "affected_version, fixed_version, fix_status "
                "FROM cve_ai_analysis WHERE cve_id = ?",
                (cve_id,)
            )
            row = cur.fetchone()
            conn.close()

            if row and row[0] and row[0].lower().strip() not in STALE_PLACEHOLDERS:
                print(f"✅ [cache-db] {cve_id}")
                try:
                    companies = json.loads(row[1]) if row[1] else []
                except Exception:
                    companies = [row[1]] if row[1] else []
                return {
                    "summary":            row[0],
                    "affected_companies": companies,
                    "remediation":        row[2] or _rule_based_remediation(description, cve_id),
                    "affected_version":   row[3] or "Unknown",
                    "fixed_version":      row[4] or "Unknown",
                    "fix_status":         row[5] or _rule_based_fix_status(description),
                    "company":            companies[0] if companies else "Unknown",
                }
        except Exception as e:
            print(f"⚠️ DB cache error for {cve_id}: {e}")

    # Step 2: Response cache
    cache_key = get_cache_key(f"{cve_id}:{description[:200]}", "analysis_v3")
    if USE_AI_CACHE:
        cached_raw = get_cached_ai_response(cache_key)
        if cached_raw:
            try:
                result = json.loads(cached_raw)
                # KEY FIX: skip cache if it contains stale/unavailable summaries
                summary_val = result.get("summary", "").lower().strip()
                if summary_val in STALE_PLACEHOLDERS or "ai analysis unavailable" in summary_val or not summary_val:
                    print(f"🔄 [cache-stale] Bypassing stale cache for {cve_id}")
                    try:
                        c = sqlite3.connect(DB)
                        c.execute("DELETE FROM ai_cache WHERE cache_key = ?", (cache_key,))
                        c.execute("DELETE FROM cve_ai_analysis WHERE cve_id = ?", (cve_id,))
                        c.commit(); c.close()
                    except Exception:
                        pass
                else:
                    print(f"✅ [cache-resp] {cve_id}")
                    _store_analysis_to_db(cve_id, result)
                    return result
            except Exception:
                pass
    else:
        print(f"🔄 [cache-off] Fresh call for {cve_id}")

    # Step 3: AI API call
    result = None
    if USE_AI:
        provider, api_key, model = get_ai_config()
        print(f"🤖 [{provider}] Calling for {cve_id}...")
        ai_data = call_ai_json(cve_id, description, provider, api_key, model)

        if ai_data:
            vendor    = ai_data.get("affected_vendor", "Unknown")
            companies = extract_affected_companies(description)
            if vendor and vendor not in ("Unknown", "N/A", "", "None"):
                if vendor not in companies:
                    companies.insert(0, vendor)

            valid_statuses = {"Fix Available", "Not Fixed", "Workaround Available", "Unknown"}
            fix_status = ai_data.get("fix_status", "Unknown")
            if fix_status not in valid_statuses:
                fix_status = _rule_based_fix_status(description)

            remediation = ai_data.get("remediation", "").strip()
            # Only reject remediation if it's a known useless placeholder
            # Do NOT reject if it mentions vendor advisory — AI may have specific steps too
            useless = ["unknown", "n/a", "none", ""]
            is_useless = (
                not remediation
                or remediation.lower() in useless
                or remediation.lower() == "apply all recommended mitigations"
                or remediation.lower() == "apply recommended mitigations"
                or remediation.lower() == "review vendor advisory"
            )
            if is_useless:
                remediation = _rule_based_remediation(description, cve_id)

            result = {
                "summary":            ai_data.get("summary", "No summary available"),
                "affected_companies": companies,
                "remediation":        remediation,
                "affected_version":   ai_data.get("affected_version", "Unknown"),
                "fixed_version":      ai_data.get("fixed_version", "Unknown"),
                "fix_status":         fix_status,
                "company":            companies[0] if companies else "Unknown",
            }
            print(f"   fix_status:  {result['fix_status']}")
            print(f"   remediation: {result['remediation'][:80]}...")

    # Step 4: Rule-based fallback
    if result is None:
        provider_check, key_check, _ = get_ai_config()
        if not key_check and provider_check != "ollama":
            print(f"⚠️ [fallback] {cve_id} — NO API KEY SET. Go to /settings to add your {provider_check} key.")
        else:
            print(f"⚠️ [fallback] {cve_id} — AI call failed, using rule-based fallback")
        companies = extract_affected_companies(description)
        result = {
            "summary":            "AI analysis unavailable — review description manually.",
            "affected_companies": companies,
            "remediation":        _rule_based_remediation(description, cve_id),
            "affected_version":   "Unknown",
            "fixed_version":      "Unknown",
            "fix_status":         _rule_based_fix_status(description),
            "company":            companies[0] if companies else "Unknown",
            "_is_fallback":       True,   # marker — do NOT cache this
        }

    # Step 5: Persist — only cache REAL AI results, never fallback
    is_fallback = result.pop("_is_fallback", False)
    if not is_fallback:
        if USE_AI_CACHE:
            cache_ai_response(cache_key, json.dumps(result))
        _store_analysis_to_db(cve_id, result)
    else:
        # Store fallback to DB so UI shows something, but NOT to ai_cache
        # so it retries on next page load once user adds their API key
        _store_analysis_to_db(cve_id, result)

    return result


# ============================================================
# DATABASE HELPERS
# ============================================================

def get_db_connection():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn


def calculate_severity(score):
    if score is None:
        return "Unknown"
    try:
        score = float(score)
        if   score >= 9.0: return "Critical"
        elif score >= 7.0: return "High"
        elif score >= 4.0: return "Medium"
        elif score > 0:    return "Low"
        else:              return "Unknown"
    except (ValueError, TypeError):
        return "Unknown"


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def extract_keywords_from_file(filepath, filename):
    ext = filename.rsplit('.', 1)[1].lower() if '.' in filename else ''
    print(f"📄 Extracting from {ext} file: {filename}")
    keywords = set()

    try:
        if ext == 'txt':
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    kw = line.strip()
                    if kw and not kw.startswith('#'):
                        keywords.add(kw.lower())

        elif ext == 'csv':
            df = pd.read_csv(filepath)
            for col in df.columns:
                if any(k in col.lower() for k in ['keyword','component','package','name','product','software']):
                    for val in df[col].dropna():
                        keywords.add(str(val).lower().strip())
                    break
            else:
                for val in df.iloc[:, 0].dropna():
                    keywords.add(str(val).lower().strip())

        elif ext in ['xlsx', 'xls']:
            df = pd.read_excel(filepath)
            for col in df.columns:
                if any(k in col.lower() for k in ['keyword','component','package','name','product','software']):
                    for val in df[col].dropna():
                        keywords.add(str(val).lower().strip())
                    break
            else:
                for val in df.iloc[:, 0].dropna():
                    keywords.add(str(val).lower().strip())

        elif ext == 'json':
            with open(filepath, 'r', encoding='utf-8') as f:
                data = json.load(f)
            if isinstance(data, list):
                for item in data:
                    if isinstance(item, str):
                        keywords.add(item.lower())
                    elif isinstance(item, dict):
                        for key in ['keyword','component','name','product']:
                            if key in item:
                                keywords.add(str(item[key]).lower())

        elif ext == 'xml':
            tree = ET.parse(filepath)
            root = tree.getroot()
            for tag in ['keyword','component','name','product']:
                for elem in root.findall(f'.//{tag}'):
                    if elem.text:
                        keywords.add(elem.text.lower())

    except Exception as e:
        print(f"Error extracting keywords: {e}")
        return []

    cleaned = []
    for kw in keywords:
        if kw and len(kw) < 100 and kw not in ['nan','none','null']:
            c = re.sub(r'[^a-zA-Z0-9\s\.\-]', '', kw).strip()
            if c and len(c) > 1:
                cleaned.append(c)

    print(f"✅ Extracted {len(cleaned)} keywords: {cleaned[:5]}")
    return cleaned


def _enrich_row(row_dict, use_ai=False):
    """Enrich a CVE row. Never calls DeepSeek — loads from DB cache only."""
    row_dict["severity"]       = calculate_severity(row_dict.get("cvss_score"))
    row_dict["published_date"] = row_dict.get(DATE_COLUMN, "N/A")

    row_dict.setdefault("ai_summary", None)
    row_dict.setdefault("affected_companies", [])
    row_dict.setdefault("remediation", None)
    row_dict.setdefault("affected_version", "Unknown")
    row_dict.setdefault("fixed_version", "Unknown")
    row_dict.setdefault("fix_status", "Unknown")
    row_dict.setdefault("matched_keywords", [])

    try:
        conn = sqlite3.connect(DB)
        cur  = conn.cursor()
        cur.execute(
            "SELECT summary, affected_companies, remediation, "
            "affected_version, fixed_version, fix_status "
            "FROM cve_ai_analysis WHERE cve_id = ?",
            (row_dict["cve_id"],)
        )
        ai_row = cur.fetchone()
        conn.close()

        if ai_row and ai_row[0] and ai_row[0].lower().strip() not in STALE_PLACEHOLDERS:
            try:
                companies = json.loads(ai_row[1]) if ai_row[1] else []
            except Exception:
                companies = [ai_row[1]] if ai_row[1] else []
            row_dict["ai_summary"]         = ai_row[0]
            row_dict["affected_companies"] = companies
            row_dict["remediation"]        = ai_row[2] or ""
            row_dict["affected_version"]   = ai_row[3] or "Unknown"
            row_dict["fixed_version"]      = ai_row[4] or "Unknown"
            row_dict["fix_status"]         = ai_row[5] or "Unknown"
            return row_dict
    except Exception as e:
        print(f"⚠️ DB cache read error for {row_dict['cve_id']}: {e}")

    row_dict["affected_companies"] = extract_affected_companies(row_dict.get("description", ""))
    row_dict["fix_status"]         = _rule_based_fix_status(row_dict.get("description", ""))
    row_dict["remediation"]        = _rule_based_remediation(row_dict.get("description", ""), row_dict.get("cve_id", ""))
    return row_dict


def search_cves_by_keywords(keywords, severity_filter=None, page=1, per_page=50, use_ai=False):
    conn   = get_db_connection()
    cursor = conn.cursor()

    if not keywords:
        return [], 0

    conditions, params = [], []
    for kw in keywords:
        if kw and len(kw) > 1:
            conditions.append("description LIKE ?")
            params.append(f"%{kw}%")

    if not conditions:
        return [], 0

    query = "SELECT * FROM cves WHERE " + " OR ".join(conditions)

    if severity_filter:
        if   severity_filter == "Critical": query += " AND cvss_score >= 9.0"
        elif severity_filter == "High":     query += " AND cvss_score >= 7.0 AND cvss_score < 9.0"
        elif severity_filter == "Medium":   query += " AND cvss_score >= 4.0 AND cvss_score < 7.0"
        elif severity_filter == "Low":      query += " AND cvss_score > 0 AND cvss_score < 4.0"

    count_q = query.replace("SELECT *", "SELECT COUNT(*) as count")
    cursor.execute(count_q, params)
    result = cursor.fetchone()
    total  = result['count'] if result else 0

    query += f" ORDER BY {DATE_COLUMN} DESC LIMIT ? OFFSET ?"
    params.extend([per_page, (page - 1) * per_page])

    try:
        cursor.execute(query, params)
        rows = cursor.fetchall()
    except sqlite3.OperationalError as e:
        print(f"⚠️ Ordering error: {e}")
        query = query.replace(f" ORDER BY {DATE_COLUMN} DESC", "")
        cursor.execute(query, params)
        rows = cursor.fetchall()

    conn.close()

    cves = []
    for row in rows:
        rd = dict(row)
        desc_lower = (rd.get("description") or "").lower()
        rd["matched_keywords"] = [kw for kw in keywords if kw.lower() in desc_lower]
        rd = _enrich_row(rd, use_ai=use_ai)
        cves.append(rd)

    return cves, total



# ============================================================
# MULTI-SOURCE VULNERABILITY DATABASES
# ============================================================

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def fetch_cisa_kev(db_path=None):
    """Fetch CISA Known Exploited Vulnerabilities — marks CVEs as actively exploited."""
    db_path = db_path or DB
    print("📥 Fetching CISA KEV catalog...")
    try:
        resp = requests.get(CISA_KEV_URL, timeout=30)
        if resp.status_code != 200:
            print(f"⚠️  CISA KEV HTTP {resp.status_code}")
            return 0, 0

        vulns = resp.json().get("vulnerabilities", [])
        print(f"   CISA KEV: {len(vulns)} known exploited CVEs")

        conn   = sqlite3.connect(db_path)
        cursor = conn.cursor()
        for col, typ in [("is_kev","INTEGER DEFAULT 0"),("kev_date_added","TEXT"),
                         ("kev_ransomware","TEXT"),("source","TEXT DEFAULT 'nvd'")]:
            try:
                cursor.execute(f"ALTER TABLE cves ADD COLUMN {col} {typ}")
            except Exception:
                pass

        added = updated = 0
        for v in vulns:
            cve_id     = v.get("cveID", "")
            date_added = v.get("dateAdded", "")
            ransomware = v.get("knownRansomwareCampaignUse", "Unknown")
            product    = v.get("product", "")
            vendor     = v.get("vendorProject", "")
            desc       = v.get("shortDescription", "")
            due_date   = v.get("dueDate", "")
            if not cve_id:
                continue

            cursor.execute("SELECT cve_id FROM cves WHERE cve_id=?", (cve_id,))
            if cursor.fetchone():
                cursor.execute("""
                    UPDATE cves SET is_kev=1, kev_date_added=?, kev_ransomware=?
                    WHERE cve_id=?
                """, (date_added, ransomware, cve_id))
                updated += 1
            else:
                full_desc = (f"{vendor} {product}: {desc} "
                             f"(CISA KEV — patch by {due_date})")
                cursor.execute("""
                    INSERT OR IGNORE INTO cves
                      (cve_id, description, severity, published,
                       last_modified, is_kev, kev_date_added, kev_ransomware, source)
                    VALUES (?,?,?,?,?,1,?,?,'kev')
                """, (cve_id, full_desc, "Unknown", date_added,
                      date_added, date_added, ransomware))
                added += 1

        conn.commit()
        conn.close()
        print(f"✅ CISA KEV: {added} new CVEs added, {updated} marked as actively exploited")
        return added, updated
    except Exception as e:
        print(f"⚠️  CISA KEV error: {e}")
        return 0, 0


def fetch_github_advisories(db_path=None, days=180):
    """Fetch GitHub Security Advisories — fills gaps in NVD for software CVEs."""
    db_path = db_path or DB
    token   = os.environ.get("GITHUB_TOKEN", "")
    print("📥 Fetching GitHub Security Advisories...")

    headers = {"Accept": "application/vnd.github+json",
               "X-GitHub-Api-Version": "2022-11-28"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    else:
        print("   ℹ️  No GITHUB_TOKEN — using unauthenticated (60 req/hr limit)")

    from datetime import datetime, timedelta
    cutoff = (datetime.utcnow() - timedelta(days=days)).strftime("%Y-%m-%dT00:00:00Z")

    conn   = sqlite3.connect(db_path)
    cursor = conn.cursor()
    for col, typ in [("source","TEXT"),("affected_versions","TEXT")]:
        try:
            cursor.execute(f"ALTER TABLE cves ADD COLUMN {col} {typ}")
        except Exception:
            pass

    added = updated = 0
    page  = 1

    while True:
        try:
            resp = requests.get(
                "https://api.github.com/advisories",
                headers=headers,
                params={"per_page": 100, "page": page,
                        "published": f">{cutoff}", "type": "reviewed"},
                timeout=30
            )
            if resp.status_code == 401:
                print("⚠️  GitHub token invalid — set GITHUB_TOKEN env var")
                break
            if resp.status_code == 403:
                print("⚠️  GitHub rate limit hit — add GITHUB_TOKEN for 5000 req/hr")
                break
            if resp.status_code != 200:
                print(f"⚠️  GitHub API HTTP {resp.status_code}")
                break

            advisories = resp.json()
            if not advisories:
                break

            for adv in advisories:
                cve_id = adv.get("cve_id", "") or adv.get("ghsa_id", "")
                if not cve_id:
                    continue

                desc       = (adv.get("description") or adv.get("summary") or "")[:2000]
                severity   = (adv.get("severity") or "unknown").capitalize()
                cvss_score = None
                try:
                    cvss_score = float((adv.get("cvss") or {}).get("score") or 0) or None
                except Exception:
                    pass
                published  = (adv.get("published_at") or "")[:10]
                updated_at = (adv.get("updated_at")   or "")[:10]
                affected_v = ""
                try:
                    for vuln in (adv.get("vulnerabilities") or []):
                        vr = vuln.get("vulnerable_version_range","")
                        if vr:
                            affected_v = vr[:100]; break
                except Exception:
                    pass

                cursor.execute("SELECT cve_id FROM cves WHERE cve_id=?", (cve_id,))
                if cursor.fetchone():
                    cursor.execute("""
                        UPDATE cves SET
                          affected_versions=COALESCE(NULLIF(affected_versions,''),?)
                        WHERE cve_id=?
                    """, (affected_v, cve_id))
                    updated += 1
                else:
                    cursor.execute("""
                        INSERT OR IGNORE INTO cves
                          (cve_id,description,cvss_score,severity,published,
                           last_modified,affected_versions,source)
                        VALUES (?,?,?,?,?,?,?,'ghsa')
                    """, (cve_id,desc,cvss_score,severity,published,updated_at,affected_v))
                    added += 1

            conn.commit()
            print(f"   GitHub page {page}: {len(advisories)} processed")
            page += 1
            time.sleep(1)
            if len(advisories) < 100:
                break

        except Exception as e:
            print(f"⚠️  GitHub Advisory error: {e}")
            break

    conn.close()
    print(f"✅ GitHub Advisory: {added} new, {updated} updated")
    return added, updated



def fetch_mitre_cve(db_path=None, days=30):
    """
    Fetch CVEs directly from MITRE's official CVE API.
    This catches CVEs in NVD's backlog — published by MITRE but not yet
    scored/enriched by NVD. No API key required.
    API: https://cveawg.mitre.org/api/cve
    """
    db_path = db_path or DB
    print("📥 Fetching from MITRE CVE API (fills NVD backlog gaps)...")

    from datetime import datetime, timedelta
    cutoff = (datetime.utcnow() - timedelta(days=days)).strftime("%Y-%m-%dT00:00:00.000Z")

    conn   = sqlite3.connect(db_path)
    cursor = conn.cursor()
    for col, typ in [("source","TEXT"),("affected_versions","TEXT")]:
        try:
            cursor.execute(f"ALTER TABLE cves ADD COLUMN {col} {typ}")
        except Exception:
            pass

    added = updated = 0
    start = 0
    per   = 500

    while True:
        try:
            resp = requests.get(
                "https://cveawg.mitre.org/api/cve",
                params={
                    "state":          "PUBLISHED",
                    "datePublicFrom": cutoff,
                    "startIndex":     start,
                    "resultsPerPage": per,
                },
                headers={"User-Agent": "CVE-Dashboard/1.0"},
                timeout=30
            )

            if resp.status_code != 200:
                print(f"⚠️  MITRE API HTTP {resp.status_code}")
                break

            data  = resp.json()
            total = data.get("totalResults", 0)
            cves  = data.get("cves", [])

            if not cves:
                break

            print(f"   MITRE: {total:,} total | batch {start+1}-{start+len(cves)}")

            for cve in cves:
                meta    = cve.get("cveMetadata", {})
                cve_id  = meta.get("cveId", "")
                if not cve_id:
                    continue

                published = (meta.get("datePublished") or "")[:10]
                updated_t = (meta.get("dateUpdated")   or "")[:10]

                # Get English description
                desc = ""
                try:
                    containers = cve.get("containers", {})
                    cna = containers.get("cna", {})
                    for d in cna.get("descriptions", []):
                        if d.get("lang", "").startswith("en"):
                            desc = d.get("value", "")
                            break
                except Exception:
                    pass

                # Get affected versions from CNA
                affected_v = ""
                try:
                    cna = cve.get("containers", {}).get("cna", {})
                    for affected in cna.get("affected", []):
                        for ver in affected.get("versions", []):
                            v = ver.get("version","")
                            s = ver.get("status","")
                            le = ver.get("lessThan","") or ver.get("lessThanOrEqual","")
                            if s == "affected" and (v or le):
                                part = f"< {le}" if le else f">= {v}"
                                affected_v = part; break
                        if affected_v:
                            break
                except Exception:
                    pass

                # Get CVSS if available in CNA
                cvss_score = None
                severity   = "Unknown"
                try:
                    cna = cve.get("containers",{}).get("cna",{})
                    for metric in cna.get("metrics",[]):
                        for key in ["cvssV4_0","cvssV3_1","cvssV3_0","cvssV2_0"]:
                            if key in metric:
                                cvss_score = float(metric[key].get("baseScore",0)) or None
                                severity   = metric[key].get("baseSeverity","Unknown")
                                break
                        if cvss_score:
                            break
                except Exception:
                    pass

                if cvss_score and not severity or severity == "Unknown":
                    if   cvss_score >= 9.0: severity = "Critical"
                    elif cvss_score >= 7.0: severity = "High"
                    elif cvss_score >= 4.0: severity = "Medium"
                    else:                   severity = "Low"

                # Check if already in DB
                cursor.execute("SELECT cve_id, cvss_score FROM cves WHERE cve_id=?", (cve_id,))
                row = cursor.fetchone()

                if row:
                    # Only update if MITRE has better data than what we have
                    existing_score = row[1]
                    if not existing_score and cvss_score:
                        cursor.execute("""
                            UPDATE cves SET cvss_score=?, severity=?,
                            affected_versions=COALESCE(NULLIF(affected_versions,''),?)
                            WHERE cve_id=?
                        """, (cvss_score, severity, affected_v, cve_id))
                        updated += 1
                    elif not existing_score:
                        # Update description if empty
                        cursor.execute("""
                            UPDATE cves SET
                            description=COALESCE(NULLIF(description,''),?),
                            affected_versions=COALESCE(NULLIF(affected_versions,''),?)
                            WHERE cve_id=?
                        """, (desc, affected_v, cve_id))
                        updated += 1
                else:
                    # New CVE not in NVD yet — add it
                    cursor.execute("""
                        INSERT OR IGNORE INTO cves
                          (cve_id, description, cvss_score, severity,
                           published, last_modified, affected_versions, source)
                        VALUES (?,?,?,?,?,?,?,'mitre')
                    """, (cve_id, desc[:2000], cvss_score, severity,
                          published, updated_t, affected_v))
                    added += 1

            conn.commit()
            start += len(cves)
            if start >= total:
                break
            time.sleep(1)  # MITRE has no official rate limit but be polite

        except Exception as e:
            print(f"⚠️  MITRE fetch error: {e}")
            break

    conn.close()
    print(f"✅ MITRE CVE API: {added} new CVEs added, {updated} enriched")
    return added, updated

# ============================================================
# ROUTES
# ============================================================

@app.route("/search", methods=["POST"])
def search_post():
    """POST-based search so keywords don't appear in URL."""
    keyword         = request.form.get("keyword", "").strip()
    keywords_text   = request.form.get("keywords", "")
    severity_filter = request.form.get("severity", "")
    use_ai          = request.form.get("use_ai", "false") == "true"
    tab             = request.form.get("tab", "single")

    if keywords_text:
        keywords = [k.strip() for k in keywords_text.split("\n") if k.strip()]
        kw_enc = _obfuscate(",".join(keywords[:20]))
    elif keyword:
        kw_enc = _obfuscate(keyword)
        keywords = [keyword]
    else:
        return redirect(url_for("index"))

    sev_enc = _obfuscate(severity_filter) if severity_filter else ""
    return redirect(url_for("index",
        kw=kw_enc, sv=sev_enc,
        use_ai="true" if use_ai else "false",
        tab=tab, page=1))


@app.route("/", methods=["GET"])
def index():
    # Decode obfuscated URL params
    kw_enc          = request.args.get("kw", "")
    sv_enc          = request.args.get("sv", "")
    keywords_param  = _deobfuscate(kw_enc) if kw_enc else request.args.get("keywords", "")
    severity_filter = _deobfuscate(sv_enc) if sv_enc else request.args.get("severity", "")
    search_mode     = request.args.get("search_mode", "single")
    keyword         = request.args.get("keyword", "")
    page            = int(request.args.get("page", 1))
    # Check both 'ai' and 'use_ai' params — 'true'/'1' from either means enabled
    _ai_a  = request.args.get("ai", "")
    _ai_b  = request.args.get("use_ai", "false")
    use_ai = (_ai_a in ("1", "true")) or (_ai_b in ("1", "true"))

    if keywords_param:
        keywords = [k.strip() for k in keywords_param.split(',') if k.strip()]
        cves, total = search_cves_by_keywords(keywords, severity_filter, page, use_ai=use_ai)
        active_keywords = keywords

    elif search_mode == "single" and keyword:
        cves, total = search_cves_by_keywords([keyword], severity_filter, page, use_ai=use_ai)
        active_keywords = [keyword]

    else:
        conn   = get_db_connection()
        cursor = conn.cursor()
        try:
            cursor.execute(f"SELECT * FROM cves ORDER BY {DATE_COLUMN} DESC LIMIT 50")
        except Exception:
            cursor.execute("SELECT * FROM cves LIMIT 50")
        rows = cursor.fetchall()
        conn.close()

        cves = []
        for row in rows:
            rd = dict(row)
            rd["matched_keywords"] = []
            rd = _enrich_row(rd, use_ai=use_ai)
            cves.append(rd)

        active_keywords = []
        keyword = ""
        total   = len(cves)

    total_pages = (total // 50) + (1 if total % 50 > 0 else 0) if total else 1

    return render_template(
        "index.html",
        cves=cves,
        keyword=keyword,
        severity_filter=severity_filter,
        active_keywords=active_keywords,
        page=page,
        total_pages=total_pages,
        use_ai=use_ai
    )


@app.route("/upload-bom", methods=["POST"])
def upload_bom():
    if 'bom_file' not in request.files:
        return redirect(url_for('index', error='No file uploaded'))
    file            = request.files['bom_file']
    severity_filter = request.form.get("severity_bom", "")
    use_ai          = request.form.get("use_ai_bom", "false") == "true"
    if file.filename == '':
        return redirect(url_for('index', error='No file selected'))
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        try:
            file.save(filepath)
            keywords = extract_keywords_from_file(filepath, filename)
            os.remove(filepath)
            if not keywords:
                return redirect(url_for('index', error='No valid keywords found in file'))
            kw_str = ','.join([quote(k) for k in keywords[:20]])
            return redirect(f"/?keywords={kw_str}&severity={severity_filter}&use_ai={'true' if use_ai else 'false'}&tab=bom")
        except Exception as e:
            return redirect(url_for('index', error=f'Error processing file: {str(e)}'))
    return redirect(url_for('index', error='Invalid file type'))


@app.route("/multi-keyword", methods=["POST"])
def multi_keyword():
    keywords_text   = request.form.get("keywords", "")
    severity_filter = request.form.get("severity_multi", "")
    use_ai          = request.form.get("use_ai_multi", "false") == "true"
    keywords = [k.strip() for k in keywords_text.split('\n') if k.strip()]
    if not keywords:
        return redirect(url_for('index', error='No keywords provided'))
    kw_str = ','.join([quote(k) for k in keywords[:20]])
    return redirect(f"/?keywords={kw_str}&severity={severity_filter}&use_ai={'true' if use_ai else 'false'}&tab=multi")


@app.route("/export")
def export_results():
    keywords_param  = request.args.get("keywords", "")
    severity_filter = request.args.get("severity", "")
    if not keywords_param:
        return "No keywords provided", 400
    keywords = [k.strip() for k in keywords_param.split(',') if k.strip()]
    cves, _  = search_cves_by_keywords(keywords, severity_filter, page=1, per_page=1000, use_ai=True)

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['CVE ID','CVSS Score','Severity','Published','Description',
                     'AI Summary','Affected Version','Fixed Version','Fix Status',
                     'Affected Companies','Remediation','Matched Keywords'])
    for cve in cves:
        writer.writerow([
            cve.get('cve_id',''),
            cve.get('cvss_score',''),
            cve.get('severity',''),
            (cve.get('published_date','') or '')[:10],
            (cve.get('description','') or '').replace('\n',' '),
            (cve.get('ai_summary','') or '').replace('\n',' '),
            cve.get('affected_version','Unknown'),
            cve.get('fixed_version','Unknown'),
            cve.get('fix_status','Unknown'),
            ', '.join(cve.get('affected_companies',[])),
            (cve.get('remediation','') or '').replace('\n',' '),
            ', '.join(cve.get('matched_keywords',[])),
        ])
    output.seek(0)
    return Response(output.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": "attachment;filename=cve_analysis_report.csv"})



@app.route("/api/ai-status")
def api_ai_status():
    """Returns whether an AI key is configured in the current session."""
    provider, api_key, model = get_ai_config()
    return jsonify({
        "provider":   provider,
        "model":      model,
        "has_key":    bool(api_key and provider != "ollama") or provider == "ollama",
        "ai_enabled": USE_AI,
    })

# ── Stats cache — built once at startup, refreshed every 5 min ───────────
_stats_cache      = {}
_stats_cache_ts   = 0

def _build_stats_cache():
    """Pre-compute stats so /stats never runs a slow COUNT on 335K rows live."""
    global _stats_cache, _stats_cache_ts
    try:
        conn   = sqlite3.connect(DB, timeout=60)
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='cves'")
        if not cursor.fetchone():
            conn.close(); return
        # Single pass — much faster than 6 separate COUNTs
        cursor.execute("""
            SELECT
                COUNT(*),
                SUM(CASE WHEN cvss_score >= 9.0 THEN 1 ELSE 0 END),
                SUM(CASE WHEN cvss_score >= 7.0 AND cvss_score < 9.0 THEN 1 ELSE 0 END),
                SUM(CASE WHEN cvss_score >= 4.0 AND cvss_score < 7.0 THEN 1 ELSE 0 END),
                SUM(CASE WHEN cvss_score > 0   AND cvss_score < 4.0 THEN 1 ELSE 0 END),
                MIN(published), MAX(published)
            FROM cves
        """)
        total, crit, high, med, low, oldest, newest = cursor.fetchone()
        cursor.execute("SELECT COUNT(*) FROM cve_ai_analysis")
        ai_enhanced = cursor.fetchone()[0]
        # New CVEs in last 7 days
        cursor.execute("SELECT COUNT(*) FROM cves WHERE published >= date('now','-7 days')")
        new7 = cursor.fetchone()[0]
        conn.close()
        _stats_cache = {
            "total_cves": total or 0,
            "critical":   int(crit  or 0),
            "high":       int(high  or 0),
            "medium":     int(med   or 0),
            "low":        int(low   or 0),
            "ai_enhanced": ai_enhanced or 0,
            "oldest_cve": oldest,
            "newest_cve": newest,
            "new_7days":  new7 or 0,
        }
        _stats_cache_ts = time.time()
        print(f"📊 Stats cached: {_stats_cache['total_cves']:,} CVEs, "
              f"{_stats_cache['critical']} critical, {_stats_cache['high']} high")
    except Exception as e:
        print(f"⚠️  Stats cache error: {e}")

@app.route("/stats")
def stats():
    global _stats_cache, _stats_cache_ts
    # Rebuild if empty or older than 5 minutes
    if not _stats_cache or (time.time() - _stats_cache_ts) > 300:
        threading.Thread(target=_build_stats_cache, daemon=True).start()
    if _stats_cache:
        return jsonify(_stats_cache)
    # First load — build synchronously so page has data
    _build_stats_cache()
    return jsonify(_stats_cache) if _stats_cache else jsonify({"total_cves":0,"critical":0,
        "high":0,"medium":0,"low":0,"ai_enhanced":0,"oldest_cve":None,"newest_cve":None})


@app.route("/api/ai-analyze", methods=["POST"])
def api_ai_analyze():
    """Lazy AI endpoint — called by frontend after page renders."""
    data = request.get_json()
    if not data or "cves" not in data:
        return jsonify({"error": "Missing cves list"}), 400

    # Diagnose: log what provider/key is active for THIS request
    provider, api_key, model = get_ai_config()
    if not api_key and provider != "ollama":
        print(f"⚠️ /api/ai-analyze: NO API KEY in session for provider '{provider}'!")
        print(f"   Session keys present: {list(session.keys())}")
        print(f"   Hint: Go to /settings and save your API key — it must be set per browser session.")
    else:
        print(f"ℹ️  /api/ai-analyze: provider={provider} model={model} key={'set (len=' + str(len(api_key)) + ')' if api_key else 'MISSING'}")

    # Log transparent analytics — provider + model only, NEVER the API key
    try:
        ip_hash = hashlib.sha256((request.remote_addr or "").encode()).hexdigest()[:16]
        conn = sqlite3.connect(DB)
        conn.execute(
            "INSERT INTO usage_analytics (event, provider, model, ip_hash) VALUES (?,?,?,?)",
            ("ai_analyze", provider, model, ip_hash)
        )
        conn.commit(); conn.close()
    except Exception:
        pass  # analytics failure never breaks the main flow

    results = {}
    for item in data["cves"][:5]:
        cve_id = item.get("cve_id", "")
        if not cve_id:
            continue
        try:
            ai = analyze_cve_with_ai(cve_id, item.get("description", ""))
            results[cve_id] = {
                "summary":            ai.get("summary", ""),
                "affected_companies": ai.get("affected_companies", []),
                "remediation":        ai.get("remediation", ""),
                "affected_version":   ai.get("affected_version", "Unknown"),
                "fixed_version":      ai.get("fixed_version", "Unknown"),
                "fix_status":         ai.get("fix_status", "Unknown"),
            }
        except Exception as e:
            results[cve_id] = {"error": str(e)}
    return jsonify(results)


@app.route("/keyword-stats")
def keyword_stats():
    keywords_param  = request.args.get("keywords", "")
    severity_filter = request.args.get("severity", "")
    conn   = get_db_connection()
    cursor = conn.cursor()

    if keywords_param:
        keywords   = [k.strip() for k in keywords_param.split(',') if k.strip()]
        conditions = ["description LIKE ?" for kw in keywords if kw and len(kw) > 1]
        params     = [f"%{kw}%" for kw in keywords if kw and len(kw) > 1]
        base_where = "WHERE (" + " OR ".join(conditions) + ")"
        if severity_filter:
            if   severity_filter == "Critical": base_where += " AND cvss_score >= 9.0"
            elif severity_filter == "High":     base_where += " AND cvss_score >= 7.0 AND cvss_score < 9.0"
            elif severity_filter == "Medium":   base_where += " AND cvss_score >= 4.0 AND cvss_score < 7.0"
            elif severity_filter == "Low":      base_where += " AND cvss_score > 0 AND cvss_score < 4.0"
    else:
        base_where = "WHERE 1=1"
        params     = []

    try:
        cursor.execute(f"SELECT COUNT(*) FROM cves {base_where}", params);                    total    = cursor.fetchone()[0]
        cursor.execute(f"SELECT COUNT(*) FROM cves {base_where} AND cvss_score >= 9.0", params); critical = cursor.fetchone()[0]
        cursor.execute(f"SELECT COUNT(*) FROM cves {base_where} AND cvss_score >= 7.0 AND cvss_score < 9.0", params); high = cursor.fetchone()[0]
        cursor.execute(f"SELECT COUNT(*) FROM cves {base_where} AND cvss_score >= 4.0 AND cvss_score < 7.0", params); medium = cursor.fetchone()[0]
        cursor.execute(f"SELECT COUNT(*) FROM cves {base_where} AND cvss_score > 0 AND cvss_score < 4.0", params); low = cursor.fetchone()[0]
        conn.close()
        return jsonify({"total":total,"critical":critical,"high":high,"medium":medium,"low":low,"filtered":bool(keywords_param)})
    except Exception as e:
        conn.close()
        return jsonify({"error":str(e),"total":0,"critical":0,"high":0,"medium":0,"low":0})


@app.route("/keyword-counts")
def keyword_counts():
    keywords_param  = request.args.get("keywords", "")
    severity_filter = request.args.get("severity", "")
    if not keywords_param:
        return jsonify({})
    keywords = [k.strip() for k in keywords_param.split(',') if k.strip()]
    counts   = {}
    conn     = get_db_connection()
    cursor   = conn.cursor()
    for kw in keywords:
        query  = "SELECT COUNT(*) as count FROM cves WHERE description LIKE ?"
        params = [f"%{kw}%"]
        if severity_filter:
            if   severity_filter == "Critical": query += " AND cvss_score >= 9.0"
            elif severity_filter == "High":     query += " AND cvss_score >= 7.0 AND cvss_score < 9.0"
            elif severity_filter == "Medium":   query += " AND cvss_score >= 4.0 AND cvss_score < 7.0"
            elif severity_filter == "Low":      query += " AND cvss_score > 0 AND cvss_score < 4.0"
        try:
            cursor.execute(query, params)
            result     = cursor.fetchone()
            counts[kw] = result['count'] if result else 0
        except Exception as e:
            counts[kw] = 0
    conn.close()
    return jsonify(counts)


# ── ADMIN ROUTES ──────────────────────────────────────────────

@app.route("/admin/clear-ai/<cve_id>")
def clear_ai(cve_id):
    """Clear stored AI data for a single CVE."""
    conn = sqlite3.connect(DB)
    conn.execute("DELETE FROM cve_ai_analysis WHERE cve_id = ?", (cve_id,))
    conn.execute("DELETE FROM ai_cache WHERE cache_key LIKE ?", (f"%{cve_id}%",))
    conn.commit(); conn.close()
    return jsonify({"status":"success","message":f"Cleared AI data for {cve_id}"})


@app.route("/admin/regenerate/<cve_id>")
def regenerate_ai(cve_id):
    """Force fresh DeepSeek analysis for one CVE."""
    conn   = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT description FROM cves WHERE cve_id = ?", (cve_id,))
    row = cursor.fetchone()
    conn.close()
    if not row:
        return jsonify({"error": f"{cve_id} not found"}), 404
    c = sqlite3.connect(DB)
    c.execute("DELETE FROM cve_ai_analysis WHERE cve_id = ?", (cve_id,))
    c.execute("DELETE FROM ai_cache WHERE cache_key LIKE ?", (f"%{cve_id}%",))
    c.commit(); c.close()
    return jsonify(analyze_cve_with_ai(cve_id, row['description']))


@app.route("/admin/clear-all-cache")
def clear_all_cache():
    """Clear stale/placeholder AI records only. Valid analysis preserved."""
    conn   = sqlite3.connect(DB)
    cursor = conn.cursor()
    cursor.execute(
        "DELETE FROM cve_ai_analysis WHERE summary IN (?, ?, ?, ?)",
        ("No AI summary available","Information not available",
         "AI analysis unavailable","AI analysis unavailable — review description manually.")
    )
    deleted_analysis = cursor.rowcount
    cursor.execute("DELETE FROM ai_cache")
    deleted_cache = cursor.rowcount
    conn.commit(); conn.close()
    return jsonify({
        "status":"success",
        "deleted_stale_analysis": deleted_analysis,
        "deleted_cache_entries":  deleted_cache,
        "message": "Stale AI data cleared. Valid analysis preserved.",
    })


@app.route("/admin/clear-all-ai")
def clear_all_ai():
    """
    WIPE ALL stored AI analysis and cache.
    Use before sharing the project with others who have a different API key.
    After wiping, set USE_AI_CACHE=False so their first run generates fresh data.
    """
    conn   = sqlite3.connect(DB)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM cve_ai_analysis"); deleted_analysis = cursor.rowcount
    cursor.execute("DELETE FROM ai_cache");        deleted_cache    = cursor.rowcount
    conn.commit(); conn.close()
    return jsonify({
        "status":           "success",
        "deleted_analysis": deleted_analysis,
        "deleted_cache":    deleted_cache,
        "message":          "ALL AI analysis wiped. Safe to share project now.",
        "next_steps": [
            "1. Set USE_AI_CACHE = False in app.py before sharing",
            "2. Recipient sets their own DEEPSEEK_API_KEY",
            "3. Recipient sets USE_AI_CACHE = True after first run to enable caching",
        ],
    })


# ── DEBUG / TEST ──────────────────────────────────────────────

@app.route("/test-ai")
def test_ai():
    resp = call_deepseek("Say Hello", max_tokens=10)
    return f"✅ DeepSeek working: {resp}" if resp else "❌ DeepSeek not working."


@app.route("/debug/ai/<cve_id>")
def debug_ai(cve_id):
    conn   = sqlite3.connect(DB)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM cve_ai_analysis WHERE cve_id = ?", (cve_id,))
    row = cursor.fetchone()
    conn.close()
    if row:
        return jsonify({"cve_id":row[0],"summary":row[1],"companies":row[2],
                        "remediation":row[3],"affected_version":row[4],
                        "fixed_version":row[5],"fix_status":row[6],"created_at":row[7]})
    return jsonify({"error":"No AI data found for this CVE"})


@app.route("/test-cve/<cve_id>")
def test_cve(cve_id):
    conn   = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT description FROM cves WHERE cve_id = ?", (cve_id,))
    row = cursor.fetchone()
    conn.close()
    if not row:
        return f"CVE {cve_id} not found"
    description = row['description']
    c = sqlite3.connect(DB)
    c.execute("DELETE FROM cve_ai_analysis WHERE cve_id = ?", (cve_id,))
    c.execute("DELETE FROM ai_cache WHERE cache_key LIKE ?", (f"%{cve_id}%",))
    c.commit(); c.close()
    result = analyze_cve_with_ai(cve_id, description)
    return f"""<html><body style="font-family:Arial;margin:20px;background:#f9f9f9">
    <h2>Test: {cve_id}</h2>
    <p><b>Fix Status:</b> {result.get('fix_status')}</p>
    <p><b>Summary:</b> {result.get('summary')}</p>
    <p><b>Remediation:</b> {result.get('remediation')}</p>
    <p><b>Affected:</b> {result.get('affected_version')} → Fixed: {result.get('fixed_version')}</p>
    <p><b>Companies:</b> {', '.join(result.get('affected_companies',[]))}</p>
    <pre style="background:#1e1e1e;color:#ccc;padding:15px;border-radius:8px;overflow-x:auto">{json.dumps(result,indent=2)}</pre>
    <hr><pre style="background:#1e1e1e;color:#ccc;padding:15px;border-radius:8px">{description[:800]}...</pre>
    <p><a href="/">← Back to Dashboard</a></p></body></html>"""


# ============================================================
# AI PROVIDER SETTINGS  (per-user, stored in session)
# ============================================================

@app.route("/settings", methods=["GET"])
def settings():
    from flask import session as fs
    current_provider = fs.get("ai_provider", DEFAULT_AI_PROVIDER)
    current_key      = fs.get("ai_api_key", "")
    current_model    = fs.get("ai_model", "")
    masked_key = (current_key[:6] + "..." + current_key[-4:]) if len(current_key) > 12 else ("*" * len(current_key))

    providers_json = json.dumps(PROVIDER_INFO)

    return f"""<!DOCTYPE html>
<html>
<head>
  <title>AI Provider Settings — CVE Dashboard</title>
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.1/font/bootstrap-icons.css">
  <style>
    body {{ background:#f1f5f9; font-family:'Inter',sans-serif; }}
    .card {{ border:none; border-radius:14px; box-shadow:0 2px 16px rgba(0,0,0,0.08); }}
    .provider-card {{ border:2px solid #e2e8f0; border-radius:12px; padding:16px; cursor:pointer;
                      transition:all 0.2s; background:#fff; }}
    .provider-card:hover {{ border-color:#3b82f6; box-shadow:0 0 0 3px rgba(59,130,246,0.1); }}
    .provider-card.selected {{ border-color:#3b82f6; background:#eff6ff; }}
    .provider-card .name {{ font-weight:700; font-size:0.95rem; }}
    .free-badge {{ background:#dcfce7; color:#15803d; font-size:0.7rem;
                   padding:2px 8px; border-radius:10px; font-weight:600; }}
    .paid-badge {{ background:#fef3c7; color:#92400e; font-size:0.7rem;
                   padding:2px 8px; border-radius:10px; font-weight:600; }}
  </style>
</head>
<body>
<div class="container py-5" style="max-width:720px">
  <div class="d-flex align-items-center gap-3 mb-4">
    <a href="/" class="btn btn-outline-secondary btn-sm"><i class="bi bi-arrow-left"></i></a>
    <h4 class="mb-0"><i class="bi bi-robot me-2 text-primary"></i>AI Provider Settings</h4>
  </div>

  <div class="card p-4 mb-4">
    <h6 class="text-muted mb-3 fw-bold text-uppercase" style="font-size:.75rem;letter-spacing:.5px">
      Choose Your AI Provider
    </h6>
    <div class="row g-3" id="providerGrid">
      <!-- filled by JS -->
    </div>
  </div>

  <div class="card p-4 mb-4" id="keySection">
    <h6 class="text-muted mb-3 fw-bold text-uppercase" style="font-size:.75rem;letter-spacing:.5px">
      API Key &amp; Model
    </h6>
    <div class="mb-3" id="keyField">
      <label class="form-label fw-semibold">API Key</label>
      <div class="input-group">
        <input type="password" class="form-control" id="apiKeyInput"
               placeholder="Paste your API key here"
               value="{masked_key if current_key else ''}">
        <button class="btn btn-outline-secondary" type="button" onclick="toggleKey()">
          <i class="bi bi-eye" id="eyeIcon"></i>
        </button>
      </div>
      <div class="form-text" id="keyHint">
        <a href="#" id="getKeyLink" target="_blank">Get API key →</a>
      </div>
    </div>
    <div class="mb-3">
      <label class="form-label fw-semibold">Model</label>
      <select class="form-select" id="modelSelect">
        <!-- filled by JS -->
      </select>
    </div>
  </div>

  <div class="d-flex gap-2">
    <button class="btn btn-primary px-4" onclick="saveSettings()">
      <i class="bi bi-check-lg me-1"></i>Save &amp; Test Connection
    </button>
    <button class="btn btn-outline-danger" onclick="clearSettings()">
      <i class="bi bi-trash me-1"></i>Clear Settings
    </button>
  </div>

  <div id="testResult" class="mt-3" style="display:none"></div>

  <div class="mt-4 p-3 rounded" style="background:#f8fafc;border:1px solid #e2e8f0;font-size:.82rem;color:#64748b">
    <i class="bi bi-shield-lock me-1"></i>
    API keys are stored only in your browser session and never saved to the server.
    They are cleared when you close the browser tab.
  </div>
</div>

<script>
const PROVIDERS = {providers_json};
const currentProvider = "{current_provider}";
const currentModel    = "{current_model}";

function renderProviders() {{
  const grid = document.getElementById('providerGrid');
  grid.innerHTML = '';
  Object.entries(PROVIDERS).forEach(([id, info]) => {{
    const selected = id === currentProvider;
    const badge = info.free_tier
      ? '<span class="free-badge ms-2">Free tier</span>'
      : '<span class="paid-badge ms-2">Paid</span>';
    grid.innerHTML += `
      <div class="col-6 col-md-3">
        <div class="provider-card ${{selected ? 'selected' : ''}}" onclick="selectProvider('${{id}}')" id="pcard-${{id}}">
          <div class="name">${{info.name}} ${{badge}}</div>
        </div>
      </div>`;
  }});
  updateModelList(currentProvider);
  updateKeyHint(currentProvider);
}}

function selectProvider(id) {{
  document.querySelectorAll('.provider-card').forEach(c => c.classList.remove('selected'));
  document.getElementById('pcard-' + id).classList.add('selected');
  const isOllama = id === 'ollama';
  document.getElementById('keyField').style.opacity = isOllama ? '0.4' : '1';
  document.getElementById('apiKeyInput').disabled  = isOllama;
  if (isOllama) document.getElementById('apiKeyInput').placeholder = 'No API key needed for Ollama';
  else document.getElementById('apiKeyInput').placeholder = PROVIDERS[id]?.placeholder || 'API key';
  updateModelList(id);
  updateKeyHint(id);
}}

function updateModelList(id) {{
  const sel = document.getElementById('modelSelect');
  sel.innerHTML = '';
  (PROVIDERS[id]?.models || []).forEach(m => {{
    const opt = document.createElement('option');
    opt.value = m; opt.textContent = m;
    if (m === currentModel) opt.selected = true;
    sel.appendChild(opt);
  }});
}}

function updateKeyHint(id) {{
  const link = document.getElementById('getKeyLink');
  link.href = PROVIDERS[id]?.url || '#';
  link.textContent = `Get ${{PROVIDERS[id]?.name || ''}} API key →`;
}}

function getSelectedProvider() {{
  const sel = document.querySelector('.provider-card.selected');
  if (!sel) return currentProvider;
  return sel.id.replace('pcard-', '');
}}

function toggleKey() {{
  const inp = document.getElementById('apiKeyInput');
  const ico = document.getElementById('eyeIcon');
  if (inp.type === 'password') {{ inp.type = 'text';     ico.className = 'bi bi-eye-slash'; }}
  else                         {{ inp.type = 'password'; ico.className = 'bi bi-eye'; }}
}}

async function saveSettings() {{
  const provider = getSelectedProvider();
  const api_key  = document.getElementById('apiKeyInput').value.trim();
  const model    = document.getElementById('modelSelect').value;
  const btn      = document.querySelector('button.btn-primary');
  const res      = document.getElementById('testResult');

  btn.disabled = true;
  btn.innerHTML = '<span class="spinner-border spinner-border-sm me-2"></span>Testing...';

  try {{
    const r = await fetch('/settings/save', {{
      method: 'POST',
      headers: {{'Content-Type': 'application/json'}},
      body: JSON.stringify({{provider, api_key, model}})
    }});
    const d = await r.json();
    res.style.display = 'block';
    if (d.ok) {{
      res.className = 'alert alert-success';
      res.innerHTML = `<i class="bi bi-check-circle me-2"></i>${{d.message}}`;
      setTimeout(() => window.location.href = '/', 1500);
    }} else {{
      res.className = 'alert alert-danger';
      res.innerHTML = `<i class="bi bi-x-circle me-2"></i>${{d.message}}`;
    }}
  }} catch(e) {{
    res.style.display = 'block';
    res.className = 'alert alert-danger';
    res.innerHTML = 'Connection error — check server is running.';
  }}
  btn.disabled = false;
  btn.innerHTML = '<i class="bi bi-check-lg me-1"></i>Save &amp; Test Connection';
}}

async function clearSettings() {{
  await fetch('/settings/clear', {{method:'POST'}});
  window.location.reload();
}}

renderProviders();
</script>
</body>
</html>"""


@app.route("/settings/save", methods=["POST"])
def settings_save():
    from flask import session as fs
    data     = request.get_json()
    provider = data.get("provider", "deepseek")
    api_key  = data.get("api_key", "").strip()
    model    = data.get("model", "")

    # Test the connection
    test_ok  = False
    message  = ""
    try:
        if provider == "ollama":
            resp = requests.get(OLLAMA_URL.replace("/api/generate", "/api/tags"), timeout=5)
            test_ok = resp.status_code == 200
            message = "Ollama is running locally ✓" if test_ok else "Cannot reach Ollama — is it running?"
        elif provider == "claude":
            headers = {
                "x-api-key": api_key, "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            }
            payload = {
                "model": model, "max_tokens": 10,
                "messages": [{"role": "user", "content": "Say OK"}],
            }
            resp    = requests.post(CLAUDE_API_URL, json=payload, headers=headers, timeout=15)
            test_ok = resp.status_code == 200
            message = f"Claude API connected ✓" if test_ok else f"Claude API error: {resp.status_code}"
        else:
            url     = DEEPSEEK_API_URL if provider == "deepseek" else OPENAI_API_URL
            headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
            payload = {
                "model": model, "max_tokens": 10, "temperature": 0.1,
                "messages": [{"role": "user", "content": "Say OK"}],
            }
            resp    = requests.post(url, json=payload, headers=headers, timeout=15)
            if resp.status_code == 200:
                # Validate we got actual content back (catches deepseek-reasoner empty content)
                try:
                    rj = resp.json()
                    choices = rj.get("choices", [])
                    if choices:
                        msg = choices[0].get("message", {})
                        content   = (msg.get("content") or "").strip()
                        reasoning = (msg.get("reasoning_content") or "").strip()
                        if content:
                            test_ok = True
                            message = f"{PROVIDER_INFO.get(provider,{}).get('name',provider)} connected ✓  (model: {model})"
                        elif reasoning:
                            # deepseek-reasoner: content empty, reasoning present
                            # API works but model won't return JSON — warn user
                            test_ok = False
                            message = (f"API key is valid but '{model}' only returns reasoning text, not JSON. "
                                       f"Switch model to 'deepseek-chat' for AI analysis to work.")
                        else:
                            test_ok = False
                            message = (f"API connected but got empty response for model '{model}'.")
                    elif "error" in rj:
                        test_ok = False
                        message = f"API error: {rj['error'].get('message', rj['error'])}"
                    else:
                        test_ok = False
                        message = f"Unexpected response: {str(rj)[:200]}"
                except Exception as e:
                    test_ok = False
                    message = f"Response parse error: {e}"
            else:
                test_ok = False
                try:
                    err_body = resp.json()
                    message = f"HTTP {resp.status_code}: {err_body.get('error',{}).get('message', resp.text[:200])}"
                except Exception:
                    message = f"HTTP {resp.status_code}: {resp.text[:200]}"
    except Exception as e:
        message = f"Connection failed: {e}"

    if test_ok:
        fs["ai_provider"] = provider
        fs["ai_api_key"]  = api_key
        fs["ai_model"]    = model
        return jsonify({"ok": True, "message": f"{message} — Settings saved."})
    else:
        return jsonify({"ok": False, "message": message})


@app.route("/settings/clear", methods=["POST"])
def settings_clear():
    from flask import session as fs
    fs.pop("ai_provider", None)
    fs.pop("ai_api_key",  None)
    fs.pop("ai_model",    None)
    return jsonify({"ok": True})


# ============================================================
# ADMIN LOGIN + DB UPDATER
# ============================================================

def admin_required(f):
    """Decorator: redirect to /admin/login if not authenticated."""
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        from flask import session as fs
        if not fs.get("admin_logged_in"):
            return redirect(url_for("admin_login", next=request.path))
        return f(*args, **kwargs)
    return decorated


@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    from flask import session as fs
    error = ""
    if request.method == "POST":
        if (request.form.get("username") == ADMIN_USERNAME and
                request.form.get("password") == ADMIN_PASSWORD):
            fs["admin_logged_in"] = True
            return redirect(request.args.get("next") or url_for("admin_panel"))
        error = "Invalid credentials"

    return f"""<!DOCTYPE html>
<html>
<head>
  <title>Admin Login</title>
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
  <style>
    body {{ background:#0f172a; display:flex; align-items:center; justify-content:center;
            min-height:100vh; font-family:'Inter',sans-serif; }}
    .login-card {{ background:#1e293b; border-radius:16px; padding:40px; width:360px;
                   box-shadow:0 20px 60px rgba(0,0,0,0.5); }}
    .form-control {{ background:#0f172a; border-color:#334155; color:#e2e8f0; }}
    .form-control:focus {{ background:#0f172a; border-color:#3b82f6; color:#e2e8f0; box-shadow:none; }}
    label {{ color:#94a3b8; font-size:.85rem; }}
    h5 {{ color:#e2e8f0; }}
  </style>
</head>
<body>
  <div class="login-card">
    <div class="text-center mb-4">
      <i class="bi bi-shield-lock-fill text-primary" style="font-size:2.5rem"></i>
      <h5 class="mt-2">Admin Panel</h5>
      <p style="color:#64748b;font-size:.82rem">CVE Dashboard</p>
    </div>
    {'<div class="alert alert-danger py-2 text-center" style="font-size:.85rem">' + error + '</div>' if error else ''}
    <form method="POST">
      <div class="mb-3">
        <label>Username</label>
        <input type="text" name="username" class="form-control mt-1" autofocus>
      </div>
      <div class="mb-4">
        <label>Password</label>
        <input type="password" name="password" class="form-control mt-1">
      </div>
      <button type="submit" class="btn btn-primary w-100">Login</button>
    </form>
  </div>
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.1/font/bootstrap-icons.css">
</body>
</html>"""


@app.route("/admin/logout")
def admin_logout():
    from flask import session as fs
    fs.pop("admin_logged_in", None)
    return redirect(url_for("index"))


@app.route("/admin")
@admin_required
def admin_panel():
    conn   = sqlite3.connect(DB)
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM cves");            total_cves = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM cve_ai_analysis"); ai_count   = cursor.fetchone()[0]
    try:
        cursor.execute(f"SELECT MIN({DATE_COLUMN}), MAX({DATE_COLUMN}) FROM cves")
        dr = cursor.fetchone()
        oldest, newest = (dr[0] or "?")[:10], (dr[1] or "?")[:10]
    except Exception:
        oldest, newest = "?", "?"
    conn.close()

    return f"""<!DOCTYPE html>
<html>
<head>
  <title>Admin Panel — CVE Dashboard</title>
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.1/font/bootstrap-icons.css">
  <style>
    body {{ background:#f1f5f9; font-family:'Inter',sans-serif; }}
    .card {{ border:none; border-radius:14px; box-shadow:0 2px 16px rgba(0,0,0,0.07); }}
    .stat-val {{ font-size:1.8rem; font-weight:800; color:#1e293b; }}
    .action-btn {{ border-radius:10px; font-weight:600; }}
  </style>
</head>
<body>
<div class="container py-4" style="max-width:760px">
  <div class="d-flex align-items-center justify-content-between mb-4">
    <div class="d-flex align-items-center gap-3">
      <a href="/" class="btn btn-outline-secondary btn-sm"><i class="bi bi-arrow-left"></i></a>
      <h4 class="mb-0"><i class="bi bi-shield-shaded me-2 text-primary"></i>Admin Panel</h4>
    </div>
    <a href="/admin/logout" class="btn btn-outline-danger btn-sm">
      <i class="bi bi-box-arrow-right me-1"></i>Logout
    </a>
  </div>

  <!-- Stats -->
  <div class="row g-3 mb-4">
    <div class="col-4"><div class="card p-3 text-center">
      <div class="stat-val">{total_cves:,}</div>
      <div class="text-muted" style="font-size:.8rem">Total CVEs</div>
    </div></div>
    <div class="col-4"><div class="card p-3 text-center">
      <div class="stat-val">{ai_count:,}</div>
      <div class="text-muted" style="font-size:.8rem">AI Analyzed</div>
    </div></div>
    <div class="col-4"><div class="card p-3 text-center">
      <div class="stat-val" style="font-size:1rem">{oldest}<br><small class="text-muted" style="font-size:.7rem">to</small><br>{newest}</div>
      <div class="text-muted" style="font-size:.8rem">Date Range</div>
    </div></div>
  </div>

  <!-- Upload DB File -->
  <div class="card p-4 mb-4">
    <h5 class="mb-1"><i class="bi bi-file-earmark-arrow-up me-2 text-primary"></i>Upload DB File</h5>
    <p class="text-muted mb-3" style="font-size:.85rem">
      Upload a pre-built <code>.db</code> file to merge CVEs into the database.
      Existing data is backed up first — no data is lost.
    </p>
    <label class="btn btn-outline-primary action-btn">
      <i class="bi bi-upload me-1"></i>Choose .db File
      <input type="file" id="dbFileInput" accept=".db,.sqlite,.sqlite3" style="display:none"
             onchange="uploadDb(this)">
    </label>
    <div id="uploadProgress" style="display:none;margin-top:12px">
      <div class="progress mb-2" style="height:7px;border-radius:6px">
        <div class="progress-bar progress-bar-striped progress-bar-animated bg-primary"
             id="uploadBar" style="width:30%"></div>
      </div>
      <div id="uploadStatus" style="font-size:.82rem;color:#64748b"></div>
    </div>
  </div>

  <!-- AI Cache Management -->
  <div class="card p-4 mb-4">
    <h5 class="mb-3"><i class="bi bi-robot me-2 text-primary"></i>AI Cache Management</h5>
    <div class="d-flex gap-2 flex-wrap">
      <button class="btn btn-outline-warning action-btn"
              onclick="adminAction('/admin/clear-all-cache','Clear stale/placeholder AI records?')">
        <i class="bi bi-trash2 me-1"></i>Clear Stale AI
      </button>
      <button class="btn btn-outline-danger action-btn"
              onclick="adminAction('/admin/clear-all-ai','WIPE ALL AI data? This cannot be undone.')">
        <i class="bi bi-nuclear me-1"></i>Wipe All AI Data
      </button>
    </div>
    <p class="text-muted mt-2 mb-0" style="font-size:.78rem">
      "Clear Stale" removes placeholder-only records. "Wipe All" clears everything — use before sharing project.
    </p>
    <div id="actionResult" class="mt-3" style="display:none"></div>
  </div>

  <div class="card p-4">
    <h5 class="mb-2"><i class="bi bi-info-circle me-2 text-muted"></i>Other Actions</h5>
    <div class="d-flex gap-2 flex-wrap">
      <a href="/update-cve" class="btn btn-success action-btn">
        <i class="bi bi-cloud-arrow-down me-1"></i>Update from NVD
      </a>
      <button class="btn btn-outline-warning action-btn"
              onclick="adminAction('/admin/fetch-kev','Fetch CISA KEV (actively exploited CVEs)?')">
        <i class="bi bi-exclamation-triangle me-1"></i>CISA KEV
      </button>
      <button class="btn btn-outline-info action-btn"
              onclick="adminAction('/admin/fetch-ghsa','Fetch GitHub Security Advisories?')">
        <i class="bi bi-github me-1"></i>GitHub GHSA
      </button>
      <button class="btn btn-outline-purple action-btn" style="border-color:#7c3aed;color:#7c3aed"
              onclick="adminAction('/admin/fetch-mitre','Fetch from MITRE API (fills NVD backlog)?')">
        <i class="bi bi-database me-1"></i>MITRE CVE
      </button>
      <button class="btn btn-outline-secondary action-btn"
              onclick="adminAction('/admin/fetch-all-sources','Fetch ALL sources (MITRE+KEV+GHSA)?')">
        <i class="bi bi-collection me-1"></i>All Sources
      </button>
      <a href="/settings" class="btn btn-outline-primary action-btn">
        <i class="bi bi-gear me-1"></i>AI Settings
      </a>
    </div>
  </div>
</div>

<script>
async function uploadDb(input) {{
  const file = input.files[0];
  if (!file) return;
  if (!confirm('Merge this DB file? Existing DB will be backed up first.')) {{ input.value=''; return; }}
  const prog = document.getElementById('uploadProgress');
  const stat = document.getElementById('uploadStatus');
  const bar  = document.getElementById('uploadBar');
  prog.style.display = 'block';
  stat.textContent = 'Uploading ' + file.name + '...';
  const fd = new FormData();
  fd.append('db_file', file);
  try {{
    const r = await fetch('/admin/upload-db', {{method:'POST', body:fd}});
    const d = await r.json();
    bar.classList.remove('progress-bar-animated');
    bar.classList.add(d.ok ? 'bg-success' : 'bg-danger');
    stat.innerHTML = d.ok
      ? '<span class="text-success fw-bold">✓ ' + d.message + '</span>'
      : '<span class="text-danger">✗ ' + d.message + '</span>';
  }} catch(e) {{
    stat.innerHTML = '<span class="text-danger">Upload error: ' + e.message + '</span>';
  }}
}}

async function adminAction(url, confirmMsg) {{
  if (!confirm(confirmMsg)) return;
  const res = document.getElementById('actionResult');
  res.style.display = 'block';
  res.className = 'alert alert-info py-2';
  res.textContent = 'Working...';
  try {{
    const r = await fetch(url);
    const d = await r.json();
    res.className = 'alert alert-success py-2';
    res.textContent = d.message || JSON.stringify(d);
  }} catch(e) {{
    res.className = 'alert alert-danger py-2';
    res.textContent = 'Error: ' + e.message;
  }}
}}
</script>
</body>
</html>"""


@app.route("/admin/update-db", methods=["POST"])
@admin_required
def update_db():
    """
    Stream CVE updates from NVD for the last DB_UPDATE_DAYS days.
    Uses NVD API 2.0. Streams JSON progress lines to the browser.
    """
    from datetime import datetime, timedelta

    def generate():
        from datetime import timezone

        now      = datetime.now(timezone.utc)
        pub_from = (now - timedelta(days=DB_UPDATE_DAYS)).strftime("%Y-%m-%dT%H:%M:%S.000+00:00")
        mod_from = (now - timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%S.000+00:00")
        date_to  = now.strftime("%Y-%m-%dT%H:%M:%S.000+00:00")

        headers = {"User-Agent": "CVE-Dashboard/1.0"}
        if NVD_API_KEY:
            headers["apiKey"] = NVD_API_KEY

        results_per  = 2000
        added = updated = skipped = 0

        conn   = sqlite3.connect(DB)
        cursor = conn.cursor()

        # Ensure cves table has all needed columns
        try:
            cursor.execute("PRAGMA table_info(cves)")
            existing_cols = {row[1] for row in cursor.fetchall()}
            for col in ['cve_id','description','cvss_score','severity','published',
                        'last_modified','references','cwe_id','affected_versions',
                        'source','is_kev','kev_date_added','kev_ransomware']:
                if col not in existing_cols:
                    col_name = '"references"' if col == 'references' else col
                    cursor.execute(f"ALTER TABLE cves ADD COLUMN {col_name} TEXT")
            conn.commit()
        except Exception as e:
            yield json.dumps({"log": f"Schema check warning: {e}"}) + "\n"

        # TWO-PASS: Pass 1 = new CVEs (pubDate), Pass 2 = updated CVEs (lastModDate)
        fetch_passes = [
            ("pubStartDate",     "pubEndDate",     pub_from, date_to, "new CVEs"),
            ("lastModStartDate", "lastModEndDate", mod_from, date_to, "recently modified CVEs"),
        ]

        for pass_start_key, pass_end_key, pass_from_dt, pass_to_dt, pass_label in fetch_passes:
            yield json.dumps({"log": f"Starting pass: {pass_label}…", "progress": 5}) + "\n"
            start_index   = 0
            total_results = None

            while True:
                params = {
                    pass_start_key:  pass_from_dt,
                    pass_end_key:    pass_to_dt,
                    "startIndex":     start_index,
                    "resultsPerPage": results_per,
                }

                yield json.dumps({
                    "status":   f"Fetching records {start_index + 1}\u20132000...",
                    "progress": min(10 + int((start_index / max(total_results or 1, 1)) * 85), 94),
                }) + "\n"

                try:
                    resp = requests.get(NVD_API_URL, params=params, headers=headers, timeout=60)
                    if resp.status_code == 403:
                        yield json.dumps({"done": True, "success": False,
                                          "status": "NVD API rate limit. Add NVD_API_KEY env var."}) + "\n"
                        conn.close(); return

                    if resp.status_code in (503, 429, 500, 502, 504):
                        _s = getattr(update_db, "_retry_5xx", 0) + 1
                        update_db._retry_5xx = _s
                        if _s <= 5:
                            wait = min(30 * _s, 120)
                            yield json.dumps({"log": f"NVD HTTP {resp.status_code} — server busy, retrying in {wait}s (attempt {_s}/5)..."}) + "\n"
                            time.sleep(wait)
                            continue
                        update_db._retry_5xx = 0
                        yield json.dumps({"done": True, "success": False,
                                          "status": f"NVD server error ({resp.status_code}) — try again later"}) + "\n"
                        conn.close(); return
                    if resp.status_code != 200:
                        yield json.dumps({"done": True, "success": False,
                                          "status": f"NVD API error: HTTP {resp.status_code}"}) + "\n"
                        conn.close(); return

                    data          = resp.json()
                    total_results = data.get("totalResults", 0)
                    vulnerabilities = data.get("vulnerabilities", [])

                    if total_results == 0:
                        yield json.dumps({"log": f"No CVEs found for {pass_label}.", "progress": 99}) + "\n"
                        break

                    yield json.dumps({"log": f"Total: {total_results:,} | Batch: {len(vulnerabilities)}"}) + "\n"

                    for item in vulnerabilities:
                        cve_data = item.get("cve", {})
                        cve_id   = cve_data.get("id", "")
                        if not cve_id:
                            continue

                        descs = cve_data.get("descriptions", [])
                        desc  = next((d["value"] for d in descs if d.get("lang") == "en"), "")

                        metrics  = cve_data.get("metrics", {})
                        cvss     = None
                        severity = None
                        for key in ["cvssMetricV40","cvssMetricV31","cvssMetricV30","cvssMetricV2"]:
                            if key in metrics and metrics[key]:
                                try:
                                    entry    = metrics[key][0]
                                    cvss     = float(entry["cvssData"]["baseScore"])
                                    severity = (entry["cvssData"].get("baseSeverity")
                                                or entry.get("baseSeverity", ""))
                                except Exception:
                                    pass
                                break
                        if not severity and cvss is not None:
                            if   cvss >= 9.0: severity = "Critical"
                            elif cvss >= 7.0: severity = "High"
                            elif cvss >= 4.0: severity = "Medium"
                            else:             severity = "Low"
                        severity = (severity or "Unknown").capitalize()

                        published     = cve_data.get("published", "")[:10]
                        last_modified = cve_data.get("lastModified", "")[:10]

                        cwe_id = ""
                        for w in cve_data.get("weaknesses", []):
                            for d in w.get("description", []):
                                if d.get("lang") == "en":
                                    cwe_id = d.get("value", ""); break

                        refs = [r.get("url","") for r in cve_data.get("references", [])[:10]]

                        affected_versions = ""
                        try:
                            ver_parts = []
                            for cfg in cve_data.get("configurations", []):
                                for node in cfg.get("nodes", []):
                                    for m in node.get("cpeMatch", []):
                                        if not m.get("vulnerable"): continue
                                        ve  = m.get("versionEndExcluding", "")
                                        vei = m.get("versionEndIncluding", "")
                                        vi  = m.get("versionStartIncluding", "")
                                        if ve:    ver_parts.append(f"< {ve}")
                                        elif vei: ver_parts.append(f"<= {vei}")
                                        elif vi:  ver_parts.append(f">= {vi}")
                            if ver_parts:
                                seen, unique = set(), []
                                for v in ver_parts:
                                    if v not in seen: seen.add(v); unique.append(v)
                                affected_versions = ", ".join(unique[:5])
                        except Exception:
                            pass

                        cursor.execute("SELECT cve_id FROM cves WHERE cve_id = ?", (cve_id,))
                        if cursor.fetchone():
                            cursor.execute("""
                                UPDATE cves SET description=?, cvss_score=?, severity=?,
                                published=?, last_modified=?, cwe_id=?,
                                "references"=?, affected_versions=? WHERE cve_id=?
                            """, (desc, cvss, severity, published, last_modified, cwe_id,
                                  json.dumps(refs), affected_versions, cve_id))
                            updated += 1
                        else:
                            cursor.execute("""
                                INSERT INTO cves
                                  (cve_id, description, cvss_score, severity, published,
                                   last_modified, cwe_id, "references", affected_versions)
                                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                            """, (cve_id, desc, cvss, severity, published, last_modified,
                                  cwe_id, json.dumps(refs), affected_versions))
                            added += 1

                    conn.commit()
                    start_index += results_per
                    if start_index >= total_results:
                        break
                    time.sleep(0.7 if NVD_API_KEY else 6)

                except Exception as e:
                    yield json.dumps({"log": f"Fetch error: {e}", "progress": 50}) + "\n"
                    time.sleep(5)
                    continue


        conn.close()
        yield json.dumps({
            "done":    True,
            "success": True,
            "progress": 100,
            "status":  f"Done — {added:,} added, {updated:,} updated, from last {DB_UPDATE_DAYS} days",
            "log":     f"✅ Added: {added}  Updated: {updated}  Total processed: {added + updated}",
        }) + "\n"

    return Response(generate(), mimetype="application/x-ndjson")


@app.route("/admin/upload-db", methods=["POST"])
@admin_required
def upload_db_file():
    """Upload a .db file to replace/merge into the current database."""
    if 'db_file' not in request.files:
        return jsonify({"ok": False, "message": "No file uploaded"})

    file = request.files['db_file']
    if not file.filename.endswith(('.db', '.sqlite', '.sqlite3')):
        return jsonify({"ok": False, "message": "Only .db / .sqlite files accepted"})

    try:
        import shutil
        # Save uploaded file to temp
        tmp_path = os.path.join(tempfile.gettempdir(), "uploaded_cve.db")
        file.save(tmp_path)

        # Verify it's a valid SQLite DB
        test_conn = sqlite3.connect(tmp_path)
        test_conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
        test_conn.close()

        # Backup current DB
        backup_path = DB + ".backup"
        shutil.copy2(DB, backup_path)

        # Merge: copy all CVEs from uploaded DB into current DB
        src_conn  = sqlite3.connect(tmp_path)
        src_cur   = src_conn.cursor()
        dest_conn = sqlite3.connect(DB)
        dest_cur  = dest_conn.cursor()

        src_cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='cves'")
        if not src_cur.fetchone():
            src_conn.close(); dest_conn.close()
            return jsonify({"ok": False, "message": "Uploaded DB has no 'cves' table"})

        src_cur.execute("SELECT * FROM cves")
        rows       = src_cur.fetchall()
        src_cur.execute("PRAGMA table_info(cves)")
        cols       = [c[1] for c in src_cur.fetchall()]
        src_conn.close()

        placeholders = ",".join(["?" for _ in cols])
        inserted = 0
        for row in rows:
            try:
                dest_cur.execute(
                    f"INSERT OR REPLACE INTO cves ({','.join(cols)}) VALUES ({placeholders})",
                    row
                )
                inserted += 1
            except Exception:
                pass

        dest_conn.commit(); dest_conn.close()
        os.remove(tmp_path)

        return jsonify({
            "ok":      True,
            "message": f"Merged {inserted:,} CVEs from uploaded file. Backup saved at {backup_path}",
        })

    except Exception as e:
        return jsonify({"ok": False, "message": f"Error: {str(e)}"})


# ============================================================
# PUBLIC NVD UPDATE  — no admin login, user provides NVD key
# ============================================================

# ============================================================
# UPDATE CVE PAGE TEMPLATE  (Jinja2 — no f-string escaping issues)
# ============================================================
@app.route("/update-cve", methods=["GET"])
def update_cve_page():
    # In production, require admin login to update DB
    if _IS_PRODUCTION:
        from flask import session as fs
        if not fs.get("admin_logged_in"):
            return redirect(url_for("admin_login", next="/update-cve"))
    """Public page: user enters NVD API key and fetches CVEs from NVD."""
    from datetime import datetime, timedelta
    cutoff = (datetime.now() - timedelta(days=DB_UPDATE_DAYS)).strftime("%Y-%m-%d")
    html = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Update CVE Database</title>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.1/font/bootstrap-icons.css">
<style>
body{background:#0f172a;min-height:100vh;display:flex;align-items:center;
     justify-content:center;font-family:system-ui,sans-serif;}
.box{background:#1e293b;border:1px solid #334155;border-radius:16px;
     padding:36px;width:100%;max-width:560px;box-shadow:0 20px 60px rgba(0,0,0,.5);}
.form-control{background:#0f172a!important;border-color:#334155!important;color:#e2e8f0!important;}
.form-control::placeholder{color:#475569!important;}
#logBox{background:#0f172a;color:#94a3b8;border-radius:8px;padding:12px;
        font-size:.75rem;max-height:260px;overflow-y:auto;display:none;
        font-family:monospace;white-space:pre-wrap;word-break:break-all;}
#progWrap{display:none;}
</style>
</head>
<body>
<div class="box">
  <div class="d-flex align-items-center gap-3 mb-3">
    <a href="/" class="btn btn-sm btn-outline-secondary"><i class="bi bi-arrow-left"></i></a>
    <h5 class="mb-0 text-white">
      <i class="bi bi-cloud-download me-2 text-success"></i>Update CVE Database
    </h5>
  </div>
  <p style="color:#94a3b8;font-size:.84rem">
    Fetches CVEs from the last <b style="color:#fff">""" + str(DB_UPDATE_DAYS) + """ days</b>
    (from <code style="color:#67e8f9">""" + cutoff + """</code>).
    Adds/updates only &mdash; never deletes existing data.
  </p>
  <div class="mb-3">
    <label style="color:#94a3b8;font-size:.84rem">
      NVD API Key <span style="color:#475569">(optional &mdash; free at nvd.nist.gov)</span>
    </label>
    <div class="input-group mt-1">
      <input id="nvdKey" type="password" class="form-control"
             placeholder="Leave blank to use anonymous rate limit">
      <button class="btn btn-outline-secondary" type="button"
              onclick="var f=document.getElementById('nvdKey');
                       f.type=f.type==='password'?'text':'password';">
        <i class="bi bi-eye"></i>
      </button>
    </div>
  </div>

  <div id="progWrap" class="mb-2">
    <div class="progress" style="height:8px;border-radius:6px;background:#0f172a">
      <div id="progBar" class="progress-bar progress-bar-striped progress-bar-animated bg-success"
           style="width:0%"></div>
    </div>
  </div>

  <div id="statusMsg" style="min-height:20px;font-size:.82rem;color:#94a3b8;margin-bottom:8px"></div>
  <div id="logBox"></div>

  <button id="fetchBtn" class="btn btn-success w-100 mt-2"
          onclick="startUpdate()">
    <i class="bi bi-cloud-arrow-down me-1"></i>
    Fetch Last """ + str(DB_UPDATE_DAYS) + """ Days from NVD
  </button>
</div>

<script>
var pollTimer = null;
var lastLogLen = 0;

function startUpdate() {
  console.log('[NVD] startUpdate() called');
  var key  = document.getElementById('nvdKey').value.trim();
  var btn  = document.getElementById('fetchBtn');
  var prog = document.getElementById('progWrap');
  var bar  = document.getElementById('progBar');
  var stat = document.getElementById('statusMsg');
  var log  = document.getElementById('logBox');

  btn.disabled = true;
  btn.innerHTML = '<span class="spinner-border spinner-border-sm me-2" style="width:.9rem;height:.9rem"></span>Starting...';
  prog.style.display = 'block';
  bar.style.width = '3%';
  stat.textContent = 'Sending request to server...';
  log.style.display = 'none';
  log.textContent = '';
  lastLogLen = 0;

  console.log('[NVD] POSTing to /api/nvd-update');

  fetch('/api/nvd-update', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({nvd_api_key: key})
  })
  .then(function(r) {
    console.log('[NVD] Got response status:', r.status);
    return r.json();
  })
  .then(function(data) {
    console.log('[NVD] Response data:', data);
    if (data.ok) {
      stat.textContent = 'Update started! Fetching progress...';
      pollTimer = setInterval(doPoll, 1500);
    } else {
      stat.innerHTML = '<span style="color:#f87171">Error: ' + data.message + '</span>';
      resetBtn();
    }
  })
  .catch(function(err) {
    console.error('[NVD] fetch error:', err);
    stat.innerHTML = '<span style="color:#f87171">Request failed: ' + err.message + ' &mdash; check browser console</span>';
    resetBtn();
  });
}

function resetBtn() {
  var btn = document.getElementById('fetchBtn');
  btn.disabled = false;
  btn.innerHTML = '<i class="bi bi-cloud-arrow-down me-1"></i>Fetch Last """ + str(DB_UPDATE_DAYS) + """ Days from NVD';
}

function doPoll() {
  fetch('/api/nvd-status')
  .then(function(r) { return r.json(); })
  .then(function(d) {
    var bar  = document.getElementById('progBar');
    var stat = document.getElementById('statusMsg');
    var log  = document.getElementById('logBox');

    if (d.progress) bar.style.width = d.progress + '%';
    if (d.status)   stat.textContent = d.status;

    if (d.log && d.log.length > lastLogLen) {
      log.style.display = 'block';
      log.textContent += d.log.slice(lastLogLen).join('\\n') + '\\n';
      log.scrollTop = log.scrollHeight;
      lastLogLen = d.log.length;
    }

    if (d.done) {
      clearInterval(pollTimer);
      pollTimer = null;
      bar.style.width = '100%';
      bar.classList.remove('progress-bar-animated');
      if (d.success) {
        bar.classList.replace('bg-success', 'bg-success');
        stat.innerHTML = '<span style="color:#4ade80;font-weight:700">&#10003; ' + d.status + '</span>';
        setTimeout(function() { window.location.href = '/'; }, 3000);
      } else {
        bar.classList.replace('bg-success', 'bg-danger');
        stat.innerHTML = '<span style="color:#f87171;font-weight:700">&#10007; ' + d.status + '</span>';
        resetBtn();
      }
    }
  })
  .catch(function(err) {
    console.warn('[NVD] poll error:', err);
  });
}
</script>
</body>
</html>"""
    resp = Response(html, mimetype="text/html")
    resp.headers.pop("Content-Security-Policy", None)
    return resp


# NVD update job state
_nvd_job  = {"running": False, "progress": 0, "status": "idle",
              "log": [], "success": None, "done": False}
_nvd_lock = threading.Lock()


def _run_nvd_update(user_key):
    """Background thread: fetch CVEs from NVD and update the local DB."""
    from datetime import datetime, timedelta, timezone
    global _nvd_job

    def _log(msg, progress=None):
        with _nvd_lock:
            _nvd_job["log"].append(msg)
            if progress is not None:
                _nvd_job["progress"] = progress
            _nvd_job["status"] = msg[:120]
        print(f"[NVD] {msg}")

    try:
        now      = datetime.now(timezone.utc)
        pub_from = (now - timedelta(days=DB_UPDATE_DAYS)).strftime("%Y-%m-%dT%H:%M:%S.000+00:00")
        mod_from = (now - timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%S.000+00:00")
        date_to  = now.strftime("%Y-%m-%dT%H:%M:%S.000+00:00")

        req_headers = {"User-Agent": "CVE-Dashboard/1.0"}
        if user_key:
            req_headers["apiKey"] = user_key

        results_per = 2000
        added = updated = 0

        conn   = sqlite3.connect(DB)
        cursor = conn.cursor()

        try:
            cursor.execute("PRAGMA table_info(cves)")
            existing = {row[1] for row in cursor.fetchall()}
            for col in ["cve_id","description","cvss_score","severity",
                        "published","last_modified","references","cwe_id","affected_versions",
                        "source","is_kev","kev_date_added","kev_ransomware"]:
                if col not in existing:
                    col_sql = '"references"' if col == "references" else col
                    cursor.execute(f"ALTER TABLE cves ADD COLUMN {col_sql} TEXT")
            conn.commit()
        except Exception as ex:
            _log(f"Schema note: {ex}")

        fetch_passes = [
            ("pubStartDate",     "pubEndDate",     pub_from, date_to, "new publications"),
            ("lastModStartDate", "lastModEndDate", mod_from, date_to, "recently modified"),
        ]

        for pass_start_key, pass_end_key, pass_from, pass_to, pass_label in fetch_passes:
            _log(f"Pass: {pass_label}", progress=5)
            start_index   = 0
            total_results = None

            while True:
                params = {
                    pass_start_key:  pass_from,
                    pass_end_key:    pass_to,
                    "startIndex":     start_index,
                    "resultsPerPage": results_per,
                }
                prog = min(10 + int((start_index / max(total_results or 1, 1)) * 85), 94)
                _log(f"Fetching records {start_index+1}-{start_index+results_per}...", progress=prog)

                try:
                    resp = requests.get(NVD_API_URL, params=params,
                                        headers=req_headers, timeout=60)

                    if resp.status_code == 403:
                        _log("NVD rate limit — add free NVD API key")
                        with _nvd_lock:
                            _nvd_job.update({"done": True, "success": False,
                                "status": "Rate limited — add NVD API key"})
                        conn.close(); return

                    if resp.status_code in (503, 429, 500, 502, 504):
                        _retry_5xx = getattr(_run_nvd_update, "_retry_5xx", 0) + 1
                        _run_nvd_update._retry_5xx = _retry_5xx
                        if _retry_5xx <= 5:
                            wait = min(30 * _retry_5xx, 120)
                            _log(f"NVD HTTP {resp.status_code} (attempt {_retry_5xx}/5)"
                                 f" — NVD server busy, retrying in {wait}s...")
                            time.sleep(wait)
                            continue
                        _run_nvd_update._retry_5xx = 0
                        _log(f"NVD HTTP {resp.status_code} after 5 retries — try again later")
                        with _nvd_lock:
                            _nvd_job.update({"done": True, "success": False,
                                "status": f"NVD server error ({resp.status_code}) — try again later"})
                        conn.close(); return

                    if resp.status_code == 404:
                        _retry = getattr(_run_nvd_update, "_retry_404", 0) + 1
                        _run_nvd_update._retry_404 = _retry
                        if _retry <= 3:
                            wait = 30 * _retry
                            _log(f"NVD 404 (attempt {_retry}/3) — retrying in {wait}s...")
                            time.sleep(wait)
                            continue
                        _run_nvd_update._retry_404 = 0
                        _log("NVD 404 after 3 retries — try again later")
                        with _nvd_lock:
                            _nvd_job.update({"done": True, "success": False,
                                "status": "NVD 404 after retries — try again later"})
                        conn.close(); return

                    if resp.status_code != 200:
                        msg = f"NVD HTTP {resp.status_code}"
                        _log(msg)
                        with _nvd_lock:
                            _nvd_job.update({"done": True, "success": False, "status": msg})
                        conn.close(); return

                    data_json     = resp.json()
                    total_results = data_json.get("totalResults", 0)
                    vuln_list     = data_json.get("vulnerabilities", [])

                    if total_results == 0:
                        _log(f"No CVEs for {pass_label}.")
                        break

                    _log(f"Total: {total_results:,} | Batch: {len(vuln_list)}")

                    for item in vuln_list:
                        cve_data = item.get("cve", {})
                        cve_id   = cve_data.get("id", "")
                        if not cve_id:
                            continue

                        descs = cve_data.get("descriptions", [])
                        desc  = next((d["value"] for d in descs if d.get("lang") == "en"), "")

                        metrics  = cve_data.get("metrics", {})
                        cvss = severity = None
                        for mk in ["cvssMetricV40","cvssMetricV31","cvssMetricV30","cvssMetricV2"]:
                            if mk in metrics and metrics[mk]:
                                try:
                                    e2 = metrics[mk][0]
                                    cvss     = float(e2["cvssData"]["baseScore"])
                                    severity = (e2["cvssData"].get("baseSeverity")
                                                or e2.get("baseSeverity",""))
                                except Exception:
                                    pass
                                break
                        if not severity and cvss is not None:
                            if   cvss >= 9.0: severity = "Critical"
                            elif cvss >= 7.0: severity = "High"
                            elif cvss >= 4.0: severity = "Medium"
                            else:             severity = "Low"
                        severity = (severity or "Unknown").capitalize()

                        published     = cve_data.get("published",    "")[:10]
                        last_modified = cve_data.get("lastModified", "")[:10]

                        cwe_id = ""
                        for w in cve_data.get("weaknesses", []):
                            for d in w.get("description", []):
                                if d.get("lang") == "en":
                                    cwe_id = d.get("value",""); break

                        refs = [r.get("url","") for r in cve_data.get("references",[])[:10]]

                        affected_versions = ""
                        try:
                            ver_parts = []
                            for cfg in cve_data.get("configurations", []):
                                for node in cfg.get("nodes", []):
                                    for m in node.get("cpeMatch", []):
                                        if not m.get("vulnerable"): continue
                                        ve  = m.get("versionEndExcluding","")
                                        vei = m.get("versionEndIncluding","")
                                        vi  = m.get("versionStartIncluding","")
                                        if ve:    ver_parts.append(f"< {ve}")
                                        elif vei: ver_parts.append(f"<= {vei}")
                                        elif vi:  ver_parts.append(f">= {vi}")
                            if ver_parts:
                                seen, unique = set(), []
                                for v in ver_parts:
                                    if v not in seen: seen.add(v); unique.append(v)
                                affected_versions = ", ".join(unique[:5])
                        except Exception:
                            pass

                        cursor.execute("SELECT cve_id FROM cves WHERE cve_id=?", (cve_id,))
                        if cursor.fetchone():
                            cursor.execute("""
                                UPDATE cves SET description=?,cvss_score=?,severity=?,
                                published=?,last_modified=?,cwe_id=?,"references"=?,
                                affected_versions=? WHERE cve_id=?
                            """, (desc,cvss,severity,published,last_modified,
                                  cwe_id,json.dumps(refs),affected_versions,cve_id))
                            updated += 1
                        else:
                            cursor.execute("""
                                INSERT INTO cves
                                  (cve_id,description,cvss_score,severity,published,
                                   last_modified,cwe_id,"references",affected_versions)
                                VALUES (?,?,?,?,?,?,?,?,?)
                            """, (cve_id,desc,cvss,severity,published,last_modified,
                                  cwe_id,json.dumps(refs),affected_versions))
                            added += 1

                    conn.commit()
                    start_index += results_per
                    if start_index >= total_results:
                        break
                    time.sleep(0.7 if user_key else 6)

                except Exception as ex:
                    _log(f"Fetch error: {ex}")
                    time.sleep(5)
                    continue

        conn.close()

        # After NVD — fetch CISA KEV and MITRE to fill any gaps
        _log("Fetching CISA KEV (actively exploited CVEs)...", progress=95)
        try:
            kev_added, kev_updated = fetch_cisa_kev()
            _log(f"CISA KEV: {kev_added} new, {kev_updated} marked exploited")
        except Exception as e:
            _log(f"CISA KEV skipped: {e}")

        _log("Fetching MITRE (fills NVD backlog)...", progress=97)
        try:
            mitre_added, mitre_updated = fetch_mitre_cve(days=30)
            _log(f"MITRE: {mitre_added} new, {mitre_updated} enriched")
        except Exception as e:
            _log(f"MITRE skipped: {e}")

        _build_stats_cache()
        msg = (f"Done — NVD: {added:,} added/{updated:,} updated | "
               f"MITRE+KEV also fetched")
        _log(f"✅ {msg}", progress=100)
        with _nvd_lock:
            _nvd_job.update({"done":True,"success":True,"status":msg,"running":False})

    except Exception as ex:
        print(f"[NVD] Fatal: {ex}")
        with _nvd_lock:
            _nvd_job.update({"done":True,"success":False,
                             "status":f"Fatal error: {ex}","running":False})


@app.route("/api/nvd-update", methods=["POST"])
def api_nvd_update():
    """Start NVD update in background thread, return job ID."""
    global _nvd_job
    with _nvd_lock:
        if _nvd_job.get("running"):
            return jsonify({"ok": False, "message": "Update already running"}), 409

        body     = request.get_json(silent=True) or {}
        user_key = (body.get("nvd_api_key") or "").strip() or NVD_API_KEY

        _nvd_job = {"running": True, "progress": 0, "status": "Starting...",
                    "log": [], "success": None, "done": False}

    t = threading.Thread(target=_run_nvd_update, args=(user_key,), daemon=True)
    t.start()
    return jsonify({"ok": True, "message": "Update started"})


@app.route("/api/nvd-status")
def api_nvd_status():
    """Poll endpoint: returns current NVD update job status."""
    with _nvd_lock:
        job = dict(_nvd_job)
        # Only return last 50 log lines to keep response small
        job["log"] = job["log"][-50:]
        if job.get("done"):
            _nvd_job["running"] = False
    return jsonify(job)


@app.route("/admin/analytics")
@admin_required
def analytics():
    """View transparent usage analytics."""
    conn = sqlite3.connect(DB)
    cur  = conn.cursor()
    cur.execute("""
        SELECT provider, model, COUNT(*) as calls,
               COUNT(DISTINCT ip_hash) as unique_users,
               DATE(created_at) as day
        FROM usage_analytics
        WHERE event = 'ai_analyze'
        GROUP BY provider, model, DATE(created_at)
        ORDER BY day DESC, calls DESC
        LIMIT 100
    """)
    rows = cur.fetchall()
    cur.execute("SELECT COUNT(*) FROM usage_analytics")
    total = cur.fetchone()[0]
    cur.execute("SELECT COUNT(DISTINCT ip_hash) FROM usage_analytics")
    unique = cur.fetchone()[0]
    conn.close()

    table_rows = "".join(
        f"<tr><td>{r[4]}</td><td><b>{r[0]}</b></td><td>{r[1]}</td>"
        f"<td>{r[2]}</td><td>{r[3]}</td></tr>"
        for r in rows
    )
    return f"""<!DOCTYPE html><html><head>
    <title>Usage Analytics</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
    </head><body class="p-4" style="background:#f1f5f9">
    <div class="container" style="max-width:900px">
    <div class="d-flex gap-3 align-items-center mb-4">
      <a href="/admin" class="btn btn-sm btn-outline-secondary">← Back</a>
      <h4 class="mb-0">📊 Usage Analytics</h4>
    </div>
    <div class="row g-3 mb-4">
      <div class="col-4"><div class="card p-3 text-center">
        <div style="font-size:1.8rem;font-weight:800">{total:,}</div>
        <div class="text-muted" style="font-size:.8rem">Total AI Calls</div>
      </div></div>
      <div class="col-4"><div class="card p-3 text-center">
        <div style="font-size:1.8rem;font-weight:800">{unique:,}</div>
        <div class="text-muted" style="font-size:.8rem">Unique Users</div>
      </div></div>
    </div>
    <div class="card p-0 overflow-hidden">
    <table class="table table-sm mb-0">
      <thead class="table-dark"><tr>
        <th>Date</th><th>Provider</th><th>Model</th><th>Calls</th><th>Unique IPs</th>
      </tr></thead>
      <tbody>{table_rows}</tbody>
    </table></div>
    <p class="text-muted mt-3" style="font-size:.78rem">
      ℹ️ API keys are NEVER stored. Only provider name, model, and hashed IP logged.
    </p>
    </div></body></html>"""

@app.route("/webhook/update-db")
def webhook_update_db():
    """Public webhook for external cron services (cron-job.org etc).
    Requires WEBHOOK_SECRET env var to match the 'token' query param.
    Example: GET /webhook/update-db?token=your-secret
    """
    secret = os.environ.get("WEBHOOK_SECRET", "")
    if not secret:
        return jsonify({"error": "WEBHOOK_SECRET not configured"}), 500
    token = request.args.get("token", "")
    if not token or token != secret:
        return jsonify({"error": "Invalid token"}), 403

    # Check if update already running
    with _nvd_lock:
        if _nvd_job.get("running"):
            return jsonify({"status": "already_running"}), 200

    # Start background update
    user_key = os.environ.get("NVD_API_KEY", "")
    with _nvd_lock:
        _nvd_job.update({"running": True, "done": False,
                         "progress": 0, "status": "Starting...",
                         "log": [], "success": False})
    threading.Thread(target=_run_nvd_update,
                     args=(user_key,), daemon=True).start()
    return jsonify({"status": "started", "message": "NVD update triggered"}), 200

@app.route("/admin/fetch-kev")
@admin_required
def admin_fetch_kev():
    """Fetch CISA KEV and mark exploited CVEs."""
    added, updated = fetch_cisa_kev()
    _build_stats_cache()
    return jsonify({"ok": True, "added": added, "updated": updated,
                    "message": f"CISA KEV: {added} new, {updated} marked as exploited"})


@app.route("/admin/fetch-ghsa")
@admin_required
def admin_fetch_ghsa():
    """Fetch GitHub Security Advisories."""
    added, updated = fetch_github_advisories()
    _build_stats_cache()
    return jsonify({"ok": True, "added": added, "updated": updated,
                    "message": f"GitHub GHSA: {added} new, {updated} updated"})


@app.route("/admin/fetch-mitre")
@admin_required
def admin_fetch_mitre():
    """Fetch from MITRE CVE API — fills NVD backlog gaps."""
    added, updated = fetch_mitre_cve(days=90)
    _build_stats_cache()
    return jsonify({"ok": True, "added": added, "updated": updated,
                    "message": f"MITRE API: {added} new CVEs added, {updated} enriched"})


@app.route("/admin/fetch-all-sources")
@admin_required
def admin_fetch_all_sources():
    """Fetch from ALL vulnerability sources."""
    results = {}
    ka, ku = fetch_cisa_kev()
    results["cisa_kev"] = {"added": ka, "updated": ku}
    ma, mu = fetch_mitre_cve(days=90)
    results["mitre"] = {"added": ma, "updated": mu}
    ga, gu = fetch_github_advisories()
    results["github_ghsa"] = {"added": ga, "updated": gu}
    _build_stats_cache()
    total_new = ka + ma + ga
    return jsonify({"ok": True, "results": results,
                    "message": f"Multi-source: {total_new} new CVEs across NVD+MITRE+KEV+GHSA"})


@app.route("/health")
def health_check():
    """Render health check endpoint."""
    try:
        conn = sqlite3.connect(DB)
        conn.execute("SELECT COUNT(*) FROM cves")
        conn.close()
        return jsonify({"status": "ok", "db": "connected"}), 200
    except Exception as e:
        return jsonify({"status": "error", "detail": str(e)}), 500

@app.errorhandler(404)
def not_found_error(error):  return "Page not found", 404

@app.errorhandler(500)
def internal_error(error):   return "Internal server error", 500


# ============================================================
# STARTUP
# ============================================================

if __name__ == "__main__":
    init_database()
    ensure_ai_table_columns()

    print("=" * 55)
    print("🚀 CVE Monitoring Dashboard")
    print("=" * 55)
    print(f"📁 Database:  {DB}")
    print(f"🤖 AI:        {'Enabled' if USE_AI else 'Disabled'}")
    print(f"🔌 Provider:  {DEFAULT_AI_PROVIDER} (users can change via /settings)")
    print(f"💾 AI Cache:  {'ON' if USE_AI_CACHE else 'OFF'}")
    print(f"📅 Date col:  {DATE_COLUMN}")
    print(f"🔐 Admin:     /admin  (user: {ADMIN_USERNAME})")

    # Clear stale records on startup
    try:
        conn   = sqlite3.connect(DB)
        cursor = conn.cursor()
        cursor.execute(
            "DELETE FROM cve_ai_analysis WHERE summary IN (?, ?, ?, ?)",
            ("No AI summary available","Information not available",
             "AI analysis unavailable","AI analysis unavailable — review description manually.")
        )
        # Wipe any cached remediation containing generic/NVD-link text so it regenerates
        cursor.execute(
            "UPDATE cve_ai_analysis SET remediation = NULL WHERE "
            "remediation LIKE '%nvd.nist.gov%' OR "
            "remediation LIKE '%No patch info in CVE description%' OR "
            "remediation LIKE '%monitor vendor advisories%' OR "
            "remediation LIKE '%check vendor advisories%'"
        )
        cleared = cursor.rowcount
        conn.commit(); conn.close()
        if cleared:
            print(f"🧹 Cleared {cleared} stale AI records")
    except Exception as e:
        print(f"⚠️ Stale clear error: {e}")

    try:
        conn   = sqlite3.connect(DB)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM cves");            cve_count = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM cve_ai_analysis"); ai_count  = cursor.fetchone()[0]
        conn.close()
        print(f"📊 CVEs in DB:  {cve_count:,}")
        print(f"📊 AI cached:   {ai_count:,}")
    except Exception as e:
        print(f"📊 Stats error: {e}")

    print(f"\n🌐  http://127.0.0.1:5000")
    print(f"⚙️   AI Settings:  http://127.0.0.1:5000/settings")
    print(f"🔧  Admin Panel:  http://127.0.0.1:5000/admin")
    print(f"\n   Admin routes:")
    print(f"   /admin/update-db      → fetch last {DB_UPDATE_DAYS} days from NVD")
    print(f"   /admin/clear-all-ai   → wipe all AI data (use before sharing)")
    print(f"   /admin/clear-all-cache→ clear stale AI only")
    print("=" * 55)

    port  = int(os.environ.get("PORT", 5000))
    debug = not _IS_PRODUCTION
    if _IS_PRODUCTION:
        print("🔒 Production mode — debug disabled, secure cookies enabled")
    app.run(debug=debug, host="0.0.0.0", port=port)
