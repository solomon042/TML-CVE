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
from datetime import datetime, timedelta, timezone
import threading
from collections import deque
import psycopg2
from psycopg2 import pool
from psycopg2.extras import Json
import schedule
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

app = Flask(__name__)

# ============================================================
# ENVIRONMENT CONFIGURATION
# ============================================================

DB = os.environ.get('CVE_DB_PATH', '/tmp/nvd_database.db')

GITHUB_REPO  = os.environ.get('GITHUB_REPO',  'solomon042/TML-CVE-Dashboard')
GITHUB_TAG   = os.environ.get('GITHUB_TAG',   'v1.0.0')
GITHUB_ASSET = os.environ.get('GITHUB_ASSET', 'nvd_database.db')

DATABASE_URL = os.environ.get('DATABASE_URL', '')

SMTP_SERVER    = os.environ.get('SMTP_SERVER',    'smtp.gmail.com')
SMTP_PORT      = int(os.environ.get('SMTP_PORT',  587))
SMTP_USERNAME  = os.environ.get('SMTP_USERNAME',  '')
SMTP_PASSWORD  = os.environ.get('SMTP_PASSWORD',  '')
ALERT_EMAIL_FROM = os.environ.get('ALERT_EMAIL_FROM', SMTP_USERNAME or 'cve-alerts@localhost')

app.config['SECRET_KEY']                = os.environ.get('FLASK_SECRET_KEY', secrets.token_hex(32))
app.config['SESSION_COOKIE_HTTPONLY']   = True
app.config['SESSION_COOKIE_SAMESITE']   = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=8)

ADMIN_USERNAME = os.environ.get('ADMIN_USERNAME', 'admin')
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', 'cve@admin2024')

app.config['UPLOAD_FOLDER']      = tempfile.gettempdir()
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
ALLOWED_EXTENSIONS = {'txt', 'csv', 'json', 'xml', 'xlsx', 'xls'}

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY = os.environ.get("NVD_API_KEY", "")

# Global: tracks when the last successful NVD update ran (in-memory + PostgreSQL)
_last_update_time: datetime | None = None
_last_update_lock = threading.Lock()

def get_last_update_time() -> datetime | None:
    """Return last update time from memory, then PostgreSQL, then None."""
    global _last_update_time
    if _last_update_time:
        return _last_update_time
    if postgres_pool:
        try:
            conn = postgres_pool.getconn()
            cur  = conn.cursor()
            cur.execute("""
                SELECT value FROM app_settings WHERE key = 'last_nvd_update'
            """)
            row = cur.fetchone()
            cur.close()
            postgres_pool.putconn(conn)
            if row and row[0]:
                dt = datetime.fromisoformat(row[0])
                with _last_update_lock:
                    _last_update_time = dt
                return dt
        except Exception:
            pass
    return None

def set_last_update_time(dt: datetime):
    """Persist the last update time to memory and PostgreSQL."""
    global _last_update_time
    with _last_update_lock:
        _last_update_time = dt
    if postgres_pool:
        try:
            conn = postgres_pool.getconn()
            cur  = conn.cursor()
            cur.execute("""
                INSERT INTO app_settings (key, value)
                VALUES ('last_nvd_update', %s)
                ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value
            """, (dt.isoformat(),))
            conn.commit()
            cur.close()
            postgres_pool.putconn(conn)
        except Exception as e:
            print(f"⚠️  Could not persist last_update: {e}")

USE_AI       = True
USE_AI_CACHE = True
DATE_COLUMN  = "published"

DEFAULT_AI_PROVIDER = "deepseek"
DEEPSEEK_API_URL    = "https://api.deepseek.com/v1/chat/completions"
DEEPSEEK_MODEL      = "deepseek-chat"
OPENAI_API_URL      = "https://api.openai.com/v1/chat/completions"
OPENAI_MODEL        = "gpt-4o-mini"
CLAUDE_API_URL      = "https://api.anthropic.com/v1/messages"
CLAUDE_MODEL        = "claude-3-haiku-20240307"
OLLAMA_URL          = "http://localhost:11434/api/generate"
OLLAMA_MODEL        = "llama3.2"

STALE_PLACEHOLDERS = {
    "no ai summary available",
    "information not available",
    "ai analysis unavailable",
    "ai analysis unavailable — review description manually.",
    "",
}

PROVIDER_INFO = {
    "deepseek": {
        "name": "DeepSeek",
        "placeholder": "sk-...",
        "models": ["deepseek-chat", "deepseek-reasoner"],
        "free_tier": True,
        "url": "https://platform.deepseek.com/api_keys",
    },
    "openai": {
        "name": "OpenAI / ChatGPT",
        "placeholder": "sk-proj-...",
        "models": ["gpt-4o-mini", "gpt-4o", "gpt-3.5-turbo"],
        "free_tier": False,
        "url": "https://platform.openai.com/api-keys",
    },
    "claude": {
        "name": "Anthropic Claude",
        "placeholder": "sk-ant-...",
        "models": ["claude-3-haiku-20240307", "claude-3-5-sonnet-20241022"],
        "free_tier": False,
        "url": "https://console.anthropic.com/settings/keys",
    },
    "ollama": {
        "name": "Ollama (Local)",
        "placeholder": "No API key needed",
        "models": ["llama3.2", "llama3.1", "mistral", "phi3", "gemma2"],
        "free_tier": True,
        "url": "https://ollama.com/download",
    },
}

# ============================================================
# LOAD BOMS FROM ENVIRONMENT VARIABLES
# ============================================================

def load_boms_from_env():
    boms = []
    i = 1
    print("📋 Loading BOMs from environment variables...")
    while True:
        keywords = os.environ.get(f'BOM_KEYWORDS_{i}')
        email    = os.environ.get(f'BOM_EMAIL_{i}')
        name     = os.environ.get(f'BOM_NAME_{i}', f'BOM {i}')
        if not keywords or not email:
            break
        keyword_list = [k.strip().lower() for k in keywords.split(',') if k.strip()]
        boms.append({'id': i, 'name': name, 'email': email, 'keywords': keyword_list})
        print(f"   ✅ Loaded BOM {i}: {name} — {len(keyword_list)} keywords → {email}")
        i += 1
    if i == 1:
        print("   ⚠️  No BOM env vars found. Set BOM_KEYWORDS_1, BOM_EMAIL_1, BOM_NAME_1 etc.")
    return boms

ENV_BOMS = load_boms_from_env()

# ============================================================
# DOWNLOAD DATABASE FROM GITHUB
# ============================================================

def download_cve_from_github():
    if os.path.exists(DB):
        file_size = os.path.getsize(DB)
        if file_size > 1024 * 1024:
            size_mb = file_size / (1024 * 1024)
            print(f"✅ CVE database already exists ({size_mb:.1f} MB)")
            try:
                test_conn = sqlite3.connect(DB)
                cursor = test_conn.cursor()
                cursor.execute("SELECT count(*) FROM cves")
                count = cursor.fetchone()[0]
                cursor.close()
                test_conn.close()
                print(f"✅ Database valid: {count:,} CVEs")
                return True
            except Exception as e:
                print(f"⚠️  Existing DB check failed: {e}")
                return True
        else:
            print(f"⚠️  Existing DB empty ({file_size} bytes), re-downloading")
            try:
                os.remove(DB)
            except Exception:
                pass

    download_url = f"https://github.com/{GITHUB_REPO}/releases/download/{GITHUB_TAG}/{GITHUB_ASSET}"
    print(f"📥 Downloading from GitHub: {download_url}")
    try:
        response = requests.get(download_url, stream=True, timeout=120)
        response.raise_for_status()
        total_size  = int(response.headers.get('content-length', 0))
        downloaded  = 0
        last_percent = 0
        with open(DB, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                if chunk:
                    f.write(chunk)
                    downloaded += len(chunk)
                    if total_size:
                        pct = int((downloaded / total_size) * 100)
                        if pct % 10 == 0 and pct > last_percent:
                            print(f"   Progress: {pct}%")
                            last_percent = pct
        size_mb = os.path.getsize(DB) / (1024 * 1024)
        print(f"✅ Downloaded: {size_mb:.1f} MB")
        return True
    except Exception as e:
        print(f"❌ Download failed: {e}")
        return False

# ============================================================
# POSTGRESQL CONNECTION POOL
# ============================================================

postgres_pool = None

def init_postgres():
    global postgres_pool
    if not DATABASE_URL:
        print("⚠️  DATABASE_URL not configured — PostgreSQL features disabled")
        return False
    try:
        postgres_pool = psycopg2.pool.SimpleConnectionPool(1, 20, DATABASE_URL)
        conn = postgres_pool.getconn()
        cur  = conn.cursor()

        cur.execute("""
            CREATE TABLE IF NOT EXISTS ai_generations (
                id SERIAL PRIMARY KEY,
                ip_address INET NOT NULL,
                cve_id TEXT NOT NULL,
                ai_summary TEXT,
                affected_companies JSONB,
                remediation TEXT,
                affected_version TEXT,
                fixed_version TEXT,
                fix_status TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_accessed TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(ip_address, cve_id)
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS cve_tracking (
                cve_id TEXT PRIMARY KEY,
                first_seen_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_new BOOLEAN DEFAULT TRUE,
                cvss_score REAL,
                severity TEXT,
                description TEXT,
                published_date TEXT,
                affected_companies JSONB
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS alert_history (
                id SERIAL PRIMARY KEY,
                email TEXT NOT NULL,
                cve_id TEXT NOT NULL,
                bom_name TEXT NOT NULL,
                matched_keyword TEXT,
                sent_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        # App settings table (stores last_update time etc.)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS app_settings (
                key   TEXT PRIMARY KEY,
                value TEXT
            )
        """)
        cur.execute("CREATE INDEX IF NOT EXISTS idx_alert_email ON alert_history(email)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_alert_cve   ON alert_history(cve_id)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_cve_new     ON cve_tracking(is_new)")

        conn.commit()
        cur.close()
        postgres_pool.putconn(conn)
        print("✅ PostgreSQL tables ready")
        return True
    except Exception as e:
        print(f"❌ PostgreSQL init failed: {e}")
        return False

# ============================================================
# EMAIL
# ============================================================

def send_email_alert(to_email: str, subject: str, html_content: str) -> bool:
    """Send an HTML email via configured SMTP server."""
    if not SMTP_USERNAME or not SMTP_PASSWORD:
        print("⚠️  SMTP credentials not configured — skipping email")
        return False
    try:
        msg = MIMEMultipart('alternative')
        msg['From']    = ALERT_EMAIL_FROM
        msg['To']      = to_email
        msg['Subject'] = subject
        msg.attach(MIMEText(html_content, 'html'))

        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.ehlo()
        server.starttls()
        server.login(SMTP_USERNAME, SMTP_PASSWORD)
        server.send_message(msg)
        server.quit()
        print(f"📧 Alert sent → {to_email}")
        return True
    except Exception as e:
        print(f"❌ Email failed ({to_email}): {e}")
        return False


def get_keyword_statistics(keywords: list) -> dict:
    """Return per-keyword CVE counts from the local SQLite database."""
    stats = {}
    try:
        conn   = sqlite3.connect(DB)
        cursor = conn.cursor()
        for keyword in keywords:
            cursor.execute(
                "SELECT COUNT(*) FROM cves WHERE LOWER(description) LIKE ?",
                (f'%{keyword.lower()}%',)
            )
            total = cursor.fetchone()[0]

            cursor.execute("""
                SELECT
                    SUM(CASE WHEN cvss_score >= 9.0                          THEN 1 ELSE 0 END),
                    SUM(CASE WHEN cvss_score >= 7.0 AND cvss_score < 9.0     THEN 1 ELSE 0 END),
                    SUM(CASE WHEN cvss_score >= 4.0 AND cvss_score < 7.0     THEN 1 ELSE 0 END),
                    SUM(CASE WHEN cvss_score > 0  AND cvss_score < 4.0       THEN 1 ELSE 0 END)
                FROM cves WHERE LOWER(description) LIKE ?
            """, (f'%{keyword.lower()}%',))
            sev = cursor.fetchone()

            cursor.execute("""
                SELECT COUNT(*) FROM cves
                WHERE LOWER(description) LIKE ?
                AND julianday('now') - julianday(published) <= 7
            """, (f'%{keyword.lower()}%',))
            new_count = cursor.fetchone()[0]

            stats[keyword] = {
                'total':    total,
                'critical': sev[0] or 0,
                'high':     sev[1] or 0,
                'medium':   sev[2] or 0,
                'low':      sev[3] or 0,
                'new':      new_count,
            }
        cursor.close()
        conn.close()
    except Exception as e:
        print(f"⚠️  keyword stats error: {e}")
    return stats


def send_bom_alert(email: str, bom_name: str, keywords: list, matches: list):
    """Build and send the formatted CVE alert email for a BOM."""
    keyword_stats = get_keyword_statistics(keywords)

    subject = (
        f"🚨 CVE Alert: {len(matches)} new vulnerabilit{'y' if len(matches)==1 else 'ies'} "
        f"match your BOM '{bom_name}'"
    )

    # ── Keyword statistics table ──────────────────────────────
    stats_rows_html = ""
    total_all = total_crit = total_high = total_med = total_low = total_new = 0

    for idx, (keyword, s) in enumerate(keyword_stats.items()):
        total_all  += s['total']
        total_crit += s['critical']
        total_high += s['high']
        total_med  += s['medium']
        total_low  += s['low']
        total_new  += s['new']
        row_bg = '#f9f9f9' if idx % 2 == 0 else '#ffffff'
        stats_rows_html += f"""
        <tr style="background-color:{row_bg};">
            <td style="padding:8px;border:1px solid #ddd;font-weight:bold;">{keyword}</td>
            <td style="padding:8px;border:1px solid #ddd;text-align:center;">{s['total']:,}</td>
            <td style="padding:8px;border:1px solid #ddd;text-align:center;color:#d9534f;font-weight:bold;">{s['critical']:,}</td>
            <td style="padding:8px;border:1px solid #ddd;text-align:center;color:#f0ad4e;font-weight:bold;">{s['high']:,}</td>
            <td style="padding:8px;border:1px solid #ddd;text-align:center;color:#5bc0de;font-weight:bold;">{s['medium']:,}</td>
            <td style="padding:8px;border:1px solid #ddd;text-align:center;color:#5cb85c;font-weight:bold;">{s['low']:,}</td>
            <td style="padding:8px;border:1px solid #ddd;text-align:center;background:#fcf8e3;font-weight:bold;">{s['new']:,}</td>
        </tr>"""

    stats_table_html = f"""
    <h3 style="color:#333;margin-top:25px;">📊 Keyword Statistics (All Time)</h3>
    <table style="width:100%;border-collapse:collapse;margin-top:15px;font-size:13px;">
        <tr style="background:#4a5568;color:white;">
            <th style="padding:10px;border:1px solid #ddd;">Keyword</th>
            <th style="padding:10px;border:1px solid #ddd;">Total</th>
            <th style="padding:10px;border:1px solid #ddd;">Critical</th>
            <th style="padding:10px;border:1px solid #ddd;">High</th>
            <th style="padding:10px;border:1px solid #ddd;">Medium</th>
            <th style="padding:10px;border:1px solid #ddd;">Low</th>
            <th style="padding:10px;border:1px solid #ddd;">New (7d)</th>
        </tr>
        {stats_rows_html}
        <tr style="background:#e2e8f0;font-weight:bold;">
            <td style="padding:10px;border:1px solid #ddd;">TOTAL</td>
            <td style="padding:10px;border:1px solid #ddd;text-align:center;">{total_all:,}</td>
            <td style="padding:10px;border:1px solid #ddd;text-align:center;color:#d9534f;">{total_crit:,}</td>
            <td style="padding:10px;border:1px solid #ddd;text-align:center;color:#f0ad4e;">{total_high:,}</td>
            <td style="padding:10px;border:1px solid #ddd;text-align:center;color:#5bc0de;">{total_med:,}</td>
            <td style="padding:10px;border:1px solid #ddd;text-align:center;color:#5cb85c;">{total_low:,}</td>
            <td style="padding:10px;border:1px solid #ddd;text-align:center;background:#fcf8e3;">{total_new:,}</td>
        </tr>
    </table>""" if keyword_stats else ""

    # ── Today's matches table ──────────────────────────────────
    matches_rows_html = ""
    for match in matches:
        cve   = match["cve"]
        score = cve.get('cvss_score')
        if score and float(score) >= 9:
            sev_color = "#d9534f"
        elif score and float(score) >= 7:
            sev_color = "#f0ad4e"
        elif score and float(score) >= 4:
            sev_color = "#5bc0de"
        else:
            sev_color = "#5cb85c"

        desc_snippet = (cve.get('description') or '')[:200]
        if len(cve.get('description') or '') > 200:
            desc_snippet += "…"

        matches_rows_html += f"""
        <tr>
            <td style="padding:10px;border:1px solid #ddd;">
                <a href="https://nvd.nist.gov/vuln/detail/{cve['cve_id']}"
                   style="color:#1a56db;">{cve['cve_id']}</a>
            </td>
            <td style="padding:10px;border:1px solid #ddd;text-align:center;font-weight:bold;color:{sev_color};">
                {score if score else 'N/A'}
            </td>
            <td style="padding:10px;border:1px solid #ddd;text-align:center;">
                <span style="background:{sev_color};color:white;padding:3px 8px;border-radius:12px;font-size:.8rem;">
                    {cve.get('severity', 'Unknown')}
                </span>
            </td>
            <td style="padding:10px;border:1px solid #ddd;text-align:center;font-weight:bold;background:#f0f7ff;">
                {match['keyword']}
            </td>
            <td style="padding:10px;border:1px solid #ddd;">{desc_snippet}</td>
        </tr>"""

    html = f"""
    <html>
    <head>
    <meta charset="UTF-8">
    <style>
        body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; margin: 0; padding: 0; }}
        .wrapper {{ max-width: 900px; margin: 0 auto; padding: 20px; }}
        .header {{ background: linear-gradient(135deg,#667eea 0%,#764ba2 100%);
                   color: white; padding: 24px; text-align: center;
                   border-radius: 8px 8px 0 0; }}
        .header h1 {{ margin: 0; font-size: 1.6rem; }}
        .header p  {{ margin: 6px 0 0; opacity: .9; }}
        .body  {{ background: white; padding: 24px; border: 1px solid #e5e7eb;
                   border-top: none; border-radius: 0 0 8px 8px; }}
        .summary-box {{ background: #f8f9fa; padding: 16px; border-radius: 8px;
                        margin-bottom: 20px; border: 1px solid #dee2e6; }}
        .summary-box h3 {{ margin-top: 0; color: #4a5568; }}
        .summary-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 8px; }}
        .footer {{ margin-top: 30px; padding: 16px; color: #777; font-size: 12px;
                   text-align: center; border-top: 1px solid #ddd; }}
        table {{ border-collapse: collapse; }}
    </style>
    </head>
    <body>
    <div class="wrapper">
        <div class="header">
            <h1>🚨 CVE Alert</h1>
            <p>{len(matches)} new vulnerabilit{'y' if len(matches)==1 else 'ies'} match your BOM</p>
        </div>
        <div class="body">
            <div class="summary-box">
                <h3>📋 BOM Summary</h3>
                <div class="summary-grid">
                    <div><strong>BOM Name:</strong> {bom_name}</div>
                    <div><strong>Date:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M UTC')}</div>
                    <div><strong>Recipient:</strong> {email}</div>
                    <div><strong>New Matches:</strong>
                        <span style="color:#d9534f;font-weight:bold;">{len(matches)}</span>
                    </div>
                </div>
            </div>

            {stats_table_html}

            <h3 style="color:#333;margin-top:30px;">🆕 New CVEs Found Today</h3>
            <table style="width:100%;border-collapse:collapse;margin-top:15px;font-size:13px;">
                <tr style="background:#4a5568;color:white;">
                    <th style="padding:10px;border:1px solid #ddd;text-align:left;">CVE ID</th>
                    <th style="padding:10px;border:1px solid #ddd;">CVSS</th>
                    <th style="padding:10px;border:1px solid #ddd;">Severity</th>
                    <th style="padding:10px;border:1px solid #ddd;">Matched Keyword</th>
                    <th style="padding:10px;border:1px solid #ddd;text-align:left;">Description</th>
                </tr>
                {matches_rows_html}
            </table>

            <div class="footer">
                <p>This is an automated alert from your CVE Monitoring Dashboard.</p>
                <p>You received this because your BOM "<strong>{bom_name}</strong>" contains
                   keywords that match these CVEs.</p>
                <p>© {datetime.now().year} CVE Monitoring Dashboard</p>
            </div>
        </div>
    </div>
    </body>
    </html>"""

    return send_email_alert(email, subject, html)

# ============================================================
# DAILY CVE UPDATE
# ============================================================

def fetch_new_cves_from_nvd():
    """Fetch CVEs published in the last 24 hours and update the SQLite DB + send BOM alerts."""
    print(f"🔄 [{datetime.now()}] Starting daily CVE update…")

    end_date   = datetime.now(timezone.utc)
    start_date = end_date - timedelta(days=1)
    pub_start  = start_date.strftime("%Y-%m-%dT%H:%M:%S.000+00:00")
    pub_end    = end_date.strftime("%Y-%m-%dT%H:%M:%S.000+00:00")

    headers = {"User-Agent": "CVE-Dashboard/1.0"}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY

    new_cves = []
    try:
        params = {
            "pubStartDate":   pub_start,
            "pubEndDate":     pub_end,
            "resultsPerPage": 2000,
        }
        resp = requests.get(NVD_API_URL, params=params, headers=headers, timeout=60)
        if resp.status_code != 200:
            print(f"❌ NVD API returned {resp.status_code}")
            return

        vulnerabilities = resp.json().get("vulnerabilities", [])
        print(f"📥 NVD returned {len(vulnerabilities)} CVEs for last 24 h")

        conn   = sqlite3.connect(DB)
        cursor = conn.cursor()

        for item in vulnerabilities:
            cve_data = item.get("cve", {})
            cve_id   = cve_data.get("id", "")
            if not cve_id:
                continue

            descs = cve_data.get("descriptions", [])
            desc  = next((d["value"] for d in descs if d.get("lang") == "en"), "")

            metrics = cve_data.get("metrics", {})
            cvss    = None
            for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                if key in metrics and metrics[key]:
                    try:
                        cvss = float(metrics[key][0]["cvssData"]["baseScore"])
                    except Exception:
                        pass
                    break

            published = cve_data.get("published", "")[:10]
            companies = extract_affected_companies(desc)

            cursor.execute("SELECT cve_id FROM cves WHERE cve_id = ?", (cve_id,))
            if not cursor.fetchone():
                cursor.execute(
                    "INSERT INTO cves (cve_id, description, cvss_score, published) VALUES (?,?,?,?)",
                    (cve_id, desc, cvss, published)
                )
                new_cves.append({
                    "cve_id":    cve_id,
                    "description": desc,
                    "cvss_score":  cvss,
                    "severity":    calculate_severity(cvss),
                    "published":   published,
                    "companies":   companies,
                })
                print(f"   🆕 {cve_id}")

        conn.commit()
        conn.close()

        if new_cves and postgres_pool:
            update_cve_tracking(new_cves)

        if new_cves:
            check_boms_and_send_alerts(new_cves)

        # ✅ Record successful update time
        set_last_update_time(datetime.now(timezone.utc))

        print(f"✅ Daily update done — {len(new_cves)} new CVEs added")

    except Exception as e:
        print(f"❌ Daily update error: {e}")
        import traceback; traceback.print_exc()


def update_cve_tracking(new_cves: list):
    try:
        conn = postgres_pool.getconn()
        cur  = conn.cursor()
        for cve in new_cves:
            cur.execute("""
                INSERT INTO cve_tracking
                    (cve_id, first_seen_date, is_new, cvss_score, severity,
                     description, published_date, affected_companies)
                VALUES (%s, CURRENT_TIMESTAMP, TRUE, %s, %s, %s, %s, %s)
                ON CONFLICT (cve_id) DO NOTHING
            """, (
                cve["cve_id"], cve["cvss_score"], cve["severity"],
                cve["description"], cve["published"], Json(cve["companies"])
            ))
        conn.commit()
        cur.close()
        postgres_pool.putconn(conn)
    except Exception as e:
        print(f"❌ cve_tracking update error: {e}")


def check_boms_and_send_alerts(new_cves: list):
    if not ENV_BOMS:
        return
    print(f"   Checking {len(ENV_BOMS)} BOM(s)…")
    for bom in ENV_BOMS:
        matches = []
        for cve in new_cves:
            desc_lower = (cve["description"] or "").lower()
            for keyword in bom['keywords']:
                if keyword.lower() in desc_lower:
                    matches.append({"cve": cve, "keyword": keyword})
                    break

        if matches:
            if postgres_pool:
                try:
                    conn = postgres_pool.getconn()
                    cur  = conn.cursor()
                    for match in matches:
                        cur.execute("""
                            INSERT INTO alert_history (email, cve_id, bom_name, matched_keyword)
                            VALUES (%s, %s, %s, %s)
                        """, (bom['email'], match['cve']['cve_id'], bom['name'], match['keyword']))
                    conn.commit()
                    cur.close()
                    postgres_pool.putconn(conn)
                except Exception as e:
                    print(f"   ⚠️  alert_history write error: {e}")

            send_bom_alert(bom['email'], bom['name'], bom['keywords'], matches)
            print(f"   📧 {bom['name']}: {len(matches)} alert(s) → {bom['email']}")

# ============================================================
# SCHEDULER
# ============================================================

def run_scheduler():
    while True:
        schedule.run_pending()
        time.sleep(60)

schedule.every().day.at("02:00").do(fetch_new_cves_from_nvd)

scheduler_thread = threading.Thread(target=run_scheduler, daemon=True)
scheduler_thread.start()
print("⏰ Scheduler started — daily CVE update at 02:00 UTC")

# ============================================================
# RATE LIMITING
# ============================================================

_rate_lock = threading.Lock()
_request_log: dict = {}

def _is_rate_limited(ip: str, max_req: int = 60, window: int = 60) -> bool:
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
    ip = request.remote_addr or "unknown"
    if request.path in ('/api/nvd-update', '/api/nvd-status', '/admin/update-db'):
        return
    if request.path.startswith('/admin'):
        limit = 20
    elif request.path.startswith('/api/ai-analyze'):
        limit = 120
    elif request.path.startswith('/api/'):
        limit = 2000
    else:
        limit = 80
    if _is_rate_limited(ip, max_req=limit, window=60):
        return jsonify({"error": "Too many requests. Please slow down."}), 429
    bad_patterns = ['../', '.env', 'wp-admin', 'phpmyadmin', '.git', 'etc/passwd']
    if any(p in request.path.lower() for p in bad_patterns):
        abort(404)

@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options']        = 'SAMEORIGIN'
    response.headers['X-XSS-Protection']       = '1; mode=block'
    response.headers['Referrer-Policy']        = 'strict-origin-when-cross-origin'
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
# CSRF / URL HELPERS
# ============================================================

def _obfuscate(text: str) -> str:
    import base64
    return base64.urlsafe_b64encode(text.encode()).decode().rstrip("=")

def _deobfuscate(token: str) -> str:
    import base64
    padding = 4 - len(token) % 4
    if padding != 4:
        token += "=" * padding
    try:
        return base64.urlsafe_b64decode(token).decode()
    except Exception:
        return token

def generate_csrf_token() -> str:
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(24)
    return session["csrf_token"]

def validate_csrf(token: str) -> bool:
    return secrets.compare_digest(session.get("csrf_token", ""), token or "")

@app.context_processor
def inject_csrf():
    return {"csrf_token": generate_csrf_token()}

# ============================================================
# AI CONFIGURATION
# ============================================================

def get_ai_config():
    provider = session.get("ai_provider", DEFAULT_AI_PROVIDER)
    api_key  = session.get("ai_api_key",  "")
    model    = session.get("ai_model",    "")
    if provider == "deepseek":
        api_key = api_key or os.environ.get("DEEPSEEK_API_KEY",  "")
        model   = model   or DEEPSEEK_MODEL
    elif provider == "openai":
        api_key = api_key or os.environ.get("OPENAI_API_KEY",    "")
        model   = model   or OPENAI_MODEL
    elif provider == "claude":
        api_key = api_key or os.environ.get("ANTHROPIC_API_KEY", "")
        model   = model   or CLAUDE_MODEL
    elif provider == "ollama":
        api_key = "ollama"
        model   = model or OLLAMA_MODEL
    return provider, api_key, model

# ============================================================
# DATABASE INIT
# ============================================================

def init_database():
    try:
        conn   = sqlite3.connect(DB)
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS cves (
                cve_id TEXT PRIMARY KEY,
                description TEXT,
                cvss_score REAL,
                severity TEXT,
                published TEXT,
                last_modified TEXT,
                "references" TEXT,
                cwe_id TEXT
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS cve_ai_analysis (
                cve_id TEXT PRIMARY KEY,
                summary TEXT,
                affected_companies TEXT,
                remediation TEXT,
                affected_version TEXT,
                fixed_version TEXT,
                fix_status TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS ai_cache (
                cache_key TEXT PRIMARY KEY,
                response TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        for idx_sql in [
            "CREATE INDEX IF NOT EXISTS idx_cves_published   ON cves(published DESC)",
            "CREATE INDEX IF NOT EXISTS idx_cves_cvss_score  ON cves(cvss_score)",
            "CREATE INDEX IF NOT EXISTS idx_ai_fix_status    ON cve_ai_analysis(fix_status)",
        ]:
            try:
                cursor.execute(idx_sql)
            except Exception as e:
                print(f"⚠️  Index warning: {e}")
        conn.commit()
        conn.close()
        print("✅ SQLite database initialised")
        return True
    except Exception as e:
        print(f"⚠️  SQLite init error: {e}")
        return False

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

# ============================================================
# UTILITY
# ============================================================

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

KNOWN_VENDORS = [
    "Microsoft","Apple","Google","Amazon","Meta","Facebook","Twitter",
    "Linux","Windows","Adobe","Oracle","IBM","Intel","AMD","NVIDIA",
    "Cisco","Dell","HP","Lenovo","Samsung","Sony","Tenda","TP-Link",
    "D-Link","Netgear","Asus","Linksys","Bosch","Alps Alpine","Harman",
    "Nissan","Tesla","Ford","Toyota","Honda","Volkswagen","BMW","Mercedes",
    "Qualcomm","MediaTek","Broadcom","Texas Instruments","Infineon",
    "STMicroelectronics","Renesas","NXP","Microchip","Analog Devices",
    "Apache","Nginx","Red Hat","Canonical","Ubuntu","Debian","Fedora",
    "SUSE","VMware","Docker","Kubernetes","GitHub","GitLab","Atlassian",
    "WordPress","Drupal","Joomla","Magento","Shopify","WooCommerce",
    "Siemens","Schneider","Rockwell","Honeywell","ABB","Mitsubishi",
]

def extract_affected_companies(description: str) -> list:
    dl    = description.lower()
    found = [v for v in KNOWN_VENDORS if v.lower() in dl]
    return found

# ============================================================
# RULE-BASED HELPERS
# ============================================================

def _rule_based_fix_status(description: str) -> str:
    d = description.lower()
    if any(t in d for t in ["fixed in","patched in","update to","upgrade to"]):
        return "Fix Available"
    if any(t in d for t in ["no fix","unpatched","no patch"]):
        return "Not Fixed"
    if any(t in d for t in ["workaround","mitigation"]):
        return "Workaround Available"
    return "Unknown"

def _rule_based_remediation(description: str, cve_id: str = "") -> str:
    d = description.lower()
    if "update" in d or "upgrade" in d:
        return "Upgrade to the latest patched version immediately."
    if "workaround" in d or "disable" in d:
        return "Apply vendor-recommended workaround until patch is available."
    if "patch" in d or "fix" in d:
        return "Apply the available security patch as soon as possible."
    return f"Check https://nvd.nist.gov/vuln/detail/{cve_id} for vendor advisories."

# ============================================================
# ENRICH ROW
# ============================================================

def _enrich_row(row_dict, use_ai=False):
    row_dict["severity"]           = calculate_severity(row_dict.get("cvss_score"))
    row_dict["published_date"]     = row_dict.get(DATE_COLUMN, "N/A")
    row_dict.setdefault("ai_summary",        None)
    row_dict.setdefault("affected_companies", [])
    row_dict.setdefault("remediation",        None)
    row_dict.setdefault("affected_version",  "Unknown")
    row_dict.setdefault("fixed_version",     "Unknown")
    row_dict.setdefault("fix_status",        "Unknown")
    row_dict.setdefault("matched_keywords",  [])

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
            row_dict["ai_summary"]        = ai_row[0]
            row_dict["affected_companies"] = companies
            row_dict["remediation"]        = ai_row[2] or ""
            row_dict["affected_version"]   = ai_row[3] or "Unknown"
            row_dict["fixed_version"]      = ai_row[4] or "Unknown"
            row_dict["fix_status"]         = ai_row[5] or "Unknown"
            return row_dict
    except Exception as e:
        print(f"⚠️  DB cache read error for {row_dict.get('cve_id')}: {e}")

    row_dict["affected_companies"] = extract_affected_companies(row_dict.get("description",""))
    row_dict["fix_status"]         = _rule_based_fix_status(row_dict.get("description",""))
    row_dict["remediation"]        = _rule_based_remediation(row_dict.get("description",""), row_dict.get("cve_id",""))
    return row_dict

# ============================================================
# CVE SEARCH
# ============================================================

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
    if severity_filter == "Critical":
        query += " AND cvss_score >= 9.0"
    elif severity_filter == "High":
        query += " AND cvss_score >= 7.0 AND cvss_score < 9.0"
    elif severity_filter == "Medium":
        query += " AND cvss_score >= 4.0 AND cvss_score < 7.0"
    elif severity_filter == "Low":
        query += " AND cvss_score > 0 AND cvss_score < 4.0"

    count_q = query.replace("SELECT *", "SELECT COUNT(*) as count")
    cursor.execute(count_q, params)
    result = cursor.fetchone()
    total  = result['count'] if result else 0

    query += f" ORDER BY {DATE_COLUMN} DESC LIMIT ? OFFSET ?"
    params.extend([per_page, (page - 1) * per_page])
    try:
        cursor.execute(query, params)
    except sqlite3.OperationalError:
        query = query.replace(f" ORDER BY {DATE_COLUMN} DESC", "")
        cursor.execute(query, params)
    rows = cursor.fetchall()
    conn.close()

    cves = []
    for row in rows:
        rd = dict(row)
        dl = (rd.get("description") or "").lower()
        rd["matched_keywords"] = [kw for kw in keywords if kw.lower() in dl]
        rd = _enrich_row(rd, use_ai=use_ai)
        cves.append(rd)
    return cves, total

# ============================================================
# ROUTES — STATS
# ============================================================

@app.route("/stats")
def stats():
    try:
        conn   = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM cves")
        total    = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM cves WHERE cvss_score >= 9.0")
        critical = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM cves WHERE cvss_score >= 7.0 AND cvss_score < 9.0")
        high     = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM cves WHERE cvss_score >= 4.0 AND cvss_score < 7.0")
        medium   = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM cves WHERE cvss_score > 0 AND cvss_score < 4.0")
        low      = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM cve_ai_analysis")
        ai_count = cursor.fetchone()[0]
        cursor.execute("SELECT MIN(published), MAX(published) FROM cves")
        row    = cursor.fetchone()
        oldest = row[0] if row else None
        newest = row[1] if row else None

        # NEW in last 7 days — try PostgreSQL first, fall back to SQLite published date
        new_7_days = 0
        if postgres_pool:
            try:
                pg_conn = postgres_pool.getconn()
                pg_cur  = pg_conn.cursor()
                pg_cur.execute("""
                    SELECT COUNT(*) FROM cve_tracking
                    WHERE first_seen_date >= NOW() - INTERVAL '7 days'
                """)
                new_7_days = pg_cur.fetchone()[0]
                pg_cur.close()
                postgres_pool.putconn(pg_conn)
            except Exception:
                pass

        # Fallback: count by published date in SQLite
        if new_7_days == 0:
            try:
                cursor.execute("""
                    SELECT COUNT(*) FROM cves
                    WHERE julianday('now') - julianday(published) <= 7
                """)
                new_7_days = cursor.fetchone()[0]
            except Exception:
                pass

        conn.close()

        date_range = "No data"
        if oldest and newest:
            date_range = f"{oldest[:10]} – {newest[:10]}"

        # Last update time
        last_update = get_last_update_time()
        last_update_str = None
        if last_update:
            # Format in user-friendly way: "Mar 10, 2026, 05:44 PM"
            last_update_str = last_update.strftime("%b %d, %Y, %I:%M %p UTC").replace(" 0", " ")

        return jsonify({
            "total_cves":    total,
            "critical":      critical,
            "high":          high,
            "medium":        medium,
            "low":           low,
            "ai_enhanced":   ai_count,
            "oldest_cve":    oldest,
            "newest_cve":    newest,
            "date_range":    date_range,
            "new_7_days":    new_7_days,
            "last_update":   last_update_str,
        })
    except Exception as e:
        print(f"❌ /stats error: {e}")
        return jsonify({"total_cves":0,"critical":0,"high":0,"medium":0,"low":0,
                        "ai_enhanced":0,"oldest_cve":None,"newest_cve":None,
                        "date_range":"Error","new_7_days":0,"last_update":None})


@app.route("/keyword-stats")
def keyword_stats():
    """Severity counts optionally filtered by keywords."""
    keywords_raw = request.args.get("keywords", "")
    severity     = request.args.get("severity", "")
    keywords     = [k.strip() for k in keywords_raw.split(',') if k.strip()] if keywords_raw else []

    try:
        conn   = get_db_connection()
        cursor = conn.cursor()

        base_where = ""
        params     = []

        if keywords:
            conds = ["description LIKE ?" for _ in keywords]
            base_where = "WHERE (" + " OR ".join(conds) + ")"
            params     = [f"%{kw}%" for kw in keywords]
            if severity == "Critical":
                base_where += " AND cvss_score >= 9.0"
            elif severity == "High":
                base_where += " AND cvss_score >= 7.0 AND cvss_score < 9.0"
            elif severity == "Medium":
                base_where += " AND cvss_score >= 4.0 AND cvss_score < 7.0"
            elif severity == "Low":
                base_where += " AND cvss_score > 0 AND cvss_score < 4.0"

        cursor.execute(f"SELECT COUNT(*) FROM cves {base_where}", params)
        total = cursor.fetchone()[0]

        p = params.copy()
        cursor.execute(
            f"SELECT COUNT(*) FROM cves {base_where} {'AND' if base_where else 'WHERE'} cvss_score >= 9.0",
            p + ([] if not base_where.endswith("9.0") else [])
        )
        # Simpler approach: run 4 separate filtered queries
        def sev_count(min_s, max_s):
            if base_where:
                q = f"SELECT COUNT(*) FROM cves {base_where} AND cvss_score >= ? AND cvss_score < ?"
            else:
                q = "SELECT COUNT(*) FROM cves WHERE cvss_score >= ? AND cvss_score < ?"
            cursor.execute(q, params + [min_s, max_s])
            return cursor.fetchone()[0]

        def sev_count_ge(min_s):
            if base_where:
                q = f"SELECT COUNT(*) FROM cves {base_where} AND cvss_score >= ?"
            else:
                q = "SELECT COUNT(*) FROM cves WHERE cvss_score >= ?"
            cursor.execute(q, params + [min_s])
            return cursor.fetchone()[0]

        def sev_count_range(min_s, max_s, gt=False):
            op = ">" if gt else ">="
            if base_where:
                q = f"SELECT COUNT(*) FROM cves {base_where} AND cvss_score {op} ? AND cvss_score < ?"
            else:
                q = f"SELECT COUNT(*) FROM cves WHERE cvss_score {op} ? AND cvss_score < ?"
            cursor.execute(q, params + [min_s, max_s])
            return cursor.fetchone()[0]

        critical = sev_count_ge(9.0) if not keywords else sev_count_range(9.0, 99.9)
        # recompute properly
        crit_q  = (f"SELECT COUNT(*) FROM cves {base_where} {'AND' if base_where else 'WHERE'} cvss_score >= 9.0") if base_where else "SELECT COUNT(*) FROM cves WHERE cvss_score >= 9.0"
        high_q  = (f"SELECT COUNT(*) FROM cves {base_where} {'AND' if base_where else 'WHERE'} cvss_score >= 7.0 AND cvss_score < 9.0") if base_where else "SELECT COUNT(*) FROM cves WHERE cvss_score >= 7.0 AND cvss_score < 9.0"
        med_q   = (f"SELECT COUNT(*) FROM cves {base_where} {'AND' if base_where else 'WHERE'} cvss_score >= 4.0 AND cvss_score < 7.0") if base_where else "SELECT COUNT(*) FROM cves WHERE cvss_score >= 4.0 AND cvss_score < 7.0"
        low_q   = (f"SELECT COUNT(*) FROM cves {base_where} {'AND' if base_where else 'WHERE'} cvss_score > 0 AND cvss_score < 4.0") if base_where else "SELECT COUNT(*) FROM cves WHERE cvss_score > 0 AND cvss_score < 4.0"

        cursor.execute(crit_q, params); critical = cursor.fetchone()[0]
        cursor.execute(high_q, params); high     = cursor.fetchone()[0]
        cursor.execute(med_q,  params); medium   = cursor.fetchone()[0]
        cursor.execute(low_q,  params); low      = cursor.fetchone()[0]
        conn.close()

        return jsonify({
            "total":    total,
            "critical": critical,
            "high":     high,
            "medium":   medium,
            "low":      low,
            "filtered": bool(keywords),
        })
    except Exception as e:
        print(f"❌ /keyword-stats error: {e}")
        return jsonify({"total":0,"critical":0,"high":0,"medium":0,"low":0,"filtered":False})


@app.route("/keyword-counts")
def keyword_counts():
    """Return per-keyword total CVE counts."""
    keywords_raw = request.args.get("keywords", "")
    severity     = request.args.get("severity", "")
    keywords     = [k.strip() for k in keywords_raw.split(',') if k.strip()]
    counts       = {}
    if not keywords:
        return jsonify(counts)
    try:
        conn   = sqlite3.connect(DB)
        cursor = conn.cursor()
        for kw in keywords:
            sev_clause = ""
            if severity == "Critical":
                sev_clause = " AND cvss_score >= 9.0"
            elif severity == "High":
                sev_clause = " AND cvss_score >= 7.0 AND cvss_score < 9.0"
            elif severity == "Medium":
                sev_clause = " AND cvss_score >= 4.0 AND cvss_score < 7.0"
            elif severity == "Low":
                sev_clause = " AND cvss_score > 0 AND cvss_score < 4.0"
            cursor.execute(
                f"SELECT COUNT(*) FROM cves WHERE LOWER(description) LIKE ?{sev_clause}",
                (f"%{kw.lower()}%",)
            )
            counts[kw] = cursor.fetchone()[0]
        conn.close()
    except Exception as e:
        print(f"❌ /keyword-counts error: {e}")
    return jsonify(counts)

# ============================================================
# ROUTES — MAIN SEARCH + INDEX
# ============================================================

@app.route("/search", methods=["POST"])
def search_post():
    keyword      = request.form.get("keyword", "").strip()
    keywords_text = request.form.get("keywords", "")
    severity_filter = request.form.get("severity") or request.form.get("severity_multi") or request.form.get("severity_bom") or ""
    use_ai = request.form.get("use_ai", "false") == "true"
    tab    = request.form.get("tab", "single")

    if keywords_text:
        keywords = [k.strip() for k in keywords_text.split("\n") if k.strip()]
        kw_enc   = _obfuscate(",".join(keywords[:20]))
    elif keyword:
        kw_enc   = _obfuscate(keyword)
    else:
        return redirect(url_for("index"))

    sev_enc = _obfuscate(severity_filter) if severity_filter else ""
    return redirect(url_for("index",
        kw=kw_enc, sv=sev_enc,
        use_ai="true" if use_ai else "false",
        tab=tab, page=1))


@app.route("/", methods=["GET"])
def index():
    kw_enc          = request.args.get("kw", "")
    sv_enc          = request.args.get("sv", "")
    keywords_param  = _deobfuscate(kw_enc) if kw_enc else request.args.get("keywords", "")
    severity_filter = _deobfuscate(sv_enc) if sv_enc else request.args.get("severity", "")
    keyword         = request.args.get("keyword", "")
    page            = int(request.args.get("page", 1))
    use_ai          = request.args.get("use_ai", "false") in ("true", "1")

    try:
        if keywords_param:
            keywords = [k.strip() for k in keywords_param.split(',') if k.strip()]
            cves, total = search_cves_by_keywords(keywords, severity_filter, page, use_ai=use_ai)
            active_keywords = keywords
        elif keyword:
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
            total = len(cves)

        # Mark new CVEs from PostgreSQL tracking
        if postgres_pool and cves:
            try:
                conn = postgres_pool.getconn()
                cur  = conn.cursor()
                cur.execute("""
                    SELECT cve_id FROM cve_tracking
                    WHERE first_seen_date > NOW() - INTERVAL '7 days' AND is_new = TRUE
                """)
                new_set = {r[0] for r in cur.fetchall()}
                for cve in cves:
                    cve['is_new'] = cve['cve_id'] in new_set
                cur.close()
                postgres_pool.putconn(conn)
            except Exception:
                pass

        total_pages = max(1, (total // 50) + (1 if total % 50 > 0 else 0))

        return render_template(
            "index.html",
            view="dashboard",
            cves=cves,
            keyword=keyword,
            severity_filter=severity_filter,
            active_keywords=active_keywords,
            page=page,
            total_pages=total_pages,
            use_ai=use_ai,
            env_boms=ENV_BOMS,
        )
    except Exception as e:
        print(f"❌ index error: {e}")
        import traceback; traceback.print_exc()
        return render_template(
            "index.html",
            view="dashboard",
            cves=[], keyword=keyword, severity_filter=severity_filter,
            active_keywords=[], page=1, total_pages=1,
            use_ai=use_ai, env_boms=ENV_BOMS,
        )

# ============================================================
# ROUTES — BOM UPLOAD
# ============================================================

def _parse_bom_file(file) -> list:
    """Extract keyword list from an uploaded BOM file."""
    filename  = secure_filename(file.filename)
    ext       = filename.rsplit('.', 1)[-1].lower()
    keywords  = []

    if ext == 'txt':
        text = file.read().decode('utf-8', errors='ignore')
        keywords = [line.strip() for line in text.splitlines() if line.strip()]

    elif ext == 'csv':
        text   = file.read().decode('utf-8', errors='ignore')
        reader = csv.reader(io.StringIO(text))
        for row in reader:
            for cell in row:
                val = cell.strip()
                if val:
                    keywords.append(val)

    elif ext in ('xlsx', 'xls'):
        import openpyxl
        wb = openpyxl.load_workbook(io.BytesIO(file.read()), read_only=True, data_only=True)
        for sheet in wb.worksheets:
            for row in sheet.iter_rows(values_only=True):
                for cell in row:
                    if cell:
                        keywords.append(str(cell).strip())
        wb.close()

    elif ext == 'json':
        data = json.loads(file.read().decode('utf-8', errors='ignore'))
        if isinstance(data, list):
            for item in data:
                if isinstance(item, str):
                    keywords.append(item.strip())
                elif isinstance(item, dict):
                    for v in item.values():
                        keywords.append(str(v).strip())
        elif isinstance(data, dict):
            for v in data.values():
                keywords.append(str(v).strip())

    elif ext == 'xml':
        root = ET.fromstring(file.read().decode('utf-8', errors='ignore'))
        for elem in root.iter():
            if elem.text and elem.text.strip():
                keywords.append(elem.text.strip())

    return [k for k in keywords if k and len(k) > 1][:200]


@app.route("/upload-bom", methods=["POST"])
def upload_bom():
    if 'bom_file' not in request.files:
        return redirect(url_for('index', error='No file uploaded'))
    f = request.files['bom_file']
    if not f or not allowed_file(f.filename):
        return redirect(url_for('index', error='Invalid file type'))

    severity = request.form.get('severity_bom', '')
    use_ai   = request.form.get('use_ai_bom', 'false') == 'true'

    try:
        keywords = _parse_bom_file(f)
        if not keywords:
            return redirect(url_for('index', error='No keywords found in file'))
        kw_enc  = _obfuscate(",".join(keywords))
        sev_enc = _obfuscate(severity) if severity else ""
        return redirect(url_for('index',
            kw=kw_enc, sv=sev_enc,
            use_ai="true" if use_ai else "false",
            tab="bom", page=1))
    except Exception as e:
        print(f"❌ BOM upload error: {e}")
        return redirect(url_for('index', error=f'Parse error: {str(e)}'))

# ============================================================
# ROUTES — EXPORT
# ============================================================

@app.route("/export")
def export_csv():
    keywords_raw    = request.args.get("keywords", "")
    severity_filter = request.args.get("severity", "")
    keywords        = [k.strip() for k in keywords_raw.split(',') if k.strip()]
    if not keywords:
        return "No keywords specified", 400

    cves, _ = search_cves_by_keywords(keywords, severity_filter, page=1, per_page=5000)
    output  = io.StringIO()
    writer  = csv.DictWriter(output, fieldnames=[
        "cve_id","cvss_score","severity","published",
        "fix_status","affected_version","fixed_version",
        "affected_companies","matched_keywords","description"
    ])
    writer.writeheader()
    for cve in cves:
        writer.writerow({
            "cve_id":            cve.get("cve_id",""),
            "cvss_score":        cve.get("cvss_score",""),
            "severity":          cve.get("severity",""),
            "published":         cve.get("published",""),
            "fix_status":        cve.get("fix_status",""),
            "affected_version":  cve.get("affected_version",""),
            "fixed_version":     cve.get("fixed_version",""),
            "affected_companies":";".join(cve.get("affected_companies") or []),
            "matched_keywords":  ";".join(cve.get("matched_keywords") or []),
            "description":       (cve.get("description") or "")[:500],
        })

    output.seek(0)
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition":
                 f"attachment; filename=cve_export_{datetime.now().strftime('%Y%m%d_%H%M')}.csv"}
    )

# ============================================================
# ROUTES — AI ANALYSIS
# ============================================================

def _call_ai_api(provider: str, api_key: str, model: str, prompt: str) -> str | None:
    try:
        if provider == "ollama":
            resp = requests.post(OLLAMA_URL, json={"model": model, "prompt": prompt, "stream": False}, timeout=30)
            if resp.status_code == 200:
                return resp.json().get("response","")
            return None

        if provider == "claude":
            headers = {
                "x-api-key": api_key,
                "anthropic-version": "2023-06-01",
                "Content-Type": "application/json",
            }
            payload = {"model": model, "max_tokens": 512,
                       "messages": [{"role":"user","content": prompt}]}
            resp = requests.post(CLAUDE_API_URL, json=payload, headers=headers, timeout=30)
            if resp.status_code == 200:
                return resp.json()["content"][0]["text"]
            return None

        # OpenAI / DeepSeek compatible
        url     = DEEPSEEK_API_URL if provider == "deepseek" else OPENAI_API_URL
        headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
        payload = {"model": model, "max_tokens": 512,
                   "messages": [{"role":"user","content": prompt}]}
        resp = requests.post(url, json=payload, headers=headers, timeout=30)
        if resp.status_code == 200:
            return resp.json()["choices"][0]["message"]["content"]
        return None
    except Exception as e:
        print(f"⚠️  AI call error ({provider}): {e}")
        return None


def _ai_analyse_one(cve_id: str, description: str, provider: str, api_key: str, model: str) -> dict:
    prompt = f"""Analyse this CVE briefly and return JSON only (no markdown).

CVE: {cve_id}
Description: {description[:800]}

Return ONLY valid JSON with these keys:
{{
  "summary": "2-3 sentence plain English summary",
  "affected_version": "affected version string or Unknown",
  "fixed_version": "fixed version or Unknown",
  "fix_status": "Fix Available|Not Fixed|Workaround Available|Unknown",
  "remediation": "1-2 sentence actionable advice"
}}"""

    cache_key = hashlib.md5(f"{provider}{model}{cve_id}".encode()).hexdigest()
    try:
        conn = sqlite3.connect(DB)
        cur  = conn.cursor()
        cur.execute("SELECT response FROM ai_cache WHERE cache_key = ?", (cache_key,))
        row  = cur.fetchone()
        conn.close()
        if row:
            return json.loads(row[0])
    except Exception:
        pass

    raw = _call_ai_api(provider, api_key, model, prompt)
    if not raw:
        return {"error": "AI call failed"}

    # Strip markdown fences if present
    raw = re.sub(r"```json|```", "", raw).strip()
    try:
        data = json.loads(raw)
    except Exception:
        # Try to extract JSON object
        m = re.search(r"\{.*\}", raw, re.DOTALL)
        if m:
            try:
                data = json.loads(m.group())
            except Exception:
                return {"error": "JSON parse failed"}
        else:
            return {"error": "No JSON found"}

    # Persist to SQLite cache + ai_analysis table
    try:
        conn = sqlite3.connect(DB)
        cur  = conn.cursor()
        cur.execute(
            "INSERT OR REPLACE INTO ai_cache (cache_key, response) VALUES (?,?)",
            (cache_key, json.dumps(data))
        )
        cur.execute("""
            INSERT OR REPLACE INTO cve_ai_analysis
                (cve_id, summary, affected_companies, remediation,
                 affected_version, fixed_version, fix_status)
            VALUES (?,?,?,?,?,?,?)
        """, (
            cve_id,
            data.get("summary",""),
            json.dumps([]),
            data.get("remediation",""),
            data.get("affected_version","Unknown"),
            data.get("fixed_version","Unknown"),
            data.get("fix_status","Unknown"),
        ))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"⚠️  AI cache write error: {e}")

    return data


@app.route("/api/ai-analyze", methods=["POST"])
def ai_analyze():
    provider, api_key, model = get_ai_config()
    if not api_key or (provider != "ollama" and len(api_key) < 8):
        return jsonify({"error": "No API key configured"}), 400

    payload = request.get_json(silent=True) or {}
    cves    = payload.get("cves", [])
    if not cves:
        return jsonify({}), 400

    results = {}
    for item in cves[:10]:          # cap per request
        cve_id = item.get("cve_id","")
        desc   = item.get("description","")
        if cve_id:
            results[cve_id] = _ai_analyse_one(cve_id, desc, provider, api_key, model)

    return jsonify(results)


@app.route("/api/ai-status")
def ai_status():
    provider, api_key, model = get_ai_config()
    has_key = bool(api_key and len(api_key) > 8)
    return jsonify({
        "ai_enabled": USE_AI,
        "has_key":    has_key,
        "provider":   provider,
        "model":      model,
    })

# ============================================================
# ROUTES — SETTINGS
# ============================================================

@app.route("/settings/save", methods=["POST"])
def settings_save():
    data     = request.get_json(silent=True) or {}
    provider = data.get("provider", DEFAULT_AI_PROVIDER)
    api_key  = data.get("api_key", "").strip()
    model    = data.get("model", "")

    if provider not in PROVIDER_INFO:
        return jsonify({"ok": False, "message": "Unknown provider"})
    if provider != "ollama" and not api_key:
        return jsonify({"ok": False, "message": "API key required"})

    session["ai_provider"] = provider
    session["ai_api_key"]  = api_key
    session["ai_model"]    = model
    session.permanent      = True

    # Quick connectivity test
    test_prompt = "Reply with the word PONG only."
    result      = _call_ai_api(provider, api_key, model or PROVIDER_INFO[provider]["models"][0], test_prompt)
    if result is None:
        return jsonify({"ok": False, "message": "Key saved but test call failed — check key/model"})
    return jsonify({"ok": True, "message": f"Connected to {PROVIDER_INFO[provider]['name']} ✓"})


@app.route("/settings", methods=["GET"])
def settings_page():
    provider, api_key, model = get_ai_config()
    return render_template("settings.html",
                           provider=provider, model=model,
                           has_key=bool(api_key),
                           providers=PROVIDER_INFO)

# ============================================================
# ROUTES — MANUAL DB UPDATE (admin)
# ============================================================

@app.route("/update-cve", methods=["GET", "POST"])
def update_cve():
    """Trigger a manual NVD update. GET shows confirmation page, POST runs it."""
    if request.method == "GET" and not session.get("admin_logged_in"):
        csrf = generate_csrf_token()
        return f"""<!DOCTYPE html>
<html><head>
<meta charset="UTF-8">
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body class="bg-light d-flex align-items-center justify-content-center" style="min-height:100vh;">
<div class="card shadow" style="max-width:480px;width:100%;">
  <div class="card-body p-4 text-center">
    <h4 class="mb-3"><i class="bi bi-cloud-arrow-down text-primary"></i> Manual CVE Update</h4>
    <p class="text-muted mb-4">
      Fetches CVEs published in the last 24 hours from the NVD API,
      updates the local database, and sends BOM alert emails if matches are found.
    </p>
    <form method="post">
      <input type="hidden" name="csrf_token" value="{csrf}">
      <button type="submit" class="btn btn-primary btn-lg px-5">
        ▶ Run Update Now
      </button>
    </form>
    <p class="text-muted mt-3" style="font-size:.8rem;">
      Scheduled: automatically runs at 02:00 UTC every day
    </p>
    <a href="/" class="btn btn-sm btn-outline-secondary mt-2">← Back to Dashboard</a>
  </div>
</div>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css">
</body></html>"""

    # POST or admin: run update in background thread
    def _run():
        fetch_new_cves_from_nvd()

    t = threading.Thread(target=_run, daemon=True)
    t.start()

    # If it's an AJAX / JSON request return JSON; otherwise redirect to dashboard
    if request.headers.get('Accept','').startswith('application/json') or \
       request.headers.get('Content-Type','') == 'application/json':
        return jsonify({"status": "Update started", "started_at": datetime.utcnow().isoformat()})

    return redirect(url_for('index') + '?update=started')

# ============================================================
# ROUTES — ADMIN
# ============================================================

@app.route("/admin", methods=["GET", "POST"])
def admin():
    login_error = None

    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            session["admin_logged_in"] = True
            session.permanent = True
        else:
            login_error = "Invalid username or password"

    if not session.get("admin_logged_in"):
        return render_template("index.html",
                               view="admin_login",
                               login_error=login_error,
                               csrf_token=generate_csrf_token(),
                               cves=[], active_keywords=[], keyword=None,
                               severity_filter="", use_ai=False,
                               total_pages=1, page=1, env_boms=ENV_BOMS)

    # Gather admin data
    db_size = os.path.getsize(DB) / (1024 * 1024) if os.path.exists(DB) else 0
    try:
        conn   = sqlite3.connect(DB)
        cur    = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM cves")
        total  = cur.fetchone()[0]
        cur.execute("SELECT MAX(published) FROM cves")
        latest = (cur.fetchone()[0] or "N/A")[:10]
        conn.close()
    except Exception:
        total  = 0
        latest = "N/A"

    recent_alerts = []
    if postgres_pool:
        try:
            conn = postgres_pool.getconn()
            cur  = conn.cursor()
            cur.execute("""
                SELECT email, cve_id, bom_name, matched_keyword, sent_at
                FROM alert_history ORDER BY sent_at DESC LIMIT 20
            """)
            recent_alerts = [
                {"email": r[0], "cve_id": r[1], "bom_name": r[2],
                 "keyword": r[3],
                 "sent_at": r[4].strftime("%Y-%m-%d %H:%M") if r[4] else ""}
                for r in cur.fetchall()
            ]
            cur.close()
            postgres_pool.putconn(conn)
        except Exception:
            pass

    scheduler_next = schedule.next_run().strftime("%Y-%m-%d %H:%M UTC") if schedule.next_run() else "N/A"

    return render_template("index.html",
                           view="admin",
                           db_size_mb=f"{db_size:.1f}",
                           total_cves=total,
                           latest_cve=latest,
                           env_boms=ENV_BOMS,
                           recent_alerts=recent_alerts,
                           scheduler_next=scheduler_next,
                           smtp_configured=bool(SMTP_USERNAME and SMTP_PASSWORD),
                           pg_connected=bool(postgres_pool),
                           csrf_token=generate_csrf_token(),
                           cves=[], active_keywords=[], keyword=None,
                           severity_filter="", use_ai=False,
                           total_pages=1, page=1)


@app.route("/admin/logout")
def admin_logout():
    session.pop("admin_logged_in", None)
    return redirect(url_for("admin"))


@app.route("/admin/trigger-update", methods=["POST"])
def admin_trigger_update():
    if not session.get("admin_logged_in"):
        abort(403)
    t = threading.Thread(target=fetch_new_cves_from_nvd, daemon=True)
    t.start()
    return jsonify({"status": "Update triggered", "time": datetime.utcnow().isoformat()})


@app.route("/admin/test-email", methods=["POST"])
def admin_test_email():
    if not session.get("admin_logged_in"):
        abort(403)
    data  = request.get_json(silent=True) or {}
    to    = data.get("email", SMTP_USERNAME)
    ok    = send_email_alert(to, "✅ CVE Dashboard — Test Email",
                             "<h2>Test email from CVE Monitoring Dashboard</h2>"
                             "<p>SMTP is configured correctly.</p>")
    return jsonify({"ok": ok})

# ============================================================
# ROUTES — BOMS API
# ============================================================

@app.route("/api/boms", methods=["GET"])
def get_boms():
    boms = []
    for bom in ENV_BOMS:
        entry = {
            "id":         f"env_{bom['id']}",
            "bom_name":   bom['name'],
            "email":      bom['email'],
            "keywords":   bom['keywords'],
            "created_at": None,
            "source":     "environment",
            "alerts_last_7_days": 0,
        }
        boms.append(entry)

    if postgres_pool:
        try:
            conn = postgres_pool.getconn()
            cur  = conn.cursor()
            for bom in boms:
                cur.execute("""
                    SELECT COUNT(*) FROM alert_history
                    WHERE email = %s AND sent_at > NOW() - INTERVAL '7 days'
                """, (bom['email'],))
                bom['alerts_last_7_days'] = cur.fetchone()[0]
            cur.close()
            postgres_pool.putconn(conn)
        except Exception as e:
            print(f"⚠️  BOM alert counts error: {e}")

    return jsonify(boms)


@app.route("/api/alerts/recent", methods=["GET"])
def get_recent_alerts():
    if not postgres_pool:
        return jsonify([])
    try:
        conn = postgres_pool.getconn()
        cur  = conn.cursor()
        cur.execute("""
            SELECT email, cve_id, matched_keyword, bom_name, sent_at
            FROM alert_history
            WHERE sent_at > NOW() - INTERVAL '24 hours'
            ORDER BY sent_at DESC LIMIT 20
        """)
        alerts = [
            {"email": r[0], "cve_id": r[1], "keyword": r[2],
             "bom_name": r[3], "sent_at": r[4].isoformat() if r[4] else None}
            for r in cur.fetchall()
        ]
        cur.close()
        postgres_pool.putconn(conn)
        return jsonify(alerts)
    except Exception as e:
        print(f"❌ /api/alerts/recent error: {e}")
        return jsonify([])

# ============================================================
# ROUTES — NVD MANUAL TRIGGER (lightweight API endpoint)
# ============================================================

@app.route("/api/nvd-update", methods=["POST"])
def api_nvd_update():
    """Lightweight endpoint for external cron triggers (e.g. Koyeb cron job)."""
    secret = request.headers.get("X-Update-Secret", "")
    expected = os.environ.get("UPDATE_SECRET", "")
    if expected and secret != expected:
        return jsonify({"error": "Unauthorized"}), 403
    t = threading.Thread(target=fetch_new_cves_from_nvd, daemon=True)
    t.start()
    return jsonify({"status": "started", "time": datetime.utcnow().isoformat()})


@app.route("/api/nvd-status")
def api_nvd_status():
    db_ok    = False
    db_count = 0
    try:
        conn = sqlite3.connect(DB)
        cur  = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM cves")
        db_count = cur.fetchone()[0]
        cur.close()
        conn.close()
        db_ok = True
    except Exception:
        pass
    return jsonify({
        "db_ok":      db_ok,
        "cve_count":  db_count,
        "pg_ok":      bool(postgres_pool),
        "bom_count":  len(ENV_BOMS),
        "smtp_ok":    bool(SMTP_USERNAME and SMTP_PASSWORD),
        "next_run":   schedule.next_run().isoformat() if schedule.next_run() else None,
        "time_utc":   datetime.utcnow().isoformat(),
    })

# ============================================================
# STARTUP
# ============================================================

init_database()
download_cve_from_github()
init_postgres()

if __name__ == "__main__":
    print("=" * 60)
    print("🚀  CVE Monitoring Dashboard")
    print("=" * 60)
    print(f"📁  SQLite DB  : {DB}")
    print(f"📦  GitHub     : {GITHUB_REPO} / {GITHUB_TAG}")
    print(f"🐘  PostgreSQL : {'✅ Connected' if postgres_pool else '❌ Not connected'}")
    print(f"📧  SMTP       : {SMTP_SERVER}:{SMTP_PORT} user={SMTP_USERNAME or '(not set)'}")
    print(f"📋  BOMs       : {len(ENV_BOMS)} loaded")
    print(f"⏰  Scheduler  : daily at 02:00 UTC")
    print("=" * 60)
    port = int(os.environ.get('PORT', 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
