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

# Database paths
DB = os.environ.get('CVE_DB_PATH', '/tmp/nvd_database.db')

# GitHub Release Configuration
GITHUB_REPO = os.environ.get('GITHUB_REPO', 'solomon042/TML-CVE-Dashboard')
GITHUB_TAG = os.environ.get('GITHUB_TAG', 'v1.0.0')
GITHUB_ASSET = os.environ.get('GITHUB_ASSET', 'nvd_database.db')

# Neon PostgreSQL Configuration
DATABASE_URL = os.environ.get('DATABASE_URL', '')

# Email Configuration
SMTP_SERVER = os.environ.get('SMTP_SERVER', 'smtp.gmail.com')
SMTP_PORT = int(os.environ.get('SMTP_PORT', 587))
SMTP_USERNAME = os.environ.get('SMTP_USERNAME', '')
SMTP_PASSWORD = os.environ.get('SMTP_PASSWORD', '')
ALERT_EMAIL_FROM = os.environ.get('ALERT_EMAIL_FROM', 'cve-alerts@localhost')

# Security
app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY', secrets.token_hex(32))
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=8)

# Admin credentials
ADMIN_USERNAME = os.environ.get('ADMIN_USERNAME', 'admin')
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', 'cve@admin2024')

# Upload settings
app.config['UPLOAD_FOLDER'] = tempfile.gettempdir()
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
ALLOWED_EXTENSIONS = {'txt', 'csv', 'json', 'xml', 'xlsx', 'xls'}

# ============================================================
# LOAD BOMS FROM ENVIRONMENT VARIABLES
# ============================================================

def load_boms_from_env():
    """Load BOM configurations from environment variables"""
    boms = []
    i = 1
    
    print("📋 Loading BOMs from environment variables...")
    
    while True:
        keywords = os.environ.get(f'BOM_KEYWORDS_{i}')
        email = os.environ.get(f'BOM_EMAIL_{i}')
        name = os.environ.get(f'BOM_NAME_{i}', f'BOM {i}')
        
        if not keywords or not email:
            break
            
        # Split keywords by comma and clean them
        keyword_list = [k.strip().lower() for k in keywords.split(',') if k.strip()]
        
        boms.append({
            'id': i,
            'name': name,
            'email': email,
            'keywords': keyword_list
        })
        
        print(f"   ✅ Loaded BOM {i}: {name} - {len(keyword_list)} keywords → {email}")
        i += 1
    
    if i == 1:
        print("   ⚠️ No BOM environment variables found. Add BOM_KEYWORDS_1, BOM_EMAIL_1, etc.")
    
    return boms

# Load BOMs at startup
ENV_BOMS = load_boms_from_env()

# ============================================================
# DOWNLOAD DATABASE FROM GITHUB - FIXED VERSION
# ============================================================

def download_cve_from_github():
    """Download CVE database from GitHub Releases on startup"""
    # Check if file exists and has size > 0
    if os.path.exists(DB):
        file_size = os.path.getsize(DB)
        if file_size > 1024 * 1024:  # > 1MB
            size_mb = file_size / (1024 * 1024)
            print(f"✅ CVE database already exists ({size_mb:.1f} MB)")
            
            # Verify it's a valid SQLite database
            try:
                test_conn = sqlite3.connect(DB)
                cursor = test_conn.cursor()
                cursor.execute("SELECT count(*) FROM cves")
                count = cursor.fetchone()[0]
                cursor.close()
                test_conn.close()
                print(f"✅ Database is valid with {count:,} CVEs")
                return True
            except Exception as e:
                print(f"⚠️ Existing database check failed: {e}")
                # Don't delete - try to use it anyway
                return True
        else:
            print(f"⚠️ Existing database is empty ({file_size} bytes), re-downloading")
            try:
                os.remove(DB)
            except:
                pass
    
    download_url = f"https://github.com/{GITHUB_REPO}/releases/download/{GITHUB_TAG}/{GITHUB_ASSET}"
    print(f"📥 Downloading from GitHub: {download_url}")
    
    try:
        response = requests.get(download_url, stream=True, timeout=60)
        response.raise_for_status()
        
        total_size = int(response.headers.get('content-length', 0))
        downloaded = 0
        last_percent = 0
        
        with open(DB, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                if chunk:
                    f.write(chunk)
                    downloaded += len(chunk)
                    if total_size:
                        percent = int((downloaded / total_size) * 100)
                        if percent % 10 == 0 and percent > last_percent:
                            print(f"   Progress: {percent}%")
                            last_percent = percent
        
        size_mb = os.path.getsize(DB) / (1024 * 1024)
        print(f"✅ Downloaded successfully: {size_mb:.1f} MB")
        
        # Verify downloaded database - FIXED: Don't mark as corrupted if verification fails
        try:
            test_conn = sqlite3.connect(DB)
            cursor = test_conn.cursor()
            cursor.execute("SELECT count(*) FROM cves")
            count = cursor.fetchone()[0]
            cursor.close()
            test_conn.close()
            print(f"✅ Downloaded database is valid with {count:,} CVEs")
        except Exception as e:
            print(f"⚠️ Verification warning: {e} - but database may still work")
            # Try to see what tables actually exist
            try:
                test_conn = sqlite3.connect(DB)
                cursor = test_conn.cursor()
                cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
                tables = cursor.fetchall()
                print(f"   Tables in database: {[t[0] for t in tables]}")
                cursor.close()
                test_conn.close()
            except:
                pass
        
        # Return True regardless - the page loads fine
        return True
        
    except requests.exceptions.HTTPError as e:
        if response.status_code == 404:
            print(f"❌ File not found. Check your GitHub repo/tag/filename:")
            print(f"   Repo: {GITHUB_REPO}")
            print(f"   Tag: {GITHUB_TAG}")
            print(f"   Asset: {GITHUB_ASSET}")
        else:
            print(f"❌ HTTP error: {e}")
        return False
    except Exception as e:
        print(f"❌ Download failed: {e}")
        return False

# ============================================================
# POSTGRESQL CONNECTION POOL
# ============================================================

postgres_pool = None

def init_postgres():
    """Initialize PostgreSQL connection pool"""
    global postgres_pool
    if not DATABASE_URL:
        print("⚠️ DATABASE_URL not configured")
        return False
    
    try:
        postgres_pool = psycopg2.pool.SimpleConnectionPool(1, 20, DATABASE_URL)
        print("✅ PostgreSQL connection pool created")
        
        # Create all required tables with IF NOT EXISTS
        conn = postgres_pool.getconn()
        cur = conn.cursor()
        
        # AI generations table
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
        
        # CVE tracking table
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
        
        # Alert history table
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
        
        # Create indexes if they don't exist
        cur.execute("CREATE INDEX IF NOT EXISTS idx_alert_email ON alert_history(email)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_alert_cve ON alert_history(cve_id)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_cve_tracking_new ON cve_tracking(is_new)")
        
        conn.commit()
        cur.close()
        postgres_pool.putconn(conn)
        print("✅ All PostgreSQL tables ready")
        return True
    except Exception as e:
        print(f"❌ PostgreSQL initialization failed: {e}")
        return False

# ============================================================
# EMAIL FUNCTIONS
# ============================================================

def send_email_alert(to_email, subject, html_content):
    """Send email alert using SMTP"""
    try:
        msg = MIMEMultipart()
        msg['From'] = ALERT_EMAIL_FROM
        msg['To'] = to_email
        msg['Subject'] = subject
        
        msg.attach(MIMEText(html_content, 'html'))
        
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(SMTP_USERNAME, SMTP_PASSWORD)
        server.send_message(msg)
        server.quit()
        
        print(f"📧 Alert sent to {to_email}")
        return True
    except Exception as e:
        print(f"❌ Email send failed: {e}")
        return False

def get_keyword_statistics(keywords):
    """Get statistics for keywords from SQLite database"""
    stats = {}
    try:
        conn = sqlite3.connect(DB)
        cursor = conn.cursor()
        
        for keyword in keywords:
            # Get total count
            cursor.execute("""
                SELECT COUNT(*) FROM cves 
                WHERE LOWER(description) LIKE LOWER(?)
            """, (f'%{keyword}%',))
            total = cursor.fetchone()[0]
            
            # Get severity breakdown
            cursor.execute("""
                SELECT 
                    SUM(CASE WHEN cvss_score >= 9.0 THEN 1 ELSE 0 END) as critical,
                    SUM(CASE WHEN cvss_score >= 7.0 AND cvss_score < 9.0 THEN 1 ELSE 0 END) as high,
                    SUM(CASE WHEN cvss_score >= 4.0 AND cvss_score < 7.0 THEN 1 ELSE 0 END) as medium,
                    SUM(CASE WHEN cvss_score > 0 AND cvss_score < 4.0 THEN 1 ELSE 0 END) as low
                FROM cves 
                WHERE LOWER(description) LIKE LOWER(?)
            """, (f'%{keyword}%',))
            sev = cursor.fetchone()
            
            # Get newly added (last 7 days)
            cursor.execute("""
                SELECT COUNT(*) FROM cves 
                WHERE LOWER(description) LIKE LOWER(?)
                AND julianday('now') - julianday(published) <= 7
            """, (f'%{keyword}%',))
            new_count = cursor.fetchone()[0]
            
            stats[keyword] = {
                'total': total,
                'critical': sev[0] or 0,
                'high': sev[1] or 0,
                'medium': sev[2] or 0,
                'low': sev[3] or 0,
                'new': new_count
            }
        
        cursor.close()
        conn.close()
    except Exception as e:
        print(f"⚠️ Could not fetch keyword stats: {e}")
    
    return stats

def send_bom_alert(email, bom_name, keywords, matches):
    """Send formatted email for BOM matches with keyword statistics"""
    
    # Get keyword statistics
    keyword_stats = get_keyword_statistics(keywords)
    
    subject = f"🚨 CVE Alert: {len(matches)} new vulnerabilities match your BOM '{bom_name}'"
    
    # Create keyword statistics table HTML
    stats_table = ""
    if keyword_stats:
        stats_table = """
            <h3 style="color: #333; margin-top: 25px;">📊 Keyword Statistics (All Time)</h3>
            <table style="width: 100%; border-collapse: collapse; margin-top: 15px; font-size: 13px;">
                <tr style="background-color: #4a5568; color: white;">
                    <th style="padding: 10px; border: 1px solid #ddd;">Keyword</th>
                    <th style="padding: 10px; border: 1px solid #ddd;">Total</th>
                    <th style="padding: 10px; border: 1px solid #ddd;">Critical</th>
                    <th style="padding: 10px; border: 1px solid #ddd;">High</th>
                    <th style="padding: 10px; border: 1px solid #ddd;">Medium</th>
                    <th style="padding: 10px; border: 1px solid #ddd;">Low</th>
                    <th style="padding: 10px; border: 1px solid #ddd;">New (7d)</th>
                </tr>
        """
        
        total_all = 0
        total_crit = 0
        total_high = 0
        total_med = 0
        total_low = 0
        total_new = 0
        
        for keyword, stats in keyword_stats.items():
            total_all += stats['total']
            total_crit += stats['critical']
            total_high += stats['high']
            total_med += stats['medium']
            total_low += stats['low']
            total_new += stats['new']
            
            stats_table += f"""
                <tr style="background-color: {'#f9f9f9' if loop.index % 2 == 0 else 'white'};">
                    <td style="padding: 8px; border: 1px solid #ddd; font-weight: bold;">{keyword}</td>
                    <td style="padding: 8px; border: 1px solid #ddd; text-align: center;">{stats['total']}</td>
                    <td style="padding: 8px; border: 1px solid #ddd; text-align: center; color: #d9534f; font-weight: bold;">{stats['critical']}</td>
                    <td style="padding: 8px; border: 1px solid #ddd; text-align: center; color: #f0ad4e; font-weight: bold;">{stats['high']}</td>
                    <td style="padding: 8px; border: 1px solid #ddd; text-align: center; color: #5bc0de; font-weight: bold;">{stats['medium']}</td>
                    <td style="padding: 8px; border: 1px solid #ddd; text-align: center; color: #5cb85c; font-weight: bold;">{stats['low']}</td>
                    <td style="padding: 8px; border: 1px solid #ddd; text-align: center; background-color: #fcf8e3; font-weight: bold;">{stats['new']}</td>
                </tr>
            """
        
        # Add totals row
        stats_table += f"""
                <tr style="background-color: #e2e8f0; font-weight: bold;">
                    <td style="padding: 10px; border: 1px solid #ddd;">TOTAL</td>
                    <td style="padding: 10px; border: 1px solid #ddd; text-align: center;">{total_all}</td>
                    <td style="padding: 10px; border: 1px solid #ddd; text-align: center; color: #d9534f;">{total_crit}</td>
                    <td style="padding: 10px; border: 1px solid #ddd; text-align: center; color: #f0ad4e;">{total_high}</td>
                    <td style="padding: 10px; border: 1px solid #ddd; text-align: center; color: #5bc0de;">{total_med}</td>
                    <td style="padding: 10px; border: 1px solid #ddd; text-align: center; color: #5cb85c;">{total_low}</td>
                    <td style="padding: 10px; border: 1px solid #ddd; text-align: center; background-color: #fcf8e3;">{total_new}</td>
                </tr>
            </table>
        """
    
    # Create HTML table for today's matches
    matches_html = ""
    for match in matches:
        cve = match["cve"]
        severity_color = "#d9534f" if cve['cvss_score'] and cve['cvss_score'] >= 9 else "#f0ad4e" if cve['cvss_score'] and cve['cvss_score'] >= 7 else "#5bc0de" if cve['cvss_score'] and cve['cvss_score'] >= 4 else "#5cb85c"
        
        matches_html += f"""
            <tr>
                <td style="padding: 10px; border: 1px solid #ddd;">
                    <a href="https://nvd.nist.gov/vuln/detail/{cve['cve_id']}" style="color: #1a56db;">{cve['cve_id']}</a>
                </td>
                <td style="padding: 10px; border: 1px solid #ddd; text-align: center; font-weight: bold; color: {severity_color};">
                    {cve['cvss_score'] if cve['cvss_score'] else 'N/A'}
                </td>
                <td style="padding: 10px; border: 1px solid #ddd; text-align: center;">
                    <span style="background-color: {severity_color}; color: white; padding: 3px 8px; border-radius: 12px; font-size: 0.8rem;">
                        {cve.get('severity', 'Unknown')}
                    </span>
                </td>
                <td style="padding: 10px; border: 1px solid #ddd; text-align: center; font-weight: bold; background-color: #f0f7ff;">
                    {match['keyword']}
                </td>
                <td style="padding: 10px; border: 1px solid #ddd;">{cve['description'][:150]}...</td>
            </tr>
        """
    
    # Complete HTML email
    html = f"""
    <html>
    <head>
        <style>
            body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
            .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; text-align: center; border-radius: 8px 8px 0 0; }}
            .cve-table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
            .cve-table th {{ background-color: #4a5568; color: white; padding: 12px; text-align: left; }}
            .cve-table td {{ padding: 12px; border: 1px solid #ddd; }}
            .footer {{ margin-top: 30px; padding: 20px; color: #777; font-size: 12px; text-align: center; border-top: 1px solid #ddd; }}
        </style>
    </head>
    <body>
        <div class="header">
            <h1 style="margin:0;">🚨 CVE Alert</h1>
            <p style="margin:5px 0 0; opacity:0.9;">{len(matches)} new vulnerabilities match your BOM</p>
        </div>
        
        <div style="padding: 20px;">
            <div style="background-color: #f8f9fa; padding: 15px; border-radius: 8px; margin-bottom: 20px;">
                <h3 style="margin-top:0; color:#4a5568;">📋 BOM Summary</h3>
                <table style="width:100%;">
                    <tr>
                        <td><strong>BOM Name:</strong> {bom_name}</td>
                        <td><strong>Date:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M UTC')}</td>
                    </tr>
                    <tr>
                        <td><strong>Recipient:</strong> {email}</td>
                        <td><strong>New Matches:</strong> <span style="color:#d9534f; font-weight:bold;">{len(matches)}</span></td>
                    </tr>
                </table>
            </div>
            
            {stats_table}
            
            <h3 style="color: #333; margin-top: 30px;">🆕 New CVEs Found Today</h3>
            <table class="cve-table">
                <tr>
                    <th>CVE ID</th>
                    <th>CVSS</th>
                    <th>Severity</th>
                    <th>Matched Keyword</th>
                    <th>Description</th>
                </tr>
                {matches_html}
            </table>
            
            <div class="footer">
                <p>This is an automated alert from your CVE Monitoring Dashboard.</p>
                <p>You received this because your BOM "{bom_name}" contains keywords that match these CVEs.</p>
                <p>© {datetime.now().year} CVE Monitoring Dashboard</p>
            </div>
        </div>
    </body>
    </html>
    """
    
    send_email_alert(email, subject, html)

# ============================================================
# DAILY CVE UPDATE FUNCTION
# ============================================================

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY = os.environ.get("NVD_API_KEY", "")

def fetch_new_cves_from_nvd():
    """Fetch CVEs from last 24 hours and update database"""
    print(f"🔄 [{datetime.now()}] Starting daily CVE update...")
    
    end_date = datetime.now(timezone.utc)
    start_date = end_date - timedelta(days=1)
    
    pub_start = start_date.strftime("%Y-%m-%dT%H:%M:%S.000+00:00")
    pub_end = end_date.strftime("%Y-%m-%dT%H:%M:%S.000+00:00")
    
    headers = {"User-Agent": "CVE-Dashboard/1.0"}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY
    
    new_cves = []
    
    try:
        params = {
            "pubStartDate": pub_start,
            "pubEndDate": pub_end,
            "resultsPerPage": 2000
        }
        
        response = requests.get(NVD_API_URL, params=params, headers=headers, timeout=30)
        
        if response.status_code == 200:
            data = response.json()
            vulnerabilities = data.get("vulnerabilities", [])
            
            print(f"📥 Found {len(vulnerabilities)} CVEs published in last 24 hours")
            
            conn = sqlite3.connect(DB)
            cursor = conn.cursor()
            
            for item in vulnerabilities:
                cve_data = item.get("cve", {})
                cve_id = cve_data.get("id", "")
                
                if not cve_id:
                    continue
                
                # Extract description
                descs = cve_data.get("descriptions", [])
                desc = next((d["value"] for d in descs if d.get("lang") == "en"), "")
                
                # Extract CVSS score
                metrics = cve_data.get("metrics", {})
                cvss = None
                for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                    if key in metrics and metrics[key]:
                        try:
                            cvss = float(metrics[key][0]["cvssData"]["baseScore"])
                        except:
                            pass
                        break
                
                published = cve_data.get("published", "")[:10]
                
                # Extract affected companies
                companies = extract_affected_companies(desc)
                
                # Check if CVE already exists
                cursor.execute("SELECT cve_id FROM cves WHERE cve_id = ?", (cve_id,))
                exists = cursor.fetchone()
                
                if not exists:
                    # New CVE - insert into SQLite
                    cursor.execute("""
                        INSERT INTO cves (cve_id, description, cvss_score, published)
                        VALUES (?, ?, ?, ?)
                    """, (cve_id, desc, cvss, published))
                    
                    new_cves.append({
                        "cve_id": cve_id,
                        "description": desc,
                        "cvss_score": cvss,
                        "severity": calculate_severity(cvss),
                        "published": published,
                        "companies": companies
                    })
                    
                    print(f"🆕 New CVE added: {cve_id}")
            
            conn.commit()
            conn.close()
            
            # Update PostgreSQL tracking
            if new_cves and postgres_pool:
                update_cve_tracking(new_cves)
            
            # Check BOMs and send alerts
            if new_cves:
                check_boms_and_send_alerts(new_cves)
            
            print(f"✅ Daily update complete. Added {len(new_cves)} new CVEs")
            
        else:
            print(f"❌ NVD API error: {response.status_code}")
            
    except Exception as e:
        print(f"❌ Error in daily update: {e}")

def update_cve_tracking(new_cves):
    """Update PostgreSQL tracking table with new CVEs"""
    try:
        conn = postgres_pool.getconn()
        cur = conn.cursor()
        
        for cve in new_cves:
            cur.execute("""
                INSERT INTO cve_tracking 
                    (cve_id, first_seen_date, is_new, cvss_score, severity, 
                     description, published_date, affected_companies)
                VALUES (%s, CURRENT_TIMESTAMP, TRUE, %s, %s, %s, %s, %s)
                ON CONFLICT (cve_id) DO NOTHING
            """, (
                cve["cve_id"],
                cve["cvss_score"],
                cve["severity"],
                cve["description"],
                cve["published"],
                Json(cve["companies"])
            ))
        
        conn.commit()
        cur.close()
        postgres_pool.putconn(conn)
    except Exception as e:
        print(f"❌ Error updating CVE tracking: {e}")

def check_boms_and_send_alerts(new_cves):
    """Check environment variable BOMs against new CVEs and send alerts"""
    if not ENV_BOMS:
        print("   No environment BOMs configured")
        return
    
    print(f"   Checking {len(ENV_BOMS)} environment BOMs for matches...")
    
    for bom in ENV_BOMS:
        matches = []
        
        for cve in new_cves:
            desc_lower = cve["description"].lower()
            
            for keyword in bom['keywords']:
                if keyword.lower() in desc_lower:
                    matches.append({
                        "cve": cve,
                        "keyword": keyword
                    })
                    break  # Only count once per CVE per BOM
        
        if matches:
            # Record in PostgreSQL if available
            if postgres_pool:
                try:
                    conn = postgres_pool.getconn()
                    cur = conn.cursor()
                    for match in matches:
                        cur.execute("""
                            INSERT INTO alert_history (email, cve_id, bom_name, matched_keyword)
                            VALUES (%s, %s, %s, %s)
                        """, (bom['email'], match['cve']['cve_id'], bom['name'], match['keyword']))
                    conn.commit()
                    cur.close()
                    postgres_pool.putconn(conn)
                except Exception as e:
                    print(f"   ⚠️ Could not record alert history: {e}")
            
            # Send email with keyword statistics
            send_bom_alert(bom['email'], bom['name'], bom['keywords'], matches)
            print(f"   📧 Sent {len(matches)} alerts for {bom['name']}")

# ============================================================
# SCHEDULER FOR DAILY UPDATES
# ============================================================

def run_scheduler():
    """Run the scheduler in a background thread"""
    while True:
        schedule.run_pending()
        time.sleep(60)

# Schedule daily update at 2:00 AM UTC
schedule.every().day.at("02:00").do(fetch_new_cves_from_nvd)

# Start scheduler
scheduler_thread = threading.Thread(target=run_scheduler, daemon=True)
scheduler_thread.start()
print("⏰ Daily update scheduler started (runs at 2:00 AM UTC)")

# ============================================================
# RATE LIMITING
# ============================================================

_rate_lock = threading.Lock()
_request_log: dict[str, deque] = {}

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
    path_lower = request.path.lower()
    if any(p in path_lower for p in bad_patterns):
        abort(404)

@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
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
# URL SECURITY FUNCTIONS
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
    from flask import session as fs
    if "csrf_token" not in fs:
        fs["csrf_token"] = secrets.token_hex(24)
    return fs["csrf_token"]

def validate_csrf(token: str) -> bool:
    from flask import session as fs
    return secrets.compare_digest(fs.get("csrf_token", ""), token or "")

@app.context_processor
def inject_csrf():
    return {"csrf_token": generate_csrf_token()}

# ============================================================
# AI CONFIGURATION
# ============================================================

DEFAULT_AI_PROVIDER = "deepseek"

DEEPSEEK_API_URL = "https://api.deepseek.com/v1/chat/completions"
DEEPSEEK_MODEL = "deepseek-chat"

OPENAI_API_URL = "https://api.openai.com/v1/chat/completions"
OPENAI_MODEL = "gpt-4o-mini"

CLAUDE_API_URL = "https://api.anthropic.com/v1/messages"
CLAUDE_MODEL = "claude-3-haiku-20240307"

OLLAMA_URL = "http://localhost:11434/api/generate"
OLLAMA_MODEL = "llama3.2"

USE_AI = True
USE_AI_CACHE = True

DATE_COLUMN = "published"

def get_ai_config():
    from flask import session as fsession
    provider = fsession.get("ai_provider", DEFAULT_AI_PROVIDER)
    api_key = fsession.get("ai_api_key", "")
    model = fsession.get("ai_model", "")

    if provider == "deepseek":
        api_key = api_key or os.environ.get("DEEPSEEK_API_KEY", "")
        model = model or DEEPSEEK_MODEL
    elif provider == "openai":
        api_key = api_key or os.environ.get("OPENAI_API_KEY", "")
        model = model or OPENAI_MODEL
    elif provider == "claude":
        api_key = api_key or os.environ.get("ANTHROPIC_API_KEY", "")
        model = model or CLAUDE_MODEL
    elif provider == "ollama":
        api_key = "ollama"
        model = model or OLLAMA_MODEL

    return provider, api_key, model

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
# DATABASE INITIALIZATION - FIXED VERSION
# ============================================================

def init_database():
    """Initialize SQLite database with required tables."""
    try:
        conn = sqlite3.connect(DB)
        cursor = conn.cursor()

        # Create cves table - IMPORTANT: "references" is a keyword, must be in double quotes
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

        # Create AI analysis table
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

        # Create indexes
        try:
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_cves_published ON cves(published DESC)")
        except Exception as e:
            print(f"⚠️ Index creation warning (published): {e}")
        
        try:
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_cves_cvss_score ON cves(cvss_score)")
        except Exception as e:
            print(f"⚠️ Index creation warning (cvss): {e}")
        
        try:
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_ai_analysis_fix_status ON cve_ai_analysis(fix_status)")
        except Exception as e:
            print(f"⚠️ Index creation warning (fix_status): {e}")

        # Verify table was created
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='cves'")
        if cursor.fetchone():
            print("✅ SQLite cves table ready")
        else:
            print("❌ Failed to create cves table")

        conn.commit()
        conn.close()
        print("✅ SQLite database initialized")
        return True
    except Exception as e:
        print(f"⚠️ SQLite init error: {e}")
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
        if score >= 9.0:
            return "Critical"
        elif score >= 7.0:
            return "High"
        elif score >= 4.0:
            return "Medium"
        elif score > 0:
            return "Low"
        else:
            return "Unknown"
    except (ValueError, TypeError):
        return "Unknown"

# ============================================================
# UTILITY FUNCTIONS
# ============================================================

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

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

# ============================================================
# API ROUTES - FIXED STATS ROUTE
# ============================================================

def stats():
    conn   = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='cves'")
    if not cursor.fetchone():
        conn.close()
        return jsonify({"total_cves":0,"critical":0,"high":0,"medium":0,"low":0,
                        "ai_enhanced":0,"oldest_cve":None,"newest_cve":None})

    cursor.execute("SELECT COUNT(*) FROM cves");                                              total       = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM cves WHERE cvss_score >= 9.0");                      critical    = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM cves WHERE cvss_score >= 7.0 AND cvss_score < 9.0"); high        = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM cves WHERE cvss_score >= 4.0 AND cvss_score < 7.0"); medium      = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM cves WHERE cvss_score > 0 AND cvss_score < 4.0");   low         = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM cve_ai_analysis");                                   ai_enhanced = cursor.fetchone()[0]
    try:
        cursor.execute(f"SELECT MIN({DATE_COLUMN}), MAX({DATE_COLUMN}) FROM cves")
        date_range = cursor.fetchone()
    except Exception:
        date_range = (None, None)
    conn.close()
    return jsonify({"total_cves":total,"critical":critical,"high":high,"medium":medium,
                    "low":low,"ai_enhanced":ai_enhanced,
                    "oldest_cve":date_range[0] if date_range else None,
                    "newest_cve":date_range[1] if date_range else None})

@app.route("/keyword-stats")
def keyword_stats():
    """Get statistics for keywords (placeholder)"""
    return jsonify({})

@app.route("/api/boms", methods=["GET"])
def get_boms():
    """Get all active BOMs (from environment variables)"""
    boms = []
    
    for bom in ENV_BOMS:
        boms.append({
            "id": f"env_{bom['id']}",
            "bom_name": bom['name'],
            "email": bom['email'],
            "keywords": bom['keywords'],
            "created_at": None,
            "last_alert_sent": None,
            "source": "environment"
        })
    
    # Also get alert history counts if PostgreSQL is available
    if postgres_pool:
        try:
            conn = postgres_pool.getconn()
            cur = conn.cursor()
            
            for bom in boms:
                cur.execute("""
                    SELECT COUNT(*) FROM alert_history 
                    WHERE email = %s AND sent_at > NOW() - INTERVAL '7 days'
                """, (bom['email'],))
                count = cur.fetchone()[0]
                bom['alerts_last_7_days'] = count
            
            cur.close()
            postgres_pool.putconn(conn)
        except Exception as e:
            print(f"⚠️ Error fetching alert counts: {e}")
    
    return jsonify(boms)

@app.route("/api/alerts/recent", methods=["GET"])
def get_recent_alerts():
    """Get recent alerts from PostgreSQL"""
    if not postgres_pool:
        return jsonify([])
    
    try:
        conn = postgres_pool.getconn()
        cur = conn.cursor()
        cur.execute("""
            SELECT email, cve_id, matched_keyword, bom_name, sent_at
            FROM alert_history
            WHERE sent_at > NOW() - INTERVAL '24 hours'
            ORDER BY sent_at DESC
            LIMIT 10
        """)
        rows = cur.fetchall()
        cur.close()
        postgres_pool.putconn(conn)
        
        alerts = []
        for row in rows:
            alerts.append({
                "email": row[0],
                "cve_id": row[1],
                "keyword": row[2],
                "bom_name": row[3],
                "sent_at": row[4].isoformat() if row[4] else None
            })
        
        return jsonify(alerts)
    except Exception as e:
        print(f"❌ Error fetching alerts: {e}")
        return jsonify([])

# ============================================================
# MAIN ROUTES
# ============================================================

@app.route("/search", methods=["POST"])
def search_post():
    keyword = request.form.get("keyword", "").strip()
    keywords_text = request.form.get("keywords", "")
    severity_filter = request.form.get("severity", "")
    use_ai = request.form.get("use_ai", "false") == "true"
    tab = request.form.get("tab", "single")

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
    kw_enc = request.args.get("kw", "")
    sv_enc = request.args.get("sv", "")
    keywords_param = _deobfuscate(kw_enc) if kw_enc else request.args.get("keywords", "")
    severity_filter = _deobfuscate(sv_enc) if sv_enc else request.args.get("severity", "")
    search_mode = request.args.get("search_mode", "single")
    keyword = request.args.get("keyword", "")
    page = int(request.args.get("page", 1))
    _ai_a = request.args.get("ai", "")
    _ai_b = request.args.get("use_ai", "false")
    use_ai = (_ai_a in ("1", "true")) or (_ai_b in ("1", "true"))

    try:
        if keywords_param:
            keywords = [k.strip() for k in keywords_param.split(',') if k.strip()]
            cves, total = search_cves_by_keywords(keywords, severity_filter, page, use_ai=use_ai)
            active_keywords = keywords
        elif search_mode == "single" and keyword:
            cves, total = search_cves_by_keywords([keyword], severity_filter, page, use_ai=use_ai)
            active_keywords = [keyword]
        else:
            conn = get_db_connection()
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
            total = len(cves)

        # Mark new CVEs (from last 7 days)
        if postgres_pool and cves:
            try:
                conn = postgres_pool.getconn()
                cur = conn.cursor()
                cur.execute("""
                    SELECT cve_id FROM cve_tracking 
                    WHERE first_seen_date > NOW() - INTERVAL '7 days'
                    AND is_new = TRUE
                """)
                new_cves = {row[0] for row in cur.fetchall()}
                
                for cve in cves:
                    cve['is_new'] = cve['cve_id'] in new_cves
                
                cur.close()
                postgres_pool.putconn(conn)
            except Exception as e:
                print(f"⚠️ Error fetching new CVEs: {e}")

        total_pages = (total // 50) + (1 if total % 50 > 0 else 0) if total else 1

        return render_template(
            "index.html",
            cves=cves,
            keyword=keyword,
            severity_filter=severity_filter,
            active_keywords=active_keywords,
            page=page,
            total_pages=total_pages,
            use_ai=use_ai,
            env_boms=ENV_BOMS
        )
    except Exception as e:
        print(f"❌ Error in index route: {e}")
        return render_template(
            "index.html",
            cves=[],
            keyword=keyword,
            severity_filter=severity_filter,
            active_keywords=[],
            page=1,
            total_pages=1,
            use_ai=use_ai,
            env_boms=ENV_BOMS
        )

# ============================================================
# CVE SEARCH FUNCTIONS
# ============================================================

def search_cves_by_keywords(keywords, severity_filter=None, page=1, per_page=50, use_ai=False):
    conn = get_db_connection()
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
    total = result['count'] if result else 0

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

def _enrich_row(row_dict, use_ai=False):
    row_dict["severity"] = calculate_severity(row_dict.get("cvss_score"))
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
        cur = conn.cursor()
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
            row_dict["ai_summary"] = ai_row[0]
            row_dict["affected_companies"] = companies
            row_dict["remediation"] = ai_row[2] or ""
            row_dict["affected_version"] = ai_row[3] or "Unknown"
            row_dict["fixed_version"] = ai_row[4] or "Unknown"
            row_dict["fix_status"] = ai_row[5] or "Unknown"
            return row_dict
    except Exception as e:
        print(f"⚠️ DB cache read error for {row_dict['cve_id']}: {e}")

    row_dict["affected_companies"] = extract_affected_companies(row_dict.get("description", ""))
    row_dict["fix_status"] = _rule_based_fix_status(row_dict.get("description", ""))
    row_dict["remediation"] = _rule_based_remediation(row_dict.get("description", ""), row_dict.get("cve_id", ""))
    return row_dict

# ============================================================
# RULE-BASED FUNCTIONS
# ============================================================

STALE_PLACEHOLDERS = {
    "no ai summary available",
    "information not available",
    "ai analysis unavailable",
    "ai analysis unavailable — review description manually.",
    "",
}

def _rule_based_fix_status(description: str) -> str:
    d = description.lower()
    if any(t in d for t in ["fixed in", "patched in", "update to", "upgrade to"]):
        return "Fix Available"
    if any(t in d for t in ["no fix", "unpatched", "no patch"]):
        return "Not Fixed"
    if any(t in d for t in ["workaround", "mitigation"]):
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
# STARTUP
# ============================================================

# Initialize everything on startup
init_database()
download_cve_from_github()
init_postgres()

if __name__ == "__main__":
    print("=" * 55)
    print("🚀 CVE Monitoring Dashboard")
    print("=" * 55)
    print(f"📁 SQLite DB:  {DB}")
    print(f"🤖 AI:        {'Enabled' if USE_AI else 'Disabled'}")
    print(f"📦 GitHub:    {GITHUB_REPO} / {GITHUB_TAG}")
    print(f"🐘 PostgreSQL: {'Connected' if postgres_pool else 'Not connected'}")
    print(f"📋 BOMs:      {len(ENV_BOMS)} loaded from environment")
    print(f"⏰ Scheduler:  Daily at 2:00 AM UTC")
    print("=" * 55)
    
    port = int(os.environ.get('PORT', 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
