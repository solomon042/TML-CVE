#!/usr/bin/env python3
"""
nvd_sync.py — bring nvd_database.db up to date from the NVD API (+ CISA KEV).

Runs outside the web app (GitHub Actions, see TML-CVE-Dashboard's db-sync
workflow), because Koyeb has no persistent disk: the app re-downloads the DB
release asset on every restart, so updates made inside the app are lost.

    python nvd_sync.py --db nvd_database.db            # since last sync
    python nvd_sync.py --db nvd_database.db --since 2026-07-23

Fetches everything PUBLISHED or MODIFIED since the last successful sync
(app_settings.last_nvd_update, minus a 2-day overlap), in <=120-day windows
(NVD API limit), upserts with the same columns/format as app.py's NVD update,
marks CISA KEV entries, and records the new last_nvd_update.

Env: NVD_API_KEY (optional; ~10x faster and fewer rate-limit pauses)
"""

import argparse
import json
import os
import sqlite3
import sys
import time
from datetime import datetime, timedelta, timezone

import requests

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
WINDOW_DAYS = 119
PAGE = 2000


def log(msg):
    print(f"[{datetime.now(timezone.utc):%H:%M:%S}] {msg}", flush=True)


def parse_cve(cve_data):
    """NVD 2.0 'cve' object -> row tuple, same rules as app.py."""
    cve_id = cve_data.get("id", "")
    descs = cve_data.get("descriptions", [])
    desc = next((d["value"] for d in descs if d.get("lang") == "en"), "")

    metrics = cve_data.get("metrics", {})
    cvss = severity = None
    for mk in ["cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
        if metrics.get(mk):
            try:
                e2 = metrics[mk][0]
                cvss = float(e2["cvssData"]["baseScore"])
                severity = e2["cvssData"].get("baseSeverity") or e2.get("baseSeverity", "")
            except Exception:
                pass
            break
    if not severity and cvss is not None:
        severity = ("Critical" if cvss >= 9.0 else "High" if cvss >= 7.0
                    else "Medium" if cvss >= 4.0 else "Low")
    severity = (severity or "Unknown").capitalize()

    cwe_id = ""
    for w in cve_data.get("weaknesses", []):
        for d in w.get("description", []):
            if d.get("lang") == "en":
                cwe_id = d.get("value", "")
                break

    refs = [r.get("url", "") for r in cve_data.get("references", [])[:10]]

    parts = []
    for cfg in cve_data.get("configurations", []):
        for node in cfg.get("nodes", []):
            for m in node.get("cpeMatch", []):
                if not m.get("vulnerable"):
                    continue
                ve, vei, vi = (m.get("versionEndExcluding", ""), m.get("versionEndIncluding", ""),
                               m.get("versionStartIncluding", ""))
                if ve:
                    parts.append(f"< {ve}")
                elif vei:
                    parts.append(f"<= {vei}")
                elif vi:
                    parts.append(f">= {vi}")
    affected = ", ".join(list(dict.fromkeys(parts))[:5])

    return (cve_id, desc, cvss, severity, cve_data.get("published", "")[:10],
            cve_data.get("lastModified", "")[:10], cwe_id, json.dumps(refs), affected)


def upsert(cur, row):
    cve_id, desc, cvss, sev, pub, mod, cwe, refs, aff = row
    cur.execute("SELECT 1 FROM cves WHERE cve_id=?", (cve_id,))
    if cur.fetchone():
        cur.execute('UPDATE cves SET description=?,cvss_score=?,severity=?,published=?,'
                    'last_modified=?,cwe_id=?,"references"=?,affected_versions=? WHERE cve_id=?',
                    (desc, cvss, sev, pub, mod, cwe, refs, aff, cve_id))
        return 0
    cur.execute('INSERT INTO cves (cve_id,description,cvss_score,severity,published,'
                'last_modified,cwe_id,"references",affected_versions) VALUES (?,?,?,?,?,?,?,?,?)',
                row)
    return 1


def fetch_window(session, key_from, key_to, start, end, api_key):
    """Yield NVD 'cve' objects for one <=120-day window, paging and retrying."""
    headers = {"User-Agent": "TML-CVE-Dashboard-sync/1.0"}
    if api_key:
        headers["apiKey"] = api_key
    index, total = 0, None
    while total is None or index < total:
        params = {key_from: start.strftime("%Y-%m-%dT%H:%M:%S.000+00:00"),
                  key_to: end.strftime("%Y-%m-%dT%H:%M:%S.000+00:00"),
                  "startIndex": index, "resultsPerPage": PAGE}
        for attempt in range(1, 9):
            try:
                r = session.get(NVD_API_URL, params=params, headers=headers, timeout=90)
            except requests.RequestException as e:
                r, err = None, str(e)
            if r is not None and r.status_code == 200:
                break
            wait = min(15 * attempt, 120)
            log(f"  NVD {'HTTP ' + str(r.status_code) if r is not None else err} "
                f"(attempt {attempt}/8) — retrying in {wait}s")
            time.sleep(wait)
        else:
            raise RuntimeError(f"NVD failed for {key_from} {start:%Y-%m-%d} index {index}")
        data = r.json()
        total = data.get("totalResults", 0)
        vulns = data.get("vulnerabilities", [])
        log(f"  {key_from[:-4]} {start:%Y-%m-%d}..{end:%Y-%m-%d}: {index + len(vulns):,}/{total:,}")
        for v in vulns:
            yield v.get("cve", {})
        if not vulns:
            break
        index += PAGE
        time.sleep(0.8 if api_key else 6.5)


def sync(db_path, since=None, api_key="", mod_days=7):
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute("CREATE TABLE IF NOT EXISTS app_settings (key TEXT PRIMARY KEY, value TEXT)")
    cols = {r[1] for r in cur.execute("PRAGMA table_info(cves)")}
    for col, typ in [("source", "TEXT"), ("is_kev", "INTEGER DEFAULT 0"), ("kev_date_added", "TEXT"),
                     ("kev_ransomware", "TEXT"), ('"references"', "TEXT"), ("cwe_id", "TEXT"),
                     ("affected_versions", "TEXT")]:
        if col.strip('"') not in cols:
            cur.execute(f"ALTER TABLE cves ADD COLUMN {col} {typ}")
    conn.commit()

    now = datetime.now(timezone.utc)
    if since:
        start = datetime.strptime(since, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    else:
        row = cur.execute("SELECT value FROM app_settings WHERE key='last_nvd_update'").fetchone()
        last = None
        if row and row[0]:
            try:
                last = datetime.fromisoformat(row[0].replace("Z", "+00:00"))
            except ValueError:
                last = None
        if last is None:
            row = cur.execute("SELECT MAX(published) FROM cves WHERE published LIKE '____-__-__%'").fetchone()
            last = datetime.strptime(row[0][:10], "%Y-%m-%d").replace(tzinfo=timezone.utc)
        start = last - timedelta(days=2)
    before = cur.execute("SELECT COUNT(*) FROM cves").fetchone()[0]
    log(f"DB has {before:,} CVEs; syncing everything published or modified since {start:%Y-%m-%d}")

    session = requests.Session()
    added = updated = 0
    # New CVEs come back in their current state, so the "modified" pass only
    # needs to catch changes to older CVEs — capped to keep runs short.
    mod_start = max(start, now - timedelta(days=mod_days))
    for key_from, key_to, w0 in (("pubStartDate", "pubEndDate", start),
                                 ("lastModStartDate", "lastModEndDate", mod_start)):
        w_start = w0
        while w_start < now:
            w_end = min(w_start + timedelta(days=WINDOW_DAYS), now)
            n = 0
            for cve in fetch_window(session, key_from, key_to, w_start, w_end, api_key):
                if not cve.get("id"):
                    continue
                if upsert(cur, parse_cve(cve)):
                    added += 1
                else:
                    updated += 1
                n += 1
                if n % 2000 == 0:
                    conn.commit()
            conn.commit()
            w_start = w_end

    # CISA KEV — mark actively exploited CVEs (same as app.fetch_cisa_kev)
    try:
        kev = session.get(CISA_KEV_URL, timeout=60).json().get("vulnerabilities", [])
        k_new = 0
        for v in kev:
            cid = v.get("cveID")
            if not cid:
                continue
            if cur.execute("SELECT 1 FROM cves WHERE cve_id=?", (cid,)).fetchone():
                cur.execute("UPDATE cves SET is_kev=1, kev_date_added=?, kev_ransomware=? WHERE cve_id=?",
                            (v.get("dateAdded", ""), v.get("knownRansomwareCampaignUse", "Unknown"), cid))
            else:
                desc = (f"{v.get('vendorProject', '')} {v.get('product', '')}: "
                        f"{v.get('shortDescription', '')} (CISA KEV — patch by {v.get('dueDate', '')})")
                cur.execute("INSERT OR IGNORE INTO cves (cve_id, description, severity, published, "
                            "last_modified, is_kev, kev_date_added, kev_ransomware, source) "
                            "VALUES (?,?,?,?,?,1,?,?,'kev')",
                            (cid, desc, "Unknown", v.get("dateAdded", ""), v.get("dateAdded", ""),
                             v.get("dateAdded", ""), v.get("knownRansomwareCampaignUse", "Unknown")))
                k_new += 1
        conn.commit()
        log(f"CISA KEV: {len(kev):,} entries checked, {k_new} new")
    except Exception as e:
        log(f"CISA KEV skipped: {e}")

    cur.execute("INSERT INTO app_settings (key, value) VALUES ('last_nvd_update', ?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (now.isoformat(timespec="seconds").replace("+00:00", "Z"),))
    conn.commit()
    after = cur.execute("SELECT COUNT(*) FROM cves").fetchone()[0]
    newest = cur.execute("SELECT MAX(published) FROM cves WHERE published LIKE '____-__-__%'").fetchone()[0]
    conn.close()
    log(f"Done — {added:,} added, {updated:,} updated · {before:,} → {after:,} CVEs · newest {newest}")
    return added, updated


def main(argv=None):
    ap = argparse.ArgumentParser(description="Sync nvd_database.db from NVD + CISA KEV")
    ap.add_argument("--db", default="nvd_database.db")
    ap.add_argument("--since", help="YYYY-MM-DD (default: last successful sync - 2 days)")
    ap.add_argument("--mod-days", type=int, default=7,
                    help="max days of 'recently modified' CVEs to re-fetch (default 7)")
    args = ap.parse_args(argv)
    if not os.path.exists(args.db):
        sys.exit(f"DB not found: {args.db}")
    sync(args.db, args.since, os.environ.get("NVD_API_KEY", "").strip(), args.mod_days)


if __name__ == "__main__":
    main()
