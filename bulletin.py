"""
Monthly Automotive Vulnerability Bulletin
=========================================
Builds a one-page brochure that combines, for a given calendar month:

  1. Automotive-relevant CVEs already in the local DB (NVD / MITRE / GHSA / KEV)
  2. Automotive company cyber-incidents drafted by the configured AI provider,
     then SOURCE-VERIFIED (the cited URL must resolve AND its page must name the
     company) — unverified items are dropped, never published.

Self-contained: app.py calls `register(app, ...)` with the few helpers it needs
(dependency injection, so there is no circular import). Bulletins are cached one
row per month in the `bulletins` table. A scheduler job builds the *previous*
month on the 1st (e.g. August's bulletin is generated on September 1st).
"""

import re
import json
import ipaddress
import socket
from datetime import datetime, timezone, date
from urllib.parse import urlparse

import requests
from markupsafe import escape

# ---------------------------------------------------------------------------
# Automotive relevance filter
# ---------------------------------------------------------------------------
# Tier A — pure-play automotive OEMs / suppliers / automotive-industry products.
# Distinctive enough to match on the name alone.
_TIER_A = [
    r"tesla", r"toyota", r"lexus", r"\bford\b", r"general motors", r"onstar",
    r"chevrolet", r"cadillac", r"\bbuick\b", r"\bgmc\b", r"\bbmw\b", r"mercedes[- ]benz",
    r"daimler", r"volkswagen", r"\baudi\b", r"porsche", r"skoda|škoda", r"\bcupra\b",
    r"lamborghini", r"honda", r"\bacura\b", r"nissan", r"infiniti", r"hyundai", r"\bkia\b",
    r"stellantis", r"chrysler", r"\bjeep\b", r"peugeot", r"citro[eë]n", r"\bopel\b", r"vauxhall",
    r"alfa romeo", r"maserati", r"renault", r"\bdacia\b", r"volvo", r"polestar", r"\bgeely\b",
    r"\bbyd auto\b", r"xpeng", r"li auto", r"great wall motor", r"\bchery\b", r"\bsaic\b",
    r"mg motor", r"subaru", r"\bmazda\b", r"mitsubishi motors", r"\bisuzu\b", r"tata motors",
    r"jaguar land rover", r"\bjlr\b", r"land rover", r"mahindra", r"maruti", r"rivian",
    r"vinfast", r"ferrari", r"mclaren", r"aston martin", r"fisker",
    # commercial / truck / bus / brake
    r"scania", r"man truck", r"daf trucks", r"\biveco\b", r"paccar", r"kenworth", r"peterbilt",
    r"navistar", r"freightliner", r"daimler truck", r"ashok leyland", r"eicher", r"\btraton\b",
    r"\bbendix\b", r"\bwabco\b", r"knorr[- ]bremse", r"\bmeritor\b", r"allison transmission",
    r"zf friedrichshafen", r"zf group",
    # tier-1 / tier-2 suppliers & automotive tech
    r"\bdenso\b", r"\baptiv\b", r"\bvaleo\b", r"faurecia", r"\bforvia\b", r"autoliv", r"veoneer",
    r"\baisin\b", r"hyundai mobis", r"\bmobis\b", r"visteon", r"\bmarelli\b", r"yazaki",
    r"nexteer", r"borgwarner", r"\btenneco\b", r"\bgentex\b", r"mobileye", r"elektrobit",
    r"vector informatik", r"\bdspace\b", r"\betas\b", r"autosar", r"cerence",
    r"nvidia drive", r"snapdragon ride", r"android automotive", r"carplay", r"android auto\b",
    r"automotive grade linux", r"\buconnect\b", r"ford sync|\bsync ?[34]\b", r"bluelink",
    r"nissanconnect", r"connecteddrive", r"hondalink", r"fordpass", r"mercedes me",
    r"subaru starlink", r"kia connect",
    # telematics / fleet
    r"samsara", r"geotab", r"calamp", r"webfleet", r"omnitracs", r"powerfleet", r"spireon",
    r"airbiquity", r"octo telematics", r"cartrack", r"verizon connect",
    # diagnostics / aftermarket / CAN tooling
    r"\bautel\b", r"launch tech", r"\bactia\b", r"\bsofting\b", r"\bkvaser\b", r"peak-system",
    r"\btexa\b", r"cojali", r"hella gutmann", r"delphi technologies", r"intrepid control",
    r"xentry diagnos", r"techstream",
    # EV charging
    r"chargepoint", r"wallbox", r"alpitronic", r"\bevbox\b", r"blink charging", r"kempower",
    r"\bzaptec\b", r"\beasee\b", r"hardy barth", r"electrify america", r"\bionity\b", r"\bevgo\b",
    r"pod point", r"enel x way", r"tritium charg", r"abb e-?mobility", r"\bevlink\b",
    r"versicharge", r"shell recharge", r"bp pulse", r"\bocpp\b",
]

# Tier B — mixed-industry vendors: only count when the description ALSO carries
# automotive context (below).
_TIER_B = [
    r"\bbosch\b", r"continental", r"\bmagna\b", r"\blear\b", r"\bdana\b", r"\bhella\b",
    r"\bharman\b", r"panasonic", r"garmin", r"pioneer", r"\balpine\b", r"\bnxp\b", r"infineon",
    r"renesas", r"qualcomm", r"nvidia", r"siemens", r"\babb\b", r"schneider", r"phoenix contact",
    r"hitachi", r"\bsony\b", r"\blucid\b", r"\blotus\b", r"\bgenesis\b", r"rolls[- ]royce",
    r"wind river", r"green hills", r"blackberry qnx|\bqnx\b", r"\bzf\b", r"\bdelphi\b",
    r"kenwood|clarion", r"\bsumitomo\b", r"\bfurukawa\b",
]

_AUTO_CONTEXT = re.compile(r"""
    \b(vehicle|vehicles|automotive|automobile|\bcars?\b|truck|trucks|
    \bECUs?\b|electronic\ control\ unit|CAN[\s-]?bus|CAN\ FD|LIN\ bus|FlexRay|automotive\ ethernet|
    telematics|OBD(?:-?II)?|infotainment|head[\s-]unit|\bADAS\b|autonomous\ driving|
    connected\ car|in-vehicle|dashcam|electric\ vehicle|\bEVs?\b\ charg|EV\ charg\w*|
    charging\ station|charge\ point|\bOCPP\b|\bV2X\b|\bV2G\b|key\ fob|keyless|immobili[sz]er|
    brake|\bABS\b|powertrain|engine\ control|transmission\ control|tachograph|fleet\ management|
    driver\ assistance|\bTPMS\b|tire\ pressure|over-the-air|OTA\ update)\b
""", re.I | re.X)

# Wrap every company pattern in non-alphanumeric lookarounds so a name can only
# match as a whole word, never as a substring (e.g. 'lexus' inside 'plexus',
# 'li auto' inside other text). This is the automated pipeline's false-positive guard.
def _wb(p):
    return re.compile(r"(?<![A-Za-z0-9])(?:" + p + r")(?![A-Za-z0-9])", re.I)

_TA = [_wb(p) for p in _TIER_A]
_TB = [_wb(p) for p in _TIER_B]


def automotive_match(description: str):
    """Return (matched_name, tier) if the text is automotive-relevant, else (None, None)."""
    if not description:
        return None, None
    for rx in _TA:
        m = rx.search(description)
        if m:
            return m.group(0), "A"
    if _AUTO_CONTEXT.search(description):
        for rx in _TB:
            m = rx.search(description)
            if m:
                return m.group(0), "B"
    return None, None


def _subsystem(text: str) -> str:
    """Coarse bucket for the 'by system' breakdown."""
    t = (text or "").lower()
    if re.search(r"ocpp|charg|\bev\b|wallbox|supercharger", t):   return "EV charging"
    if re.search(r"brake|\babs\b|bendix|traction", t):            return "Brake / ABS"
    if re.search(r"can[\s-]?bus|can fd|lin bus|flexray|softing|kvaser", t): return "CAN / in-vehicle bus"
    if re.search(r"infotainment|head[\s-]unit|carplay|android auto|uconnect", t): return "Infotainment"
    if re.search(r"telematics|fleet|obd|gps trackrenderer", t):   return "Telematics / fleet"
    if re.search(r"key fob|keyless|immobili|pkes|rolling code", t): return "Keyless entry"
    if re.search(r"diagnos|xentry|techstream|blf|log parser", t): return "Diagnostics / tooling"
    return "Other vehicle systems"


# ---------------------------------------------------------------------------
# Source verification (SSRF-guarded) for AI-drafted incidents
# ---------------------------------------------------------------------------
def _host_is_public(host: str) -> bool:
    """Reject localhost / private / link-local / reserved addresses (SSRF guard)."""
    if not host:
        return False
    if host.lower() in ("localhost", "127.0.0.1", "::1"):
        return False
    try:
        infos = socket.getaddrinfo(host, None)
    except Exception:
        return False
    for info in infos:
        ip = info[4][0]
        try:
            addr = ipaddress.ip_address(ip.split("%")[0])
        except ValueError:
            continue
        if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved or addr.is_multicast:
            return False
    return True


def _company_tokens(company: str):
    """Significant lowercase tokens from a company name, dropping generic suffixes."""
    stop = {"inc", "ltd", "llc", "corp", "co", "gmbh", "ag", "sa", "plc", "group",
            "motors", "motor", "automotive", "the", "and", "of", "north", "america"}
    toks = [t for t in re.split(r"[^a-z0-9]+", (company or "").lower()) if len(t) > 2 and t not in stop]
    return toks


def verify_incident(inc: dict, timeout: int = 8) -> bool:
    """
    An incident is publishable only if its source URL resolves (HTTP < 400) AND
    the fetched page text mentions the company. This filters dead/fabricated
    links and obvious hallucinations. It does NOT prove the claim is accurate —
    the brochure labels these as AI-compiled, source-checked.
    """
    url = (inc.get("source_url") or "").strip()
    company = (inc.get("company") or "").strip()
    if not url or not company:
        return False
    try:
        p = urlparse(url)
    except Exception:
        return False
    if p.scheme not in ("http", "https") or not p.hostname:
        return False
    if not _host_is_public(p.hostname):
        return False
    try:
        r = requests.get(url, timeout=timeout, allow_redirects=True,
                         headers={"User-Agent": "TML-CVE-Bulletin/1.0 (+source-verification)"})
    except Exception as e:
        print(f"   [verify] fetch failed for {url}: {e}")
        return False
    if r.status_code >= 400:
        print(f"   [verify] {r.status_code} for {url}")
        return False
    body = (r.text or "").lower()
    toks = _company_tokens(company)
    if not toks:
        return False
    hit = any(tok in body for tok in toks)
    if not hit:
        print(f"   [verify] page does not mention '{company}': {url}")
    inc["source_domain"] = p.hostname
    return hit


# ---------------------------------------------------------------------------
# register() — wires everything onto the Flask app
# ---------------------------------------------------------------------------
def register(app, *, get_db_connection, call_ai_provider, server_ai_config,
             db_path, date_column, admin_required):
    import sqlite3

    # Ensure the bulletins table exists regardless of launch method.
    # (app.py's init_database() only runs under __main__, not under gunicorn.)
    try:
        _c = sqlite3.connect(db_path)
        _c.execute("""
            CREATE TABLE IF NOT EXISTS bulletins (
                month          TEXT PRIMARY KEY,
                html           TEXT,
                data_json      TEXT,
                cve_count      INTEGER DEFAULT 0,
                incident_count INTEGER DEFAULT 0,
                generated_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                status         TEXT DEFAULT 'published'
            )
        """)
        _c.commit()
        _c.close()
    except Exception as _e:
        print(f"⚠️ [bulletin] could not ensure bulletins table: {_e}")

    def _month_bounds(month_key: str):
        y, m = int(month_key[:4]), int(month_key[5:7])
        start = f"{y:04d}-{m:02d}-01"
        end = f"{y+1:04d}-01-01" if m == 12 else f"{y:04d}-{m+1:02d}-01"
        return start, end

    def _prev_month_key(today: date = None) -> str:
        today = today or datetime.now(timezone.utc).date()
        y, m = today.year, today.month
        return f"{y-1:04d}-12" if m == 1 else f"{y:04d}-{m-1:02d}"

    def _month_label(month_key: str) -> str:
        return datetime.strptime(month_key, "%Y-%m").strftime("%B %Y")

    # ---- gather automotive CVEs for the month from the local DB -----------
    def gather_cves(month_key: str, limit: int = 40):
        start, end = _month_bounds(month_key)
        conn = get_db_connection()
        cur = conn.cursor()
        try:
            cur.execute(
                f"SELECT cve_id, description, cvss_score, severity, {date_column} AS pub, "
                f"cwe_id, source, is_kev, \"references\" "
                f"FROM cves WHERE {date_column} >= ? AND {date_column} < ? "
                f"AND description IS NOT NULL",
                (start, end),
            )
            rows = cur.fetchall()
        finally:
            conn.close()
        out = []
        for r in rows:
            desc = r["description"] or ""
            name, tier = automotive_match(desc)
            if not name:
                continue
            score = r["cvss_score"]
            try:
                score = float(score) if score is not None else None
            except (TypeError, ValueError):
                score = None
            ref = r["references"] or ""
            first_ref = ref.split(",")[0].split()[0].strip() if ref else ""
            out.append({
                "cve_id": r["cve_id"],
                "score": score,
                "severity": (r["severity"] or _sev_from_score(score)),
                "cwe": r["cwe_id"] or "",
                "published": (r["pub"] or "")[:10],
                "source": r["source"] or "nvd",
                "is_kev": bool(r["is_kev"]),
                "matched": name,
                "subsystem": _subsystem(name + " " + desc),
                "description": desc.strip(),
                "ref": first_ref if first_ref.startswith("http") else "",
            })
        out.sort(key=lambda x: (0 if x["is_kev"] else 1, -(x["score"] or 0), x["cve_id"]))
        return out[:limit]

    def _sev_from_score(score):
        if score is None:
            return "Unknown"
        if score >= 9.0:  return "Critical"
        if score >= 7.0:  return "High"
        if score >= 4.0:  return "Medium"
        if score > 0:     return "Low"
        return "Unknown"

    # ---- AI-drafted, source-verified incidents ----------------------------
    def gather_incidents(month_key: str, max_items: int = 8):
        provider, api_key, model = server_ai_config()
        if not api_key and provider != "ollama":
            print("   [bulletin] no server AI key configured — skipping incident section")
            return [], "no-ai-key"
        label = _month_label(month_key)
        prompt = (
            "You are an automotive-sector threat-intelligence analyst. List real, publicly "
            f"reported cyber INCIDENTS affecting automotive OEMs, their suppliers, dealers, or "
            f"automotive-industry companies that were first reported during {label}. "
            "Only include incidents you are confident are real and that have a public news or "
            "advisory page. Do NOT invent incidents or URLs. If you are unsure, return fewer.\n\n"
            "Respond with ONLY a JSON array (no markdown, no prose). Each element:\n"
            '{"company": str, "category": "ransomware|data breach|supply chain|extortion|other", '
            '"severity": "Critical|High|Medium|Low", "date": "YYYY-MM-DD", '
            '"summary": str (one sentence), "source_url": str (a real article URL)}\n'
            f"Return at most {max_items} items."
        )
        raw = call_ai_provider(prompt, max_tokens=1600, provider=provider, api_key=api_key, model=model)
        if not raw:
            return [], "ai-failed"
        items = _parse_json_array(raw)
        if not items:
            return [], "ai-unparseable"
        verified = []
        for inc in items[:max_items]:
            if not isinstance(inc, dict):
                continue
            name, _ = automotive_match(str(inc.get("company", "")) + " " + str(inc.get("summary", "")))
            if not name:
                # keep only automotive-company incidents
                continue
            if verify_incident(inc):
                verified.append(inc)
        verified.sort(key=lambda x: str(x.get("date", "")), reverse=True)
        return verified, ("ok" if verified else "none-verified")

    def _parse_json_array(raw: str):
        s = raw.strip()
        if s.startswith("```"):
            s = re.sub(r"^```[a-zA-Z]*\n?", "", s).rsplit("```", 1)[0]
        a, b = s.find("["), s.rfind("]")
        if a == -1 or b == -1 or b <= a:
            return []
        try:
            return json.loads(s[a:b + 1])
        except Exception:
            return []

    # ---- stats -------------------------------------------------------------
    def compute_stats(cves):
        sev = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        systems = {}
        top_score = 0.0
        kev = 0
        for c in cves:
            s = c["severity"] if c["severity"] in sev else _sev_from_score(c["score"])
            if s in sev:
                sev[s] += 1
            systems[c["subsystem"]] = systems.get(c["subsystem"], 0) + 1
            if c["score"] and c["score"] > top_score:
                top_score = c["score"]
            if c["is_kev"]:
                kev += 1
        return {"total": len(cves), "sev": sev, "systems": systems,
                "top_score": top_score, "kev": kev}

    # ---- build + store -----------------------------------------------------
    def build_bulletin(month_key: str, max_incidents: int = 8):
        print(f"📄 [bulletin] building {month_key} …")
        cves = gather_cves(month_key)
        incidents, inc_status = gather_incidents(month_key, max_incidents)
        stats = compute_stats(cves)
        generated_at = datetime.now(timezone.utc)
        html = render_bulletin(month_key, cves, incidents, stats, generated_at, inc_status)
        payload = {"month": month_key, "generated_at": generated_at.isoformat(),
                   "stats": stats, "cves": cves, "incidents": incidents,
                   "incident_status": inc_status}
        conn = sqlite3.connect(db_path)
        try:
            conn.execute(
                "INSERT INTO bulletins (month, html, data_json, cve_count, incident_count, "
                "generated_at, status) VALUES (?,?,?,?,?,?, 'published') "
                "ON CONFLICT(month) DO UPDATE SET html=excluded.html, data_json=excluded.data_json, "
                "cve_count=excluded.cve_count, incident_count=excluded.incident_count, "
                "generated_at=excluded.generated_at, status='published'",
                (month_key, html, json.dumps(payload), len(cves), len(incidents),
                 generated_at.isoformat()),
            )
            conn.commit()
        finally:
            conn.close()
        print(f"✅ [bulletin] {month_key}: {len(cves)} CVEs, {len(incidents)} verified incidents ({inc_status})")
        return {"month": month_key, "cve_count": len(cves),
                "incident_count": len(incidents), "incident_status": inc_status}

    def get_bulletin(month_key: str):
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        try:
            row = conn.execute("SELECT * FROM bulletins WHERE month=?", (month_key,)).fetchone()
        finally:
            conn.close()
        return dict(row) if row else None

    def list_bulletins():
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        try:
            rows = conn.execute(
                "SELECT month, cve_count, incident_count, generated_at, status "
                "FROM bulletins ORDER BY month DESC").fetchall()
        finally:
            conn.close()
        return [dict(r) for r in rows]

    # ---- scheduler job -----------------------------------------------------
    def monthly_job():
        """Run daily; only acts on the 1st (UTC). Builds the previous month."""
        today = datetime.now(timezone.utc).date()
        if today.day != 1:
            return
        mk = _prev_month_key(today)
        if get_bulletin(mk):
            print(f"⏰ [bulletin] {mk} already exists — skipping")
            return
        try:
            build_bulletin(mk)
        except Exception as e:
            print(f"⚠️ [bulletin] monthly build failed for {mk}: {e}")

    # =======================================================================
    # ROUTES
    # =======================================================================
    from flask import Response, abort, redirect, request, jsonify
    import threading

    _gen_lock = threading.Lock()
    _gen_state = {"running": False, "month": None, "result": None}

    @app.route("/bulletin")
    def bulletin_latest():
        rows = list_bulletins()
        if not rows:
            return _placeholder_page()
        return Response(get_bulletin(rows[0]["month"])["html"], mimetype="text/html")

    @app.route("/bulletin/<month>")
    def bulletin_month(month):
        if not re.match(r"^\d{4}-\d{2}$", month):
            abort(404)
        b = get_bulletin(month)
        if not b:
            abort(404)
        return Response(b["html"], mimetype="text/html")

    @app.route("/bulletin/<month>/download.html")
    def bulletin_dl_html(month):
        if not re.match(r"^\d{4}-\d{2}$", month):
            abort(404)
        b = get_bulletin(month)
        if not b:
            abort(404)
        return Response(b["html"], mimetype="text/html", headers={
            "Content-Disposition": f'attachment; filename="automotive-bulletin-{month}.html"'})

    @app.route("/bulletin/<month>/download.json")
    def bulletin_dl_json(month):
        if not re.match(r"^\d{4}-\d{2}$", month):
            abort(404)
        b = get_bulletin(month)
        if not b:
            abort(404)
        return Response(b["data_json"], mimetype="application/json", headers={
            "Content-Disposition": f'attachment; filename="automotive-bulletin-{month}.json"'})

    @app.route("/admin/bulletins")
    @admin_required
    def bulletin_admin_list():
        rows = list_bulletins()
        return _admin_list_page(rows, _gen_state)

    @app.route("/admin/bulletin/generate", methods=["POST", "GET"])
    @admin_required
    def bulletin_generate():
        month = request.args.get("month") or request.form.get("month") or _prev_month_key()
        if not re.match(r"^\d{4}-\d{2}$", month):
            return jsonify({"ok": False, "message": "month must be YYYY-MM"}), 400
        with _gen_lock:
            if _gen_state["running"]:
                return jsonify({"ok": False, "message": f"already generating {_gen_state['month']}"}), 409
            _gen_state.update({"running": True, "month": month, "result": None})

        def _worker():
            try:
                res = build_bulletin(month)
                _gen_state["result"] = res
            except Exception as e:
                _gen_state["result"] = {"error": str(e)}
                print(f"⚠️ [bulletin] generate failed: {e}")
            finally:
                _gen_state["running"] = False

        threading.Thread(target=_worker, daemon=True).start()
        return jsonify({"ok": True, "message": f"Generating bulletin for {month} in background."})

    @app.route("/admin/bulletin/status")
    @admin_required
    def bulletin_status():
        return jsonify(_gen_state)

    return {"monthly_job": monthly_job, "build_bulletin": build_bulletin,
            "prev_month_key": _prev_month_key}


# ---------------------------------------------------------------------------
# HTML rendering  (standalone, print-ready, theme-aware)
# ---------------------------------------------------------------------------
_SEV_CLASS = {"Critical": "c", "High": "h", "Medium": "m", "Low": "l", "Unknown": "l"}
_SEV_SHORT = {"Critical": "CRIT", "High": "HIGH", "Medium": "MED", "Low": "LOW", "Unknown": "N/A"}


def render_bulletin(month_key, cves, incidents, stats, generated_at, inc_status):
    label = datetime.strptime(month_key, "%Y-%m").strftime("%B %Y")
    edition = datetime.strptime(month_key, "%Y-%m").strftime("No. %m · %B %Y")
    sev = stats["sev"]
    total = stats["total"]

    # severity bar
    def pct(n):
        return round(100 * n / total, 1) if total else 0
    sevbar = ""
    for k, cls in (("Critical", "s-c"), ("High", "s-h"), ("Medium", "s-m"), ("Low", "s-l")):
        if sev.get(k):
            sevbar += f'<span class="{cls}" style="width:{pct(sev[k])}%"></span>'
    if not sevbar:
        sevbar = '<span class="s-l" style="width:100%;opacity:.4"></span>'

    sevleg = ""
    for k, cls in (("Critical", "c"), ("High", "h"), ("Medium", "m"), ("Low", "l")):
        sevleg += (f'<div class="row"><span class="dot {cls}"></span>'
                   f'<span class="lab">{k}</span><span class="cnt">{sev.get(k,0)}</span></div>')

    # systems breakdown
    systems = sorted(stats["systems"].items(), key=lambda kv: -kv[1])
    smax = max([v for _, v in systems], default=1)
    cats = ""
    for name, n in systems:
        cats += (f'<div class="cat"><span class="name">{escape(name)}</span>'
                 f'<span class="track"><span class="fill" style="width:{max(8,round(100*n/smax))}%"></span></span>'
                 f'<span class="num">{n}</span></div>')
    if not cats:
        cats = '<p class="empty">No automotive CVEs recorded for this month.</p>'

    # CVE rows
    drows = ""
    for c in cves:
        cls = _SEV_CLASS.get(c["severity"], "l")
        short = _SEV_SHORT.get(c["severity"], "N/A")
        score = f'{c["score"]:.1f}' if c["score"] is not None else "—"
        cwe = escape(c["cwe"]) if c["cwe"] else "—"
        kev = '<span class="kevflag">KEV</span>' if c["is_kev"] else ""
        cve_link = escape(c["cve_id"])
        if c["ref"]:
            cve_link = f'<a href="{escape(c["ref"])}" target="_blank" rel="noopener">{escape(c["cve_id"])}</a>'
        desc = escape(c["description"][:280] + ("…" if len(c["description"]) > 280 else ""))
        drows += (
            f'<div class="drow"><div class="top">'
            f'<span class="cve">{cve_link}</span>'
            f'<span class="chip {cls}">{short} <span class="sc">{score}</span></span>{kev}'
            f'<span class="prod">{escape(c["matched"])}</span>'
            f'<span class="meta"><span>{cwe}</span><span>{escape(c["published"])}</span>'
            f'<span class="sys">{escape(c["subsystem"])}</span></span>'
            f'</div><div class="desc">{desc}</div></div>'
        )
    if not drows:
        drows = '<div class="drow"><div class="desc empty">No automotive-attributed CVEs were published in NVD/MITRE/GHSA for this month.</div></div>'

    # incident rows
    irows = ""
    for inc in incidents:
        sv = str(inc.get("severity", "")).capitalize()
        cls = _SEV_CLASS.get(sv, "l")
        short = _SEV_SHORT.get(sv, "INFO")
        dom = escape(inc.get("source_domain", ""))
        url = escape(inc.get("source_url", "#"))
        irows += (
            f'<div class="inc"><div class="itop">'
            f'<span class="chip {cls}">{short}</span>'
            f'<span class="icat">{escape(str(inc.get("category","")).upper())}</span>'
            f'<span class="idate">{escape(str(inc.get("date","")))}</span>'
            f'<span class="verified">✓ source-verified</span></div>'
            f'<h4>{escape(str(inc.get("company","")))}</h4>'
            f'<p>{escape(str(inc.get("summary","")))}</p>'
            f'<a class="isrc" href="{url}" target="_blank" rel="noopener">Source · {dom} →</a>'
            f'</div>'
        )
    if inc_status == "no-ai-key":
        inc_note = ('No AI provider key is configured on the server, so the incident feed was '
                    'skipped for this edition. Set <code>DEEPSEEK_API_KEY</code> (or another '
                    'provider) to enable it.')
        irows = f'<div class="inc-empty">{inc_note}</div>'
    elif not incidents:
        irows = ('<div class="inc-empty">No automotive company incidents passed source '
                 'verification for this month. Items are only shown when their cited source '
                 'URL resolves and names the company.</div>')

    top_score = f'{stats["top_score"]:.1f}' if stats["top_score"] else "—"
    gen_str = generated_at.strftime("%d %b %Y %H:%M UTC")

    return _PAGE.format(
        label=escape(label), edition=escape(edition), month=escape(month_key),
        total=total, crit=sev.get("Critical", 0), high=sev.get("High", 0),
        med=sev.get("Medium", 0), low=sev.get("Low", 0), kev=stats["kev"],
        top_score=top_score, sevbar=sevbar, sevleg=sevleg, cats=cats,
        drows=drows, irows=irows, inc_count=len(incidents), gen=escape(gen_str),
    )


# The full standalone page template. Braces in CSS are doubled for str.format().
_PAGE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Automotive Cyber Bulletin — {label}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Archivo:wght@500;600;700;800&family=IBM+Plex+Mono:wght@400;500;600&family=IBM+Plex+Sans:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
:root{{
  --paper:#f0ede7;--surface:#fbfaf7;--surface-2:#f5f2ec;--ink:#171a20;--ink-2:#4a4f59;
  --ink-muted:#82868f;--rule:#dedad1;--rule-strong:#c7c2b6;--accent:#0d6e78;
  --accent-bright:#0f8b97;--sev-crit:#c53434;--sev-high:#e0743e;--sev-med:#e0a319;
  --sev-low:#4f7bb0;--sev-crit-wash:#f6e4e2;--sev-high-wash:#f8e8de;--sev-med-wash:#f7eed4;
  --sev-low-wash:#e6edf5;--good:#1a8a3f;color-scheme:light;
}}
@media (prefers-color-scheme:dark){{:root:not([data-theme="light"]){{
  --paper:#0c0d10;--surface:#15171c;--surface-2:#1b1e24;--ink:#f2f1ee;--ink-2:#b9bcc4;
  --ink-muted:#82868f;--rule:#282b31;--rule-strong:#363a42;--accent:#26b4c0;
  --accent-bright:#3ac9d5;--sev-crit:#e05a5a;--sev-high:#ec8f5e;--sev-med:#ecb43a;
  --sev-low:#6e9ad0;--sev-crit-wash:#2c1a1c;--sev-high-wash:#2b2018;--sev-med-wash:#2a2413;
  --sev-low-wash:#141d29;--good:#3fbf63;color-scheme:dark;
}}}}
:root[data-theme="dark"]{{
  --paper:#0c0d10;--surface:#15171c;--surface-2:#1b1e24;--ink:#f2f1ee;--ink-2:#b9bcc4;
  --ink-muted:#82868f;--rule:#282b31;--rule-strong:#363a42;--accent:#26b4c0;
  --accent-bright:#3ac9d5;--sev-crit:#e05a5a;--sev-high:#ec8f5e;--sev-med:#ecb43a;
  --sev-low:#6e9ad0;--sev-crit-wash:#2c1a1c;--sev-high-wash:#2b2018;--sev-med-wash:#2a2413;
  --sev-low-wash:#141d29;--good:#3fbf63;color-scheme:dark;
}}
*{{box-sizing:border-box}}
body{{margin:0;background:var(--paper);color:var(--ink);
  font-family:"IBM Plex Sans",system-ui,-apple-system,"Segoe UI",sans-serif;line-height:1.5;
  -webkit-font-smoothing:antialiased;}}
.wrap{{max-width:860px;margin:0 auto;padding:26px 22px 64px}}
.toolbar{{max-width:860px;margin:0 auto;padding:14px 22px 0;display:flex;justify-content:flex-end;gap:8px}}
.btn{{font-family:"IBM Plex Mono",monospace;font-size:11px;font-weight:500;letter-spacing:.04em;
  text-transform:uppercase;cursor:pointer;background:var(--surface);color:var(--ink-2);
  border:1px solid var(--rule-strong);border-radius:7px;padding:7px 12px;text-decoration:none;
  display:inline-flex;align-items:center;gap:6px;transition:.15s}}
.btn:hover{{border-color:var(--accent);color:var(--accent-bright)}}
.btn:focus-visible{{outline:2px solid var(--accent-bright);outline-offset:2px}}
.masthead{{border-top:3px solid var(--ink);border-bottom:1px solid var(--rule-strong);
  padding:20px 0 18px;margin-bottom:26px}}
.eyebrow{{font-family:"IBM Plex Mono",monospace;font-size:11px;font-weight:500;letter-spacing:.22em;
  text-transform:uppercase;color:var(--accent-bright);display:flex;align-items:center;gap:9px}}
.eyebrow::before{{content:"";width:22px;height:2px;background:var(--accent-bright);display:inline-block}}
h1.title{{font-family:"Archivo",sans-serif;font-weight:800;font-size:clamp(2.4rem,7vw,4rem);
  line-height:.94;letter-spacing:-.02em;margin:14px 0 0;text-wrap:balance}}
.edition{{display:flex;flex-wrap:wrap;gap:8px 20px;align-items:baseline;margin-top:16px;padding-top:14px;
  border-top:1px solid var(--rule);font-family:"IBM Plex Mono",monospace;font-size:12.5px;color:var(--ink-2)}}
.edition .vol{{color:var(--ink);font-weight:600}}
.edition .scope{{color:var(--ink-muted)}}
.edition .desk{{margin-left:auto;color:var(--ink-muted)}}
section{{margin-top:36px}}
.sec-head{{display:flex;align-items:baseline;gap:12px;margin-bottom:16px;padding-bottom:9px;
  border-bottom:1px solid var(--rule-strong)}}
.sec-num{{font-family:"IBM Plex Mono",monospace;font-size:12px;font-weight:600;color:var(--accent-bright)}}
.sec-head h2{{font-family:"Archivo",sans-serif;font-weight:700;font-size:1.4rem;letter-spacing:-.01em;margin:0}}
.sec-head .aside{{margin-left:auto;font-family:"IBM Plex Mono",monospace;font-size:11px;color:var(--ink-muted)}}
.glance{{display:grid;grid-template-columns:1.15fr 1fr 1fr;gap:1px;background:var(--rule);
  border:1px solid var(--rule);border-radius:12px;overflow:hidden}}
.tile{{background:var(--surface);padding:18px 18px 16px}}
.tile.hero{{background:var(--surface-2)}}
.tile .k{{font-family:"IBM Plex Mono",monospace;font-size:10.5px;font-weight:500;letter-spacing:.12em;
  text-transform:uppercase;color:var(--ink-muted)}}
.tile .v{{font-family:"Archivo",sans-serif;font-weight:800;line-height:1;margin-top:8px}}
.tile.hero .v{{font-size:3.6rem;color:var(--accent-bright)}}
.tile .v.big{{font-size:2.2rem}}
.tile .sub{{font-size:12.5px;color:var(--ink-2);margin-top:8px}}
.tile .sub b{{color:var(--ink);font-weight:600}}
.splits{{display:flex;gap:6px;margin-top:12px;flex-wrap:wrap}}
.split{{font-family:"IBM Plex Mono",monospace;font-size:11px;font-weight:600;padding:3px 8px;
  border-radius:5px;display:inline-flex;gap:5px;align-items:center}}
.split.c{{background:var(--sev-crit-wash);color:var(--sev-crit)}}
.split.h{{background:var(--sev-high-wash);color:var(--sev-high)}}
.split.m{{background:var(--sev-med-wash);color:var(--sev-med)}}
.coverage{{font-size:12px;color:var(--ink-muted);margin-top:14px;padding-left:13px;
  border-left:2px solid var(--rule-strong);line-height:1.45}}
.coverage b{{color:var(--ink-2)}}
.dist{{display:grid;grid-template-columns:1fr 1fr;gap:26px}}
.dist h3{{font-family:"IBM Plex Mono",monospace;font-size:11px;font-weight:600;letter-spacing:.1em;
  text-transform:uppercase;color:var(--ink-2);margin:0 0 12px}}
.sevbar{{display:flex;height:30px;border-radius:6px;overflow:hidden;background:var(--paper);gap:2px}}
.sevbar span{{display:block}}
.sevbar .s-c{{background:var(--sev-crit)}}.sevbar .s-h{{background:var(--sev-high)}}
.sevbar .s-m{{background:var(--sev-med)}}.sevbar .s-l{{background:var(--sev-low)}}
.sevleg{{display:flex;flex-direction:column;gap:9px;margin-top:14px}}
.sevleg .row{{display:flex;align-items:center;gap:9px;font-size:13px}}
.dot{{width:11px;height:11px;border-radius:3px;flex:none}}
.dot.c{{background:var(--sev-crit)}}.dot.h{{background:var(--sev-high)}}
.dot.m{{background:var(--sev-med)}}.dot.l{{background:var(--sev-low)}}
.sevleg .lab{{color:var(--ink-2)}}
.sevleg .cnt{{margin-left:auto;font-family:"IBM Plex Mono",monospace;font-weight:600;color:var(--ink);
  font-variant-numeric:tabular-nums}}
.cats{{display:flex;flex-direction:column;gap:11px}}
.cat{{display:flex;align-items:center;gap:11px}}
.cat .track{{flex:1;height:9px;border-radius:5px;background:var(--surface-2);overflow:hidden}}
.cat .fill{{height:100%;background:var(--accent);border-radius:5px}}
.cat .name{{font-size:12.5px;color:var(--ink-2);width:135px;flex:none}}
.cat .num{{font-family:"IBM Plex Mono",monospace;font-size:12px;font-weight:600;color:var(--ink);
  width:16px;text-align:right;font-variant-numeric:tabular-nums}}
.empty{{font-size:12.5px;color:var(--ink-muted)}}
.digest{{display:flex;flex-direction:column;gap:1px;background:var(--rule);border:1px solid var(--rule);
  border-radius:12px;overflow:hidden}}
.drow{{background:var(--surface);padding:15px 17px}}
.drow .top{{display:flex;align-items:center;gap:10px;flex-wrap:wrap}}
.cve{{font-family:"IBM Plex Mono",monospace;font-size:13.5px;font-weight:600;color:var(--ink)}}
.cve a{{color:var(--ink);text-decoration:none;border-bottom:1px solid var(--rule-strong)}}
.cve a:hover{{color:var(--accent-bright);border-color:var(--accent-bright)}}
.chip{{font-family:"IBM Plex Mono",monospace;font-size:11px;font-weight:600;padding:2px 8px;
  border-radius:20px;display:inline-flex;gap:5px;align-items:center}}
.chip .sc{{font-variant-numeric:tabular-nums}}
.chip.c{{background:var(--sev-crit-wash);color:var(--sev-crit)}}
.chip.h{{background:var(--sev-high-wash);color:var(--sev-high)}}
.chip.m{{background:var(--sev-med-wash);color:var(--sev-med)}}
.chip.l{{background:var(--sev-low-wash);color:var(--sev-low)}}
.kevflag{{font-family:"IBM Plex Mono",monospace;font-size:10px;font-weight:700;letter-spacing:.06em;
  color:#fff;background:var(--sev-crit);padding:2px 6px;border-radius:4px}}
.prod{{font-size:12px;color:var(--accent-bright);font-family:"IBM Plex Mono",monospace;font-weight:500}}
.meta{{margin-left:auto;font-family:"IBM Plex Mono",monospace;font-size:11px;color:var(--ink-muted);
  display:flex;gap:12px;align-items:center;flex-wrap:wrap}}
.drow .desc{{font-size:13px;color:var(--ink-2);margin-top:7px;line-height:1.5}}
.drow .desc.empty{{margin-top:0}}
.field{{display:flex;flex-direction:column;gap:2px}}
.inc{{padding:16px 0;border-top:1px solid var(--rule)}}
.inc:first-child{{border-top:none}}
.itop{{display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin-bottom:7px}}
.icat{{font-family:"IBM Plex Mono",monospace;font-size:10.5px;font-weight:600;letter-spacing:.08em;
  color:var(--ink-muted)}}
.idate{{font-family:"IBM Plex Mono",monospace;font-size:11px;color:var(--ink-muted)}}
.verified{{margin-left:auto;font-family:"IBM Plex Mono",monospace;font-size:10.5px;font-weight:600;
  color:var(--good)}}
.inc h4{{font-family:"Archivo",sans-serif;font-weight:700;font-size:1.05rem;margin:0 0 5px}}
.inc p{{margin:0 0 7px;font-size:13px;color:var(--ink-2)}}
.isrc{{font-family:"IBM Plex Mono",monospace;font-size:11.5px;color:var(--accent-bright);text-decoration:none}}
.isrc:hover{{text-decoration:underline}}
.inc-empty{{font-size:13px;color:var(--ink-muted);background:var(--surface);border:1px solid var(--rule);
  border-radius:10px;padding:16px;line-height:1.5}}
.inc-empty code{{font-family:"IBM Plex Mono",monospace;font-size:12px;color:var(--ink-2)}}
footer{{margin-top:44px;padding-top:20px;border-top:3px solid var(--ink)}}
.method{{font-size:12px;color:var(--ink-muted);line-height:1.55;margin:0 0 18px}}
.method b{{color:var(--ink-2);font-weight:600}}
.colophon{{display:flex;justify-content:space-between;flex-wrap:wrap;gap:8px;margin-top:8px;
  font-family:"IBM Plex Mono",monospace;font-size:11px;color:var(--ink-muted)}}
.colophon .brand{{color:var(--ink-2);font-weight:600}}
@media (max-width:640px){{
  .glance{{grid-template-columns:1fr}}.dist{{grid-template-columns:1fr;gap:26px}}
  .meta{{margin-left:0;width:100%;margin-top:4px}}
}}
@media print{{
  :root{{--paper:#fff;--surface:#fff;--surface-2:#f6f4ef}}
  .toolbar{{display:none}}body{{font-size:11px}}.wrap{{max-width:none;padding:0 8mm}}
  section{{break-inside:avoid;margin-top:20px}}.drow,.inc,.tile{{break-inside:avoid}}
  a{{color:var(--ink)!important;text-decoration:none}}
  @page{{size:A4;margin:14mm 0}}
}}
@media (prefers-reduced-motion:reduce){{*{{transition:none!important}}}}
</style>
</head>
<body>
<div class="toolbar">
  <button class="btn" id="themeBtn" type="button">◑ Theme</button>
  <a class="btn" href="/bulletin/{month}/download.json">⭳ JSON</a>
  <a class="btn" href="/bulletin/{month}/download.html">⭳ HTML</a>
  <button class="btn" id="printBtn" type="button">⎙ Save as PDF</button>
</div>
<div class="wrap">
  <header class="masthead">
    <div class="eyebrow">TMPVL Cybersecurity · Automotive Threat Desk</div>
    <h1 class="title">Automotive Cyber Bulletin</h1>
    <div class="edition">
      <span class="vol">{edition}</span>
      <span class="scope">Passenger · commercial · EV-charging</span>
      <span class="desk">Monthly digest</span>
    </div>
  </header>

  <section>
    <div class="sec-head"><span class="sec-num">01</span><h2>At a glance</h2>
      <span class="aside">CVE data · {label}</span></div>
    <div class="glance">
      <div class="tile hero"><div class="k">Automotive-attributed CVEs</div>
        <div class="v">{total}</div>
        <div class="splits">
          <span class="split c">{crit} Critical</span>
          <span class="split h">{high} High</span>
          <span class="split m">{med} Medium</span>
        </div></div>
      <div class="tile"><div class="k">Highest severity</div><div class="v big">{top_score}</div>
        <div class="sub">Top CVSS base score recorded across automotive entries this month.</div></div>
      <div class="tile"><div class="k">Actively exploited</div><div class="v big">{kev}</div>
        <div class="sub"><b>KEV.</b> On CISA's Known Exploited Vulnerabilities catalog.</div></div>
    </div>
    <p class="coverage"><b>Coverage.</b> Counts NVD / MITRE / GHSA records whose text names an automotive OEM,
      Tier-1/2 supplier, or EV-charging / diagnostic vendor. Company incidents in §04 are AI-compiled and
      source-verified — the cited URL must resolve and name the company, or the item is dropped.</p>
  </section>

  <section>
    <div class="sec-head"><span class="sec-num">02</span><h2>Distribution</h2></div>
    <div class="dist">
      <div><h3>By severity</h3>
        <div class="sevbar">{sevbar}</div>
        <div class="sevleg">{sevleg}</div>
      </div>
      <div><h3>By affected system</h3><div class="cats">{cats}</div></div>
    </div>
  </section>

  <section>
    <div class="sec-head"><span class="sec-num">03</span><h2>Vulnerability digest</h2>
      <span class="aside">KEV first · then CVSS</span></div>
    <div class="digest">{drows}</div>
  </section>

  <section>
    <div class="sec-head"><span class="sec-num">04</span><h2>In the field</h2>
      <span class="aside">{inc_count} verified · {label}</span></div>
    <div class="field">{irows}</div>
  </section>

  <footer>
    <p class="method"><b>Methodology.</b> CVEs are pulled from the dashboard's local database (NVD 2.0 + MITRE +
      GHSA, with CISA KEV flags) for the month's publication dates and filtered to automotive OEMs, suppliers and
      EV-charging / diagnostic vendors. Company incidents are drafted by the configured AI provider and then
      source-verified: each cited URL is fetched server-side and kept only if it resolves and its page names the
      company. Source verification confirms a live citation, not the accuracy of every claim — treat incidents as
      leads to confirm against primary sources.</p>
    <div class="colophon">
      <span class="brand">TMPVL · Automotive Threat Desk</span>
      <span>Generated {gen} · auto-built on the 1st for the prior month</span>
    </div>
  </footer>
</div>
<script>
(function(){{
  var root=document.documentElement;
  function cur(){{var s=root.getAttribute('data-theme');
    return s?s:(window.matchMedia&&window.matchMedia('(prefers-color-scheme: dark)').matches?'dark':'light');}}
  var t=document.getElementById('themeBtn'); if(t) t.addEventListener('click',function(){{
    root.setAttribute('data-theme',cur()==='dark'?'light':'dark');}});
  var p=document.getElementById('printBtn'); if(p) p.addEventListener('click',function(){{window.print();}});
}})();
</script>
</body>
</html>"""


# ---------------------------------------------------------------------------
# small helper pages
# ---------------------------------------------------------------------------
def _placeholder_page():
    from flask import Response
    html = ("<!doctype html><meta charset=utf-8><title>Automotive Cyber Bulletin</title>"
            "<body style='font-family:system-ui;background:#0c0d10;color:#e2e2e2;"
            "display:flex;min-height:100vh;align-items:center;justify-content:center;text-align:center'>"
            "<div><h1 style='font-weight:800'>Automotive Cyber Bulletin</h1>"
            "<p style='color:#9aa'>No bulletin has been generated yet.<br>An admin can build one from "
            "<code>/admin/bulletins</code>, or it will auto-build on the 1st of the month.</p></div>")
    return Response(html, mimetype="text/html")


def _admin_list_page(rows, gen_state):
    from flask import Response
    from datetime import datetime as _dt
    prev = (_dt.utcnow().replace(day=1))
    y, m = prev.year, prev.month
    default_month = f"{y-1:04d}-12" if m == 1 else f"{y:04d}-{m-1:02d}"
    items = ""
    for r in rows:
        items += (
            f"<tr><td><a href='/bulletin/{r['month']}' target='_blank'>{r['month']}</a></td>"
            f"<td>{r['cve_count']}</td><td>{r['incident_count']}</td>"
            f"<td style='color:#8a8f98'>{(r['generated_at'] or '')[:16].replace('T',' ')}</td>"
            f"<td><a href='/bulletin/{r['month']}/download.html'>HTML</a> · "
            f"<a href='/bulletin/{r['month']}/download.json'>JSON</a></td></tr>"
        )
    if not items:
        items = "<tr><td colspan=5 style='color:#8a8f98;padding:18px'>No bulletins yet.</td></tr>"
    running = gen_state.get("running")
    banner = (f"<div class='note run'>⏳ Generating <b>{gen_state.get('month')}</b>… refresh in ~30s.</div>"
              if running else "")
    html = f"""<!doctype html><meta charset=utf-8><title>Bulletins — Admin</title>
<meta name=viewport content="width=device-width,initial-scale=1">
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;600;700&family=IBM+Plex+Mono:wght@500&display=swap" rel=stylesheet>
<style>
 body{{font-family:'IBM Plex Sans',system-ui;background:#0d0f13;color:#e7e7e4;margin:0;padding:32px}}
 .box{{max-width:760px;margin:0 auto}}
 h1{{font-weight:700;font-size:1.5rem;margin:0 0 4px}}
 .sub{{color:#8a8f98;font-size:.9rem;margin-bottom:24px}}
 .card{{background:#15181e;border:1px solid #262a31;border-radius:12px;padding:20px;margin-bottom:20px}}
 label{{font-size:.8rem;color:#9aa0aa;display:block;margin-bottom:6px;font-family:'IBM Plex Mono'}}
 input{{background:#0d0f13;border:1px solid #2c313a;border-radius:8px;color:#e7e7e4;padding:9px 12px;
   font-family:'IBM Plex Mono';font-size:.9rem;width:140px}}
 button{{background:#0f8b97;border:none;color:#fff;font-weight:600;border-radius:8px;padding:10px 16px;
   cursor:pointer;font-size:.9rem;margin-left:8px}}
 button:hover{{background:#12a0ad}}
 table{{width:100%;border-collapse:collapse;font-size:.9rem}}
 th,td{{text-align:left;padding:9px 10px;border-bottom:1px solid #262a31}}
 th{{color:#8a8f98;font-weight:600;font-size:.75rem;text-transform:uppercase;letter-spacing:.05em}}
 a{{color:#3ac9d5;text-decoration:none}} a:hover{{text-decoration:underline}}
 .note{{padding:10px 14px;border-radius:8px;font-size:.85rem;margin-bottom:16px}}
 .note.run{{background:#123037;color:#8fe3ec}}
 .hint{{color:#8a8f98;font-size:.8rem;margin-top:10px;line-height:1.5}}
 code{{background:#0d0f13;padding:1px 5px;border-radius:4px;font-family:'IBM Plex Mono';font-size:.82rem}}
</style>
<div class=box>
 <h1>Monthly Bulletins</h1>
 <div class=sub>Automotive vulnerability brochures · <a href="/admin">← Admin</a></div>
 {banner}
 <div class=card>
   <label>Generate / rebuild a month</label>
   <form onsubmit="gen(event)">
     <input id=month type=text value="{default_month}" placeholder="YYYY-MM">
     <button type=submit>Generate now</button>
   </form>
   <div class=hint>Runs in the background (AI incident draft + source verification can take ~20–40s).
     The scheduler auto-builds the previous month on the 1st at 00:30 UTC. Latest published bulletin is at
     <code>/bulletin</code>.</div>
 </div>
 <div class=card>
   <table><thead><tr><th>Month</th><th>CVEs</th><th>Incidents</th><th>Generated</th><th>Download</th></tr></thead>
   <tbody>{items}</tbody></table>
 </div>
</div>
<script>
async function gen(e){{e.preventDefault();var m=document.getElementById('month').value.trim();
 var r=await fetch('/admin/bulletin/generate?month='+encodeURIComponent(m),{{method:'POST'}});
 var d=await r.json(); alert(d.message||'started'); if(d.ok) setTimeout(()=>location.reload(),1500);}}
</script>"""
    return Response(html, mimetype="text/html")
