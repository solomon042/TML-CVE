"""
news_archive.py — public monthly archive of the automotive cyber-incident
news feed (the "TMPVL E&E Cyber Security News Feed" emails).

The news monitor (github.com/solomon042/automotive-cve-monitor, private)
commits one file per month to news_archive/<YYYY-MM>.json. This module reads
those files through the GitHub contents API and renders:

    /news            -> redirect to the newest month
    /news/<YYYY-MM>  -> every incident first reported in that month

Env:
    NEWS_ARCHIVE_TOKEN  fine-grained GitHub token, Contents: read-only on the
                        monitor repo (required — the repo is private)
    NEWS_ARCHIVE_REPO   owner/repo (default solomon042/automotive-cve-monitor)
    NEWS_ARCHIVE_PATH   folder in that repo (default news_archive)

Self-contained: app.py only calls register(app).
"""

import os
import re
import threading
import time
from datetime import datetime

import requests
from flask import Response, abort, redirect
from markupsafe import escape

_REPO = os.environ.get("NEWS_ARCHIVE_REPO", "solomon042/automotive-cve-monitor")
_PATH = os.environ.get("NEWS_ARCHIVE_PATH", "news_archive")
_TTL = 600          # seconds; new incidents show up within 10 minutes
_MONTH_RE = re.compile(r"^\d{4}-\d{2}$")

_cache = {}         # key -> (fetched_at, value)
_lock = threading.Lock()


def _gh(url_path, raw=False):
    token = os.environ.get("NEWS_ARCHIVE_TOKEN", "")
    if not token:
        raise RuntimeError("NEWS_ARCHIVE_TOKEN is not set")
    headers = {"Authorization": f"Bearer {token}",
               "X-GitHub-Api-Version": "2022-11-28",
               "Accept": "application/vnd.github.raw+json" if raw
               else "application/vnd.github+json"}
    r = requests.get(f"https://api.github.com/repos/{_REPO}/contents/{url_path}",
                     headers=headers, timeout=15)
    if r.status_code == 404:
        return None
    r.raise_for_status()
    return r.json()


def _cached(key, loader):
    """TTL cache; on fetch errors keep serving the last good copy."""
    now = time.time()
    with _lock:
        hit = _cache.get(key)
    if hit and now - hit[0] < _TTL:
        return hit[1]
    try:
        value = loader()
    except (requests.RequestException, RuntimeError, ValueError) as e:
        print(f"[news_archive] fetch failed for {key}: {e}")
        if hit:
            return hit[1]
        raise
    with _lock:
        _cache[key] = (now, value)
    return value


def list_months():
    def load():
        items = _gh(_PATH) or []
        return sorted((i["name"][:7] for i in items
                       if i.get("type") == "file"
                       and re.fullmatch(r"\d{4}-\d{2}\.json", i.get("name", ""))),
                      reverse=True)
    return _cached("__months__", load)


def get_month(month):
    return _cached(month, lambda: _gh(f"{_PATH}/{month}.json", raw=True))


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------
_SEV_COL = {"critical": "#C0392B", "high": "#E08A1E",
            "medium": "#C9A227", "low": "#5E6E84"}
_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
_INFO_BLUE = "#1565C0"


def _label(month, fmt="%B %Y"):
    return datetime.strptime(month, "%Y-%m").strftime(fmt)


def _safe_url(u):
    u = (u or "").strip()
    return u if re.match(r"^https?://", u, re.I) else ""


def _card(r):
    sev = (r.get("severity") or "").lower()
    hist = bool(r.get("historical"))
    col = _INFO_BLUE if hist else _SEV_COL.get(sev, "#5E6E84")
    tag = ('<span class="tag info">INFORMATION</span>' if hist
           else '<span class="tag">INCIDENT</span>')
    when = escape((r.get("first_seen") or "")[:10])
    try:
        when = datetime.strptime(str(when), "%Y-%m-%d").strftime("%d %b %Y")
    except ValueError:
        pass
    older = (f' · older attack (~{escape(r.get("timeframe") or "earlier")}), not new'
             if hist else "")
    desc = escape((r.get("info_note") or r.get("summary") or "")[:400])
    impact = escape((r.get("impact") or "")[:200])
    impact_html = (f'<div class="impact" style="border-left-color:{col}">'
                   f'<span style="color:{col}">⚠ Impact:</span> {impact}</div>'
                   if impact else "")
    n = r.get("report_count") or 1
    srcs = escape(", ".join((r.get("sources") or [])[:5]))
    corro = (f'<div class="meta">Reported by {n} outlet{"s" if n != 1 else ""}'
             f'{" · " + str(srcs) if n > 1 and srcs else ""}</div>')
    link = _safe_url(r.get("link"))
    link_html = (f'<a class="src" href="{escape(link)}" target="_blank" '
                 f'rel="noopener noreferrer">Read source →</a>' if link else "")
    return f"""
    <div class="card" style="border-left-color:{col}">
      <div class="top" style="color:{col}">{tag} {escape(sev.upper() or "N/A")}
        · <span class="itype">{escape(r.get("incident_type") or "incident")}</span>
        <span class="when">· first reported {when}{older}</span></div>
      <div class="org">{escape(r.get("organization") or "Unknown")}
        <span class="sector">{escape(r.get("sector") or "—")}</span></div>
      <div class="desc">{desc}</div>
      {impact_html}{corro}{link_html}
    </div>"""


def render_month(month, data, months):
    recs = list((data or {}).get("incidents", {}).values())
    recs.sort(key=lambda r: (bool(r.get("historical")),
                             _SEV_ORDER.get((r.get("severity") or "").lower(), 4),
                             r.get("first_seen", "")))
    incidents = [r for r in recs if not r.get("historical")]
    info = [r for r in recs if r.get("historical")]
    count = lambda s: sum(1 for r in incidents
                          if (r.get("severity") or "").lower() == s)

    tabs = "".join(
        f'<a class="tab{" on" if m == month else ""}" href="/news/{m}">'
        f'{_label(m, "%b %Y")}</a>' for m in months)

    def tile(n, lab, color):
        return (f'<div class="tile"><div class="n" style="color:{color}">{n}</div>'
                f'<div class="l">{lab}</div></div>')

    body = ""
    if incidents:
        body += (f'<div class="sec red">Incidents first reported in {_label(month)}'
                 f' — {len(incidents)}</div>' + "".join(_card(r) for r in incidents))
    else:
        body += ('<div class="none">✓ No new automotive cyber incidents were '
                 f'reported in {_label(month)}</div>')
    if info:
        body += (f'<div class="sec blue">ℹ Information — older incidents back in the '
                 f'news ({len(info)}) · not new attacks</div>'
                 + "".join(_card(r) for r in info))

    updated = escape(((data or {}).get("updated") or "")[:16].replace("T", " "))
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Cyber News Archive · {_label(month)}</title>
<style>
  *{{box-sizing:border-box}}
  body{{margin:0;background:#F4F6F9;font-family:Arial,Helvetica,sans-serif;color:#334155}}
  .wrap{{max-width:820px;margin:0 auto;padding:20px 16px 40px}}
  .head{{background:#0E2A47;border-radius:14px 14px 0 0;padding:22px 24px 8px}}
  .title{{font:700 22px Arial;color:#fff}}
  .sub{{font:600 11px Arial;color:#9FC0E0;letter-spacing:.12em;text-transform:uppercase;margin-top:6px}}
  .tabs{{background:#0E2A47;padding:14px 20px 4px;display:flex;flex-wrap:wrap;gap:8px}}
  .tab{{font:600 12px Arial;color:#9FC0E0;text-decoration:none;padding:7px 14px;
        border:1px solid #1E4A78;border-radius:16px}}
  .tab.on{{background:#E08A1E;border-color:#E08A1E;color:#0E2A47}}
  .tiles{{background:#0E2A47;padding:12px 18px 20px;display:grid;
          grid-template-columns:repeat(5,1fr);gap:10px}}
  .tile{{background:#13365C;border:1px solid #1E4A78;border-radius:10px;padding:14px 6px;text-align:center}}
  .tile .n{{font:700 24px Arial}}
  .tile .l{{font:600 9px Arial;letter-spacing:.07em;text-transform:uppercase;color:#9FC0E0;margin-top:4px}}
  .main{{background:#fff;border:1px solid #E2E8F0;border-top:none;border-radius:0 0 14px 14px;padding:20px 18px}}
  .sec{{font:600 11px Arial;letter-spacing:.1em;text-transform:uppercase;padding-bottom:8px;margin:6px 0 16px}}
  .sec.red{{color:#C0392B;border-bottom:2px solid #C0392B}}
  .sec.blue{{color:#1565C0;border-bottom:2px solid #BBD3EE;margin-top:26px}}
  .none{{background:#E6F4EC;border:1px solid #BFE3CD;border-radius:10px;padding:18px;
         text-align:center;font:700 15px Arial;color:#1E7A52;margin-bottom:16px}}
  .card{{border:1px solid #E2E8F0;border-left:5px solid;border-radius:10px;padding:14px 18px;margin-bottom:12px}}
  .top{{font:700 11px Arial;letter-spacing:.05em}}
  .tag{{color:#fff;background:#5E6E84;padding:2px 8px;border-radius:10px;margin-right:4px}}
  .tag.info{{background:#1565C0}}
  .itype{{color:#5E6E84;text-transform:uppercase}}
  .when{{font-weight:500;color:#94A3B8}}
  .org{{font:600 15px Arial;color:#0E2A47;margin:6px 0 2px}}
  .sector{{font:500 10px Arial;color:#fff;background:#5E6E84;padding:2px 7px;border-radius:10px}}
  .desc{{font-size:13px;line-height:1.5;margin-top:5px}}
  .impact{{font:600 12px Arial;color:#0E2A47;margin-top:8px;background:#F4F6F9;
           border-left:3px solid;padding:7px 10px;border-radius:4px}}
  .meta{{font-size:11px;color:#6B7A90;margin-top:8px}}
  .src{{display:inline-block;margin-top:9px;font:600 12px Arial;color:#1565C0;text-decoration:none}}
  .foot{{font-size:10.5px;color:#94A3B8;margin-top:14px;line-height:1.6;border-top:1px solid #E2E8F0;padding-top:12px}}
  @media (max-width:560px){{.tiles{{grid-template-columns:repeat(3,1fr)}}.title{{font-size:18px}}}}
</style></head>
<body><div class="wrap">
  <div class="head">
    <div class="title">TMPVL E&amp;E Cyber Security News Feed</div>
    <div class="sub">Monthly archive · {_label(month)} · Automotive threat intelligence</div>
  </div>
  <div class="tabs">{tabs}</div>
  <div class="tiles">
    {tile(len(incidents), "Incidents", "#FF6B66" if incidents else "#FFFFFF")}
    {tile(count("critical"), "Critical", "#FF6B66")}
    {tile(count("high"), "High", "#FFC04D")}
    {tile(count("medium"), "Medium", "#E6C35C")}
    {tile(len(info), "Info", "#7FB2E8")}
  </div>
  <div class="main">
    {body}
    <div class="foot">Every automotive cyber incident the monitor first reported in
      {_label(month)}, de-duplicated across outlets. INFORMATION = an older attack that
      resurfaced in the news that month (not a new incident). Verify against primary
      sources before circulating.{f" · Last updated {updated} UTC" if updated else ""}</div>
  </div>
</div></body></html>"""


def _message_page(title, msg, status=200):
    html = (f"<!doctype html><meta charset=utf-8><meta name=viewport "
            f"content='width=device-width,initial-scale=1'><title>{escape(title)}</title>"
            f"<body style='margin:0;font-family:Arial,sans-serif;background:#F4F6F9;"
            f"display:flex;min-height:100vh;align-items:center;justify-content:center;"
            f"text-align:center;padding:16px'><div><h1 style='color:#0E2A47'>"
            f"{escape(title)}</h1><p style='color:#5E6E84'>{escape(msg)}</p></div>")
    return Response(html, status=status, mimetype="text/html")


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
def register(app):
    @app.route("/news")
    def news_latest():
        try:
            months = list_months()
        except Exception:
            return _message_page("Cyber News Archive",
                                 "The archive is temporarily unavailable.", 503)
        if not months:
            return _message_page("Cyber News Archive", "No archived months yet.")
        return redirect(f"/news/{months[0]}")

    @app.route("/news/<month>")
    def news_month(month):
        if not _MONTH_RE.match(month):
            abort(404)
        try:
            months = list_months()
            data = get_month(month) if month in months else None
        except Exception:
            return _message_page("Cyber News Archive",
                                 "The archive is temporarily unavailable.", 503)
        if data is None:
            return _message_page("Cyber News Archive",
                                 f"No archive for {month}.", 404)
        return Response(render_month(month, data, months), mimetype="text/html")
