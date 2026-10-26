"""
news_archive.py — public pages for the automotive cyber-incident news feed
(the "TMPVL E&E Cyber Security News Feed" emails).

The news monitor (github.com/solomon042/automotive-cve-monitor, private)
commits, per month:
    news_archive/<YYYY-MM>.json   incidents + connected-car tech vulnerabilities
    newsletter/<YYYY-MM>.json     the Claude-written monthly newsletter
This module reads them through the GitHub contents API and renders:

    /news                  -> redirect to the newest archive month
    /news/<YYYY-MM>        -> everything first reported in that month
    /newsletter            -> redirect to the newest newsletter
    /newsletter/<YYYY-MM>  -> the monthly newsletter

Env:
    NEWS_ARCHIVE_TOKEN  fine-grained GitHub token, Contents: read-only on the
                        monitor repo (required — the repo is private)
    NEWS_ARCHIVE_REPO   owner/repo (default solomon042/automotive-cve-monitor)

Self-contained: app.py only calls register(app).
"""

import os
import re
import threading
import time
from collections import Counter
from datetime import datetime

import requests
from flask import Response, abort, redirect
from markupsafe import escape

_REPO = os.environ.get("NEWS_ARCHIVE_REPO", "solomon042/automotive-cve-monitor")
_ARCHIVE = "news_archive"
_NEWSLETTER = "newsletter"
_TTL = 600          # seconds; new items show up within 10 minutes
_MONTH_RE = re.compile(r"^\d{4}-\d{2}$")
_BRAND = {"name": "Solomon Raja", "title": "Cyber Security", "initials": "SR"}

_cache = {}         # key -> (fetched_at, value)
_lock = threading.Lock()


# ---------------------------------------------------------------------------
# Data access (GitHub contents API, cached)
# ---------------------------------------------------------------------------
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


def list_months(folder=_ARCHIVE):
    def load():
        items = _gh(folder) or []
        return sorted((i["name"][:7] for i in items
                       if i.get("type") == "file"
                       and re.fullmatch(r"\d{4}-\d{2}\.json", i.get("name", ""))),
                      reverse=True)
    return _cached(f"{folder}/__months__", load)


def get_month(month, folder=_ARCHIVE):
    return _cached(f"{folder}/{month}", lambda: _gh(f"{folder}/{month}.json", raw=True))


# ---------------------------------------------------------------------------
# Shared bits
# ---------------------------------------------------------------------------
_SEV_COL = {"critical": "#C0392B", "high": "#E08A1E",
            "medium": "#C9A227", "low": "#5E6E84"}
_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
_INFO_BLUE = "#1565C0"
_TECH = "#6D28D9"


def _label(month, fmt="%B %Y"):
    return datetime.strptime(month, "%Y-%m").strftime(fmt)


def _safe_url(u):
    u = (u or "").strip()
    return u if re.match(r"^https?://", u, re.I) else ""


def _sev(r):
    return (r.get("severity") or "").lower()


def _date(iso):
    try:
        return datetime.strptime(str(iso)[:10], "%Y-%m-%d").strftime("%d %b %Y")
    except ValueError:
        return ""


def _clean_timeframe(tf):
    """Keep only real dates like '2025', 'Jun 2026', 'June 2026'."""
    tf = (tf or "").strip()
    return tf if re.fullmatch(r"(?:[A-Za-z]{3,9}\.? )?(?:19|20)\d{2}", tf) else ""


_BASE_CSS = """
  *{box-sizing:border-box}
  body{margin:0;background:#F4F6F9;font-family:Arial,Helvetica,sans-serif;color:#334155}
  a{color:#1565C0}
  .wrap{max-width:860px;margin:0 auto;padding:20px 16px 40px}
  .head{background:#0E2A47;border-radius:14px 14px 0 0;padding:22px 24px 8px;
        display:flex;justify-content:space-between;align-items:center;gap:16px}
  .title{font:700 22px Arial;color:#fff}
  .sub{font:600 11px Arial;color:#9FC0E0;letter-spacing:.12em;text-transform:uppercase;margin-top:6px}
  .brand{display:flex;align-items:center;gap:10px;flex-shrink:0}
  .brand .ini{width:38px;height:38px;border-radius:9px;background:#E08A1E;color:#0E2A47;
              font:700 15px Arial;display:flex;align-items:center;justify-content:center}
  .brand .nm{font:700 13px Arial;color:#fff;text-align:right}
  .brand .tt{font:600 10px Arial;color:#E08A1E;letter-spacing:.06em;text-transform:uppercase;text-align:right}
  .nav{background:#0E2A47;padding:10px 20px 4px;display:flex;flex-wrap:wrap;gap:8px;align-items:center}
  .tab{font:600 12px Arial;color:#9FC0E0;text-decoration:none;padding:7px 14px;
       border:1px solid #1E4A78;border-radius:16px;background:none;cursor:pointer}
  .tab.on{background:#E08A1E;border-color:#E08A1E;color:#0E2A47}
  .navlbl{font:600 10px Arial;color:#5F86AE;letter-spacing:.1em;text-transform:uppercase;margin-right:4px}
  .main{background:#fff;border:1px solid #E2E8F0;border-top:none;border-radius:0 0 14px 14px;padding:20px 18px}
  .foot{font-size:10.5px;color:#94A3B8;margin-top:18px;line-height:1.6;border-top:1px solid #E2E8F0;padding-top:12px}
  .links{margin-top:10px;display:flex;flex-wrap:wrap;gap:14px;font:600 12px Arial}
  .links a{text-decoration:none}
  .printbtn{margin-left:auto}
  @media (max-width:600px){.head{flex-direction:column;align-items:flex-start}.brand .nm,.brand .tt{text-align:left}
                           .title{font-size:18px}}
  @media print{body{background:#fff}.nav,.filters,.printbtn,.links{display:none!important}
               .wrap{padding:0}.card,.block{break-inside:avoid}}
"""


def _brand_html():
    return (f'<div class="brand"><div><div class="nm">{_BRAND["name"]}</div>'
            f'<div class="tt">{_BRAND["title"]}</div></div>'
            f'<div class="ini">{_BRAND["initials"]}</div></div>')


def _links_html(month):
    return (f'<div class="links"><a href="/">← CVE Dashboard</a>'
            f'<a href="/bulletin">Monthly CVE Bulletin</a>'
            f'<a href="/news/{month}">Incident archive · {_label(month, "%b %Y")}</a>'
            f'<a href="/newsletter/{month}">Newsletter · {_label(month, "%b %Y")}</a></div>')


def _page(title, sub, nav, body, foot, extra_css="", script=""):
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title}</title>
<style>{_BASE_CSS}{extra_css}</style></head>
<body><div class="wrap">
  <div class="head"><div>
      <div class="title">TMPVL E&amp;E Cyber Security News Feed</div>
      <div class="sub">{sub}</div></div>{_brand_html()}</div>
  {nav}
  <div class="main">{body}<div class="foot">{foot}</div></div>
</div>{script}</body></html>"""


# ---------------------------------------------------------------------------
# /news/<month> — monthly archive
# ---------------------------------------------------------------------------
_ARCHIVE_CSS = """
  .tiles{background:#0E2A47;padding:12px 18px 20px;display:grid;
         grid-template-columns:repeat(6,1fr);gap:10px}
  .tile{background:#13365C;border:1px solid #1E4A78;border-radius:10px;padding:14px 6px;text-align:center}
  .tile .n{font:700 24px Arial}
  .tile .l{font:600 9px Arial;letter-spacing:.07em;text-transform:uppercase;color:#9FC0E0;margin-top:4px}
  .summary{background:#F4F6F9;border-radius:10px;padding:12px 16px;font-size:13px;line-height:1.6;
           color:#0E2A47;margin-bottom:14px}
  .filters{display:flex;flex-wrap:wrap;gap:8px;margin-bottom:16px}
  .filters .tab{color:#1565C0;border-color:#BBD3EE}
  .filters .tab.on{background:#1565C0;border-color:#1565C0;color:#fff}
  .sec{font:600 11px Arial;letter-spacing:.1em;text-transform:uppercase;padding-bottom:8px;margin:8px 0 16px}
  .sec.red{color:#C0392B;border-bottom:2px solid #C0392B}
  .sec.blue{color:#1565C0;border-bottom:2px solid #BBD3EE;margin-top:26px}
  .sec.purple{color:#6D28D9;border-bottom:2px solid #D9CCF7;margin-top:26px}
  .none{background:#E6F4EC;border:1px solid #BFE3CD;border-radius:10px;padding:18px;
        text-align:center;font:700 15px Arial;color:#1E7A52;margin-bottom:16px}
  .card{border:1px solid #E2E8F0;border-left:5px solid;border-radius:10px;padding:14px 18px;margin-bottom:12px}
  .top{font:700 11px Arial;letter-spacing:.05em}
  .pill{color:#fff;padding:2px 9px;border-radius:10px;margin-right:6px}
  .itype{color:#5E6E84;text-transform:uppercase}
  .when{font-weight:500;color:#94A3B8}
  .org{font:600 15px Arial;color:#0E2A47;margin:6px 0 2px}
  .sector{font:500 10px Arial;color:#fff;background:#5E6E84;padding:2px 7px;border-radius:10px}
  .cve{font:600 10px Arial;color:#6D28D9;background:#F1EBFD;padding:2px 7px;border-radius:10px;margin-right:4px}
  .desc{font-size:13px;line-height:1.5;margin-top:5px}
  .impact{font:600 12px Arial;color:#0E2A47;margin-top:8px;background:#F4F6F9;
          border-left:3px solid;padding:7px 10px;border-radius:4px;line-height:1.5}
  .meta{font-size:11px;color:#6B7A90;margin-top:8px}
  .src{display:inline-block;margin-top:9px;font:600 12px Arial;color:#1565C0;text-decoration:none}
  .empty-filter{display:none;text-align:center;color:#94A3B8;font-size:13px;padding:18px}
  @media (max-width:600px){.tiles{grid-template-columns:repeat(3,1fr)}}
"""

_FILTER_JS = """<script>
(function(){
  var btns=document.querySelectorAll('.filters .tab');
  function apply(f){
    var shown=0;
    document.querySelectorAll('.card').forEach(function(c){
      var ok = f==='all' || (c.dataset.tags||'').split(' ').indexOf(f)>=0;
      c.style.display = ok ? '' : 'none'; if(ok) shown++;
    });
    document.querySelectorAll('.sec').forEach(function(s){
      var grp=s.dataset.group, any=false;
      document.querySelectorAll('.card[data-group="'+grp+'"]').forEach(function(c){
        if(c.style.display!=='none') any=true;});
      s.style.display = any ? '' : 'none';
    });
    var em=document.querySelector('.empty-filter'); if(em) em.style.display = shown ? 'none':'block';
  }
  btns.forEach(function(b){ b.addEventListener('click',function(){
    btns.forEach(function(x){x.classList.remove('on')}); b.classList.add('on'); apply(b.dataset.f);
  });});
  var p=document.querySelector('.printbtn'); if(p) p.addEventListener('click',function(){window.print()});
})();
</script>"""


def _incident_card(r):
    sev = _sev(r)
    hist = bool(r.get("historical"))
    col = _INFO_BLUE if hist else _SEV_COL.get(sev, "#5E6E84")
    pill = (f'<span class="pill" style="background:{_INFO_BLUE}">INFORMATION</span>'
            if hist else
            f'<span class="pill" style="background:{col}">{escape(sev.upper() or "N/A")}</span>')
    sev_txt = f'{escape(sev.upper())} · ' if hist and sev else ""
    when = _date(r.get("first_seen"))
    tf = _clean_timeframe(r.get("timeframe"))
    older = (f" · older attack ({escape(tf)}) · not new" if tf else " · older attack · not new") if hist else ""
    desc = escape((r.get("info_note") or r.get("summary") or "")[:400])
    impact = escape((r.get("impact") or "")[:200])
    impact_html = (f'<div class="impact" style="border-left-color:{col}">'
                   f'<span style="color:{col}">⚠ Impact:</span> {impact}</div>' if impact else "")
    n = r.get("report_count") or 1
    srcs = escape(", ".join((r.get("sources") or [])[:5]))
    corro = (f'<div class="meta">Reported by {n} outlets · {srcs}</div>' if n > 1 else "")
    link = _safe_url(r.get("link"))
    link_html = (f'<a class="src" href="{escape(link)}" target="_blank" '
                 f'rel="noopener noreferrer">Read source →</a>' if link else "")
    sector = (r.get("sector") or "").lower()
    tags = ["incident" if not hist else "info", sector if sector in ("oem", "supplier") else "other"]
    if sev in ("critical", "high") and not hist:
        tags.append("crit")
    group = "info" if hist else "incident"
    return f"""
    <div class="card" data-group="{group}" data-tags="{' '.join(tags)}" style="border-left-color:{col}">
      <div class="top" style="color:{col}">{pill}{sev_txt}<span class="itype">{escape(r.get("incident_type") or "incident")}</span>
        <span class="when">· first reported {when}{older}</span></div>
      <div class="org">{escape(r.get("organization") or "Unknown")}
        <span class="sector">{escape(r.get("sector") or "—")}</span></div>
      <div class="desc">{desc}</div>
      {impact_html}{corro}{link_html}
    </div>"""


def _vuln_card(v):
    sev = _sev(v)
    col = _SEV_COL.get(sev, "#5E6E84")
    cves = "".join(f'<span class="cve">{escape(c)}</span>' for c in (v.get("cves") or [])[:5])
    vendor = f' · {escape(v["vendor"])}' if v.get("vendor") else ""
    n = v.get("report_count") or 1
    srcs = escape(", ".join((v.get("sources") or [])[:5]))
    corro = f'<div class="meta">Reported by {n} outlets · {srcs}</div>' if n > 1 else ""
    link = _safe_url(v.get("link"))
    link_html = (f'<a class="src" href="{escape(link)}" target="_blank" '
                 f'rel="noopener noreferrer">Read source →</a>' if link else "")
    tags = ["tech"] + (["crit"] if sev in ("critical", "high") else [])
    return f"""
    <div class="card" data-group="tech" data-tags="{' '.join(tags)}" style="border-left-color:{_TECH}">
      <div class="top" style="color:{_TECH}"><span class="pill" style="background:{col}">{escape(sev.upper() or "N/A")}</span>
        <span style="text-transform:uppercase">{escape(v.get("domain") or "")}</span>
        <span class="when">· first reported {_date(v.get("first_seen"))}</span></div>
      <div class="org">{escape(v.get("technology") or "")}{vendor}</div>
      <div>{cves}</div>
      <div class="desc">{escape((v.get("summary") or "")[:400])}</div>
      <div class="impact" style="border-left-color:{_TECH};background:#F6F2FE">
        <span style="color:{_TECH}">🚗 In the vehicle:</span> {escape(v.get("why_relevant") or "")}<br>
        <span style="color:{_TECH}">✔ Action:</span> {escape(v.get("action") or "")}</div>
      {corro}{link_html}
    </div>"""


def _summary_line(month, incidents, vulns):
    if not incidents and not vulns:
        return ""
    parts = [f"<b>{len(incidents)}</b> incident{'s' if len(incidents) != 1 else ''}"]
    if vulns:
        parts.append(f"<b>{len(vulns)}</b> connected-car vulnerabilit{'y' if len(vulns) == 1 else 'ies'}")
    if incidents:
        types = Counter((r.get("incident_type") or "incident").lower() for r in incidents)
        top, cnt = types.most_common(1)[0]
        parts.append(f"most common: <b>{escape(top)}</b> ({cnt})")
        sectors = Counter((r.get("sector") or "other").lower() for r in incidents)
        parts.append(f"OEMs <b>{sectors.get('oem', 0)}</b> · suppliers <b>{sectors.get('supplier', 0)}</b>"
                     f" · other <b>{sum(sectors.values()) - sectors.get('oem', 0) - sectors.get('supplier', 0)}</b>")
        worst = min(incidents, key=lambda r: (_SEV_ORDER.get(_sev(r), 4), r.get("first_seen", "")))
        if _sev(worst):
            parts.append(f"most severe: <b>{escape(worst.get('organization') or '')}</b> "
                         f"({escape(_sev(worst).capitalize())})")
    return f'<div class="summary">{_label(month)} at a glance — ' + " · ".join(parts) + "</div>"


def render_month(month, data, months, has_newsletter=False):
    data = data or {}
    recs = list(data.get("incidents", {}).values())
    recs.sort(key=lambda r: (_SEV_ORDER.get(_sev(r), 4), r.get("first_seen", "")))
    incidents = [r for r in recs if not r.get("historical")]
    info = [r for r in recs if r.get("historical")]
    vulns = sorted(data.get("vulns", {}).values(),
                   key=lambda r: (_SEV_ORDER.get(_sev(r), 4), r.get("first_seen", "")))
    count = lambda s: sum(1 for r in incidents if _sev(r) == s)

    tabs = "".join(f'<a class="tab{" on" if m == month else ""}" href="/news/{m}">'
                   f'{_label(m, "%b %Y")}</a>' for m in months)
    nl = (f'<a class="tab" href="/newsletter/{month}">📰 Newsletter</a>' if has_newsletter else "")
    nav = (f'<div class="nav"><span class="navlbl">Archive</span>{tabs}{nl}'
           f'<button class="tab printbtn" type="button">🖨 Print / PDF</button></div>')

    def tile(n, lab, color):
        return (f'<div class="tile"><div class="n" style="color:{color}">{n}</div>'
                f'<div class="l">{lab}</div></div>')
    nav += (f'<div class="tiles">'
            f'{tile(len(incidents), "Incidents", "#FF6B66" if incidents else "#FFFFFF")}'
            f'{tile(count("critical"), "Critical", "#FF6B66")}'
            f'{tile(count("high"), "High", "#FFC04D")}'
            f'{tile(count("medium"), "Medium", "#E6C35C")}'
            f'{tile(len(vulns), "Car-tech", "#C4A8FF")}'
            f'{tile(len(info), "Info", "#7FB2E8")}</div>')

    filters = ('<div class="filters">'
               '<button class="tab on" data-f="all" type="button">All</button>'
               '<button class="tab" data-f="oem" type="button">OEM</button>'
               '<button class="tab" data-f="supplier" type="button">Supplier</button>'
               '<button class="tab" data-f="crit" type="button">Critical + High</button>'
               + ('<button class="tab" data-f="tech" type="button">🚗 Car-tech</button>' if vulns else "")
               + '</div>')

    body = _summary_line(month, incidents, vulns) + filters
    if incidents:
        body += (f'<div class="sec red" data-group="incident">Incidents first reported in '
                 f'{_label(month)} — {len(incidents)}</div>'
                 + "".join(_incident_card(r) for r in incidents))
    else:
        body += ('<div class="none">✓ No new automotive cyber incidents were '
                 f'reported in {_label(month)}</div>')
    if vulns:
        body += (f'<div class="sec purple" data-group="tech">🚗 Connected-car tech watch — '
                 f'{len(vulns)} vulnerabilit{"y" if len(vulns) == 1 else "ies"} in in-vehicle technology</div>'
                 + "".join(_vuln_card(v) for v in vulns))
    if info:
        body += (f'<div class="sec blue" data-group="info">ℹ Information — older incidents back in the '
                 f'news ({len(info)}) · not new attacks</div>'
                 + "".join(_incident_card(r) for r in info))
    body += '<div class="empty-filter">Nothing matches this filter.</div>'

    updated = escape((data.get("updated") or "")[:16].replace("T", " "))
    foot = (f"Every automotive cyber incident and connected-car vulnerability the monitor first "
            f"reported in {_label(month)}, de-duplicated across outlets. INFORMATION = an older "
            f"attack that resurfaced in the news (not a new incident). Verify against primary "
            f"sources before circulating.{f' · Last updated {updated} UTC' if updated else ''}"
            + _links_html(month))
    return _page(f"Cyber News Archive · {_label(month)}",
                 f"Monthly archive · {_label(month)} · Automotive threat intelligence",
                 nav, body, foot, _ARCHIVE_CSS, _FILTER_JS)


# ---------------------------------------------------------------------------
# /newsletter/<month> — the monthly newsletter
# ---------------------------------------------------------------------------
_NL_CSS = """
  .hero{padding:6px 4px 18px;border-bottom:1px solid #E2E8F0;margin-bottom:20px}
  .kicker{font:700 11px Arial;color:#E08A1E;letter-spacing:.14em;text-transform:uppercase}
  .hl{font:800 30px Georgia,'Times New Roman',serif;color:#0E2A47;line-height:1.2;margin:8px 0 10px}
  .stand{font:400 17px Georgia,serif;color:#475569;line-height:1.55}
  .nums{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;margin:0 0 22px}
  .num{background:#0E2A47;border-radius:12px;padding:16px;text-align:center}
  .num .v{font:800 26px Arial;color:#FFC04D}
  .num .l{font:600 11px Arial;color:#9FC0E0;margin-top:6px;line-height:1.4}
  .block{margin:0 0 24px}
  .bh{font:700 12px Arial;letter-spacing:.12em;text-transform:uppercase;color:#0E2A47;
      border-bottom:2px solid #0E2A47;padding-bottom:7px;margin-bottom:14px}
  .prose{font:400 15px Georgia,serif;line-height:1.7;color:#1F2937}
  .themes{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:14px}
  .theme{border:1px solid #E2E8F0;border-top:4px solid #E08A1E;border-radius:10px;padding:14px 16px}
  .theme h3{font:700 15px Arial;color:#0E2A47;margin:0 0 8px}
  .theme p{font-size:13.5px;line-height:1.6;margin:0}
  .spot{background:#FFF7EC;border:1px solid #F5D6A8;border-radius:12px;padding:18px 20px}
  .spot .org{font:700 11px Arial;color:#B4650E;letter-spacing:.1em;text-transform:uppercase}
  .spot h3{font:700 19px Georgia,serif;color:#0E2A47;margin:6px 0 10px}
  .spot ul{margin:10px 0 0 18px;padding:0;font-size:13.5px;line-height:1.7}
  .tw{border:1px solid #E2E8F0;border-left:5px solid #6D28D9;border-radius:10px;padding:12px 16px;margin-bottom:10px}
  .tw .d{font:700 10.5px Arial;color:#6D28D9;letter-spacing:.08em;text-transform:uppercase}
  .tw h4{font:700 14.5px Arial;color:#0E2A47;margin:5px 0 6px}
  .tw p{font-size:13.5px;line-height:1.6;margin:0}
  .acts{list-style:none;margin:0;padding:0}
  .acts li{display:flex;gap:12px;padding:10px 0;border-bottom:1px solid #EEF2F6;font-size:14px;line-height:1.55}
  .acts .who{flex:0 0 130px;font:700 11px Arial;color:#1565C0;text-transform:uppercase;letter-spacing:.06em;padding-top:3px}
  .outlook{background:#0E2A47;color:#E2ECF7;border-radius:12px;padding:18px 20px;font:400 15px Georgia,serif;line-height:1.7}
  .outlook b{color:#FFC04D;font-family:Arial;font-size:11px;letter-spacing:.12em;text-transform:uppercase;display:block;margin-bottom:6px}
  @media (max-width:600px){.hl{font-size:24px}.acts li{flex-direction:column;gap:2px}.acts .who{flex:none}}
"""


def render_newsletter(month, nl, months, archive_months):
    c = (nl or {}).get("content", {})
    tabs = "".join(f'<a class="tab{" on" if m == month else ""}" href="/newsletter/{m}">'
                   f'{_label(m, "%b %Y")}</a>' for m in months)
    arch = (f'<a class="tab" href="/news/{month}">🗂 Incident archive</a>'
            if month in archive_months else "")
    nav = (f'<div class="nav"><span class="navlbl">Newsletter</span>{tabs}{arch}'
           f'<button class="tab printbtn" type="button">🖨 Print / PDF</button></div>'
           f'<div style="background:#0E2A47;height:14px"></div>')

    def paras(t):
        return "".join(f"<p>{escape(p)}</p>" for p in str(t or "").split("\n") if p.strip())

    body = (f'<div class="hero"><div class="kicker">Monthly newsletter · {_label(month)}</div>'
            f'<div class="hl">{escape(c.get("headline") or _label(month))}</div>'
            f'<div class="stand">{escape(c.get("standfirst") or "")}</div></div>')
    nums = c.get("by_the_numbers") or []
    if nums:
        body += '<div class="nums">' + "".join(
            f'<div class="num"><div class="v">{escape(n.get("value", ""))}</div>'
            f'<div class="l">{escape(n.get("label", ""))}</div></div>' for n in nums[:4]) + "</div>"
    if c.get("executive_summary"):
        body += (f'<div class="block"><div class="bh">Executive summary</div>'
                 f'<div class="prose">{paras(c["executive_summary"])}</div></div>')
    themes = c.get("themes") or []
    if themes:
        body += ('<div class="block"><div class="bh">Key themes this month</div><div class="themes">'
                 + "".join(f'<div class="theme"><h3>{escape(t.get("title", ""))}</h3>'
                           f'<p>{escape(t.get("body", ""))}</p></div>' for t in themes[:4])
                 + "</div></div>")
    sp = c.get("spotlight") or {}
    if sp.get("title"):
        lessons = "".join(f"<li>{escape(x)}</li>" for x in (sp.get("lessons") or [])[:4])
        body += (f'<div class="block"><div class="bh">Incident spotlight</div><div class="spot">'
                 f'<div class="org">{escape(sp.get("organization", ""))}</div>'
                 f'<h3>{escape(sp.get("title", ""))}</h3>'
                 f'<div class="prose" style="font-size:14.5px">{paras(sp.get("body"))}</div>'
                 + (f"<ul>{lessons}</ul>" if lessons else "") + "</div></div>")
    tw = c.get("car_tech_watch") or []
    if tw:
        body += ('<div class="block"><div class="bh">🚗 Connected-car tech watch</div>'
                 + "".join(f'<div class="tw"><div class="d">{escape(t.get("domain", ""))}</div>'
                           f'<h4>{escape(t.get("technology", ""))}</h4>'
                           f'<p>{escape(t.get("body", ""))}</p></div>' for t in tw[:6])
                 + "</div>")
    acts = c.get("actions") or []
    if acts:
        body += ('<div class="block"><div class="bh">Recommended actions</div><ul class="acts">'
                 + "".join(f'<li><span class="who">{escape(a.get("audience", ""))}</span>'
                           f'<span>{escape(a.get("action", ""))}</span></li>' for a in acts[:8])
                 + "</ul></div>")
    if c.get("outlook"):
        body += (f'<div class="block"><div class="outlook"><b>Outlook</b>'
                 f'{escape(c["outlook"])}</div></div>')

    gen = _date((nl or {}).get("generated_at"))
    foot = (f"Written with Claude from the incidents and connected-car vulnerabilities the "
            f"monitor recorded in {_label(month)}{f' · generated {gen}' if gen else ''}. "
            f"Verify against primary sources before circulating." + _links_html(month))
    script = ("<script>(function(){var p=document.querySelector('.printbtn');"
              "if(p)p.addEventListener('click',function(){window.print()});})();</script>")
    return _page(f"Automotive Cyber Newsletter · {_label(month)}",
                 f"Monthly newsletter · {_label(month)} · Automotive threat intelligence",
                 nav, body, foot, _NL_CSS, script)


def _message_page(title, msg, status=200):
    html = (f"<!doctype html><meta charset=utf-8><meta name=viewport "
            f"content='width=device-width,initial-scale=1'><title>{escape(title)}</title>"
            f"<body style='margin:0;font-family:Arial,sans-serif;background:#F4F6F9;"
            f"display:flex;min-height:100vh;align-items:center;justify-content:center;"
            f"text-align:center;padding:16px'><div><h1 style='color:#0E2A47'>"
            f"{escape(title)}</h1><p style='color:#5E6E84'>{escape(msg)}</p>"
            f"<p><a href='/' style='color:#1565C0'>← CVE Dashboard</a></p></div>")
    return Response(html, status=status, mimetype="text/html")


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
def register(app):
    def latest(folder, prefix, title):
        try:
            months = list_months(folder)
        except Exception:
            return _message_page(title, "Temporarily unavailable — please try again shortly.", 503)
        if not months:
            return _message_page(title, "Nothing published yet.")
        return redirect(f"{prefix}/{months[0]}")

    @app.route("/news")
    def news_latest():
        return latest(_ARCHIVE, "/news", "Cyber News Archive")

    @app.route("/news/<month>")
    def news_month(month):
        if not _MONTH_RE.match(month):
            abort(404)
        try:
            months = list_months(_ARCHIVE)
            data = get_month(month, _ARCHIVE) if month in months else None
            try:
                has_nl = month in list_months(_NEWSLETTER)
            except Exception:
                has_nl = False
        except Exception:
            return _message_page("Cyber News Archive",
                                 "Temporarily unavailable — please try again shortly.", 503)
        if data is None:
            return _message_page("Cyber News Archive", f"No archive for {month}.", 404)
        return Response(render_month(month, data, months, has_nl), mimetype="text/html")

    @app.route("/newsletter")
    def newsletter_latest():
        return latest(_NEWSLETTER, "/newsletter", "Automotive Cyber Newsletter")

    @app.route("/newsletter/<month>")
    def newsletter_month(month):
        if not _MONTH_RE.match(month):
            abort(404)
        try:
            months = list_months(_NEWSLETTER)
            nl = get_month(month, _NEWSLETTER) if month in months else None
            try:
                arch = list_months(_ARCHIVE)
            except Exception:
                arch = []
        except Exception:
            return _message_page("Automotive Cyber Newsletter",
                                 "Temporarily unavailable — please try again shortly.", 503)
        if nl is None:
            return _message_page("Automotive Cyber Newsletter",
                                 f"No newsletter for {month} yet.", 404)
        return Response(render_newsletter(month, nl, months, arch), mimetype="text/html")
