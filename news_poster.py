"""
news_poster.py — monthly one-page A4 awareness posters for the automotive
cyber-incident news feed, in two styles:

    rings — dark navy, glowing circuit traces, four neon rings, watching eyes
    car   — white, connected car sending Bluetooth / Wi-Fi / 4G signals

Each poster is one self-contained SVG (fonts embedded) built from the month's
archive data, so it can be viewed, printed, or downloaded as SVG / PNG.

    /poster                          -> newest month
    /poster/<YYYY-MM>                -> both styles, with download buttons
    /poster/<YYYY-MM>/<style>.svg    -> the poster (?download=1 to save)
    /poster/<YYYY-MM>/<style>/print  -> A4 print view (Save as PDF)
"""

import base64
import math
import os
import random
import re
from datetime import datetime
from html import escape as _esc

from flask import Response, abort, redirect

W, H = 1000, 1414                      # A4 portrait (210 x 297)
STYLES = {"rings": "Circuit rings", "car": "Connected car"}
_FONT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static", "fonts")
_font_css = None


def x(s):
    return _esc(str(s), quote=True)


def _fonts():
    """@font-face rules with the fonts embedded, so the SVG renders the same
    everywhere (browser, <img>, canvas → PNG, other apps)."""
    global _font_css
    if _font_css is None:
        rules = []
        for fam, fn, extra in (("Archivo", "archivo-latin.woff2", "font-weight:400 900;font-stretch:62% 125%;"),
                               ("IBM Plex Mono", "plexmono-600-latin.woff2", "font-weight:600;")):
            try:
                with open(os.path.join(_FONT_DIR, fn), "rb") as f:
                    b64 = base64.b64encode(f.read()).decode()
                rules.append(f"@font-face{{font-family:'{fam}';{extra}"
                             f"src:url(data:font/woff2;base64,{b64}) format('woff2');}}")
            except OSError:
                pass
        _font_css = "".join(rules)
    return _font_css


_CSS = """
.d{font-family:'Archivo','Arial Narrow',Arial,sans-serif}
.m{font-family:'IBM Plex Mono',Menlo,monospace;font-weight:600}
"""


# ---------------------------------------------------------------------------
# Month facts
# ---------------------------------------------------------------------------
_SEV = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def facts(month, data):
    recs = list((data or {}).get("incidents", {}).values())
    new = sorted([r for r in recs if not r.get("historical")],
                 key=lambda r: (_SEV.get((r.get("severity") or "").lower(), 4), r.get("first_seen", "")))
    names = []
    for r in new:
        n = re.split(r"\s*[(/,]", (r.get("organization") or "").strip())[0].strip()
        if n and n not in names:
            names.append(n[:22])
    return {
        "label": datetime.strptime(month, "%Y-%m").strftime("%B %Y"),
        "short": datetime.strptime(month, "%Y-%m").strftime("%b %Y"),
        "n": len(new),
        "ransom": sum(1 for r in new if "ransom" in (r.get("incident_type") or "").lower()),
        "vulns": len((data or {}).get("vulns", {})),
        "names": names[:3],
    }


def _plural(n, one, many):
    return f"{n} {one if n == 1 else many}"


# ---------------------------------------------------------------------------
# Generative circuit traces (deterministic per month)
# ---------------------------------------------------------------------------
def _circuits(seed, color, light):
    r = random.Random(seed)
    u = W / 60
    out = []
    for _ in range(int(W / 9)):
        cx = r.random() * W
        cy = H * (0.42 + r.random() * 0.36) if light else H * (0.25 + r.random() * 0.75)
        ang = r.choice([0, 45, -45, 90, 180, -90])
        segs = 2 + r.randrange(4)
        a = (0.10 + r.random() * 0.10) if light else (0.18 + r.random() * 0.45)
        sw = u * (0.18 + r.random() * 0.22)
        pts = [(cx, cy)]
        for _s in range(segs):
            ln = u * (3 + r.random() * 9)
            cx += math.cos(math.radians(ang)) * ln
            cy += math.sin(math.radians(ang)) * ln
            pts.append((cx, cy))
            ang += 45 if r.random() < 0.5 else -45
        d = "M" + " L".join(f"{p[0]:.1f} {p[1]:.1f}" for p in pts)
        pad = u * (0.45 + r.random() * 0.4)
        out.append(f'<path d="{d}" stroke="rgba({color},{a:.2f})" stroke-width="{sw:.1f}"/>'
                   f'<circle cx="{cx:.1f}" cy="{cy:.1f}" r="{pad:.1f}" stroke="rgba({color},{a:.2f})" '
                   f'stroke-width="{u * 0.25:.1f}"/>')
        if not light and r.random() < 0.25:
            out.append(f'<rect x="{cx - u:.1f}" y="{cy - u * 0.6:.1f}" width="{u * 2:.1f}" height="{u * 1.2:.1f}" '
                       f'fill="rgba({color},{a * 0.6:.2f})" stroke="none"/>')
    filt = '' if light else ' filter="url(#cglow)"'
    return (f'<g fill="none" stroke-linecap="round" stroke-linejoin="round"{filt}>' + "".join(out) + "</g>")


def _chip(xpos, y, text, fill, stroke, fg, size=17.5, bold_num=None):
    w = len(text) * (size * 0.6 + 0.6) + 48
    return (f'<rect x="{xpos:.0f}" y="{y - size - 9:.0f}" width="{w:.0f}" height="{size + 22:.0f}" rx="{(size + 22) / 2:.0f}" '
            f'fill="{fill}" stroke="{stroke}" stroke-width="2.5"/>'
            f'<text class="m" x="{xpos + 22:.0f}" y="{y + 2:.0f}" font-size="{size}" fill="{fg}" letter-spacing=".6">{x(text)}</text>'), w


def _svg_open(title):
    return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" width="{W}" height="{H}">'
            f'<title>{x(title)}</title><style>{_fonts()}{_CSS}</style>')


# ---------------------------------------------------------------------------
# Style 1 — Circuit rings
# ---------------------------------------------------------------------------
_RINGS = [  # cx, cy, colour, lines
    (230, 640, "#B57BFF", ["Spot and", "report phishing"]),
    (760, 590, "#7C8CFF", ["Patch every", "laptop, tool", "&amp; ECU"]),
    (510, 870, "#59E08A", ["Strengthen", "your passwords"]),
    (190, 1060, "#3FD3F0", ["Protect", "customer &amp;", "vehicle data"]),
]


def _ring(cx, cy, c, lines, i):
    g = (f'<g transform="translate({cx - 150} {cy - 150}) scale(1.5)" filter="url(#rg{i})">'
         f'<circle cx="100" cy="100" r="92" fill="rgba(6,14,34,.82)" stroke="{c}" stroke-width="3"/>'
         f'<circle cx="100" cy="100" r="84" fill="none" stroke="{c}" stroke-width="2" stroke-dasharray="2 6" opacity=".9"/>'
         f'<circle cx="100" cy="100" r="74" fill="none" stroke="{c}" stroke-width="9" stroke-dasharray="22 6 4 6 10 6" opacity=".45"/>'
         f'<circle cx="100" cy="100" r="64" fill="none" stroke="{c}" stroke-width="1.5" opacity=".7"/>'
         f'<g transform="translate(100 8)"><path d="M0 -12 L11 -7 L11 2 Q11 10 0 15 Q-11 10 -11 2 L-11 -7 Z" '
         f'fill="#060E22" stroke="{c}" stroke-width="2.5"/><path d="M0 -6 L6 -3 L6 2 Q6 6 0 9 Q-6 6 -6 2 L-6 -3 Z" fill="{c}"/></g>'
         f'<g fill="{c}"><circle cx="30" cy="62" r="3"/><circle cx="172" cy="128" r="3"/>'
         f'<circle cx="58" cy="166" r="2.5"/><circle cx="150" cy="40" r="2.5"/></g></g>')
    lh = 33
    y0 = cy - (len(lines) - 1) * lh / 2 + 10
    t = "".join(f'<tspan x="{cx}" y="{y0 + k * lh:.0f}">{ln}</tspan>' for k, ln in enumerate(lines))
    return g + f'<text class="d" text-anchor="middle" font-size="27" font-weight="700" fill="#fff">{t}</text>'


def poster_rings(month, f):
    filters = "".join(f'<filter id="rg{i}" x="-20%" y="-20%" width="140%" height="140%">'
                      f'<feDropShadow dx="0" dy="0" stdDeviation="6" flood-color="{c}"/></filter>'
                      for i, (_, _, c, _) in enumerate(_RINGS))
    defs = (f'<defs>'
            f'<radialGradient id="bg1" cx=".7" cy=".35" r=".9"><stop offset="0" stop-color="#1C3F7A"/>'
            f'<stop offset=".45" stop-color="#0F2550"/><stop offset="1" stop-color="#081530"/></radialGradient>'
            f'<filter id="cglow" x="-5%" y="-5%" width="110%" height="110%"><feGaussianBlur stdDeviation="5" result="b"/>'
            f'<feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge></filter>'
            f'<filter id="tglow"><feGaussianBlur stdDeviation="10" result="b"/><feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge></filter>'
            f'<filter id="bglow"><feDropShadow dx="0" dy="0" stdDeviation="7" flood-color="#5BA8FF"/></filter>'
            f'<linearGradient id="shade" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#081530" stop-opacity="0"/>'
            f'<stop offset=".55" stop-color="#050C1C" stop-opacity=".85"/><stop offset="1" stop-color="#03070F"/></linearGradient>'
            f'<radialGradient id="skin" cx=".5" cy=".5" r=".6"><stop offset="0" stop-color="#C9B49C"/><stop offset="1" stop-color="#6E5E4E"/></radialGradient>'
            f'<radialGradient id="iris" cx=".5" cy=".5" r=".5"><stop offset="0" stop-color="#0A0A0A"/><stop offset=".45" stop-color="#1B2A3A"/>'
            f'<stop offset=".75" stop-color="#2E8BC0"/><stop offset="1" stop-color="#123047"/></radialGradient>'
            f'{filters}</defs>')
    eye = ('<path d="M0 40 Q 70 -22 150 30 Q 70 88 0 40 Z" fill="url(#skin)" opacity=".9"/>'
           '<circle cx="78" cy="36" r="24" fill="url(#iris)"/><circle cx="78" cy="36" r="9" fill="#020305"/>'
           '<circle cx="70" cy="28" r="4" fill="#fff" opacity=".7"/>'
           '<path d="M0 40 Q 70 -22 150 30" fill="none" stroke="#1A120C" stroke-width="5"/>')
    eyes = (f'<svg x="0" y="{H - 340}" width="{W}" height="340" viewBox="0 0 600 340" preserveAspectRatio="xMidYMax slice">'
            f'<rect width="600" height="340" fill="url(#shade)"/>'
            f'<g transform="translate(232 205)">{eye}</g><g transform="translate(560 190) scale(-1 1)">{eye}</g>'
            f'<rect y="250" width="600" height="90" fill="#03070F" opacity=".55"/></svg>')

    # month chips
    chips_txt = [f["label"]]
    chips_txt.append(f"{_plural(f['n'], 'automotive company', 'automotive companies')} hit" if f["n"]
                     else "No new incidents")
    if f["ransom"]:
        chips_txt.append(f"{f['ransom']} by ransomware")
    elif f["vulns"]:
        chips_txt.append(f"{_plural(f['vulns'], 'car-tech flaw', 'car-tech flaws')}")
    chips, cx = [], 70
    for t in chips_txt:
        svg, w = _chip(cx, 356, t, "rgba(8,21,48,.8)", "rgba(91,168,255,.6)", "#fff")
        chips.append(svg)
        cx += w + 18

    body = (
        f'<rect width="{W}" height="{H}" fill="url(#bg1)"/>'
        + _circuits(f"rings-{month}", "91,168,255", False)
        # title box with glowing brackets
        + '<g fill="none" stroke="#5BA8FF" stroke-width="7" filter="url(#bglow)">'
          '<path d="M70 190 V70 H190"/><path d="M800 180 V300 H680"/></g>'
        + '<text class="m" x="110" y="128" font-size="19" fill="#9FC6FF" letter-spacing="3">TMPVL E&amp;E · CYBER SECURITY</text>'
        + '<text class="d" x="110" y="205" font-size="74" font-weight="900" fill="#fff">SECURE VEHICLES</text>'
        + '<text class="d" x="110" y="279" font-size="74" font-weight="900" fill="#fff">START '
          '<tspan fill="#FFC93C" filter="url(#tglow)">WITH US</tspan></text>'
        + '<rect x="870" y="75" width="70" height="70" rx="16" fill="#E08A1E"/>'
          '<text class="d" x="905" y="121" text-anchor="middle" font-size="28" font-weight="800" fill="#0E2A47">SR</text>'
        + eyes
        + "".join(_ring(cx_, cy_, c, lines, i) for i, (cx_, cy_, c, lines) in enumerate(_RINGS))
        + "".join(chips)
        + '<text class="d" x="500" y="1336" text-anchor="middle" font-size="23" fill="#E3ECFA">Attackers look for the gaps in our defences.</text>'
        + '<text class="d" x="500" y="1371" text-anchor="middle" font-size="23" fill="#9FC6FF">'
          'Report anything suspicious to IT / SOC and protect our vehicles, together.</text>'
    )
    return _svg_open(f"Secure vehicles start with us — {f['label']}") + defs + body + "</svg>"


# ---------------------------------------------------------------------------
# Style 3 — Connected car (white)
# ---------------------------------------------------------------------------
def poster_car(month, f):
    if f["n"]:
        fact = f"{f['short']}: {_plural(f['n'], 'automotive company', 'automotive companies')} hit"
        if f["names"]:
            fact += " — " + ", ".join(f["names"])
    else:
        fact = f"{f['short']}: no new incidents. Stay alert."
    if f["vulns"]:
        fact += f" · {_plural(f['vulns'], 'car-tech flaw', 'car-tech flaws')}"
    if len(fact) > 76:
        fact = fact[:75].rstrip(" ,·—") + "…"

    car = (
        '<svg x="-20" y="585" width="1040" height="470" viewBox="0 0 640 330" overflow="visible">'
        '<defs><marker id="arr" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="5" markerHeight="5" orient="auto">'
        '<path d="M0 0 L10 5 L0 10 Z" fill="#E11D2E"/></marker></defs>'
        '<g fill="none" stroke="#2563EB" stroke-width="3" stroke-linecap="round">'
        '<path d="M330 92 a26 26 0 0 1 36 -14" opacity=".9"/><path d="M322 74 a48 48 0 0 1 60 -26" opacity=".6"/>'
        '<path d="M314 56 a70 70 0 0 1 84 -38" opacity=".35"/></g>'
        '<path d="M400 40 C470 10 520 -20 560 -70" fill="none" stroke="#E11D2E" stroke-width="3" stroke-dasharray="8 8" marker-end="url(#arr)"/>'
        '<path d="M40 232 L40 200 Q44 180 74 174 L170 160 Q222 112 286 98 L420 94 Q478 98 522 146 L590 160 Q620 168 622 196 L622 232 Z" '
        'fill="#F1F5F9" stroke="#0B1220" stroke-width="5" stroke-linejoin="round"/>'
        '<path d="M200 156 Q236 124 284 114 L346 112 L346 156 Z" fill="#DBEAFE" stroke="#0B1220" stroke-width="4"/>'
        '<path d="M360 112 L416 112 Q460 116 494 152 L360 156 Z" fill="#DBEAFE" stroke="#0B1220" stroke-width="4"/>'
        '<path d="M330 94 L330 78" stroke="#0B1220" stroke-width="4"/>'
        '<g fill="none" stroke="#2563EB" stroke-width="2.5" opacity=".8"><path d="M90 214 H190 L210 194 H300"/>'
        '<path d="M300 194 H420 L440 214 H560"/><path d="M250 214 V194"/><path d="M380 214 L400 194"/></g>'
        '<g fill="#fff" stroke="#2563EB" stroke-width="2.5"><circle cx="90" cy="214" r="5"/><circle cx="560" cy="214" r="5"/>'
        '<circle cx="300" cy="194" r="5"/><circle cx="250" cy="214" r="5"/></g>'
        '<circle cx="150" cy="236" r="42" fill="#0B1220"/><circle cx="150" cy="236" r="18" fill="#94A3B8"/>'
        '<circle cx="510" cy="236" r="42" fill="#0B1220"/><circle cx="510" cy="236" r="18" fill="#94A3B8"/>'
        '<line x1="0" y1="280" x2="640" y2="280" stroke="#CBD5E1" stroke-width="3"/>'
        '<g class="m" font-size="15">'
        '<rect x="70" y="300" width="120" height="30" rx="15" fill="#0B1220"/><text x="130" y="320" fill="#fff" text-anchor="middle">BLUETOOTH</text>'
        '<rect x="205" y="300" width="90" height="30" rx="15" fill="#0B1220"/><text x="250" y="320" fill="#fff" text-anchor="middle">WI-FI</text>'
        '<rect x="310" y="300" width="100" height="30" rx="15" fill="#0B1220"/><text x="360" y="320" fill="#fff" text-anchor="middle">4G / 5G</text>'
        '<rect x="425" y="300" width="120" height="30" rx="15" fill="#E11D2E"/><text x="485" y="320" fill="#fff" text-anchor="middle">APP / CLOUD</text></g>'
        '<g fill="none" stroke="#E11D2E" stroke-width="3.5" stroke-linejoin="round"><path d="M598 92 l14 -24 l14 24 z"/>'
        '<path d="M560 120 l11 -19 l11 19 z"/></g>'
        '<g class="d" fill="#E11D2E" font-weight="900" text-anchor="middle"><text x="612" y="89" font-size="15">!</text>'
        '<text x="571" y="118" font-size="12">!</text></g></svg>')

    hood = ('<svg x="752" y="100" width="214" height="246" viewBox="0 0 200 230">'
            '<path d="M10 230 C16 182 42 162 70 154 C62 136 58 116 62 94 C68 56 90 34 110 34 C132 34 154 56 160 94 '
            'C164 116 160 136 152 154 C180 162 196 182 200 230 Z" fill="#0B1220"/>'
            '<path d="M82 104 C82 78 96 64 110 64 C124 64 138 78 138 104 C138 132 128 150 110 152 C92 150 82 132 82 104 Z" fill="#000"/>'
            '<circle cx="98" cy="104" r="4" fill="#E11D2E"/><circle cx="122" cy="104" r="4" fill="#E11D2E"/></svg>')

    checks = [("PAIR CAREFULLY", ["Only pair test phones", "and tools you own.", "Remove old pairings."]),
              ("PATCH FAST", ["Track Bluetooth, Wi-Fi", "and modem fixes", "from suppliers."]),
              ("REPORT", ["Seen a strange signal,", "app or request?", "Tell IT / SOC."])]
    chk = ""
    for k, (t, lines) in enumerate(checks):
        cx = 70 + k * 293
        chk += (f'<rect x="{cx}" y="1160" width="267" height="6" fill="#0B1220"/>'
                f'<text class="d" x="{cx}" y="1200" font-size="25" font-weight="800" fill="#0B1220">{t}</text>'
                + "".join(f'<text class="d" x="{cx}" y="{1234 + j * 31}" font-size="22" fill="#1F2937">{x(ln)}</text>'
                          for j, ln in enumerate(lines)))

    sub = ["Bluetooth, Wi-Fi, 4G/5G telematics and phone apps",
           "keep vehicles connected. Every one of them is a",
           "door an attacker can knock on."]
    body = (
        f'<rect width="{W}" height="{H}" fill="#FFFFFF"/>'
        + _circuits(f"car-{month}", "15,23,42", True)
        + f'<text class="m" x="70" y="83" font-size="18" fill="#64748B" letter-spacing="2.5">TMPVL E&amp;E · CYBER SECURITY · {x(f["short"].upper())}</text>'
        + '<g class="d" font-size="100" font-weight="900" style="font-stretch:62%" fill="#0B1220" lengthAdjust="spacingAndGlyphs">'
          '<text x="66" y="222" textLength="520" lengthAdjust="spacingAndGlyphs">IS YOUR CAR</text>'
          '<text x="66" y="314" textLength="380" lengthAdjust="spacingAndGlyphs" fill="#E11D2E">TALKING</text>'
          '<text x="66" y="406" textLength="640" lengthAdjust="spacingAndGlyphs">TO STRANGERS?</text></g>'
        + hood
        + "".join(f'<text class="d" x="70" y="{482 + i * 37}" font-size="26" fill="#334155">{x(s)}</text>'
                  for i, s in enumerate(sub))
        + car
        + '<rect x="70" y="1062" width="590" height="62" fill="#E11D2E"/>'
          '<text class="d" x="98" y="1105" font-size="35" font-weight="800" fill="#fff" textLength="534" lengthAdjust="spacingAndGlyphs">PROTECT CONNECTED VEHICLES</text>'
        + chk
        + f'<text class="m" x="70" y="1372" font-size="16" fill="#64748B">{x(fact)}</text>'
        + '<rect x="880" y="1330" width="60" height="60" rx="14" fill="#E08A1E"/>'
          '<text class="d" x="910" y="1369" text-anchor="middle" font-size="24" font-weight="800" fill="#0E2A47">SR</text>'
    )
    return _svg_open(f"Is your car talking to strangers? — {f['label']}") + body + "</svg>"


def build(style, month, data):
    f = facts(month, data)
    return poster_rings(month, f) if style == "rings" else poster_car(month, f)


# ---------------------------------------------------------------------------
# Pages
# ---------------------------------------------------------------------------
_PAGE_JS = """<script>
(function(){
  function utf8b64(s){ return btoa(unescape(encodeURIComponent(s))); }
  document.querySelectorAll('[data-png]').forEach(function(btn){
    btn.addEventListener('click', function(){
      var old = btn.textContent; btn.textContent = 'Preparing…'; btn.disabled = true;
      fetch(btn.dataset.png).then(function(r){ return r.text(); }).then(function(svg){
        var img = new Image();
        img.onload = function(){
          setTimeout(function(){
            var c = document.createElement('canvas'); c.width = 2480; c.height = 3508;
            var ctx = c.getContext('2d'); ctx.drawImage(img, 0, 0, c.width, c.height);
            c.toBlob(function(b){
              var a = document.createElement('a'); a.href = URL.createObjectURL(b);
              a.download = btn.dataset.name; document.body.appendChild(a); a.click();
              setTimeout(function(){ URL.revokeObjectURL(a.href); a.remove(); }, 1500);
              btn.textContent = old; btn.disabled = false;
            }, 'image/png');
          }, 250);
        };
        img.onerror = function(){ btn.textContent = 'PNG failed — use SVG'; btn.disabled = false; };
        img.src = 'data:image/svg+xml;base64,' + utf8b64(svg);
      }).catch(function(){ btn.textContent = 'PNG failed — use SVG'; btn.disabled = false; });
    });
  });
})();
</script>"""

_PAGE_CSS = """
  .posters{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,330px),1fr));gap:26px}
  .pc{display:flex;flex-direction:column;gap:12px;min-width:0}
  .pc h3{font:700 15px Arial;color:#0E2A47;margin:0}
  .pc h3 small{font:600 11px Arial;color:#94A3B8;letter-spacing:.08em;text-transform:uppercase;margin-left:6px}
  .pc img{width:100%;height:auto;border-radius:4px;box-shadow:0 1px 2px rgba(0,0,0,.08),0 10px 26px rgba(14,42,71,.2);background:#fff}
  .dl{display:flex;flex-wrap:wrap;gap:8px}
  .dl a,.dl button{font:600 12.5px Arial;padding:8px 14px;border-radius:18px;text-decoration:none;cursor:pointer;
                   border:1px solid #1565C0;color:#1565C0;background:#fff}
  .dl .pri{background:#1565C0;color:#fff}
  .dl button:disabled{opacity:.6;cursor:wait}
  .hint{font-size:12.5px;color:#64748B;line-height:1.55;margin-top:16px}
"""


def render_page(month, months, page_fn, label_fn, links_fn):
    tabs = "".join(f'<a class="tab{" on" if m == month else ""}" href="/poster/{m}">{label_fn(m, "%b %Y")}</a>'
                   for m in months)
    nav = (f'<div class="nav"><span class="navlbl">Poster</span>{tabs}</div>'
           f'<div style="background:#0E2A47;height:14px"></div>')
    cards = ""
    for style, name in STYLES.items():
        fn = f"tmpvl-cyber-poster-{month}-{style}"
        cards += (f'<div class="pc"><h3>{name}<small>A4 · {label_fn(month, "%B %Y")}</small></h3>'
                  f'<img src="/poster/{month}/{style}.svg" alt="{name} poster for {label_fn(month)}" loading="lazy">'
                  f'<div class="dl"><button class="pri" type="button" data-png="/poster/{month}/{style}.svg" '
                  f'data-name="{fn}.png">⬇ Download PNG</button>'
                  f'<a href="/poster/{month}/{style}.svg?download=1">⬇ SVG</a>'
                  f'<a href="/poster/{month}/{style}/print" target="_blank" rel="noopener">🖨 Print / PDF</a></div></div>')
    body = (f'<div class="posters">{cards}</div>'
            '<div class="hint">PNG = A4 at 300 dpi, ready for screens, Teams or printing. '
            'SVG = vector, sharp at any size and editable in design tools. '
            'Print / PDF opens an A4 page — choose "Save as PDF" in the print dialog.</div>')
    foot = ("One-page awareness posters built from the month's incident archive. "
            "Facts and company names update automatically every month." + links_fn(month))
    return page_fn(f"Cyber Poster · {label_fn(month)}",
                   f"Monthly poster · {label_fn(month)} · Automotive threat intelligence",
                   nav, body, foot, _PAGE_CSS, _PAGE_JS)


def register(app, *, list_months, get_month, page_fn, label_fn, links_fn, message_fn):
    def month_data(month):
        if not re.match(r"^\d{4}-\d{2}$", month):
            abort(404)
        months = list_months()
        if month not in months:
            return months, None
        return months, get_month(month)

    @app.route("/poster")
    def poster_latest():
        try:
            months = list_months()
        except Exception:
            return message_fn("Cyber Poster", "Temporarily unavailable — please try again shortly.", 503)
        if not months:
            return message_fn("Cyber Poster", "Nothing published yet.")
        return redirect(f"/poster/{months[0]}")

    @app.route("/poster/<month>")
    def poster_page(month):
        try:
            months, data = month_data(month)
        except Exception:
            return message_fn("Cyber Poster", "Temporarily unavailable — please try again shortly.", 503)
        if data is None:
            return message_fn("Cyber Poster", f"No poster for {month}.", 404)
        return Response(render_page(month, months, page_fn, label_fn, links_fn), mimetype="text/html")

    @app.route("/poster/<month>/<style>.svg")
    def poster_svg(month, style):
        if style not in STYLES:
            abort(404)
        try:
            _, data = month_data(month)
        except Exception:
            abort(503)
        if data is None:
            abort(404)
        from flask import request
        headers = {"Cache-Control": "public, max-age=600"}
        if request.args.get("download"):
            headers["Content-Disposition"] = f'attachment; filename="tmpvl-cyber-poster-{month}-{style}.svg"'
        return Response(build(style, month, data), mimetype="image/svg+xml", headers=headers)

    @app.route("/poster/<month>/<style>/print")
    def poster_print(month, style):
        if style not in STYLES:
            abort(404)
        try:
            _, data = month_data(month)
        except Exception:
            abort(503)
        if data is None:
            abort(404)
        html = (f"<!doctype html><meta charset=utf-8><title>Cyber poster {x(month)} · {STYLES[style]}</title>"
                "<style>@page{size:A4;margin:0}html,body{margin:0;background:#fff}"
                "img{display:block;width:210mm;height:297mm}"
                "@media screen{body{background:#555}img{width:min(100vw,70.7vh);height:auto;margin:0 auto}}</style>"
                f"<img id=p src='/poster/{month}/{style}.svg' alt='poster'>"
                "<script>document.getElementById('p').addEventListener('load',function(){setTimeout(function(){window.print()},400)});</script>")
        return Response(html, mimetype="text/html")
