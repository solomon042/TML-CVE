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
STYLES = {"board": "Threat board", "rings": "Circuit rings", "car": "Connected car"}
_FONT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static", "fonts")
_BRAND_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static", "brand")
_font_css = None
_logos = {}


def _logo(name):
    """Brand logo as a data URI, so downloaded SVG/PNG posters are self-contained."""
    if name not in _logos:
        try:
            with open(os.path.join(_BRAND_DIR, name), "rb") as f:
                _logos[name] = "data:image/png;base64," + base64.b64encode(f.read()).decode()
        except OSError:
            _logos[name] = ""
    return _logos[name]


def _logo_img(name, xpos, y, w, h):
    uri = _logo(name)
    return (f'<image href="{uri}" x="{xpos}" y="{y}" width="{w}" height="{h}" '
            f'preserveAspectRatio="xMidYMid meet"/>') if uri else ""


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
        + '<rect x="812" y="52" width="148" height="128" rx="16" fill="#fff"/>'
        + _logo_img("vsecure-logo.png", 822, 60, 128, 112)
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
    if len(fact) > 62:
        fact = fact[:61].rstrip(" ,·—") + "…"

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
        + _logo_img("vsecure-horizontal.png", 690, 1336, 250, 45)
    )
    return _svg_open(f"Is your car talking to strangers? — {f['label']}") + body + "</svg>"


# ---------------------------------------------------------------------------
# Style 0 — Threat board (data poster: one illustrated card per item)
# ---------------------------------------------------------------------------
_SEV_COL = {"critical": "#FF5A4E", "high": "#FFA62B", "medium": "#F2C744", "low": "#9FB3C8"}
_TECH_COL = "#B794FF"
_INFO_COL = "#6CB4FF"


def _wrap(text, width, max_lines):
    words, lines, cur = str(text or "").split(), [], ""
    for w_ in words:
        if len(cur) + len(w_) + (1 if cur else 0) <= width:
            cur = f"{cur} {w_}" if cur else w_
        else:
            if cur:
                lines.append(cur)
            cur = w_
        if len(lines) == max_lines:
            break
    if cur and len(lines) < max_lines:
        lines.append(cur)
    if len(lines) == max_lines and " ".join(lines) != " ".join(words):
        lines[-1] = lines[-1][:max(0, width - 1)].rstrip(" ,.;:") + "…"
    return lines


def _icon(kind, c):
    """60x60 line icon centred on (0,0)."""
    sw = 'fill="none" stroke="%s" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"' % c
    if kind == "lock":
        return (f'<g {sw}><path d="M-13 -4 V-14 A13 13 0 0 1 13 -14 V-4"/>'
                f'<rect x="-20" y="-4" width="40" height="30" rx="5"/></g>'
                f'<circle cx="0" cy="8" r="4.5" fill="{c}"/><rect x="-2" y="9" width="4" height="9" fill="{c}"/>')
    if kind == "data":
        return (f'<g {sw}><ellipse cx="-4" cy="-17" rx="18" ry="6"/><path d="M-22 -17 V15 A18 6 0 0 0 14 15 V-17"/>'
                f'<path d="M-22 -1 A18 6 0 0 0 14 -1"/></g>'
                f'<path d="M22 4 C22 4 15 13 15 17 A7 7 0 0 0 29 17 C29 13 22 4 22 4 Z" fill="{c}"/>')
    if kind == "car":
        return (f'<g {sw}><path d="M-26 12 V3 L-18 1 L-10 -9 H10 L18 1 L26 4 V12 Z"/>'
                f'<path d="M-4 -18 A10 10 0 0 1 8 -22"/><path d="M-8 -26 A18 18 0 0 1 12 -31"/></g>'
                f'<circle cx="-14" cy="13" r="6" fill="{c}"/><circle cx="14" cy="13" r="6" fill="{c}"/>')
    if kind == "chip":
        pins = "".join(f'<path d="M{p} -26 V-20 M{p} 20 V26 M-26 {p} H-20 M20 {p} H26"/>' for p in (-10, 0, 10))
        return (f'<g {sw}><rect x="-20" y="-20" width="40" height="40" rx="5"/>{pins}'
                f'<path d="M-6 -7 L6 4 L0 10 V-10 L6 -4 L-6 7" stroke-width="3"/></g>')
    if kind == "clock":
        return (f'<g {sw}><path d="M-17 -14 A22 22 0 1 1 -22 2"/><path d="M-24 -20 L-17 -14 L-11 -21"/>'
                f'<path d="M0 -11 V1 L9 7"/></g>')
    return (f'<g {sw}><rect x="-24" y="-19" width="48" height="38" rx="5"/><path d="M-24 -9 H24"/>'
            f'<path d="M-14 1 L-6 7 L-14 13"/><path d="M0 13 H12"/></g>')


def _icon_kind(r, kind):
    if kind == "tech":
        return "chip"
    if kind == "info":
        return "clock"
    t = f"{r.get('incident_type', '')} {r.get('summary', '')} {r.get('title', '')}".lower()
    itype = (r.get("incident_type") or "").lower()
    if "ransom" in itype or "extortion" in itype:
        return "lock"
    if any(k in t for k in ("vehicle", " car ", "telematic", "ecu", "connected car", "shark", "keyless", "infotainment")):
        return "car"
    if any(k in itype for k in ("breach", "leak", "exposure", "data")):
        return "data"
    return "hack"


def _date_short(iso):
    try:
        return datetime.strptime(str(iso)[:10], "%Y-%m-%d").strftime("%d %b %Y").upper()
    except ValueError:
        return ""


def poster_board(month, data, nl=None):
    f = facts(month, data)
    recs = list((data or {}).get("incidents", {}).values())
    new = sorted([r for r in recs if not r.get("historical")],
                 key=lambda r: (_SEV.get((r.get("severity") or "").lower(), 4), r.get("first_seen", "")))
    info = sorted([r for r in recs if r.get("historical")], key=lambda r: r.get("first_seen", ""))
    vulns = sorted((data or {}).get("vulns", {}).values(),
                   key=lambda r: (_SEV.get((r.get("severity") or "").lower(), 4), r.get("first_seen", "")))
    items = [("new", r) for r in new] + [("tech", v) for v in vulns] + [("info", r) for r in info]
    shown, extra = items[:5], len(items) - 5
    crit_high = sum(1 for r in new if (r.get("severity") or "").lower() in ("critical", "high"))

    head = ((nl or {}).get("content") or {}).get("headline") or (
        f"{_plural(f['n'], 'new automotive cyber incident', 'new automotive cyber incidents')}"
        + (f", {f['ransom']} ransomware" if f["ransom"] else "")
        + (f", {_plural(f['vulns'], 'connected-car flaw', 'connected-car flaws')}" if f["vulns"] else ""))
    hl = _wrap(head, 44, 2)

    defs = ('<defs><linearGradient id="bgb" x1="0" y1="0" x2="0" y2="1">'
            '<stop offset="0" stop-color="#0B1D36"/><stop offset="1" stop-color="#0E2A47"/></linearGradient>'
            '<filter id="ag"><feGaussianBlur stdDeviation="8" result="b"/><feMerge><feMergeNode in="b"/>'
            '<feMergeNode in="SourceGraphic"/></feMerge></filter></defs>')

    out = [f'<rect width="{W}" height="{H}" fill="url(#bgb)"/>',
           _circuits(f"board-{month}", "91,168,255", True),
           '<rect x="60" y="52" width="300" height="78" rx="14" fill="#fff"/>',
           _logo_img("vsecure-horizontal.png", 74, 60, 272, 62),
           '<text class="m" x="940" y="84" text-anchor="end" font-size="17" fill="#9FC0E0" letter-spacing="2.5">TMPVL E&amp;E · CYBER THREAT BOARD</text>',
           '<text class="d" x="940" y="114" text-anchor="end" font-size="19" font-weight="700" fill="#E08A1E">Solomon Raja · Cyber Security</text>',
           f'<text class="d" x="56" y="268" font-size="122" font-weight="900" style="font-stretch:64%" fill="#FFB547" filter="url(#ag)">{x(f["label"].split()[0].upper())}</text>',
           f'<text class="d" x="60" y="312" font-size="28" font-weight="700" fill="#fff" letter-spacing="1">{x(f["label"].split()[1])} · AUTOMOTIVE CYBER INCIDENTS</text>']
    out += [f'<text class="d" x="60" y="{372 + i * 42}" font-size="34" font-weight="700" fill="#E3ECFA">{x(ln)}</text>'
            for i, ln in enumerate(hl)]

    tiles = [(f["n"], "NEW INCIDENTS", "#FF6B66" if f["n"] else "#FFFFFF"),
             (crit_high, "CRITICAL + HIGH", "#FFA62B"),
             (f["ransom"], "RANSOMWARE", "#F2C744"),
             (f["vulns"], "CAR-TECH FLAWS", _TECH_COL)]
    for i, (v, lab, col) in enumerate(tiles):
        tx = 60 + i * 225
        out.append(f'<rect x="{tx}" y="470" width="205" height="112" rx="16" fill="#13365C" stroke="#1E4A78" stroke-width="2"/>'
                   f'<text class="d" x="{tx + 102}" y="534" text-anchor="middle" font-size="54" font-weight="900" fill="{col}">{v}</text>'
                   f'<text class="m" x="{tx + 102}" y="564" text-anchor="middle" font-size="14" fill="#9FC0E0" letter-spacing="1.2">{lab}</text>')

    y = 612
    if not items:
        out.append('<rect x="60" y="612" width="880" height="200" rx="18" fill="rgba(46,160,90,.15)" stroke="#3FBF7F" stroke-width="2"/>'
                   '<text class="d" x="500" y="700" text-anchor="middle" font-size="40" font-weight="800" fill="#7FE0A8">No new automotive cyber incidents</text>'
                   f'<text class="d" x="500" y="748" text-anchor="middle" font-size="24" fill="#CFEFDC">were reported in {x(f["label"])}. Stay alert.</text>')
    for kind, r in shown:
        sev = (r.get("severity") or "").lower()
        col = _TECH_COL if kind == "tech" else _INFO_COL if kind == "info" else _SEV_COL.get(sev, "#9FB3C8")
        if kind == "tech":
            name = r.get("technology") or "Connected-car vulnerability"
            cves = ", ".join((r.get("cves") or [])[:2])
            dom = (r.get("domain") or "").split(" (")[0].upper()
            meta = f"CONNECTED-CAR TECH · {dom}" + (f" · {cves}" if cves else "")
            body = r.get("why_relevant") or r.get("summary") or ""
            pill = sev.upper() or "N/A"
        elif kind == "info":
            name = r.get("organization") or "Unknown"
            meta = f"OLDER ATTACK · BACK IN THE NEWS {_date_short(r.get('first_seen'))}"
            body = r.get("impact") or r.get("summary") or ""
            pill = "INFO"
        else:
            name = r.get("organization") or "Unknown"
            itype = _wrap((r.get("incident_type") or "incident").split(" / ")[0], 34, 1)[0].upper()
            meta = f"{itype} · {_date_short(r.get('first_seen'))}"
            body = r.get("impact") or r.get("summary") or ""
            pill = sev.upper() or "N/A"
        lines = _wrap(body, 60, 2)
        pw = len(pill) * 12 + 34
        out.append(
            f'<rect x="60" y="{y}" width="880" height="128" rx="18" fill="rgba(255,255,255,.06)" stroke="rgba(159,192,224,.28)" stroke-width="1.5"/>'
            f'<rect x="60" y="{y}" width="8" height="128" rx="4" fill="{col}"/>'
            f'<circle cx="138" cy="{y + 64}" r="46" fill="{col}" fill-opacity=".14" stroke="{col}" stroke-width="2.5"/>'
            f'<g transform="translate(138 {y + 64})">{_icon(_icon_kind(r, kind), col)}</g>'
            f'<text class="d" x="204" y="{y + 42}" font-size="29" font-weight="800" fill="#fff">{x(_wrap(name, 36, 1)[0] if name else "")}</text>'
            f'<rect x="{924 - pw}" y="{y + 16}" width="{pw}" height="32" rx="16" fill="{col}"/>'
            f'<text class="m" x="{924 - pw / 2:.0f}" y="{y + 38}" text-anchor="middle" font-size="15" fill="#0B1D36">{x(pill)}</text>'
            f'<text class="m" x="204" y="{y + 68}" font-size="14.5" fill="#9FC0E0" letter-spacing=".8">{x(meta[:70])}</text>'
            + "".join(f'<text class="d" x="204" y="{y + 96 + i * 24}" font-size="19.5" fill="#E3ECFA">{x(ln)}</text>'
                      for i, ln in enumerate(lines)))
        y += 144
    if extra > 0:
        out.append(f'<text class="d" x="500" y="{y + 10}" text-anchor="middle" font-size="20" font-weight="700" fill="#FFB547">'
                   f'+ {extra} more in the full archive</text>')

    out.append('<line x1="60" y1="1352" x2="940" y2="1352" stroke="#1E4A78" stroke-width="2"/>'
               f'<text class="m" x="60" y="1384" font-size="15" fill="#9FC0E0">Full details: …koyeb.app/news/{x(month)}</text>'
               '<text class="d" x="940" y="1384" text-anchor="end" font-size="16" fill="#9FC0E0">'
               'Verify against primary sources before circulating</text>')
    return _svg_open(f"Automotive cyber threat board — {f['label']}") + defs + "".join(out) + "</svg>"


def build(style, month, data, nl=None):
    if style == "board":
        return poster_board(month, data, nl)
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


def register(app, *, list_months, get_month, page_fn, label_fn, links_fn, message_fn,
             get_newsletter=lambda m: None):
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
        try:
            nl = get_newsletter(month) if style == "board" else None
        except Exception:
            nl = None
        return Response(build(style, month, data, nl), mimetype="image/svg+xml", headers=headers)

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
