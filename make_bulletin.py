#!/usr/bin/env python3
"""
make_bulletin.py — build a monthly automotive bulletin file LOCALLY (no server API key)
=======================================================================================

Monthly, once, on your own machine:

    python make_bulletin.py 2026-08              # fetch Aug 2026 automotive CVEs -> bulletins/2026-08.json
    # ...open the JSON, add this month's company incidents (e.g. with Claude Cowork)...
    python make_bulletin.py 2026-08 --verify     # source-verify the incidents you added, drop dead links
    git add bulletins/2026-08.json && git commit -m "Bulletin 2026-08" && git push

Once pushed, Koyeb redeploys with the file and the app serves it at /bulletin — the
running server never needs an AI key. CVEs come straight from the public NVD API;
incidents are written/verified here, locally, before they ever reach the site.

The `incidents` array is preserved across re-runs, so refreshing the CVE half never
wipes the incident work you (or Cowork) curated.

Incident object shape (add these to the JSON's "incidents" list):
  {
    "company":    "Toyota",                       # automotive OEM / supplier / industry co.
    "category":   "ransomware|data breach|supply chain|extortion|other",
    "severity":   "Critical|High|Medium|Low",
    "date":       "2026-08-14",                   # YYYY-MM-DD, first reported
    "summary":    "One sentence, plain language.",
    "source_url": "https://real-news-article/..."  # must resolve AND name the company
  }
"""
import sys, os, json, time, argparse
import urllib.request, urllib.parse
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import bulletin as B   # reuse the exact automotive matcher + verifier the app uses

NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def month_bounds(month_key):
    y, m = int(month_key[:4]), int(month_key[5:7])
    start = f"{y:04d}-{m:02d}-01T00:00:00.000"
    if m == 12:
        end = f"{y+1:04d}-01-01T00:00:00.000"
    else:
        end = f"{y:04d}-{m+1:02d}-01T00:00:00.000"
    return start, end


def fetch_month_cves(month_key, api_key=""):
    start, end = month_bounds(month_key)
    items, idx, total = [], 0, None
    headers = {"User-Agent": "make-bulletin/1.0"}
    if api_key:
        headers["apiKey"] = api_key
    while True:
        q = urllib.parse.urlencode({
            "pubStartDate": start, "pubEndDate": end,
            "resultsPerPage": "2000", "startIndex": str(idx),
        })
        for attempt in range(4):
            try:
                req = urllib.request.Request(f"{NVD}?{q}", headers=headers)
                with urllib.request.urlopen(req, timeout=60) as r:
                    data = json.load(r)
                break
            except Exception as e:
                print(f"  retry {attempt+1} at index {idx}: {e}", file=sys.stderr)
                time.sleep(8)
        else:
            raise SystemExit("NVD fetch failed repeatedly — try again, or pass --api-key")
        total = data.get("totalResults", 0)
        batch = data.get("vulnerabilities", [])
        items.extend(batch)
        idx += len(batch)
        print(f"  fetched {idx}/{total}", file=sys.stderr)
        if idx >= total or not batch:
            break
        time.sleep(6 if not api_key else 1)  # respect NVD rate limits
    return items


def to_cve_dict(v):
    c = v["cve"]
    desc = next((d["value"] for d in c.get("descriptions", []) if d.get("lang") == "en"), "")
    name, tier = B.automotive_match(desc)
    if not name:
        return None
    metrics = c.get("metrics", {})
    score = sev = None
    for k in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if metrics.get(k):
            d = metrics[k][0]["cvssData"]
            score = d.get("baseScore")
            sev = d.get("baseSeverity") or metrics[k][0].get("baseSeverity")
            break
    cwes = [w["value"] for wk in c.get("weaknesses", [])
            for w in wk.get("description", []) if w.get("lang") == "en"]
    refs = [r["url"] for r in c.get("references", [])]
    sev_txt = (sev or "").capitalize() if sev else B_sev_from_score(score)
    return {
        "cve_id": c["id"],
        "score": score,
        "severity": sev_txt if sev_txt in ("Critical", "High", "Medium", "Low") else B_sev_from_score(score),
        "cwe": cwes[0] if cwes else "",
        "published": (c.get("published") or "")[:10],
        "source": "nvd",
        "is_kev": bool(c.get("cisaExploitAdd")),
        "matched": name,
        "subsystem": B._subsystem(name + " " + desc),
        "description": desc.strip(),
        "ref": next((u for u in refs if u.startswith("http")), ""),
    }


def B_sev_from_score(score):
    if score is None:
        return "Unknown"
    if score >= 9.0: return "Critical"
    if score >= 7.0: return "High"
    if score >= 4.0: return "Medium"
    if score > 0:    return "Low"
    return "Unknown"


def build(month_key, out_dir, api_key, raw_file=None):
    path = os.path.join(out_dir, f"{month_key}.json")
    existing_incidents = []
    if os.path.exists(path):
        try:
            existing_incidents = json.load(open(path, encoding="utf-8")).get("incidents", [])
        except Exception:
            pass
    if raw_file:
        items = json.load(open(raw_file, encoding="utf-8"))
        print(f"  using cached raw dump: {len(items)} CVEs", file=sys.stderr)
    else:
        print(f"Fetching {month_key} CVEs from NVD…", file=sys.stderr)
        items = fetch_month_cves(month_key, api_key)
    cves = [d for d in (to_cve_dict(v) for v in items) if d]
    cves.sort(key=lambda x: (0 if x["is_kev"] else 1, -(x["score"] or 0), x["cve_id"]))
    doc = {
        "month": month_key,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "cves": cves,
        "incidents": existing_incidents,   # preserved across re-runs
    }
    os.makedirs(out_dir, exist_ok=True)
    json.dump(doc, open(path, "w", encoding="utf-8"), indent=1, ensure_ascii=False)
    print(f"\n✅ Wrote {path}")
    print(f"   {len(cves)} automotive CVEs · {len(existing_incidents)} incidents (preserved)")
    if not existing_incidents:
        print("\n   Next: add this month's company incidents to the \"incidents\" array")
        print("   (Claude Cowork can research + draft them), then run:")
        print(f"       python make_bulletin.py {month_key} --verify")
    print(f"   Then: git add {path} && git commit -m 'Bulletin {month_key}' && git push")


def verify(month_key, out_dir):
    path = os.path.join(out_dir, f"{month_key}.json")
    if not os.path.exists(path):
        raise SystemExit(f"{path} not found — build it first")
    doc = json.load(open(path, encoding="utf-8"))
    incs = doc.get("incidents", [])
    if not incs:
        print("No incidents to verify."); return
    kept, dropped = [], []
    for inc in incs:
        print(f"  checking {inc.get('company','?')} … ", end="", flush=True)
        if B.verify_incident(inc):
            print("OK"); kept.append(inc)
        else:
            print("DROPPED (link dead or does not name the company)"); dropped.append(inc)
    doc["incidents"] = kept
    json.dump(doc, open(path, "w", encoding="utf-8"), indent=1, ensure_ascii=False)
    print(f"\n✅ {len(kept)} verified, {len(dropped)} dropped → {path}")
    if dropped:
        print("   Dropped:", ", ".join(i.get("company", "?") for i in dropped))


def main():
    ap = argparse.ArgumentParser(description="Build/verify a monthly automotive bulletin file")
    ap.add_argument("month", help="YYYY-MM (e.g. 2026-08)")
    ap.add_argument("--verify", action="store_true", help="source-verify incidents in the file, drop dead links")
    ap.add_argument("--api-key", default=os.environ.get("NVD_API_KEY", ""), help="NVD API key (optional, higher rate limit)")
    ap.add_argument("--out", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "bulletins"))
    ap.add_argument("--raw", help="use a pre-downloaded NVD JSON dump instead of fetching")
    args = ap.parse_args()
    import re
    if not re.match(r"^\d{4}-\d{2}$", args.month):
        raise SystemExit("month must be YYYY-MM")
    if args.verify:
        verify(args.month, args.out)
    else:
        build(args.month, args.out, args.api_key, args.raw)


if __name__ == "__main__":
    main()
