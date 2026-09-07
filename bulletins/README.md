# Monthly Automotive Bulletin — how it works

Bulletins are **created locally and pushed to GitHub** — the running server never
needs an AI API key. Each `bulletins/<YYYY-MM>.json` file in this folder is the
**durable source of truth**: it ships with the code, and the app loads it into its
cache on boot (and on demand via the admin **Reload** button). This is why files,
not the live DB, hold bulletins — Koyeb has no persistent disk, so anything written
only to the running DB is lost on the next redeploy.

## Monthly steps (once a month)

```bash
# 1. Build the CVE half automatically from the public NVD API (no key needed):
python make_bulletin.py 2026-08

# 2. Add this month's company incidents to the "incidents" array in
#    bulletins/2026-08.json — research + draft them with Claude Cowork on your
#    desktop, or write them by hand. Shape of each incident:
#      {
#        "company": "Toyota", "category": "ransomware",
#        "severity": "High", "date": "2026-08-14",
#        "summary": "One plain sentence.",
#        "source_url": "https://real-article-that-names-the-company/..."
#      }

# 3. Source-verify what you added (drops any link that's dead or doesn't name
#    the company — verification happens HERE, locally, before it's published):
python make_bulletin.py 2026-08 --verify

# 4. Push. Koyeb redeploys with the new file and it goes live at /bulletin.
git add bulletins/2026-08.json
git commit -m "Bulletin 2026-08"
git push
```

If your Koyeb service does not auto-deploy on push, trigger a redeploy (or, once
the new file is deployed, open **Admin → Monthly Bulletins → Reload** to load it
without waiting for a boot).

## Notes

- **CVEs** are pulled fresh from NVD for the month and filtered to automotive OEMs,
  suppliers, and EV-charging / diagnostic vendors — same matcher the app uses.
- **Incidents** are yours (or Cowork's); the `--verify` step is the guardrail that
  keeps unverifiable items off the published page.
- Re-running step 1 refreshes the CVE half but **preserves** the incidents you
  already curated, so it's safe to re-run.
- Naming: the file name and its `"month"` field must match (`YYYY-MM`).
