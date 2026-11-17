# HIDS Guard — Reference-Style Dashboard Upgrade

This upgrade changes the **web dashboard design**, not the underlying HIDS sensors, security rules, accounts or saved alert records. It takes inspiration from the supplied dark/purple analytics dashboard while showing genuine HIDS-specific metrics.

## Apply the patch to your working Mac installation

1. Stop Flask in Terminal with **Control+C**.
2. Download `HIDS_Reference_Style_Dashboard_Patch.zip` into `~/Downloads`.
3. Back up your existing working project before overwriting code:

   ```bash
   cd ~/Downloads
   cp -R hids hids_backup_before_dashboard
   ```

4. Apply the patch. Its files are nested under `hids/`:

   ```bash
   unzip -o HIDS_Reference_Style_Dashboard_Patch.zip -d ~/Downloads
   cd ~/Downloads/hids
   source .venv/bin/activate
   ```

5. Run HIDS on your working port **5055**:

   ```bash
   python3 run.py
   ```

   If your `run.py` still uses port 5000 (which macOS Control Center may occupy), use:

   ```bash
   python3 -c "from web.app import create_app; create_app().run(host='127.0.0.1',port=5055,debug=False)"
   ```

6. Open **http://127.0.0.1:5055** in Safari. If the old dashboard is cached, use **Cmd+Shift+R**.
7. On the Dashboard, select a time range and click Refresh. Scan now retains the original authenticated POST workflow.

## What changed

- Purple-branded sidebar with functioning Dashboard, Security Alerts, High Severity, Host Processes, Sensor Status and Export CSV navigation.
- Eight statistic cards, alert and severity charts, top five detection rules and recent incidents, all populated by the local database.
- Responsive layouts for laptop screens.
- A new authenticated API endpoint: `/api/dashboard/analytics?range=3d`.
- Time-range options 24h, 3d, 7d and 30d.

The **Total Alerts** metric counts distinct alert records *first observed in the chosen period* (not repeated detections). Keyboard-event taps are **indicators**, not malware verdicts. Host visibility describes readable process metadata, **not device security effectiveness**.

## Files in the patch

- `hids/web/templates/base.html`
- `hids/web/templates/index.html`
- `hids/web/static/dashboard_v2.css`
- `hids/web/static/dashboard_v2.js`
- `hids/web/app.py`
- `hids/tests/test_dashboard_v2.py`
- `hids/DASHBOARD_UPGRADE_MAC.md`

The patch **does not include** `hids.db`, `hids_secret.key`, or `run.py`. Therefore it does not delete alerts/accounts, and it preserves your existing port-5055 startup setting.

## Regression checks

```bash
python3 -m pytest -q
python3 tools/check_dashboard.py
```

The added `tests/test_dashboard_v2.py` covers dashboard HTML/static files, the new analytics API, true time-window data aggregation, and continued availability of existing routes. If any test fails, restore the original directory from `hids_backup_before_dashboard` and share the error.

## Notes

A Preview PNG may accompany this patch, but that preview contains **illustrative UI values**, not the live measurements from your installation. Actual values are loaded from your current local SQLite database only after login.
