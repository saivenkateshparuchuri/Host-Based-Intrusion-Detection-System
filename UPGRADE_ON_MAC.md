# Upgrade your current HIDS installation on Mac

This patch adds read-only macOS keyboard-event-tap metadata monitoring. **It does not
install a keylogger and does not read or record keystrokes.**

## Before updating

1. Stop the running Flask server with **Control+C** in its Terminal window.
2. Back up your current `hids` folder (especially `hids.db` and `hids_secret.key`).
3. Put `HIDS_macOS_Keyboard_Tap_Patch.zip` in `~/Downloads`, next to `~/Downloads/hids`.

## Update (copy these commands into Terminal)

```bash
cd ~/Downloads
cp -R hids hids_backup_before_macos
unzip -o HIDS_macOS_Keyboard_Tap_Patch.zip -d ~/Downloads
cd ~/Downloads/hids
source .venv/bin/activate
python3 -m pytest -q
python3 tools/inspect_macos_taps.py
python3 run.py
```

Open Safari at http://127.0.0.1:5055 and click **Security Monitoring → Scan now**.
Under **Detection Modules**, the old **Input-Device Check / Unavailable** tile is now
**macOS Keyboard Tap Audit**. A working API shows **Metadata only** and a count of
enabled keyboard-event taps.

If the audit shows zero keyboard taps, this means none were *reported* at scan
time; it is not a proof that your system is keylogger-free. If the audit reports
an error, send the output of the diagnostic tool so the problem can be investigated.

If macOS shows permission dialogs, use System Settings to review them. You do
not need to approve unnecessary input-reading permissions for this metadata-only
check. Do not attempt to bypass OS privacy protections.

A legitimate app can have a keyboard event tap (hotkey, accessibility, remapper);
a `MACOS_KEYBOARD_EVENT_TAP` alert alone is scored **Low**. Suspicious execution
or persistence indicators can raise it. Confirm false positives before classifying
any program as malware.

## Data preservation

The patch archive contains **only source files**; it does NOT include, replace or
remove your SQLite database (`hids.db`), user secret (`hids_secret.key`), existing
alert history, or `.venv`. If you previously customized `config.py` yourself, back
it up first because the patch updates its rule score definitions.
