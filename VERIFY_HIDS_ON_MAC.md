# HIDS verification tools for macOS

These commands run on your **own Mac** in the **same `~/Downloads/hids` folder** you already use. The patch adds tools only; it does not replace app code or modify `hids.db`, `hids_secret.key`, or your users.

## Install

1. Stop your existing HIDS server with `Control+C`.
2. Copy `HIDS_Restart_and_Detection_Verification_Patch.zip` to `~/Downloads`.
3. Run:

```bash
cd ~/Downloads
unzip -o HIDS_Restart_and_Detection_Verification_Patch.zip -d ~/Downloads
cd ~/Downloads/hids
source .venv/bin/activate
```

## 1. Reliable startup

Run `python3 tools/run_verified.py` **instead of** `python3 run.py`.

- Refuses to start if another service is occupying TCP port 5055.
- Starts your existing HIDS Flask server and waits for the login page to respond.
- Opens the browser only when the server is reachable.
- Prints errors to the Terminal. Press `Control+C` to stop.

To check the web assets, open a second Terminal in the same folder and run:

```bash
python3 tools/check_dashboard.py
```

Expected output: `3/3 checks passed`. If Safari is blank even when checks pass, try `Command+Shift+R`, a private window, or inspect Safari's JavaScript Console. Note that an existing login cookie can redirect you from `/login` to `/`.

## 2. macOS input-monitoring detection validation

Run in a second terminal:

```bash
python3 tools/inspect_macos_taps.py
python3 tools/validate_input_detection.py
```

The first command inventories **existing** CoreGraphics event taps without inspecting keystrokes. The second checks:

- an ordinary app with a keyboard tap gives a **Low** indicator;
- a simulated process with a keyboard tap **and a suspicious temporary executable path** gives a **High** alert;
- an ordinary app without a keyboard tap gives **no** alert.

The scenarios are **synthetic metadata test cases**. They do not install or run malware, or prove that real keyloggers can be detected. To claim detection accuracy, you'd need a lawful, labeled test set in an isolated test environment with independent ground truth and false-positive measurements.

### What is verified vs not verified

| Area | Evidence |
|---|---|
| Process monitoring | Live HIDS dashboard showed 341 processes |
| Suspicious temporary execution | Safe simulator generated High alert |
| Suspicious startup persistence | Safe simulator generated Medium alert |
| Event-tap inventory | Mac showed 7 taps, 3 enabled keyboard taps |
| Keyboard-event tap + suspicious process rule | This patch provides a repeatable synthetic rule test |
| Real malicious keylogger detection | **Not validated** |

Do not describe Apple accessibility or Siri processes as malware solely because they use a keyboard event tap. Avoid granting unnecessary Input Monitoring/Accessibility permissions to the HIDS itself.
