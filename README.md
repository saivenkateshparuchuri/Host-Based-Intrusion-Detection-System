# Host-Based Intrusion Detection System (HIDS) — macOS + Linux

A **metadata-only** Python/Flask capstone prototype for investigating suspicious
processes and startup persistence. On macOS, this version adds **read-only
CoreGraphics event-tap inventory** to identify processes that have an enabled
keyboard-event listener. It never captures, logs or requests typed text.

## Install

```bash
cd hids
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt
python3 -m pytest -q
```

## Run on macOS (no sudo necessary for initial tests)

The default address is `127.0.0.1:5055`; override with `HIDS_PORT` / `HIDS_HOST`.
Self-registration is closed after the first (admin) account; set `HIDS_ALLOW_REGISTER=1` to open it.
Scan and event history older than `HIDS_RETENTION_DAYS` (30) is pruned; alerts are kept.

```bash
python3 run.py
```

Open `http://127.0.0.1:5055`. In **Detection Modules**, find **macOS Keyboard
Tap Audit**. Click **Scan now**. The tile can say:

- **Metadata only** — enumeration succeeded; it displays the number of active
  keyboard-event taps, not a list of key presses.
- **Unavailable** — event taps could not be enumerated. Check Terminal logs
  and macOS permissions. Do **not** bypass privacy controls.

For detailed read-only diagnostics:

```bash
python3 tools/inspect_macos_taps.py
```

This API enumerates *Core Graphics event taps*, which are also used legitimately
by accessibility software and hotkey tools. A tap **does not prove malware**.
The new `MACOS_KEYBOARD_EVENT_TAP` rule scores **2 (Low)** on its own and
can increase severity when correlated with other suspicious indicators.
macOS may restrict event-tap visibility; other capture mechanisms may be missed.

## Shared dashboard with laptop agents

The hosted dashboard scans its own server, not a visitor's laptop. To show
each laptop's own metadata-only process and alert results in the shared
dashboard, install this repository on each laptop and register an agent:

```bash
python3 tools/agent.py register \
  --server https://host-based-intrusion-detection-system-p1o1.onrender.com \
  --username YOUR_DASHBOARD_USER
python3 tools/agent.py run --interval 30
```

The agent stores its bearer token in `~/.hids-agent.json` with restrictive
permissions and sends process counts, unreadable counts, scan timing, and
explainable alert metadata. It never sends command-line text or keystrokes.
After registration, select the laptop from the dashboard's **Device** menu.
Use HTTPS for the dashboard URL and register each laptop separately.

To **review which apps have user-granted input permissions**, open **System
Settings → Privacy & Security → Input Monitoring** and review entries manually.
This project does not access or modify the private TCC permission database.

## Safe demonstration (no keylogger or keystroke capture)

Terminal 1:

```bash
HIDS_EXTRA_AUTOSTART=/tmp/hids_demo/autostart python3 run.py
```

Terminal 2 (after initial scan):

```bash
python3 tools/simulate_threat.py start
# Click Scan now in the HIDS dashboard
python3 tools/simulate_threat.py stop
```

A high-severity suspicious temp execution and a medium-severity suspicious
startup entry may be recorded, as observed on the current Mac prototype. **This
is a safe suspicious-activity simulation, not direct keylogger detection.**

## Project layout

- `sensors/process_sensor.py`: process metadata; Linux `/proc` device handles
- `sensors/macos_event_tap_sensor.py`: **new** macOS event-tap enumeration
- `sensors/persistence_sensor.py`: startup entries and macOS LaunchAgents
- `engine/rules.py`: indicators, explainable scoring and correlation
- `storage/db.py`: SQLite scan and alert history
- `web/`: local Flask dashboard and CSV export
- `tools/inspect_macos_taps.py`: **new** Mac sensor diagnostic command
- `tests/test_macos_event_taps.py`: **new** synthetic metadata-only tests

## Limitations and claims for the final presentation

**Supported:** host process/persistence monitoring, risk rules, stored alerts,
CSV export, and (on macOS) enumeration of observable Core Graphics event taps.

**Not established:** detection of *all* keyloggers, interception of HID input,
raw keyboard hooks not exposed as Core Graphics taps, malicious vs. legitimate
input monitoring intent, or complete operating-system security. An event-tap
finding is a behavioral signal, not a malware verdict. macOS privileges and
privacy settings can affect what metadata is visible.

**Verification status:** code tests can run on Linux with mocked tap metadata;
actual macOS native API behavior must be checked on the Mac. Do not report real
macOS tap detection until an actual observation is demonstrated.
