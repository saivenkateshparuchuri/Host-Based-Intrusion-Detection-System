#!/usr/bin/env python3
"""HIDS Capstone Presentation & Defense Demo Tool.

Safe, guided demonstration for faculty evaluators and project viva.
Simulates 4 realistic attack scenarios without causing any system harm:
  Stage 1: Suspicious execution from /tmp with hidden name (MITRE T1059)
  Stage 2: Mock persistence via LaunchAgent / Autostart (MITRE T1547)
  Stage 3: Simulated interactive reverse shell syntax (MITRE T1059.004)
  Stage 4: Process masquerading as system daemon (MITRE T1036.005)

Usage:
  python3 tools/demo_presentation.py              # Interactive presentation menu
  python3 tools/demo_presentation.py start        # Launch all 4 stages
  python3 tools/demo_presentation.py stop         # Terminate demo processes & clean files
  python3 tools/demo_presentation.py status       # Check current simulation status
"""
import json
import os
import plistlib
import signal
import subprocess
import sys
import time
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DEMO_DIR = Path("/tmp/hids_demo")
STATE_FILE = DEMO_DIR / "demo_state.json"

# macOS LaunchAgent or Linux autostart
USER_HOME = Path.home()
MACOS_LAUNCH_AGENT = USER_HOME / "Library" / "LaunchAgents" / "com.hids.capstone.demo.plist"
LINUX_AUTOSTART = USER_HOME / ".config" / "autostart" / "hids-capstone-demo.desktop"


def _load_state():
    if STATE_FILE.exists():
        try:
            return json.loads(STATE_FILE.read_text())
        except Exception:
            pass
    return {"pids": [], "files": [], "stages": []}


def _save_state(state):
    DEMO_DIR.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(json.dumps(state, indent=2))


def print_banner():
    print("""
\033[1;36m========================================================================
   🛡️  HIDS CAPSTONE DEFENSE & DEMONSTRATION SUITE
   Host-Based Intrusion Detection System — Live Attack & Defense
========================================================================\033[0m""")


def print_stage_box(stage_num, title, technique, mitre, description, dashboard_note):
    print(f"""
\033[1;33m------------------------------------------------------------------------
  STAGE {stage_num}: {title}
------------------------------------------------------------------------\033[0m
  🎯 \033[1mScenario:\033[0m     {description}
  🛡️ \033[1mHIDS Rule:\033[0m    \033[1;32m[{technique}]\033[0m
  🗺️ \033[1mMITRE ATT&CK:\033[0m \033[1;34m{mitre}\033[0m
  🖥️ \033[1mDashboard:\033[0m    {dashboard_note}
""")


def stage_1_temp_execution():
    """Stage 1: Suspicious execution from /tmp with a hidden dot-name."""
    state = _load_state()
    DEMO_DIR.mkdir(parents=True, exist_ok=True)
    script_path = DEMO_DIR / ".stage1_worker"

    script_content = """#!/usr/bin/env python3
import time
while True:
    time.sleep(5)
"""
    script_path.write_text(script_content)
    script_path.chmod(0o755)

    proc = subprocess.Popen([sys.executable, str(script_path)], start_new_session=True)
    state["pids"].append(proc.pid)
    state["files"].append(str(script_path))
    state["stages"].append("Stage 1: Temp Exec")
    _save_state(state)

    print_stage_box(
        1,
        "Suspicious Binary in Scratch / Temp Folder",
        "EXEC_IN_TEMP + HIDDEN_PROCESS_NAME",
        "T1059 / T1036.005",
        "Attacker drops an unapproved binary into /tmp with a hidden dot-name (.stage1_worker).",
        "Look for a new alert for '.stage1_worker' with Medium severity (score 3)."
    )
    print(f"  \033[32m✔ Launched simulated worker (PID {proc.pid}) at {script_path}\033[0m")
    return proc.pid


def stage_2_persistence():
    """Stage 2: Mock persistence entry pointing to /tmp."""
    state = _load_state()
    target_exec = str(DEMO_DIR / ".stage1_worker")
    auto_dir = DEMO_DIR / "autostart"
    auto_dir.mkdir(parents=True, exist_ok=True)

    created_files = []
    # Create desktop entry
    desktop_file = auto_dir / "hids-demo.desktop"
    desktop_file.write_text(f"[Desktop Entry]\nType=Application\nName=HIDS Demo\nExec={target_exec}\n")
    created_files.append(str(desktop_file))

    # Also create mock plist for macOS
    plist_file = auto_dir / "com.hids.demo.plist"
    plist_data = {
        "Label": "com.hids.demo",
        "ProgramArguments": ["/usr/bin/python3", target_exec],
        "RunAtLoad": True,
    }
    with open(plist_file, "wb") as f:
        plistlib.dump(plist_data, f)
    created_files.append(str(plist_file))

    state["files"].extend(created_files)
    state["stages"].append("Stage 2: Persistence")
    _save_state(state)

    print_stage_box(
        2,
        "Startup Persistence Entry (LaunchAgent / Autostart)",
        "PERSISTENCE_TARGET_SUSPICIOUS + CORRELATION",
        "T1547.001 (Boot or Logon Autostart Execution)",
        f"Attacker registers persistent startup hook pointing to {target_exec}.",
        "Triggers correlation! Severity escalates to High (score 4+) when linked with Stage 1."
    )
    print(f"  \033[32m✔ Created persistence entries in: {auto_dir}\033[0m")
    return str(desktop_file)


def stage_3_reverse_shell():
    """Stage 3: Benign process mimicking reverse shell syntax."""
    state = _load_state()
    # Spawns sleep with commandline string containing simulated /dev/tcp syntax
    cmd = ["sh", "-c", "exec -a 'rev_demo' sleep 3600 # /dev/tcp/192.168.1.100/4444 interactive"]
    proc = subprocess.Popen(cmd, start_new_session=True)
    state["pids"].append(proc.pid)
    state["stages"].append("Stage 3: Reverse Shell")
    _save_state(state)

    print_stage_box(
        3,
        "Interactive Reverse Shell Simulation",
        "REVERSE_SHELL_PATTERN",
        "T1059.004 (Unix Shell Redirection)",
        "Process command line includes Unix /dev/tcp socket redirection syntax.",
        "SIEM rule flags [REVERSE_SHELL_PATTERN] with Medium (score 3) immediately."
    )
    print(f"  \033[32m✔ Launched reverse-shell simulation (PID {proc.pid})\033[0m")
    return proc.pid


def stage_4_masquerading():
    """Stage 4: Process masquerading as system daemon."""
    state = _load_state()
    DEMO_DIR.mkdir(parents=True, exist_ok=True)
    daemon_name = "launchd" if sys.platform == "darwin" else "systemd"
    script_path = DEMO_DIR / daemon_name

    script_content = f"""#!/usr/bin/env python3
import time
while True:
    time.sleep(5)
"""
    script_path.write_text(script_content)
    script_path.chmod(0o755)

    proc = subprocess.Popen([sys.executable, str(script_path)], start_new_session=True)
    state["pids"].append(proc.pid)
    state["files"].append(str(script_path))
    state["stages"].append("Stage 4: Masquerading")
    _save_state(state)

    print_stage_box(
        4,
        "Process Masquerading as Critical System Daemon",
        "PROCESS_MASQUERADING",
        "T1036.005 (Masquerading: Match Legitimate Name)",
        f"Rogue program in /tmp claims to be system daemon '{daemon_name}' to fool analysts.",
        "SIEM engine flags [PROCESS_MASQUERADING] + [EXEC_IN_TEMP] -> High Severity (score 5)!"
    )
    print(f"  \033[32m✔ Launched masqueraded process (PID {proc.pid}) named '{daemon_name}'\033[0m")
    return proc.pid


def trigger_scan():
    """Trigger a scan via the scanner engine and print results."""
    print("\n\033[1m🔍 Triggering immediate HIDS security scan...\033[0m")
    try:
        sys.path.insert(0, str(BASE_DIR))
        from storage import db
        import scanner
        conn = db.connect()
        procs, alerts = scanner.run_scan(conn)
        conn.close()

        print(f"  \033[32m✔ Scan complete:\033[0m Evaluated {len(procs)} processes, generated {len(alerts)} alerts.")
        if alerts:
            print("\n  \033[1;33mTop Alerts Generated:\033[0m")
            for a in alerts[:5]:
                print(f"   • [{a.severity}] {a.subject} (PID {a.pid or '-'}): {a.reasons[0]}")
    except Exception as e:
        print(f"  ⚠️ Could not run scanner directly: {e}")
        print("  Tip: Click 'Scan now' button on your dashboard to see alerts.")


def cleanup():
    """Clean up all processes, files, and state."""
    print("\n\033[1;31m🧹 Cleaning up simulated attack processes and files...\033[0m")
    state = _load_state()

    # Kill PIDs
    for pid in state.get("pids", []):
        try:
            os.kill(pid, signal.SIGKILL)
            print(f"  ✔ Terminated demo PID {pid}")
        except (ProcessLookupError, PermissionError):
            pass

    # Remove files
    for file_path in state.get("files", []):
        try:
            p = Path(file_path)
            if p.exists():
                p.unlink()
                print(f"  ✔ Removed file {file_path}")
        except Exception as e:
            print(f"  ⚠️ Could not remove {file_path}: {e}")

    # Remove demo dir
    if DEMO_DIR.exists():
        import shutil
        shutil.rmtree(DEMO_DIR, ignore_errors=True)
        print(f"  ✔ Removed temporary directory {DEMO_DIR}")

    # Clean up LaunchAgent if present
    if MACOS_LAUNCH_AGENT.exists():
        try:
            MACOS_LAUNCH_AGENT.unlink()
            print(f"  ✔ Removed {MACOS_LAUNCH_AGENT}")
        except Exception:
            pass

    print("\n\033[1;32m✔ System baseline restored. All simulated threats cleared.\033[0m\n")


def print_status():
    """Print current simulation status."""
    state = _load_state()
    pids = state.get("pids", [])
    alive = []
    for pid in pids:
        try:
            os.kill(pid, 0)
            alive.append(pid)
        except OSError:
            pass

    print("\n\033[1m📊 Current Simulation Status:\033[0m")
    print(f"  Active stages:   {', '.join(state.get('stages', [])) or 'None'}")
    print(f"  Live demo PIDs:  {alive or 'None'}")
    print(f"  Files created:   {len(state.get('files', []))}")
    if alive:
        print("\n  \033[33mThreats are currently ACTIVE. Run 'python3 tools/demo_presentation.py stop' to clean up.\033[0m")
    else:
        print("  \033[32mSystem is clean.\033[0m")


def interactive_menu():
    print_banner()
    while True:
        print("""
\033[1mSelect a demonstration stage for your audience:\033[0m
  [1] Stage 1: Suspicious Execution in /tmp (EXEC_IN_TEMP)
  [2] Stage 2: Startup Persistence Entry (PERSISTENCE_TARGET_SUSPICIOUS)
  [3] Stage 3: Simulated Reverse Shell (REVERSE_SHELL_PATTERN)
  [4] Stage 4: Process Masquerading (PROCESS_MASQUERADING)
  ------------------------------------------------------------------
  [5] 🚀 Run FULL 4-Stage End-to-End Simulation
  [6] 🔍 Trigger Scan & Print Terminal Alert Summary
  [7] 🧹 Clean Up Everything & Reset to Baseline
  [8] 📊 Check Status of Demo Processes
  [0] Exit
""")
        try:
            choice = input("\033[1;36mEnter choice [0-8]: \033[0m").strip()
        except (KeyboardInterrupt, EOFError):
            print("\nExiting.")
            break

        if choice == "1":
            stage_1_temp_execution()
            trigger_scan()
        elif choice == "2":
            stage_2_persistence()
            trigger_scan()
        elif choice == "3":
            stage_3_reverse_shell()
            trigger_scan()
        elif choice == "4":
            stage_4_masquerading()
            trigger_scan()
        elif choice == "5":
            print("\n\033[1;35m🚀 Launching Full 4-Stage Capstone Attack Simulation...\033[0m")
            stage_1_temp_execution()
            time.sleep(1)
            stage_2_persistence()
            time.sleep(1)
            stage_3_reverse_shell()
            time.sleep(1)
            stage_4_masquerading()
            time.sleep(1)
            trigger_scan()
            print("""
\033[1;32m========================================================================
  ✔ ALL 4 ATTACK SCENARIOS ARE ACTIVE!
  👉 Open your browser at http://127.0.0.1:5055/alerts
  Demonstrate to your evaluators:
    1. High and Medium severity correlated alerts
    2. Formal MITRE ATT&CK technique tags
    3. The in-app 'Terminate Process' button to remediate the threats
========================================================================\033[0m""")
        elif choice == "6":
            trigger_scan()
        elif choice == "7":
            cleanup()
        elif choice == "8":
            print_status()
        elif choice == "0":
            print("\nGoodbye!")
            break
        else:
            print("Invalid choice, please select 0-8.")


if __name__ == "__main__":
    if len(sys.argv) > 1:
        cmd = sys.argv[1].lower()
        if cmd == "start":
            stage_1_temp_execution()
            stage_2_persistence()
            stage_3_reverse_shell()
            stage_4_masquerading()
            trigger_scan()
        elif cmd == "stop" or cmd == "cleanup":
            cleanup()
        elif cmd == "status":
            print_status()
        else:
            print(__doc__)
    else:
        interactive_menu()
