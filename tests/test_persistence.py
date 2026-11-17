import plistlib
from sensors import persistence_sensor as ps


def test_launch_agent_plist_target(tmp_path):
    f = tmp_path / "com.example.agent.plist"
    f.write_bytes(plistlib.dumps({"Label": "x", "ProgramArguments": ["/tmp/.evil", "--run"]}))
    assert ps._plist_target(str(f)) == "/tmp/.evil"


def test_launch_agent_script_target(tmp_path):
    f = tmp_path / "a.plist"
    f.write_bytes(plistlib.dumps({"ProgramArguments": ["/usr/bin/python3", "/tmp/x.py"]}))
    assert ps._plist_target(str(f)) == "/tmp/x.py"


def test_bad_plist_does_not_crash(tmp_path):
    f = tmp_path / "bad.plist"; f.write_text("not a plist")
    assert ps._plist_target(str(f)) == ""
