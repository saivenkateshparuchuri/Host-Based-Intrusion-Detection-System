"""Start the HIDS: background scanner + local dashboard (host/port from config.py)."""
import os
import sys
import subprocess
import config
from web.app import create_app

if __name__ == "__main__":
    if "--menubar" in sys.argv:
        menubar_bin = os.path.join(os.path.dirname(__file__), "tools", "HIDSMenuBar")
        if os.path.exists(menubar_bin):
            subprocess.Popen([menubar_bin])
    create_app().run(host=config.HOST, port=config.PORT, debug=False)

