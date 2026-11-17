"""Start the HIDS: background scanner + local dashboard (host/port from config.py)."""
import config
from web.app import create_app

if __name__ == "__main__":
    create_app().run(host=config.HOST, port=config.PORT, debug=False)
