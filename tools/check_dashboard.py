#!/usr/bin/env python3
"""Check the existing local HIDS HTTP endpoints; does not need login or change data."""
from urllib.request import urlopen
from urllib.error import URLError, HTTPError

import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config
BASE = f'http://{config.HOST}:{config.PORT}'


def main():
    checks = [
        ('Login page', '/login', b'HIDS'),
        ('Stylesheet', '/static/style.css', None),
        ('Dashboard CSS', '/static/dashboard_v2.css', None),
        ('Dashboard JavaScript', '/static/dashboard_v2.js', b'analytics'),
    ]
    passed = 0
    for label, path, required in checks:
        try:
            with urlopen(BASE + path, timeout=4) as res:
                data = res.read()
                ok = res.status == 200 and (required is None or required in data)
                print(('PASS' if ok else 'FAIL') + f': {label} (HTTP {res.status}, {len(data)} bytes)')
                passed += bool(ok)
        except (URLError, HTTPError, OSError) as exc:
            print(f'FAIL: {label} ({exc})')
    print(f'{passed}/{len(checks)} checks passed')
    if passed == len(checks):
        print('If Safari still shows white, use Command+Shift+R or open a private window; also check Safari Develop > Show JavaScript Console.')
    else:
        print('Check the Terminal running HIDS for errors. Do not delete your hids.db or hids_secret.key.')
    return 0 if passed == len(checks) else 1

if __name__ == '__main__':
    raise SystemExit(main())
