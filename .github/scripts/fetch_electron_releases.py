#!/usr/bin/env python3
"""Fetch full Electron release history from the official releases API.

Caches to data/electron-releases.json. On network failure the previous
cache is kept (exit 0) so the pipeline never breaks on transient errors.
"""
import json
import os
import sys
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, "..", "..", "data")
OUT = os.path.join(DATA, "electron-releases.json")
EOL_OUT = os.path.join(DATA, "electron-eol.json")
URL = "https://releases.electronjs.org/releases.json"
EOL_URL = "https://endoflife.date/api/electron.json"


def fetch(url, out, validate):
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "chromium-intel/1.0"})
        with urllib.request.urlopen(req, timeout=60) as resp:
            raw = resp.read()
        data = json.loads(raw)
        if not validate(data):
            print(f"unexpected payload for {url}, keeping cache")
            return False
        with open(out, "w") as f:
            json.dump(data, f, separators=(",", ":"))
        print(f"{os.path.basename(out)}: {len(data)} entries ({len(raw) // 1024} KB)")
        return True
    except Exception as e:
        print(f"fetch {url} failed ({e}); keeping existing cache")
        return False


def main():
    os.makedirs(DATA, exist_ok=True)
    fetch(URL, OUT, lambda d: isinstance(d, list) and len(d) >= 1000)
    fetch(EOL_URL, EOL_OUT, lambda d: isinstance(d, list) and len(d) >= 30)
    return 0


if __name__ == "__main__":
    sys.exit(main())