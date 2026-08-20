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
URL = "https://releases.electronjs.org/releases.json"


def main():
    os.makedirs(DATA, exist_ok=True)
    try:
        req = urllib.request.Request(URL, headers={"User-Agent": "chromium-intel/1.0"})
        with urllib.request.urlopen(req, timeout=60) as resp:
            raw = resp.read()
        data = json.loads(raw)
        if not isinstance(data, list) or len(data) < 1000:
            print(f"unexpected payload ({len(data)} entries), keeping cache")
            return 0
        with open(OUT, "w") as f:
            json.dump(data, f, separators=(",", ":"))
        print(f"electron-releases.json: {len(data)} releases ({len(raw) // 1024} KB)")
        return 0
    except Exception as e:
        print(f"fetch failed ({e}); keeping existing cache")
        return 0


if __name__ == "__main__":
    sys.exit(main())