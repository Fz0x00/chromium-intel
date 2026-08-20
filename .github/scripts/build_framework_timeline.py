#!/usr/bin/env python3
"""Build framework sync timeline: Electron releases -> embedded Chromium.

Inputs:
  data/electron-releases.json  (official full release history)
  data/releases-timeline.json  (Chrome channel timelines; for stable dates)

Output:
  data/framework-timeline.json — compact, frontend-ready:
  {
    "generated_at": iso,
    "reference": {"chromium_stable": "...", "chromium_stable_date": "...", "electron_latest": "..."},
    "electron": {
      "count": N,
      "versions": [ [ver, date, chromium, node, delta_days], ... ],   # stable only, date desc
      "by_chromium": { "142.0.7444.265": ["39.3.0", ...], ... },      # exact-capable lookup
      "majors": { "39": {"count": n, "min": "...", "max": "...", "first": "date", "latest": "date"} }
    }
  }

delta_days = days between this Electron release date and the date the same
Chromium build went stable (from Chrome stable timeline); null if unknown.
"""
import json
import os
import re
import sys
from datetime import date, datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, "..", "..", "data")
OUT = os.path.join(DATA, "framework-timeline.json")


def parse_date(s):
    try:
        return datetime.strptime(s[:10], "%Y-%m-%d").date()
    except Exception:
        return None


def stable_date_for(build, stable_dates):
    """Best-known stable date for a chromium build: exact match first,
    else the newest numerically-smaller same major.minor build in the
    stable timeline (lexicographic compare would misorder e.g. .103 vs .69)."""
    if build in stable_dates:
        return stable_dates[build]
    prefix = ".".join(build.split(".")[:2]) + "."
    cand = [
        v for v in stable_dates
        if v.startswith(prefix) and cmp_ver(v, build) < 0 and len(v.split(".")) == 4
    ]
    return stable_dates[max(cand, key=lambda v: tuple(int(p) for p in v.split(".")))] if cand else None


def cmp_ver(a, b):
    at = tuple(int(x) for x in a.split("."))
    bt = tuple(int(x) for x in b.split("."))
    return (at > bt) - (at < bt)


def main():
    rel_path = os.path.join(DATA, "electron-releases.json")
    if not os.path.exists(rel_path):
        print("electron-releases.json missing, run fetch_electron_releases.py first")
        return 1
    with open(rel_path) as f:
        releases = json.load(f)

    stable_dates = {}
    tl_path = os.path.join(DATA, "releases-timeline.json")
    if os.path.exists(tl_path):
        with open(tl_path) as f:
            tl = json.load(f)
        for ver, date_, *_ in tl.get("versions", {}).get("stable", []):
            stable_dates[ver] = date_

    eol = {}
    eol_path = os.path.join(DATA, "electron-eol.json")
    if os.path.exists(eol_path):
        with open(eol_path) as f:
            for c in json.load(f):
                eol[c.get("cycle")] = c
    today = date.today().isoformat()

    stable = [r for r in releases if r.get("version") and "-" not in r["version"]]
    stable.sort(key=lambda r: r["date"], reverse=True)

    versions, by_chromium, majors = [], {}, {}
    for r in stable:
        ver, date_, chrome = r["version"], r.get("date", ""), r.get("chrome", "")
        node = r.get("node", "")
        if not chrome:
            continue
        by_chromium.setdefault(chrome, []).append(ver)
        delta = None
        sdate = stable_date_for(chrome, stable_dates)
        rd = parse_date(date_)
        if sdate and rd:
            sd = parse_date(sdate)
            if sd:
                delta = (rd - sd).days
        if delta is not None and delta < 0:
            # A kernel age cannot be negative: negative values only arise from
            # date-granularity edges or missing timeline data. Treat as unknown.
            delta = None
        versions.append([ver, date_, chrome, node, delta])

        major = ver.split(".")[0]
        m = majors.setdefault(major, {"count": 0, "min": chrome, "max": chrome,
                                      "first": date_, "latest": date_})
        m["count"] += 1
        if cmp_ver(chrome, m["min"]) < 0:
            m["min"] = chrome
        if cmp_ver(chrome, m["max"]) > 0:
            m["max"] = chrome
        if date_ < m["first"]:
            m["first"] = date_
        if date_ > m["latest"]:
            m["latest"] = date_
        m["chromium_major"] = chrome.split(".")[0] if chrome else ""
        c = eol.get(major, {})
        m["eol"] = c.get("eol", "")
        m["support"] = bool(m["eol"] and m["eol"] >= today)
        if c:
            m["chrome"] = c.get("chromeVersion", "")
            m["eol_latest"] = c.get("latest", "")

    ref = {"chromium_stable": max(stable_dates, key=stable_dates.get) if stable_dates else None,
           "chromium_stable_date": stable_dates.get(max(stable_dates, key=stable_dates.get)) if stable_dates else None,
           "electron_latest": versions[0][0] if versions else None,
           "electron_latest_date": versions[0][1] if versions else None}

    out = {"generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
           "reference": ref,
           "electron": {"count": len(versions), "versions": versions,
                        "by_chromium": {k: v for k, v in sorted(by_chromium.items(), reverse=True)},
                        "majors": majors}}
    with open(OUT, "w") as f:
        json.dump(out, f, separators=(",", ":"))
    print(f"framework-timeline.json: {len(versions)} stable electron releases, "
          f"{len(by_chromium)} distinct chromium builds, {len(majors)} majors")


if __name__ == "__main__":
    sys.exit(main())