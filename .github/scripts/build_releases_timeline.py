#!/usr/bin/env python3
"""
从 Version History API 数据（data/version-history.json）构建前端轻量版本时间线
（data/releases-timeline.json），并关联官方安全公告（data/releases.json）。

输出结构：
{
  "generated_at": "...",
  "channels": [...],
  "versions": {
    "stable": [["151.0.7922.137", "2026-08-19", 1, 0], ...],  # [版本, 发布日, 公告CVE数, in_the_wild]
    ...
  },
  "announcements": { "151.0.7922.137": {"title": ..., "url": ..., "published": ...} }
}
"""

import json
import re
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
DATA = ROOT / 'data'

VER_RE = re.compile(r'^\d+\.\d+\.\d+\.\d+$')


def load_version_history():
    try:
        d = json.loads((DATA / 'version-history.json').read_text())
    except (json.JSONDecodeError, FileNotFoundError):
        return {}
    return d.get('version_history') or {}


def load_announcements():
    try:
        d = json.loads((DATA / 'releases.json').read_text())
    except (json.JSONDecodeError, FileNotFoundError):
        return {}, {}
    ann, verinfo = {}, {}
    for r in d.get('releases', []):
        v = r.get('version', '')
        if not VER_RE.match(v):
            continue
        # 同一版本多条公告（多平台/多次更新）取 cves 并集、in_the_wild 真值
        cur = verinfo.get(v, {'cves': 0, 'in_the_wild': False, 'published': ''})
        cur['cves'] += len(r.get('cves') or [])
        cur['in_the_wild'] = cur['in_the_wild'] or bool(r.get('in_the_wild'))
        announced = r.get('published', '')
        if announced and (not cur['published'] or announced < cur['published']):
            cur['published'] = announced[:10]
        verinfo[v] = cur
        ann.setdefault(v, []).append({
            'title': r.get('title', ''),
            'url': r.get('url', ''),
            'published': announced[:10],
        })
    return ann, verinfo


def norm_date(s):
    if not s:
        return ''
    return s[:10]


def main():
    vh = load_version_history()
    announcements, verinfo = load_announcements()

    versions = {}
    for ch, data in vh.items():
        first_seen = {}
        for rel in data.get('releases', []):
            ver = rel.get('version', '')
            st = (rel.get('serving') or {}).get('startTime', '')
            if not VER_RE.match(ver) or not st:
                continue
            if ver not in first_seen or st < first_seen[ver]:
                first_seen[ver] = st
        items = []
        for ver, st in first_seen.items():
            vi = verinfo.get(ver, {'cves': 0, 'in_the_wild': False})
            items.append([ver, norm_date(st), vi['cves'], 1 if vi['in_the_wild'] else 0])
        items.sort(key=lambda x: (x[1], x[0]), reverse=True)
        versions[ch] = items

    # 公告独立存（版本 → 公告列表）
    ann_out = {}
    for ver, lst in announcements.items():
        ann_out[ver] = lst[0] if len(lst) == 1 else lst

    output = {
        'generated_at': datetime.now(timezone.utc).isoformat(),
        'source': 'versionhistory.googleapis.com + chromium releases blog',
        'channels': list(versions.keys()),
        'version_count': {ch: len(items) for ch, items in versions.items()},
        'versions': versions,
        'announcements': ann_out,
    }
    (DATA / 'releases-timeline.json').write_text(
        json.dumps(output, ensure_ascii=False, separators=(',', ':')) + '\n', encoding='utf-8')

    total = sum(len(items) for items in versions.values())
    size = (DATA / 'releases-timeline.json').stat().st_size // 1024
    print(f'Wrote data/releases-timeline.json: {total} version records ({size} KB)')


if __name__ == '__main__':
    main()