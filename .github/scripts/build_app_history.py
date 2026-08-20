#!/usr/bin/env python3
"""
从 chromium-intel 仓库 git 历史重建 per-app 版本历史（app-history.json）。

遍历 data/assets.json 的每次变更提交，聚合每个 app 出现过的
(app_version, chromium_version) 及其首次 / 最后被发现的时间，
并映射捆绑 Chromium 版本的官方发布日期（data/releases.json）。

输出 data/app-history.json，之后每次 assets.json 更新都会自然包含在该
脚本的输入范围内（基于 git 历史，幂等重建）。
"""

import json
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
DATA = ROOT / 'data'

APP_VER_RE = re.compile(r'^\d+(\.\d+){1,3}([-+][0-9A-Za-z._-]+)?$')
CHROME_VER_RE = re.compile(r'^\d+\.\d+\.\d+\.\d+$')


def git_log(root):
    out = subprocess.run(
        ['git', 'log', '--reverse', '--format=%H|%ct', '--', 'data/assets.json'],
        cwd=str(root), capture_output=True, text=True, check=True,
    )
    lines = [l for l in out.stdout.splitlines() if l.strip()]
    if len(lines) <= 1:
        print('WARNING: shallow checkout or no history — app history will be '
              'limited to the current snapshot (ensure fetch-depth: 0 for CI)')
    for line in lines:
        sha, ctime = line.split('|')
        yield sha, datetime.fromtimestamp(int(ctime), tz=timezone.utc)


def git_show(root, sha, path):
    out = subprocess.run(
        ['git', 'show', f'{sha}:{path}'],
        cwd=str(root), capture_output=True, text=True,
    )
    if out.returncode != 0:
        return None
    try:
        return json.loads(out.stdout)
    except json.JSONDecodeError:
        return None


def parse_scan_time(v):
    ts = (v or '').strip()
    if not ts:
        return None
    try:
        d = datetime.fromisoformat(ts.replace('Z', '+00:00'))
        return d.astimezone(timezone.utc).isoformat()
    except ValueError:
        return None


def sort_key(v):
    parts = re.split(r'[-+.]', v)
    sk = []
    for p in parts:
        if p.isdigit():
            sk.append((0, int(p)))
        else:
            sk.append((1, p))
    return sk


def load_release_dates():
    try:
        d = json.loads((DATA / 'releases.json').read_text())
    except (json.JSONDecodeError, FileNotFoundError):
        return {}, {}
    dates, cves = {}, {}
    for r in d.get('releases', []):
        v = r.get('version', '')
        pub = r.get('published', '')
        if CHROME_VER_RE.match(v) and pub:
            dates.setdefault(v, pub[:10])
            cves.setdefault(v, len(r.get('cves') or []))
    return dates, cves


def load_scan_history():
    """读取 hunter 侧持久化的扫描观察记录（data/app-history-scan.json，可选）。"""
    try:
        d = json.loads((DATA / 'app-history-scan.json').read_text())
    except (json.JSONDecodeError, FileNotFoundError):
        return {}
    out = {}
    for ob in d.get('observations') or []:
        name = (ob.get('app_name') or '').strip()
        ver = (ob.get('app_version') or '').strip()
        chrome = (ob.get('chromium_version') or '').strip()
        if not name or not APP_VER_RE.match(ver) or not CHROME_VER_RE.match(chrome):
            continue
        out.setdefault(name, []).append(ob)
    return out


def merge_seen(v, first, last):
    if first and (not v.get('first_seen') or first < v['first_seen']):
        v['first_seen'] = first
    if last and (not v.get('last_seen') or last > v['last_seen']):
        v['last_seen'] = last


def main():
    release_dates, release_cves = load_release_dates()

    apps = {}
    for sha, commit_at in git_log(ROOT):
        snapshot = git_show(ROOT, sha, 'data/assets.json')
        if not snapshot:
            continue
        seen_at = parse_scan_time(snapshot.get('scan_time')) or commit_at.isoformat()
        seen_day = seen_at[:10]
        for a in snapshot.get('apps') or []:
            name = (a.get('app_name') or '').strip()
            if not name:
                continue
            ver = (a.get('app_version') or '').strip()
            chrome = (a.get('chromium_version') or '').strip()
            if not APP_VER_RE.match(ver) or not CHROME_VER_RE.match(chrome):
                continue
            rec = apps.setdefault(name, {
                'framework': a.get('framework', ''),
                'platform': a.get('platform', ''),
                'versions': {},
            })
            key = f'{ver}|{chrome}'
            v = rec['versions'].setdefault(key, {
                'app_version': ver,
                'chromium_version': chrome,
                'electron_version': '',
                'first_seen': '',
                'last_seen': '',
            })
            merge_seen(v, seen_day, seen_day)

    # 叠加 hunter 扫描通道（含 electron_version 与精确时间戳）
    for name, obs in load_scan_history().items():
        rec = apps.setdefault(name, {'framework': '', 'platform': '', 'versions': {}})
        if not rec['platform']:
            rec['platform'] = obs[0].get('platform', '')
        for ob in obs:
            ver = (ob.get('app_version') or '').strip()
            chrome = (ob.get('chromium_version') or '').strip()
            key = f'{ver}|{chrome}'
            v = rec['versions'].setdefault(key, {
                'app_version': ver,
                'chromium_version': chrome,
                'electron_version': '',
                'first_seen': '',
                'last_seen': '',
            })
            merge_seen(v, ob.get('first_seen'), ob.get('last_seen'))
            if ob.get('electron_version') and not v.get('electron_version'):
                v['electron_version'] = ob['electron_version']

    result = {}
    for name, rec in sorted(apps.items()):
        versions = [v for v in rec['versions'].values()]
        versions.sort(key=lambda v: (sort_key(v['app_version']), v['app_version']), reverse=True)
        for v in versions:
            v['chromium_release_date'] = release_dates.get(v['chromium_version'], '')
            n = release_cves.get(v['chromium_version'])
            v['chromium_release_cves'] = n if n is not None else 0
        current = versions[0] if versions else None
        result[name] = {
            'framework': rec['framework'],
            'platform': rec['platform'],
            'current': current,
            'versions': versions,
        }

    output = {
        'generated_at': datetime.now(timezone.utc).isoformat(),
        'source': 'assets.json git history + hunter scan history',
        'total_apps': len(result),
        'apps': result,
    }
    (DATA / 'app-history.json').write_text(
        json.dumps(output, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(f'Wrote data/app-history.json: {len(result)} apps, '
          f'{sum(len(a["versions"]) for a in result.values())} version records')


if __name__ == '__main__':
    main()