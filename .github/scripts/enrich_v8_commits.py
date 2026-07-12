#!/usr/bin/env python3
"""
为高价值 V8 CVE（KEV + in-the-wild）提取 commit 级别的版本信息。

从 Gerrit CL 详情中解析：
- 修复 commit hash
- 修复所在 Chromium 版本
- 影响范围（introduced → fixed）
- V8 版本映射

输出：追加到 data/exploit-intel.json
"""
import json, re, sys
from pathlib import Path
from urllib.request import urlopen, Request
from urllib.error import HTTPError
import time

DATA_DIR = Path(__file__).resolve().parent.parent.parent / 'data'
GERRIT_API = 'https://chromium-review.googlesource.com/changes/'

# Chromium 大版本 ↔ V8 版本映射（Electron/Chrome 已知数据点）
# 用于从 Chromium version 推导 V8 version
CHROMIUM_TO_V8 = {
    '60': '6.0',
    '64': '6.4',
    '70': '7.0',
    '80': '8.0',
    '90': '9.0',
    '100': '10.0',
    '108': '10.8',
    '116': '11.6',
    '120': '12.0',
    '124': '12.4',
    '128': '12.8',
    '132': '13.2',
    '134': '13.4',
    '136': '13.6',
    '138': '13.8',
    '139': '13.9',
}

def chromium_to_v8_approx(chrome_major):
    """从 Chromium 大版本号估算 V8 版本"""
    for c_ver in sorted(CHROMIUM_TO_V8.keys(), key=int, reverse=True):
        if int(chrome_major) >= int(c_ver):
            return CHROMIUM_TO_V8[c_ver]
    return f"{int(chrome_major) // 10}.{int(chrome_major) % 10}"

def fetch_gerrit_detail(gerrit_url, cache):
    """从 Gerrit 获取 CL 详情，含 commit message"""
    if gerrit_url in cache:
        return cache[gerrit_url]
    
    # Gerrit URL 格式: https://chromium-review.googlesource.com/c/v8/v8/+/1234567
    if '/c/' not in gerrit_url:
        return None
    
    try:
        change_id = gerrit_url.split('/c/')[1].split('/+/')[0] + '~' + gerrit_url.split('+/')[1]
        api_url = f"https://chromium-review.googlesource.com/changes/{change_id}?o=CURRENT_REVISION&o=CURRENT_COMMIT"
        req = Request(api_url)
        resp = urlopen(req, timeout=10)
        # Gerrit returns )]}' prefix
        text = resp.read().decode('utf-8')
        text = text[text.index('\n') + 1:] if text.startswith(")]}'") else text
        detail = json.loads(text)
        cache[gerrit_url] = detail
        return detail
    except Exception as e:
        print(f"  Gerrit fetch error: {e}", file=sys.stderr)
        return None

def parse_commit_info(detail):
    """从 Gerrit CL 详情中提取 commit 信息"""
    if not detail:
        return None
    
    info = {}
    try:
        revisions = detail.get('revisions', {})
        for rev_id, rev in revisions.items():
            commit = rev.get('commit', {})
            msg = commit.get('message', '')
            
            # 提取 commit hash
            info['commit'] = rev_id[:12] if rev_id else None
            
            # 提取 Cr-Commit-Position
            m = re.search(r'Cr-Commit-Position: refs/heads/main@{#(\d+)}', msg)
            if m:
                info['commit_position'] = int(m.group(1))
            
            # 提取 Reviewed-on
            m = re.search(r'Reviewed-on: (https://[^\s]+)', msg)
            if m:
                info['review_url'] = m.group(1)
            
            # 提取 Bug 引用
            bugs = re.findall(r'Bug: (?:chromium:)?(\d+)', msg)
            if bugs:
                info['bug_ids'] = bugs
            
            # 提取 Regression/引入信息
            if 'regression' in msg.lower() or 'introduced' in msg.lower():
                m = re.search(r'(?:regression from|introduced (?:in|by))\s*(?:commit\s+)?([a-f0-9]{7,40})', msg, re.IGNORECASE)
                if m:
                    info['introduced_by'] = m.group(1)[:12]
            
            # 提取 Fixes
            m = re.search(r'(?:Fixed|Fixes)[:\s]+(\d+)', msg, re.IGNORECASE)
            if m:
                info['fixes_bug'] = m.group(1)
            
            # 提取分支信息
            branches = re.findall(r'\((?:cherry[-\s]pick|merge).*?(M\d+)', msg, re.IGNORECASE)
            if branches:
                info['cherry_pick_branches'] = branches
            
            break  # 只看第一个 revision
    except Exception as e:
        print(f"  Parse error: {e}", file=sys.stderr)
    
    return info if info else None

def extract_fixed_version(cve):
    """从 CVE 提取 Chromium 修复版本"""
    versions = cve.get('versions', [])
    if versions:
        m = re.search(r'(\d+\.\d+\.\d+\.\d+)', versions[0])
        if m:
            return m.group(1)
    desc = cve.get('description', '')
    m = re.search(r'prior to (\d+\.\d+\.\d+\.\d+)', desc)
    if m:
        return m.group(1)
    return None

def main():
    risk = json.loads((DATA_DIR / 'risk-report.json').read_text())
    
    # 筛选高价值 V8 CVE
    high_value = [c for c in risk['cves'] 
                  if c.get('version_granularity') == 'v8'
                  and (c.get('in_kev') or c.get('in_the_wild'))]
    
    print(f"High-value V8 CVEs: {len(high_value)}")
    
    # 加载现有 exploit-intel
    intel_path = DATA_DIR / 'exploit-intel.json'
    existing = json.loads(intel_path.read_text()) if intel_path.exists() else []
    existing_ids = {e['cve_id'] for e in existing}
    
    # 加载 Gerrit 缓存
    gerrit_cache_file = DATA_DIR / 'gerrit-cache.json'
    gerrit_cache = json.loads(gerrit_cache_file.read_text()) if gerrit_cache_file.exists() else {}
    
    # Gerrit 详情缓存
    gerrit_detail_cache = {}
    
    new_entries = 0
    for cve in sorted(high_value, key=lambda c: c['id']):
        cve_id = cve['id']
        if cve_id in existing_ids:
            continue
        
        gerrit_url = cve.get('gerrit_url', '')
        if not gerrit_url:
            print(f"  {cve_id}: no Gerrit URL, skip")
            continue
        
        print(f"  {cve_id}...", end=' ')
        
        detail = fetch_gerrit_detail(gerrit_url, gerrit_detail_cache)
        info = parse_commit_info(detail)
        
        fixed_ver = extract_fixed_version(cve)
        chrome_major = fixed_ver.split('.')[0] if fixed_ver else '?'
        v8_approx = chromium_to_v8_approx(chrome_major)
        
        entry = {
            'cve_id': cve_id,
            'component': 'V8',
            'version_granularity': 'v8',
            'chromium_fixed': fixed_ver,
            'v8_fixed_approx': v8_approx,
            'commit_info': info,
            'exploit_status': {
                'level': 'ANALYZED',
                'label': 'patch_analysis',
                'detail': f'Fixed in Chromium {fixed_ver} (V8 ≈ {v8_approx}). Gerrit patch analyzed.'
            },
            'in_kev': cve.get('in_kev', False),
            'in_the_wild': cve.get('in_the_wild', False),
            'description': cve.get('description', '')[:200],
            'published': cve.get('published', ''),
            'last_updated': '2026-07-02',
        }
        
        if info and info.get('introduced_by'):
            entry['commit_info']['introduced_by'] = info['introduced_by']
            print(f"commit={info.get('commit','?')} pos={info.get('commit_position','?')} introduced={info.get('introduced_by','?')}")
        elif info:
            print(f"commit={info.get('commit','?')} pos={info.get('commit_position','?')}")
        else:
            print("no detail")
        
        existing.append(entry)
        new_entries += 1
        
        # Gerrit API rate limit
        time.sleep(0.5)
    
    if new_entries > 0:
        intel_path.write_text(json.dumps(existing, indent=2, ensure_ascii=False))
        print(f"\nAdded {new_entries} new entries to exploit-intel.json")
    else:
        print("\nNo new entries (all already exist)")

if __name__ == '__main__':
    main()
