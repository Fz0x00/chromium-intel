#!/usr/bin/env python3
"""
资产风险评估：将 hunter 上报的资产清单（assets.json）与 CVE 数据库匹配，
找出每个 app 受影响的 CVE，生成 asset-risk-report.json。

输入：
  data/risk-report.json  — CVE 数据库（含 exploitability 评估）
  data/assets.json       — hunter 上报的资产清单

输出：
  data/asset-risk-report.json — 每个 app 的匹配结果
"""

import json
import re
from datetime import datetime
from pathlib import Path


VER_RE = re.compile(r'(\d+)\.(\d+)\.(\d+)\.(\d+)')
PRIOR_RE = re.compile(r'(?:prior to|before)\s+(\d+\.\d+\.\d+\.\d+)', re.IGNORECASE)
ANDROID_RE = re.compile(r'on android', re.IGNORECASE)
IOS_RE = re.compile(r'on ios|on iphone', re.IGNORECASE)


def parse_version(v):
    m = VER_RE.search(v or '')
    if not m:
        return None
    return tuple(int(x) for x in m.groups())


def cmp_ver(a, b):
    """a < b → -1, a == b → 0, a > b → 1"""
    va, vb = parse_version(a), parse_version(b)
    if va is None or vb is None:
        return 0
    if va < vb:
        return -1
    if va > vb:
        return 1
    return 0


def get_fixed_version(cve):
    """从 CVE 提取修复版本"""
    versions = cve.get('versions', [])
    if versions:
        v = versions[0]
        m = VER_RE.search(v)
        if m:
            return m.group(0)
    desc = cve.get('description', '')
    m = PRIOR_RE.search(desc)
    if m:
        return m.group(1)
    m = VER_RE.search(desc)
    if m:
        return m.group(0)
    return None


def is_desktop_cve(cve):
    """判断是否影响桌面平台（排除 Android/iOS only）"""
    desc = cve.get('description', '')
    if ANDROID_RE.search(desc) and 'desktop' not in desc.lower() and 'on windows' not in desc.lower() and 'on mac' not in desc.lower() and 'on linux' not in desc.lower():
        return False
    if IOS_RE.search(desc) and 'desktop' not in desc.lower():
        return False
    return True


def classify(cve, fixed_ver, app_chromium_ver=''):
    """分类 CVE 优先级，带 exploitability confidence

    confidence 分级:
      VERIFIED — exploit 在此 app 版本上已验证通过
      LIKELY   — 组件匹配 + 有公开 PoC/补丁/已验证数据
      RANGE    — 仅 CVE 版本号在范围内，无额外 exploit 证据

    版本粒度感知：
      对于 Blink/Skia/ANGLE 等与 Chromium release 同步的组件，
      Chromium 版本匹配即视为充分。对于 V8 等独立开发的组件，
      需要 V8 特定版本验证。
    """
    in_kev = cve.get('in_kev', False)
    in_wild = cve.get('in_the_wild', False)
    has_poc = cve.get('has_public_exploit', False)
    has_patch = bool(cve.get('bug_url') or cve.get('gerrit_url'))

    exploit_intel = cve.get('exploit_intel', {})
    exploit_status = exploit_intel.get('exploit_status', {})
    v8_range = exploit_intel.get('v8_exploit_range', {})
    # exploit-intel 可覆盖自动标记的 granularity
    granularity = exploit_intel.get('version_granularity') or cve.get('version_granularity', 'chromium')
    is_exploit_verified = exploit_status.get('level', '') in ('VERIFIED', 'VERIFIED_PARTIAL')
    tested_apps = exploit_intel.get('tested_apps', [])

    # 判断此 app 是否在已验证/已失败的版本上
    app_verified = False
    app_bad = False

    for ta in tested_apps:
        ta_ver = ta.get('chromium', '')
        # 模糊匹配：app chromium 版本以 tested 版本开头（如 "134.0.6998.88" 匹配 "134"）
        if ta_ver and (app_chromium_ver or '').startswith(ta_ver):
            result_lower = ta.get('result', '').lower()
            if any(w in result_lower for w in ('not triggered', 'too old', 'patched', 'does not')):
                app_bad = True
            elif any(w in result_lower for w in ('verified', 'works', 'confirmed')):
                app_verified = True

    # Assign confidence based on granularity
    if granularity == 'chromium':
        # Blink/Skia/ANGLE 等：Chromium 版本匹配就够
        if is_exploit_verified and not app_bad:
            confidence = 'VERIFIED'
        elif is_exploit_verified:
            confidence = 'LIKELY'
        elif has_poc or has_patch:
            confidence = 'LIKELY'
        else:
            confidence = 'RANGE'
    else:
        # V8 等独立开发组件：需要 V8 版本级别验证
        if app_verified:
            confidence = 'VERIFIED'
        elif is_exploit_verified and not app_bad:
            confidence = 'LIKELY'
        elif has_poc or has_patch:
            confidence = 'LIKELY'
        else:
            confidence = 'RANGE'

    if in_kev:
        priority = 'CRITICAL'
    elif in_wild:
        priority = 'HIGH'
    elif has_patch:
        priority = 'PATCH'
    else:
        priority = 'OTHER'

    result = {
        'id': cve['id'],
        'priority': priority,
        'confidence': confidence,
        'in_kev': in_kev,
        'in_the_wild': in_wild,
        'has_poc': has_poc,
        'has_patch': has_patch,
        'app_exploit_verified': app_verified,
        'component': cve.get('component', 'Unknown'),
        'published': cve.get('published', '')[:10],
        'description': (cve.get('description', '') or '')[:200],
        'fixed_version': fixed_ver,
        'blog_url': cve.get('blog_url', ''),
        'bug_url': cve.get('bug_url', ''),
        'gerrit_url': cve.get('gerrit_url', ''),
    }
    if is_exploit_verified:
        result['v8_range'] = v8_range.get('description', '')
        result['v8_note'] = cve.get('exploitability', {}).get('v8_note', '')
    if app_bad:
        result['v8_note'] = 'Exploit verified elsewhere but version behavior differs on this app'
    if has_poc:
        refs = cve.get('exploit_refs', [])
        if refs:
            result['exploit_refs'] = refs[:3]
    return result


def main():
    data_dir = Path(__file__).resolve().parent.parent.parent / 'data'

    # 加载 CVE 数据库
    risk = json.loads((data_dir / 'risk-report.json').read_text())
    cves = risk.get('cves', [])
    print(f"Loaded {len(cves)} CVEs from risk-report.json")

    # 预处理桌面 CVE + 修复版本
    desktop_cves = []
    for cve in cves:
        if not is_desktop_cve(cve):
            continue
        fv = get_fixed_version(cve)
        if fv:
            cve['_fixed'] = fv
            desktop_cves.append(cve)
    print(f"Desktop CVEs with known fix: {len(desktop_cves)}")

    # 加载资产清单
    assets_path = data_dir / 'assets.json'
    if not assets_path.exists():
        print(f"WARNING: {assets_path} not found — skipping asset matching")
        return
    assets = json.loads(assets_path.read_text()) or {}
    apps = assets.get('apps') or []
    print(f"Loaded {len(apps)} apps from assets.json")

    # 匹配
    results = []
    for app in apps:
        cv = app.get('chromium_version', '')
        if not cv or not parse_version(cv):
            continue

        matched = []
        counts = {'CRITICAL': 0, 'HIGH': 0, 'PATCH': 0, 'OTHER': 0}
        confidence_counts = {'VERIFIED': 0, 'LIKELY': 0, 'RANGE': 0}
        top_cves = []

        for cve in desktop_cves:
            if cmp_ver(cv, cve['_fixed']) < 0:
                mc = classify(cve, cve['_fixed'], cv)
                matched.append(mc)
                counts[mc['priority']] += 1
                confidence_counts[mc['confidence']] += 1
                if mc['priority'] in ('CRITICAL', 'HIGH'):
                    top_cves.append(mc)

        # 按优先级排序 top CVEs
        priority_order = {'CRITICAL': 0, 'HIGH': 1, 'PATCH': 2, 'OTHER': 3}
        top_cves.sort(key=lambda c: (priority_order[c['priority']], c['id']))

        results.append({
            'app_name': app.get('app_name', app.get('name', '?')),
            'app_version': app.get('app_version', ''),
            'framework': app.get('framework', ''),
            'chromium_version': cv,
            'platform': app.get('platform', assets.get('platform', '')),
            'total_cves': len(matched),
            'critical': counts['CRITICAL'],
            'high': counts['HIGH'],
            'has_patch': counts['PATCH'],
            'exploit_verified': confidence_counts['VERIFIED'],
            'exploit_likely': confidence_counts['LIKELY'],
            'exploit_range_only': confidence_counts['RANGE'],
            'top_cves': top_cves[:50],
        })

    # 排序：先 CRITICAL 降序，再 HIGH，再 TOTAL
    results.sort(key=lambda r: (-r['critical'], -r['high'], -r['total_cves']))

    output = {
        'generated_at': datetime.utcnow().isoformat() + 'Z',
        'assets_updated': assets.get('scan_time', ''),
        'total_apps': len(results),
        'total_critical': sum(r['critical'] for r in results),
        'total_high': sum(r['high'] for r in results),
        'total_verified': sum(r['exploit_verified'] for r in results),
        'apps': results,
    }

    out_path = data_dir / 'asset-risk-report.json'
    out_path.write_text(json.dumps(output, ensure_ascii=False))
    print(f"\nSaved asset risk report to {out_path}")
    print(f"  Apps: {len(results)}")
    print(f"  Critical (CISA KEV): {output['total_critical']}")
    print(f"  High (in-the-wild): {output['total_high']}")
    print(f"  Exploit verified: {output['total_verified']}")
    print(f"\nExploitability confidence breakdown:")
    print(f"  VERIFIED = exploit confirmed on this V8 version")
    print(f"  LIKELY   = component match + public PoC/patch exists")
    print(f"  RANGE    = in CVE version range only, no exploit validation")
    print(f"\nTop 5 at-risk apps:")
    for r in results[:5]:
        print(f"  {r['app_name']:24s} Chromium {r['chromium_version']:18s} "
              f"CRIT={r['critical']} HIGH={r['high']} "
              f"VERIF={r['exploit_verified']} LIKELY={r['exploit_likely']} RANGE={r['exploit_range_only']}")


if __name__ == '__main__':
    main()
