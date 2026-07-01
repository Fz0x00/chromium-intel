#!/usr/bin/env python3
"""从 cvelistV5 提取 Chromium 相关 CVE（精简版）"""

import json
import re
from datetime import datetime
from pathlib import Path


def extract_chromium_cves():
    """从 cvelistV5 提取 Chromium CVE，输出精简数据"""

    cve_dir = Path('data/cvelistV5/cves')
    if not cve_dir.exists():
        print(f"Error: {cve_dir} not found")
        return []

    print(f"Scanning {cve_dir}...")
    chromium_cves = []

    for year_dir in sorted(cve_dir.iterdir()):
        if not year_dir.is_dir():
            continue
        for subsection in year_dir.iterdir():
            if not subsection.is_dir():
                continue
            for cve_file in subsection.glob('*.json'):
                try:
                    cve_data = json.loads(cve_file.read_text())
                    if is_chromium_cve(cve_data):
                        parsed = parse_cve(cve_data)
                        if parsed:
                            chromium_cves.append(parsed)
                except Exception:
                    pass

    print(f"Found {len(chromium_cves)} Chromium CVEs")
    return chromium_cves


def is_chromium_cve(cve_data):
    """精确判断是否是 Chrome/Chromium CVE"""

    metadata = cve_data.get('cveMetadata', {})

    # 方法1: assignerShortName == 'Chrome' (最可靠的判断)
    if metadata.get('assignerShortName') == 'Chrome':
        return True

    # 方法2: affected 产品为 Chrome/Chromium，vendor 为 Google
    cna = cve_data.get('containers', {}).get('cna', {})
    for affected in cna.get('affected', []):
        product = (affected.get('product') or '').lower()
        vendor = (affected.get('vendor') or '').lower()

        if vendor == 'google' and ('chrome' in product or 'chromium' in product):
            return True

    return False


def parse_cve(cve_data):
    """解析 CVE 数据，只保留关键字段"""

    metadata = cve_data.get('cveMetadata', {})
    cna = cve_data.get('containers', {}).get('cna', {})

    cve_id = metadata.get('cveId', '')
    if not cve_id:
        return None

    # CVSS 分数
    cvss_score = 0
    for metric in cna.get('metrics', []):
        for key in ('cvssV3_1', 'cvssV3_0', 'cvssV4_0'):
            if key in metric:
                cvss_score = metric[key].get('baseScore', 0)
                break
        if cvss_score > 0:
            break

    # 描述（截断至 200 字符，足够展示漏洞类型）
    desc = ''
    for d in cna.get('descriptions', []):
        if d.get('lang') == 'en':
            desc = d.get('value', '')
            break
    if len(desc) > 200:
        desc = desc[:197] + '...'

    # 受影响版本
    versions = []
    for affected in cna.get('affected', []):
        product = (affected.get('product') or '').lower()
        if 'chrome' in product or 'chromium' in product:
            for v in affected.get('versions', []):
                lt = v.get('lessThan', '') or v.get('versionEndExcluding', '')
                lte = v.get('versionEndIncluding', '')
                ver = v.get('version', '')
                versions.append(lt or lte or ver)
    versions = list(set(versions))[:5]

    # 提取 references：bug tracker ID / Gerrit / Release Blog / Exploit refs
    bug_id = None
    gerrit_url = None
    blog_url = None
    exploit_refs = []
    for ref in cna.get('references', []):
        url = ref.get('url', '')
        if not url:
            continue
        tags = ref.get('tags', [])
        # Chromium bug tracker
        m = re.search(r'(?:crbug\.com/|issues\.chromium\.org/issues/)(\d+)', url)
        if m and not bug_id:
            bug_id = m.group(1)
        # Gerrit
        if 'chromium-review.googlesource.com' in url and not gerrit_url:
            gerrit_url = url
        # Release blog
        if 'chromereleases.googleblog.com' in url and not blog_url:
            blog_url = url
        # Public exploit / PoC references (NVD "Exploit" tag)
        if 'Exploit' in tags:
            exploit_refs.append(url)

    result = {
        'id': cve_id,
        'published': metadata.get('datePublished', ''),
        'cvss': cvss_score,
        'description': desc,
        'versions': versions,
        'bug_id': bug_id,
        'gerrit_url': gerrit_url,
        'blog_url': blog_url,
    }
    if exploit_refs:
        result['has_public_exploit'] = True
        result['exploit_refs'] = exploit_refs[:5]
    return result


def main():
    cves = extract_chromium_cves()

    output_dir = Path('data')
    output_dir.mkdir(exist_ok=True)

    # 按发布时间排序
    cves.sort(key=lambda x: x.get('published', ''), reverse=True)

    output = {
        'generated_at': datetime.utcnow().isoformat() + 'Z',
        'total_cves': len(cves),
        'cves': cves,
    }

    output_file = output_dir / 'chromium-cves.json'
    output_file.write_text(json.dumps(output, indent=2, ensure_ascii=False))

    print(f"\nSaved {len(cves)} CVEs to {output_file}")
    return output


if __name__ == '__main__':
    main()
