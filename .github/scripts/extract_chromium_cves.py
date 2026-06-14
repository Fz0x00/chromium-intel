#!/usr/bin/env python3
"""从 cvelistV5 提取 Chromium 相关 CVE"""

import json
from datetime import datetime
from pathlib import Path


# Chromium 相关关键词
CHROMIUM_KEYWORDS = [
    'google chrome', 'chromium', 'microsoft edge',
    'electron', 'cef', 'blink', 'v8 engine', 'skia',
    'webrtc', 'pdfium', 'angle', 'weblayer',
    'chrome os', 'android webview',
]


def extract_chromium_cves():
    """从 cvelistV5 提取 Chromium 相关 CVE"""
    
    cve_dir = Path('data/cvelistV5/cves')
    
    if not cve_dir.exists():
        print(f"Error: {cve_dir} not found. Please run: git clone --depth=1 https://github.com/CVEProject/cvelistV5.git data/cvelistV5")
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
                        chromium_cves.append(parse_cve(cve_data))
                except Exception as e:
                    print(f"  Error processing {cve_file}: {e}")
    
    print(f"Found {len(chromium_cves)} Chromium CVEs")
    return chromium_cves


def is_chromium_cve(cve_data):
    """判断是否是 Chromium CVE"""
    
    # 方法1: 通过 assignerShortName
    metadata = cve_data.get('cveMetadata', {})
    if metadata.get('assignerShortName') == 'Chrome':
        return True
    
    # 方法2: 通过 affected 产品
    cna = cve_data.get('containers', {}).get('cna', {})
    for affected in cna.get('affected', []):
        product = (affected.get('product') or '').lower()
        vendor = (affected.get('vendor') or '').lower()
        
        # 检查产品和供应商
        if ('chrome' in product or 'chromium' in product) and 'google' in vendor:
            return True
        
        # 旧版 CVE (2018年前) 使用 n/a 标记
        if product == 'n/a' and vendor == 'n/a':
            return True
    
    # 方法3: 通过描述中的关键词
    for desc in cna.get('descriptions', []):
        desc_value = (desc.get('value') or '').lower()
        if any(kw in desc_value for kw in CHROMIUM_KEYWORDS):
            return True
    
    return False


def parse_cve(cve_data):
    """解析 CVE 数据"""
    
    metadata = cve_data.get('cveMetadata', {})
    cna = cve_data.get('containers', {}).get('cna', {})
    
    # 提取受影响版本
    affected_versions = []
    for affected in cna.get('affected', []):
        product = (affected.get('product') or '').lower()
        if 'chrome' in product or 'chromium' in product:
            for version in affected.get('versions', []):
                affected_versions.append({
                    'version': version.get('version', ''),
                    'less_than': version.get('lessThan', ''),
                    'less_than_or_equal': version.get('versionEndIncluding', ''),
                })
    
    # 提取参考链接
    references = []
    for ref in cna.get('references', []):
        references.append({
            'url': ref.get('url', ''),
            'name': ref.get('name', ''),
            'tags': ref.get('tags', []),
        })
    
    # 提取 CVSS 分数
    cvss_score = 0
    for metric in cna.get('metrics', []):
        if 'cvssV3_1' in metric:
            cvss_score = metric['cvssV3_1'].get('baseScore', 0)
            break
        elif 'cvssV3_0' in metric:
            cvss_score = metric['cvssV3_0'].get('baseScore', 0)
            break
    
    # 提取 CWE
    cwe_ids = []
    for problem in cna.get('problemTypes', []):
        for desc in problem.get('descriptions', []):
            if desc.get('cweId'):
                cwe_ids.append(desc['cweId'])
    
    return {
        'cve_id': metadata.get('cveId', ''),
        'published': metadata.get('datePublished', ''),
        'description': cna.get('descriptions', [{}])[0].get('value', ''),
        'affected_versions': affected_versions,
        'references': references,
        'cvss_score': cvss_score,
        'cwe_ids': cwe_ids,
    }


def main():
    """主函数"""
    cves = extract_chromium_cves()
    
    # 创建输出目录
    output_dir = Path('data')
    output_dir.mkdir(exist_ok=True)
    
    # 保存结果
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
