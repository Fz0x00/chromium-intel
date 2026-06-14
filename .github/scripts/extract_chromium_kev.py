#!/usr/bin/env python3
"""从 CISA KEV 提取 Chromium 相关漏洞"""

import json
from datetime import datetime
from pathlib import Path


# Chromium 相关关键词
CHROMIUM_KEYWORDS = [
    'google chrome', 'chromium', 'microsoft edge',
    'electron', 'cef', 'blink', 'v8', 'skia',
    'webrtc', 'pdfium', 'angle', 'weblayer',
    'chrome os', 'android webview',
]


def extract_chromium_kev():
    """从 kev-data 提取 Chromium 相关 KEV"""
    
    kev_file = Path('data/kev-data/known_exploited_vulnerabilities.json')
    
    if not kev_file.exists():
        print(f"Error: {kev_file} not found. Please run: git clone --depth=1 https://github.com/cisagov/kev-data.git data/kev-data")
        return []
    
    print(f"Loading KEV from {kev_file}...")
    kev_data = json.loads(kev_file.read_text())
    
    chromium_kev = []
    for vuln in kev_data.get('vulnerabilities', []):
        if is_chromium_related(vuln):
            chromium_kev.append({
                'cve_id': vuln.get('cveID', ''),
                'vendor': vuln.get('vendorProject', ''),
                'product': vuln.get('product', ''),
                'vulnerability_name': vuln.get('vulnerabilityName', ''),
                'date_added': vuln.get('dateAdded', ''),
                'short_description': vuln.get('shortDescription', ''),
                'required_action': vuln.get('requiredAction', ''),
                'due_date': vuln.get('dueDate', ''),
                'known_ransomware_use': vuln.get('knownRansomwareCampaignUse', ''),
                'notes': vuln.get('notes', ''),
            })
    
    print(f"Found {len(chromium_kev)} Chromium KEVs")
    return chromium_kev


def is_chromium_related(vuln):
    """判断是否 Chromium 相关"""
    
    product = (vuln.get('product') or '').lower()
    vendor = (vuln.get('vendorProject') or '').lower()
    name = (vuln.get('vulnerabilityName') or '').lower()
    description = (vuln.get('shortDescription') or '').lower()
    
    # 检查产品、供应商、漏洞名称、描述
    text = f"{product} {vendor} {name} {description}"
    
    return any(kw in text for kw in CHROMIUM_KEYWORDS)


def main():
    """主函数"""
    kev = extract_chromium_kev()
    
    # 创建输出目录
    output_dir = Path('data')
    output_dir.mkdir(exist_ok=True)
    
    # 保存结果
    output = {
        'generated_at': datetime.utcnow().isoformat() + 'Z',
        'total_kev': len(kev),
        'kev': kev,
    }
    
    output_file = output_dir / 'kev.json'
    output_file.write_text(json.dumps(output, indent=2, ensure_ascii=False))
    
    print(f"\nSaved {len(kev)} KEVs to {output_file}")
    return output


if __name__ == '__main__':
    main()
