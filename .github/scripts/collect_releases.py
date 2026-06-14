#!/usr/bin/env python3
"""Chrome Releases Blog 采集器"""

import json
import re
from datetime import datetime
from pathlib import Path

import feedparser
import requests


def collect_releases():
    """从 Chrome Releases Blog 采集漏洞公告"""
    
    print("Fetching Chrome Releases Blog RSS...")
    feed = feedparser.parse("https://chromereleases.googleblog.com/feeds/posts/default")
    
    releases = []
    for entry in feed.entries:
        if not is_security_update(entry):
            continue
        
        release = {
            'title': entry.title,
            'published': entry.get('published', ''),
            'url': entry.link,
            'content': entry.get('summary', ''),
            'version': extract_version(entry),
            'cves': extract_cves(entry),
            'in_the_wild': check_in_the_wild(entry),
            'severity': extract_severity(entry),
            'platforms': extract_platforms(entry),
        }
        releases.append(release)
        print(f"  Found: {release['version']} - {len(release['cves'])} CVEs")
    
    return releases


def is_security_update(entry):
    """判断是否是安全更新文章"""
    title = entry.get('title', '').lower()
    return 'stable channel has been updated' in title


def extract_version(entry):
    """提取版本号"""
    title = entry.get('title', '')
    match = re.search(r'(\d+\.\d+\.\d+\.\d+)', title)
    return match.group(1) if match else None


def extract_cves(entry):
    """提取 CVE 列表"""
    content = entry.get('summary', '')
    cves = re.findall(r'CVE-\d{4}-\d+', content)
    return list(set(cves))


def check_in_the_wild(entry):
    """检查是否有在野利用"""
    content = entry.get('summary', '').lower()
    return 'in the wild' in content or 'exploited' in content


def extract_severity(entry):
    """提取严重程度"""
    content = entry.get('summary', '')
    match = re.search(r'security severity: (\w+)', content, re.IGNORECASE)
    return match.group(1) if match else None


def extract_platforms(entry):
    """提取影响平台"""
    content = entry.get('summary', '').lower()
    platforms = []
    
    if 'windows' in content:
        platforms.append('Windows')
    if 'mac' in content or 'linux' in content:
        platforms.append('Mac/Linux')
    if 'android' in content:
        platforms.append('Android')
    if 'ios' in content:
        platforms.append('iOS')
    
    return platforms if platforms else ['Desktop']


def main():
    """主函数"""
    releases = collect_releases()
    
    # 创建输出目录
    output_dir = Path('data')
    output_dir.mkdir(exist_ok=True)
    
    # 保存结果
    output = {
        'generated_at': datetime.utcnow().isoformat() + 'Z',
        'latest_version': releases[0]['version'] if releases else None,
        'latest_release_date': releases[0]['published'] if releases else None,
        'total_releases': len(releases),
        'releases': releases,
    }
    
    output_file = output_dir / 'releases.json'
    output_file.write_text(json.dumps(output, indent=2, ensure_ascii=False))
    
    print(f"\nSaved {len(releases)} releases to {output_file}")
    return output


if __name__ == '__main__':
    main()
