#!/usr/bin/env python3
"""Chrome Releases Blog 采集器（HTML 解析版）"""

import json
import re
from datetime import datetime
from pathlib import Path

import requests
from bs4 import BeautifulSoup


MAX_POSTS = 500  # 最多抓取文章数


def collect_releases():
    """从 Chrome Releases Blog HTML 页面采集漏洞公告"""

    releases = []
    next_url = "https://chromereleases.googleblog.com/search?max-results=25"

    for _ in range(MAX_POSTS // 25 + 1):
        print(f"Fetching: {next_url}")
        try:
            resp = requests.get(next_url, timeout=30, headers={
                'User-Agent': 'Mozilla/5.0 (compatible; ChromiumIntel/1.0)'
            })
            resp.raise_for_status()
        except Exception as e:
            print(f"  Error: {e}")
            break

        soup = BeautifulSoup(resp.text, 'html.parser')
        posts = soup.find_all(class_='post')

        if not posts:
            posts = soup.find_all('article')
        if not posts:
            posts = soup.find_all('div', class_=re.compile(r'post|entry|blog'))

        for post in posts:
            title_el = post.find(['h2', 'h3', 'h1', 'a'], class_=re.compile(r'title|entry-title|post-title'))
            if not title_el:
                continue

            title = title_el.get_text(strip=True)
            if not is_security_update_title(title):
                continue

            link = None
            a = title_el.find('a') or title_el
            if a.name == 'a':
                link = a.get('href')

            content_el = post.find(class_=re.compile(r'content|body|entry-content|post-body|snippet'))
            content = content_el.get_text(strip=True) if content_el else ''

            release = {
                'title': title,
                'published': extract_date(post),
                'url': link or '',
                'content': content,
                'version': extract_version(title),
                'cves': extract_cves(content),
                'in_the_wild': check_in_the_wild(content),
                'severity': extract_severity(content),
                'platforms': extract_platforms(content),
            }
            releases.append(release)
            print(f"  Found: {release['version']} - {len(release['cves'])} CVEs")

        # 查找下一页
        older = soup.find('a', string=re.compile(r'Older|Next|下一页|较早', re.IGNORECASE))
        if older and older.get('href'):
            next_url = older['href']
        else:
            break

    return releases


def is_security_update_title(title):
    """判断是否是安全更新文章"""
    t = title.lower()
    return any(kw in t for kw in [
        'stable channel has been updated',
        'stable channel update',
        'extended stable',
        'dev channel',
        'beta channel',
    ]) and 'updated' in t


def extract_version(title):
    """提取版本号"""
    match = re.search(r'(\d+\.\d+\.\d+\.\d+)', title)
    return match.group(1) if match else None


def extract_date(post):
    """提取发布日期"""
    date_el = post.find(['time', 'span', 'div'], class_=re.compile(r'date|time|published', re.IGNORECASE))
    if date_el:
        dt = date_el.get('datetime') or date_el.get_text(strip=True)
        return dt
    return ''


def extract_cves(content):
    """提取 CVE 列表"""
    cves = re.findall(r'CVE-\d{4}-\d+', content)
    return list(set(cves))


def check_in_the_wild(content):
    """检查是否有在野利用"""
    c = content.lower()
    return 'in the wild' in c or 'exploited' in c


def extract_severity(content):
    """提取严重程度"""
    match = re.search(r'severity:?\s*(\w+)', content, re.IGNORECASE)
    return match.group(1) if match else None


def extract_platforms(content):
    """提取影响平台"""
    c = content.lower()
    platforms = []
    if 'windows' in c: platforms.append('Windows')
    if 'mac' in c or 'linux' in c: platforms.append('Mac/Linux')
    if 'android' in c: platforms.append('Android')
    if 'ios' in c: platforms.append('iOS')
    return platforms if platforms else ['Desktop']


def main():
    releases = collect_releases()

    output_dir = Path('data')
    output_dir.mkdir(exist_ok=True)

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
