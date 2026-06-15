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

    for page in range(MAX_POSTS // 25 + 1):
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

        # Strategy: find all links, filter those that look like security update posts
        all_links = soup.find_all('a', href=True)
        update_links = []
        for a in all_links:
            text = a.get_text(strip=True).lower()
            if 'chromeos' in text:
                continue  # Skip ChromeOS updates
            if any(kw in text for kw in [
                'stable channel update',
                'extended stable channel update',
                'dev channel update',
                'beta channel update',
            ]):
                update_links.append(a)
                print(f"  Link text: {a.get_text(strip=True)[:100]}")

        print(f"  Found {len(update_links)} update links")

        for a in update_links:
            title = a.get_text(strip=True)
            # Skip ChromeOS-only posts
            if 'chromeos' in title.lower() and 'desktop' not in title.lower():
                continue

            link = a['href']
            if link.startswith('/'):
                link = 'https://chromereleases.googleblog.com' + link

            # Fetch the individual post for content and version
            content = ''
            try:
                post_resp = requests.get(link, timeout=30, headers={
                    'User-Agent': 'Mozilla/5.0 (compatible; ChromiumIntel/1.0)'
                })
                post_soup = BeautifulSoup(post_resp.text, 'html.parser')
                body = post_soup.find(class_=re.compile(r'post-body|entry-content|content'))
                if body:
                    content = body.get_text(strip=True)
                else:
                    content = post_soup.body.get_text(strip=True) if post_soup.body else ''

                # Extract version from post content
                version = extract_version(title + ' ' + content)
                if not version:
                    continue
            except:
                continue

            release = {
                'title': title,
                'published': '',
                'url': link,
                'content': content[:5000],
                'version': version,
                'cves': extract_cves(content),
                'in_the_wild': check_in_the_wild(content),
                'severity': extract_severity(content),
                'platforms': extract_platforms(content),
            }
            releases.append(release)
            print(f"  Found: {version} - {len(release['cves'])} CVEs")

        # Look for "Older Posts" / "Newer Posts" / pagination
        older = None
        for a in all_links:
            if a.get_text(strip=True).lower() in ('older posts', 'next', '»', 'more posts'):
                older = a
                break
        if older and older.get('href'):
            next_url = older['href']
            if next_url.startswith('/'):
                next_url = 'https://chromereleases.googleblog.com' + next_url
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
