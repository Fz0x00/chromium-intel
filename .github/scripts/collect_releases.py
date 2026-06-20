#!/usr/bin/env python3
"""Chrome Releases Blog 采集器（Blogger Atom Feed API）"""

import json
import re
import time
from datetime import datetime
from html import unescape
from pathlib import Path

import requests

MAX_POSTS = 500
FEED_URL = "https://chromereleases.googleblog.com/feeds/posts/default"
PAGE_SIZE = 25


def collect_releases():
    """从 Blogger Atom Feed API 采集漏洞公告"""

    releases = []
    start_index = 1

    while len(releases) < MAX_POSTS:
        url = f"{FEED_URL}?alt=json&max-results={PAGE_SIZE}&start-index={start_index}"
        print(f"Fetching feed: start-index={start_index}")

        try:
            resp = requests.get(url, timeout=30, headers={
                'User-Agent': 'Mozilla/5.0 (compatible; ChromiumIntel/1.0)'
            })
            resp.raise_for_status()
            data = resp.json()
        except Exception as e:
            print(f"  Error: {e}")
            break

        entries = data.get('feed', {}).get('entry', [])
        if not entries:
            print("  No more entries")
            break

        print(f"  Got {len(entries)} entries")

        for entry in entries:
            # Get title - handle both {"$t": "..."} and direct string
            title_raw = entry.get('title', '')
            title = title_raw.get('$t', '') if isinstance(title_raw, dict) else str(title_raw)

            # Get published - handle both {"$t": "..."} and direct string
            published_raw = entry.get('published', '')
            published = published_raw.get('$t', '') if isinstance(published_raw, dict) else str(published_raw)

            # Get content - handle both {"$t": "..."} and direct string
            content_raw = entry.get('content', '')
            if isinstance(content_raw, dict):
                content = content_raw.get('$t', '')
            elif isinstance(content_raw, list):
                content = content_raw[0].get('$t', '') if content_raw else ''
            else:
                content = str(content_raw)

            # Get link
            link = ''
            for l in entry.get('link', []):
                if isinstance(l, dict) and l.get('rel') == 'alternate':
                    link = l.get('href', '')
                    break

            # Skip ChromeOS-only posts
            t_lower = title.lower()
            if 'chromeos' in t_lower and 'desktop' not in t_lower:
                continue

            # Only keep stable / extended stable updates
            if not any(kw in t_lower for kw in [
                'stable channel update',
                'stable channel has been updated',
                'extended stable',
            ]):
                continue

            # Extract version
            version = extract_version(title + ' ' + content)
            if not version:
                continue

            release = {
                'title': title,
                'published': published,
                'url': link,
                'content': strip_html(content)[:5000],
                'version': version,
                'cves': extract_cves(content),
                'in_the_wild': check_in_the_wild(content),
                'severity': extract_severity(content),
                'platforms': extract_platforms(content),
            }
            releases.append(release)
            print(f"  {version} - {len(release['cves'])} CVEs - {published[:10]}")

        start_index += PAGE_SIZE
        time.sleep(1)  # polite delay

    return releases


def strip_html(html_str):
    """去除 HTML 标签"""
    text = re.sub(r'<[^>]+>', ' ', html_str)
    return unescape(text).strip()


def extract_version(text):
    """提取版本号"""
    match = re.search(r'(\d+\.\d+\.\d+\.\d+)', text)
    return match.group(1) if match else None


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
