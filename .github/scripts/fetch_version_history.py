#!/usr/bin/env python3
"""从 Google Version History API 获取 Chrome 版本发布时间线"""

import json
from datetime import datetime
from pathlib import Path

import requests


# Chrome 频道列表
CHANNELS = ['extended', 'stable', 'beta', 'dev', 'canary']


def fetch_version_history():
    """获取 Chrome 版本发布时间线"""
    
    version_history = {}
    
    for channel in CHANNELS:
        print(f"Fetching version history for {channel}...")
        url = f"https://versionhistory.googleapis.com/v1/chrome/platforms/all/channels/{channel}/versions/all/releases"
        
        try:
            response = requests.get(url, timeout=30)
            response.raise_for_status()
            version_history[channel] = response.json()
            print(f"  Found {len(version_history[channel].get('releases', []))} releases")
        except Exception as e:
            print(f"  Error fetching {channel}: {e}")
            version_history[channel] = {'releases': []}
    
    return version_history


def get_release_dates(version_history, version):
    """获取特定版本的发布时间"""
    
    dates = {}
    for channel, data in version_history.items():
        for release in data.get('releases', []):
            if release.get('version') == version:
                dates[channel] = release.get('serving', {}).get('startTime', '')
                break
    
    return dates


def main():
    """主函数"""
    version_history = fetch_version_history()
    
    # 创建输出目录
    output_dir = Path('data')
    output_dir.mkdir(exist_ok=True)
    
    # 统计信息
    total_releases = sum(len(data.get('releases', [])) for data in version_history.values())
    
    # 保存结果
    output = {
        'generated_at': datetime.utcnow().isoformat() + 'Z',
        'channels': CHANNELS,
        'total_releases': total_releases,
        'version_history': version_history,
    }
    
    output_file = output_dir / 'version-history.json'
    output_file.write_text(json.dumps(output, indent=2, ensure_ascii=False))
    
    print(f"\nSaved version history ({total_releases} releases) to {output_file}")
    return output


if __name__ == '__main__':
    main()
