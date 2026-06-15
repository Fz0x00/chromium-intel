#!/usr/bin/env python3
"""构建风险报告 - 合并所有数据源"""

import json
from datetime import datetime
from pathlib import Path


def load_json(filepath):
    """加载 JSON 文件"""
    path = Path(filepath)
    if not path.exists():
        print(f"Warning: {filepath} not found")
        return {}
    return json.loads(path.read_text())


def build_risk_report():
    """构建风险报告"""
    
    print("Loading data sources...")
    
    # 1. 加载各数据源
    releases = load_json('data/releases.json')
    chromium_cves = load_json('data/chromium-cves.json')
    kev = load_json('data/kev.json')
    version_history = load_json('data/version-history.json')
    
    cves = chromium_cves.get('cves', [])
    kev_list = kev.get('kev', [])
    releases_list = releases.get('releases', [])
    
    print(f"  Releases: {len(releases_list)}")
    print(f"  CVEs: {len(cves)}")
    print(f"  KEVs: {len(kev_list)}")
    
    # 2. 构建 KEV 索引
    kev_index = {k['cve_id']: k for k in kev_list}
    
    # 3. 构建 releases 索引 (按 CVE)
    releases_by_cve = {}
    for release in releases_list:
        for cve_id in release.get('cves', []):
            if cve_id not in releases_by_cve:
                releases_by_cve[cve_id] = []
            releases_by_cve[cve_id].append(release)
    
    # 4. 关联数据
    print("\nCorrelating data...")
    for cve in cves:
        cve_id = cve['id']
        
        # 关联 KEV
        kev_entry = kev_index.get(cve_id)
        if kev_entry:
            cve['in_kev'] = True
            cve['kev_date'] = kev_entry.get('date_added', '')
            cve['kev_context'] = kev_entry.get('short_description', '')
            cve['kev_action'] = kev_entry.get('required_action', '')
        else:
            cve['in_kev'] = False
        
        # 关联 Chrome Releases Blog
        release_info = releases_by_cve.get(cve_id, [])
        if release_info:
            cve['in_the_wild'] = release_info[0].get('in_the_wild', False)
            cve['severity'] = release_info[0].get('severity', '')
            # Use release blog URL if CVE doesn't have one
            if not cve.get('blog_url'):
                cve['blog_url'] = release_info[0].get('url', '')
        else:
            cve['in_the_wild'] = False
            cve['severity'] = ''
        
        # 构造追踪链接
        bug_id = cve.get('bug_id')
        if bug_id:
            cve['bug_url'] = f'https://issues.chromium.org/issues/{bug_id}'
            cve['crbug_url'] = f'https://crbug.com/{bug_id}'
        else:
            cve['bug_url'] = None
            cve['crbug_url'] = None
        
        # Gerrit 补丁链接直接来自 CVE 数据
        
        # 计算风险评分
        cve['risk_score'] = calculate_risk_score(cve)
    
    # 5. 按风险评分排序
    cves.sort(key=lambda x: x.get('risk_score', 0), reverse=True)
    
    # 6. 生成摘要
    summary = generate_summary(cves)
    
    # 7. 保存报告
    output_dir = Path('data')
    output_dir.mkdir(exist_ok=True)
    
    report = {
        'generated_at': datetime.utcnow().isoformat() + 'Z',
        'summary': summary,
        'cves': cves,
    }
    
    output_file = output_dir / 'risk-report.json'
    output_file.write_text(json.dumps(report, indent=2, ensure_ascii=False))
    
    print(f"\nSaved risk report to {output_file}")
    print(f"\nSummary:")
    print(f"  Total CVEs: {summary['total_cves']}")
    print(f"  In KEV: {summary['in_kev']}")
    print(f"  In the Wild: {summary['in_the_wild']}")
    print(f"  Critical: {summary['critical']}")
    print(f"  High: {summary['high']}")
    print(f"  Medium: {summary['medium']}")
    print(f"  Low: {summary['low']}")
    
    return report


def calculate_risk_score(cve):
    """计算风险评分 (0-100)"""
    
    score = 0
    
    # 1. KEV 在野利用 (40%)
    if cve.get('in_kev'):
        score += 40
    
    # 2. 在野利用状态 (30%)
    if cve.get('in_the_wild'):
        score += 30
    
    # 3. 严重程度 (20%)
    severity = cve.get('severity', '') or ''
    cvss = cve.get('cvss', 0)
    
    if severity == 'critical' or cvss >= 9.0:
        score += 20
    elif severity == 'high' or cvss >= 7.0:
        score += 15
    elif severity == 'medium' or cvss >= 4.0:
        score += 10
    elif severity == 'low' or cvss > 0:
        score += 5
    
    # 4. CVSS 分数补充 (10%)
    if cvss > 0:
        score += min(int(cvss), 10)
    
    return min(score, 100)


def generate_summary(cves):
    """生成摘要"""
    
    summary = {
        'total_cves': len(cves),
        'in_kev': sum(1 for c in cves if c.get('in_kev')),
        'in_the_wild': sum(1 for c in cves if c.get('in_the_wild')),
        'critical': 0,
        'high': 0,
        'medium': 0,
        'low': 0,
        'avg_risk_score': 0,
    }
    
    total_score = 0
    for cve in cves:
        score = cve.get('risk_score', 0)
        total_score += score
        
        if score >= 70:
            summary['critical'] += 1
        elif score >= 50:
            summary['high'] += 1
        elif score >= 30:
            summary['medium'] += 1
        else:
            summary['low'] += 1
    
    if len(cves) > 0:
        summary['avg_risk_score'] = round(total_score / len(cves), 1)
    
    return summary


def main():
    """主函数"""
    return build_risk_report()


if __name__ == '__main__':
    main()
