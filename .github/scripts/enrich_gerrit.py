#!/usr/bin/env python3
"""从 Chromium Gerrit API 提取补丁链接（通过 bug ID 搜索）"""
import json
import re
import time
from datetime import datetime
from pathlib import Path

import requests

GERRIT_SEARCH = "https://chromium-review.googlesource.com/changes/?q=bug:{bug_id}&n=3&o=CURRENT_REVISION"


def fetch_gerrit_urls(bug_ids):
    """批量查询 Gerrit API，获取补丁链接"""
    cache = load_cache()
    new_entries = 0

    for bug_id in bug_ids:
        if bug_id in cache:
            continue

        try:
            resp = requests.get(
                GERRIT_SEARCH.format(bug_id=bug_id),
                timeout=15,
                headers={"User-Agent": "ChromiumIntel/1.0"}
            )
            resp.raise_for_status()
        except Exception:
            time.sleep(0.3)
            continue

        # Gerrit 返回 JSON 但有 XSSI 前缀 )]}'
        text = resp.text
        if text.startswith(")]}'"):
            text = text[5:].strip()

        try:
            changes = json.loads(text) if isinstance(text, str) else text
        except json.JSONDecodeError:
            cache[bug_id] = None  # 标记已查但无结果
            continue

        if not changes:
            cache[bug_id] = None
            continue

        # 取第一个 chromium/src 的 CL
        for change in changes:
            project = change.get("project", "")
            if "chromium/src" not in project and "chromium" not in project:
                continue

            cl_number = change.get("_number")
            revision = change.get("revisions", {}).get("current_revision", "")
            commit_msg = ""
            if revision:
                commit = change["revisions"].get(revision, {}).get("commit", {})
                commit_msg = commit.get("message", "")

            # 提取 Gerrit URL 和可能的 commit SHA
            subject = change.get("subject", "")
            gerrit_url = f"https://chromium-review.googlesource.com/c/chromium/src/+/{cl_number}"

            cache[bug_id] = {
                "gerrit_url": gerrit_url,
                "cl_number": cl_number,
                "subject": subject,
                "commit_message": commit_msg[:500],
            }
            new_entries += 1
            break
        else:
            cache[bug_id] = None

        time.sleep(0.5)  # 避免触发限流

    return cache, new_entries


def load_cache():
    """加载 Gerrit 缓存"""
    path = Path("data/gerrit-cache.json")
    if path.exists():
        return json.loads(path.read_text())
    return {}


def save_cache(cache):
    """保存 Gerrit 缓存"""
    path = Path("data/gerrit-cache.json")
    path.parent.mkdir(exist_ok=True)
    path.write_text(json.dumps(cache, indent=2, ensure_ascii=False))


def get_bug_ids_from_cves():
    """从 risk-report.json 提取 bug_id 列表，按风险评分排序"""
    # 优先读 risk-report，有风险评分可以排优先级
    for path in ('data/risk-report.json', 'data/chromium-cves.json'):
        p = Path(path)
        if p.exists():
            data = json.loads(p.read_text())
            # 按 risk_score 降序排列
            cves = data.get('cves', [])
            cves.sort(key=lambda x: x.get('risk_score', 0), reverse=True)
            bug_ids = []
            for cve in cves:
                bug_id = cve.get('bug_id')
                if bug_id and bug_id not in bug_ids:
                    bug_ids.append(bug_id)
            if bug_ids:
                print(f"  Read from {path} with risk scores")
                return bug_ids
    return []


def enrich_risk_report():
    """将 Gerrit 缓存合并到 risk-report.json"""
    cache = load_cache()
    if not cache:
        return

    path = Path("data/risk-report.json")
    if not path.exists():
        return

    report = json.loads(path.read_text())
    enriched = 0

    for cve in report.get("cves", []):
        bug_id = cve.get("bug_id")
        if not bug_id or cve.get("gerrit_url"):
            continue

        entry = cache.get(bug_id)
        if entry and entry.get("gerrit_url"):
            cve["gerrit_url"] = entry["gerrit_url"]
            cve["gerrit_cl"] = entry.get("cl_number")
            cve["gerrit_subject"] = entry.get("subject")
            enriched += 1

    path.write_text(json.dumps(report, indent=2, ensure_ascii=False))
    print(f"Enriched {enriched} CVEs with Gerrit links")


def main():
    import sys
    argv = sys.argv[1:]

    # 解析参数
    dry_run = "--dry-run" in argv
    do_enrich = "--enrich" in argv
    max_fetch = 200
    for a in argv:
        if a.isdigit():
            max_fetch = int(a)
            break

    bug_ids = get_bug_ids_from_cves()
    print(f"Found {len(bug_ids)} bug IDs from CVEs")

    # 已经有缓存的跳过，只查新的
    cache = load_cache()
    to_fetch = [b for b in bug_ids if b not in cache]
    print(f"  Already cached: {len(bug_ids) - len(to_fetch)}")
    print(f"  Need to fetch: {len(to_fetch)}")

    if to_fetch and not dry_run:
        # 已按风险评分排序，取前 max_fetch 个

        # 限制每轮查询数量，避免工作流超时
        if len(to_fetch) > max_fetch:
            print(f"  Limiting to {max_fetch} (batch mode)")
            to_fetch = to_fetch[:max_fetch]

        cache, new_entries = fetch_gerrit_urls(to_fetch)
        save_cache(cache)
        print(f"  New entries: {new_entries}")
    else:
        print("  Skipping fetch")

    if do_enrich:
        enrich_risk_report()


if __name__ == "__main__":
    main()
