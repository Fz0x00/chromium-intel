# Chromium Intel

自动化收集和分析 Chromium 生态系统漏洞情报。

## 数据源

| 数据源 | 访问方式 | 频率 | 说明 |
|--------|----------|------|------|
| Chrome Releases Blog | RSS | 每日 | 官方安全公告 |
| CVEProject/cvelistV5 | git pull | 每30分钟 | CVE 详情 |
| CISA KEV | git pull | 每日 | 已知在野利用漏洞 |
| Version History API | REST API | 每日 | 版本发布时间线 |
| Gerrit API | REST API | 按需 | 修复代码链接 |

## 项目结构

```
chromium-intel/
├── .github/
│   ├── scripts/
│   │   ├── collect_releases.py      # Chrome Releases Blog 采集器
│   │   ├── extract_chromium_cves.py  # cvelistV5 提取器
│   │   ├── extract_chromium_kev.py   # CISA KEV 提取器
│   │   ├── fetch_version_history.py  # Version History API 采集器
│   │   └── build_risk_report.py      # 风险报告构建器
│   └── workflows/
│       ├── collect-releases.yml      # 每日采集 Chrome Releases
│       ├── sync-cve.yml              # 每30分钟同步 CVE
│       ├── sync-kev.yml              # 每日同步 CISA KEV
│       ├── fetch-version-history.yml # 每日获取版本历史
│       ├── build-risk-report.yml     # 构建风险报告
│       └── deploy-pages.yml          # 部署到 GitHub Pages
├── data/                             # 数据目录 (自动生成)
├── docs/                             # GitHub Pages 输出
├── requirements.txt                  # Python 依赖
└── README.md
```

## 风险评分算法

```
风险评分 (0-100) = 
  KEV 在野利用 (40%) + 
  在野利用状态 (30%) + 
  严重程度 (20%) + 
  CVSS 分数 (10%)
```

## 本地运行

```bash
# 安装依赖
pip install -r requirements.txt

# 运行各采集器
python .github/scripts/collect_releases.py
python .github/scripts/extract_chromium_cves.py
python .github/scripts/extract_chromium_kev.py
python .github/scripts/fetch_version_history.py

# 构建风险报告
python .github/scripts/build_risk_report.py
```

## GitHub Pages

启用 GitHub Pages 后，访问: `https://<username>.github.io/chromium-intel/`

## License

MIT
