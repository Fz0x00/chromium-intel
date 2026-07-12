# chromium-intel 模型缺陷：Chromium 版本 ≠ V8 可利用性

## 背景

通过 CVE-2025-5419 的实战研究，我们发现了一个**模型层面的根本性缺陷**：

当前 `chromium-intel` 通过 Chromium 版本号比较来判断应用是否受某个 CVE 影响：

```python
# match_assets.py 核心逻辑
if cmp_ver(app_chromium_version, cve_fixed_version) < 0:
    # 应用版本 < 修复版本 → 标记为"受影响"
```

这个判断在**安全公告层面**是正确的，但在 **exploit 可利用性层面**可能产生误判。

## 实证

| 环境 | Chromium 版本 | V8 版本 | CVE 说受影响? | 实际可 exploit? |
|------|:----------:|:------:|:----------:|:------------:|
| 讯飞听见 | 134 | 13.4.114 | ✓ (< 137) | **✗** SSE 不触发 |
| d8 自编译 | 139+ | 13.9.0 | ✗ (> 137) | **✓** SSE 触发 |

同一条 CVE-2025-5419，满足版本条件的不行，不满足版本条件的反而行。

## 已实施的改进

### 1. exploit 情报数据库 (`data/exploit-intel.json`)

新增结构化的 exploit 验证数据库，每条记录包含：
- `v8_exploit_range`: 精确的 V8 版本范围 (`min_v8_version`, `max_v8_version`, `known_good`, `known_bad`)
- `exploit_status`: 验证状态 (`VERIFIED_PARTIAL` / `LIKELY` / `RANGE`)
- `exploit_chain`: 各 Stage 的需求条件
- `tested_apps`: 已测试应用及结果
- `key_findings`: 关键发现

当前录入：CVE-2025-5419（1 条，可扩展）

### 2. build_risk_report.py 集成

- 加载 `exploit-intel.json` 并合并到 risk-report
- 为匹配的 CVE 添加 `exploit_intel` 字段
- 统计 `has_exploit_intel` 和 `exploit_verified` 数量

### 3. match_assets.py 三级 confidence

```python
# 新的 confidence 分级
VERIFIED = exploit 在与此 app 相同（或兼容）的 V8 版本上实际验证通过
LIKELY   = 组件匹配 + 有公开 PoC/补丁，但未在该 V8 版本验证
RANGE    = 仅 CVE 版本号在范围内，无额外 exploit 证据
```

- 通过 `tested_apps` 列表检查该 app 的 Chromium 版本是否已被测试
- `app_exploit_verified` 字段明确标识 exploit 是否在该 app 版本上验证
- `v8_note` 字段提供上下文解释

### 改进前后对比

```
改进前:
  讯飞听见 + CVE-2025-5419 → CRITICAL（受 CVE 影响）

改进后:
  讯飞听见 + CVE-2025-5419 → CRITICAL / LIKELY / app_exploit_verified=false
  v8_note: "Exploit verified elsewhere but SSE behavior differs on this V8 version"
```

## 待实施

### V8 commit 追踪层

- 建立 Chromium release → V8 commit hash 映射
- 对每个 V8 CVE，bisect 找到精确的引入 commit
- 标记哪些 Chromium release 分支包含/不包含该 bug

### 自动验证框架

- 在 Electron 应用沙箱中运行最小化 PoC
- 上报实际可利用性状态
- 与 exploit intel 数据库联动

## 影响

改进后的系统给出三层信息：
1. 应用在 CVE 版本范围内？ → 告警级别 (CRITICAL/HIGH/PATCH/OTHER)
2. V8 代码状态是否支持已知 exploit 策略？ → exploit confidence (VERIFIED/LIKELY/RANGE)
3. 是否已在该 app 版本上验证？ → app_exploit_verified (true/false)
