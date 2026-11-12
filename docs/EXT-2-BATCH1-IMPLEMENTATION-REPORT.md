# EXT-2 批次 1 Remediation 实施报告

> 交付日期：2026-11-11
> 实施依据：`docs/EXT-2-BATCH1-REMEDIATION-PLAN.md`（360 行 / 20,056 B，SHA256 `b32f5f5d626f6aa620b10fd33d2ada31e8faf879e7e0ff5c7cbfa3009d8b252b`）
> 裁定依据：用户 2026-11-11 的 D1–D6 裁定及批次 1 正式实施授权
> 项目根：`C:/Users/ZTL/Desktop/DualVerify-Sentinel/`（HEAD `9913c50`）
> 自引用说明 `[I]`：本报告自身的行数 / 字节数 / SHA256 在**最终答复**中给出，不写入正文。

---

## 1. 授权与裁定

本轮仅在用户明确授权的三个文件内实施，逐项落实 D1–D6：

| 编号 | 裁定内容 | 落实位置 |
|---|---|---|
| **D1** | 批准 `INFO → info`，保持现有语义，不提升风险等级 | `semgrep.py:104`；测试 `N-INFO` / `N-info` |
| **D2** | 批准 `EXPERIMENT / INVENTORY → info`，但必须保留原始类别标识及明确审计说明，不得伪装成普通漏洞，也不得静默丢弃 | `semgrep.py:109-110`、`:480-484`；测试 `N-EXP-audit` / `N-INV-audit` / `S-03` |
| **D3** | 批准 `records_skipped > 0` 时 `completeness` 降级为 `PARTIAL` | `semgrep.py:495-500`；测试 `M-06` / `S-01` / `G-09` |
| **D4** | 批准纳入 W1-05（`name` 映射短语动态化） | `semgrep.py:437-438`、`:471-475` |
| **D5** | 批准暂不处理 W1-06，等待真实 Semgrep 基线 | 未实施（登记） |
| **D6** | 批准新增 `skip_counts` meta 键 | `semgrep.py:223-246`；测试 `M-05` / `S-01` / `S-02` |

**授权文件范围（仅限）**：

1. `vuln_hunter/adapters_ext/semgrep.py`
2. `tests/test_semgrep_adapter.py`
3. `tests/test_semgrep_integration.py`

**未授权 / 明确排除**：冻结五文件、`findings.py`、Planner、其他 Adapter、G15、C14、六项历史验收状态、配置与基准文档、任何证据或副产物。

---

## 2. 执行前基线核对

实施前逐项核对，确认基线与授权范围一致：

| 核验项 | 基线值 | 结论 |
|---|---|---|
| 冻结五文件哈希 | 见 W1 报告 §1.2 | 与 W1 报告逐项一致，未变 |
| `vuln_hunter/adapters_ext/semgrep.py` SHA256 | `434dfcfa90c85ad465c9cd102e966d87d4faf2f149d7c2d1733fe368b696ee9e` | 621 行 |
| `tests/test_semgrep_adapter.py` SHA256 | `403c683af51ec5bf4e00a3a8dfc01a399ca387a301560858c814ae58df6cdf67` | 702 行 |
| `tests/test_semgrep_integration.py` SHA256 | `1c084bd8f9727caed8e65c6f5421b1c89fe6f5d10adc7c9612f4834b0383ab52` | 753 行 |
| W1 报告 SHA256 | `39ca01dc058fe69e8c864b8e0ddb801b191498b14427bdf7d95bd43367da5bf8` | 未变 |
| 批次 1 方案 SHA256 | `b32f5f5d626f6aa620b10fd33d2ada31e8faf879e7e0ff5c7cbfa3009d8b252b` | 未变 |
| HEAD | `9913c50` | 未变 |
| `semgrep` 是否在 PATH | 否 | 未安装 |

**未发现任何需要超出授权范围的必要改动**，故未触发「停止并单独报告」条件。

---

## 3. 逐文件差异

### 3.1 `vuln_hunter/adapters_ext/semgrep.py`（621 → 713 行）

SHA256：`434dfcfa…ee9e` → `5002660a5c3f031fb53c0ea16bc8da1875b6b5edb396db306d4a3dec3df81f3e`

| # | 位置 | 差异 |
|---|---|---|
| 1 | `:77-111` | `_SEVERITY_MAP` 由 3 值扩展为 **9 值**；补充官方映射依据注释（rule-syntax 引文 + schema description 引文 + D1/D2 裁定标注）；`SEMGREP_SEVERITY_MAP`（`:118`）随之更新 |
| 2 | `:223-246` | `_meta()` 新增 `skip_counts` 关键字参数；非空时写入 `meta["skip_counts"]`（D6）。**仅固定类别名与计数，无任何工具值** |
| 3 | `:625-638` | 新增 `_raw_severity(rec)` 辅助函数：仅返回小写原始 token 用于审计标注，不写日志、不写 meta |
| 4 | `:436-451` | 采收循环新增 `skip_counts` 分类计数（`unsupported_severity` / `malformed_record`）与 `mapping_phrase` 动态生成（W1-05） |
| 5 | `:471-486` | `name` 构造：映射短语由实时 `_SEVERITY_MAP` 生成；`EXPERIMENT`/`INVENTORY` 追加「原始类别 … 为官方遗留值（schema 标注 should be removed），系统映射为 info 并保留类别标识」（D2） |
| 6 | `:490-521` | detail 构造：新增 **D3 PARTIAL 降级**、skipped 计数与原因类别可见性、log 输出、`meta` 传入 `skip_counts` |
| 7 | `:675-677` | `_to_finding()` severity 注释更新为「九值映射」表述 |

### 3.2 `tests/test_semgrep_adapter.py`（702 → 794 行）

SHA256：`403c683a…df67` → `a9373eb2965ffc73604914269f27387fb45b9b1ce7bb8a3b3608b9cfb6978dbd`

| # | 位置 | 差异 |
|---|---|---|
| 1 | `:270-275` | `A-12` 断言由 3 值更新为 **九值**全等断言 |
| 2 | `:557-607` | N 段重写：九值逐项映射（含大小写）+ D2 审计断言 `N-EXP-audit` / `N-INV-audit` + 未知值跳过 `N-bad-*`（`WEIRD` / `""` / `None`）+ 非字符串跳过 `N-bad-type-*`（`123` / `["HIGH"]`） |
| 3 | `:548-555` | 新增 `M-05`（`skip_counts` 分类：1 unsupported + 5 malformed）、`M-06`（PARTIAL 降级可见） |
| 4 | `:609-656` | 新增 S 段：`S-01` 可见性、`S-02` 混合跳过、`S-03` 遗留类别采收、`S-04` 无跳过 COMPLETE |

### 3.3 `tests/test_semgrep_integration.py`（753 → 776 行）

SHA256：`1c084bd8…ab52` → `e0a4587b97a29c5b08cf555672832faf96b054b7568108cbe69df08c0460c4a4`

| # | 位置 | 差异 |
|---|---|---|
| 1 | `:719-729` | 新增 `G-09`：Executor 路径下 1 条 unsupported severity → `COMPLETED` 但 `PARTIAL`，detail 含跳过计数（D3/W1-02） |
| 2 | `:730-740` | 新增 `G-10`：冻结 `render_report()` 正文含 `1 record(s) skipped`、`unsupported severity`、`completeness=PARTIAL` |
| 3 | `:741` | `observe("G-09", ...)` 纳入跨场景残留扫描 |

---

## 4. 九值映射表

`_SEVERITY_MAP`（`semgrep.py:101-111`）——官方 `match_severity` 全值域：

| Semgrep 原始值 | 统一 Finding severity | 依据 | 裁定 |
|---|---|---|---|
| `ERROR` | `high` | 官方 legacy 映射 | — |
| `WARNING` | `medium` | 官方 legacy 映射 | — |
| `INFO` | `info` | D1 | **保持现有语义** |
| `CRITICAL` | `critical` | 官方当前推荐 | — |
| `HIGH` | `high` | 官方当前推荐 | — |
| `MEDIUM` | `medium` | 官方当前推荐 | — |
| `LOW` | `low` | 官方当前推荐 | — |
| `EXPERIMENT` | `info` | D2 | **保留原始类别标识**（`name` 标注） |
| `INVENTORY` | `info` | D2 | **保留原始类别标识**（`name` 标注） |
| 未知 / 缺失 / 非字符串 | —（不采收） | fail-closed | 记录跳过并计入 `skip_counts` |

映射输入**大小写不敏感**（`_to_finding()` 先 `.lower()`）。未知值不降级、不静默丢弃：`_to_finding()` 抛 `FindingError`，采收循环 `continue` 并分类计数。

---

## 5. 状态转换

| 扫描情形 | `AdapterResult.status` | `meta["completeness"]` | findings | detail 前缀 |
|---|---|---|---|---|
| `rc != 0` | `FAILED` | — | 不采收 | `[completeness=…]` 语义不适用（既有 fail-closed 路径） |
| 报告结构不可信（缺 `errors`/`paths`/`paths.skipped` 等） | `FAILED` | `INCOMPLETE` | **不采收** | `[completeness=INCOMPLETE]` |
| `errors[]` 非空 | `FAILED` | `INCOMPLETE` | **不采收** | `[completeness=INCOMPLETE]` |
| 未解释的 `paths.skipped` | `FAILED` | `INCOMPLETE` | **不采收** | `[completeness=INCOMPLETE]` |
| 已解释的 `paths.skipped` | `COMPLETED` | `PARTIAL` | 采收 | `[completeness=PARTIAL]` |
| `records_skipped > 0`（D3） | `COMPLETED` | **`PARTIAL`**（由 `COMPLETE` 降级） | 采收 | `[completeness=PARTIAL]` |
| 干净扫描（无跳过） | `COMPLETED` | `COMPLETE` | 采收 | `[completeness=COMPLETE]` |

**关键不变式**：

- `INCOMPLETE` 路径**不采收任何 Finding**（`:420-431` 提前返回）。
- 不引入新的 `AdapterResult.status` 值；`PARTIAL` 仅存在于 `meta["completeness"]` + detail 前缀 + journal `meta`，**冻结 `runner.py` 的 `STATUS_PRIORITY` 未改**。
- 既有 `PARTIAL`（已解释 `paths.skipped`）保持不变；D3 降级只作用于原 `COMPLETE`。

---

## 6. 报告可见性验证

**通道**：冻结 `report.py:43-48` 渲染 `r.get('reason') or r.get('detail','')`；`AdapterResult.detail` 是 adapter 进入报告步骤表的**唯一通道**。本轮**未修改 `report.py`**。

**detail 构造**（`semgrep.py:502-508`）：

```python
detail = f"[completeness={level}] semgrep exit {rc}, {len(findings)} finding(s)"
if total_skipped:
    cats = ", ".join(f"{v} {k.replace('_', ' ')}"
                     for k, v in skip_counts.items() if v)
    detail += f", {total_skipped} record(s) skipped ({cats})"
```

**验证**：`G-10` 通过冻结 `render_report()` 渲染真实步骤表，断言正文同时包含：

- `1 record(s) skipped`（跳过数量）
- `unsupported severity`（原因类别）
- `completeness=PARTIAL`（完整性降级）

即「最终报告正文必须显示跳过数量和原因类别」已由**未修改的冻结渲染器**实测证明。

---

## 7. 测试结果

实施完成后按方案 §8 运行六组测试，逐组记录命令、退出码、断言数与结果：

| # | 命令 | 退出码 | 断言数 | 结果 |
|---|---|---|---|---|
| 1 | `python tests/test_semgrep_adapter.py` | 0 | 125 | 125/125 PASS |
| 2 | `python tests/test_semgrep_integration.py` | 0 | 48 | 48/48 PASS |
| 3 | `python tests/test_d2d1_proccleanup.py`（冻结） | 0 | 21 | PASS=21 FAIL=0 SKIP=0 |
| 4 | `python tests/test_d2d0_d2d4.py`（冻结） | 0 | 30 | PASS=30 FAIL=0 SKIP=0 |
| 5 | `python tests/test_findings_schema.py` | 0 | 104 | 104/104 PASS |
| 6 | `python tests/test_findings_integration.py` | 0 | 88 | 88/88 PASS |
| | **合计** | **全 0** | **416** | **0 失败** |

说明：

- 组 1–2 为本批次针对性测试（九值映射、D2 审计、D3 降级、D6 分类、W1-05、报告可见性）。
- 组 3–4 为冻结五文件中的两个测试，验证冻结核心行为未被破坏。
- 组 5–6 为 `findings.py` 统一 schema 的额外确认（该文件只读、未修改）。
- 全部测试基于 `_spawn` mock；**未安装、未下载、未运行真实 Semgrep**（CR-06 缺口依旧，见 §9）。

---

## 8. 冻结文件哈希与 Git 状态

### 8.1 冻结五文件（与 W1 报告 §1.2 基线逐项一致，未变）

| 文件 | SHA256 |
|---|---|
| `vuln_hunter/adapters.py` | `65ece047b13784e0efbf00bd71166279734ea150a90ec56db5830bd551098f59` |
| `vuln_hunter/runner.py` | `29d71dc54f34bc024bde13cc8ec5fcac2745fddeb676ad302aaa5320ebcd842c` |
| `vuln_hunter/report.py` | `59caebb3094896f1a6eb0e63de16b87d59c52a6512a77d2e0661a54e60761683` |
| `tests/test_d2d1_proccleanup.py` | `1cd2b9483c4869c4fbad4ecadeafaad8b67a1396b69d8694bb62852a2c194c13` |
| `tests/test_d2d0_d2d4.py` | `840046857997917bec2dd542c7af6819261001af42bce5a6aa14684bf668aaf9` |

### 8.2 Git 状态

| 核验项 | 值 |
|---|---|
| HEAD | `9913c50`（未变） |
| `git diff --stat` | `5 files changed, 83 insertions(+), 4 deletions(-)`（与基线一致） |
| `git status --short` | 5 个 `M` + 24 个 `??` |
| 5 个 `M` | `pyproject.toml`、`tests/test_engine.py`、`tests/test_taskgraph.py`、`vuln_hunter/__main__.py`、`vuln_hunter/planner.py` —— **均为既有改动，非批次 1 所为** |
| 24 个 `??` | 既有 23 项 + 本报告 1 项（`docs/EXT-2-BATCH1-IMPLEMENTATION-REPORT.md`） |

**副产物保留**：`output/vuln_hunter_report.md`（2,724 B，2026-11-08 22:14）仍在，未清理。`%TEMP%\tmp.AvXfUFcabf\` 仍不存在，登记 `[U]`（非本轮操作）。

---

## 9. 边界与未变更项

**本轮未做**（严格边界）：

- 未安装、下载或运行真实 Semgrep；`semgrep` 仍不在 PATH，零 Semgrep 痕迹。
- 未修改冻结五文件、`findings.py`、Planner、其他 Adapter、G15、C14。
- 未修改任何配置或基准文档。
- 未清理任何证据或副产物。
- 未改变任何历史 `UNKNOWN` 或失败记录；未将任何历史 `FAIL` 改写为 `PASS`。
- 未触碰六项历史验收状态。

**仍开放 / 未闭合**：

| 编号 | 事项 | 状态 |
|---|---|---|
| W1-03 | 缺 `paths.skipped` → `INCOMPLETE` 与官方 schema「非必填」冲突 | **暂缓**，等待真实 Semgrep 基线（U9） |
| W1-04 | `paths.scanned`（官方必填）未检查 | **暂缓**，同上 |
| W1-06 | `_skip_explained` 宽于 schema 的 `reason` 要求 | **不处理**（D5 裁定） |
| CR-06 | 真实 Semgrep 二进制端到端验证缺口 | **未闭合**；所有测试基于 `_spawn` mock，L3 证据 ≠ 真机兼容性证据 |
| 批次 2 | W1-03/W1-04 Remediation | **未授权** |

---

## 10. 完成后停止

批次 1 Remediation 实施到此停止。等待人工审批下一步（批次 2 / 真实 Semgrep 基线 / CR-06 闭环）。

在获得明确审批前：不修改任何源码、测试、配置或基准文档，不运行测试或 Semgrep，不改变任何验收状态，不清理任何证据或副产物。

*报告结束。*
