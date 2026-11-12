# EXT-2 批次 1 最小 Remediation 实施方案（准备稿，未实施）

> **任务**：`W1 审查报告已收到。现阶段只批准准备批次 1 的最小 Remediation 实施方案，暂不授权源码修改。`
> **性质**：**实施方案准备**。本轮**不修改任何源码、测试、配置、基准文档**；不运行测试或 Semgrep；不下载/安装工具。
> **范围**：仅 W1-01（九值 Severity 映射）、W1-02（`records_skipped` 报告可见性）、W1-05/W1-06（仅评估是否顺带低风险解决）。
> **明确暂缓**：W1-03（`paths.skipped` 策略）、W1-04（`paths.scanned` 检查）**不在本批次**，等待真实 Semgrep 基线（U9）。
> **完成日期**：2026-11-11
> **状态**：准备完成，**停止等待人工审批**。审批通过前不实施任何代码修改。

---

## 1. 授权范围与边界

### 1.1 本轮授权（逐字约束）

用户批准：**只准备批次 1 的最小 Remediation 实施方案，暂不授权源码修改。**

范围仅限：

1. **W1-01**：修复 Semgrep 九种 Severity 的映射问题，重点覆盖官方当前推荐的 `CRITICAL/HIGH/MEDIUM/LOW`，确保合法发现不会因映射缺失而被静默跳过。
2. **W1-02**：设计在不修改冻结文件 `report.py` 的前提下，让 `records_skipped` 的数量及必要原因在最终报告中可见。
3. **W1-05/W1-06**：仅评估是否可以随上述修复低风险解决；不要求必须修改。

### 1.2 本轮禁止事项 `[E]`

- 不修改源码、测试、配置、基准文档；
- 不运行测试、Semgrep；
- 不下载或安装任何工具；
- 不修改冻结五文件；
- 不触碰 G15、C14、六项测试验收状态；
- 保留所有现有证据和副产物，不做清理；
- W1-03/W1-04 暂不修复。

### 1.3 本轮实际执行 `[E]`

只读读取既有源码/测试/基准文档；只读执行 `sha256sum` / `git rev-parse` / `git diff --stat` / `git status` / `ls`；新建本方案文档。

---

## 2. 九种 Severity 的逐项映射依据

### 2.1 依据来源（L0 官方证据，`[R]`）

**来源 A：官方规则语法**（`https://semgrep.dev/docs/writing-rules/rule-syntax`，Phase A §8.1 逐字）：

```text
`severity` `string` Severity can be `LOW`, `MEDIUM`, `HIGH`, or `CRITICAL`.
It indicates the criticality of issues detected by a rule. ...
The older levels `ERROR`, `WARNING`, and `INFO` match `HIGH`, `MEDIUM`, and `LOW`.
Severity values remain backwards compatible.
```

**来源 B：官方 JSON schema `match_severity`**（Phase A §8.2 逐字）：

```json
"match_severity": {
  "oneOf": [
    { "const": "ERROR" },
    { "const": "WARNING" },
    { "const": "EXPERIMENT" },
    { "const": "INVENTORY" },
    { "description": "since 1.72.0, meant to replace the cases above where Error -> High,
        Warning -> Medium. Critical/Low are the only really new category here without
        equivalent before. Experiment and Inventory above should be removed. Info can be kept.",
      "const": "CRITICAL" },
    { "const": "HIGH" },
    { "const": "MEDIUM" },
    { "const": "LOW" },
    { "description": "generic placeholder for non-risky things (including experiments)",
      "const": "INFO" }
  ]
}
```

**来源 C：项目统一 Finding schema**（`vuln_hunter/findings.py:67`，`[E]`）：

```python
ALLOWED_SEVERITY = ("info", "low", "medium", "high", "critical")
```

### 2.2 逐项映射表

| # | 官方 `extra.severity` | 官方依据（逐字/出处） | 项目 Finding severity | 确定性 |
|---|---|---|---|---|
| 1 | `ERROR` | 来源 A：`ERROR ... match HIGH`；来源 B：`Error -> High` | `high` | **明确** |
| 2 | `WARNING` | 来源 A：`WARNING ... match MEDIUM`；来源 B：`Warning -> Medium` | `medium` | **明确** |
| 3 | `CRITICAL` | 来源 B：官方新类别（`Critical/Low are the only really new category`） | `critical` | **明确** |
| 4 | `HIGH` | 来源 A/B：官方推荐值；统一 schema 有 `high` | `high` | **明确** |
| 5 | `MEDIUM` | 来源 A/B：官方推荐值；统一 schema 有 `medium` | `medium` | **明确** |
| 6 | `LOW` | 来源 A/B：官方推荐值；统一 schema 有 `low` | `low` | **明确** |
| 7 | `INFO` | 来源 A：`INFO match LOW`；来源 B：`generic placeholder for non-risky things` | `info`（现状）**或** `low` | **需裁定**（两个落点均有官方依据，见 §2.3） |
| 8 | `EXPERIMENT` | 来源 B：`Experiment and Inventory above should be removed`；无 severity 对应 | `info`（建议）**或**显式跳过+可见 | **需裁定**（无官方 Finding severity 对应，见 §2.4） |
| 9 | `INVENTORY` | 来源 B：同上 | `info`（建议）**或**显式跳过+可见 | **需裁定**（同上） |

### 2.3 `INFO` 的裁定项（不猜测）`[I]`

两个候选落点**都有**官方依据，但指向不同：

- **`info`**：现状。依据来源 B 的描述「generic placeholder for non-risky things」——语义上 `info` 即「非风险信息」，与统一 schema 的 `info` 一致；且**行为不变**，回归风险最低。
- **`low`**：依据来源 A 的逐字「`INFO` match `LOW`」——官方明确把旧 `INFO` 对应到新 `LOW`。

**不猜测**：本方案不自行选定。推荐 **保持 `info`**（最小行为变化、语义贴合 schema 描述），并在实施记录中登记「官方 rule-syntax 将 `INFO` 对应 `LOW`，本实现保留 `info`，属已知语义差异」。若用户要求严格对齐官方对应关系，则改为 `low` 并同步更新测试。

### 2.4 `EXPERIMENT` / `INVENTORY` 的裁定项（不猜测）`[I]`

官方 schema 明确说二者「should be removed」，**没有**给出到 Finding severity 的对应关系。因此：

- **不得猜测**一个严重度；
- 可选方案：
  - **方案 (a)（建议）**：映射为 `info`，并在报告 `name` 说明中**显式标注**「遗留值，系统映射为 info」——保证不静默丢失，且不虚构严重度；
  - **方案 (b)**：保留「跳过」行为，但通过 §3 的可见性机制让其在报告中显式出现（`N record(s) skipped (unsupported_severity)`）；
  - **方案 (c)**：映射为 `low`——**不推荐**，因为无官方依据，属猜测。

**推荐 (a)**：既不静默丢失，也不虚构严重度，且与「non-risky placeholder」的语义方向一致。

### 2.5 映射实现位置 `[E]`

`vuln_hunter/adapters_ext/semgrep.py`：

- `_SEVERITY_MAP`（`:80-84`）——唯一映射表；
- `SEMGREP_SEVERITY_MAP = dict(_SEVERITY_MAP)`（`:91`）——公开副本，自动跟随；
- `_to_finding()`（`:565-568`）——查表，未命中抛 `FindingError`。

---

## 3. 跳过记录处理原则与 W1-02 可见性设计

### 3.1 处理原则（强制）`[I]`

| 编号 | 原则 |
|---|---|
| **P1** | 不支持 severity / 结构的记录**绝不**被降级或伪装成有效 finding；维持 `_to_finding()` 抛 `FindingError` → `continue` 的 fail-closed 行为。 |
| **P2** | 跳过必须**三处可审计**：① `attempt` 日志（已有，`:405`）；② journal `attempt_end.meta`（已有，`:443`）；③ **最终报告**（W1-02 补齐）。 |
| **P3** | 跳过**不得**使扫描呈现为「完整无跳过」：启用 §3.3 的降级后，`records_skipped > 0` 时 `meta.completeness` 至少为 `PARTIAL`，`detail` 前缀为 `[completeness=PARTIAL]`。 |
| **P4** | 跳过原因**只记录固定类别**（`unsupported_severity` / `malformed_record`），**绝不**写入原始工具值（保持 CR-03 安全边界）。 |
| **P5** | `INCOMPLETE`（结构/完整性失败）路径**不采收**任何 finding（维持 `:384-395` 现状）。 |

### 3.2 可见性通道（不改 `report.py`）`[E]`

冻结 `report.py` 步骤表渲染逻辑（`:43-48`）：

```python
f"| {sid} | {r['adapter']} | ... | {r.get('reason') or r.get('detail','')} |"
```

`Executor` 把 `AdapterResult.detail` 写入 `rec["detail"]`（`runner.py:272`），而 `reason` 仅在门禁拒绝等场景设置。因此 **`AdapterResult.detail` 是 adapter 能控制的、进入报告步骤表的唯一通道**。

**结论**：只需扩展 `_run()` 构造的 `detail` 字符串，即可让 `records_skipped` 数量与原因进入最终报告，**无需触碰 `report.py`**。

### 3.3 实现设计（仅方案，未实施）

**改动点 1：分类计数**（`:397-406` 采收循环）

```python
findings = []
skip_counts = {"unsupported_severity": 0, "malformed_record": 0}
for i, rec in enumerate(raw_results):
    try:
        f = _to_finding(rec, target)
    except FindingError as exc:
        # FindingError 消息均为 value-free 固定字符串（字段名/类别），不含工具值
        if "severity" in str(exc):
            skip_counts["unsupported_severity"] += 1
        else:
            skip_counts["malformed_record"] += 1
        log.write(f"record {i} skipped: {exc}\n")
        continue
    ...
```

**改动点 2：可选降级 + detail 可见性**（`:383` 之后、`:433-435` 之前/之处）

```python
total_skipped = sum(skip_counts.values())
# 可选（推荐启用，对应 P3）：有跳过记录时不得呈现为「完整无跳过」
if total_skipped and level == "COMPLETE":
    level = "PARTIAL"
    reasons.append(f"{total_skipped} record(s) skipped (unsupported severity/shape)")

detail = f"[completeness={level}] semgrep exit {rc}, {len(findings)} finding(s)"
if total_skipped:
    cats = ", ".join(f"{v} {k.replace('_', ' ')}"
                     for k, v in skip_counts.items() if v)
    detail += f", {total_skipped} record(s) skipped ({cats})"
if reasons:
    detail += "; " + "; ".join(reasons)
```

**改动点 3：meta 扩展**（`:196-210` `_meta` / `:438-445` 调用）

- 保留现有 `records_skipped`（`:443`）；
- 可选新增 `skip_counts` 键（`dict`，仅固定类别与计数），便于 journal 审计。**不新增 `AdapterResult.status`，不改冻结文件。**

### 3.4 报告呈现效果（预期）`[I]`

启用降级后，一个含 2 条合法 + 1 条 `CRITICAL`（映射扩展后合法）+ 1 条未知 severity 的报告：

```text
| s5-semgrep | semgrep | R1 | `...` | COMPLETED | 1 | [completeness=PARTIAL] semgrep exit 0, 3 finding(s), 1 record(s) skipped (1 unsupported severity) |
```

- 状态仍为 `COMPLETED`（兼容方案，`STATUS_PRIORITY` 无 `PARTIAL`）；
- `completeness=PARTIAL` 显式可见，**不再伪装为完整扫描**；
- 原因类别可见，但**不含**原始工具值。

---

## 4. W1-05 / W1-06 评估

### 4.1 W1-05（`name` 硬编码映射说明）`[E]`

- 现状：`semgrep.py:424-429` 硬编码 `ERROR→high / WARNING→medium / INFO→info`。
- 若扩展 `_SEVERITY_MAP`，该字符串**必然失真**（遗漏 `CRITICAL/HIGH/MEDIUM/LOW` 等）。
- **评估**：**可低风险顺带解决，建议纳入批次 1**。改动仅限 `semgrep.py` 内一个字符串构造，且现有测试断言（集成 `E-03` 只检查「由 Semgrep 报告的」「非 DualVerify-Sentinel 自行判定」等子串，不依赖完整映射文本）不受影响。
- 建议实现：动态生成映射短语，例如：

```python
_mapping_phrase = " / ".join(f"{k.upper()}→{v}" for k, v in _SEVERITY_MAP.items())
d["name"] = (f"{f.title} "
             f"[severity={f.severity} 由 Semgrep 报告的 severity 字段经 "
             f"{_mapping_phrase} 映射得到；非 DualVerify-Sentinel 自行判定]")
```

### 4.2 W1-06（`_skip_explained` 宽于 schema）`[E]`

- 现状：`_SKIP_REASON_KEYS = ("reason", "type", "message", "code")`（`:142`），宽于 schema 的 `reason` 要求。
- 该逻辑属于 `paths.skipped` 判定链，与 **W1-03（明确暂缓）** 直接相关。
- **评估**：技术上可低风险修改（仅收窄一个元组），但**不建议纳入批次 1**：
  - 收窄会改变 `paths.skipped` 判定行为，与「W1-03 暂缓、等待真机基线」冲突；
  - 在真机 `skipped_target` 键名集合未知（U4/U18）前收窄，可能误判真机合法输出；
  - 无独立收益。
- **结论**：**不纳入批次 1**，留待 W1-03 真机基线后一并裁定。

---

## 5. 精确修改清单（待授权后实施）

> 以下为**拟修改**，本轮**未实施** `[E]`。

### 5.1 源码：`vuln_hunter/adapters_ext/semgrep.py`

| 位置 | 函数/对象 | 拟改动 |
|---|---|---|
| `:80-84` | `_SEVERITY_MAP` | 扩展为覆盖官方明确值（`CRITICAL/HIGH/MEDIUM/LOW`），并按裁定加入 `INFO` 与 `EXPERIMENT/INVENTORY` |
| `:91` | `SEMGREP_SEVERITY_MAP` | 无需改动（`dict(_SEVERITY_MAP)` 自动跟随） |
| `:397-406` | `_run()` 采收循环 | 新增 `skip_counts` 分类计数（固定类别） |
| `:383` 后 / `:433-435` | `_run()` detail 构造 | 可选降级（`COMPLETE→PARTIAL`）+ 追加 skipped 计数与原因类别 |
| `:438-445` | `_run()` `AdapterResult` / `_meta` | 传入 `records_skipped`（已有）；可选新增 `skip_counts` |
| `:424-429` | `_run()` `name` 构造 | 动态生成映射短语（W1-05） |

### 5.2 测试：`tests/test_semgrep_adapter.py`

| 用例 | 拟改动 |
|---|---|
| N 段（`:547-563`） | 重写为**九值逐项映射断言**（含 `CRITICAL/HIGH/MEDIUM/LOW`）；未知值（`WEIRD`/``/None/非字符串）断言跳过且**可见性信号存在** |
| 新增段（建议 S 段） | `records_skipped` 可见性：构造 1 合法 + 1 未知 severity，断言 `detail` 含 skipped 计数；若启用降级，断言 `meta["completeness"] == "PARTIAL"` 且前缀 `[completeness=PARTIAL]` |
| M 段（`:521-544`） | 复核 `records_skipped == 6` 仍成立；若启用降级，确认 `completeness` 变化是否需同步断言 |
| Q-06（`:636-641`） | 保持（无 skip → `COMPLETE`） |

### 5.3 测试：`tests/test_semgrep_integration.py`

| 用例 | 拟改动 |
|---|---|
| 新增 G-09 | 真实 `Executor` + 冻结 `render_report()`，验证 `detail` 含 skipped 计数（可见性进入报告步骤表） |
| 若启用降级 | 验证 `[completeness=PARTIAL]` 出现在渲染报告中 |
| 现有 G-01..G-08 / E-01..E-08 | 保持；复核是否因 `INFO` 语义或 detail 文本变化需同步 |

### 5.4 预期结果

| 场景 | 预期 |
|---|---|
| 官方明确值（`CRITICAL/HIGH/MEDIUM/LOW`/`ERROR/WARNING`） | 全部产出 Finding，severity 正确映射，`records_skipped=0` |
| `INFO` | 按裁定（`info` 或 `low`）产出 Finding |
| `EXPERIMENT/INVENTORY` | 按裁定：映射 `info` 并标注，或跳过但可见 |
| 未知值（`WEIRD`/缺失/非字符串） | 跳过；`detail` 含计数与原因类别；若启用降级，`completeness=PARTIAL` |
| 现有合法扫描（无跳过） | `COMPLETE` / `COMPLETED`，行为不变 |
| `paths.skipped` 相关 | **完全不变**（W1-03/04 暂缓） |
| 冻结文件 | **完全不变** |

---

## 6. 不修改项与边界 `[E]`

- **冻结五文件**（`adapters.py` / `runner.py` / `report.py` / `test_d2d1_proccleanup.py` / `test_d2d0_d2d4.py`）：**不触碰**。
- **W1-03/W1-04**：**暂不修复**，等待真实 Semgrep 基线（U9）。
- **`paths.skipped` 策略、`_completeness()` 判定逻辑**：**不变**。
- **`build_command()` / `_spawn()` / 执行门禁 / 状态枚举**：**不变**。
- **`findings.py` / `journal.py` / `policy.py` / `planner.py` / `__main__.py`**：**不变**。
- **W1-06**：**不纳入**（见 §4.2）。
- **Git**：本轮无源码修改，不涉及提交。

---

## 7. 风险与回滚

| 风险 | 说明 | 缓解 |
|---|---|---|
| `INFO` 语义变化 | 若裁定改 `low`，会改变现有 N 段断言与用户预期 | 默认保持 `info`；如改 `low` 需同步测试并登记差异 |
| detail 文本变化 | 进入报告步骤表，可能影响报告快照 | 现有测试未对 detail 全文做断言；实施后复核 |
| 降级 PARTIAL 影响面 | `records_skipped>0` 时 `completeness` 由 `COMPLETE` 变 `PARTIAL` | 仅影响有跳过的扫描；无跳过路径不变 |
| 分类计数依赖异常消息 | 用固定消息关键词分类 | `_to_finding()` 消息均为 value-free 固定字符串；实施时补测试覆盖 |
| 映射扩展引入新值 | 纯向后兼容增强 | 现有 3 值映射保持不变 |

**回滚方案**：单文件 `semgrep.py` + 两个测试文件 revert；无配置/环境/证据变更；冻结哈希不受影响。

---

## 8. 验证计划（授权后执行，本轮不执行）`[I]`

1. `python tests/test_semgrep_adapter.py` —— 九值映射、可见性、降级用例全绿；
2. `python tests/test_semgrep_integration.py` —— 真实门禁/执行链 + 冻结 `render_report()` 可见性验证；
3. 相关离线回归（含冻结五文件中的两个测试）；
4. 冻结五文件哈希复核、HEAD、Git 状态复核；
5. 副产物保留确认（`output/vuln_hunter_report.md`；`%TEMP%\tmp.AvXfUFcabf\` 已消失，登记 `[U]`）。

---

## 9. 需人工裁定的开放项

| 编号 | 事项 | 选项 | 建议 |
|---|---|---|---|
| **D1** | `INFO` 映射 | `info`（现状）/ `low`（官方对应） | **保持 `info`**（最小变化），登记语义差异 |
| **D2** | `EXPERIMENT` / `INVENTORY` | 映射 `info` 并标注 / 显式跳过+可见 / 其他 | **映射 `info` 并标注**（不静默丢失、不虚构严重度） |
| **D3** | 是否启用 `records_skipped>0 → PARTIAL` 降级 | 启用 / 仅可见不降级 | **启用**（满足「不伪装为完整扫描」） |
| **D4** | W1-05 是否纳入 | 纳入 / 不纳入 | **纳入**（映射扩展的必要配套） |
| **D5** | W1-06 是否纳入 | 纳入 / 不纳入 | **不纳入**（与 W1-03 暂缓冲突） |
| **D6** | 分类计数是否新增 `skip_counts` meta 键 | 新增 / 仅 detail | **新增**（便于 journal 审计，不改 schema） |

---

## 10. 收尾核验

> 本节记录方案准备完成后（2026-11-11）的只读复核结果 `[E]`。

| 核验项 | 准备前基线 | 完成后复核 | 结论 |
|---|---|---|---|
| 冻结五文件哈希 | 见 W1 报告 §1.2 | 与 W1 报告 §1.2 逐项一致 | 不变 |
| `vuln_hunter/adapters_ext/semgrep.py` SHA256 | `434dfcfa90c85ad465c9cd102e966d87d4faf2f149d7c2d1733fe368b696ee9e` | `434dfcfa90c85ad465c9cd102e966d87d4faf2f149d7c2d1733fe368b696ee9e` | 不变 |
| `tests/test_semgrep_adapter.py` SHA256 | `403c683af51ec5bf4e00a3a8dfc01a399ca387a301560858c814ae58df6cdf67` | `403c683af51ec5bf4e00a3a8dfc01a399ca387a301560858c814ae58df6cdf67` | 不变 |
| `tests/test_semgrep_integration.py` SHA256 | `1c084bd8f9727caed8e65c6f5421b1c89fe6f5d10adc7c9612f4834b0383ab52` | `1c084bd8f9727caed8e65c6f5421b1c89fe6f5d10adc7c9612f4834b0383ab52` | 不变 |
| W1 报告 SHA256 | `39ca01dc058fe69e8c864b8e0ddb801b191498b14427bdf7d95bd43367da5bf8` | `39ca01dc058fe69e8c864b8e0ddb801b191498b14427bdf7d95bd43367da5bf8` | 不变 |
| HEAD | `9913c50` | `9913c50` | 未变 |
| `git diff --stat` | 5 files / 83 insertions / 4 deletions | `5 files changed, 83 insertions(+), 4 deletions(-)` | 一致 |
| `git status --short` | 5 个 `M` + 22 个 `??` | 5 个 `M` + 23 个 `??`；新增项仅 `?? docs/EXT-2-BATCH1-REMEDIATION-PLAN.md` | 仅新增本方案 1 项 `??` |
| `output/vuln_hunter_report.md` | 存在（2,724 B，11-08 22:14） | 存在（2,724 B，11-08 22:14） | 保留 |
| `%TEMP%\tmp.AvXfUFcabf\` | 已不存在 | 不存在 | `[U]`（非本轮操作） |

**工具与环境状态** `[E]`：`semgrep: not on PATH`。本轮**未产生任何 Semgrep 安装、下载或运行痕迹**；未修改任何源码/测试/配置；`git diff` 的 `LF will be replaced by CRLF` 仅为工具 warning。

> **自引用说明** `[I]`：本方案自身的行数 / 字节数 / SHA256 在**最终答复**中给出，不写入正文。

---

## 11. 完成后停止

本方案为「批次 1 最小 Remediation 实施方案」的**唯一交付物**。本轮到此停止，**不实施任何代码修改**，不运行测试或 Semgrep，不下载/安装工具，不修改冻结文件或验收状态，不清理任何证据或副产物。

在获得明确审批前：不修改 `semgrep.py`、不更新测试、不调整 `paths.skipped` 策略、不改变 `CR-06` / `EXT-2` / G15 / C14 / 六项测试阶段状态。

*方案结束。*
