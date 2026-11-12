# EXT-2 W1 独立只读代码审查：Severity 九值映射 与 paths.skipped 完整性判定

> **任务**：`EXT-2 下一阶段：W1 独立 Code Review`
> **性质**：独立、只读代码审查；不修改任何源码、测试、配置、规则或文档（本报告除外）。
> **审查对象**：当前 `vuln_hunter/adapters_ext/semgrep.py` 及其调用链，仅针对两项问题：
> 1. Severity 九值映射完整性；
> 2. `paths.skipped` 缺失及不同结构下的完整性判定。
> **完成日期**：2026-11-11
> **结论摘要**：确认 **2 项 BLOCKER 级确定性缺陷**（W1-01 severity 映射缺口、W1-02 丢记录可观测性缺口）、**2 项 HIGH**（W1-03 `paths.skipped` 策略契约冲突、W1-04 `paths.scanned` 未检查）、**2 项 LOW**（W1-05 硬编码映射说明、W1-06 `_skip_explained` 过宽）。**建议进入 Remediation，但分两批**：确定性缺陷可立即修复；条件性策略须等真机基线 U9 闭合。

---

## 1. 审查范围与基线

### 1.1 授权范围（逐字约束）

用户批准启动 W1，**只针对以下两个问题**开展独立只读代码审查：

1. Severity 九值映射完整性；
2. `paths.skipped` 缺失及不同结构下的完整性判定。

审查基准：

- `docs/EXT-2-PHASE-A-PLAN-GAP-ANALYSIS.md`
- `docs/EXT-2-PHASE-A-VERIFICATION-REPORT.md`
- 当前 `vuln_hunter/adapters_ext/semgrep.py`
- 当前相关测试文件及必要的接口定义。

**本授权只包含 W1**，不包含 Remediation、Plan 修改、wheel 下载、环境准备或真实扫描。

### 1.2 审查对象与基线哈希 `[E]`

分析开始前（2026-11-11）只读采集，全部由 `sha256sum` 取得：

| 文件 | SHA256 |
|---|---|
| `vuln_hunter/adapters_ext/semgrep.py` | `434dfcfa90c85ad465c9cd102e966d87d4faf2f149d7c2d1733fe368b696ee9e` |
| `vuln_hunter/adapters_ext/__init__.py` | `9654fd2b081d5084678d5043f888a3050674d9f8d3d38559f9f0659994a97067` |
| `tests/test_semgrep_adapter.py` | `403c683af51ec5bf4e00a3a8dfc01a399ca387a301560858c814ae58df6cdf67` |
| `tests/test_semgrep_integration.py` | `1c084bd8f9727caed8e65c6f5421b1c89fe6f5d10adc7c9612f4834b0383ab52` |
| `vuln_hunter/findings.py` | `544729a84dcddc738e2e9cd6af187c8afc7af8ace06c619ba76ec3ebd322b33d` |
| `vuln_hunter/adapters.py`（冻结） | `65ece047b13784e0efbf00bd71166279734ea150a90ec56db5830bd551098f59` |
| `vuln_hunter/runner.py`（冻结） | `29d71dc54f34bc024bde13cc8ec5fcac2745fddeb676ad302aaa5320ebcd842c` |
| `vuln_hunter/report.py`（冻结） | `59caebb3094896f1a6eb0e63de16b87d59c52a6512a77d2e0661a54e60761683` |
| `tests/test_d2d1_proccleanup.py`（冻结） | `1cd2b9483c4869c4fbad4ecadeafaad8b67a1396b69d8694bb62852a2c194c13` |
| `tests/test_d2d0_d2d4.py`（冻结） | `840046857997917bec2dd542c7af6819261001af42bce5a6aa14684bf668aaf9` |

基准文档：

| 文件 | SHA256 |
|---|---|
| `docs/EXT-2-PHASE-A-PLAN-GAP-ANALYSIS.md` | `5c852500de094e4ee709b547c8ea7da1e14c16773c5aef4fb2bbbe231b1af487` |
| `docs/EXT-2-PHASE-A-VERIFICATION-REPORT.md` | `3d40300b91720eea786ae73299bdabe74df54cd696c37ef9309a0f03ec731185` |

Git 基线 `[E]`：HEAD `9913c50`；`git diff --stat` = `5 files changed, 83 insertions(+), 4 deletions(-)`；`git status --short` = 5 个 `M` + 21 个 `??`。

### 1.3 严格边界 `[E]`

本轮**未**：修改任何源码/测试/配置/规则/文档（本报告除外）；下载、安装、运行 Semgrep；执行测试或扫描；修改 Git 状态或提交；修改冻结五文件；清理任何验证副产物；改变 `CR-06` / `EXT-2` / G15 / C14 / 六项测试阶段状态；顺带审查或重构其他模块。

本轮**仅**：只读读取源码/测试/接口/基准文档；只读执行 `sha256sum` / `git rev-parse` / `git diff --stat` / `git status` / `ls`；新建本报告。

### 1.4 副产物状态变化（重要）`[E]` + `[U]`

| 副产物 | 上一轮记录（2026-11-09） | 本轮 W1 开始时（2026-11-11） | 结论 |
|---|---|---|---|
| `output/vuln_hunter_report.md` | 存在（2,724 B，11-08 22:14） | 存在（2,724 B，11-08 22:14） | **仍在，未改动** |
| `%TEMP%\tmp.AvXfUFcabf\` | 存在（目录，11-08 22:14） | **不存在**；`%TEMP%` 下无任何 `tmp.*` 条目（`$TEMP` 与 `cmd /c echo %TEMP%` 均为 `C:\Users\ZTL\AppData\Local\Temp`，路径解析无误） | **已消失**；**非本轮操作所致**（本轮全程只读，未执行任何删除/移动/清理）；消失原因 `[U]`（可能为系统临时清理或用户手动清理，无法从只读证据判定） |

> **边界声明** `[I]`：用户要求「不清理任何验证副产物」。本轮**未清理**；该目录的消失发生在 W1 授权之前或之外，本轮无法恢复，也不推断原因。`output/vuln_hunter_report.md` 仍按约束保留。

---

## 2. 审查方法与证据分层

本节沿用 `docs/EXT-2-PHASE-A-PLAN-GAP-ANALYSIS.md` §4 的证据分层，避免混淆：

| 层 | 含义 | 本轮使用 |
|---|---|---|
| **L0** | 官方文档 / Schema 声明 | Phase A 报告 §7.3 / §7.4 / §8.1 / §8.2 / §8.3 的逐字引用 `[R]` |
| **L1** | Semgrep 真机运行输出 | **本轮不可用**（禁止运行 Semgrep）；相关结论一律 `[U]` |
| **L2** | Adapter 实际解析结果（源码可静态判定） | `semgrep.py` 逐行调用链 `[E]` |
| **L3** | 人工注入故障测试（mock `_spawn`） | 两个测试文件的既有断言 `[E]`；**不等于真机兼容性证据** |
| **L4** | 网络出站观测 | 本轮不涉及 |

**判定纪律** `[I]`：
- 源码可静态判定的事实标 `[E]`，**不依赖真机**；
- 依赖真机输出形态的结论标 `[U]`，**不推断**；
- L0 与 L2 冲突时，**先登记冲突**，不得仅凭 L0 改码，也不得仅凭 L2 否定官方契约。

---

## 3. 问题一：Severity 九值映射完整性

### 3.1 完整调用链（逐行）`[E]`

从 JSON 读取到最终 status/report 的完整路径如下（行号均为当前 `semgrep.py`）：

```text
(1) _run() :342-343   json.loads(stdout) -> data（dict）
(2) _run() :359-363   raw_results = data["results"]，要求 list
(3) _run() :399-401   for i, rec in enumerate(raw_results):
                          f = _to_finding(rec, target)
(4) _to_finding() :562-564   extra = rec.get("extra")，要求 dict
(5) _to_finding() :565       sev_raw = _str_field(extra, "severity").lower()
       _str_field() :482-490 val = rec.get(name)
                                 None -> ""（不报错）
                                 非 str -> raise FindingError
                                 否则 -> _sanitize(val.strip())
(6) _sanitize() :110-118     中和 \r\n\t、C0/C1 控制字符、ESC；
                                 转义 Markdown 元字符；文本保留
(7) _to_finding() :566       sev = _SEVERITY_MAP.get(sev_raw)
(8) _to_finding() :567-568   sev is None -> raise FindingError(
                                 "semgrep record: unsupported or missing severity")
(9) _run() :402-406       except FindingError:
                             skipped += 1
                             log.write(f"record {i} skipped: {exc}")
                             continue          # 不改变 status / ok
(10) _run() :433-435     detail = f"[completeness={level}] semgrep exit {rc}, "
                                 f"{len(findings)} finding(s)"
                          # detail 不含 skipped 计数
(11) _run() :438-445     return AdapterResult("COMPLETED", True, detail, findings,
                                 meta=_meta(level, reasons,
                                            records_seen=len(raw_results),
                                            records_used=len(findings),
                                            records_skipped=skipped, ...))
(12) runner._attempt_loop() :251-260
                          journal.append("attempt_end", status=res.status,
                                         ok=res.ok, detail=res.detail, meta=...)
(13) runner._attempt_loop() :267-273
                          res.status == "COMPLETED" -> break；rec["status"]=COMPLETED
(14) report.render_report() :43-48
                          步骤表渲染 r.get('reason') or r.get('detail','')
                          # 不含 records_skipped
(15) report.render_report() :57-63
                          发现列表渲染 f.get('name') 与 f.get('severity')
```

**关键事实** `[E]`：`_SEVERITY_MAP`（`:80-84`）只有 3 个键；映射失败路径**只** `continue`，`status`/`ok` 不变；即使 `raw_results` 全部被跳过，仍返回 `AdapterResult("COMPLETED", True, ...)`，`findings=[]`，`meta.records_skipped=N`。

### 3.2 九值映射矩阵（实际执行路径）`[E]` + `[R]`

官方输出 schema `match_severity` 允许 9 值（Phase A §8.2 逐字 `[R]`）。逐值给出**当前实现的实际执行路径**：

| # | 官方 `extra.severity` | `.lower()` 后 | `_SEVERITY_MAP` 命中 | 实际执行路径 | `records_skipped` | 整体 status / ok | 分类 |
|---|---|---|---|---|---|---|---|
| 1 | `ERROR` | `error` | ✅ → `high` | `Finding(severity="high")` → 采收 | 否 | `COMPLETED` / `True` | 已正确映射 |
| 2 | `WARNING` | `warning` | ✅ → `medium` | `Finding(severity="medium")` → 采收 | 否 | `COMPLETED` / `True` | 已正确映射 |
| 3 | `INFO` | `info` | ✅ → `info` | `Finding(severity="info")` → 采收 | 否 | `COMPLETED` / `True` | 已映射，但官方把 `INFO` 对应 `LOW`，语义偏移 `[I]` |
| 4 | `EXPERIMENT` | `experiment` | ❌ | `FindingError` → `continue` | **是（+1/条）** | `COMPLETED` / `True` | **未映射被跳过** |
| 5 | `INVENTORY` | `inventory` | ❌ | `FindingError` → `continue` | **是（+1/条）** | `COMPLETED` / `True` | **未映射被跳过** |
| 6 | `CRITICAL` | `critical` | ❌ | `FindingError` → `continue` | **是（+1/条）** | `COMPLETED` / `True` | **未映射被跳过**（官方**当前推荐**值） |
| 7 | `HIGH` | `high` | ❌（键是 `error`） | `FindingError` → `continue` | **是（+1/条）** | `COMPLETED` / `True` | **未映射被跳过**（官方**当前推荐**值） |
| 8 | `MEDIUM` | `medium` | ❌（键是 `warning`） | `FindingError` → `continue` | **是（+1/条）** | `COMPLETED` / `True` | **未映射被跳过**（官方**当前推荐**值） |
| 9 | `LOW` | `low` | ❌ | `FindingError` → `continue` | **是（+1/条）** | `COMPLETED` / `True` | **未映射被跳过**（官方**当前推荐**值） |

**统计** `[E]`+`[R]`：已映射 **3 / 9**；未映射但被静默跳过 **6 / 9**；其中 **4 个**（`CRITICAL` / `HIGH` / `MEDIUM` / `LOW`）是官方**当前推荐**的规则 severity 值（Phase A §8.1 `[R]`）。

**边界行为补充** `[E]`：
- 大小写不敏感（`.lower()`）：`Critical` / `critical` 行为一致。
- `severity` 缺失或为 `None`：`_str_field` 返回 `""` → `.lower()` 为 `""` → 未命中 → 跳过。
- `severity` 为非字符串（int / list / dict）：`_str_field` 抛 `FindingError` → 跳过。
- `severity` 含控制字符（如 `"ERROR\x00"`）：`_sanitize` 先把 `\x00` 替换为空格并 `" ".join(out.split())`，得到 `"ERROR"` → **会被映射**。即净化发生在映射之前，可能把畸形值「修复」为可映射值。这**不是**缺陷，但属需知晓的边界行为 `[I]`。

### 3.3 未知 Severity 是否导致 Finding 静默丢失 `[E]`

**是，且为源码层确定事实，无需真机即可裁定** `[E]`+`[I]`：

1. `_to_finding()` 对映射外值抛 `FindingError`（`:567-568`）；
2. 采收循环仅 `continue`（`:402-406`），**不改变** `status` / `ok`；
3. `AdapterResult("COMPLETED", True, ...)` 在 `raw_results` 全被跳过时依然返回（`:438-445`），`findings=[]`；
4. `meta.records_skipped` 记录跳过数（`:443`），`attempt` 日志记录 `record i skipped`（`:405`）；
5. **但** `AdapterResult.detail`（`:433`）不含 skipped 计数；冻结 `report.py` 步骤表渲染 `detail`（`:43-48`）→ **报告正文看不到「有 N 条记录被丢弃」**。

**可观测性缺口** `[E]`+`[I]`：
- 可见：`journal` 的 `attempt_end.meta.records_skipped`；`attempt` 日志的 `record i skipped`。
- 不可见：`report` 步骤表与发现列表（只看 `detail` / `name` / `severity`）。
- 结果：一个官方推荐 severity（如 `CRITICAL`）规则命中的扫描，可能在报告中呈现为 `COMPLETED` + `(无发现)`，而**没有任何报告层信号**说明 finding 被丢弃。这是「假成功」风险。

**测试固化问题** `[E]`：`tests/test_semgrep_adapter.py` N 段（`:547-563`）把该缺陷行为**固化为期望**：

```python
for sev in ("CRITICAL", "LOW", "", None):
    ...
    check(f"N-bad-{sev!r}", res.status == "COMPLETED"
          and res.findings == [] and res.meta["records_skipped"] == 1,
          f"severity {sev!r} is NOT in the mapping -> record skipped "
          f"(fail-closed, never silently downgraded to info)")
```

即测试明确断言「未知 severity → 跳过且整体 `COMPLETED`」。这在映射扩展前可视为 fail-closed 记录策略，但**未断言任何报告层可见性**，也未覆盖官方推荐值。Remediation 必须同步更新该段。

### 3.4 三类结论区分（问题一）

| 类别 | 结论 |
|---|---|
| **源码已证实** `[E]` | 映射仅 3/9；6 值（含官方推荐 4 值）被跳过；整体仍 `COMPLETED`/`ok=True`；`detail` 不含 skipped 计数；测试 N 段固化该行为；`name` 字段硬编码映射说明（`:424-429`）。 |
| **依赖真实 Semgrep 输出** `[U]` | 1.182.1 + 自写规则下 `extra.severity` 的**实际取值集合**（U10）；官方推荐值是否真的出现在真机输出中。若真机只输出旧 3 值，则实际影响面缩小；若输出新值，则命中即丢。 |
| **尚未确认** `[U]` | 真机是否会把 `CRITICAL/HIGH/MEDIUM/LOW` 与旧值混用；`EXPERIMENT`/`INVENTORY` 是否真实出现（schema description 暗示应移除，Phase A §8.2 `[R]`）。 |

---

## 4. 问题二：paths.skipped 完整性判定

### 4.1 完整调用链（两道关卡）`[E]`

`semgrep.py` 对完整性信号有**两道独立关卡**，原计划与 Phase A 报告已指出，本节给出完整路径：

```text
(1) _run() :342-343   json.loads(stdout) -> data（dict）
(2) 结构校验（:354-378）—— 使用 .get(默认值)，缺键不拦截：
      raw_results = data["results"]                     :359
      raw_errors   = data.get("errors", [])             :364  ← 缺键默认 []
      paths        = data.get("paths", {})              :369  ← 缺键默认 {}
      skipped_paths = paths.get("skipped", [])          :374  ← 缺键默认 []
      if not isinstance(raw_errors, list):   FAILED     :365-368
      if not isinstance(paths, dict):        FAILED     :370-373
      if not isinstance(skipped_paths, list): FAILED    :375-378
(3) _completeness() :157-193（第二关，无默认值，缺键拦截）：
      if "errors" not in data:                 INCOMPLETE  :164-166
      elif data["errors"]:                     INCOMPLETE  :167-169
      paths = data.get("paths")                            :171
      if not isinstance(paths, dict):          INCOMPLETE  :172-174
      elif "skipped" not in paths:             INCOMPLETE  :176-179
      else:
          skipped = paths["skipped"]
          unexplained = sum(1 for it in skipped
                            if not _skip_explained(it))     :182
          if skipped:                                     :183
              if unexplained:  level = INCOMPLETE          :184-187
              else:            level = PARTIAL (若非 INCOMPLETE) :188-192
(4) _skip_explained() :145-154：item 是 dict 且
      reason/type/message/code 之一为非空字符串 -> True
(5) _run() :383-395   level == INCOMPLETE ->
      AdapterResult("FAILED", False,
                    "[completeness=INCOMPLETE] ...",
                    meta=_meta("INCOMPLETE", reasons,
                               records_seen=len(raw_results),
                               errors_seen=len(raw_errors),
                               paths_skipped=skipped_count))
      # 零采收
(6) _run() :397-445   level == COMPLETE / PARTIAL ->
      采收 findings；AdapterResult("COMPLETED", True, detail, findings,
                                  meta=_meta(level, reasons, ...))
```

`_SKIP_REASON_KEYS`（`:142`）= `("reason", "type", "message", "code")`。

### 4.2 paths.skipped 结构判定矩阵 `[E]` + `[R]`

| 情形 | 输入形态 | 结构校验 `:354-378` | `_completeness()` `:157-193` | 最终结果 | 官方 schema 对照 `[R]` | 真机是否生成 |
|---|---|---|---|---|---|---|
| **①** `paths.skipped` 键缺失 | `paths` 为 dict，含 `scanned`，无 `skipped` | 放行（`.get` 默认 `[]`） | `"skipped" not in paths` → `INCOMPLETE` | `FAILED`、零采收、`meta.completeness=INCOMPLETE`、`detail` 带 `[completeness=INCOMPLETE]` | **合法**：`scanned_and_skipped.required` 仅 `[scanned]`，`skipped` 可选（Phase A §7.3） | `[U]`（U9） |
| **②** `paths.skipped = []` | 空 list | 通过 | `if skipped:` 为 `False` → `level` 保持 `COMPLETE` | `COMPLETED` / `COMPLETE`、正常采收、`meta.paths_skipped=0` | 合法（空数组合法） | `[U]`（U9 相关） |
| **③** 非空、全部 explained | `[{"path":…, "reason":…}, …]` | 通过 | `unexplained=0` → `PARTIAL` | `COMPLETED` / `PARTIAL`、采收、`detail` 带 `[completeness=PARTIAL]`、`meta.paths_skipped=N` | 合法（`skipped_target.required=[path,reason]`） | `[U]`（U4/U18） |
| **④** 非空、存在 unexplained | 裸字符串 / dict 无 reason-like / 非 dict | 通过 | `unexplained>0` → `INCOMPLETE` | `FAILED`、零采收 | **不合法**（schema 要求 object+path+reason）；fail-closed 方向一致 | `[U]`（schema 层不支持，`[R]`） |
| **⑤** 混合 | 部分 explained、部分 unexplained | 通过 | `unexplained>0` → `INCOMPLETE` | `FAILED`、零采收 | 部分不合法 | `[U]` |
| **⑥** `paths` 键缺失 | 无 `paths` | 放行（默认 `{}`） | `paths=None` → 非 dict → `INCOMPLETE` | `FAILED`（经完整性判定，非结构校验） | **不合法**（根级 `required` 含 `paths`） | `[U]` |
| **⑦** `paths` 非 dict | `"paths": []` 等 | 直接 `FAILED`（`'paths' is not an object`） | 不再执行 | `FAILED` | 不合法 | `[U]` |
| **⑧** `paths.skipped` 非 list | `None` / dict / 字符串 | 直接 `FAILED`（`'paths.skipped' is not a list`） | 不再执行 | `FAILED` | 不合法（schema 要求 array） | `[U]` |
| **⑨** `paths.scanned` 缺失 | `{"paths": {"skipped": []}}` | 通过（**不检查 scanned**） | 不检查 scanned → `COMPLETE` | `COMPLETED` / `COMPLETE` | **不合法**（`scanned` 是 `scanned_and_skipped.required`） | `[U]` |

**关键观察** `[E]`+`[I]`：
- 情形 ① 与 ② 是**策略冲突核心**：官方允许省略 `skipped`，当前实现判 `FAILED`。
- 情形 ③ 的 `_skip_explained()` 接受 `type/message/code`，**宽于** schema 的 `reason` 要求 → 若真机出现「有 `type` 无 `reason`」的异形条目，会被判「已解释 → PARTIAL」，而该输出本身不符合 schema（过宽风险，W1-06）。
- 情形 ⑥⑦⑧ 的失败**来源不同**（结构校验 vs 完整性判定），但 `meta` 未区分，可能影响问题定位。
- 情形 ⑨ 是本轮新发现的关联缺口（详见 §4.4）。

### 4.3 与官方 schema 对照 `[R]` + `[E]`

| 官方 schema 声明（Phase A §7.3 逐字） | 当前实现 `[E]` | 一致性 |
|---|---|---|
| 根级 `required` 含 `errors` | `:164-169` 缺 `errors` → `INCOMPLETE` | ✅ 一致（保守有依据） |
| 根级 `required` 含 `paths` | `:171-174` `paths` 非 dict → `INCOMPLETE` | ✅ 一致 |
| `scanned_and_skipped.required` 仅 `[scanned]`，`skipped` **可选** | `:176-179` 缺 `skipped` → `INCOMPLETE` | 🔴 **契约冲突** |
| `skipped_target.required = [path, reason]`，`reason` 为字符串常量 | `:145-154` 接受 `reason/type/message/code` | ⚠️ **过宽**（相容但宽于 schema） |
| `scanned` 是 `scanned_and_skipped.required` | **未检查** | 🔴 **缺口**（W1-04） |
| `errors` 是 array | `:364-368` 要求 list、非空即 `INCOMPLETE` | ✅ 一致（元素结构未核对，U11） |

### 4.4 关联发现：`paths.scanned` 未检查 `[E]`

官方 schema 中 `scanned` 是 `scanned_and_skipped` 的**必填**字段（Phase A §7.3 逐字 `[R]`）。当前实现：

- 结构校验（`:369-378`）只检查 `paths` 是 dict、`paths.skipped` 是 list；
- `_completeness()`（`:157-193`）只检查 `paths` 是 dict、`paths.skipped` 键存在及其内容；
- **没有任何位置检查 `paths.scanned` 是否存在或是否为 list**。

因此 `{"paths": {"skipped": []}}`（缺 `scanned`）会被判 `COMPLETE`，而该报告不符合官方 schema `[E]`+`[R]`。

**范围说明** `[I]`：本项属「paths 结构判定」的关联缺口，不在用户列出的两个问题字面范围内，但处于同一判定链，故作为**关联发现**登记，建议与 W1-03 一并裁定；**本轮不扩大修复范围**。

### 4.5 三类结论区分（问题二）

| 类别 | 结论 |
|---|---|
| **源码已证实** `[E]` | 缺 `skipped` → `INCOMPLETE`/`FAILED`（策略与 schema 冲突）；空 `skipped` → `COMPLETE`；explained → `PARTIAL`；unexplained → `INCOMPLETE`；`paths` 缺失/非 dict、`skipped` 非 list → `FAILED`；`scanned` 完全未检查；`_skip_explained` 宽于 schema。 |
| **依赖真实 Semgrep 输出** `[U]` | 1.182.1 在**无跳过文件**时是否省略 `paths.skipped` 键（U9）；真机 `skipped_target` 的键名集合（是否恒含 `reason`）；真机 `paths.scanned` 是否恒存在。 |
| **尚未确认** `[U]` | 若真机恒含 `skipped=[]`，则情形 ① 永不发生，策略可保留但需真机证据；若真机可能省略，则正常扫描会被误判 `FAILED`。 |

---

## 5. 问题清单与等级

| 编号 | 问题 | 等级 | 类型 | 证据 |
|---|---|---|---|---|
| **W1-01** | `_SEVERITY_MAP` 仅覆盖 3/9 官方值，官方当前推荐的 `CRITICAL/HIGH/MEDIUM/LOW` 全部未映射；命中即丢 finding，整体仍 `COMPLETED`/`ok=True` | **BLOCKER** | 确定性实现缺陷（无需真机） | §3.1 / §3.2 / §3.3 `[E]` |
| **W1-02** | 丢记录可观测性缺口：`AdapterResult.detail` 不含 `records_skipped`，冻结 `report.py` 步骤表不可见；测试 N 段把「跳过且 `COMPLETED`」固化为期望，且未覆盖官方推荐值 | **BLOCKER** | 确定性实现缺陷 + 测试固化 | §3.3 `[E]` |
| **W1-03** | `paths.skipped` 键缺失被判 `INCOMPLETE`/`FAILED`，与官方 schema「`skipped` 非必填」冲突；合法报告可能被误判失败 | **HIGH** | 条件性策略冲突（须等 U9） | §4.2 情形① / §4.3 `[E]`+`[R]` |
| **W1-04** | `paths.scanned`（官方必填）完全未检查，缺 `scanned` 仍可判 `COMPLETE` | **HIGH** | 确定性实现缺口（关联发现） | §4.4 `[E]`+`[R]` |
| **W1-05** | `name` 字段硬编码映射说明 `ERROR→high / WARNING→medium / INFO→info`（`:424-429`）；扩展映射后不会自动更新，报告标注将失真 | **LOW** | 可维护性/证据准确性 | §3.3 `[E]` |
| **W1-06** | `_skip_explained()` 接受 `type/message/code`，宽于 schema 的 `reason` 要求；异形条目可能被误判「已解释 → PARTIAL」 | **LOW** | 契约相容性（过宽） | §4.2 情形③ `[E]`+`[R]` |

---

## 6. 影响评估：Findings / Journal / Report / 冻结接口

| 层 | 当前行为 | 修复后预期变化 | 是否需改冻结文件 |
|---|---|---|---|
| **Findings** | severity 未映射 → 记录被丢弃，`findings=[]` 但 `COMPLETED` | 映射扩展 → 官方推荐值可采收；`records_skipped>0` 时至少 `PARTIAL` 或 `detail` 可见 | **否**（`findings.py` 不动） |
| **Journal** | `attempt_end.meta` 已含 `records_skipped` / `completeness` / `paths_skipped` | 字段已存在，值语义更完整；**无需新增字段** | **否**（`journal.py` 不动） |
| **Report** | 步骤表渲染 `detail`；发现列表渲染 `name`/`severity` | `detail` 追加 skipped 计数；`name` 映射说明动态化 | **否**（`report.py` 不动） |
| **冻结核心接口** | `adapters.py` / `runner.py` / `report.py` / `findings.py` / 两个冻结测试 | **全部不变** | **否** |
| **状态枚举** | `runner.STATUS_PRIORITY` 无 `PARTIAL`，`_summary_bucket()` 未识别 → `FAILED` | 继续用 `meta.completeness` + `detail` 前缀兼容；**不新增 `AdapterResult.status`** | **否** |
| **其他 Adapter** | gitleaks / nuclei / bandit / http-probe | **不受影响**（改动仅限 `adapters_ext/semgrep.py`） | **否** |
| **执行门禁** | `ToolAdapter.execute()` 的 RunTicket + live PolicyEngine + 窗口/风险/依赖门禁 | **不变** | **否** |

**结论** `[I]`：两项问题的修复可完全限制在 `vuln_hunter/adapters_ext/semgrep.py` 与两个 EXT-2 测试文件内，**不需要触碰任何冻结文件**，也不会改变执行门禁与状态枚举。

---

## 7. 最小修复建议（不在本轮实施）

> 以下建议**仅供后续 Remediation 输入**，本轮**未修改任何代码** `[E]`。每项给出最小改动与可选方案。

### F1 — 扩展 `_SEVERITY_MAP`（对应 W1-01）

最小改动（纯向后兼容增强，统一 schema 五个目标值均有合法落点）：

```python
_SEVERITY_MAP = {
    # 旧值（保留，向后兼容）
    "error": "high",
    "warning": "medium",
    "info": "info",
    # 官方当前推荐值
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    # 遗留值：须显式裁定（二选一）
    "experiment": "info",   # 方案 A：显式映射为 info，并在 name 说明标注为系统映射
    "inventory": "info",    # 方案 A
    # 方案 B：不加入映射，保留跳过，但必须配合 F2 使其可见
}
```

**注意** `[I]`：
- `INFO` 官方对应 `LOW`，当前映射为 `info`；是否对齐 `low` 属条件性差异，须等 U10 真机闭合后再定，**不在 F1 最小范围内**。
- `EXPERIMENT` / `INVENTORY` 的处置必须**显式裁定并写入结论**，不得继续静默跳过。

### F2 — 丢记录可见性 / 完整性（对应 W1-02）

三选一或组合，推荐 **A+B**：

- **方案 A（最小）**：`records_skipped > 0` 时，在 `AdapterResult.detail` 追加 `, N record(s) skipped (unsupported severity/shape)`，使其进入冻结 `report.py` 步骤表。
- **方案 B（更稳）**：`records_skipped > 0` 且当前 `completeness == "COMPLETE"` 时，把 `level` 降为 `PARTIAL`，`detail` 前缀相应变为 `[completeness=PARTIAL]`，并在 `reasons` 中登记「N 条记录因 severity/结构不被支持而跳过」。
- **方案 C（最严）**：对**完全无法解析**（`records_used == 0 and records_seen > 0`）的报告改判 `FAILED`。可能过度严格，不建议作为默认。

### F3 — `paths.skipped` 策略（对应 W1-03）

**不在 W1 改码**。条件性建议：

1. 先由 W6' 真机基线采集闭合 U9（1.182.1 无跳过文件时是否省略 `skipped`）。
2. 若真机**恒含** `skipped`（即使为空）：**保留现状**，只需在证据中登记「schema 允许省略但本版本未省略」。
3. 若真机**可能省略**：推荐折中 —— 缺 `skipped` 但 `scanned` 存在且 `errors` 为空时，判 **`PARTIAL`**（显式标注「skipped 覆盖未验证」），而非 `COMPLETE` 或 `FAILED`；并在 `meta` / `detail` 记录。
4. 同时建议记录失败来源（结构校验 vs 完整性判定），便于定位。

### F4 — `paths.scanned` 检查（对应 W1-04）

- 最小改动：在 `_completeness()` 增加 `scanned` 存在性（及 list 类型）检查；缺失或类型错误 → `INCOMPLETE`。
- 或作为**已知缺口**登记，留待下一轮裁定（本轮不扩大范围）。

### F5 — `name` 映射说明动态化（对应 W1-05）

把 `:424-429` 的硬编码字符串改为基于实际映射生成，例如：

```python
d["name"] = (f"{f.title} "
             f"[severity={f.severity} 由 Semgrep 报告的 severity 字段经 "
             f"{_mapping_phrase()} 映射得到；非 DualVerify-Sentinel 自行判定]")
```

避免扩展映射后报告标注失真。

### F6 — `_skip_explained` 收窄（对应 W1-06）

- 最小改动：把 `_SKIP_REASON_KEYS` 收窄为 `("reason",)`，与 schema 对齐。
- 或保留宽判定，但在文档/证据中登记「接受 `type/message/code` 属有意宽容」，避免误读为 schema 要求。

---

## 8. 回归测试清单

> 本轮**未执行任何测试** `[E]`。以下为 Remediation 后必须覆盖的清单。

### 8.1 必须新增/更新的用例（`tests/test_semgrep_adapter.py`）

| 用例 | 内容 | 对应问题 |
|---|---|---|
| N 段扩展 | 官方 9 值逐值映射断言（含 `CRITICAL/HIGH/MEDIUM/LOW`）；大小写不敏感；`EXPERIMENT`/`INVENTORY` 按裁定结果断言 | W1-01 |
| N-bad 重写 | 未知/非字符串/缺失 severity → 明确断言 `records_skipped>0` 且 `detail` 可见（或 `completeness=PARTIAL`），**不再断言「COMPLETED 即可」** | W1-02 |
| 新增 | `records_skipped>0` 时 `detail` 含 skipped 计数（或 `PARTIAL`） | W1-02 |
| Q-03 更新 | 缺 `paths.skipped` 的期望依据 U9 裁定结果调整（若放宽则断言 `PARTIAL` 而非 `FAILED`） | W1-03 |
| 新增 | 缺 `paths.scanned` → `INCOMPLETE`（若采纳 F4） | W1-04 |
| 新增 | `name` 映射说明与 `_SEVERITY_MAP` 一致（动态生成） | W1-05 |
| 新增 | `_skip_explained` 边界：有 `type` 无 `reason` 的条目行为（依 F6 裁定） | W1-06 |

### 8.2 集成测试（`tests/test_semgrep_integration.py`）

- G 段扩展：官方推荐 severity 值经真实 Executor → Journal → Report 链路；
- 验证 `records_skipped>0` 信号能到达冻结 `render_report` 步骤表（若采纳 F2）；
- 验证 `paths.scanned` 缺失场景（若采纳 F4）；
- 保留现有 G-01..G-08 全部断言。

### 8.3 回归范围

- `tests/test_semgrep_adapter.py`（mock 单测）；
- `tests/test_semgrep_integration.py`（真实门禁/执行链 + mock 工具）；
- 相关离线回归（冻结五文件中的 `test_d2d1_proccleanup.py` / `test_d2d0_d2d4.py` 及既有 17 项）；
- 冻结五文件哈希复核；
- `EXT-2` 两套件与冻结回归**不得**因本次修改而改变历史结论。

---

## 9. UNKNOWN 与风险边界

### 9.1 UNKNOWN 清单

| 编号 | 未知项 | 影响 | 闭合方式 |
|---|---|---|---|
| U9 | 1.182.1 在无跳过文件时是否省略 `paths.skipped` 键 | 决定 W1-03 是否需改码 | W6' 真机基线采集（RV-01） |
| U10 | 1.182.1 + 自写规则下真实 `extra.severity` 取值集合 | 决定 W1-01 实际影响面 | W6' 真机基线采集（RV-02） |
| U11 | `errors[]` 元素结构（schema 页面截断） | 完整性判定对 errors 元素结构的容忍度 | 真机 / schema 补全 |
| U12 | `EXPERIMENT` / `INVENTORY` 在 1.182.1 是否真实出现 | 决定 F1 处置方案 | W6' 真机基线采集 |
| U13 | 真机 `paths.scanned` 是否恒存在 | 决定 W1-04 优先级 | W6' 真机基线采集 |
| U14 | `%TEMP%\tmp.AvXfUFcabf\` 消失原因 | 副产物完整性 | 无法从只读证据判定（`[U]`） |
| U15 | 官方 schema 未 pin 到 1.182.1（位于 `main` 分支） | L0 证据与版本的时间差 | 真机基线采集时比对 |

### 9.2 风险边界

1. **不得仅凭 L0 改码** `[I]`：W1-03 的策略调整必须等 U9；本轮只登记冲突。
2. **L3 ≠ 真机** `[I]`：所有测试基于 `_spawn` mock，不能证明真实 Semgrep 兼容性；`CR-06` 仍是未闭合 BLOCKER（验收证据层）。
3. **不改冻结文件** `[E]`：修复范围严格限制在 `adapters_ext/semgrep.py` 与两个 EXT-2 测试。
4. **状态枚举不扩展** `[I]`：继续使用 `meta.completeness` + `detail` 前缀兼容方案，不引入 `AdapterResult.status="PARTIAL"`。
5. **不改变历史状态** `[E]`：`CR-06` / `EXT-2` / G15 FAIL / `EXECUTION_INTEGRITY=NOT_OK` / C14 FAIL / 历史 `UNKNOWN` / 六项测试阶段状态一律原样。

---

## 10. 是否建议进入 Remediation

**建议进入 Remediation，但分两批** `[I]`：

| 批次 | 内容 | 前置条件 | 可立即进行 |
|---|---|---|---|
| **批次 1（确定性）** | W1-01（映射扩展）+ W1-02（可见性/完整性）+ W1-05（name 动态化）+ W1-06（可选收窄） | 无（源码层已裁定） | ✅ 是 |
| **批次 2（条件性）** | W1-03（`paths.skipped` 策略）+ W1-04（`scanned` 检查） | U9 真机基线闭合 | ❌ 否，须等 W6' |

**理由** `[I]`：
- 批次 1 是**确定性实现缺陷**，无需真机即可裁定，且修复范围小、风险低；
- 批次 2 涉及**策略冲突**，放宽可能引入「假完整」风险，收紧可能误判合法报告，必须由真机证据支撑；
- 两批均**不需要**修改冻结文件或改变状态枚举。

**Remediation 前须再次确认** `[I]`：具体修复方案（F1 的 `EXPERIMENT`/`INVENTORY` 处置、F2 的方案选择、F3 的策略选择、F4 是否纳入）需用户单独授权。

---

## 11. 收尾核验

> 本节记录分析完成后（2026-11-11）的只读复核结果 `[E]`。

| 核验项 | 分析前基线 | 完成后复核 | 结论 |
|---|---|---|---|
| 冻结五文件哈希 | 见 §1.2 | 与 §1.2 逐项一致（`adapters.py` / `runner.py` / `report.py` / `test_d2d1_proccleanup.py` / `test_d2d0_d2d4.py`） | 不变 |
| `vuln_hunter/adapters_ext/semgrep.py` SHA256 | `434dfcfa90c85ad465c9cd102e966d87d4faf2f149d7c2d1733fe368b696ee9e` | `434dfcfa90c85ad465c9cd102e966d87d4faf2f149d7c2d1733fe368b696ee9e` | 不变 |
| `tests/test_semgrep_adapter.py` SHA256 | `403c683af51ec5bf4e00a3a8dfc01a399ca387a301560858c814ae58df6cdf67` | `403c683af51ec5bf4e00a3a8dfc01a399ca387a301560858c814ae58df6cdf67` | 不变 |
| `tests/test_semgrep_integration.py` SHA256 | `1c084bd8f9727caed8e65c6f5421b1c89fe6f5d10adc7c9612f4834b0383ab52` | `1c084bd8f9727caed8e65c6f5421b1c89fe6f5d10adc7c9612f4834b0383ab52` | 不变 |
| 基准文档（Gap Analysis / Phase A）SHA256 | 见 §1.2 | 与 §1.2 逐项一致（`5c852500…b1af487` / `3d40300b…731185`） | 不变 |
| HEAD | `9913c50` | `9913c50` | 未变 |
| `git diff --stat` | 5 files / 83 insertions / 4 deletions | `5 files changed, 83 insertions(+), 4 deletions(-)` | 一致 |
| `git status --short` | 5 个 `M` + 21 个 `??` | 5 个 `M` + 22 个 `??`；新增项仅 `?? docs/EXT-2-W1-SEVERITY-SKIPPED-CODE-REVIEW.md` | 仅新增本报告 1 项 `??` |
| `output/vuln_hunter_report.md` | 存在（2,724 B，11-08 22:14） | 存在（2,724 B，11-08 22:14） | 保留 |
| `%TEMP%\tmp.AvXfUFcabf\` | W1 开始时已不存在 | 不存在 | `[U]`（非本轮操作） |

**工具与环境状态** `[E]`：`semgrep: not on PATH`；`pip show semgrep` → `WARNING: Package(s) not found: semgrep`。即本轮**未产生任何 Semgrep 安装、下载或运行痕迹**；`git diff` 的 `LF will be replaced by CRLF` 仅为工具 warning，未执行 Git 写操作、未改换行符。

> **自引用说明** `[I]`：本报告自身的行数 / 字节数 / SHA256 在**最终答复**中给出，不写入正文，避免写入自身哈希导致校验值失效。

---

## 12. 完成后停止

本报告为 `EXT-2 下一阶段：W1 独立 Code Review` 的**唯一交付物**。本轮到此停止，**不自动进入 Remediation**，不修改任何源码/测试/配置/基准文档/现有证据，不下载或运行 Semgrep，不执行扫描或测试，不改变任何验收状态。

在获得明确授权前：不实施 F1–F6 中的任何修复、不更新测试、不调整 `paths.skipped` 策略、不修改冻结文件、不改变 `CR-06` / `EXT-2` / G15 / C14 / 六项测试阶段状态。

*报告结束。*
