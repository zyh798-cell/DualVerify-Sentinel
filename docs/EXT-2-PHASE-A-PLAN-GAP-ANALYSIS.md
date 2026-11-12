# DualVerify-Sentinel V1 — EXT-2 Phase A 后续：Real Verification Plan 差异分析

- **任务**：`EXT-2 Phase A 后续：Real Verification Plan 差异分析`（**只读分析，不实施**）
- **生成时间**：2026-11-09（本地时间，GMT+8）
- **仓库**：`C:/Users/ZTL/Desktop/DualVerify-Sentinel`，分支 `main`，HEAD `9913c50`（分析期间未变）
- **基准文档**：`docs/EXT-2-REAL-VERIFICATION-PLAN.md`（下称「原计划」，690 行）、`docs/EXT-2-PHASE-A-VERIFICATION-REPORT.md`（下称「Phase A 报告」，629 行）
- **唯一新建文件**：`docs/EXT-2-PHASE-A-PLAN-GAP-ANALYSIS.md`（本分析文档）
- **阶段性质**：纯只读。未联网、未下载、未安装、未运行 Semgrep、未执行扫描/测试、未创建 venv / 规则 / fixture / 脚本、未修改任何源码/测试/配置/基准文档/现有证据、未修改 PATH / 注册表 / 系统环境变量、未删除/移动/覆盖任何文件、未执行任何 Git 写操作、未改变任何验收状态。

> **标注体系（本轮严格采用用户指定的四态）**
>
> - `[E]` **当前源码/文档直接观测** —— 本轮只读读取到的实际内容：`semgrep.py` 当前实现、两份基准文档原文、本机只读命令输出。
> - `[R]` **官方资料证据** —— **本轮未重新联网**；全部转引自 Phase A 报告 §10 登记的 S1–S8 官方来源逐字证据（PyPI JSON API / PyPI 项目页 / GitHub release / CLI reference / getting-started CLI / semgrep-interfaces JSON schema / rule-syntax / metrics）。引用时同时给出 Phase A 章节号。
> - `[I]` **合理推论** —— 基于 `[E]`+`[R]` 的分析判断，**明确标注，不作为事实**，凡涉及真实工具行为者一律附加 `[U]` 约束。
> - `[U]` **尚未确认** —— 严格按「不得推断」登记，不因 Schema 声明或文档表述而提前闭合。
>
> **重要边界**：官方 JSON schema 位于 `semgrep/semgrep-interfaces` 的 **`main` 分支、未 pin 到 1.182.1**（Phase A §7.1 / U4 `[R]`）。本分析**不把 Schema 声明等同于 1.182.1 的实际输出**；凡涉及「真机会生成什么 JSON」的结论一律标 `[U]` 并列入 §10。

### 输出要求 ↔ 章节对照

| 用户要求 | 本文档章节 |
|---|---|
| 1. 本轮范围与禁止事项 | §1 |
| 2. Phase A 关键证据摘要 | §2 |
| 3. RV-01 至 RV-07 逐项差异表 | §4 |
| 4. `paths.skipped` 判定分析 | §5 |
| 5. Severity 九值映射矩阵 | §6 |
| 6. CR-06 前置依赖与推荐执行顺序 | §7 |
| 7. 风险清单 | §8 |
| 8. 建议修订内容 | §9 |
| 9. 尚未解决的 UNKNOWN | §10 |
| 10. 下一阶段需要用户批准的事项 | §11 |
| 重点事项 5「验证证据分层」 | §3（独立章节） |
| 五、收尾核验 | §12 |

---

## 1. 本轮范围与禁止事项

### 1.1 本轮实际读取的文件（仅 3 个）

| # | 文件 | 用途 | 是否属于任务明确范围 |
|---|---|---|---|
| 1 | `docs/EXT-2-REAL-VERIFICATION-PLAN.md` | 基准文档 1，逐项提取 RV 场景、预期、章节号 | ✅ 用户指定 |
| 2 | `docs/EXT-2-PHASE-A-VERIFICATION-REPORT.md` | 基准文档 2，逐项提取官方证据、UNKNOWN | ✅ 用户指定 |
| 3 | `vuln_hunter/adapters_ext/semgrep.py` | 任务二要求「对照当前 `semgrep.py` 的实际实现」、任务三要求「与当前 `_SEVERITY_MAP`、`_to_finding()` 的实际处理逻辑进行对照」 | ✅ 任务内明确要求 |

`[E]` **未读取任何其它源码 / 测试 / 配置文件**。关于 `runner.py` / `report.py` / `planner.py` / `adapters.py` 的结论，全部**转引自两份基准文档中已登记的 `[E]` 内容**（原计划 §3.2、§6.1、§8.2；Phase A §9.4），**未重新打开这些文件**。`[E]`

> **停止条件响应** `[E]`：本轮分析未发现必须读取授权范围外文件的情况，**未触发「先停止并报告」条件**，未自行扩大读取范围。

### 1.2 禁止事项逐项核验 `[E]`

| 禁止项 | 状态 |
|---|---|
| 不修改原计划或 Phase A 报告 | ✅ 哈希见 §12，均未变 |
| 不修改任何源码 / 测试 / 配置 / 规则 / fixture | ✅ 零修改 |
| 不下载 / 不安装 / 不运行 Semgrep | ✅ 零执行（本轮**未发起任何网络请求**） |
| 不创建 venv 或验证环境 | ✅ 零创建 |
| 不执行扫描或测试 | ✅ 零执行 |
| 不修改 PATH / 注册表 / 系统环境变量 | ✅ 仅运行只读 `sha256sum` / `git status` / `git rev-parse` / `git diff` / `ls` / `date` / `grep` |
| 不删除 / 移动 / 覆盖任何文件 | ✅ 零操作；唯一新建为本分析文档 |
| 不执行 Git commit / reset / checkout / restore / stash 或其它写操作 | ✅ 仅只读 `status` / `diff` / `rev-parse` |
| 不改变 `CR-06` / `EXT-2` / 六项测试阶段验收状态 | ✅ 原样保留 |
| 不改变 G15 FAIL / `EXECUTION_INTEGRITY=NOT_OK` / C14 FAIL / 任何 UNKNOWN | ✅ 原样保留 |
| 不自动进入下一阶段 | ✅ 完成后停止，§11 仅列待批准事项 |

### 1.3 本分析不做的事 `[E]`

- 不修改 `_SEVERITY_MAP`、`_completeness()`、`_skip_explained()` 或任何其它代码；§6 的映射策略与 §5 的建议行为**仅为 Code Review / Remediation 的输入**。
- 不改写原计划的任何章节；§9 给出的是**修订建议**。
- 不裁定 Phase A 登记的 UNKNOWN；§10 仅汇总与新识别。
- 不把 Schema 声明、官方文档或 Tier B 注入结果表述为「1.182.1 的真实行为」或「网络层完全离线证明」（见 §3）。

---

## 2. Phase A 关键证据摘要

> 以下 `[R]` 全部转引自 Phase A 报告的逐字证据，**本轮未重新联网核验** `[E]`。

| # | 证据 | Phase A 章节 | 对原计划的直接影响 |
|---|---|---|---|
| **A1** | `semgrep 1.182.1`：Released 2026-10-22、`LGPL-2.1-or-later`、`Requires Python >=3.10`、classifiers 含 `Microsoft :: Windows` + Python 3.13/3.14；PyPI 页显示已有更新版 `1.184.0` | §3.1 / §3.2 `[R]` | 原计划 §2.1「第三方检索结果、需人工复核」→ 已由官方源闭合；pin 属刻意固定基线 |
| **A2** | 官方 JSON API 给出 8 个分发文件 `digests.sha256`；`win_amd64` wheel = `e464d398…b68c`；tag 含 `cp313`/`py313`/`win_amd64` | §4 / §5.1 `[R]` | 原计划 §2.4 A2「Windows wheel 是否存在」**分发层已闭合**；运行层仍 U2 |
| **A3** | 官方 getting-started 逐字：「`scan`/`ci` 完成即 `0`，无论有无 findings；`1` 需 `--error`」 | §6.4 `[R]` | 支撑 `CR-01` 的 `rc==0` 收窄；`RV-01`/`RV-02` 的 rc 预期有官方依据，但**仍需真机实测** |
| **A4** | 官方 CLI reference「Exit codes」段 vs 内嵌 `--help` 的 `EXIT STATUS` 段**内部不一致**（rc=1 条件、rc=7 语义、`14` vs `99`） | §6.1–§6.3 / U7 `[R]`+`[U]` | `RV-05` 的 rc 对照表需扩充差异列，真机前不得裁定 |
| **A5** | 官方 JSON schema 根级 `required = [results, errors, paths]`；`version` 非必填 | §7.2 `[R]` | 原计划 §6.4 对 `errors`/`paths` 的保守要求**成立且有官方依据** |
| **A6** | `scanned_and_skipped.required = [scanned]`，**`paths.skipped` 非必填** | §7.3 / §7.4 `[R]` | 🔴 **与 `CR-02`「缺 `skipped` 即 FAILED」冲突**；`RV-01` 的 `COMPLETED/COMPLETE` 不再是唯一合法预期 |
| **A7** | `skipped_target` 是 dict、`required=[path, reason]`；`skip_reason` 为 17 个字符串常量 | §7.3 / §7.4 `[R]` | 与 `_skip_explained()` 相容；原计划 §6.4「裸字符串 = 最可能的适配触发点」应**降级** |
| **A8** | 官方规则 `severity` 当前推荐 `LOW/MEDIUM/HIGH/CRITICAL`，旧 `ERROR/WARNING/INFO` 向后兼容并 match `HIGH/MEDIUM/LOW` | §8.1 `[R]` | 🔴 原计划 §4.2 的 fixture 规则**全部使用旧值**，其真实输出可能被规范化为新值 |
| **A9** | 官方 schema `match_severity` 允许 **9 值**：`ERROR WARNING EXPERIMENT INVENTORY CRITICAL HIGH MEDIUM LOW INFO`；自 1.72.0 起新值替换旧值 | §8.2 `[R]` | 🔴 `_SEVERITY_MAP` 仅 3 值；6 值会被静默跳过 |
| **A10** | CLI `--severity` 过滤 flag 仅 `INFO/WARNING/ERROR` | §6.5 `[R]` | **过滤值域 ≠ 输出值域**，原计划 §6.2 需明确区分 |
| **A11** | 官方 metrics：本地 `--config` 不发 metrics；`--metrics off` 永不发送；源码/私有规则永不上传 | §9.1 `[R]` | **配置层证据**，不能替代原计划 §7 的网络层观测 |
| **A12** | `--enable-version-check`「Checks Semgrep servers」，是独立于 metrics 的出站路径；`false` 取值语义未说明 | §6.5 / §9.2 / U8 `[R]`+`[U]` | 网络观测窗口需覆盖「结果返回之后」 |
| **A13** | `SEMGREP_RULES` / `SEMGREP_SEND_METRICS` / `SEMGREP_BASELINE_COMMIT` / `SEMGREP_FORCE_COLOR` 未被 `tool_env()` 清理 | §9.4 `[R]`+`[E]` | 原计划 §7.2 L1 的 env 快照核对项需扩充 |
| **A14** | 首次运行会写 `~/.semgrep/settings.yml`（anonymous user ID） | §9.3 `[R]` | 原计划 §9 隔离/清理边界需登记该**本地写入副作用** |
| **A15** | 官方 `--timeout` 是**每文件每规则**（默认 5s，`--timeout-threshold` 默认 3） | §6.5 `[R]` | 原计划 §5.2 `RV-07` 的触发方式描述存在**术语混淆** |
| **A16** | `--json-output` / `--output` / `--*-output` 可「post to URL」 | §6.5 `[R]` | 潜在出站路径；EXT-2 命令不含这些 flag，配置层核对项需显式确认 |
| **A17** | `results[]`（`cli_match`）/ `errors[]`（`cli_error`）定义因 schema 页面 `[content truncated]` 未读到 | §7.5 / U5 / U11 `[U]` | 原计划 §6.1 字段核对表的「真实报告实际」列仍为 `[U]` |
| **A18** | Phase A 登记 U1–U14，其中 U2/U4/U9/U10 直接影响 RV 预期 | §11 `[U]` | 见 §10 |

---

## 3. 验证证据分层（重点事项 5）

> 本节为**证据纪律**，后续所有 RV 场景、修订建议与验收判据均受其约束 `[E]`。

| 层 | 定义 | 能证明什么 | **禁止的表述** | 对应原计划 / Phase A |
|---|---|---|---|---|
| **L0 官方文档与 Schema** `[R]` | Phase A S1–S8 逐字证据；schema 来自 `main` 分支、**未 pin 版本** | 官方**声明**的发布信息、允许值域、字段可选性、CLI 语义 | ❌ 不得表述为「1.182.1 实际输出如此」；❌ 不得表述为「网络层已证明离线」 | Phase A §3–§9；原计划 §2、§6 |
| **L1 Semgrep 真实运行输出** `[E]`（待 Phase B 产生） | 真实二进制 + 本地规则 + fixture 的原始 `stdout` / `rc` / `stderr`，保存于隔离证据目录 | 该版本、该配置、该输入下的**真实工具行为** | ❌ 不得与 L3 注入结果混同；❌ 不得把单次运行外推到所有配置/版本 | 原计划 §5.1 Tier A、§9.2 |
| **L2 Adapter 实际解析结果** `[E]`（待 Phase B 产生） | `AdapterResult.status` / `ok` / `detail` / `meta` / `findings`、`journal.attempt_end`、渲染报告 | **实现**如何处理给定输入 | ❌ 不得表述为「工具行为」；❌ 不得因 `COMPLETED` 反推「扫描完整且无遗漏」 | 原计划 §8.2；`semgrep.py:309-445` `[E]` |
| **L3 人工注入的故障测试** `[I]`（待 Phase B 产生） | Tier B 转发包装器替换 stdout/rc；或既有测试 mock `_spawn` | **故障处理路径**在假定输入下的正确性 | ❌ **不得描述为真实 Semgrep 兼容性证据**；❌ 不得用于闭合 U9/U10/U4 | 原计划 §5.1 Tier B、§5.2 RV-06、§1.1（全部既有测试） |
| **L4 网络出站观测证据** `[E]`（待 Phase B 产生） | L1 配置层静态核对 + L2 进程/连接采样 + L3 阻断层验证 | **本次运行、本观测窗口、本主机、本配置**下未观测到非 loopback 出站 | ❌ **不得把配置层禁用 metrics 表述为网络层完全离线证明**；❌ 不得表述为「工具永不联网」 | 原计划 §7.2–§7.4；Phase A §9.2 |

**两条硬边界（用户重点事项 5 明确要求）** `[E]`：

1. **Tier B / mock ≠ 真机**：原计划 §5.1 已有「诚实边界」声明，本分析确认其**完全有效且应保留**；Phase A 未产生任何 L1 证据，因此原计划 §1.1 的 Q1–Q7 **仍全部未闭合**。`[R]`+`[E]`+`[I]`
2. **配置层 ≠ 网络层**：Phase A §9.1 的 `--metrics off` / 本地 `--config` / 「code is never uploaded」全部是 L0 官方声明；Phase A §9.2 已明确「不能替代网络层观测」。原计划 §7.4 的证据边界同样有效。二者**必须分层引用，不得合并成一句「已验证无外网」**。`[R]`+`[E]`

> **本轮自身证据层级** `[E]`：本文档所有 `[R]` 均为 L0，且**本轮未新增任何 L1/L2/L3/L4 证据**；因此本分析**不闭合任何 `CR-06` 判据**。

---

## 4. RV-01 至 RV-07 逐项差异表

### 4.1 主差异表

> 「原计划章节」列精确到小节/行；「Phase A 章节」列给出证据位置；「结论」列四态：保持 / 调整 / 预期被改变 / 待真机。`[E]` 指源码或文档原文，`[R]` 指官方资料转引，`[I]` 指推论，`[U]` 指未确认。

| ID | 原计划章节与原始预期 `[E]` | Phase A 证据 `[R]`+`[U]` | 差异分析 `[I]` | 结论 |
|---|---|---|---|---|
| **RV-01** 正常无发现 | §5.2 L293：`rc=0`、`COMPLETED`/`COMPLETE`、`0` findings；§5.3 L303 自称「最高优先级、`CR-02` 成败点」；§6.4 L411 判定表首行 | §7.2 根级 `required=[results,errors,paths]`（**支持**当前要求）`[R]`；§7.3 `skipped` **非必填**（**冲突**）`[R]`；§11 U9 真机是否省略未知 `[U]`；§6.4「完成即 0」`[R]` | `rc=0` 预期有官方依据；但 `COMPLETED/COMPLETE` **不再是唯一合法预期**。当前 `semgrep.py:176-179` 对缺 `skipped` 键判 `INCOMPLETE→FAILED`，会与「合法 Schema 报告」冲突 `[E]`+`[R]`+`[I]` | **预期被改变**：改为分支预期（见 §4.2）；仍为最高优先级 |
| **RV-02** 正常有发现 | §5.2 L294：`rc=0`、`COMPLETED`/`COMPLETE`、`3`（high/medium/info）findings；§5.3 L305 期望 3 条；§4.2 L216/L226 fixture 规则用 `ERROR`/`WARNING`/`INFO` | §8.1 规则当前推荐 `LOW/MEDIUM/HIGH/CRITICAL`，旧值**向后兼容且 match** `HIGH/MEDIUM/LOW` `[R]`；§8.2 `match_severity` 9 值 `[R]`；§8.3 当前映射仅 3 值、6 值被静默跳过 `[E]`；§11 U10 真机输出未知 `[U]` | 🔴 **本轮最严重推论**：若 1.182.1 把旧值规范化为 `HIGH/MEDIUM/LOW` 输出，则 3 条 finding **可能全部**落入映射外 → `_to_finding()` 抛错 → `records_skipped=3` → 结果仍是 `COMPLETED`/`ok=True` 但 `findings=[]`。这比原计划 §6.2 设想的「个别 `CRITICAL` 丢失」严重得多 `[I]`（**待 U10 真机确认**） | **预期被改变 + fixture 必须调整**：不能预设 3 条全被采收；须逐值核对并新增 RV-11 |
| **RV-03** `paths.skipped` | §5.2 L295：视形态 `PARTIAL` 或 `FAILED`；§5.3 L307「裸字符串 → FAILED 是决定性证据」；§6.4 L415「裸字符串 = 最可能的适配触发点」 | §7.3 `skipped_target` 是 dict、`required=[path,reason]`、17 个 `skip_reason` 常量 `[R]`；§7.4 与 `_skip_explained()` **相容** `[E]`+`[R]`；U4（schema 未 pin）`[U]` | 「裸字符串」在 Schema 层**不符合**输出定义，原计划把它列为首要适配触发点应**降级**为低概率异常路径；真正首要风险是「**键缺失**」（RV-01 / §5）。预期可收窄为：按 Schema 输出 → `PARTIAL`；无 reason → `FAILED` `[I]` | **预期被改变**：首要风险点重定位；新增 RV-12 四形态专门矩阵 |
| **RV-04** `errors` 非空 | §5.2 L296：`0` 或 `2`、`FAILED`/`INCOMPLETE`、零采收；§5.3 L309 核对 `errors[]` 形态；§4.1 L198 用 `fixtures/parse-error` 语法错误文件诱发 | §7.2 `errors` 为根级必填 array `[R]`；§7.5 / U11 `cli_error` 结构未核对 `[U]`；§7.3 `skip_reason` 含 `analysis_failed_parser_or_internal_error` `[R]`；§6.5 `--strict` 才使语法非法成为 rc=3 `[R]` | ⚠️ **触发方式可能不成立**：默认扫描可能把解析失败记入 `paths.skipped`（`analysis_failed_parser_or_internal_error`）而非 `errors[]`；CLI reference 又表明语法错误仅在 `--strict` 下影响退出码。原计划「语法错误文件 → `errors[]`」是**未经验证的假设** `[I]`（**待 U11 / 真机确认**） | **场景仍有效，但触发方式需调整**；建议保留真机尝试 + 预备 Tier B 注入兜底（明确标 L3，不作兼容性证据） |
| **RV-05** 非零退出码 | §5.2 L297：无效 YAML→`5`、未知语言→`8`；`FAILED`/`INCOMPLETE`、零采收；§5.3 L311；§4.2 L231/L236 故障规则 | §6.1/§6.2 两处官方文本对 `5`/`8` 语义一致 `[R]`；§6.3 / U7 `1`/`7`/`14`/`99` 有内部差异 `[U]`；§6.4「完成即 0」支撑 `rc!=0→FAILED` `[R]`；§6.5 官方 `--strict` 语义 `[R]` | `rc=5` 预期（非法 YAML）较稳；`rc=8`（未知语言）需真机确认（官方「invalid language」与「unknown language in rule」未必等价）`[I]`。当前 `semgrep.py:322-329` 的 `rc!=0→FAILED` 方向正确 `[E]`。原计划未覆盖官方差异 rc `[E]` | **场景仍有效，需扩充**：新增 rc 差异观测列、记录「rc × stdout 是否合法 JSON」组合；新增 RV-16 |
| **RV-06** 无效 JSON | §5.2 L298：Tier B 注入截断 JSON、`FAILED`/`INCOMPLETE`、原始输出不落地；§5.1 L287 已有诚实边界；§5.3 L313 | Phase A **未产生改变此场景的证据**（它本就是注入式故障测试）`[E]`；`semgrep.py:342-352` 分支未变 `[E]` | 原计划的「诚实边界」声明**完全有效且应保留**；建议在 Tier B 定义中把措辞进一步明确为「**人工注入的故障测试；真实二进制确实启动，但输出被人为替换；不构成真实工具行为证据**」`[I]` | **保持**（并强化证据分层标注） |
| **RV-07** 超时 | §5.2 L299：L1 `_run(..., timeout=1)`；「或大 fixture + 极小 `--timeout`」；`TIMEOUT`；§5.3 L315 提示 `Executor` 重试 | §6.5 官方 `--timeout` 是**每文件每规则**、默认 5s、`--timeout-threshold` 默认 3 `[R]`；§6.5 `--enable-version-check` 可能「reduce exit time after returning results」`[R]`；`semgrep.py:260-263` `build_command()` **不传** `--timeout` `[E]` | ⚠️ **术语混淆**：EXT-2 只有 `subprocess.run(timeout=...)` 的**进程级**超时（`semgrep.py:456-457` `[E]`）；CLI `--timeout` 是 dynamic-step 的进程级预算（`__main__.py`，转引自原计划 §8.1 `[E]`）；二者**都不是** Semgrep 自己的 `--timeout`。原计划 §5.2 的第二种触发方式表述有误 `[I]`。另：版本检查可能在结果返回之后，超时/网络观测窗口需覆盖进程退出后的短暂区间 `[I]` | **场景仍有效，触发方式描述需修正**；观测窗口需延长 |

### 4.2 RV-01 修订后的分支预期（建议，`[I]`）

| 真机观察（待 U9 确认） | 当前实现结果 `[E]` | 应记录的结论 |
|---|---|---|
| `errors=[]`、`paths.skipped=[]`、字段齐全 | `COMPLETED` / `COMPLETE` / 0 findings | 基线通过 |
| `errors=[]`、**`paths` 无 `skipped` 键**（Schema 合法 `[R]`） | `FAILED` / `INCOMPLETE` / 零采收（`semgrep.py:176-179`） | **实现与官方 Schema 不符 → 记为契约差异，不是「扫描失败」**；触发原计划 §6.5 停止与报告流程 |
| `errors=[]`、`paths.skipped` 含带 reason 条目 | `COMPLETED` / `PARTIAL`（`semgrep.py:182-192`） | 记录 `meta.paths_skipped` 与 `[completeness=PARTIAL]` 是否进入报告 |
| `errors` 或 `paths` 缺键 / 结构异常 | `FAILED` / `INCOMPLETE` | 与 Schema `required` 一致，属正确 fail-closed |

> **不得仅凭 Schema 断言 1.182.1 会省略 `skipped` 键** `[U]`（U9）。上表是**条件分支**，不是对真实输出的预测。`[I]`

### 4.3 建议新增的 RV 场景 `[I]`

| ID | 场景 | 层 | 触发依据 | 目的 |
|---|---|---|---|---|
| **RV-11** | Severity 九值矩阵 | L1（真机，若规则可写 7 值）+ L3（补 2 个特殊值注入） | Phase A §8.1/§8.2 `[R]`、§6 矩阵 | 逐值记录映射命中/跳过、`records_skipped`、整体 `COMPLETED` 假象 |
| **RV-12** | `paths.skipped` 四形态（缺键 / `[]` / 带 reason / 无 reason） | L1（能自然触发者）+ L3（缺键/异形注入） | Phase A §7.3 `[R]`、§5 本分析 | 闭合 U9 后判定 `CR-02` 策略 |
| **RV-13** | `paths` 结构异常（缺失 / 非 dict / `skipped` 非 list） | L3 | `semgrep.py:369-378` `[E]` | 区分「结构校验拦截」与「完整性判定拦截」两条路径 |
| **RV-14** | env 快照 + `SEMGREP_RULES` / `SEMGREP_SEND_METRICS` 清理验证 | L4-L1 配置层 | Phase A §9.4 `[R]`+`[E]` | 确认无隐式 config 覆盖 / metrics 启用 |
| **RV-15** | `~/.semgrep/settings.yml` 写入副作用观测 | L1 环境副作用 | Phase A §9.3 `[R]` | 登记执行期本地写入，纳入隔离/清理边界 |
| **RV-16** | 官方差异 rc（`7` / `14` / `99`）定向观测（若可触发） | L1 + L3 | Phase A §6.3 / U7 `[R]`+`[U]` | 裁定官方内部文本差异 |
| **RV-17** | 网络出站三层观测独立留证 | L4 | 原计划 §7、Phase A §9.2 | 保证「无外网」结论有独立证据，不与配置层证据混同 |

原计划 §5.4 已有的 `RV-08`（空白 stdout）/ `RV-09`（哨兵清扫）/ `RV-10`（非 ASCII 解码）**建议保留** `[E]`；`RV-10` 与 Phase A §6.5 的 flag/env 表无冲突 `[I]`。

### 4.4 必须等待真实 Semgrep 输出才能确定的结论 `[U]`

| # | 结论 | 闭合方式 |
|---|---|---|
| D1 | 1.182.1 无跳过文件时是否省略 `paths.skipped` | RV-01 真机（U9） |
| D2 | 1.182.1 对旧 severity 规则值输出的 `extra.severity` 是新值还是旧值 | RV-02 真机（U10 / U15） |
| D3 | `results[]` / `errors[]` 的实际字段结构 | RV-02 / RV-04 真机（U5 / U11） |
| D4 | 官方退出码差异（1/7/14/99）在 1.182.1 的实际取值 | RV-05 / RV-16 真机（U7） |
| D5 | 语法错误文件能否自然诱发 `errors[]` | RV-04 真机（U11 / U16） |
| D6 | `main` 分支 Schema 是否精确对应 1.182.1 | 全矩阵真机比对（U4） |
| D7 | wheel 内 `semgrep-core` 能否在本机启动并完成扫描 | venv 准备 + 首次真机（U2） |
| D8 | 是否存在实际出站连接（版本检查 / telemetry） | L4 三层观测（U8 / U13） |

> **任何 L0（官方资料）或 L3（注入）证据都不足以替代 D1–D8** `[E]`。这也是 §7 推荐顺序中「基线真机采集」必须早于「按差异做 Remediation」的根本原因 `[I]`。

---

## 5. `paths.skipped` 判定分析

> **醒目声明** `[E]`：本节「官方 Schema 声明」列是 **L0 证据**，「当前实现」列是 **`[E]` 源码事实**；「真机是否生成该形态」一律标 `[U]`。**本分析不推断 1.182.1 在任何扫描场景下实际生成的 JSON**（Phase A U4 / U9 / §7.1）。

### 5.1 当前实现的两层处理链 `[E]`

`semgrep.py` 对完整性信号有**两道独立关卡**，这一点原计划未显式区分：

```python
# 第一关：结构校验（_run, :354-378）—— 使用 .get(默认值)，缺键不拦截
raw_errors = data.get("errors", [])          # :364
paths = data.get("paths", {})                 # :369  ← 缺键时默认为 {}
skipped_paths = paths.get("skipped", [])     # :374  ← 缺键时默认为 []
if not isinstance(skipped_paths, list):      # :375-378 直接 FAILED
    ...

# 第二关：完整性分级（_completeness, :157-193）—— 使用 data.get(无默认值)，缺键拦截
level, reasons, skipped_count = _completeness(data)   # :383
if level == "INCOMPLETE":                            # :384-395
    return AdapterResult("FAILED", False, "[completeness=INCOMPLETE] ...",
                         meta=_meta("INCOMPLETE", reasons, ...))
```

`_completeness()` 关键分支 `[E]`：

```python
if "errors" not in data:                 # :164 → INCOMPLETE
elif data["errors"]:                     # :167 → INCOMPLETE
paths = data.get("paths")                # :171  ← 无默认值
if not isinstance(paths, dict):          # :172 → INCOMPLETE
elif "skipped" not in paths:             # :176 → INCOMPLETE
else:
    skipped = paths["skipped"]
    unexplained = sum(1 for it in skipped if not _skip_explained(it))   # :182
    if skipped:                          # :183  ← 空列表不进入任何分支
        if unexplained:  level = "INCOMPLETE"                            # :184-187
        else:            level = "PARTIAL" (若 level != INCOMPLETE)      # :188-192
```

`_skip_explained()`（`:145-154`）`[E]`：仅当 item 是 `dict` 且 `reason/type/message/code` 之一为**非空字符串**时返回 `True`；`_SKIP_REASON_KEYS`（`:142`）= `("reason","type","message","code")`。

### 5.2 五种情形逐项对照

| 情形 | 官方 Schema 声明 `[R]` | 当前实现实际行为 `[E]` | 潜在误判 `[I]` | 建议行为 `[I]`（**不得直接改代码**） | 真机是否生成该形态 |
|---|---|---|---|---|---|
| **① `paths.skipped` 字段缺失**（`paths` 为 dict，含 `scanned`） | `scanned_and_skipped.required` 仅 `[scanned]`；`skipped` **可选**（Phase A §7.3）→ 该报告**合法** | 结构校验 `:374` 默认 `[]` **放行**；`_completeness()` `:176-179` 判 `INCOMPLETE` → `FAILED`、零采收、`meta.completeness=INCOMPLETE`、`detail` 带 `[completeness=INCOMPLETE]` | 🔴 **合法报告被判失败**；且 `RV-01` 会因此从「正常无发现」变成 `FAILED`，原计划 §5.2 L293 的预期失效 | 优先**先真机确认 U9**；若确认 1.182.1 会省略，建议在 Code Review 裁定了「缺 `skipped` 但 `scanned` 存在 ⇒ 视为无跳过（`COMPLETE`）」后再由 Remediation 实现；若真机恒含 `skipped=[]`，则**无需改动**，只需在报告中登记「Schema 允许省略但本版本未省略」 | **`[U]`**（U9） |
| **② `paths.skipped = []`** | `skipped` 为 `array`，空数组合法（Phase A §7.3） | 结构校验通过；`if skipped:` 为 `False`，`level` 保持 `COMPLETE`（前提 `errors=[]` 且键存在）→ `COMPLETED` / `COMPLETE`、正常采收、`meta.paths_skipped=0`（`semgrep.py:433-445`） | 无（该路径与设计意图一致） | **保持现状**；在 RV-01 证据中显式记录该键存在且为空 | **`[U]`**（U9 相关） |
| **③ 含解释信息的条目**（`{"path":…, "reason":…}`） | `skipped_target.required=[path,reason]`；`reason` ∈ 17 个 `skip_reason` 常量（Phase A §7.3） | `_skip_explained()` 命中 `reason` → `unexplained=0` → `level=PARTIAL`（`:188-192`）→ `COMPLETED` / `PARTIAL`，采收，detail 带 `[completeness=PARTIAL]`，`meta.paths_skipped=N` | ⚠️ **过宽风险**：`_SKIP_REASON_KEYS` 还接受 `type/message/code`，而 Schema 只要求 `reason`。若真机出现「有 `type` 无 `reason`」的异形条目，adapter 会判「已解释→PARTIAL」，而该输出本身不符合 Schema `[I]` | **保持现状**（相容性是主要结论）；在 RV-03 证据中记录真实键名，若出现 `type/message/code` 命中而 `reason` 缺失，单独登记为契约差异 | **`[U]`**（U4 / U18） |
| **④ 缺少解释信息的条目**（裸字符串 / dict 无 reason-like） | **不符合** `skipped_target`（要求 object + `path` + `reason`）（Phase A §7.3） | `_skip_explained()` 返回 `False` → `unexplained>0` → `INCOMPLETE`（`:184-187`）→ `FAILED`、零采收 | 无（fail-closed 与 Schema 方向一致） | **保持现状**，但把该情形定位为 **L3 人工注入的故障测试**，不列为真机预期；原计划 §6.4 L415「最可能的适配触发点」应降级 | **`[U]`**（Schema 层不支持，`[R]`；真机行为 `[U]`） |
| **⑤ `paths` 缺失或结构异常** | `paths` 是**根级必填**且为 object（Phase A §7.2） | **5a 缺键**：结构校验 `:369` 默认 `{}` 放行 → `_completeness()` `:171-174` 得 `None` → `INCOMPLETE` → `FAILED`（**经完整性判定，非结构校验**）。**5b 非 dict**：结构校验 `:370-373` 直接 `FAILED`。**5c `skipped` 非 list**：结构校验 `:375-378` 直接 `FAILED` | 无（严格判定有官方依据）；但 5a/5b/5c 的**失败来源不同**，原计划证据清单未区分，可能影响问题定位 `[I]` | **保持现状**；在证据 `adapter-result.json` 中记录失败来源（结构校验 vs 完整性判定），建议新增 `meta` 区分字段或仅在执行报告文字说明 | **`[U]`**（Schema 层要求必填，`[R]`；真机行为 `[U]`） |

### 5.3 结论 `[I]`

1. 原计划把「`paths.skipped` 裸字符串」当作 `CR-02` 首要适配触发点（§5.3 L307、§6.4 L415）**应重定位** —— Phase A §7.3 表明 Schema 输出是带 `reason` 的 dict，首要风险实际是**① 键缺失**。`[R]`+`[E]`+`[I]`
2. 当前实现对 `errors` / `paths` 的严格判定**有官方 Schema 依据**（根级 `required`），不应放宽。`[R]`+`[E]`
3. **是否放宽「缺 `skipped` 键」策略，必须等 U9 真机闭合**，不得仅凭 Schema 声明决定。`[U]`
4. 结构校验与完整性判定是两道关卡，建议在执行报告中分开记录。`[E]`+`[I]`

---

## 6. Severity 九值映射矩阵

### 6.1 当前处理链 `[E]`

```python
_SEVERITY_MAP = {"error": "high", "warning": "medium", "info": "info"}   # semgrep.py:80-84
SEMGREP_SEVERITY_MAP = dict(_SEVERITY_MAP)                                # :91
# :86-90 注释：「unified Finding schema requires info|low|medium|high|critical」

# _to_finding(), :565-568
sev_raw = _str_field(extra, "severity").lower()      # 净化 + 小写
sev = _SEVERITY_MAP.get(sev_raw)
if sev is None:
    raise FindingError("semgrep record: unsupported or missing severity")

# _run() 采收循环, :399-406
except FindingError as exc:
    skipped += 1
    log.write(f"record {i} skipped: {exc}\n")
    continue

# :438-445
return AdapterResult("COMPLETED", True, detail, findings,
                     meta=_meta(level, reasons, records_seen=..., records_used=len(findings),
                                records_skipped=skipped, ...))
```

**关键事实** `[E]`：映射外值抛错后仅被 `continue`，**不改变 `status` / `ok`**；即使 `raw_results` 全部被跳过，仍返回 `AdapterResult("COMPLETED", True, ...)`，只是 `findings=[]` 且 `meta.records_skipped=N`。

### 6.2 九值矩阵 `[R]`（官方 schema `match_severity`，Phase A §8.2）+ `[E]`（当前实现）

| # | 官方 `match_severity` 值 | 规则 YAML 可写性 `[R]`（Phase A §8.1） | `.lower()` 后 | `_SEVERITY_MAP` 命中 | `_to_finding()` 结果 | `records_skipped` | 整体 status / ok | 分类 |
|---|---|---|---|---|---|---|---|---|
| 1 | `ERROR` | 旧值，向后兼容（match `HIGH`） | `error` | ✅ → `high` | 产出 Finding | 否 | `COMPLETED` / `True` | **已正确映射** |
| 2 | `WARNING` | 旧值，向后兼容（match `MEDIUM`） | `warning` | ✅ → `medium` | 产出 Finding | 否 | `COMPLETED` / `True` | **已正确映射** |
| 3 | `INFO` | 旧值，向后兼容（match `LOW`） | `info` | ✅ → `info` | 产出 Finding | 否 | `COMPLETED` / `True` | **已映射但语义偏移**（官方对应 `LOW`，实现为 `info`）`[I]` |
| 4 | `EXPERIMENT` | Schema 允许；rule-syntax 未列为可写值 | `experiment` | ❌ | `FindingError` → 跳过 | **是（+1/条）** | `COMPLETED` / `True` | **未映射被跳过** |
| 5 | `INVENTORY` | Schema 允许；rule-syntax 未列为可写值 | `inventory` | ❌ | `FindingError` → 跳过 | **是（+1/条）** | `COMPLETED` / `True` | **未映射被跳过** |
| 6 | `CRITICAL` | **当前推荐值** | `critical` | ❌ | `FindingError` → 跳过 | **是（+1/条）** | `COMPLETED` / `True` | **未映射被跳过** |
| 7 | `HIGH` | **当前推荐值** | `high` | ❌（键是 `error`） | `FindingError` → 跳过 | **是（+1/条）** | `COMPLETED` / `True` | **未映射被跳过** |
| 8 | `MEDIUM` | **当前推荐值** | `medium` | ❌（键是 `warning`） | `FindingError` → 跳过 | **是（+1/条）** | `COMPLETED` / `True` | **未映射被跳过** |
| 9 | `LOW` | **当前推荐值** | `low` | ❌ | `FindingError` → 跳过 | **是（+1/条）** | `COMPLETED` / `True` | **未映射被跳过** |

**统计** `[E]`+`[R]`：已映射 **3 / 9**；未映射但被跳过 **6 / 9**；其中 4 个是官方**当前推荐**的规则 severity 值。

### 6.3 用户要求的五个明确区分 `[E]`+`[I]`

| 问题 | 结论 |
|---|---|
| **已正确映射** | `ERROR`→`high`、`WARNING`→`medium`、`INFO`→`info`（3 值）`[E]`。`INFO` 映射本身工作，但官方 rule-syntax 把 `INFO` 对应为 `LOW`，与统一 schema 的 `info` 语义有偏移，属**非致命差异** `[R]`+`[I]` |
| **未映射但被跳过** | `EXPERIMENT`、`INVENTORY`、`CRITICAL`、`HIGH`、`MEDIUM`、`LOW`（6 值）→ `_to_finding()` 抛 `FindingError`，记录 `continue` `[E]` |
| **是否影响 `records_skipped`** | **是**。每个被跳过的记录使 `skipped += 1`（`:404`），最终写入 `meta.records_skipped`（`:443`）`[E]`。但 `detail` 只写「`{len(findings)} finding(s)` from `{len(raw_results)} record(s), `{skipped}` skipped」到**日志**（`:436-437`），`AdapterResult.detail`（`:433`）**不含 skipped 计数** → 报告正文未必能看到 `[E]`+`[I]` |
| **是否可能出现扫描 `COMPLETED` 但 Finding 丢失** | **是，且已确认为实现层确定事实** `[E]`：`status="COMPLETED"`、`ok=True` 在映射失败路径下不变，即使 `raw_results` 全被跳过仍返回 `COMPLETED`。区别只体现在 `meta.records_skipped` 与 attempt log，`report.py` 步骤表渲染的是 `detail`（转引自原计划 §8.2 / Phase A 报告登记 `[E]`）。**这不是推测，无需真机即可裁定** `[E]`+`[I]` |
| **推荐的映射 / 失败处理策略** | 见 §6.4，**本轮不修改任何映射代码** `[E]` |

### 6.4 推荐策略（仅供后续 Code Review / Remediation 输入，`[I]`，**不得直接实施**）

1. **映射扩展（向后兼容纯增强）** `[I]`：按 Phase A §8.1 官方对应关系补齐 `high→high`、`medium→medium`、`low→low`、`critical→critical`，保留现有 3 个旧值键不变；统一 schema 已允许 `info|low|medium|high|critical`（`semgrep.py:86-90` 注释 `[E]`），五个目标值均有合法落点。
2. **`EXPERIMENT` / `INVENTORY` 的处置需单独裁定** `[I]`：Phase A §8.2 的 schema description 说「Experiment and Inventory above should be removed. Info can be kept.」，暗示它们是遗留值。建议：映射到 `info` **或**显式拒绝，但**必须二选一并写入 Code Review 结论**，不能继续「静默跳过」。
3. **更根本的架构修复（强烈建议纳入 Code Review）** `[I]`：**任何**映射外/结构异常记录都不应只被静默跳过而让整体报 `COMPLETED`/`ok=True`。可选方案：(a) `records_skipped > 0` 时把该计数写入 `AdapterResult.detail` 与 `meta`，使其进入冻结 `report.py` 步骤表；(b) 对**完全无法解析**的报告改判 `FAILED`；(c) 至少在报告层显式标注「N 条记录被丢弃」。这比单纯补映射更能防止「假成功」。
4. **顺序约束** `[I]`：#1/#3 属**确定性实现缺陷**（不依赖真机输出，可由 Code Review 立即裁定）；是否把 `INFO` 对齐到 `LOW`、以及是否需要按 1.182.1 实际输出调整，属**条件性差异**，须等 U10 / U15 真机闭合。二者应分开立项、分开验收。
5. **fixture 规则必须重写** `[I]`：原计划 §4.2 全部使用旧值 `ERROR`/`WARNING`/`INFO`，无法覆盖官方当前推荐的 4 值，且可能因输出规范化导致 `RV-02` 全丢（§4.1）。建议同时保留旧值规则（验证向后兼容）与新值规则（验证映射扩展），逐值记录。

---

## 7. CR-06 前置依赖与推荐执行顺序

### 7.1 七项工作与依赖分析 `[I]`

| 代号 | 工作 | 依赖 | 可与谁并行 | 证据层 | 关键约束 |
|---|---|---|---|---|---|
| **W1** | CR-02 与 Severity 的**独立 Code Review**（只读） | 无（本分析文档即可作为输入） | W4、W5 | L0 + `[E]` 源码 | 区分「确定性缺陷」（九值映射 + 静默跳过）与「条件性差异」（缺 `skipped` 键，待 U9）；不修改任何文件 |
| **W2** | 必要的 **Remediation** | W1；**条件性部分**还依赖 W6' | 可与 W3 的「非预期部分」并行，但**最终 Plan 修订必须在 W2 完成后定稿** | `[E]` 源码 + 测试 | 仅改授权文件；冻结五文件不变；EXT-2 两套件 + 相关离线回归全绿；不重跑六项历史测试 |
| **W3** | **Real Verification Plan 修订** | W1 + W2（RV 预期必须按**修复后**代码基线写） | 起草可与 W2 并行，**定稿必须在 W2 之后** | L0 + `[E]` | 不改写历史结论（建议纯追加 §14 或另建 v2 文档）`[I]` |
| **W4** | **wheel 下载与 SHA256 本地核验**（人工执行） | 无 | W1、W5 | L0 → `[E]` 本地哈希 | 闭合 U12 / U14；不改系统环境 |
| **W5** | **隔离 venv 准备** | W4 | W1 | `[E]` | 闭合 U2（运行层）；进程级 PATH；记录 `semgrep --version` |
| **W6'** | **基线真机采集**（新增建议，见 §7.2） | W4 + W5 | 与 W1/W2 的确定性部分可并行，但**必须先于条件性 Remediation** | **L1 + L2 + L4** | 不改代码、不下验收结论；只采集原始 stdout / rc / env / 网络观测 |
| **W6** | **Semgrep 真实运行**（正式 RV 全矩阵） | W3 + W5 + W6' | 场景之间可并行（不同证据目录） | L1 + L2 + L3 + L4 | 每场景证据齐全、哈希可复核、哨兵零命中 |
| **W7** | **完整链路验证** | W6（至少完成 RV-01/RV-02 的成功场景） | 可与 W6 的后半段并行，**验收结论必须在 W6 之后** | L2 | 原计划 §8.2 的 8 个核对点全通过；audit verify=OK |

### 7.2 推荐执行顺序（主方案，`[I]`）

```
阶段 0（可立即启动，可并行）
  ├─ W1 独立 Code Review（只读）           ─┐
  ├─ W4 wheel 下载 + 本地 SHA256 核验      ─┼─ 互不依赖，可同时开展
  └─ W5 隔离 venv 准备（依赖 W4）          ─┘

阶段 1（必须先于「条件性 Remediation」，串行）
  └─ W6' 基线真机采集：在【不修改任何代码】的前提下，跑 1 次有 findings +
     1 次无 findings 的最小真实扫描，只采集原始 stdout / rc / env / 网络观测，
     不下 PASS/FAIL 结论。目的：闭合 U9 / U10 / U15 / U4(部分) / U2。

阶段 2（串行）
  ├─ W2 Remediation：只修【W1 裁定的确定性缺陷】+【W6' 真机确认的差异】
  └─ W3 Plan 修订定稿：按修复后代码基线重写 RV 预期（纯追加 / v2）

阶段 3（串行）
  ├─ W6 正式 RV 全矩阵（含新增 RV-11..RV-17）
  └─ W7 完整链路验证 + 审计完整性

阶段 4（人工验收）
  └─ CR-06 闭合判定（C1–C9 + §7.4 新增判据），由人工决定，不由本分析代劳
```

**为什么把 W6' 放在 W2 之前（本分析的核心判断）** `[I]`：

- Phase A 的两项重大差异中，`paths.skipped` 缺键策略**依赖 U9**（真机是否省略该键），而 Schema 来自未 pin 版本的 `main` 分支（U4）`[R]`+`[U]`。若直接按 Schema 做 Remediation，等于**按未经真机确认的假设改代码**，既违反原计划 §6.5「不符即停止、不擅自改代码」，又会使后续验证的**代码基线漂移**、证据无法归因 `[I]`。
- 但 **Severity 映射缺口是确定性缺陷**：官方 Schema 明确允许 9 值、`_SEVERITY_MAP` 只覆盖 3 值、且失败路径会报 `COMPLETED` —— 这些**不依赖真机输出**即可裁定（§6.3）`[E]`+`[R]`。因此 W1 可以立即启动，W2 的**确定性部分**不必等 W6'；只有**条件性部分**（`paths.skipped` 策略、`INFO`↔`LOW` 对齐）必须等 W6' `[I]`。
- W6' 与 W1/W2 的确定性部分**可以并行**，但 W6' 必须在**条件性 Remediation** 之前完成 `[I]`。

### 7.3 备选顺序（若用户选择「先 Remediation、后真机」）`[I]`

- 顺序：W1 → W2（**仅确定性缺陷**）→ W3 → W4/W5 → W6 → W7。
- **必须附加的约束**：`paths.skipped` 缺键策略**冻结不改**，在修订后的 Plan 中把 U9 列为显式待验证项；Remediation 报告须声明「未依据未 pin 版本的 Schema 调整完整性判定」。
- **代价** `[I]`：RV-01/RV-02 的预期仍需按「当前实现」写，若真机出现差异会触发原计划 §6.5 停止流程，需再起一轮 Remediation，反而增加往返；且无法区分「差异来自工具」还是「差异来自刚改过的代码」。
- **本分析推荐主方案（含 W6'）** `[I]`，理由如上。

### 7.4 每一步的验收条件 `[I]`

| 步骤 | 验收条件（可判定） |
|---|---|
| W1 Code Review | 产出独立只读报告；每个问题含严重等级、源码行号、官方证据编号、是否影响验收；**明确区分确定性缺陷 / 条件性差异**；未修改任何文件 |
| W4 wheel 核验 | 目标 `win_amd64` wheel 本地 SHA256 == `e464d398…b68c`（Phase A §4 `[R]`）；完整依赖树及其哈希写入 `requirements.lock`（闭合 U14）；记录 wheel 名 / Python tag / 平台 tag；未改动系统环境 |
| W5 venv | `semgrep --version` 返回 `1.182.1`；`semgrep scan --help` 含 `scan`、`--json`、`--metrics`（闭合 A3 的 flag 接受性问题与 U2 运行层）；进程级 PATH，不改持久化 |
| **W6' 基线采集** | 原始 `stdout.json` + 其 SHA256 落在隔离证据目录；**至少** 1 次 `rc=0` 无 findings + 1 次 `rc=0` 有 findings；记录：顶层键集合、`paths.skipped` 存在性与形态、真实 `extra.severity` 值集合、`paths.scanned` 是否存在、rc；env 快照含 `SEMGREP_RULES`/`SEMGREP_SEND_METRICS`；L1 配置层 + L2 进程观测留证；**未修改任何代码、未判定 PASS/FAIL** |
| W2 Remediation | 仅修改授权文件；冻结五文件哈希不变；`python tests/test_semgrep_adapter.py` 与 `python tests/test_semgrep_integration.py` 全绿；新增九值矩阵与 `paths.skipped` 四形态针对性用例；不重跑六项历史测试；产出 Remediation 报告；**未依据未 pin Schema 调整条件性策略**（主方案下由 W6' 提供依据） |
| W3 Plan 修订 | 按修复后基线重写 RV 矩阵；每个预期标注 `[E]/[R]/[I]/[U]`；证据分层（§3）写入；§11 批准清单更新；**历史 §1–§13 结论不改写**（纯追加或 v2 文档） |
| W6 正式真机 | RV-01..RV-07 + RV-08..RV-17 全部执行；每场景 §9.2 证据清单齐全且哈希可复核；哨兵清扫零命中；L3 注入结果在报告中**明确标为注入** |
| W7 链路 | 原计划 §8.2 的 8 个核对点全通过；`meta.records_skipped` 异常有可审计痕迹；`audit_status()` verify=OK；`report_written` 恰好一条；CLI 退出码语义正确 |
| **CR-06 闭合** | 原计划 C1–C9 **全部满足**，且新增判据：九值映射覆盖结论已裁定、`paths.skipped` 四形态结论已裁定、env 快照已核对、`settings.yml` 副作用已登记、L4 三层网络观测完成并附证据边界声明；由**人工验收**决定 |

### 7.5 串行 / 并行总表 `[I]`

| 关系 | 工作对 | 理由 |
|---|---|---|
| **必须串行** | W4 → W5 | venv 依赖已核验的 wheel |
| **必须串行** | W6' → W2（条件性部分） | 不得按未 pin Schema 猜测真机行为 |
| **必须串行** | W2 → W3（定稿） | RV 预期必须对应修复后代码基线 |
| **必须串行** | W3 → W6 | 执行方案必须先冻结，否则证据无法归因 |
| **必须串行** | W6 → W7（验收结论） | 链路结论依赖真机产物 |
| **必须串行** | W7 → `CR-06` 闭合 | 判据依赖链路证据 |
| **可并行** | W1 ∥ W4 ∥ W5 | 只读审查与环境准备互不依赖 |
| **可并行** | W1/W2 确定性部分 ∥ W6' | 确定性缺陷不依赖真机输出 |
| **可并行** | W6 各场景之间 | 不同证据目录、互不覆盖 |
| **可并行（起草）** | W3 起草 ∥ W2 | 但 W3 **定稿**必须在 W2 之后 |

---

## 8. 风险清单

| # | 风险 | 证据 | 等级 | 影响 `[I]` | 缓解建议 `[I]` | 状态 |
|---|---|---|---|---|---|---|
| **RK-01** | 6/9 官方 severity 值未映射且被静默跳过，整体仍报 `COMPLETED` | §6.2 / Phase A §8.2 `[R]` + `semgrep.py:400-406, 438-445` `[E]` | **高** | 真实安全发现丢失且无人察觉 | W1 立即裁定 + W2 修映射与「假成功」 | 未处理 |
| **RK-02** | 原计划 fixture 规则全用旧 severity，真机若输出规范化新值会导致 `RV-02` 三条 finding 全丢 | §4.1 RV-02 / Phase A §8.1 `[R]` + 原计划 §4.2 `[E]` | **高** | 核心验证场景得出误导性「通过」 | 重写 fixture 规则（旧值+新值），新增 RV-11 | 未处理 |
| **RK-03** | `paths.skipped` 缺键（Schema 合法）被判 `FAILED`，正常扫描被误判失败 | §5.2① / Phase A §7.3 `[R]` + `semgrep.py:176-179` `[E]` | **高** | `RV-01` 预期失效；`CR-02` 需适配 | W6' 闭合 U9 后再裁定；不预先改代码 | 待 U9 |
| **RK-04** | Schema 来自 `main` 分支未 pin 版本，不能代表 1.182.1 | Phase A §7.1 / U4 `[U]` | 中高 | 基于错误契约改代码 | W6' 基线采集比对；Plan 标注证据层 | 待 W6' |
| **RK-05** | `RV-04` 触发方式（语法错误 → `errors[]`）可能不成立，解析失败或进入 `paths.skipped` | §4.1 RV-04 / Phase A §7.3 `skip_reason` `[R]` | 中 | 场景无法产生目标信号，误判为「通过」 | 保留真机尝试 + L3 注入兜底（明确标注） | 待 U11/U16 |
| **RK-06** | `RV-07` 把 CLI `--timeout`、Semgrep `--timeout`、进程级 timeout 三种概念混淆 | §4.1 RV-07 / Phase A §6.5 `[R]` + `semgrep.py:260-263, 456-457` `[E]` | 中 | 超时场景触发方式写错，证据无效 | 修订 Plan §5.2 表述，明确只用进程级 timeout | 待 W3 |
| **RK-07** | 官方退出码文本内部不一致（1/7/14/99） | Phase A §6.3 / U7 `[R]`+`[U]` | 中 | `RV-05` 比对表可能引用错误语义 | 新增差异列 + RV-16 定向观测 | 待 U7 |
| **RK-08** | `SEMGREP_RULES` / `SEMGREP_SEND_METRICS` 未被 `tool_env()` 清理 | Phase A §9.4 `[R]`+`[E]` | 中 | 隐式 config 覆盖 / metrics 启用，污染扫描与「无外网」结论 | RV-14 env 快照；W5 起隔离进程内显式清空 | 未处理 |
| **RK-09** | `~/.semgrep/settings.yml` 首次运行写入用户主目录 | Phase A §9.3 `[R]` | 中 | 计划外本地写入，隔离/清理边界缺口 | RV-15 观测；纳入 W3 修订 | 未处理 |
| **RK-10** | 网络观测窗口不足：版本检查可能在结果返回之后发生 | Phase A §6.5 `[R]` | 中 | 漏采出站连接 | L2 采样覆盖进程退出后短暂窗口；RV-17 | 未处理 |
| **RK-11** | 证据分层混淆：把 L3 注入当真机证据、把配置层 metrics 禁用当网络离线证明 | §3 / 用户重点事项 5 `[E]` | **高（治理）** | `CR-06` 被错误闭合 | 执行报告强制按 L0–L4 标注；验收清单加证据层检查 | 需写入 W3 |
| **RK-12** | 顺序错误导致验证基线漂移（先按 Schema 改代码再真机） | §7.2 `[I]` | **高（流程）** | 证据无法归因，可能反复 Remediation | 采用主方案（含 W6'）或备选的冻结约束 | 需人工选 |
| **RK-13** | `results[]` / `errors[]` 结构未从官方 Schema 核对（页面截断） | Phase A §7.5 / U5 / U11 `[U]` | 中 | 原计划 §6.1 核对表仍大量 `[U]` | W6' 真机字段枚举 | 待 W6' |
| **RK-14** | 完整依赖树与依赖 wheel 哈希未核对 | Phase A §4 末 / U14 `[U]` | 中 | 环境不可复现，W5 验收不完整 | W4 一并锁定 | 待 W4 |
| **RK-15** | `records_skipped` 未进入 `AdapterResult.detail`，报告正文可能看不到「N 条被丢弃」 | §6.3 / `semgrep.py:433-437` `[E]` | 中 | 即使 `meta` 有记录，人工阅读报告仍可能漏判 | W1 纳入「假成功」修复建议 | 未处理 |

---

## 9. 建议修订内容（对 `docs/EXT-2-REAL-VERIFICATION-PLAN.md`）

> **本轮未修改原计划任何内容** `[E]`。以下为**修订建议清单** `[I]`，需 W3 阶段单独授权后实施。
>
> **修订方式建议** `[I]`：沿用项目既有「纯追加」纪律 —— **新增 §14「Phase A 差异修订」**或另建 `...-PLAN-v2.md`，**不改写 §1–§13 历史结论**（与 `EXT-2-IMPLEMENTATION-REPORT.md` 纯追加 §10 的先例一致 `[E]`）。

| # | 原计划章节 | 现状 `[E]` | 建议修订 `[I]` | 依据 |
|---|---|---|---|---|
| M-01 | §2.1 / §2.2 / §2.4 | 版本信息标「第三方检索、需人工复核」；A1/A2 待核对 | 改为「已由 Phase A §3/§4/§5 官方源核实」，引用 `1.182.1`、Released 2026-10-22、8 个 `digests.sha256`、`win_amd64` wheel；A2 分**分发层已闭合 / 运行层 U2 未闭合**；去掉「若 Windows wheel 不可用则退回 WSL」的未触发条件措辞 | A1/A2 `[R]` |
| M-02 | §2.3 | SHA256 校验方法学 | 追加**已登记的 8 个官方值**（尤其 `win_amd64`），并保留「`digests.sha256` ≠ `core-metadata.sha256`」区分；标注官方声明值尚未本地比对（U12） | Phase A §4 `[R]` |
| M-03 | §4.1 / §4.2 | 5 个规则文件，全部 `ERROR/WARNING/INFO` | **重写规则集**：保留 3 个旧值规则 + 新增 `rv-high.yaml` / `rv-medium.yaml` / `rv-low.yaml` / `rv-critical.yaml`；明确「旧值为向后兼容别名，真机输出可能被规范化」；fixture 源码相应扩展 | A8/A9 + §4.1 RV-02 `[R]`+`[I]` |
| M-04 | §5.1 | Tier A/B/C 三层 + 诚实边界 | 保留并**强化**：Tier B 定义为「L3 人工注入故障测试，不构成真实工具行为证据」；新增 §5.0「证据分层 L0–L4」 | §3 本分析 `[E]` |
| M-05 | §5.2 矩阵 | 7 行固定预期 | 按 §4.1 逐行修订：RV-01 改分支预期；RV-02 取消「3 findings」硬预期、改为逐值核对；RV-03 首要风险改为「键缺失」；RV-04 标注触发方式待确认；RV-05 增 rc 差异列；RV-07 删除「极小 `--timeout`」表述 | §4 本分析 `[I]` |
| M-06 | §5.3 | 7 段核对点 | RV-01 增「顶层键集合 / `paths.scanned` / `skipped` 存在性」；RV-02 增「真实 severity 值集合 + 逐值映射结果 + `records_skipped`」；RV-03 增「真实 reason 键名」；RV-04 增「解析失败是否落入 skipped」；RV-07 增「进程级 vs 每文件 timeout 区分 + 退出后观测窗口」 | §4/§5/§6 `[I]` |
| M-07 | §5.4 | RV-08/09/10 可选 | 保留 3 项，新增 **RV-11..RV-17**（§4.3），并标注哪些属 L3 注入 | §4.3 `[I]` |
| M-08 | §6.1 字段核对表 | 「真实报告实际」列全 `[U]` | 把已被 Schema 确认的行改标 `[R]`（根级 `required`、`paths.scanned`、`skipped_target`、17 个 `skip_reason`）；新增 `paths.scanned` / `skipped_target` / `skip_reason` 三行；保留 `results[]`/`errors[]` 内部字段为 `[U]`（U5/U11） | A5/A6/A7/A17 `[R]`+`[U]` |
| M-09 | §6.2 | 「第三方资料提到 CRITICAL」的单一风险提示 | **整体替换**为 §6 的九值映射矩阵 + 五个明确区分 + 推荐策略；明确「确定性缺陷 vs 条件性差异」 | A8/A9/A10 `[R]` |
| M-10 | §6.3 | 单一官方退出码表 | 增列「内嵌 `--help` 的 `EXIT STATUS`」与「官方内部差异表（1/7/14/99）」；标注真机前不裁定 | A4/U7 `[R]`+`[U]` |
| M-11 | §6.4 判定表 | 6 行，裸字符串标「最可能适配触发点」 | **重写为 §5.2 的五情形表**；把「键缺失」列为首要风险；裸字符串降级为 L3 注入场景；新增「结构校验 vs 完整性判定」失败来源列 | §5 本分析 `[E]`+`[I]` |
| M-12 | §7.2 / §7.4 | L1 配置层核对项有限；证据边界已较完整 | 增：官方 env 键（`SEMGREP_RULES`/`SEMGREP_SEND_METRICS` 等）快照与清理；`--json-output` 类 flag 未使用确认；`~/.semgrep/settings.yml` 副作用登记；观测窗口覆盖进程退出后；**明确「配置层 ≠ 网络层」不得合并表述** | A11/A12/A13/A14/A16 `[R]`+`[E]` |
| M-13 | §8.2 链路核对点 | 8 项，含 `meta.records_skipped` | 增「`records_skipped > 0` 时报告可审计」核对点，防止 `COMPLETED` + `findings=[]` 假成功被忽略 | RK-15 `[E]` |
| M-14 | §9.2 证据清单 | `env-snapshot.txt` | 增：官方 env 键快照、`settings.yml` 观测记录、**证据层标记（L0–L4）**字段 | §3 / A13/A14 `[I]` |
| M-15 | §10.1 C1–C9 | 9 条判据 | 增：九值映射覆盖结论已裁定；`paths.skipped` 四形态结论已裁定；env 快照已核对；`settings.yml` 已登记；L4 三层观测完成且附证据边界声明；L3 结果未被误作真机证据 | §7.4 `[I]` |
| M-16 | §11 批准清单 | A 类待批准 | A1/A2 归档为「Phase A 已闭合」；新增「W1 独立 Code Review」「W2 Remediation」「W3 Plan 修订」「W6' 基线真机采集」四类授权项；§11 E3 细化为「确定性缺陷修复」与「条件性差异修复」需分别授权 | §7 / §11 本分析 `[I]` |
| M-17 | §12 标注体系 | `[E]/[R]/[S]/[I]/[U]` 五态 | 按本轮用户要求统一为 `[E]/[R]/[I]/[U]` 四态，并补充「`[R]` 转引自 Phase A S1–S8，未重新联网」的边界说明 | 本任务三 `[E]` |

---

## 10. 尚未解决的 UNKNOWN

### 10.1 沿用 Phase A 且直接影响本计划的 UNKNOWN `[U]`

| # | 事项 | Phase A 出处 | 影响的 RV / 判据 |
|---|---|---|---|
| U2 | wheel 内 Windows `semgrep-core` 可运行性 / 1.182.1 能否在本机启动 | §5.1 / §11 | W5、全部真机场景 |
| U4 | `main` 分支 Schema 是否精确对应 1.182.1 | §7.1 / §11 | §5 全部情形、RV-01/02/03 |
| U5 | `results[]`（`cli_match`）内部字段结构 | §7.5 / §11 | RV-02、原计划 §6.1 |
| U6 | `finding.severity` 允许枚举 | §7.5 / §11 | §6 矩阵（间接） |
| U7 | 官方内部退出码差异（1/7/14/99）哪个适用于 1.182.1 | §6.3 / §11 | RV-05、RV-16 |
| U8 | `SEMGREP_ENABLE_VERSION_CHECK=false` 的取值语义 | §6.5 / §11 | RV-14、RV-17 网络观测 |
| **U9** | **1.182.1 无跳过文件时是否省略 `paths.skipped`** | §7.4 / §11 | **RV-01、§5.2①、RK-03、W2 条件性部分** |
| **U10** | **1.182.1 真实 `extra.severity` 取值集合** | §8.3 / §11 | **RV-02、§6、RK-02** |
| U11 | `errors[]`（`cli_error`）元素结构 | §7.5 / §11 | RV-04 |
| U12 | 官方 `digests.sha256` 与实际下载文件是否一致 | §11 | W4 |
| U13 | 是否存在其它实际出站路径 | §9.2 / §11 | RV-17、C6 |
| U14 | 完整依赖树及依赖 wheel 的 SHA256 | §4 末 / §11 | W4、C1 |

### 10.2 本轮新识别的 UNKNOWN `[U]`

| # | 事项 | 识别依据 | 何处闭合 |
|---|---|---|---|
| **U15** | 1.182.1 是否把规则中的旧 `ERROR/WARNING/INFO` **规范化**为 `HIGH/MEDIUM/LOW` 写入 `extra.severity` | Phase A §8.1「The older levels … match HIGH, MEDIUM, LOW」`[R]`；`[I]` 推论，未证实 | W6' / RV-02（`[U]`） |
| **U16** | 语法错误文件能否在默认 `semgrep scan` 下自然诱发 `errors[]`（而非 `paths.skipped`） | Phase A §7.3 `skip_reason` 含 `analysis_failed_parser_or_internal_error` `[R]`；§6.5 `--strict` `[R]`；`[I]` 推论 | RV-04 真机（`[U]`） |
| **U17** | 无跳过报告的 `paths.scanned` 是否恒存在 / 其内容形态 | Phase A §7.3 `scanned_and_skipped.required=[scanned]` `[R]`；实际输出未观测 | W6' / RV-01（`[U]`） |
| **U18** | `skipped_target.reason` 是否在全部 17 种 `skip_reason` 下都填充；是否会出现仅 `type/message/code` 的异形条目 | Phase A §7.3 `[R]` + `_SKIP_REASON_KEYS` 更宽 `[E]`；`[I]` 推论 | RV-03 真机（`[U]`） |
| **U19** | Windows wheel 中 `semgrep-core` 的实际路径与子进程形态 | Phase A §9.4 需 PID 映射 `[E]`；wheel 内容未拆包（禁止） | W5 准备 + RV-17 网络观测（`[U]`） |
| **U20** | Remediation 后代码基线是否仍与 Phase A 证据一致（顺序风险） | §7.2 基线漂移分析 `[I]` | W2 验收 + W3 定稿（`[U]`） |
| **U21** | `records_skipped > 0` 是否能在冻结 `report.py` 的步骤表中被人工看见 | `semgrep.py:433-437` detail 不含该计数 `[E]`；渲染行为未实测 | W7 链路验证（`[U]`） |

### 10.3 本轮**未**闭合任何 UNKNOWN `[E]`

本分析只把 Phase A 的 `[R]` 证据与当前 `[E]` 源码做了对照，**未产生新的 L1/L2/L4 证据**，因此 U1–U21 全部保持未确认状态；`CR-06` 仍未闭合，`EXT-2` 仍为 `CONDITIONAL ACCEPT`。

---

## 11. 下一阶段需要用户批准的事项

> **本轮不自动进入下一阶段** `[E]`。以下仅为清单，一项都未执行、未创建、未申请执行。

**P1 — 独立 Code Review（W1，只读，可最先批准）**

- 批准对 `vuln_hunter/adapters_ext/semgrep.py` 做独立只读审查，输入为本文档 + Phase A 报告；要求区分确定性缺陷与条件性差异；不修改任何文件。

**P2 — 下载与本地核验（W4，人工执行）**

- 批准人工下载 `semgrep-1.182.1-...-none-win_amd64.whl` 及完整依赖树到本地，逐项做本地 SHA256 比对（闭合 U12/U14）；批准创建隔离证据目录保存官方页面快照（如需）。

**P3 — 隔离环境准备（W5）**

- 批准创建隔离 venv、进程级 PATH 前置、`semgrep --version` / `semgrep scan --help` 记录（闭合 U2）；明确不改系统 PATH / 注册表 / 环境变量持久化。

**P4 — 基线真机采集（W6'，新增，需单独确认是否采纳主方案）**

- 批准在**不修改任何代码**的前提下执行一次最小真实扫描（1 次有 findings + 1 次无 findings），只采集原始 stdout/rc/env/网络观测，不下验收结论；用于闭合 U9/U10/U15/U17 后再决定条件性 Remediation。
- 若用户选择 §7.3 备选顺序，需明确批准「`paths.skipped` 策略冻结不改」的约束。

**P5 — Remediation（W2，需单独授权的新任务）**

- 批准「确定性缺陷」修复：severity 九值映射扩展 + 「`COMPLETED` 但 Finding 丢失」的可审计化（§6.4 #1/#3）。
- 「条件性差异」修复（`paths.skipped` 缺键策略、`INFO`↔`LOW` 对齐）需在 P4 闭合 U9/U10 后**另行授权**。
- 约束：仅改授权文件、冻结五文件不变、EXT-2 两套件 + 相关离线回归全绿、不重跑六项历史测试、产出 Remediation 报告。

**P6 — Plan 修订（W3）**

- 批准修订方式：**纯追加 §14** 或新建 `...-PLAN-v2.md`（二选一，不改写 §1–§13 历史结论）。
- 批准按 §9 的 M-01..M-17 落实修订。

**P7 — 正式真机验证与完整链路（W6 / W7）**

- 批准 RV-01..RV-07 修订版 + RV-08..RV-17 全部执行；批准 L3 注入场景（明确标注不构成真机兼容性证据）；批准哨兵清扫。
- 批准 L4 三层网络观测 / 临时出站阻断及其恢复动作。
- 批准 CLI 运行对 `output/vuln_hunter_report.md` 的写入（或改为在 `<ISO>` 作为工作目录运行以避开）。

**P8 — 状态变更（最后，人工验收）**

- `CR-06` 闭合 / `EXT-2` 升级为完整 `PASS`：仅在 C1–C9 + §7.4 新增判据全部满足后由人工决定。
- 明确**不在本轮及后续执行阶段范围**：改写 G15 FAIL / `EXECUTION_INTEGRITY=NOT_OK` / C14 FAIL / 历史 `UNKNOWN` / 六项测试阶段状态。
- 任何删除 / 清理：须先列出具体文件清单、逐项人工确认；两个既有验证副产物不清理。

---

## 12. 收尾核验

> 本节的哈希与状态为本轮**分析开始前基线**与**完成后复核**的比对结果，全部由只读命令取得 `[E]`。

| 核验项 | 分析前基线 | 完成后复核 `[E]` | 结论 |
|---|---|---|---|
| `docs/EXT-2-REAL-VERIFICATION-PLAN.md` SHA256 | `ec0f3fca55dd189a8cb5283ee1e365efbb29e66c588b2729d9830f18f114fd9e` | `ec0f3fca55dd189a8cb5283ee1e365efbb29e66c588b2729d9830f18f114fd9e` | 不变 |
| `docs/EXT-2-PHASE-A-VERIFICATION-REPORT.md` SHA256 | `3d40300b91720eea786ae73299bdabe74df54cd696c37ef9309a0f03ec731185` | `3d40300b91720eea786ae73299bdabe74df54cd696c37ef9309a0f03ec731185` | 不变 |
| 冻结五文件哈希 | 见 §12.1 | 与 §12.1 逐项一致（见 §12.2） | 不变 |
| HEAD | `9913c50` | `9913c50` | 未变 |
| `git diff --stat`（已跟踪） | 5 files / 83 insertions(+) / 4 deletions(-) | `5 files changed, 83 insertions(+), 4 deletions(-)` | 一致 |
| `git status --short` | 5 个 `M` + 20 个 `??` | 5 个 `M` + 21 个 `??`；新增项仅 `?? docs/EXT-2-PHASE-A-PLAN-GAP-ANALYSIS.md` | 仅新增本分析文档 1 项 `??` |
| `output/vuln_hunter_report.md` | 存在（2,724 B，11-08 22:14） | 存在（2,724 B，11-08 22:14） | 保留 |
| `%TEMP%\tmp.AvXfUFcabf\` | 存在 | 存在（目录，11-08 22:14） | 保留 |

### 12.2 完成后复核命令输出摘要 `[E]`

只读命令：`sha256sum`（两份基准文档 + 冻结五文件）、`git rev-parse --short HEAD`、`git diff --stat`、`git status --short`、`ls -l/ls -ld`（两个副产物）、`command -v semgrep`、`python -m pip show semgrep`、`ls -ld ~/Tools/semgrep`。

| 冻结文件 | 复核 SHA256 |
|---|---|
| `vuln_hunter/adapters.py` | `65ece047b13784e0efbf00bd71166279734ea150a90ec56db5830bd551098f59` |
| `vuln_hunter/runner.py` | `29d71dc54f34bc024bde13cc8ec5fcac2745fddeb676ad302aaa5320ebcd842c` |
| `vuln_hunter/report.py` | `59caebb3094896f1a6eb0e63de16b87d59c52a6512a77d2e0661a54e60761683` |
| `tests/test_d2d1_proccleanup.py` | `1cd2b9483c4869c4fbad4ecadeafaad8b67a1396b69d8694bb62852a2c194c13` |
| `tests/test_d2d0_d2d4.py` | `840046857997917bec2dd542c7af6819261001af42bce5a6aa14684bf668aaf9` |

工具与环境状态 `[E]`：`semgrep: not on PATH`；`pip show semgrep` → `WARNING: Package(s) not found: semgrep`；`~/Tools/semgrep: absent`。即本轮**未产生任何 Semgrep 安装、下载或运行痕迹**。`git diff` 的 `LF will be replaced by CRLF` 仅为工具 warning，未执行 Git 写操作、未改换行符。

> **自引用说明** `[I]`：本分析文档自身的行数 / 字节数 / SHA256 在**最终答复**中给出，不写入文档正文，避免写入自身哈希导致校验值失效。

### 12.1 冻结五文件基线 `[E]`

| 文件 | SHA256 |
|---|---|
| `vuln_hunter/adapters.py` | `65ece047b13784e0efbf00bd71166279734ea150a90ec56db5830bd551098f59` |
| `vuln_hunter/runner.py` | `29d71dc54f34bc024bde13cc8ec5fcac2745fddeb676ad302aaa5320ebcd842c` |
| `vuln_hunter/report.py` | `59caebb3094896f1a6eb0e63de16b87d59c52a6512a77d2e0661a54e60761683` |
| `tests/test_d2d1_proccleanup.py` | `1cd2b9483c4869c4fbad4ecadeafaad8b67a1396b69d8694bb62852a2c194c13` |
| `tests/test_d2d0_d2d4.py` | `840046857997917bec2dd542c7af6819261001af42bce5a6aa14684bf668aaf9` |

**边界复核** `[E]`：本轮未修改原计划、Phase A 报告、任何源码/测试/配置/规则/fixture/历史证据；未下载/安装/运行 Semgrep；未创建 venv 或验证环境；未执行扫描或测试；未修改 PATH/注册表/系统环境变量；未删除/移动/覆盖任何文件；未执行 Git 写操作；未重跑六项历史测试；未改变 `CR-06` / `EXT-2` / 六项测试阶段状态；G15 FAIL / `EXECUTION_INTEGRITY=NOT_OK` / C14 FAIL / 历史 `UNKNOWN` 一律原样保留。

---

## 13. 完成后停止

本分析文档为 `EXT-2 Phase A 后续：Real Verification Plan 差异分析` 的**唯一交付物**。本轮到此停止，**不自动进入下一阶段**。

在获得 §11 的明确授权前：不实施任何修订、不开展 Code Review / Remediation、不下载 wheel、不创建 venv、不运行 Semgrep、不执行扫描或测试、不修改任何源码/测试/配置/基准文档/现有证据，不改变任何验收状态。

*文档结束。*
