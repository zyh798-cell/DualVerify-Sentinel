# EXT-2-IMPLEMENTATION-REPORT — Semgrep Adapter 实施报告

- 实施日期：2026-11-08
- 项目：`C:/Users/ZTL/Desktop/DualVerify-Sentinel`（分支 `main`，HEAD `9913c50bff074833a1ea14204a353b80f313558a`，未改动）
- 授权范围：仅本次 EXT-2 Semgrep Adapter。未触碰六项测试裁定、G15/C14、归档、备份、管理目录。
- 结论标注：`[E]` 直接观测、`[S]` 登记陈述、`[I]` 推断、`[U]` 无法确认。

---

## 1. 实际实现的功能

在 V1 确定性授权门控架构中新增 **Semgrep 多语言静态代码分析**能力，完整接入现有 Planner / Runner / Policy / Journal / Findings / Report 链路。

| 能力 | 实现 |
|---|---|
| 适配器 | `SemgrepAdapter(ToolAdapter)`，`id="semgrep"`、`risk="R1"`、本地目录扫描 |
| 授权 | 继承 `ToolAdapter.execute()` 最终门禁（RunTicket + live policy + scope-hash + window + mode ceiling + target_kind），**未绕过任何现有 Policy/Runner/执行门控** |
| 规划 | `planner.build_plan(..., semgrep_rules=...)` 在"有 source_dir **且** 二进制可解析 **且** 配置了本地 rules"时追加 `s5-semgrep` 步骤（`target_kind="fs_path"`，无 deps） |
| CLI | `--semgrep-rules`（本地规则文件/目录）；`--source-dir` 帮助文本扩展；`main()` 显式调用 `register_semgrep()` |
| 注册 | `register_semgrep()` 幂等，仅在 CLI 启动路径调用；导入任何模块零注册副作用 |
| 结构化输出 | 解析 semgrep `--json` 报告的 `results[]`，白名单抽取 `check_id` / `path` / `start.line` / `end.line` / `extra.severity` / `extra.message` / `extra.metadata`（限定键）→ 统一 `Finding`（13 字段 schema） |
| 严重性 | 文档化映射 `ERROR→high`、`WARNING→medium`、`INFO→info`；不在映射内的取值 → 记录被跳过（fail-closed，绝不静默降级为 info） |
| 报告兼容 | 为冻结的 `report.py` 渲染器增加 `name` 别名，并显式标注 severity 来源（"由 Semgrep 报告的 severity 字段经映射得到；非 DualVerify-Sentinel 自行判定"） |

**离线/无网络保证**：`--metrics off` 关闭遥测；`SEMGREP_ENABLE_VERSION_CHECK=false` 通过子进程环境变量抑制版本检查（未知 env var 被无害忽略，故不依赖 CLI flag 的存在性）；**rules 必须由操作者提供本地文件/目录**，适配器从不回退到 semgrep registry/auto 配置，也从不自动安装 semgrep。

---

## 2. 新增和修改文件清单

### 新增（3 个）

| 文件 | 行数 | 说明 |
|---|---|---|
| `vuln_hunter/adapters_ext/semgrep.py` | 约 400 | `SemgrepAdapter`、`register_semgrep()`、`semgrep_binary()`、`SEMGREP_SEVERITY_MAP`、白名单抽取与 `_to_finding()` |
| `tests/test_semgrep_adapter.py` | 约 560 | 适配器单元测试（mock `_spawn` 缝，77 项检查） |
| `tests/test_semgrep_integration.py` | 约 560 | 集成测试（真实 gate/planner/executor/journal/report，mock 工具，38 项检查） |

### 修改（3 个，全部在授权范围内、全部非冻结）

| 文件 | 改动 |
|---|---|
| `vuln_hunter/__main__.py` | `main()` 增 `register_semgrep()`；新增 `--semgrep-rules` 参数；`--source-dir` 帮助文本扩展；向 `build_plan()` 透传 `semgrep_rules` |
| `vuln_hunter/planner.py` | `build_plan()` 增 `semgrep_rules` 形参；新增 `s5-semgrep` 步骤生成逻辑；import `semgrep_binary` |
| `vuln_hunter/adapters_ext/__init__.py` | 导出 `SemgrepAdapter` / `register_semgrep()`；文档同步说明 EXT-2 |

**未修改（且未需要修改）**：`vuln_hunter/adapters.py`、`vuln_hunter/runner.py`、`vuln_hunter/report.py`、`vuln_hunter/findings.py`、`vuln_hunter/adapters_ext/gitleaks.py`、`vuln_hunter/taskgraph.py`（`_KIND_BY_ADAPTER` 未加 semgrep 条目——`kind` 仅作标签，gitleaks 现状如此；步骤显式带 `target_kind` 已足够，故按授权最小改动原则不动它）、`pyproject.toml`（`vuln_hunter.adapters_ext` 已在 `packages` 中，新文件自动随 wheel/sdist 发布）。

---

## 3. Adapter 与现有架构的集成关系

```
CLI main()
 ├─ register_gitleaks(); register_semgrep()        # EXT-1.2/EXT-2 显式注册（幂等）
 ├─ run_gate(scope)  ──► python -m vuln_hunter.gate_check   # 子进程门禁，fail-closed
 ├─ PolicyEngine(scope, mode)                      # R0–R4 天花板 / window / scope / ticket
 ├─ build_plan(..., semgrep_rules=...)             # s1-probe → s2-nuclei → s3-bandit → s4-gitleaks → s5-semgrep
 ├─ Executor.run_step(s5)                          # 12 步检查链（fs_path 仅豁免网络 scope 检查）
 │    └─ SemgrepAdapter.execute(ticket, policy)    # 继承门禁：ticket/policy/mode/scope-hash/target_kind/risk
 │         └─ _run()  → _spawn(cmd, timeout)       # 唯一子进程缝（测试可替换）
 │              └─ 白名单抽取 → Finding → to_dict() → name 别名（report.py 兼容）
 ├─ EvidenceJournal.append(step_start/attempt_*/step_end)   # 哈希链，fail-closed
 └─ render_report(...)                             # 冻结渲染器；findings 走统一 schema + 别名
```

- **注册不授权**：`register_semgrep()` 只把实例放进 `_REGISTRY`；执行仍需 live `PolicyEngine` 签发的 `RunTicket`，与 EXT-1 完全一致。
- **fs_path 先例复用**：与 bandit/gitleaks 相同，仅豁免网络 scope 校验，取消/依赖/窗口/风险上限/票据全部保留。
- **无跨适配器影响**：`B-04` 证明 semgrep 注册不替换/不影响 built-in trio 与 gitleaks 实例。

---

## 4. 测试用例、命令和实际结果

### 4.1 命令与结果汇总

| # | 命令 | 退出码 | 结果 |
|---|---|---|---|
| 1 | `python tests/test_semgrep_adapter.py` | 0 | **77/77 checks passed** |
| 2 | `python tests/test_semgrep_integration.py` | 0 | **38/38 checks passed** |
| 3 | 17 个相关离线回归套件（见 4.3） | 全 0 | 全绿 |

### 4.2 单元测试覆盖（`tests/test_semgrep_adapter.py`，77 项）

| 段 | 覆盖 |
|---|---|
| A | 注册/身份/门禁、`build_command` 契约、无 registry/auto 引用、`_spawn` 子进程 env 版本检查抑制（真实 `sys.executable` 子进程验证）、severity 映射表 |
| B | 单发现转换：白名单字段、location、description、references、evidence 仅元数据；**`extra.lines`（匹配到的源码）绝不进入任何可观测字段** |
| C | 多发现 + 定位五元组去重（相同 locator → 同一 finding_id） |
| D | 空 results → COMPLETED 0 发现；**空白 stdout → FAILED**（rc=0 与 rc=1 均 fail-closed） |
| E | 无效 JSON / JSON null / 缺 `results` / `results` 非 list / `errors` 非 list → FAILED |
| F | rc=2 带可解析报告 → FAILED 且不采收发现；rc=127 → FAILED |
| G | 超时 → TIMEOUT（runner 可分类），预算透传 |
| H | `path:line` / `path:start-end` / 裸 path（不缺建行号） |
| I | finding_id 跨运行稳定性与区分度 |
| J | 拒绝 home / 盘根 / 不存在目录 / 文件当目录：FAILED 且**零 spawn** |
| K | rules 缺失 / 路径不存在 / 空字符串 → FAILED 且**零 spawn**，**无 registry 回退**；文件型 rules 路径被接受 |
| L | **`errors[]` 非空 → FAILED（扫描不完整）且不采收任何发现**；`paths.skipped` 记入 meta 但不判失败 |
| M | 畸形记录安全跳过并计数，消息无值回显 |
| N | severity 映射（大小写不敏感）与未知取值 fail-closed |
| O | 跨场景残留清扫（41 次观测运行，源码行/指纹/密钥形态全部为零泄露） |

### 4.3 集成测试覆盖（`tests/test_semgrep_integration.py`，38 项）

| 段 | 覆盖 |
|---|---|
| A | 打包布局（`adapters_ext` 已在 pyproject `packages`；磁盘含 semgrep.py） |
| B | 显式注册、重复注册为真 no-op、built-in trio 与 gitleaks 实例不受影响、注册表恰为 5 项、无 policy 查表抛 `GateRequired`、CLI 子进程 `gate-check`、**新子进程中 `main()` 同时注册 semgrep 与 gitleaks**、`--help` 含 `--semgrep-rules` |
| C | planner：无 source_dir → 无 s5；三条件齐备 → s5 追加；二进制缺失/无 rules → 步骤省略；三工具齐备 → 顺序正确；TaskGraph 保留 `target_kind` |
| D | 真实门禁：无票据 `GateRequired`、passive(R0) REFUSED、正常路径（票据目标+本地 rules）、target_kind 双向错配 REFUSED、scope-hash 绑定失效、窗口过期拒发、CANCEL 文件、超时 2 attempts、**有效票据但缺 rules → FAILED 无 spawn（无网络回退）** |
| E | Executor 端到端：COMPLETED+发现、缺二进制 → SKIPPED（preflight）、rc=2 → FAILED、**tool errors → FAILED 不完整且不采收**、无效 JSON → FAILED、报告渲染含规则元数据+severity 来源标注 |
| F | 跨场景残留清扫（9 个场景，结果/日志/journal/报告全部无源码残留）+ journal 含可审计规则元数据 |

### 4.4 回归测试（17 个离线套件，全部 EXIT=0）

| 套件 | 结果 |
|---|---|
| `test_engine` | 30/30 |
| `test_taskgraph` | 35/35 |
| `test_graph_loop` | 25/25 |
| `test_decision` | 44/44 |
| `test_journal_chain` | 12/12 |
| `test_s2_hardening` | 15/15 |
| `test_e2e_lab` | ALL PASSED |
| `test_cli_gate` | 6/6 |
| `test_gate_packaging` | 5/5 |
| `test_check_scope` | 34/34 |
| `test_adapters_gate` | 17/17 |
| `test_p9` | ALL PASSED |
| `test_d2d0_d2d4` | PASS=30 FAIL=0 SKIP=0 |
| `test_d2d1_proccleanup`（冻结） | PASS=21 FAIL=0 SKIP=0 |
| `test_d2d4_f1` | PASS=8 FAIL=0 SKIP=0 |
| `test_d2c0_remediation` | ALL PASSED |
| `test_d2c_r4` | ALL PASSED（1 SKIP：本机无真实首跑 journal，属环境性跳过） |

**未运行**：六项历史测试（`test_findings_integration`、`test_gitleaks_adapter`、`test_ext12_registration`、`test_findings_schema`、`test_ext13f1_stdout`、`test_gitleaks_integration`）——按授权要求不重跑；`test_d2c_first_run`（受控执行套件，需真实 nuclei，不在本轮必要回归面内）。

> 说明：`test_d2d0_d2d4` 本轮为 30 PASS / 0 FAIL。该冻结文件的 D0-21 现为对 `tests/test_d2c_first_run.py` 的**源码契约 AST 检查**（`d2c-run-*` 残留观测为显式非阻断项，无 rc 影响）。这与历史记录中的 ENV-D2C-01 环境失败不是同一断言；**本运行不构成对 ENV-D2C-01 / D-4 / D-7 的裁定或关闭**，相关事项仍待人工裁定。

### 4.5 CLI 端到端验证（真实 `main()`，无任何真实工具执行）

```
python -m vuln_hunter run --scope <expired-window scope.json> --mode safe_scan \
    --target 127.0.0.1:1 --source-dir <tmp>/src --semgrep-rules <tmp> \
    --evidence-dir <tmp>/ev
→ 退出码 2；[Vuln-Hunter Status] REFUSED；[Audit] verify=chain OK (3 record(s))
→ 证据目录仅含 journal.jsonl 与 report.md，未产生任何 attempt 日志（无工具执行）
```
证明 CLI 启动路径（含 semgrep 注册与参数透传）工作正常，且过期窗口被 fail-closed 拒绝、零工具执行。`[E]`

---

## 5. 安全边界验证

| # | 要求 | 验证方式 | 结果 |
|---|---|---|---|
| 1 | 优先调用本机已安装 semgrep，不自动安装、不联网下载规则 | `semgrep_binary()` 仅 PATH + `~/Tools/semgrep/` 解析；本机**未安装**（`which semgrep` 无、`~/Tools` 仅 nuclei/osv-scanner），按 nuclei/gitleaks 既有模式优雅降级；rules 必须本地提供，缺 rules → FAILED 无 spawn 无 registry 回退 | ✅ `[E]` |
| 2 | 默认本地扫描，仅扫描授权 scope 内代码 | 复用 `fs_path` 先例；net scope 检查按既有豁免规则跳过，窗口/风险/票据/取消/依赖全部保留；适配器级路径守卫拒绝盘根与 home | ✅ `[E]` |
| 3 | 不绕过 Policy / RunTicket / Runner / 执行门禁 | 适配器未实现自己的执行入口；`_run()` 只经继承的 `execute()` 调用；无票据抛 `GateRequired`；passive(R0) REFUSED | ✅ `[E]` |
| 4 | 安全参数传递，避免 shell 注入 | `subprocess.run(list, ...)`，无 `shell=True`，无字符串拼接命令 | ✅ `[E]` |
| 5 | 正确解析结构化输出并映射到 Findings | 77+38 项检查逐字段核对；统一 `Finding` 13 字段 schema；`from_dict` finding_id 可复核 | ✅ `[E]` |
| 6 | 明确处理工具缺失/超时/非零退出/JSON 无效/扫描中断/结果不完整 | 缺二进制 → preflight SKIPPED；超时 → TIMEOUT；rc∉(0,1) → FAILED；空白/无效 JSON → FAILED；`errors[]` 非空 → FAILED 不完整 | ✅ `[E]` |
| 7 | 不将失败或不完整报告为成功/无漏洞 | 上述全部 fail-closed 分支；空白 stdout 在 rc=0 与 rc=1 下均 FAILED；不完整扫描**不采收任何发现** | ✅ `[E]` |
| 8 | 保留工具来源、扫描状态、发现结果与执行证据 | `tool="semgrep"`、`severity` 来源标注、`meta`（records_seen/used/skipped、errors_seen、paths_skipped）、attempt 日志含命令行与规则/文件/行三元组、journal 全程记录 | ✅ `[E]` |
| 9 | 不改变其他 Adapter 行为 | `B-04` 实例同一性；17 个回归套件全绿（含 gitleaks 相关 planner 顺序断言 C-06） | ✅ `[E]` |
| 10 | 源码内容不外泄 | `extra.lines`（匹配到的源码）与 `fingerprint` **从不读取**；白名单仅取元数据；跨 41+9 个观测场景残留清扫零泄露 | ✅ `[E]` |

---

## 6. 未完成事项和已知限制

1. **本机未安装 semgrep，无法做真实二进制扫描验证** `[E]`。授权明确"不自动安装依赖、不自动联网下载规则"，故未安装。所有行为（退出码语义、JSON 解析、白名单、失败路径、门禁集成）均经 mock 缝 + 真实 gate/planner/executor/journal/report 链路验证；**真实 semgrep 输出的字段形态与退出码需在安装后另行验证**（见下）。
2. **`--metrics off` / `SEMGREP_ENABLE_VERSION_CHECK=false` 未经真实 semgrep 验证** `[U]`。二者均为长期稳定 flag / 无害 env var；若某版本移除 `--metrics`，该版本将以非零退出 **FAILED（fail-closed）**，不会静默降级。
3. **semgrep 版本要求未验证** `[U]`：实现面向带 `scan` 子命令与 `--json` 的现行 semgrep；未做最低版本探测（EXT-1 对 gitleaks 有 `>= 8.18` 声明，此处因无法实测而暂不声明具体版本）。
4. **`--config` 只做存在性检查，不校验规则内容** `[I]`：规则文件是否有效由 semgrep 自身判定（非零退出 → FAILED）。
5. **`paths.skipped` 不判失败** `[I]`：被跳过的文件（二进制、超大文件等）记入 meta 以示透明，但视为正常行为而非"扫描不完整"；"不完整"仅由 `errors[]` 非空判定。
6. **`s5-semgrep` 的 `kind` 为 `"generic"`** `[I]`：`taskgraph._KIND_BY_ADAPTER` 未新增条目（gitleaks 现状相同）；`kind` 仅作标签，不影响调度与门禁。如后续需要，可在未冻结的 `taskgraph.py` 增一行。
7. **真实扫描验证清单（待 semgrep 可用时单独授权执行）**：① 单目录 + 单条本地规则 → COMPLETED 与 finding 字段核对；② `--metrics off` 与 env 抑制是否被接受；③ 真实 `errors[]` 出现时的退出码；④ 一次超时场景；⑤ 报告中 severity 来源标注可读性。

---

## 7. Git diff 与冻结文件核验结果

### 7.1 HEAD 与工作区

- HEAD：`9913c50bff074833a1ea14204a353b80f313558a`（与本轮开始前一致，**未做任何 Git 写操作、未 commit**）。`[E]`
- 工作区 `M` 文件仍为基线 5 个（`pyproject.toml`、`tests/test_engine.py`、`tests/test_taskgraph.py`、`vuln_hunter/__main__.py`、`vuln_hunter/planner.py`）——**原有未提交变更全部保留**；其中 `__main__.py` 与 `planner.py` 的 diff 同时包含先前的 EXT-1 内容与本轮 EXT-2 增量（已逐行核对，EXT-1 内容完整在位）。`[E]`
- 新增未跟踪文件 3 个（`vuln_hunter/adapters_ext/semgrep.py`、`tests/test_semgrep_adapter.py`、`tests/test_semgrep_integration.py`）。`[E]`
- `git diff --stat`：`5 files changed, 83 insertions(+), 4 deletions(-)`。`[E]`

### 7.2 冻结文件哈希（实施后实测，与基线逐一相同）

| 文件 | SHA256（前 16） | 状态 |
|---|---|---|
| `vuln_hunter/adapters.py` | `65ece047b13784e0…` | 未变 |
| `vuln_hunter/runner.py` | `29d71dc54f34bc02…` | 未变 |
| `vuln_hunter/report.py` | `59caebb3094896f1…` | 未变 |
| `tests/test_d2d1_proccleanup.py` | `1cd2b9483c4869c4…` | 未变 |
| `tests/test_d2d0_d2d4.py` | `840046857997917b…` | 未变 |

附加保护（既有基线口径，同样未变）：`vuln_hunter/findings.py` `544729a84dcddc73…`、`vuln_hunter/adapters_ext/gitleaks.py` `630139aa1f5187b6…`。

### 7.3 未触碰项确认

未触碰：原始备份、桌面归档（`DVS-V1-ARCHIVE/`）、管理目录（`DVS-V1-MANAGEMENT/`）、过期构建副本 `dualverify_sentinel-0.1.0/`、18 个空 `evidence/engine-*` 目录、G15 FAIL / `EXECUTION_INTEGRITY=NOT_OK` / C14 FAIL / 任何历史 UNKNOWN、六项测试阶段状态。未执行 `git reset/clean/checkout/restore/stash`。`[E]`

### 7.4 本轮验证产生的副产物（未删除，待人工确认）

| 路径 | 说明 |
|---|---|
| `output/vuln_hunter_report.md`（2,724 B） | §4.5 CLI 端到端验证写入；`output/` 已在 `.gitignore` 第 5 行忽略，不影响 Git 状态 |
| `%TEMP%\tmp.AvXfUFcabf\` | 同一次验证的证据目录（journal.jsonl + report.md）；安全删除策略阻止了自动清理，故原样保留 |

如需删除，请明确指示；我不会在未获确认前删除任何文件。

---

## 8. 回滚步骤（未执行）

EXT-2 为**纯增量**改动（新文件 + 注册调用 + planner 步骤 + 一个 CLI 参数），回滚无数据损失、无残留：

1. **撤销注册**：删除 `vuln_hunter/__main__.py` 中 `from .adapters_ext import register_gitleaks, register_semgrep` 里的 `register_semgrep` 及 `register_semgrep()` 调用行（恢复为仅 `register_gitleaks`）。
2. **撤销 planner**：删除 `vuln_hunter/planner.py` 中 `from .adapters_ext.semgrep import semgrep_binary`、`semgrep_rules` 形参、`s5-semgrep` 步骤块、以及 `build_plan(...)` 调用处的 `semgrep_rules=args.semgrep_rules or None`。
3. **撤销 CLI 参数**：删除 `--semgrep-rules` 参数定义；`--source-dir` 帮助文本可保留或还原。
4. **删除新增文件**：`vuln_hunter/adapters_ext/semgrep.py`、`tests/test_semgrep_adapter.py`、`tests/test_semgrep_integration.py`；`vuln_hunter/adapters_ext/__init__.py` 中的 semgrep 导出可一并移除（不影响 gitleaks）。
5. **核验**：复核冻结五文件哈希不变；重跑 §4.4 的 17 个回归套件确认全绿；确认 `git status` 的 5 个 `M` 回到 EXT-1 状态。

> 替代方案（更安全、可逆性最强）：暂不删除文件，仅把 `main()` 中的 `register_semgrep()` 调用注释掉并停用 `--semgrep-rules` 默认值——适配器随之完全不参与任何运行，等效于功能关闭而代码留档。

---

## 9. EXT-2 最终状态

# **PASS**（附 1 项环境性限制）

**判定依据**：
- 功能完整落地：适配器 + 注册 + planner + CLI + 统一 Finding + 报告链路全部就位并实测通过（77/77 + 38/38）。
- 安全要求逐条满足（§5，10/10）。
- 不修改任何冻结文件，不触碰任何保护对象，未关闭任何未决裁定。
- 17 个相关回归套件全绿，无任何既有行为改变。
- **唯一限制**：本机未安装 semgrep 且授权禁止自动安装，故真实二进制扫描未验证（§6-1/§6-7）。这是**环境限制而非实现缺口**——适配器在工具缺失时按既有模式优雅降级（SKIPPED），所有可离线验证的语义均已验证。

---

*本报告为 EXT-2 实施交付物。未自动提交 Git commit；等待人工验收。*

---

## 10. Remediation 记录（CR-01 / CR-02 / CR-03，2026-11-08）

> 本节为**纯追加**；上文 §1–§9 原文、全部历史结论与状态标注均未改写。

**授权**：`DualVerify-Sentinel V1 — EXT-2 Code Review Findings Remediation`，仅授权修复 `CR-01`（退出码契约）、`CR-02`（扫描完整性信号）、`CR-03`（报告与日志字段净化）；明确「不自动处理其他审查问题」（故 `CR-04` / `CR-05` / `CR-06` 未改动）。

**修改文件（3 个，全部为本报告 §2 登记的新增文件，均为未跟踪文件）**：

| 文件 | 修复前 → 修复后 | 修复后 SHA256（前 16） |
|---|---|---|
| `vuln_hunter/adapters_ext/semgrep.py` | 460 → 621 行 | `434dfcfa90c85ad46…` |
| `tests/test_semgrep_adapter.py` | 551 → 701 行 | `403c683af51ec5bf4…` |
| `tests/test_semgrep_integration.py` | 658 → 752 行 | `1c084bd8f9727caed…` |

未修改 `__main__.py` / `planner.py` / `adapters_ext/__init__.py` / `pyproject.toml`，也未修改任何冻结文件与既有报告正文。`git diff --stat` 仍为 §7.1 登记的 `5 files changed, 83 insertions(+), 4 deletions(-)`（全部为 EXT-1/EXT-2 既有未提交变更），证明本轮未触碰任何已跟踪文件。

**修复要点**：
- `CR-01`：成功退出码由 `rc ∈ (0,1)` 收窄为 **`rc == 0`**；docstring 契约重写，删除「1 = findings found」的未验证表述；findings 完全取自合法完整的 `results[]`，任何非零退出均 `FAILED` 且不采收发现。
- `CR-02`：`errors` 键缺失由「乐观默认 `[]`」改为 **`INCOMPLETE → FAILED`**；显式检查 `paths` 与 `paths.skipped`；跳过项必须带 reason，否则 `FAILED`。因冻结 `runner.STATUS_PRIORITY` 无 `PARTIAL`，采用**兼容方案**（不新增 status 值）：三态由 `meta["completeness"]` + `detail` 前缀 `[completeness=...]` + journal 表达，`INCOMPLETE → FAILED`（不采收），`PARTIAL → COMPLETED` 但显式标注「非完整扫描」。
- `CR-03`：新增 `_sanitize()` / `_log_line()`，对白名单字段**值**清除终端控制字符、换行与 tab，并转义 Markdown 元字符；文本保留（转义而非删除），不丢记录；`extra.lines` / `fingerprint` 仍不读取。

**测试结果**：单元 `105/105`（EXIT 0）、集成 `46/46`（EXIT 0）、相关离线回归 17 套（16 首轮全绿；冻结套件 `test_d2d0_d2d4` 首轮 FI-03 为时间依赖型 flaky，复跑 5 次均 30/30 通过，详见 Remediation 报告 §4）。未重跑六项历史测试，未运行真实 semgrep，未安装工具。

**状态限定**：§9 的 `PASS` 结论现受 `CR-06` 约束 —— 全部验证仍基于 mock 缝，真实二进制端到端扫描 **UNVERIFIED**。建议以 `CONDITIONAL ACCEPT` 看待本次修复，完整 `PASS` 需在真实 semgrep 可用并单独授权后补验。

完整差异、测试明细、冻结文件哈希复核、剩余风险与最终状态建议见 **`docs/EXT-2-REMEDIATION-REPORT.md`**。
