# D2-D 只读架构评估与执行方案

- 项目：DualVerify-Sentinel（`<PROJECT_ROOT>`）
- 日期：2026-10-31
- 性质：只读架构评估 + 方案设计。本轮**未修改任何代码/配置/模板**、未启动任何服务或工具、未产生任何网络请求。
- 结论标签：**[证据]** = 已有测试/运行证据确认；**[推断]** = 基于源码分析；**[未验证]** = 尚无证据。

---

## 1. 当前架构图（实际调用链）

```
CLI (__main__.py)
 └─ Gate: run_gate() —— 以真实子进程 python -m vuln_hunter.gate_check 校验 scope 文件（fail-closed）
     └─ PolicyEngine (policy.py) —— 模式风险天花板 / window_ok / target_allowed / adapter_allowed / issue_ticket
         └─ Planner.build_plan (planner.py) —— 静态计划（nuclei_ids / nuclei_tags / target_kind）
             └─ TaskGraph.from_plan (taskgraph.py) —— 预算 max_nodes=32 / max_spawns=8 / max_spawn_depth=2；fingerprint 去重；环检测
                 └─ AutonomousLoop (loop.py, --loop)
                     ├─ DecisionEngine (decision.py) —— RUN_NEXT / STOP（当前输入：executed/pending/last_step 计数与摘要）
                     ├─ P9 规则层 (p9.py, --p9) —— 纯规则；事件交 loop 落 Journal；子节点经 graph.add_node(dynamic=True)
                     └─ Executor (runner.py)
                         ├─ 门禁阶梯：cancel → deps → quarantine → window → adapter_allowed → target_allowed(scope) → preflight
                         ├─ 每 attempt 新发 RunTicket → Adapter.execute()（内部 8 重门禁再验，R2 需 scope-hash 绑定）
                         ├─ attempt 循环：max_attempts=2，重试间隔 TIMEOUT=10s / 其他=5s，no_retry 跳过
                         └─ Journal（每步 step_start/attempt_*/step_end，hash 链 fail-closed）
                             └─ Report (report.py) —— audit anchor + synthetic 统计隔离
```

## 2. A 方向：当前架构能力盘点

| 环节 | 已实现能力 | 已验证证据 | 尚未验证 | 已知安全限制 |
|---|---|---|---|---|
| CLI | argparse 全参数、gate 子进程前置 | test_cli_gate 6/6【证据】；D2-C 首跑实跑【证据】 | CLI 层对畸形参数组合的容错路径 | 总流程 timeout=900s（测试脚本层） |
| Gate | scope 文件经真实子进程校验，不可跳过 | test_check_scope 34/34、test_gate_packaging 5/5【证据】 | — | gate 不可用即拒绝运行（fail-closed，源码 L8-11）【证据】 |
| Policy | 风险天花板、window、scope、ticket | 首跑 policy_verdict 三步全过【证据】；decision 44/44 覆盖 | 多目标/多模板组合下的边界 | vuln_validation 天花板 R2 |
| Ticket | 每 attempt 新发；adapter.execute 内 8 重门禁再验 | test_adapters_gate 17/17【证据】 | — | R2 需 scope-hash 绑定 ticket |
| Planner | 静态两步计划 + nuclei_ids/tags 注入 | 首跑计划【证据】 | 复杂计划形态 | — |
| TaskGraph | 预算、fingerprint 去重（含动态节点，重命名不可绕过）、环检测、状态机 | test_taskgraph 35/35、test_graph_loop 25/25【证据】 | 预算耗尽时的运行中行为仅单测覆盖 | 静态节点不进指纹库（源码 L182-186 设计）【证据】 |
| DecisionEngine | RUN_NEXT/STOP、失败聚合 | decision 44/44【证据】 | 决策输入不含 findings 内容/超时分类（P10 缺口） | 纯规则 |
| Runner | 门禁阶梯、幂等、attempt/retry、CANCEL 文件、synthetic 标记 | engine 30/30、s2_hardening 15/15、真实首跑【证据】 | 真实超时/杀进程后的端到端行为（见 C 节） | 单进程设计 |
| Adapter | 三适配器；nuclei 命令契约（-duc -dr -ni -rl 20 -c 10 -severity -si 30）；timeout 分类；非零退出=FAILED 携带部分结果 | 真实首跑 COMPLETED + JSONL 解析【证据】；D2-B fake 全场景【证据】 | 真实超时场景、宽扫行为 | **Windows kill 仅及直接子进程**（源码 L352 自认）【证据】 |
| Journal | hash 链、fail-closed append、外部锚点、篡改检测 | journal 12/12；真实首跑链 OK（21 条）；E2E 篡改场景【证据】 | 磁盘满/权限故障注入 | **单进程无锁**（docstring 自认）【证据】；**尾截断无外部锚点不可检测**【证据】 |
| Report | 锚点、synthetic 统计隔离 | 真实首跑报告与锚点一致【证据】 | report 写失败时的行为（**未验证**） | — |

## 3. B 方向：P9 与动态编排

**触发/拒绝条件**（p9.py 合同，全部 fail-closed）【证据】：仅 COMPLETED、非隔离、findings 全 dict 且 type==nuclei_finding、模板 id 合法；子任务 target=parent.target **逐字**、risk 不超父实际执行风险与模式天花板、timeout=min(父,240)、scope 复检、一决策一子、等价节点去重。

**宽扫描 vs focused 扫描的本质区别**【推断，证据充分】：`nuclei_ids` 为空的节点是宽扫描（受 -severity 过滤），其 finding 模板不在任何节点参数里 → 等价检查通过 → spawn focused 复扫有意义；`nuclei_ids==[模板]` 的 focused 节点自身即等价节点 → 正确去重。D2-B（宽）spawn、D2-C（focused）拒绝，均为同一合同的正确输出（R4 收尾已实证对照）。

**真实环境合法 SPAWNED 场景设计**（不放宽合同、不伪造 finding）：

- **A1（零核心改动）**：CLI 不传 `--nuclei-id`，让 planner 生成宽扫节点；lab 模板 severity=high 会被宽扫命中（lab 目录在默认模板路径内，D2C-P8 已证可达【证据】），finding 模板 `d2b-synthetic-lab-echo` 不在任何节点参数中 → P9 SPAWN。风险：**请求量放大**——全部 ~13,690 模板将对唯一 lab 目标发请求（-rl 20 限速 + loopback 缓解；预计数分钟、数千 loopback 请求）。请求全部限定 127.0.0.1:18080（scope 强制）【推断】。
- **A2（最小核心改动）**：CLI 增加 `--nuclei-tags synthetic` 透传（planner.build_plan 已支持 nuclei_tags 参数【证据】），宽扫缩窄为仅 synthetic 标签模板 → 请求量从数千降到个位数。改动点仅 CLI 一处透传，不动 p9/taskgraph/policy。**需单独授权**。
- 两案的子任务均受原始授权约束：target 逐字继承（p9.py L220）、模板来自 finding、risk R2≤R2、scope 复检、depth+1≤2【证据】。

**验收沿用 R4 收尾的三分类**：SPAWNED（目标=127.0.0.1:18080）/ EXPECTED_REJECTION / UNEXPECTED_FAILURE，Journal 证据必须保留原始 reason。

## 4. C 方向：执行可靠性风险清单（按严重度排序）

| # | 严重度 | 风险 | 状态标签 | 缓解/验证途径 |
|---|---|---|---|---|
| 1 | 高 | **Windows 孙进程残留**：timeout 时 `proc.kill()` 仅及直接子进程（adapters.py L352 源码注释自认）；`proc.wait(timeout=10)` 超时后静默继续 | 【证据】源码自认；真实超时场景行为【未验证】 | nuclei 自身不 spawn 子进程【推断】；D2-D-1 强制超时演练 + tasklist 复查 |
| 2 | 高 | 宽扫请求放大（A1 方案固有） | 【推断】 | -rl 20 限速 + loopback + 单目标；优先 A2 |
| 3 | 中 | Journal 尾截断在无外部锚点时不可检测（docstring 自认）；report 写失败则锚点缺失 | 【证据】机制；report 失败路径【未验证】 | report_written 已含 anchor【证据】；D2-D-4 故障注入 |
| 4 | 中 | Journal 单进程无锁，并发写破坏链 | 【证据】docstring | 当前单进程设计安全；P10 引入并发前必须加锁 |
| 5 | 中 | 超时分类（classify_timeout）依赖 stderr phases 解析，nuclei 输出格式变化会降级为 UNKNOWN | 【推断】 | 真实首跑 phases 已采到【证据】；D2-D-1 实证 |
| 6 | 低 | 非零退出携带部分 findings → FAILED（不报成功）——行为正确但 P9 靠 status gate 防护，属单点防线 | 【证据】设计意图 + T1 注释 | 保持 |
| 7 | 低 | 重试固定 5/10s，无指数退避；重试会重复对目标发请求 | 【证据】源码 | lab 场景可接受 |
| 8 | 低 | 环境噪声（Defender、自启程序）致初始化方差（D2-C-P7 已证 78s–351s–超时谱） | 【证据】 | 冷启动窗口检查已列入流程 |

## 5. D2-D 分阶段测试矩阵

| 阶段 | 目的 | 前置/授权 | 预期行为与成功标准 | 停止条件 | 证据采集 | 真实工具/网络 |
|---|---|---|---|---|---|---|
| **D2-D-0 离线扩展** | 补齐离线覆盖：超时分类、部分 JSONL+非零退出、fake 子进程 kill 后残留复查（spawn sleep 子进程→kill→tasklist 断言） | 现有授权内（离线单测） | 全部新单测通过；无服务/无网络 | 任一失败即停 | 测试输出+退出码 | 否/无 |
| **D2-D-1 超时与清理实演** | 真实 nuclei 强制超时（--nuclei-timeout 极小值），验证 TIMEOUT 分类、attempt 循环、journal 完整、进程零残留 | 需**单独授权**：单目标 127.0.0.1:18080、单模板、观测+kill-switch 沿用 D2-C | 分类为 TIMEOUT_*、≤2 attempts、链 OK、无进程残留 | 非回环连接/进程残留未清理/链断裂 | journal+attempt log+tasklist 快照 | **是/仅 loopback** |
| **D2-D-2 P9 SPAWNED 实演** | 真实环境验证动态子任务全流程（spawn→add_node(dynamic)→子执行→journal 7 事件） | 需**单独授权**；方案 A2 优先（需 CLI 透传小改，先授权）；A1 需告知请求放大 | R4 分类=SPAWNED 且 spawn.target=127.0.0.1:18080；子任务状态 COMPLETED；journal 含 p9_trigger/p9_checks/p9_spawn | 合同外拒绝/目标偏离/链断裂 | journal 全文+R4 分类输出 | **是/仅 loopback** |
| **D2-D-3 取消/杀进程演练** | CANCEL 文件 + 运行中 taskkill 的清理与审计一致性 | 需**单独授权**（同 D2-D-1 边界） | 步骤 CANCELLED、链 OK、无残留 | 同上 | journal+进程快照 | **是/仅 loopback** |
| **D2-D-4 Journal/Report 故障注入** | evidence 目录只读化/磁盘故障模拟 → 验证 fail-closed 与审计一致性 | 离线（临时目录故障注入） | run 以审计失败退出，绝不静默 | — | 测试输出 | 否/无 |

**优先级**：D2-D-0 → D2-D-4（全离线，可合并一批）→ D2-D-1 → D2-D-3 → D2-D-2（最复杂，放最后）。

## 6. E 方向：P10 本地重规划前置条件

| 能力 | 现状 | P10 缺口 |
|---|---|---|
| 状态/证据模型 | Journal 事件流完备；step_end 含 status/findings/meta(timeout_class/phases)【证据】 | 需把 findings/meta 提升为决策输入（当前 decision 仅见计数与摘要【证据】） |
| 决策输入完整性 | {executed, pending, last_step} | 增量输入：失败原因分类、quarantine、timeout_class |
| 任务图变更审计 | p9_* 7 事件完备【证据】 | 需 plan_revision 事件类（重规划落 Journal） |
| 预算/循环限制 | max_steps 8 / nodes 32 / spawns 8 / depth 2【证据】 | 需独立 replan_count 预算（建议=1） |
| scope/risk 继承 | P9 逐字继承 + scope 复检【证据】 | 重规划沿用同一继承规则，禁止扩 scope |
| 失败恢复/终止 | CANCEL 文件 + deps 链【证据】 | 需"重规划后仍失败即永久 STOP"的终止规则 |

**P10 最小可行范围**【推断】：一次性 re-plan——输入为首个 FAILED/TIMEOUT 步骤的分类信号；输出≤1 个替代节点（同 adapter、同 target、同 risk、预算 replan=1）；复用 P9 的 add_node(dynamic=True) 权威通道与全部门禁；**不实现**循环重规划、多候选、跨 adapter 替换。

## 7. 各阶段所需单独授权范围

- D2-D-0 / D2-D-4：现有离线授权即可（无服务、无网络、无真实工具）。
- D2-D-1：真实 nuclei ×1–2 次运行（超时场景），单目标单模板，观测+kill-switch 同 D2-C 标准。
- D2-D-3：真实 nuclei ×1 次运行 + 运行中取消操作。
- D2-D-2：真实 nuclei ×1 次运行；若选 A2 需先授权 CLI 透传小改（一处，diff≤5 行）；若选 A1 需明确接受请求放大。
- 每阶段共用：绝对路径纪律、执行前哈希核对、R8 强制后置核验、事后立即停止。

## 8. 禁止事项与停止条件（沿用并强化）

禁止：真实扫描未单独授权即执行；修改核心安全链路（p9/taskgraph/policy/runner/gate/journal）；放宽 P9 合同或伪造 finding；非 loopback 目标；Interactsh/重定向/代理；触碰旧项目/已发布版；读取凭据；Git 写操作。
停止条件：任何非回环连接；进程残留未清理；Journal 链断裂；spawn 目标偏离 parent.target；合同外拒绝原因；探针进入冷启动窗口超时。

## 9. 项目成熟度重评估

- **受控单目标合成验证：已闭环**【证据】——S0–S3 + D2-B + D2-C + 收尾，315/315 离线回归，真实首跑全链路（含 P9 合同内拒绝、Journal 锚点、synthetic 隔离）实证。
- **执行可靠性：中等**——正常路径已实证；超时/取消/故障注入路径仅单测覆盖，真实环境【未验证】。
- **动态编排：合同完备、真实 SPAWNED 路径未实证**【未验证】（focused 自扫场景下被正确去重是预期行为）。
- **距离生产扫描能力**：尚远——多目标、真实授权流、并发与文件锁、Windows 进程深度清理、宽扫请求治理均未开始。
- P10 就绪度：前置条件中约 60% 已具备（预算/继承/审计基础），缺决策输入完整性与重规划事件模型。

---

## 本轮检查清单与副作用声明

**检查过的文件**：vuln_hunter/{__main__, adapters(全), journal(全), runner(全), p9(全), gate(全), taskgraph(结构), loop(调用点), planner(参数), report(隔离逻辑), decision/gate_check/policy(经调用点与测试引用)}；tests/ 全部 15 个文件名与历史结果；D2-C 首跑 Journal/报告（%TEMP%\d2c-run-h82jj6hl）；D2-B 场景 B Journal 与 bootstrap（%TEMP%\d2b-b-sh244vrn）。
**写入**：仅本报告文件（docs/ 目录与本文档，授权明确允许的 Markdown 交付物）。
**网络请求**：零。**服务/Nuclei 启动**：零。**代码/配置/模板修改**：零。
**待人工决定**：① D2-D 各阶段是否批准及顺序；② A1（零改动、请求放大）与 A2（CLI 透传小改）二选一；③ D2-D-1 超时值与次数上限。
