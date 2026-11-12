# DualVerify-Sentinel V1 — EXT-2 Code Review（独立只读代码审查）

- **生成时间**：2026-11-08 22:51:21（本地时间）
- **审查对象**：`EXT-2 Semgrep Adapter` 实现（承接 `docs/EXT-2-IMPLEMENTATION-REPORT.md` 的 `PASS（附 1 项环境性限制）`）
- **仓库**：`C:/Users/ZTL/Desktop/DualVerify-Sentinel`，HEAD `9913c50`，分支 `main`
- **审查性质**：独立、只读、为人工验收提供依据；**不自动修复**
- **本报告是本次审查唯一新建文件**。除本报告外，未修改、未删除、未重命名任何既有文件。

---

## 0. 结论速览

| 项目 | 结论 |
|---|---|
| **BLOCKER** | **2 项**：`CR-01`（退出码契约，代码层）、`CR-06`（真实二进制端到端验证缺口，验收证据层） |
| **NON-BLOCKER** | **4 项**：`CR-02`（完整性信号乐观默认，MEDIUM）、`CR-03`（Findings 字段未净化，MEDIUM）、`CR-04`（路径 containment，LOW）、`CR-05`（rules 参数面/编码健壮性，LOW） |
| **是否建议接受 EXT-2** | **不建议在修正前确认无条件 `PASS`**；建议 **CONDITIONAL ACCEPT（有条件接受）**，条件见 §6 |
| **是否需要修复后重新测试** | **是**。范围与禁止项见 §6.3 |
| **总体代码质量** | 良好：执行注入面闭合、门禁未被绕过、白名单抽取与源码防泄漏扎实、fail-closed 主干完整。主要风险集中在「**退出码契约未经真实工具验证**」与「**全部验证基于 mock**」这两点 |

> 审查立场：只报告有源码依据的真实风险，不把「与既有 bandit/gitleaks 一致的架构取舍」当作 EXT-2 缺陷，也不为凑数制造问题。六维度中 **Policy/RunTicket、Planner/注册** 两个维度判定为**通过（未发现 EXT-2 引入的问题）**，正面依据见 §2。

---

## 1. 审查范围与方法

### 1.1 受审六文件（只读精读，含行号核准）

| 文件 | 状态 | 行数 |
|---|---|---|
| `vuln_hunter/adapters_ext/semgrep.py` | 新增 | 460 |
| `vuln_hunter/adapters_ext/__init__.py` | 修改 | 33 |
| `vuln_hunter/planner.py` | 修改 | 94 |
| `vuln_hunter/__main__.py` | 修改 | 249 |
| `tests/test_semgrep_adapter.py` | 新增 | 551 |
| `tests/test_semgrep_integration.py` | 新增 | 658 |

### 1.2 参考接口（只读，用于判断是否偏离既有契约）

`vuln_hunter/adapters.py`（冻结）、`vuln_hunter/findings.py`（基线）、`vuln_hunter/policy.py`、`vuln_hunter/report.py`（冻结）、`vuln_hunter/runner.py`（冻结）、`vuln_hunter/adapters_ext/gitleaks.py`（EXT-1 基线）、`pyproject.toml`。

### 1.3 只读执行边界核验（本次审查实测）

```
git rev-parse --short HEAD  -> 9913c50   (未变)
git branch --show-current   -> main      (未变)
git status --short          -> 与 EXT-2 实施后状态一致，未见本轮新增写入
docs/EXT-2-CODE-REVIEW.md   -> 审查开始时 ABSENT（确认非覆盖写入）
```

冻结/基线文件 SHA256 实算值（全程只读，审查前后必然未变）：

```
65ece047b13784e0efbf00bd71166279734ea150a90ec56db5830bd551098f59  vuln_hunter/adapters.py
29d71dc54f34bc024bde13cc8ec5fcac2745fddeb676ad302aaa5320ebcd842c  vuln_hunter/runner.py
59caebb3094896f1a6eb0e63de16b87d59c52a6512a77d2e0661a54e60761683  vuln_hunter/report.py
544729a84dcddc738e2e9cd6af187c8afc7af8ace06c619ba76ec3ebd322b33d  vuln_hunter/findings.py
630139aa1f5187b62b06b2f6f4ff1c77d0c62892eb9d40aff1a165e01522937a  vuln_hunter/adapters_ext/gitleaks.py
1cd2b9483c4869c4fbad4ecadeafaad8b67a1396b69d8694bb62852a2c194c13  tests/test_d2d1_proccleanup.py
840046857997917bec2dd542c7af6819261001af42bce5a6aa14684bf668aaf9  tests/test_d2d0_d2d4.py
```

前五项与 EXT-2 实施阶段登记的基线值一致；五个冻结文件均未被触碰。

### 1.4 未执行的操作

- 未运行任何测试（包括两个 EXT-2 测试套件与回归套件）；
- 未运行 `semgrep`，未安装任何工具，未联网下载规则；
- 未执行任何 Git 写操作（`commit`/`reset`/`clean`/`checkout`/`restore`/`stash` 一律未用）；
- 未清理两个验证副产物（`output/vuln_hunter_report.md`、`%TEMP%\tmp.AvXfUFcabf\`）；
- 未修改历史证据、历史测试、`docs/EXT-2-IMPLEMENTATION-REPORT.md` 或任何验收状态文件；
- 未改写 `G15 FAIL`、`EXECUTION_INTEGRITY=NOT_OK`、`C14 FAIL` 与任何历史 `UNKNOWN`；六项测试阶段仍未关闭，本报告不将其描述为已通过。

### 1.5 关于外部文档的性质声明

`CR-01` 引用了 Semgrep 官方 CLI 退出码文档（只读外部参考，来自 `semgrep.dev` CLI reference / getting-started）。该信息**仅作辅助佐证**，**不是本机实测**，**不是唯一依据**：`CR-01` 的判定主体是 `semgrep.py` 源码（`build_command` 未传 `--error`）与 `gitleaks.py` 的逐字对照、以及测试对 `rc=1` 的建模。本机未安装 semgrep 且授权禁止安装，故**所有关于真实工具行为的推论均标注为「待真实二进制验证」**，不伪装成已确认事实。

---

## 2. 六维度逐项结论

### 2.1 执行安全 —— **通过（无 shell 注入 / 无自动安装 / 无隐式联网配置）**

- `semgrep.py:136-139` 命令以 `list[str]` 构造；`semgrep.py:303-304` `subprocess.run(cmd, ...)` **无 `shell=True`**，每个参数独立 argv，杜绝 shell 元字符注入。目标目录与规则路径均为独立元素，不拼接字符串。
- `semgrep.py:301` 复用 `adapters.py:39-54` 的 `tool_env()`（剥离代理变量、`NO_PROXY=*`）；`:302` 追加 `SEMGREP_ENABLE_VERSION_CHECK=false`；`:138` `--metrics off`；`build_command` 明确不含 `registry`/`auto`。
- `semgrep.py:113-119` `preflight()` 在缺二进制时返回错误，**不自动安装**；`planner.py:82` 在二进制不可解析时不生成步骤。
- `semgrep.py:184-189` 明确声明并实践：raw stdout 只作为局部字符串，不写入 log / detail / meta / journal / 异常文本；`proc.stderr` 从不读取。
- 遗留小面见 `CR-05`（LOW）：`--config` 值未显式拒绝 registry 特殊值 / 以 `-` 开头的值；`text=True` 未指定 encoding。均非 shell 注入。

### 2.2 Policy 与 RunTicket —— **通过（gate 未被绕过）**

- `SemgrepAdapter` 只实现 `_run()`（`semgrep.py:141`），**未覆盖** `ToolAdapter.execute()`；`adapters.py:148-220` 的最终门禁完整保留：live `PolicyEngine`、`isinstance(ticket, RunTicket)`、adapter 身份、`scope_sha256`、mode 一致性、`target_kind` 双向一致、`step.target == ticket.target`、`adapter_allowed` 风险上限、`window_ok()`。
- `semgrep.py:434-454` `register_semgrep()` 与 `gitleaks.py:306-326` 同构：显式、幂等、通过 live 模块属性访问 `_REGISTRY`、不替换已有实例；注册本身不授予执行权。
- `target_kind="fs_path"`（`planner.py:89`）与 bandit/gitleaks 先例一致；`adapters.py:213-216` 与 `policy.py:172` 仅**豁免网络 scope 校验**，窗口/mode/风险上限/取消/依赖全部保留——这是既有架构边界，不是 EXT-2 绕过。
- 集成测试 `test_semgrep_integration.py:D-01~D-08`（`:412-529`）使用**真实 `PolicyEngine`/`Executor`** 覆盖：无 ticket 抛 `GateRequired`、passive(R0) 拒绝 R1 且零 spawn、`target_kind` 双向 mismatch、scope 内容变更后 ticket 失效、过期窗口 `PolicyRefusal`、有效 ticket 下 adapter 路径守卫、有效 ticket 下缺 rules → FAILED 零 spawn；`D-09/D-10` 覆盖 CANCEL 与超时重试。覆盖充分，未发现门禁缺口。
- 例外说明：`fs_path` 无 source-root containment，见 `CR-04`（LOW，既有边界，非 EXT-2 引入）。

### 2.3 扫描完整性 —— **主干通过，存在 1 个 BLOCKER 与 1 个 MEDIUM 缺口**

已正确 fail-closed 且不采收 findings 的路径：`rc not in (0,1)`（`:191-193`）、空白 stdout（`:195-203`）、非法 JSON（`:205-209`）、非对象（`:210-211`）、`results` 缺失/非 list（`:213-217`）、`errors` 非 list（`:218-220`）、`paths`/`paths.skipped` 非容器（`:221-226`）、**`errors[]` 非空 → FAILED 且 `records_used=0`**（`:228-245`）、超时（`:175-177`）、spawn 异常（`:178-181`）。`errors[]` 处理与 `adapters.py:504-508` nuclei「非零退出不把部分结果报成功」的既有纪律一致。

缺口：`CR-01`（`rc=1` 被无条件当作成功，HIGH/BLOCKER）、`CR-02`（`errors` 键缺失被容忍、`paths.skipped` 非空不判失败且计数不进报告正文，MEDIUM）。

### 2.4 Findings 数据质量 —— **主干通过，存在 1 个 MEDIUM 净化缺口**

- 白名单抽取：`_METADATA_WHITELIST`（`:69-70`）只读 7 个 metadata key；`:390` 明确不读 `extra.lines`；`fingerprint` 不在白名单。日志只在 `:279` 写 `rule_id + location`，`:281-282` 写计数。
- severity：`_SEVERITY_MAP`（`:75-79`）ERROR/WARNING/INFO 严格映射，未知值由 `:405-406` 抛 `FindingError` 跳过记录（fail-closed，不静默降级）；`:272-277` 的 `name` alias 明确标注「由 Semgrep 报告的 severity 字段经映射得到；非 DualVerify-Sentinel 自行判定」，与 `report.py:61` 渲染 `name` 的行为配合，读者可分辨映射值与系统默认值。
- `_line()`（`:338-347`）不臆造行号；`finding_id` 由 `findings.py:243-251` 稳定哈希；`Finding` 13 字段 schema 未被改动（`findings.py:330-345`）。
- 单元测试 `B-10/B-11`、`M-03`、`O-01`（`:288-293`、`:511`、`:538-544`）与集成测试 `F-01/F-02`（`:627-638`）做了跨场景残留清扫，证明匹配到的源码行 / fingerprint / secret 形态文本不进入 detail、log、meta、findings、journal、report。
- 缺口：`CR-03` —— 白名单**字段名**做了限制，但**字段值**未净化（`path` / `check_id` / `message` / `references`），可污染日志与 Markdown 报告。

### 2.5 Planner 与注册 —— **通过（不改变既有任务顺序与依赖）**

- `planner.py:16` 新增 `semgrep_rules: str | None = None`，默认值保证所有既有调用不变；测试 `C-01`（`test_semgrep_integration.py:331-333`）验证无 `source_dir` 时计划仍为 `s1-probe, s2-nuclei`。
- `planner.py:82-92`：`s5-semgrep` 仅在 `source_dir` + binary 可解析 + `semgrep_rules` 非空三者同时成立时追加；**无 `deps`**，与 bandit/gitleaks 独立；顺序固定追加在末尾（`C-02/C-06`，`:346-401`）。二进制缺失或 rules 缺失时步骤不生成（`C-04/C-05`，`:356-387`），不会把既有绿跑拖成 SKIPPED。
- `__main__.py:55-57` 仅在 `main()` 启动时显式注册两个扩展 adapter，导入无注册副作用；`:90-93` 新增 `--semgrep-rules`；`:165-172` 透传（`args.semgrep_rules or None`）。
- `adapters_ext/__init__.py:28-32` 只导出、不注册；`pyproject.toml:21` 已含 `"vuln_hunter.adapters_ext"` 子包（本次只读核实），打包无缺口。
- 集成测试 `B-01~B-09`（`:273-326`）验证幂等注册、内置 trio + gitleaks 实例不被替换、CLI 子进程注册、`--help` 文案；`C-07`（`:403-407`）验证 `GraphBuilder` 保留 `fs_path`。

### 2.6 测试质量 —— **结构良好，但零真实工具验证（BLOCKER-验收证据）**

- 单元 `77/77`、集成 `38/38`（引用实施报告登记值，本轮未重跑）。集成测试**不是纯 mock**：真实 `PolicyEngine`、`Executor`、`EvidenceJournal`、`GraphBuilder`、`render_report`、`audit_status`；仅替换单一子进程缝 `_spawn`。在本机未安装 semgrep 且授权禁止自动安装的前提下，这是唯一可行方案，**不构成「过度模拟导致的虚假通过」**。
- 覆盖到位：命令契约/env、白名单与残留、空/畸形/非法输出、异常退出码(2/127)、超时、文件行号、`finding_id` 稳定性、路径守卫、rules 强制、`errors[]` 不完整、畸形记录、severity 映射、注册幂等、门禁链、取消、渲染报告。
- **但不能外推到真实工具行为**：`CR-06`。特别是 `CR-01` 的 `rc=1` 语义、`semgrep JSON` 的真实字段构成、`--config` 对目录/文件/registry 值的真实处理，均**未经任何真实二进制验证**。具体缺失用例见 §5。

---

## 3. 问题清单

> 每项包含：严重程度 / 文件行号 / 实际源码依据 / 触发条件 / 可能造成的影响 / 是否影响 EXT-2 验收 / 建议修复方式。

---

### CR-01 — `rc=1` 被无条件当作「扫描完成」，退出码契约未经真实 Semgrep 验证

- **严重程度**：**HIGH** ｜ **BLOCKER：是**
- **文件与行号**：`vuln_hunter/adapters_ext/semgrep.py:35-43`（docstring）、`:121-139`（`build_command`）、`:191-193`（`if rc not in (0, 1)`）；对照 `vuln_hunter/adapters_ext/gitleaks.py:35-39`、`:149-151`；测试 `tests/test_semgrep_adapter.py:310-311`、`:332-335`、`:396-429`、`:519-533`，`tests/test_semgrep_integration.py:435-448`、`:604-609`。

- **实际源码依据**：
  ```python
  # semgrep.py:35-43 (docstring)
  EXIT-CODE SEMANTICS (version-robust, no optional flags required):
    0 = scan completed, no findings; 1 = scan completed, findings found;
    anything else = failure.
  ```
  ```python
  # semgrep.py:136-139 —— 命令中没有 --error / --strict
  return [self.binary() or "semgrep", "scan", target,
          "--config", rules,
          "--json",
          "--metrics", "off"]
  ```
  ```python
  # semgrep.py:191-193 —— rc=1 与 rc=0 同列为「可继续解析」
  if rc not in (0, 1):
      log.write(f"semgrep exit {rc} (scan did not complete)\n")
      return AdapterResult("FAILED", False, f"semgrep exit {rc} (scan did not complete)")
  ```
  对照 `gitleaks.py:35-39` 的 docstring 与 `semgrep.py:35-43` **几乎逐字相同**，`:149-151` 同样是 `rc not in (0, 1)`。即：**「1 = findings found」这一契约是从 EXT-1 gitleaks 复制而来，未针对 Semgrep 重新验证**。gitleaks 的该语义在 EXT-1.3 用真实 CLI 验证过（`gitleaks.py:26-33` 记录了 8.30.1 实测）；Semgrep 没有对应实测记录。

  **辅助佐证（外部只读文档，非本机实测）**：Semgrep 官方 CLI reference 将 `0` 定义为「ran successfully… regardless of whether there were findings」（未使用 `--error` 时），`1` 定义为「found issues … **while using the `--error` flag**」，`2` 为 scan failed，另有 3/4/5/7/8/13/14 等错误码；getting-started 明确「`semgrep scan`/`semgrep ci` finish with exit code 0 as long as the scan completes, regardless of whether there were findings」，需 `--error` 或 blocking rules 才在有发现时返回 1。

- **触发条件**：真实 `semgrep` 在**未传 `--error`** 的情况下返回 `rc=1`（不同版本/配置下可能表示规则错误、部分失败、配置异常或其他非「有发现」状态），且 stdout 恰好是合法 JSON、`results=[]`、`errors=[]`。此时实现会走到 `:283-292` 返回 `AdapterResult("COMPLETED", True, "semgrep exit 1, 0 finding(s)")`。

- **可能造成的影响**：
  1. 把一次**非零退出（可能是失败/不完整）的扫描报告为 `COMPLETED` 且 0 findings**，直接命中 EXT-2 硬要求「不将扫描失败或不完整报告为成功，更不能报告为无漏洞」。
  2. docstring 向后续维护者/审计者陈述了一个**未经证实且很可能错误**的工具契约；测试（`C-01`、`H-*`、`I-*`、`N-*`、`E-07`、`D-03` 大量用 `returncode=1` 建模「成功且有发现」）把这个假设**固化为断言**，形成「实现—文档—测试」三者一致但与真实工具不一致的闭环，后续人工验收容易据此误判。
  3. 注意（避免过度夸大）：正常路径下 **findings 完全来自 `results[]` JSON，不依赖 rc**；未加 `--error` 时真实工具有发现也返回 0，因此常规扫描结果不受影响。风险集中在 `rc=1` 这个**非零退出码被无条件纳入成功集合**的窗口，以及契约可信度本身。

- **是否影响 EXT-2 验收**：**是（BLOCKER）**。EXT-2 授权书要求「明确处理……非零退出码」「不将扫描失败或不完整报告为成功」以及「结果可审计、失败状态可信，而不是只完成接口或模拟调用」。`rc=1` 是最典型的非零退出码，当前处理依赖一个未验证的复制契约。

- **建议修复方式**（三选一，均需同步改 docstring 与测试）：
  1. **推荐（最 fail-closed、最贴合真实语义）**：把成功集合收窄为 `rc == 0`；`rc=1` 与其它非零一律 `FAILED`。findings 本就来自 JSON，不损失任何结果。同时把 docstring 改为「findings 完全取自 `results[]`；退出码仅用于判定扫描是否完成」，并删除「1 = findings found」的表述。
  2. 若确需 `rc=1` 表示有发现：在 `build_command` 显式加入 `--error`，并**先用真实二进制验证**该 flag 在目标版本的行为与稳定性（注意 `semgrep.py:28-32` 明确刻意避免依赖可选 flag，加入前需重新评估该纪律）。
  3. 至少：对 `rc=1` 增加「`results` 为空则判 FAILED / 或要求 `errors` 与 `paths.scanned` 佐证」的二次判定，不无条件放行。
  修复后必须**在真实 semgrep 上验证退出码语义**（见 `CR-06`），并新增 `rc=1 + 合法 JSON + results=[] + errors=[]` 的用例，断言其**不被报告为 `COMPLETED`**（当前测试集无此组合）。

---

### CR-02 — 完整性信号被乐观默认：缺 `errors` 键视为无错误、大量 `paths.skipped` 不判失败且计数不进报告正文

- **严重程度**：**MEDIUM** ｜ **BLOCKER：否**
- **文件与行号**：`vuln_hunter/adapters_ext/semgrep.py:218-220`、`:221-226`、`:228-245`、`:287-292`；`vuln_hunter/report.py:43-48`（步骤结果表）、`:57-63`；测试 `tests/test_semgrep_adapter.py:346-350`（E-03）、`:485-489`（L-04）。

- **实际源码依据**：
  ```python
  # semgrep.py:218-220 —— errors 键缺失被默认为空
  raw_errors = data.get("errors", [])
  ...
  # semgrep.py:221-226
  paths = data.get("paths", {})
  skipped_paths = paths.get("skipped", [])
  ```
  ```python
  # semgrep.py:287-292 —— skipped 只进 adapter meta，不影响 status
  return AdapterResult(
      "COMPLETED", True,
      f"semgrep exit {rc}, {len(findings)} finding(s)",   # detail 不含 skipped 数
      findings,
      meta={..., "paths_skipped": len(skipped_paths)})
  ```
  测试把该行为**明确固化**：
  ```python
  # test_semgrep_adapter.py:348-350 (E-03)
  "report without an 'errors' key is tolerated (errors defaults to empty) -> COMPLETED, zero findings"
  # test_semgrep_adapter.py:487-489 (L-04)
  "skipped paths are recorded in meta (transparency) but do NOT fail the run: a skipped file is not an incomplete scan"
  ```
  而 `render_report()`（`report.py:43-48`）的步骤结果表只取 `r['status']` 与 `r.get('reason') or r.get('detail','')`，**不渲染 adapter `meta`**；发现区（`:57-63`）也不含完整性信息。因此 `paths_skipped` 计数只存在于 `AdapterResult.meta`（runner 记录层），**最终报告正文看不到**。

- **触发条件**：
  1. semgrep 输出为旧版本/异常输出，**不含 `errors` 键** → 实现假定「无错误」，即便扫描实际不完整也报 `COMPLETED`。
  2. 扫描因大文件、二进制、超时、权限或 `.gitignore` 导致**大量文件被跳过**（`paths.skipped` 非空甚至 `paths.scanned` 近空）→ 实现仍报 `COMPLETED`、0 findings，且报告正文无任何提示。

- **可能造成的影响**：把**覆盖范围不完整**的扫描呈现为「成功且无漏洞」。与 `errors[]` 非空即 `FAILED`（`:228-245`）的严格程度不一致：同样是「结果不完整」信号，一个 fail-closed、一个乐观放行。审计者从最终报告无法区分「全量扫描无发现」与「大部分文件被跳过无发现」。

- **是否影响 EXT-2 验收**：**部分（NON-BLOCKER）**。设计取舍有合理性——真实 semgrep 正常扫描几乎总会跳过一些文件（`node_modules`/二进制/大文件），一律判 `FAILED` 会使几乎所有真实运行变红，工程上不可行；且 `meta` 已留存计数可供 runner 层审计。但「`errors` 键缺失即假定无错误」与「skipped 完全不进 detail/报告」使 `:228-245` 建立的完整性纪律出现缺口，建议修复而非直接拒绝验收。

- **建议修复方式**：
  1. 把 `errors` 键缺失与 `errors` 非空**区别对待**但均不放行到无条件 `COMPLETED`：缺键时至少在 `detail` 显式标注「report lacks `errors` field; completeness unverified」，或按更保守策略判 `FAILED`（需真实二进制确认该键是否稳定存在）。
  2. 为 `paths.skipped` 引入**可见性**：把 `paths_skipped` 数量写入 `AdapterResult.detail`（从而进入 `report.py` 步骤表）；对「`skipped` 数量占 `scanned + skipped` 比例过高」或 `paths.scanned` 为空的情况设阈值，降级为 `PARTIAL`/`FAILED` 或至少显著标注。
  3. 新增用例：`errors` 键缺失、`errors=[]` 但 `paths.scanned=[]`、`skipped` 大量、`errors` 缺失 + 非空 `results` 四类组合，并断言报告正文可看出完整性状态；同步修订 E-03 / L-04 的断言语义。

---

### CR-03 — 白名单字段的「值」未净化，可污染日志与 Markdown 报告（报告注入）

- **严重程度**：**MEDIUM** ｜ **BLOCKER：否**
- **文件与行号**：`vuln_hunter/adapters_ext/semgrep.py:329-335`（`_str_field`）、`:350-358`（`_location`）、`:378-383`（`_metadata.references`）、`:393-398`（`check_id`/`path`）、`:407`、`414-416`、`417-431`（拼装 `Finding`）、`:272-277`（`name` alias）、`:279`（写日志）；`vuln_hunter/report.py:57-63`；`vuln_hunter/findings.py:86-98`、`:286-292`、`:230-240`。

- **实际源码依据**：
  ```python
  # semgrep.py:329-335 —— 只 .strip()，不校验字符集/长度/路径形态
  def _str_field(rec: dict, name: str) -> str:
      val = rec.get(name)
      ...
      return val.strip()
  ```
  ```python
  # semgrep.py:350-358 —— JSON 里的 path 原样拼进 location
  return f"{path}:{sline}"       # 或 f"{path}:{sline}-{eline}"
  ```
  ```python
  # semgrep.py:378-383 —— references 任意字符串/字符串列表原样采收
  refs = [r.strip() for r in raw_refs if isinstance(r, str) and r.strip()]
  ```
  ```python
  # semgrep.py:272-277 —— title 由 check_id 拼成，再拼进 name alias
  d["name"] = (f"{f.title} " f"[severity=... 由 Semgrep 报告的 ...]")
  # semgrep.py:279 —— 直接把 rule_id / location 写进纯文本日志
  log.write(f"  {f.rule_id} {f.location}\n")
  ```
  `report.py:60-63` 把 `f.get('name')` **原样**拼入 `- **{severity}** {name}` 报告行，不做 Markdown 转义。`findings.py` 的 `_cap()`（`:86-98`）只做长度截断，**不移除换行/控制字符**；`redact_evidence()` 只作用于 `evidence` 字段，`title`/`rule_id`/`location`/`references` 均不经过它。

- **触发条件**：`semgrep` 输出被视为 hostile（该前提写在 `semgrep.py:3-13` 的安全契约里）。若被扫描仓库中存在构造过的文件名/路径，或本地规则文件的 `check_id`、`message`、`metadata.references` 含换行、Markdown 语法、`|`、控制字符、超长内容，这些值会经 `check_id → title → name alias → report.py` 或 `path → location → log.write` 落地。

- **可能造成的影响**：
  1. **报告注入**：`check_id` 内含 `\n- **[CRITICAL]** …` 可在最终 Markdown 报告中伪造额外的「发现」行，破坏报告可信度与人工审计结论；含 `|` 可破坏步骤表/发现列表结构。
  2. **日志注入**：`path`/`rule_id` 含换行可在 attempt 日志中伪造行，干扰 `Executor` 日志与 journal 溯源。
  3. `references` 未做 scheme 白名单，可携带 `javascript:`、任意协议或超长字符串进入结构化输出（`_norm_references` 仅 cap 500 并校验非空，`findings.py:230-240`）。
  4. `path` 未校验是否为绝对路径、`..` 逃逸或是否位于扫描目录内，可能让「漏洞位置」指向扫描范围之外的任意路径（数据误导）。

- **是否影响 EXT-2 验收**：**否（NON-BLOCKER）**。不导致命令执行、越权或源码泄漏；触发需恶意/被污染的规则或仓库内容，属第二层数据质量风险。但考虑到「结果可审计」是授权目标，建议与其他修复一并处理。

- **建议修复方式**：
  1. 对 `path` 校验：拒绝绝对路径与含 `..` 的值（或统一转为相对扫描根的形式）、剔除/拒绝控制字符与换行、限制长度；对 `check_id`/`message`/metadata 值同样做「禁止 `\r\n` 与控制字符」校验，非法值按 `FindingError` 跳过该记录（与现有 fail-closed 风格一致）。
  2. 进入 Markdown 的字段（`name` alias、`title`）在拼装前做转义，或在 `report.py` 渲染时转义（注意 `report.py` 为冻结文件，本次不建议改动；因此**转义应在 adapter 侧完成**）。
  3. `references` 增加 scheme 白名单（仅 `http`/`https`）与长度上限。
  4. 新增用例：恶意 `path`（换行 / 绝对路径 / `..`）、含 Markdown 的 `check_id`、`javascript:` reference、超长字段，断言报告/日志不被注入且记录被安全跳过。

---

### CR-04 — `_refuse_reason` 无 source-root containment，树内符号链接行为未验证

- **严重程度**：**LOW** ｜ **BLOCKER：否**（**非 EXT-2 引入，属既有架构边界**）
- **文件与行号**：`vuln_hunter/adapters_ext/semgrep.py:307-326`；对照 `vuln_hunter/adapters_ext/gitleaks.py:221-240`（逐字相同）；`vuln_hunter/policy.py:160-197`（`fs_path` 豁免）、`vuln_hunter/adapters.py:210-216`；`vuln_hunter/report.py:99` 已声明该边界。

- **实际源码依据**：
  ```python
  # semgrep.py:311-326 —— 只拒绝：非目录、盘根、home
  p = Path(target)
  if not p.is_dir(): ...
  rp = p.resolve()
  if rp == Path(rp.anchor): ...
  if home is not None and rp == home: ...
  return None
  ```
  没有任何「target 必须位于某个授权 source root 之下」的检查；`resolve()` 只解析顶层 target，不检查目录树**内部**的符号链接是否指向扫描范围外。`fs_path` 在 `policy.py:172` 与 `adapters.py:213-216` 跳过 `target_allowed()`，因此 RunTicket 对本地路径不做 scope 归属校验。

- **触发条件**：持有任一有效的 `fs_path` RunTicket（窗口合法、mode 允许 R1、scope hash 匹配）后，把 `--source-dir` 指向 home 之外的任意本地目录；或扫描树内含指向范围外的符号链接且所用 semgrep 版本会跟随它。

- **可能造成的影响**：扫描到授权 scope 之外的本地文件；树内符号链接若被跟随，可能读取范围外文件内容并进入工具输出（虽 `extra.lines` 不被采收，但工具进程本身已读取）。

- **是否影响 EXT-2 验收**：**否**。理由：① 与 `gitleaks.py:221-240` **逐字一致**，是 EXT-1 已确立并经人工验证的既有模式，EXT-2 只是复用，未引入新偏离；② `fs_path` 豁免网络 scope 是 bandit/gitleaks 共同先例，`report.py:99` 已如实声明；③ 「本地路径与授权 scope 的绑定模型」属于六项测试阶段的授权模型议题，超出 EXT-2 单一 adapter 的修复范围。列于此仅为让人工验收看到该边界**确实存在且被识别**，不作为 EXT-2 拒收理由。

- **建议修复方式**（属后续全局加固，不建议在 EXT-2 内单独改）：引入显式的 `source_root` 授权字段并做 containment 校验；对树内符号链接采取「不跟随」的显式策略并在真实工具上验证；所有本地 adapter（bandit/gitleaks/semgrep）统一改造，避免逐个打补丁造成行为不一致。

---

### CR-05 — `--config` 值未显式拒绝 registry/`-` 开头值；`text=True` 未指定编码

- **严重程度**：**LOW** ｜ **BLOCKER：否**
- **文件与行号**：`vuln_hunter/adapters_ext/semgrep.py:135-139`、`:148-162`、`:303-304`；`vuln_hunter/planner.py:82`；对照 `vuln_hunter/adapters.py:527-532`（bandit）、`vuln_hunter/adapters_ext/gitleaks.py:214-218`（同为 `text=True`）。

- **实际源码依据**：
  ```python
  # semgrep.py:135-139
  rules = str(step.get("semgrep_rules") or "")
  return [..., "--config", rules, "--json", "--metrics", "off"]
  # semgrep.py:158-162 —— 仅检查存在性
  if not Path(rules).exists():
      return AdapterResult("FAILED", False, f"semgrep rules not found: {rules} ...")
  ```
  ```python
  # semgrep.py:303-304 —— text=True，未指定 encoding / errors
  return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=env)
  ```
  `planner.py:82` 仅检查 `semgrep_rules` 真值，不做路径形态校验；存在性检查放在 adapter `_run`（fail-closed 分层，本身合理）。

- **触发条件**：
  1. operator 传 `--semgrep-rules=auto`（或 `p/...`/`r/...` 等 registry 值），且当前工作目录恰好存在同名文件/目录使 `Path(rules).exists()` 为真；或传以 `-` 开头的值被工具解释为额外 flag → 可能触发 registry 联网拉规则或参数注入，与「no network / registry 不用」契约冲突。触发条件较苛刻（需 CWD 巧合 + 授权方自行输入特殊值）。
  2. Windows 中文 locale 下，semgrep JSON stdout 含非 ASCII 字符（中文路径、规则 `message`）时，`text=True` 按 locale 解码可能抛 `UnicodeDecodeError`，被 `:178-181` 的通用 `except Exception` 捕获 → 一次正常扫描被报 `FAILED`（fail-closed 但误判）。对照 `adapters.py:345` nuclei 使用 `encoding="utf-8", errors="replace"`。

- **可能造成的影响**：① 极端情况下违背「不联网下载规则」；② 非 ASCII 输出导致假失败，降低结果可信度。两者都不导致越权或注入执行。

- **是否影响 EXT-2 验收**：**否**。① 常规 operator 输入为本地路径，`Path.exists()` 已挡住绝大多数 registry 值；② `text=True` 与 gitleaks/bandit 既有模式一致，非 EXT-2 回归。

- **建议修复方式**：① 在 `_run` 增加显式规则：拒绝以 `-` 开头的值、拒绝已知 registry 前缀（`auto`、`p/`、`r/`、`registry`），并要求 `Path(rules).is_file() or is_dir()`；② `_spawn` 改为 `encoding="utf-8", errors="replace"`（与 nuclei 一致），并新增含中文 `message`/`path` 的输出用例。

---

### CR-06 — 零真实二进制端到端验证：全部 `PASS` 证据建立在 mock 之上

- **严重程度**：**MEDIUM** ｜ **BLOCKER：是（验收证据层，非代码缺陷）**
- **文件与行号**：`tests/test_semgrep_adapter.py:1-9`、`:138-151`、`:154-179`；`tests/test_semgrep_integration.py:1-6`、`:124-150`；`vuln_hunter/adapters_ext/semgrep.py:295-304`；`docs/EXT-2-IMPLEMENTATION-REPORT.md`（登记的「真实二进制扫描未验证」限制）。

- **实际源码依据**：
  ```python
  # test_semgrep_adapter.py:138-151 —— 唯一的子进程缝被完全替换
  class FakeRunner:
      def __call__(self, cmd, timeout):
          self.calls.append((list(cmd), timeout))
          if self.exception is not None: raise self.exception
          return FakeProc(self.returncode, self.stdout)
  # test_semgrep_adapter.py:160
  sg_mod._spawn = fake
  ```
  ```python
  # test_semgrep_integration.py:147-150 —— 导入/注册阶段也用 fake 监视
  IMPORT_SPAWN_WATCH = FakeRunner()
  sg_mod._spawn = IMPORT_SPAWN_WATCH
  ```
  两个测试套件中所有 `stdout` 均由 `fake_report()` 构造（`test_semgrep_adapter.py:121-128`、`test_semgrep_integration.py:115-121`），字段集是**开发者假定的** semgrep JSON 形状；`FakeProc`（`test_semgrep_adapter.py:131-135`）的 `stderr` 恒为常量字符串，从不参与任何断言。文件中唯一真实子进程是 `sys.executable -c ...`（`test_semgrep_adapter.py:247-249`、`test_semgrep_integration.py:302-316`），用于验证 env 与 CLI 启动，**不涉及 semgrep**。

- **触发条件**：EXT-2 授权书的目标是「**可实际运行、结果可审计、失败状态可信，而不是只完成接口或模拟调用**」；本机 `semgrep` 不可用（`which` 无、`python -m semgrep` 无模块、`~/Tools` 仅有 nuclei/osv-scanner），且阶段 1 授权明确「不自动安装依赖、不自动联网下载规则」。因此 EXT-2 全程以 `_spawn` mock 完成验证，实施报告给出 `PASS（附 1 项环境性限制）`。

- **可能造成的影响**：`PASS` 只能证明「实现逻辑在假定输入下自洽」，**不能证明**下列任一真实工具契约成立：`scan --config --json --metrics off` 在目标版本可用且 flag 稳定；真实 JSON 确实含 `results`/`errors`/`paths.skipped` 且类型如假定；真实退出码语义（见 `CR-01`）；`--config` 接受目录/单文件；`extra.severity` 值域是否只有 ERROR/WARNING/INFO；`SEMGREP_ENABLE_VERSION_CHECK=false` 与 `--metrics off` 是否足以阻止所有出站连接。这些恰是「结果可审计、失败状态可信」的核心。若据此直接确认无条件 `PASS`，验收结论的证据强度不足。

- **是否影响 EXT-2 验收**：**是（BLOCKER-验收证据）**。需强调：**这不是实现方过错**——环境约束与「禁止自动安装」均来自用户授权，实施报告也已如实登记限制。列为 blocker 是为了让人工验收明确区分「实现层已通过」与「真实运行层未验证」，避免把 mock 全绿等同于真机可信。

- **建议修复/闭合方式**（需**单独授权**，不在本次只读审查范围内）：
  1. 在受控环境提供或安装一个固定版本的 `semgrep`（记录版本号），用**本地规则文件**对一个小型、专用、无敏感内容的 fixture 源码树做一次真实端到端扫描；
  2. 记录真实 CLI 输出：退出码、JSON 顶层字段、`errors`/`paths` 结构、`extra.severity` 取值、是否有任何出站连接；据此核对 `CR-01` 的退出码契约、`CR-02` 的完整性字段、`CR-05` 的编码行为；
  3. 把真实输出（脱敏后）与结论补入验收材料，再把实现层 `PASS` 升级为完整 `PASS`；
  4. 若人工决定在安装工具前不接受该条件，则把 `EXT-2-IMPLEMENTATION-REPORT.md` 的状态显式降级为 `PASS (实现/离线层) + UNVERIFIED (真实工具层)`，并在验收状态文件中登记该未决项。

---

## 4. BLOCKER / NON-BLOCKER 汇总

| 编号 | 严重程度 | 维度 | 类型 | 是否影响验收 |
|---|---|---|---|---|
| `CR-01` | **HIGH** | 扫描完整性 / 执行安全 | **BLOCKER（代码层）** | **是** |
| `CR-06` | **MEDIUM** | 测试质量 / 验收证据 | **BLOCKER（证据层）** | **是** |
| `CR-02` | MEDIUM | 扫描完整性 | NON-BLOCKER（建议修复） | 部分 |
| `CR-03` | MEDIUM | Findings 数据质量 | NON-BLOCKER（建议修复） | 否 |
| `CR-04` | LOW | Policy / 路径边界 | NON-BLOCKER（既有架构边界） | 否 |
| `CR-05` | LOW | 执行安全 / 健壮性 | NON-BLOCKER（建议加固） | 否 |

**BLOCKER = 2；NON-BLOCKER = 4。** 未发现 CRITICAL 级问题；未发现命令注入、门禁绕过、源码泄漏、registry 隐式联网的实现路径。

---

## 5. 测试覆盖缺口（供修复后补测）

下列用例在现有 `77 + 38` checks 中**均不存在**，按优先级列出：

1. **`rc=1` 边界**（`CR-01`，最高）：`rc=1` + 合法 JSON + `results=[]` + `errors=[]` → 断言**不**报 `COMPLETED`；`rc=1` + 非空 `results` 的语义需在真实工具确认后重新建模。当前 `C-01`/`H-*`/`I-*`/`N-*`/`D-03`/`E-07` 用 `returncode=1` 建模「成功有发现」，需随契约修订同步调整。
2. **完整性字段缺失/异常**（`CR-02`）：缺 `errors` 键 + 非空 `results`；`errors=[]` 但 `paths.scanned=[]`；`paths.skipped` 数量巨大；`errors` 缺失 + `paths` 缺失同时出现。
3. **恶意/异常 JSON 值**（`CR-03`）：`path` 含 `\n`/`\r`/控制字符、绝对路径、`..`、超长；`check_id` 含 Markdown/换行；`extra.message` 含换行；`references` 为 `javascript:` / 非 http(s) / 超长；`extra.metadata` 深层畸形（嵌套 dict、非字符串列表元素）。断言报告与日志不被注入、非法记录被安全跳过。
4. **符号链接**（`CR-04`，用户明确点名）：target 本身是指向 home/盘根的符号链接（应被 `resolve()` 拒绝）；扫描树内含指向范围外的符号链接（当前 J 段 `test_semgrep_adapter.py:434-443` 只有 home/drive-root/missing-dir/file-not-dir 四种，无 symlink）。
5. **退出码全集**（`CR-01`）：当前 F 段只测 `2` 与 `127`（`test_semgrep_adapter.py:370-379`）；官方表中的 3/4/5/7/8/13/14 未显式断言（虽 `rc not in (0,1)` 逻辑上覆盖，但缺回归锚点）。
6. **rules 形态**（`CR-05`）：registry 特殊值、`-` 开头值、目录 vs 单文件 vs 空目录；`K-04`（`:464-469`）只验证「存在即可」，未验证工具侧接受与否。
7. **编码**（`CR-05`）：stdout 含中文/非 ASCII 的合法 JSON。
8. **真实二进制端到端**（`CR-06`）：**零覆盖**，见 §3 CR-06 闭合方式。
9. **stderr 语义**：`FakeProc.stderr` 恒为 `"fictional-stderr"` 且从不参与断言；实现也刻意不读 stderr，属一致设计，但「工具把关键错误只写到 stderr 而 stdout 是合法空 JSON」的组合未被任何用例建模。
10. **注册表状态隔离**：两个测试文件在模块顶层调用 `register_semgrep()` / `register_gitleaks()` 且不还原 `_REGISTRY`；当前以独立进程脚本方式运行无冲突，但若未来改为 pytest 统一收集，`B-05`（`:294-297`）对 registry 精确内容的断言可能受执行顺序影响。属可维护性提示，非缺陷。

**关于「mock 是否过度模拟」的判断**：不过度。集成测试保留了真实 `PolicyEngine`/`Executor`/`EvidenceJournal`/`GraphBuilder`/`render_report`/`audit_status`，只替换单一子进程缝，且这是「本机无工具 + 禁止自动安装」下唯一可行方案。问题不在模拟程度，而在**测试结论被外推到了未经真机验证的工具契约**（`CR-01`/`CR-06`）。

---

## 6. 最终判定与建议

### 6.1 是否建议接受 EXT-2

**不建议在修正前确认无条件 `PASS`。建议 `CONDITIONAL ACCEPT`（有条件接受）**，理由：

- 实现层质量良好：执行注入面闭合、`RunTicket`/`PolicyEngine` 门禁未被绕过、白名单抽取与「不读 `extra.lines`」落实到位、`errors[]`/空白 stdout/异常退出/超时均 fail-closed、Planner/注册改动不影响既有计划与依赖、115 个离线 checks 结构完整。**从「代码是否正确集成进现有架构」看，EXT-2 达到可交付水准。**
- 但存在 2 个 BLOCKER：`CR-01` 是「非零退出码被无条件当作成功 + 契约从 gitleaks 复制未针对 Semgrep 验证」，直接命中授权书「失败状态可信」「不把不完整报为成功」；`CR-06` 是「全部证据基于 mock，真实工具层零验证」，直接命中授权书「可实际运行……而不是只完成接口或模拟调用」。
- 因此当前 `docs/EXT-2-IMPLEMENTATION-REPORT.md` 的 `PASS（附 1 项环境性限制）` **证据强度不足以支撑无条件验收**。建议人工二选一：
  - **(A) 先修复再验收**：完成 `CR-01` 修复 + `CR-02`/`CR-03` 加固 + 真实二进制端到端验证（`CR-06` 闭合），重测通过后确认完整 `PASS`；
  - **(B) 显式降级接受**：把状态改记为 `PASS (实现/离线层) + UNVERIFIED (真实工具层)`，并在验收状态文件中登记为未决项，待工具可用时补验。

> 本报告不替人工做最终裁定，不修改 `EXT-2-IMPLEMENTATION-REPORT.md` 或任何验收状态文件。

### 6.2 BLOCKER 清单

1. **`CR-01`** — `rc=1` 退出码契约（代码层，可在本仓库内修复）。
2. **`CR-06`** — 真实 semgrep 二进制端到端验证缺口（验收证据层，需单独授权提供/安装工具；根因是环境约束与「禁止自动安装」授权，非实现方过错）。

### 6.3 是否需要修复后重新测试

**是。** 建议范围（需人工另行授权后执行，本次只读审查未运行任何测试）：

- 必跑：`tests/test_semgrep_adapter.py`、`tests/test_semgrep_integration.py`；
- 必跑：与 EXT-2 相关的离线回归套件（沿用实施阶段登记的那 17 个，**具体清单以实施报告 §4 为准**）；
- 新增：§5 中第 1–7 项边界用例；
- 补验：在真实 semgrep 可用后做一次本地规则 + fixture 源码树的端到端扫描（`CR-06`）；
- 复核：修复后重新核验五个冻结文件的 SHA256 与 `git diff`，确认未扩大修改范围；
- **禁止**：不重跑六项历史测试、不改写 `G15 FAIL` / `EXECUTION_INTEGRITY=NOT_OK` / `C14 FAIL` / 历史 `UNKNOWN`、不擅自关闭六项测试阶段、不清理两个验证副产物、不自动提交 Git。

---

## 7. 审查限制与未验证项（如实声明）

1. 本机未安装 semgrep、授权禁止自动安装，本报告**未运行任何真实扫描**；所有关于真实 Semgrep CLI/JSON/退出码的说法均为「源码依据 + 外部官方文档辅助佐证」，需真机复核。若目标版本实际行为与官方现行文档不同，`CR-01` 的严重度需相应调整（但其「契约未经本机验证、且从 gitleaks 复制」这一事实不变）。
2. 本报告未运行测试，`77/77`、`38/38`、17 个回归套件全绿等数据引自 `docs/EXT-2-IMPLEMENTATION-REPORT.md`，**本次未独立复现**。
3. 只读审查无法证明「执行期间绝对无写入」之外的运行时行为；进程级沙箱、工具子进程树清理、真实网络出站行为均不在本次审查能力范围内。
4. `CR-04` 涉及的符号链接树内行为取决于所用 semgrep 版本默认是否跟随符号链接，源码无法判定，标注为**待真机验证**。
5. 六项测试阶段尚未正式关闭；总体 `CONDITIONAL`；`G15 FAIL`、`EXECUTION_INTEGRITY=NOT_OK`、`C14 FAIL`、D-2…D-11 未裁定事项一律保持原样。本报告未将其描述为已通过。

---

**审查结束。未修复任何问题，未运行任何测试或工具，未修改任何既有文件。等待人工决定。**
