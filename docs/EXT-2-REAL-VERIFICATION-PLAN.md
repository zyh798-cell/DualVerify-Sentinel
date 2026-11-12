# DualVerify-Sentinel V1 — EXT-2 Real Semgrep Verification Preparation Plan

- **生成时间**：2026-11-08（本地时间，GMT+8）
- **仓库**：`C:/Users/ZTL/Desktop/DualVerify-Sentinel`，分支 `main`，HEAD `9913c50`（规划期间未变）
- **授权**：`DualVerify-Sentinel V1 — EXT-2 Real Semgrep Verification Preparation`
- **阶段性质**：**只读规划**。本轮**不安装、不下载、不运行 Semgrep、不执行任何扫描**，唯一新建文件即本方案文档。
- **目标**：为解决 `CR-06`（真实 Semgrep 二进制端到端验证缺口）提供一份**可执行、可审计、有边界**的受控验证方案，供人工批准后执行。
- **前置依据**：`docs/EXT-2-CODE-REVIEW.md`（`CR-06` = BLOCKER-验收证据层）、`docs/EXT-2-REMEDIATION-REPORT.md`（三项修复完成，建议 `CONDITIONAL ACCEPT`）、`docs/EXT-2-IMPLEMENTATION-REPORT.md §10`。

> **标注体系**（与既有报告一致）：`[E]` 本地直接观测；`[R]` 外部只读文档/检索参考（**需人工复核**，不作为执行依据）；`[S]` 登记陈述；`[I]` 推断；`[U]` 本轮无法确认、正是本方案要验证的对象。
>
> **本轮唯一写入**：`docs/EXT-2-REAL-VERIFICATION-PLAN.md`。未修改源码、测试、配置、历史证据、既有报告正文；未触碰五个冻结文件；未重跑六项历史测试；未清理两个验证副产物；未改写 G15 / `EXECUTION_INTEGRITY=NOT_OK` / C14 / 历史 `UNKNOWN`；六项测试阶段状态未动；未执行任何 Git 写操作。

---

## 1. 目标、范围与 CR-06 的精确边界

### 1.1 为什么必须做真机验证

`EXT-2 Remediation` 后的全部证据（单元 `105/105`、集成 `46/46`、17 套离线回归）**都替换了唯一子进程缝 `semgrep._spawn`** `[E]`。它证明的是「在假定输入下实现逻辑正确」，**不能**证明下列与真实 CLI 相关的事实：

| # | 待证问题 | 当前状态 |
|---|---|---|
| Q1 | `scan / --config <p> / --json / --metrics off` 在真实版本上是否被接受、是否产生 stdout JSON | `[U]` |
| Q2 | 真实 JSON 顶层是否稳定含 `results` / `errors` / `paths` / `paths.skipped` | `[U]` |
| Q3 | `paths.skipped` 元素形态（带 `reason` 的 dict，还是裸路径字符串） | `[U]` |
| Q4 | `extra.severity` 真实值域是否只有 `ERROR/WARNING/INFO` | `[U]` |
| Q5 | 真实退出码契约，尤其「有 findings 时是否仍为 `0`」 | `[R]` 有官方说明，`[U]` 未在本机实测 |
| Q6 | `SEMGREP_ENABLE_VERSION_CHECK=false` 与 `--metrics off` 是否真的抑制了出站连接 | `[U]` |
| Q7 | 真实输出经 `Finding` / `EvidenceJournal` / `render_report()` 的完整链路是否可用且无源码泄露 | 仅 mock 层已证 `[E]`，真实层 `[U]` |

`CR-06` 之所以是 BLOCKER，是因为 `EXT-2` 授权目标是「**可实际运行、结果可审计、失败状态可信，而不是只完成接口或模拟调用**」。上表 Q1–Q7 闭合前，不能标记无条件 `PASS`。

### 1.2 本方案要交付什么

一份**待批准的执行方案**，覆盖用户要求的 8 项：固定版本与 SHA256、准备方式、本地 fixture/规则、7 类真实执行场景、JSON/severity/退出码核对、无外网验证、完整链路验证、隔离/证据/清理/回滚。并给出 `CR-06` 的**闭合判据**与**需人工批准清单**。

### 1.3 本方案不做的事

- 不判定真实 Semgrep 的行为（不预设 `errors`/`paths.skipped` 一定存在、不预设 severity 值域、不预设退出码）。
- 不因为真机结果而修改 `semgrep.py`、测试或冻结文件；如出现契约不符，**先停止并报告**，是否修复需单独授权（见 §6.5、§10.2）。
- 不代表 `CR-06` 已闭合；本方案被批准 ≠ 验证已完成。
- 不改变任何既有验收状态（G15 / C14 / `UNKNOWN` / 六项测试阶段）。

---

## 2. 固定版本选择、官方来源与 SHA256 校验

### 2.1 Pin 建议：`semgrep == 1.182.1`

> **重要**：以下版本号与日期来自**外部只读检索** `[R]`，检索结果本身存在不一致；**最终 pin 必须由人工在 PyPI 官方页面核对后确认**。本轮未下载、未校验、未安装任何文件，因此**不提供任何具体 SHA256 值**（编造校验和会破坏证据完整性）。

| 候选 | 来源/日期 `[R]` | 观察 |
|---|---|---|
| `1.182.1` | PyPI，2026-10-22 | 第三方包健康页列为 "Latest version"，标注无已知直接漏洞；License `LGPL-2.1-or-later`；`Requires: Python >=3.10`；classifiers 含 `Microsoft :: Windows`、Python 3.13 / 3.14 |
| `v1.183.0` | GitHub `semgrep/semgrep` release，2026-10-29 | 含多项行为变更：不再提供 Intel Mac 二进制、**禁用 macOS/Windows 上基于 curl 的 telemetry**、`ci --no-suppress-errors` 退出码变化 |
| `1.163.0` | PyPI，2026-05-14 | 更旧、更长时间窗的稳定版；仅在 `1.182.1` 不可用时作退回候选 |

**推荐 pin `1.182.1`，选择依据**：

1. **可复现**：有明确 PyPI 上传日期与官方项目页，wheel 与 `digests.sha256` 可由官方 JSON API 取得 `[R]`。
2. **避免刚发布的行为变更窗口**：`1.183.0` 的 release notes 明确改动了 Windows telemetry 与 `ci` 退出码语义 `[R]`。本方案第 6 项恰要验证「无外网」，把一个刚改过 telemetry 的版本作为基线会引入额外变量；`1.182.1` 是变更前的稳定点。
3. **与本机解释器匹配**：本机 `sys.version = 3.13.14`、`requires-python >=3.10`，且该包 classifiers 含 Python 3.13 与 Windows `[R]`/`[E]`。
4. **授权/许可清晰**：引擎 `LGPL-2.1-or-later`；本方案使用**自写本地规则**，规避 2024-12 起 Semgrep 官方规则集的 `Semgrep Rules License v1.0` 使用限制 `[R]`。
5. **避开需登录字段**：检索资料提示 fingerprint 等输出字段现需登录 `[R]`；EXT-2 本就**不读取** `fingerprint`/`extra.lines` `[E]`，与该版本行为无冲突。

### 2.2 官方来源清单（`[R]`，需人工复核）

| 用途 | 官方来源 |
|---|---|
| 版本与 wheel | `https://pypi.org/project/semgrep/` 及 `https://pypi.org/project/semgrep/1.182.1/` |
| 校验和 | `https://pypi.org/pypi/semgrep/1.182.1/json` → `urls[].digests.sha256` |
| release notes / 变更 | `https://github.com/semgrep/semgrep/releases` |
| CLI 契约 | `https://semgrep.dev/docs/cli-reference`、`https://semgrep.dev/docs/getting-started/cli` |

> 本轮**未访问这些地址下载任何内容**；§2.1 的信息来自公开检索结果摘要，标注 `[R]`。

### 2.3 SHA256 校验方式（**方法学，执行阶段才做**）

三步、全部由**人工**在受控环境完成；命令为模板，**本轮不执行**：

```bash
# 步骤 1：从官方 PyPI JSON API 取得该版本每个 wheel 的官方 digests.sha256
#   GET https://pypi.org/pypi/semgrep/1.182.1/json
#   记录 filename / digests.sha256 / python 版本 / 平台 tag 到证据清单

# 步骤 2：对人工下载的每个文件做本地摘要并逐项比对
sha256sum semgrep-1.182.1-*.whl
# Windows 等效：
#   Get-FileHash -Algorithm SHA256 <file>

# 步骤 3：安装前后各校验一次，并用 pip 的哈希锁定强制执行
pip download --no-deps --dest <ISO>/wheels semgrep==1.182.1
pip hash <ISO>/wheels/<wheel>
pip install --require-hashes -r <ISO>/requirements.lock
```

**附加可复现要求**（缺一不可，写入证据）：

- 固定 `python -V` / `sys.executable` / `sys.version` / 平台（`win32`、`AMD64`）`[E]`。
- 固定**完整依赖树**及其哈希（`requirements.lock` 逐条 `--hash=sha256:...`）；只锁 `semgrep` 主包不足以复现。
- 记录 wheel 的 `Requires-Python`、平台 tag、上传日期与官方 JSON API 原文快照（纯文本，不含二进制）。
- 记录 `semgrep --version` 与 `semgrep scan --help` 原始输出（确认 `scan` 子命令与所用 flag 均存在）。

> **环境事实** `[E]`：本机 `python` 的 `sys.executable` 为 `C:\Users\ZTL\.workbuddy\binaries\python\versions\3.13.12\python.exe`，但 `sys.version` 为 `3.13.14`。**目录名与实际版本不一致**，必须以 `sys.version` 而非目录名判断 wheel 兼容性，并在证据中同时记录两者。

### 2.4 需人工核对/批准项（本类）

- **A1**：人工在 PyPI 官方页确认最终 pin 版本、wheel 是否存在、以及对应 `digests.sha256`（本轮不下载、不猜测）。
- **A2**：确认该版本是否有**可用于 Windows 的 wheel / `semgrep-core` 原生二进制** `[U]`。若官方 wheel 在 Windows 上不可用或缺少 core 组件，须**停止**并提出替代路径（隔离容器 / WSL / 官方签名的独立二进制），**单独批准**后方可继续。
- **A3**：确认所选版本 `scan` 子命令接受 `--json` 与 `--metrics off`。

---

## 3. 安装 / 准备方式（禁止自动安装、联网下载、修改系统环境）

### 3.1 本机现状 `[E]`（只读探查，2026-11-08）

| 检查 | 结果 |
|---|---|
| `command -v semgrep` | `ABSENT (not on PATH)` |
| `python -m semgrep --version` | `No module named semgrep` |
| `python -m pip show semgrep` | `Package(s) not found: semgrep` |
| `pip cache list \| grep -i semgrep` | 无缓存条目 |
| `C:/Users/ZTL/Tools/` | 仅 `nuclei/`、`osv-scanner/`；**无 `semgrep/`** |
| 仓库内 `*.yml/*.yaml/*.semgrep` 规则文件 | **零个** |
| `pyproject.toml` | `requires-python = ">=3.10"`；`packages = ["vuln_hunter", "vuln_hunter.adapters_ext"]` |

结论：**当前不具备任何真实 Semgrep 执行条件**；本轮也不打算改变这一点。

### 3.2 工具解析链（源码依据 `[E]`）

`vuln_hunter/adapters_ext/semgrep.py:66-69, 213-226, 234-235`：

```python
SEMGREP_FALLBACKS = [
    Path.home() / "Tools" / "semgrep" / "semgrep.exe",
    Path.home() / "Tools" / "semgrep" / "semgrep",
]

def semgrep_binary() -> str | None:
    exe = shutil.which("semgrep")
    if exe:
        return exe
    for p in SEMGREP_FALLBACKS:
        if p.exists():
            return str(p)
    return None
```

`planner.py:82` 仅在 `semgrep_binary() is not None and semgrep_rules` 时才生成 `s5-semgrep`。`build_command()`（`semgrep.py:245-263`）随后把解析到的路径作为 `argv[0]`，`_spawn()` 用 `subprocess.run(list, ..., shell=False)` 直接执行。

> **关键工程含义**：只要让 `shutil.which("semgrep")` 或上述两个 fallback 路径之一解析到可执行文件，**无需修改 PATH 持久化、无需写注册表、无需改动源码**即可完成工具接入。

### 3.3 三条候选准备路径（均需批准，本轮不执行）

| 路径 | 做法 | 是否改系统环境 | 评价 |
|---|---|---|---|
| **A（推荐）隔离 venv + 进程级 PATH** | 人工下载 wheel → 在 `<ISO>/venv` 建 `python -m venv` → `pip install --require-hashes` → **仅在执行验证的那个进程内**把 `<ISO>/venv/Scripts` 前置到 `PATH` | **否**（进程级临时变量，不写用户/系统 PATH、不改注册表、不装进系统 site-packages） | 最干净、可完整复现依赖、易回滚 |
| **B（备选）fallback 目录** | 人工提供官方可执行文件放到 `C:/Users/ZTL/Tools/semgrep/semgrep.exe`，命中 `SEMGREP_FALLBACKS` | 否 | 零 PATH 改动；但 Windows console script 移动后可能找不到 venv 依赖，**需先验证** `[U]` |
| **C（备选）官方便携/签名二进制** | 人工取得官方发布的独立二进制并核验签名 | 否 | 依赖树最少；需单独确认该版本是否提供 `[U]` |

**推荐 A**，并在证据中记录 `argv[0]` 的实际解析结果（`semgrep_binary()` 返回值）与 `semgrep --version` 输出，证明跑的确实是所 pin 的版本。

### 3.4 明确禁止项（执行阶段同样适用）

- 禁止 `pip install semgrep` 到系统/当前项目解释器；禁止 `pip install --user`。
- 禁止任何形式的自动下载（脚本内 `curl`/`Invoke-WebRequest`/`pip download` 由智能体执行）；**下载只能由人工在受控环境完成**（见 §11 A 类）。
- 禁止修改 PATH 持久化、环境变量持久化、注册表、`pyproject.toml`、任何已跟踪文件。
- 禁止 `--config auto`、`--config p/...`、registry URL、`semgrep login`、`semgrep ci`（`ci` 走平台认证）。
- 禁止为了「让测试通过」而修改 `semgrep.py` / `planner.py` / `__main__.py` / 测试文件 / 五个冻结文件。

> `SEMGREP_ENABLE_VERSION_CHECK=false` 是 `_spawn()` 在**子进程 env** 内设置的（`semgrep.py:454-455`），属于源码既有行为，**不是**对系统环境的修改。

---

## 4. 完全本地的 fixture 与规则设计

> 以下目录树与文件均为**执行阶段计划产物**，本轮**不创建、不写入**。所有内容位于隔离根 `<ISO>`，不进入主仓库工作树。

### 4.1 隔离根与目录树

```
<ISO>/                              # 例如 %TEMP%\dvs-ext2-real-20261108\（非 C:\ 根、非用户主目录本身）
  wheels/                           # 人工下载的官方 wheel + 官方 JSON API 快照
  venv/                             # 隔离虚拟环境（路径 A）
  requirements.lock                 # 全依赖 + --hash=sha256:...
  rules/                            # 本地规则（自写，无 registry 引用）
    rv-error.yaml
    rv-warning.yaml
    rv-info.yaml
    rv-invalid-yaml.yaml            # 故意非法 YAML（故障注入）
    rv-bad-rule.yaml                # 故意非法规则（故障注入）
  fixtures/
    clean/                          # 无任何匹配的源码
    findings/                       # 同时命中 ERROR/WARNING/INFO 三条规则
    skipped/                        # .semgrepignore + 大文件/二进制，诱发 paths.skipped
    parse-error/                    # 语法错误文件，诱发 errors[]
    slow/                           # 较大输入，配合极小 timeout
  scope.json                        # 本地授权 scope（window 覆盖执行时间）
  evidence/                         # 每次运行的原始证据（受控保存）
  run-logs/                         # 适配器 attempt log 与 CLI stdout/stderr
  reports/                          # 渲染后的 report.md 副本
  wrappers/                         # 仅 Tier B 用的受控转发包装器（可选，需批准）
```

**隔离根约束** `[E]`：`_refuse_reason()`（`semgrep.py:460-479`）拒绝「非目录 / 驱动根 / 用户主目录本身」。因此 `<ISO>` **不得**为 `C:\` 或 `C:/Users/ZTL` 本身；`%TEMP%` 子目录或 Desktop 子目录可用。

### 4.2 本地规则（自写示例，均为虚构/合成）

```yaml
# rules/rv-error.yaml
rules:
  - id: dvs-ext2-rv-error
    languages: [python]
    severity: ERROR
    message: "DVS EXT-2 synthetic fixture: ERROR-severity pattern matched (no real credential)."
    metadata:
      category: security
      cwe: "CWE-000: DVS synthetic fixture"
      confidence: LOW
      references: ["https://example.invalid/dvs-ext2-rv-error"]
    pattern: dvs_fixture_error($X)
```

`rv-warning.yaml` / `rv-info.yaml` 同构，分别把 `severity` 改为 `WARNING` / `INFO`，`id` 与 `pattern` 改为 `dvs_fixture_warning($X)` / `dvs_fixture_info($X)`。这样**一次扫描即可同时得到三个 severity 取值**，用于 §6.2 值域核对。

故障规则：

```yaml
# rules/rv-invalid-yaml.yaml —— 故意非法 YAML，预期非零退出（官方表 rc=5 [R]）
rules: [
```

```yaml
# rules/rv-bad-rule.yaml —— 故意引用未知语言，预期非零退出（官方表 rc=8 [R]）
rules:
  - id: dvs-ext2-rv-bad-rule
    languages: [dvs_nonexistent_language]
    severity: ERROR
    message: "synthetic"
    pattern: dvs_fixture_error($X)
```

### 4.3 fixture 源码（虚构占位，无真实凭据）

```python
# fixtures/findings/app.py  —— 全部为合成调用，不含任何真实密钥/源代码
def sample_error(x):
    return dvs_fixture_error(x)

def sample_warning(x):
    return dvs_fixture_warning(x)

def sample_info(x):
    return dvs_fixture_info(x)
```

`fixtures/clean/app.py` 只含普通赋值与函数，不含上述三个调用。所有 fixture 源码使用**固定哨兵字符串**（例如 `DVS_EXT2_SENTINEL_DO_NOT_LEAK`）标记，供 §8.4 的全量残留清扫核验。

### 4.4 Registry 隔离的硬性约束

| 约束 | 依据 |
|---|---|
| `--config` 只接受 `<ISO>/rules/...` 的**本地路径** | `semgrep.py:271-286`：rules 为空或路径不存在直接 `FAILED`，绝不回退 registry/auto |
| 命令中不得出现 `auto` / `p/` / `registry` / URL | 既有测试 `A-10` 已断言 `[E]`；执行阶段需再对实际 `argv` 复核 |
| 不设置 `SEMGREP_APP_TOKEN` / `SEMGREP_API_KEY` 等平台变量 | 避免任何认证/上传路径 |
| 不使用 `semgrep publish` / `login` / `ci` | 本方案只用 `scan` |
| `.semgrepignore` 仅用于**本地** skip 触发，不引用任何远程资源 | 本地文件 |

### 4.5 与 adapter 白名单的对应关系 `[E]`

规则特意只产出 `semgrep.py` 会读取的字段：`check_id`、`path`、`start.line`/`end.line`、`extra.severity`、`extra.message`、`extra.metadata`（`cwe`/`confidence`/`category`/`references`）。同时在 fixture 中**故意放入 `extra.lines` 才可能包含的哨兵文本**，用于验证白名单确实不采集匹配源码（§8.4）。

---

## 5. 真实执行测试矩阵（7 类场景）

### 5.1 三层结构（先界定「真实性」）

| 层 | 说明 | 能证明什么 |
|---|---|---|
| **Tier A — 真实二进制直通** | 真实 semgrep 二进制 + 本地规则 + fixture，直接执行，`stdout` 原始捕获 | Q1/Q2/Q3/Q4/Q5 的真实行为 |
| **Tier B — 真实二进制 + 受控输出注入** | 真实工具**确实启动并执行**，但通过一个位于隔离根的转发包装器，对 stdout / rc 做**确定性**变换 | adapter 的故障处理路径（无效 JSON、特定 rc、空白 stdout） |
| **Tier C — 完整 CLI 链路** | Tier A 的真实产物经 `python -m vuln_hunter run` 走 Policy → Executor → Journal → Report | Q7 完整链路 + 审计完整性 |

> **诚实边界（必须写进执行报告）**：`RV-06`（无效 JSON）**不是真实 Semgrep 会自然产生的输出**；`RV-07`（超时）依赖外部 timeout；`RV-05` 的非零 rc 由**故意非法的本地规则**真实触发。Tier B 只能证明「adapter 在收到该输入时行为正确」，**不能**证明「真实工具会这样输出」。不得把 Tier B 结果表述为真机兼容性证据。

### 5.2 场景矩阵

| ID | 场景 | 触发方式（真实/注入） | 期望 rc | 期望 `status` / `completeness` | 期望 findings | 层 |
|---|---|---|---|---|---|---|
| **RV-01** | 正常扫描、**无发现** | `fixtures/clean` + 三条正常规则 | `0` | `COMPLETED` / `COMPLETE` | `0` | A + C |
| **RV-02** | 正常扫描、**有发现** | `fixtures/findings` + 三条正常规则 | `0` | `COMPLETED` / `COMPLETE` | `3`（high/medium/info） | A + C |
| **RV-03** | `paths.skipped` | `fixtures/skipped` + `.semgrepignore` / 大文件 / 二进制 | `0` | 视真实形态：`PARTIAL`（有 reason）或 `FAILED`/`INCOMPLETE`（无） | 视判定 | A |
| **RV-04** | `errors` 非空 | `fixtures/parse-error` / 无法解析语言 | `0` 或 `2` `[U]` | `FAILED` / `INCOMPLETE`，**零采收** | `0` | A |
| **RV-05** | 非零退出码 | `rv-invalid-yaml.yaml`（预期 `5`）、`rv-bad-rule.yaml`（预期 `8`）`[R]` | `!= 0` | `FAILED` / `INCOMPLETE`，**零采收**（即使 stdout 有合法 JSON） | `0` | A |
| **RV-06** | 无效 JSON | Tier B 包装器把真实 stdout 替换为截断片段 `{"results": [` | `0` | `FAILED` / `INCOMPLETE`，原始输出不落地 | `0` | B |
| **RV-07** | 超时 | L1 单次 `_run(..., timeout=1)`（真实冷启动通常 >1s）；或大 fixture + 极小 `--timeout` | 被 kill | `TIMEOUT`，无部分输出保留 | `0` | A（注入 timeout） |

### 5.3 逐场景关键核对点

**RV-01（最高优先级）** — `CR-02` 保守策略的成败点。当前实现要求顶层**同时存在** `errors`、`paths`、`paths.skipped`（`semgrep.py:164-193`）。若真实报告**不含** `paths` 或 `paths.skipped`，当前代码会判 `INCOMPLETE → FAILED`，即「正常无发现扫描被判失败」。必须记录：真实顶层键集合、`errors`/`paths.skipped` 是否恒存在、`paths` 是否为 dict。

**RV-02** — 核对 `results[]` 每条的 `check_id`/`path` 是否为字符串且非空、`start.line` 是否为 `int`（非 `bool`）、`extra` 是否为对象、`extra.severity` 取值、`extra.message` 形态、`extra.metadata` 是否为 dict。期望 3 条 finding 且 `severity` 分别为 `high`/`medium`/`info`，`finding_id` 稳定可复现。

**RV-03（次高优先级）** — 核对 `paths.skipped[]` 元素形态：是 `{"path": ..., "reason": ...}` 之类的 dict，还是裸路径字符串？`_skip_explained()`（`semgrep.py:145-154`）只接受含 `reason`/`type`/`message`/`code` 之一且为非空字符串的 dict。若为裸字符串，当前实现判 `INCOMPLETE → FAILED`。这是 `CR-02` 是否需要按版本适配的**决定性证据**。

**RV-04** — 核对 `errors[]` 元素形态与是否伴随非零 rc；验证 `meta.errors_seen` 计数与零采收。

**RV-05** — 验证 `rc != 0 → FAILED`（`semgrep.py:322-329`），确认**即使 stdout 含合法 JSON 也不采收**；同时记录真实 rc 值并与 §6.3 官方表比对。

**RV-06** — 验证 `json.loads` 失败分支（`semgrep.py:342-352`），并核验原始 stdout **不出现**在 `detail` / `meta` / attempt log / journal / report 中。

**RV-07** — 验证 `subprocess.TimeoutExpired → TIMEOUT`（`semgrep.py:301-303`）。注意 `Executor.run_step()` 对 `TIMEOUT` 会重试（`runner.py:267-270`），因此 **L1 用 adapter 单次调用验证状态**，L2 链路中会看到多次 `attempt_start/attempt_end`，需在证据解读时区分。

### 5.4 建议增补（**可选，需单独批准**）

- `RV-08`：`rc=0` + 空白 stdout → `FAILED / INCOMPLETE`（`semgrep.py:331-340`）。
- `RV-09`：全链路哨兵残留清扫（§8.4 的强化版，覆盖 `evidence/`、`output/`、`reports/`）。
- `RV-10`：非 ASCII stdout 在中文 Windows locale 下的解码（`_spawn` 使用 `text=True` 且未指定 encoding，属 `CR-05` 遗留 `[E]`）。

### 5.5 运行方式（模板，本轮不执行）

**L1 — adapter 单次调用**（沿用现有测试 `run_adapter` 的调用形态，但**不 patch `_spawn`**，即真实二进制）：

```python
# <ISO>/verify_l1.py（执行阶段新建，需批准）
# 不修改仓库内任何文件；仅 import 主仓库包并直接调用受保护方法
result = SemgrepAdapter()._run(
    str(target), timeout, io.StringIO(),
    {"id": "s5-semgrep", "adapter": "semgrep", "target": str(target),
     "target_kind": "fs_path", "semgrep_rules": str(rules)})
# 记录 status / ok / detail / meta / findings / 原始 stdout（仅存 <ISO>/evidence/）
```

**L2 — 完整 CLI**（见 §8.1）。

> 执行阶段**不新建仓库内测试文件**；验证脚本一律放在 `<ISO>` 内，避免改变主仓库 `git status`。

---

## 6. 真实 JSON 字段结构 / severity 值域 / 退出码契约核对

### 6.1 字段核对表（源码白名单 ↔ 真实 JSON）

| 源码位置 `[E]` | 代码读取的字段 | 期望类型 | 真实报告实际 | 不符时处置 |
|---|---|---|---|---|
| `:355-359` | 顶层 `results` | 必须存在且为 `list` | `[U]` | 先报告，不改代码 |
| `:364-368` | 顶层 `errors` | **键必须存在**且为 `list` | `[U]` | 见 §10.2 |
| `:369-373` | 顶层 `paths` | 必须为 `dict` | `[U]` | 见 §10.2 |
| `:374-378` | `paths.skipped` | **键必须存在**且为 `list` | `[U]` | 见 §10.2 |
| `:182` | `paths.skipped[]` 元素 | dict 且含 reason-like 字段 | `[U]` | 见 §10.2 |
| `:555` | `results[].check_id` | 非空 `str` | `[U]` | 逐条跳过并计入 `records_skipped` |
| `:558` | `results[].path` | 非空 `str` | `[U]` | 同上 |
| `:493-513` | `start.line` / `end.line` | `int`（`bool` 不算）或缺失 | `[U]` | 缺失时 location 退化为 `path` |
| `:562-564` | `extra` | `dict` | `[U]` | 同上 |
| `:565-568` | `extra.severity` | `str` 且 ∈ 映射表 | `[U]` | 见 §6.2 |
| `:569` | `extra.message` | `str`（可空） | `[U]` | 空则不追加描述 |
| `:570-574` | `extra.metadata` | `dict`（可缺省） | `[U]` | 非 dict 则跳过该记录 |
| `:74-75, :516-546` | `extra.metadata.{cwe,confidence,category,subcategory,likelihood,impact,owasp,references}` | `str` 或 `list[str]` | `[U]` | 异形值忽略（不报错） |
| `:8-9, :552` | `extra.lines` / `fingerprint` | **绝不读取** | `[U]` | 由 §8.4 哨兵核验 |

**核对方法**：Tier A 每次运行把**原始 stdout 完整保存**到 `<ISO>/evidence/<id>/stdout.json`（仅隔离目录），再用一个**只读字段枚举脚本**输出「顶层键集合 / 各字段类型 / severity 值集合 / skipped 元素样例形态」的**摘要**（值脱敏，不复制源码文本）。交付报告只引用摘要与文件哈希，不粘贴原始 JSON。

### 6.2 severity 值域（重点风险）

`_SEVERITY_MAP`（`semgrep.py:80-84`）仅接受：

```python
{"error": "high", "warning": "medium", "info": "info"}
```

`_to_finding()`（`:565-568`）对映射外的值抛 `FindingError` → 该记录被**跳过**并计入 `meta.records_skipped`（`:400-406`），扫描整体仍可能是 `COMPLETED`。`[E]`

> **风险** `[R]`：有第三方资料把 Semgrep 规则 severity 描述为 `INFO / WARNING / ERROR / CRITICAL`。若真实版本输出 `CRITICAL`（或 `error` 之外的大小写/别名），当前实现会**静默丢弃该 finding**。§RV-02 必须枚举真实 `extra.severity` 的全部取值集合并逐条核对；若出现映射外值，属 `CR-06` 引出的**新发现**，须单独报告、单独授权处理，**本方案不预设修复**。

同时核对：大小写（当前实现 `.lower()` 后匹配）、是否含 `INVENTORY`/`EXPERIMENT` 等非规则 severity、以及 severity 是否位于 `extra` 内（而非规则 metadata 内）。

### 6.3 退出码契约

**官方 CLI reference `[R]`**（需人工在 `semgrep.dev/docs/cli-reference` 复核）：

| rc | 含义 |
|---|---|
| `0` | 运行成功；**包括发现了 issues 但未使用 `--error`** |
| `1` | 运行成功且发现问题，**仅在使用 `--error` 时** |
| `2` | Semgrep 自身失败 |
| `3` | 被扫描语言语法非法（仅 `--strict`） |
| `4` | 规则 schema 中 pattern 非法 |
| `5` | 配置不是合法 YAML |
| `7` | 配置中至少一条规则非法 |
| `8` | 无法识别指定语言 |
| `13` | API key 无效 |
| `14` | （已废弃）scan 失败 |

官方文档另明确：`semgrep ci` 与 `semgrep scan` **只要扫描完成就返回 0，无论是否有 findings**；要返回 `1` 需 `--error` 或 blocking rules `[R]`。

**与 EXT-2 实现的关系**：`CR-01` 修复把成功条件收窄为 `rc == 0`，且 `build_command()` 不传 `--error`（`semgrep.py:260-263`）。这与上述官方说明**方向一致** `[I]`，但：

- 这是**文档层佐证**，不是本机实测；`RV-02` 必须确认「**有 3 条 findings 时 rc 仍为 0**」。若真机返回 `1`，则 `CR-01` 的 fail-closed 策略会丢弃一次成功扫描，属需单独报告的契约不符。
- `RV-05` 必须确认无效 YAML / 非法规则的真实 rc 值，并与官方表比对。
- 记录 `rc` 时**同时记录 stdout 是否有效 JSON**，以验证「findings 只取自 `results[]`，不由 rc 推断」。

### 6.4 完整性字段核对（CR-02）

把 `RV-01`/`RV-03`/`RV-04` 的真实摘要填入判定表：

| 真实观察 | 当前代码判定 | 是否符合设计意图 |
|---|---|---|
| `errors=[]`、`paths.skipped=[]`、字段齐全 | `COMPLETE → COMPLETED` | ✅ |
| `errors` 键缺失 | `INCOMPLETE → FAILED` | 需记录真实是否发生 |
| `paths` / `paths.skipped` 键缺失 | `INCOMPLETE → FAILED` | 需记录真实是否发生 |
| `paths.skipped[]` 为带 reason 的 dict | `PARTIAL → COMPLETED` + `[completeness=PARTIAL]` | 需确认 reason 键名是否落在 `_SKIP_REASON_KEYS` 内 |
| `paths.skipped[]` 为裸字符串 | `INCOMPLETE → FAILED` | **最可能的适配触发点** |
| `errors[]` 非空 | `INCOMPLETE → FAILED`，零采收 | 需确认 |

### 6.5 不符时的处置原则

1. **立即停止该分支的后续场景**，保全原始证据与哈希。
2. 写入执行报告：真实输出摘要、与源码期望的差异、影响范围（是否导致正常扫描被判失败 / finding 被静默丢弃）。
3. **不修改任何源码/测试/配置**；是否放宽 `CR-02` 保守策略、是否扩展 severity 映射，均需**单独授权**的新一轮任务。
4. 在 `CR-06` 闭合判据中把该差异标为未决项，不得记为 `PASS`。

---

## 7. 无外部网络访问验证

### 7.1 现状：现有代码**不**阻断出站 `[E]`

`adapters.py:39-54` 的 `tool_env()`：

```python
env = dict(os.environ)
for k in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY",
          "http_proxy", "https_proxy", "all_proxy"):
    env.pop(k, None)
env["NO_PROXY"] = "*"
env["no_proxy"] = "*"
return env
```

它做的是**剥离代理并强制直连**，目的是防止 ambient proxy 污染扫描结果，**不是网络隔离**。`NO_PROXY=*` 甚至可能让直连更顺畅。`_spawn()` 另设 `SEMGREP_ENABLE_VERSION_CHECK=false`（`semgrep.py:455`），`build_command()` 带 `--metrics off`（`:262`）——这些都是**配置层**意图，不是网络层强制。

> 因此「无外部网络访问」**不能**由代码断言，必须靠**外部观测 + 环境阻断**取证。这是本节的证据边界核心。

### 7.2 三层验证方法

| 层 | 方法 | 产出证据 |
|---|---|---|
| **L1 配置层（静态）** | 核对实际 `argv` 不含 `auto`/`p/`/URL/registry；核对 `env` 快照中 `SEMGREP_ENABLE_VERSION_CHECK=false`、无平台 token、无代理变量；核对 `--config` 为本地存在路径 | `argv.txt`、`env-snapshot.txt`（脱敏）、`config-path.txt` |
| **L2 进程观测层** | 在整个扫描窗口内以固定间隔采样本机 TCP/UDP 连接与进程树，筛出 semgrep 及其子进程的**非 loopback 出站**尝试；Windows 可用 `Get-NetTCPConnection` / `netstat -ano` 定时采样，或 `pktmon` / ETW / Sysmon（若已安装） | `netmon-<id>.log` + 采样时间戳区间 + 进程 PID 映射 |
| **L3 网络阻断层（最强）** | 在**隔离环境**中断网或对该进程设置出站拒绝规则后运行；若工具仍需联网，会出现可观测的失败/超时而非静默成功。为避免「无网所以没连上」与「工具本就不联网」混淆，可设置**黑洞 DNS / 不可达代理哨兵**并记录是否有连接尝试 | 阻断配置说明 + 运行是否仍成功 + 连接尝试日志 |

### 7.3 具体手段（Windows，均需人工批准）

- 在 `<ISO>` 内运行，不改动系统防火墙的持久规则；如需临时规则，采用**显式、可撤销、有记录**的方式，并在执行结束后恢复（恢复动作本身也需批准）。
- 用 `Get-NetTCPConnection -State Established` 与 `Get-Process` 建立 PID↔连接映射，采样间隔 ≤1s，覆盖从 spawn 到进程退出的完整窗口。
- 记录 DNS 查询（若可用）与 `semgrep` 子进程列表；特别标注 `semgrep-core`、Python 子进程。
- 对每个 `RV-*` 场景各留存一份网络观测记录，避免只测「无发现」场景。

### 7.4 证据边界（必须写进执行报告）

- **能证明**：在**本次运行、本观测窗口、本主机、本版本、本配置**下，未观测到非 loopback 出站连接；`--config` 为本地路径；未使用 registry/auto。
- **不能证明**：该工具在**任何**配置/未来版本/其他子命令下永不联网；无法排除加密或极短连接逃过采样；无法排除观测工具自身盲区。
- **不能**把「断网后扫描仍成功」表述为「工具无网络依赖」的绝对结论，只能表述为「在给定隔离条件下未观测到出站依赖」。
- 若 L2/L3 因权限或工具缺失无法实施，须登记为 `[U]` 并**降低 `CR-06` 闭合等级**，不得默认通过。

### 7.5 已知历史风险点 `[R]`

`v1.183.0` release notes 提到「**Disable curl-based telemetry on macOS and Windows; default telemetry and scanning remain available**」`[R]` —— 说明 Windows 上曾存在基于 curl 的 telemetry 路径。这正是 §2.1 选择 `1.182.1`（变更**前**版本）作为基线的理由，也意味着**网络观测必须包含 Windows 上的 curl/子进程行为**，不能只看主进程。该项与 `--metrics off`、`SEMGREP_ENABLE_VERSION_CHECK=false` 是否足以覆盖，属 `[U]`，由 L2/L3 实测回答。

---

## 8. Findings / Journal / Report 完整链路验证

### 8.1 L2 CLI 命令模板（本轮不执行）

```bash
python -m vuln_hunter run \
  --scope <ISO>/scope.json \
  --mode safe_scan \
  --target 127.0.0.1 \
  --source-dir <ISO>/fixtures/findings \
  --semgrep-rules <ISO>/rules \
  --evidence-dir <ISO>/evidence/cli-rv02 \
  --timeout 120
```

`scope.json` 沿用仓库既有最小结构（参考 `tests/test_semgrep_integration.py:182-187` 的 `base_scope()` 与 `scripts/example-scope.json`）：`client` / `in_scope` / `out_of_scope` / **`window`（必须覆盖执行时刻）** / `techniques` / `confirmed_by`。门禁是**真实子进程** `python -m vuln_hunter.gate_check`（`__main__.py:127-141`），`window` 过期会直接 REFUSED。

### 8.2 链路核对点（逐项留证）

| # | 环节 | 源码依据 `[E]` | 核对内容 |
|---|---|---|---|
| 1 | Planner | `planner.py:82-92` | `plan` 中出现 `s5-semgrep`，且仅当 binary 解析成功 + 本地 rules 存在；`target_kind="fs_path"` |
| 2 | 命令 | `semgrep.py:245-263, 295` | attempt log 首行为单行、不含换行/控制字符；`argv` 为 `scan + target + --config <LOCAL> + --json + --metrics off` |
| 3 | Adapter → Finding | `semgrep.py:397-445` | `findings` 条数、`severity` 映射、`location`、`rule_id`、`name` alias（含「由 Semgrep 报告的 severity 字段经映射得到」说明） |
| 4 | Runner → Journal | `runner.py:251-260` | `attempt_end` 含 `status`、`ok`、`detail`（带 `[completeness=...]`）、`meta.completeness`、`meta.completeness_reasons`、`meta.records_seen/used/skipped`、`meta.errors_seen`、`meta.paths_skipped` |
| 5 | Findings → Report | `runner.py:300-305`、`report.py:51-64` | `## 发现` 段出现对应条目，渲染的是 `name` alias 而非 `**high** None` |
| 6 | 步骤表 | `report.py:41-47` | `s5-semgrep` 行显示 `[completeness=...]` 的 detail |
| 7 | 审计完整性 | `__main__.py:193-228` | `audit_status()` verify=OK、`head`/`count` 一致、`report_written` 恰好一条、CLI 退出码符合语义 |
| 8 | 证据不落地 | `semgrep.py:3-13` | §8.4 哨兵全量清扫 |

### 8.3 多步骤副作用与证据解读边界

`--source-dir` 会**同时**生成 `s3-bandit`（`planner.py:41-50`），并在 `gitleaks_binary()` 可用时生成 `s4-gitleaks`（`:51-69`）。这些是既有行为，**本方案不修改 planner**。后果：

- CLI 的 `summary` 可能因 bandit/gitleaks 步骤失败而为 `FAILED`，**这不代表 `s5-semgrep` 失败**。
- 链路结论必须以 `journal.jsonl` 中 `step == "s5-semgrep"` 的 `attempt_end` 事件为准，并在报告中显式说明其它步骤的状态。
- CLI 退出码语义（`__main__.py:229`）：`0` = 全部 `COMPLETED`；`1` = 有失败/拒绝；`2` = 门禁拒绝；`3` = 审计失败。不得用退出码单独判定 semgrep 成功与否。

### 8.4 敏感证据不落地（哨兵清扫）

延续现有集成测试 `F` 段做法 `[E]`：在 fixture 中埋入固定哨兵（匹配源码文本），执行完成后对**所有下游产物**做只读全文检索：

```bash
grep -r -l "DVS_EXT2_SENTINEL_DO_NOT_LEAK" \
  <ISO>/evidence <ISO>/reports <ISO>/run-logs \
  <REPO>/evidence <REPO>/output <REPO>/docs 2>/dev/null
```

期望：**零命中**。若命中，说明 `extra.lines`（匹配源码）泄露到了日志/证据/报告，属 `CR-06` 新发现的严重问题，立即停止并报告。

> **原始 stdout 的处理**：`--json` 输出含 `extra.lines`（真实匹配源码），属敏感数据。原始 stdout **只**保存在 `<ISO>/evidence/<id>/stdout.json`，**绝不**写入主仓库 `docs/`、`evidence/`、`output/`，**绝不**粘贴进交付报告；报告只引用其 SHA256 与脱敏字段摘要。

### 8.5 需人工批准项（本类）

- 新建 `<ISO>/scope.json`（本地授权 scope，`window` 需人工确认）。
- 通过 CLI 运行会**写入** `<ISO>/evidence/` 与**主仓库 `output/vuln_hunter_report.md`**。后者是既有验证副产物路径，会被覆盖 `[E]`（`__main__.py:212-215`）——**这一写入需明确批准**；若不批准，应改为在 `<ISO>` 内以工作目录运行 CLI（使 `output/` 落在隔离根），或仅做 L1 层验证。
- 不清理、不删除两个既有验证副产物。

---

## 9. 环境隔离、证据保存、清理边界与回滚

### 9.1 隔离边界

| 项 | 约束 |
|---|---|
| 位置 | `<ISO>` 独立于主仓库工作树；不得为 `C:\` 根或用户主目录本身（§4.1） |
| 解释器 | 路径 A 使用 `<ISO>/venv`，不装进系统/项目解释器 |
| 网络 | §7 的三层观测 / 阻断，任何临时规则需可撤销且有记录 |
| 写入 | 执行阶段的 fixture / 规则 / 脚本 / scope / 证据**全部**落在 `<ISO>`；主仓库唯一可能的写入是 `output/vuln_hunter_report.md`（需批准，见 §8.5） |
| Git | 不执行 commit / reset / clean / checkout / restore / stash；不覆盖既有未提交变更 |

### 9.2 证据清单（每个 `RV-*` 一份）

```
<ISO>/evidence/<rv-id>/
  manifest.txt              # 时间、版本 pin、sys.version、sys.executable、wheel 名 + SHA256
  argv.txt                  # 实际命令（脱敏路径可保留）
  env-snapshot.txt          # 子进程 env 关键键（值脱敏，不含 token）
  stdout.json               # 原始 JSON（敏感，仅隔离目录）
  stdout.sha256             # 原始 stdout 哈希
  field-summary.txt         # 顶层键集合 / 字段类型 / severity 值集合 / skipped 元素形态摘要
  rc.txt / stderr.txt       # 退出码与 stderr（脱敏）
  adapter-result.json       # status / ok / detail / meta / findings（脱敏）
  journal.jsonl             # 该次运行的审计链（如走 L2）
  report.md                 # 渲染报告副本（如走 L2）
  netmon.log                # §7 网络观测记录
  sentinel-scan.txt         # §8.4 清扫结果
```

**证据完整性**：`manifest.txt` 内记录每个文件的 SHA256；执行结束再计算一次总清单哈希，写入交付报告。证据**只读保存、不自动清理**。

### 9.3 清理边界（严格遵守）

- **不清理两个既有验证副产物**：`output/vuln_hunter_report.md` 与 `%TEMP%\tmp.AvXfUFcabf\`（`EXT-2` 实施阶段遗留，历轮均要求保留）。
- **不清理** `dualverify_sentinel-0.1.0/`、18 个空 `evidence/engine-*` 目录、桌面归档 / 备份 / 管理目录。
- **不按扩展名/目录/通配符批量删除**任何文件。
- 任何删除动作都必须**先列出具体文件清单、逐项获得人工确认**后才执行；本方案不预设任何删除。`<ISO>` 内的临时产物默认**保留**，由人工决定处置。

### 9.4 回滚方案（首选「不删除」）

1. **首选（零删除、零改动）**：只要 `semgrep_binary()` 解析不到（`shutil.which` 无命中且 `~/Tools/semgrep/{semgrep.exe,semgrep}` 不存在），`planner.build_plan()` 就**不生成 `s5-semgrep`**（`planner.py:82`）。因此**移除进程级 PATH 前置 / 不传 `--semgrep-rules`** 即等价于完全停用 EXT-2 步骤，无需删除任何文件、无需改代码。
2. 若曾写入 `~/Tools/semgrep/`：先由人工确认具体文件清单，再按确认范围移除（**需单独批准**）。
3. 若曾产生 `<ISO>`：默认保留为证据；清理需人工逐项确认。
4. 若 CLI 覆盖了 `output/vuln_hunter_report.md`：该文件为既有副产物，本轮**不覆盖、不还原**；执行阶段若获批准覆盖，需事先留存其哈希与副本。
5. 核验：回滚后复核五个冻结文件哈希不变、`git status --short` 与执行前快照一致、HEAD 不变。

---

## 10. CR-06 闭合判据与验收建议

### 10.1 闭合判据（全部满足才可建议闭合）

| # | 判据 | 证据来源 |
|---|---|---|
| C1 | 固定版本、wheel SHA256、解释器身份、完整依赖锁定均已记录并与官方一致 | §2 manifest |
| C2 | `RV-01`–`RV-07` **全部执行**，每份证据齐全且哈希可复核 | §9.2 |
| C3 | 真实 JSON 顶层键、`paths.skipped` 元素形态、`errors[]` 形态已枚举并记录 | §6.1 / §6.4 |
| C4 | 真实 `extra.severity` 值域与 `_SEVERITY_MAP` 的适配结论明确（含映射外值处置） | §6.2 |
| C5 | 真实退出码契约已核对，特别是「有 findings 仍为 0」与非法配置 rc 值 | §6.3 |
| C6 | §7 的 L1+L2（建议含 L3）网络观测完成，且结论附**证据边界**声明 | §7 |
| C7 | §8 的 8 个链路核对点全部通过，哨兵清扫零命中，审计链 verify=OK | §8 |
| C8 | 未修改任何源码/测试/配置/冻结文件/历史证据；G15/C14/UNKNOWN/六项测试阶段状态不变 | §12 |
| C9 | 所有契约不符项均已列出并明确「已裁定 / 未裁定」，未裁定项不得记为通过 | §6.5 / §10.2 |

### 10.2 三种可能结论

- **PASS（可闭合 `CR-06`）**：C1–C9 全满足且无未裁定的契约不符 → 建议把 `EXT-2` 由 `CONDITIONAL ACCEPT` 升级为完整 `PASS`（仍需人工验收，本方案不代为变更状态）。
- **CONDITIONAL（部分闭合）**：真机可运行且链路可用，但存在**已明确登记**的契约差异（例如 `paths.skipped` 为裸字符串导致正常扫描被判 `FAILED`），或网络观测 L3 未实施 → 保留 `CONDITIONAL ACCEPT`，把差异列为新发现，等待单独授权的修复轮次。
- **FAIL / 需修复**：真实 flag 不被接受、`rc` 契约与 `CR-01` 假设冲突、severity 值域导致 findings 静默丢弃、或发现源码泄露 → **停止**，出具问题报告，等待人工决定。

> 无论哪种结论，**本轮（Preparation）都不改变任何验收状态**。

---

## 11. 需人工批准清单（汇总）

> 以下全部为**执行阶段**动作，本轮**一项都未执行**。按性质分类，需人工逐类批准后另行授权。

**A 类 — 联网 / 下载（严格限制项，必须显式批准）**

- A1 人工访问 PyPI / GitHub 官方页，核对最终 pin 版本与 `digests.sha256`。
- A2 人工下载 `semgrep==<pin>` wheel 及全部依赖 wheel 到 `<ISO>/wheels`。
- A3（条件）若 Windows wheel 不可用：批准替代路径（隔离容器 / WSL / 官方签名独立二进制）。
- A4（条件）若需查询官方 CLI 文档以复核退出码表：批准该只读检索。

**B 类 — 新建文件 / 写入（均位于 `<ISO>`，主仓库例外已标注）**

- B1 创建隔离根 `<ISO>` 与 §4.1 目录树。
- B2 写入 5 个规则文件、4 组 fixture 源码、`.semgrepignore`、`scope.json`、`requirements.lock`。
- B3 新建 `<ISO>/verify_l1.py`、字段枚举脚本、Tier B 转发包装器（如采用）。
- B4 创建 `<ISO>/venv`（隔离虚拟环境）并安装已哈希锁定的依赖。
- B5 **主仓库写入例外**：CLI 会覆盖 `output/vuln_hunter_report.md`；需批准，或改为在 `<ISO>` 作为工作目录运行以避开。
- B6 写入 `docs/EXT-2-REAL-VERIFICATION-REPORT.md`（执行阶段交付报告；本轮不创建）。

**C 类 — 环境 / 网络配置**

- C1 在**验证进程级**前置 `<ISO>/venv/Scripts` 到 `PATH`（不改持久化）。
- C2 §7 的临时出站阻断规则 / 断网 / 网络观测工具启用，及其**恢复动作**。
- C3（条件）命中 `SEMGREP_FALLBACKS` 的 `~/Tools/semgrep/` 目录写入。

**D 类 — 删除 / 清理（默认不做，需逐项确认）**

- D1 任何 `<ISO>` 内产物的清理：须先列具体文件清单并逐项确认。
- D2 任何 `~/Tools/semgrep/` 的移除：同上。
- **明确禁止**：清理 `output/vuln_hunter_report.md`、`%TEMP%\tmp.AvXfUFcabf\`、`dualverify_sentinel-0.1.0/`、空 evidence 目录、归档/备份/管理目录。

**E 类 — 状态变更（本方案不提出，仅列出以示边界）**

- E1 把 `CR-06` 标记为闭合 / 把 `EXT-2` 升级为 `PASS`：只能在 §10.1 C1–C9 全部满足后，由**人工验收**决定。
- E2 任何对 G15 / `EXECUTION_INTEGRITY` / C14 / 历史 `UNKNOWN` / 六项测试阶段状态的改写：**不在本方案范围内**。
- E3 任何源码/测试/冻结文件修改以适配真实契约：**需单独授权的新任务**。

---

## 12. 本轮保护边界核验

| 项 | 状态 |
|---|---|
| 未安装 Semgrep、未下载任何 wheel/二进制、未运行任何扫描 | ✅ 仅执行只读命令 |
| 未修改源码 / 测试 / 配置 / 历史证据 / 既有报告正文 | ✅ 唯一新建文件为本方案文档 |
| 五个冻结文件 | ✅ 未触碰（哈希逐项复核见 §12.1） |
| 未重跑六项历史测试 | ✅ 未运行任何测试 |
| 两个验证副产物 | ✅ 未清理（保留） |
| G15 / C14 / `UNKNOWN` / 六项测试阶段状态 | ✅ 未改写 |
| Git 写操作 / commit | ✅ 未执行（仅只读 `status` / `diff` / `rev-parse`） |
| 超出授权的动作 | ✅ 已全部列入 §11 等待批准，未擅自执行 |

### 12.1 冻结五文件哈希复核（2026-11-08，与 Remediation 收尾完全一致）`[E]`

| 文件 | SHA256 | 状态 |
|---|---|---|
| `vuln_hunter/adapters.py` | `65ece047b13784e0efbf00bd71166279734ea150a90ec56db5830bd551098f59` | 未变 |
| `vuln_hunter/runner.py` | `29d71dc54f34bc024bde13cc8ec5fcac2745fddeb676ad302aaa5320ebcd842c` | 未变 |
| `vuln_hunter/report.py` | `59caebb3094896f1a6eb0e63de16b87d59c52a6512a77d2e0661a54e60761683` | 未变 |
| `tests/test_d2d1_proccleanup.py` | `1cd2b9483c4869c4fbad4ecadeafaad8b67a1396b69d8694bb62852a2c194c13` | 未变 |
| `tests/test_d2d0_d2d4.py` | `840046857997917bec2dd542c7af6819261001af42bce5a6aa14684bf668aaf9` | 未变 |

附加基线同样未变：`vuln_hunter/findings.py` `544729a84dcddc738e2e9cd6af187c8afc7af8ace06c619ba76ec3ebd322b33d`、`vuln_hunter/adapters_ext/gitleaks.py` `630139aa1f5187b62b06b2f6f4ff1c77d0c62892eb9d40aff1a165e01522937a`。

其它只读核验：HEAD `9913c50` 未变；`git diff --stat` 仍为原 5 个 `M` 文件 / `83 insertions(+), 4 deletions(-)`；`git status --short` 较本轮开始前**仅新增** `?? docs/EXT-2-REAL-VERIFICATION-PLAN.md`；`output/vuln_hunter_report.md` 与 `%TEMP%\tmp.AvXfUFcabf\` 仍在；`~/Tools/semgrep/` 仍不存在、`pip show semgrep` 仍为 not found（证明未产生任何安装痕迹）。`[E]`

**外部信息获取说明**：本轮进行了**只读**公开信息检索以确定候选版本与官方 CLI 契约，所有结果标注 `[R]` 并注明需人工复核；其中**一项查询被安全策略拦截（审批超时），未重试、未绕过、未推断其内容**，相关事项已完整转入 §2.4 / §11 A 类待批准清单。本轮**未联网下载任何工具或文件**。

---

## 13. 完成后停止

本方案为 `EXT-2 Real Semgrep Verification Preparation` 的唯一交付物。**本轮到此停止，等待人工批准具体执行方案**（§11 清单）。在获得批准前：

- 不安装工具、不联网下载、不运行 Semgrep、不执行任何扫描；
- 不创建 fixture / 规则 / 验证脚本 / scope / 证据目录；
- 不修改任何源码、测试、配置、冻结文件或历史证据；
- 不改变任何验收状态。

*文档结束。*
