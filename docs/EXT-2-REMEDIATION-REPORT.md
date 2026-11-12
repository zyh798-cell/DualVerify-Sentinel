# DualVerify-Sentinel V1 — EXT-2 Remediation Report（CR-01 / CR-02 / CR-03）

- **生成时间**：2026-11-08（本地时间，GMT+8）
- **仓库**：`C:/Users/ZTL/Desktop/DualVerify-Sentinel`，分支 `main`，HEAD `9913c50`（**未变**）
- **授权**：`DualVerify-Sentinel V1 — EXT-2 Code Review Findings Remediation`
- **修复范围**：仅 `CR-01`（Semgrep 退出码契约）、`CR-02`（扫描完整性信号）、`CR-03`（报告与日志字段净化）
- **前置依据**：`docs/EXT-2-CODE-REVIEW.md`（独立只读审查，BLOCKER 2 / NON-BLOCKER 4）
- **实施记录更新**：`docs/EXT-2-IMPLEMENTATION-REPORT.md` 已**纯追加** §10，§1–§9 原文未改写
- **最终状态建议**：**CONDITIONAL ACCEPT（有条件接受）** —— 三项修复在离线层全部通过；`CR-06` 仍未闭合，完整 `PASS` 需真实二进制验证

> 标注：`[E]` 直接观测、`[S]` 登记陈述、`[I]` 推断、`[U]` 无法确认。本轮未运行真实 semgrep、未安装任何工具。

---

## 1. 授权范围与执行边界

| 项 | 执行情况 |
|---|---|
| 允许修改的三个文件 | ✅ 仅改 `vuln_hunter/adapters_ext/semgrep.py`、`tests/test_semgrep_adapter.py`、`tests/test_semgrep_integration.py` |
| 「必须修改其他文件时先停止」 | ✅ **未触发**：无需修改任何其他代码/配置文件。文档侧仅按授权 §5 追加实施记录 §10 与新建本报告 |
| 五个冻结文件 | ✅ 绝对未修改（哈希见 §5） |
| 不覆盖已有未提交变更 | ✅ `git diff --stat` 与基线完全一致，见 §3.3 |
| 不清理两个验证副产物 | ✅ `output/vuln_hunter_report.md`、`%TEMP%\tmp.AvXfUFcabf\` 原样保留 |
| 不修改 G15 / C14 / 历史 UNKNOWN | ✅ 未触碰；六项测试阶段仍未关闭，未描述为已通过 |
| 不执行 Git commit / 写操作 | ✅ 未执行（仅 `status` / `diff` / `rev-parse` 只读） |
| 不自动处理其他审查问题 | ✅ `CR-04`、`CR-05`、`CR-06` 均未改动，仅在 §6 记录 |
| 不运行真实 Semgrep / 不安装工具 | ✅ 全部测试仍替换单一 `_spawn` 缝 |
| 不重跑六项历史测试 | ✅ 未运行 `test_findings_integration` / `test_gitleaks_adapter` / `test_ext12_registration` / `test_findings_schema` / `test_ext13f1_stdout` / `test_gitleaks_integration` |

---

## 2. CR-01 / CR-02 / CR-03 修复前后差异

### 2.1 CR-01 — Semgrep 退出码契约（HIGH / 原 BLOCKER）

| 项 | 修复前 | 修复后 |
|---|---|---|
| 成功退出码集合 | `rc not in (0, 1) → FAILED`，即 **`rc=1` 被当作扫描完成** | **`rc != 0 → FAILED`**，仅 `rc == 0` 是已证明的完整扫描 |
| docstring 契约 | 「`0 = 无发现；1 = 有发现；其他 = 失败`」（从 `gitleaks.py:35-39` 逐字复制，未在 Semgrep 上验证） | 重写：明确「未传 `--error`，任何非零退出码都无已证明的『有发现』含义」；findings 完全取自合法完整的 `results[]` |
| 命令 | `scan / --config / --json / --metrics off`（无 `--error`） | **不变**（保持 verified-flag 纪律，不引入可选 flag 依赖）；新增测试 `P-04` 断言永不含 `--error` |
| 非零退出时的 findings | 空白/非法 JSON 会 FAILED，但 `rc=1` + 合法 JSON 会走到采收分支 | 立即 `FAILED`，`meta.completeness=INCOMPLETE`，**零 findings 采收** |
| 测试建模 | `returncode=1` 被大量用作「成功且有发现」（C/H/I/N/E-07/D-03 等 14 处） | 全部改为 `returncode=0`；新增 P 段把 `rc=1`（空 JSON / 带 findings）与 2/3/4/5/7/8/13/14/127 作为**负面用例** |

关键源码差异（`semgrep.py`）：

```diff
-        if rc not in (0, 1):
-            log.write(f"semgrep exit {rc} (scan did not complete)\n")
-            return AdapterResult("FAILED", False, f"semgrep exit {rc} (scan did not complete)")
+        if rc != 0:
+            reason = f"non-zero exit {rc} (no --error flag: unproven)"
+            log.write(f"semgrep exit {rc} -> FAILED ({reason})\n")
+            return AdapterResult(
+                "FAILED", False,
+                f"semgrep exit {rc} (non-zero exit is not treated as a "
+                f"completed scan; no findings harvested)",
+                meta=_meta("INCOMPLETE", [reason]))
```

**验收对应**：满足「不得把未经证明的非零退出码当作扫描成功」「Findings 以合法、完整的 JSON 结果为依据」「增加 rc=1 + 合法空 JSON 等测试」。`[E]`

> 说明：官方 CLI 文档仅作辅助佐证（见 `EXT-2-CODE-REVIEW.md §1.5`）。本修复**不依赖**任何关于真实 Semgrep 退出码的假设——收窄为 `rc==0` 后，即便未来某版本确实在 `rc=1` 时输出合法结果，实现仍 fail-closed，不会误报成功。

### 2.2 CR-02 — 扫描完整性信号（MEDIUM / 原 NON-BLOCKER）

| 信号 | 修复前 | 修复后 |
|---|---|---|
| `errors` 键缺失 | `data.get("errors", [])` **乐观默认为空** → 可报 `COMPLETED` 0 发现（测试 E-03 固化） | 明确策略：**`INCOMPLETE → FAILED`**，detail 含 `lacks 'errors' field; completeness unverified`，零采收 |
| `errors[]` 非空 | `FAILED`，不采收 | 保持 `FAILED`，统一归入 `INCOMPLETE`，`meta.errors_seen` 保留计数 |
| `paths` 对象缺失 | 默认 `{}` 容忍 | **`INCOMPLETE → FAILED`**（覆盖不可验证） |
| `paths.skipped` 键缺失 | 默认 `[]` 容忍 | **`INCOMPLETE → FAILED`**（无法排除跳过） |
| `paths.skipped` 非空 | 仅记 `meta.paths_skipped`，**不判失败、不进报告正文** | 逐项检查 reason：`reason/type/message/code` 任一非空 ⇒ **已解释** → `PARTIAL`；裸字符串/异形 ⇒ **未解释** → `INCOMPLETE/FAILED` |
| 完整性状态可见性 | 仅 adapter `meta`（报告正文看不到） | `detail` 前缀 `[completeness=...]` 经冻结 `report.py:47` **进入报告步骤表**；`meta["completeness"]` 与 `meta["completeness_reasons"]` 进入 journal `attempt_end.meta` |

**`PARTIAL` 兼容方案（用户要求「先报告兼容方案、不得擅自修改核心 schema」）**：

`runner.py:29-37` 的冻结 `STATUS_PRIORITY = [REFUSED, ABORTED, CANCELLED, FAILED, TIMEOUT, SKIPPED, COMPLETED]` **无 `PARTIAL`**；`runner.py:40-48` 的 `_summary_bucket()` 把任何未识别状态按 `FAILED` 处理（fail-closed 设计）。因此本轮：

1. **不新增 `AdapterResult.status` 值**，不修改 `adapters.py` / `runner.py` / `report.py`（全部冻结）；
2. 三态放在 **adapter 私有层**：`meta["completeness"] ∈ {COMPLETE, PARTIAL, INCOMPLETE}` + `detail` 前缀 + journal；
3. 对外 `status` 映射（全部为现有枚举）：

| completeness | 触发 | 对外 status / ok | findings | 报告正文 |
|---|---|---|---|---|
| `COMPLETE` | 字段齐全、`errors=[]`、无跳过 | `COMPLETED` / `True` | 采收 | `[completeness=COMPLETE]` |
| `PARTIAL` | 跳过项**全部带 reason**、`errors=[]` | `COMPLETED` / `True` | 采收 | `[completeness=PARTIAL] … skipped` 明确标注非完整 |
| `INCOMPLETE` | 非零退出、缺 `errors`/`paths`/`paths.skipped`、`errors[]` 非空、未解释跳过、结构错误、空白/非法 JSON | **`FAILED` / `False`** | **不采收** | `[completeness=INCOMPLETE] … results incomplete` |

4. 因此「**存在未解释的跳过或错误时报告完整扫描**」被完全排除；`PARTIAL` 虽对外为 `COMPLETED`，但 detail/meta/报告均显式标注「非完整扫描」，不冒充完整。
5. `runner._summary_bucket()` 的 fail-closed 语义与 `summary_status()` 的最差状态优先规则**完全不变**；测试 `Q-07` 断言本轮所有观测结果只出现 `COMPLETED/FAILED/TIMEOUT`，`G-05` 证明 `PARTIAL` 标记确实进入冻结渲染器的步骤表。`[E]`

> 保守性说明：真实 Semgrep 的 `paths.skipped` 元素形态、`errors`/`paths` 键是否稳定存在**尚未经真实二进制验证**（`CR-06`）。当前策略刻意从紧：缺字段/裸字符串跳过均判 `FAILED`。若真机验证表明 skipped 常以纯路径字符串给出，需按版本适配「可解释」判定；该适配属后续单独授权事项，本轮未做。`[U]`

### 2.3 CR-03 — 报告与日志字段净化（MEDIUM / 原 NON-BLOCKER）

| 项 | 修复前 | 修复后 |
|---|---|---|
| 白名单字段的**值** | `_str_field()` 仅 `.strip()`；`path` / `check_id` / `message` / `references` 原样进入 `title` / `description` / `evidence` / `name` / 纯文本日志 | 新增 `_sanitize()`：`\r` `\n` `\t` 与 C0/C1 控制字符（含 ESC）→ 空格并折叠空白；Markdown 元字符 `\ \| \` \* \_ \[ \] \< \> \#` 反斜杠转义 |
| 命令行日志 | `log.write("$ " + " ".join(cmd))`，operator 传入的 target/rules 含换行即可伪造日志行 | 新增 `_log_line()`：只做控制/换行中性化（不转义 Markdown，保持路径可读） |
| 报告注入 | `report.py:60-63` 原样渲染 `name`（含 `check_id`），换行可伪造新发现行，`*` `\|` 可破坏格式 | `name` 由净化后的 `f.title` 构造，`G-08` 断言渲染报告中不出现伪造的 `- **[CRITICAL]**` 行 |
| `extra.lines` / `fingerprint` | 不读取 | **仍不读取**（`R-05` 用含恶意值的记录验证残留清扫） |
| 必要原始证据 | — | **保留**：净化是转义/替换而非删除，记录不因「看起来奇怪」被丢弃；`R-01` 断言仍产出 1 条 finding，`R-06` 断言可读文本（如 `evil`）仍在 `rule_id` |
| 审计透明 | — | `meta["sanitization"]` 固定说明净化规则（value-free） |

关键源码差异：

```diff
-def _str_field(rec: dict, name: str) -> str:
-    val = rec.get(name)
-    ...
-    return val.strip()
+def _str_field(rec: dict, name: str) -> str:
+    """CR-03: every whitelisted string value is sanitised before it can
+    reach a Finding, the plain-text attempt log or the Markdown report."""
+    val = rec.get(name)
+    ...
+    return _sanitize(val.strip())
```

`_metadata()` 的 tags 与 references 同样改为经 `_sanitize()` 处理；`_to_finding()` 因所有输入字段已净化，其拼装的 `description` / `title` / `location` 自动获得保护。未对 `references` 做 scheme 白名单（避免丢弃非 URL 形式的合法引用，符合「不丢失必要原始证据」），仅做字符中性化。`[E]`

---

## 3. 修改文件与实际 diff

### 3.1 文件清单（3 个代码/测试文件 + 2 个文档交付物）

| 文件 | 类型 | 修复前 → 修复后行数 | 修复后 SHA256 |
|---|---|---|---|
| `vuln_hunter/adapters_ext/semgrep.py` | 修改（未跟踪新增文件） | 460 → **621** | `434dfcfa90c85ad465c9cd102e966d87d4faf2f149d7c2d1733fe368b696ee9e` |
| `tests/test_semgrep_adapter.py` | 修改（未跟踪新增文件） | 551 → **701** | `403c683af51ec5bf4e00a3a8dfc01a399ca387a301560858c814ae58df6cdf67` |
| `tests/test_semgrep_integration.py` | 修改（未跟踪新增文件） | 658 → **752** | `1c084bd8f9727caed8e65c6f5421b1c89fe6f5d10adc7c9612f4834b0383ab52` |
| `docs/EXT-2-IMPLEMENTATION-REPORT.md` | **纯追加 §10** | 246 → 274 | `e68bbcb59d77f64e…` |
| `docs/EXT-2-REMEDIATION-REPORT.md` | 新建 | 本报告 | 见文末交付说明 |

**未修改**：`vuln_hunter/__main__.py`、`vuln_hunter/planner.py`、`vuln_hunter/adapters_ext/__init__.py`、`pyproject.toml`、`vuln_hunter/adapters.py`、`vuln_hunter/runner.py`、`vuln_hunter/report.py`、`vuln_hunter/findings.py`、`vuln_hunter/adapters_ext/gitleaks.py`、任何历史测试/证据/报告正文。

### 3.2 精确替换点（实际 diff 摘要）

三个受审文件均为 **Git 未跟踪文件**（`git status` 中为 `??`），因此 `git diff` 不产生它们的行级 diff。以下列出本轮**全部**精确替换点，完整内容以文件为准：

**`semgrep.py`（7 处）**
1. `L35-43` docstring `EXIT-CODE SEMANTICS` 段 → CR-01/CR-02 新契约；
2. `import json` 后新增 `import re`；
3. `SEMGREP_SEVERITY_MAP` 后**新增 ~118 行**：`_CONTROL_RE`、`_MARKDOWN_SPECIALS`、`_SANITIZATION_NOTE`、`_sanitize()`、`_log_line()`、`_SKIP_REASON_KEYS`、`_skip_explained()`、`_completeness()`、`_meta()`；
4. 命令行日志 `log.write("$ " + " ".join(cmd) + "\n")` → `_log_line()` 逐项处理；
5. `_run()` 主体：rc 判定、空白 stdout / JSON / 结构校验各失败分支统一带 `_meta("INCOMPLETE", …)`；删除原 `if raw_errors:` 独立分支，改由 `_completeness()` 统一分级；成功分支 `detail` 加 `[completeness=...]` 前缀与 reasons；
6. `_str_field()` → `_sanitize()`；
7. `_metadata()` → tags/refs 全部净化。`__all__` 未改。

**`tests/test_semgrep_adapter.py`（7 处）**
1. 头部 coverage map 增 P/Q/R 段与 remediation 声明；
2. `fake_report()` 增 `include_errors / include_paths / include_skipped / scanned` 关键字参数（用于构造不完整报告）；
3. 全文 `returncode=1` → `returncode=0`（14 处；其中 `returncode=127` 因前缀误伤，已单独修正回 `127`，见 §4.4）；
4. `D-03` 描述改为 rc=0 空白输出；
5. `E-03` 断言由「缺 `errors` 键被容忍 → COMPLETED」改为 → `FAILED / INCOMPLETE`；
6. `L-04` 改为「带 reason 跳过 → PARTIAL」，新增 `L-05`「裸字符串跳过 → FAILED」；
7. 新增 **P 段 13 项、Q 段 7 项、R 段 7 项**（共 27 项）+ `O-01` 自动覆盖 61 次观测运行。

**`tests/test_semgrep_integration.py`（4 处）**
1. 头部 coverage map 增 G 段与 remediation 声明；
2. `fake_report()` 增完整性构造参数；
3. `E-07` 的 `returncode=1` → `0`（使该用例仍测「非法 JSON」而非退出码）；
4. 新增 **G 段 8 项**（CR-01 ×2、CR-02 ×4、CR-03 ×2，全部经真实 Executor + 冻结 `render_report`）+ `F-01` 自动覆盖 15 个场景。

### 3.3 Git 状态核验

```
git rev-parse --short HEAD   -> 9913c50            (未变)
git diff --stat              -> 5 files changed, 83 insertions(+), 4 deletions(-)
   pyproject.toml | tests/test_engine.py | tests/test_taskgraph.py
   vuln_hunter/__main__.py | vuln_hunter/planner.py
   （与 EXT-2 实施报告 §7.1 登记的基线完全一致 ⇒ 本轮未触碰任何已跟踪文件）
git status --short           -> M 文件仍为上述 5 个；?? 列表较审查前
                                仅新增 docs/EXT-2-CODE-REVIEW.md（上一轮交付）
                                与本轮 docs/EXT-2-REMEDIATION-REPORT.md
```

`git diff` 输出含既有 LF→CRLF warning，为工具提示，未执行任何换行符改写操作。`[E]`

### 3.4 实施记录更新方式

`docs/EXT-2-IMPLEMENTATION-REPORT.md` 采用**在末尾追加 §10** 的方式，原文 §1–§9（含 §9 的 `PASS` 结论、§6 已知限制、§7 哈希、§8 回滚步骤）**逐字未改**。§10 记录修复范围、三个文件行数/哈希、修复要点、测试结果摘要，并明确「§9 的 PASS 现受 CR-06 约束」。`[E]`

---

## 4. 测试命令、退出码与结果

### 4.1 EXT-2 两个套件（最终运行）

| # | 命令 | 退出码 | 结果 |
|---|---|---|---|
| 1 | `python tests/test_semgrep_adapter.py` | **0** | **105/105 checks passed**（修复前 77/77 → 新增 28 项） |
| 2 | `python tests/test_semgrep_integration.py` | **0** | **46/46 checks passed**（修复前 38/38 → 新增 8 项） |

新增用例分布：`P-01..P-05 / P-03-2..14,127`（CR-01，13 项）、`Q-01..Q-07`（CR-02，7 项）、`L-04 改写 + L-05`（CR-02）、`R-01..R-07`（CR-03，7 项）、`G-01..G-08`（集成层，8 项）。`O-01` 残留清扫覆盖 **61** 次观测运行、`F-01` 覆盖 **15** 个集成场景，均零泄露。`[E]`

### 4.2 相关离线回归（17 套）

命令形式：`python tests/<suite>.py`（逐套记录退出码与末行）。

| 套件 | EXIT | 结果 |
|---|---|---|
| `test_engine` | 0 | 30/30 |
| `test_taskgraph` | 0 | 35/35 |
| `test_graph_loop` | 0 | 25/25 |
| `test_decision` | 0 | 44/44 |
| `test_journal_chain` | 0 | 12/12 |
| `test_s2_hardening` | 0 | 15/15 |
| `test_e2e_lab` | 0 | ALL PASSED |
| `test_cli_gate` | 0 | 6/6 |
| `test_gate_packaging` | 0 | 5/5 |
| `test_check_scope` | 0 | 34/34 |
| `test_adapters_gate` | 0 | 17/17 |
| `test_p9` | 0 | ALL PASSED |
| `test_d2d1_proccleanup`（冻结） | 0 | PASS |
| `test_d2d4_f1` | 0 | PASS |
| `test_d2c0_remediation` | 0 | ALL PASSED |
| `test_d2c_r4` | 0 | ALL PASSED（1 SKIP：本机无真实首跑 journal，环境性） |
| `test_d2d0_d2d4`（冻结） | **首轮 1；复跑 5 次均 0** | 见 §4.3 |

**未运行**：六项历史测试（按授权）、`test_d2c_first_run`（需真实 nuclei，不在本轮必要回归面）、真实 semgrep（禁止安装/运行）。`[E]`

### 4.3 冻结套件首轮失败的定性与处置（如实登记）

首轮 `test_d2d0_d2d4.py` 输出 `D2D0+D2D4: PASS=29 FAIL=1 SKIP=0`，唯一失败为 `FI-03`。只读排查结论：

- `FI-03`（`tests/test_d2d0_d2d4.py:459-488`）断言 `a2["head"] == audit["head"]`，比较的是**两个独立 `EvidenceJournal`** 各自 append 三条事件后的链头；
- `vuln_hunter/journal.py:34-35` 的 `utcnow()` 为 **`timespec="seconds"`**（秒级），`:143` 每条记录都带 `ts`。两次 append 若跨越秒边界，链头哈希必然不同 → 断言偶发失败；
- 复跑 **5 次**全部 `[PASS] FI-03` 且 `PASS=30 FAIL=0 SKIP=0`；
- 该冻结套件**不引用** `semgrep` 或 `adapters_ext`（`grep` 零命中），与本次修复无因果关系。

**处置**：按保护边界**未修改该冻结文件、未重定断言、未改写任何历史结果**；此处如实登记该时间依赖型 flaky 观测。本轮不把该套件记为「无条件通过」，结论表述为「首轮 1 次偶发失败，复跑 5 次全绿，判定为历史 flaky，与本次改动无关」。`[E]`

### 4.4 实施过程中的一处自纠

对单元测试执行全文 `returncode=1 → returncode=0` 替换时，`returncode=127`（F-03）因前缀匹配被误改为 `returncode=027`，导致 `SyntaxError: leading zeros in decimal integer literals`。已用 `grep` 定位**唯一**受影响处并精确修正为 `127`；修正后单元测试 `EXIT=0 / 105-105`。未使用任何批量回退或 Git 写操作。`[E]`

---

## 5. 冻结文件哈希复核

| 文件 | 修复前基线（Code Review §1.3） | 修复后实测 | 状态 |
|---|---|---|---|
| `vuln_hunter/adapters.py` | `65ece047b13784e0…` | `65ece047b13784e0efbf00bd71166279734ea150a90ec56db5830bd551098f59` | **未变** |
| `vuln_hunter/runner.py` | `29d71dc54f34bc02…` | `29d71dc54f34bc024bde13cc8ec5fcac2745fddeb676ad302aaa5320ebcd842c` | **未变** |
| `vuln_hunter/report.py` | `59caebb3094896f1…` | `59caebb3094896f1a6eb0e63de16b87d59c52a6512a77d2e0661a54e60761683` | **未变** |
| `tests/test_d2d1_proccleanup.py` | `1cd2b9483c4869c4…` | `1cd2b9483c4869c4fbad4ecadeafaad8b67a1396b69d8694bb62852a2c194c13` | **未变** |
| `tests/test_d2d0_d2d4.py` | `840046857997917b…` | `840046857997917bec2dd542c7af6819261001af42bce5a6aa14684bf668aaf9` | **未变** |

附加基线同样未变：`vuln_hunter/findings.py` `544729a84dcddc73…`、`vuln_hunter/adapters_ext/gitleaks.py` `630139aa1f5187b6…`。

未修改且哈希与 EXT-2 实施阶段一致的受保护链文件：`vuln_hunter/__main__.py` `704e58fc26d547a4…`、`vuln_hunter/planner.py` `251f760ab1cc920d…`、`vuln_hunter/adapters_ext/__init__.py` `9654fd2b081d5084…`。`[E]`

---

## 6. 剩余风险（尤其 CR-06）

| 编号 | 风险 | 状态 | 说明 |
|---|---|---|---|
| **CR-06** | **真实 Semgrep 二进制端到端验证缺口（原 BLOCKER-验收证据）** | **未闭合** | 本机未安装 semgrep，授权明确禁止自动安装/联网下载规则。本轮 151 项 checks + 17 套回归**全部仍基于 `_spawn` mock**。无法证明：真实 `scan --config --json --metrics off` 的 flag 兼容性、真实 JSON 顶层字段构成、`errors`/`paths`/`paths.skipped` 的真实形态与「reason」字段命名、真实退出码语义、`extra.severity` 值域、以及无任何出站连接。**这直接关系授权目标「可实际运行、结果可审计、失败状态可信，而不是只完成接口或模拟调用」。** |
| CR-02 保守策略 | 完整性字段从紧判定可能导致真实扫描全 `FAILED` | **待真机验证** | 若真实报告不含 `errors`/`paths.skipped` 键，或 `skipped` 以纯路径字符串给出，当前「缺字段/无 reason → FAILED」策略会使正常扫描失败。需真机确认后按版本适配；本轮按「宁可 fail-closed」原则未放宽。`[U]` |
| CR-04 | `_refuse_reason` 无 source-root containment、树内符号链接未验证 | **未处理（用户明确不自动处理）** | 与 `gitleaks.py:221-240` 逐字一致，属既有架构边界，非 EXT-2 引入；符号链接树内行为取决于真实工具版本。`[U]` |
| CR-05 | `--config` 未显式拒绝 registry/以 `-` 开头的值；`_spawn` `text=True` 未指定 encoding | **未处理（用户明确不自动处理）** | 触发条件苛刻；非 ASCII stdout 在中文 locale 下可能假失败。与 gitleaks/bandit 既有模式一致。`[U]` |
| 单条记录跳过 | 畸形记录仍被逐条跳过、整体可 `COMPLETED` | **沿用既有设计** | `meta.records_skipped` 与 attempt 日志留痕；本轮未扩大授权改此行为。`[S]` |
| 冻结套件 flaky | `FI-03` 秒级时间戳依赖 | **已登记，未修复** | 见 §4.3；不属 EXT-2 范围。`[E]` |

**其他沿用限制**（见 `EXT-2-IMPLEMENTATION-REPORT.md §6`）：`--metrics off` / `SEMGREP_ENABLE_VERSION_CHECK=false` 未经真机验证；`--config` 只做存在性检查；`s5-semgrep` 的 `kind` 为 `generic`；六项测试阶段未关闭，G15 FAIL / `EXECUTION_INTEGRITY=NOT_OK` / C14 FAIL / 历史 UNKNOWN 一律保持原样。

---

## 7. 保护边界核验汇总

- HEAD `9913c50` 未变；**无 Git commit**；未执行 `reset/clean/checkout/restore/stash`。`[E]`
- 五个冻结文件哈希逐一不变（§5）。`[E]`
- 原有 5 个 `M` 未提交变更全部保留，`git diff --stat` 与基线一致。`[E]`
- 两个验证副产物未清理；未触碰 `dualverify_sentinel-0.1.0/`、18 个空 `evidence/engine-*` 目录、归档/备份/管理目录。`[E]`
- 未修改历史证据、历史测试、既有报告正文（实施报告仅追加 §10）。`[E]`
- 未改写 G15 / C14 / 历史 UNKNOWN；六项测试阶段未关闭。`[E]`
- 本轮唯一新建文件：`docs/EXT-2-REMEDIATION-REPORT.md`；唯一追加：`docs/EXT-2-IMPLEMENTATION-REPORT.md §10`。`[E]`

---

## 8. 回滚方案（未执行）

三个受改文件均为未跟踪的 EXT-2 新增文件，回滚不产生数据损失：

1. 恢复 `vuln_hunter/adapters_ext/semgrep.py`：删除本轮新增的 `import re`、辅助函数块；把 `_run()` 恢复为 `rc not in (0,1)` + 原 `if raw_errors:` 分支 + 原 `meta` 结构；`_str_field()` / `_metadata()` 恢复为 `.strip()`；docstring 恢复原退出码契约。
2. 恢复 `tests/test_semgrep_adapter.py` / `tests/test_semgrep_integration.py`：删除 P/Q/R 与 G 段，恢复 `fake_report()` 原签名、`E-03` / `L-04` / `E-07` 原断言，把 P/Q/R 之外改回的 `returncode=0` 中属于「原为 1」的 14 处还原。
3. 撤销文档：删除 `docs/EXT-2-IMPLEMENTATION-REPORT.md` 的 §10（仅删除追加段，§1–§9 不动）；`docs/EXT-2-REMEDIATION-REPORT.md` 为交付留档，可保留。
4. 核验：复核冻结五文件哈希不变；重跑两个 EXT-2 套件与相关回归；确认 `git status` 回到修复前快照。

> 更安全的等效停用方式（不涉及删除）：在 `planner.build_plan` 不生成 `s5-semgrep` 或不传 `--semgrep-rules`，适配器即完全不参与运行。本轮未执行任何回滚。

---

## 9. 最终状态建议

### **CR-01 / CR-02 / CR-03 修复：完成（离线层 PASS）**

- 三项修复全部落在授权的三个文件内，未触碰任何冻结文件与核心 schema；
- `PARTIAL` 采用兼容方案实现三态可区分，未修改 `STATUS_PRIORITY` / `AdapterResult`；
- 单元 `105/105`、集成 `46/46`、相关离线回归 16 套首轮全绿 + 1 套历史 flaky 复跑 5 次全绿；
- 净化保持证据不丢失，`extra.lines` / `fingerprint` 仍不读取，残留清扫零泄露。

### **EXT-2 整体：建议 `CONDITIONAL ACCEPT`，不建议标记无条件 `PASS`**

理由：`CR-06` 仍是**未闭合的 BLOCKER（验收证据层）**。修复的是「实现逻辑在假定输入下的正确性」，而授权目标要求「可实际运行……而不是只完成接口或模拟调用」。在真实 semgrep 可用前，所有关于工具契约的结论仍是 `[U]`。

建议人工二选一：

- **(A) 先补验再验收**（推荐）：单独授权在受控环境提供/安装固定版本 semgrep，用本地规则 + fixture 源码树做一次真实端到端扫描，核对退出码、JSON 字段、`errors`/`paths.skipped` 形态、severity 值域与出站连接；据此复核本轮 CR-02 的保守策略是否需要按版本适配；随后确认完整 `PASS`。
- **(B) 显式降级接受**：把 EXT-2 状态登记为 `PASS (实现/离线层) + UNVERIFIED (真实工具层)`，并将 `CR-06` 作为未决项写入验收状态文件，待工具可用时补验。

**是否需要修复后重新测试**：本轮已完成并全部通过（§4）。若走 (A)，需在上述真实二进制验证后**再补一轮**针对真实输出的端到端用例；仍不重跑六项历史测试。

---

*本报告为 EXT-2 Remediation 交付物。未自动修复 CR-04/05/06，未运行真实 Semgrep，未安装工具，未执行 Git commit。完成后停止，等待人工验收。*
