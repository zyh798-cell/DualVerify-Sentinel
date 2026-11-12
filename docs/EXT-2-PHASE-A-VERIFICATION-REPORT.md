# DualVerify-Sentinel V1 — EXT-2 Real Semgrep Verification — Phase A 核验报告

- **授权**：`EXT-2 Real Semgrep Verification — Phase A Approval`（仅批准 `docs/EXT-2-REAL-VERIFICATION-PLAN.md §11` 的 A 类事项）
- **核验窗口**：2026-11-09 17:47:54 – 18:06:51 GMT+8（UTC 09:47:54 – 10:06:51Z）
- **仓库**：`C:/Users/ZTL/Desktop/DualVerify-Sentinel`，分支 `main`，HEAD `9913c50`（**未变**）
- **阶段性质**：**纯只读信息核验**。未下载任何文件、未安装任何软件、未创建 venv / 规则 / fixture / 验证脚本、未运行 Semgrep、未执行任何扫描、未修改源码/测试/配置/现有证据、未修改 PATH / 注册表 / 系统环境变量、未删除/覆盖/移动任何文件、未执行 Git 写操作。
- **唯一新建文件**：本核验报告 `docs/EXT-2-PHASE-A-VERIFICATION-REPORT.md`。
- **前置依据**：`docs/EXT-2-REAL-VERIFICATION-PLAN.md`（§2 / §6 / §7 / §11 A 类）、`docs/EXT-2-REMEDIATION-REPORT.md`（`CR-06` 未闭合，`CONDITIONAL ACCEPT`）。

> **标注体系**：`[E]` 本机直接观测；`[R]` 官方来源原文/逐字数据（本轮只读获取，附来源与 URL）；`[I]` 基于 `[E]`+`[R]` 的分析推断（**明确标注，不作为事实**）；`[U]` 无法确认，按停止条件登记为 UNKNOWN，**不推断**。
>
> **本轮未重试任何被安全策略拦截的网络操作**：上一轮 Preparation 阶段有一次 WebSearch（`pypi JSON API digests sha256 pip download --require-hashes verify wheel checksum official`）被拦截并超时，本轮**未重复该查询、未换工具/措辞绕过、未推断其内容**。本轮使用的是**本阶段用户明确授权**的官方 URL 只读访问，目的为核对发布信息、SHA256、wheel 兼容性、CLI 契约与相关行为。

---

## 0. 结论摘要（先看这里）

| # | 结论 | 状态 |
|---|---|---|
| 1 | `semgrep==1.182.1` 官方发布信息、来源、许可证、Python 要求、classifiers 全部核实 | ✅ `[R]` |
| 2 | 官方 PyPI JSON API 给出**全部 8 个分发文件的 `digests.sha256`**，含 `win_amd64` wheel | ✅ `[R]` |
| 3 | **存在与本机 Python 3.13 / Windows / AMD64 匹配的官方 wheel**（tag 含 `cp313`+`py313`+`win_amd64`，`requires_python >=3.10`） | ✅ 分发层已确认 `[R]`+`[E]` |
| 4 | wheel 内是否捆绑可运行的 Windows `semgrep-core`、1.182.1 能否在本机实际启动 | **`UNKNOWN`**（官方页面未说明，禁止推断；不选择任何替代安装方式） |
| 5 | 官方 CLI「`scan`/`ci` 扫描完成即 `0`，无论有无 findings；`1` 需 `--error`」逐字确认 | ✅ 与 `CR-01` 收窄方向一致 `[R]` |
| 6 | **官方内部退出码文本存在不一致**（正文 vs 内嵌 `--help` 的 `EXIT STATUS`），差异已登记 | ⚠️ `[R]`，真机前不裁定 |
| 7 | 官方 JSON schema：根级 `required = [results, errors, paths]` → `CR-02` 对 `errors`/`paths` 的要求**成立** | ✅ `[R]` |
| 8 | **官方 JSON schema：`paths.skipped` 不是必填**（`scanned_and_skipped.required` 仅 `[scanned]`）→ 与 `CR-02`「缺 `paths.skipped` 即 FAILED」存在**契约冲突** | 🔴 **重大发现 `[R]`，未修改代码** |
| 9 | `skipped_target` 是 dict 且 `required = [path, reason]` → 与 `_skip_explained()` 的 `reason` 判定**相容** | ✅ `[R]` |
| 10 | **官方 severity 值域远超 `_SEVERITY_MAP`**：规则 YAML 当前推荐 `LOW/MEDIUM/HIGH/CRITICAL`，`match_severity` 允许 9 个值；EXT-2 仅映射 3 个 | 🔴 **重大发现 `[R]`，未修改代码** |
| 11 | 官方 metrics 说明：本地 `--config` 文件不发 metrics；`--metrics off` 永不发送；源码/私有规则永不上传 | ✅ 配置层证据 `[R]`，**不等于网络层证明** |
| 12 | 新发现：官方 env（`SEMGREP_RULES` / `SEMGREP_SEND_METRICS`）未被 `tool_env()` 清理；首次运行会写 `~/.semgrep/settings.yml` | ⚠️ `[R]`，仅登记 |
| 13 | 是否触发停止条件 | 「来源不可访问」**未触发**；「wheel 兼容性无法确认」在**运行层**触发 → 已标 UNKNOWN，**未自行选择替代安装方式**；无操作超出授权。**按指令完成后停止，不进入 Phase B** |

> **两个重大发现（#8 / #10）均为 `CR-06` 引出的新契约差异。本轮严格只读，未修改任何代码、测试、配置或方案文档；是否适配需单独授权。**

---

## 1. 授权范围与执行边界核验

| 授权项 | 执行情况 |
|---|---|
| 1. 核对 `semgrep==1.182.1` 官方发布信息、来源及 SHA256 校验和 | ✅ §3 / §4 |
| 2. 核对该版本是否存在与本机 Python / Windows / 架构兼容的 wheel | ✅ 分发层确认；运行层 UNKNOWN（§5） |
| 3. 核对官方 CLI 文档中的退出码、JSON 输出字段、Severity 值域及相关行为 | ✅ §6 / §7 / §8 / §9；部分字段因官方页面内容截断标 UNKNOWN（§11） |
| 4. 记录来源、核验时间、原始证据和无法确认事项 | ✅ §2 / §10 / §11 及各节逐字引文 |

| 禁止项 | 执行情况 |
|---|---|
| 不下载任何文件 / 安装任何软件 | ✅ 未写盘、未 `pip install`、未 `pip download`；`pip show semgrep` 仍为 not found、`semgrep` 仍不在 PATH、`~/Tools/semgrep` 仍不存在 |
| 不创建 venv / 规则 / fixture / 验证脚本 | ✅ 零创建 |
| 不运行 Semgrep / 不执行扫描 | ✅ 零执行 |
| 不修改源码 / 测试 / 配置 / Git 状态 / 现有证据 | ✅ 未修改任何既有文件；未执行 Git 写操作；唯一文件变化为新建本报告 |
| 不修改 PATH / 注册表 / 系统环境变量 | ✅ 未修改 |
| 不删除 / 覆盖 / 移动任何文件 | ✅ 零操作 |
| 不重试被拦截的网络操作 / 不绕过审批 | ✅ 上一轮被拦截的 WebSearch 未重试、未换路、未推断；本轮仅做本阶段授权的官方 URL 只读访问 |
| 不自行进入 Phase B | ✅ 本轮完成后停止；§13 仅列所需授权 |

**「读取官方 JSON / HTML 文本」与「下载文件」的边界说明**：本轮通过只读方式访问官方页面的**文本内容**（PyPI JSON API 元数据、HTML 文档、JSON schema 文本）并在此引用，**未把任何 wheel、sdist、二进制、压缩包写入本地磁盘**。所引 SHA256 为**官方声明值**（`digests.sha256`），**不是**本地文件实测哈希；本地实测需下载文件，属 Phase B，本轮禁止。

---

## 2. 本机环境事实 `[E]`（只读，2026-11-09）

```
sys.version             = 3.13.14 (main, Jun 11 2026, 04:04:46) [MSC v.1944 64 bit (AMD64)]
sys.version_info        = (3, 13, 14, 'final', 0)
sys.executable          = C:\Users\ZTL\.workbuddy\binaries\python\versions\3.13.12\python.exe
platform.platform()     = Windows-11-10.0.26300-SP0
platform.machine()      = AMD64
platform.architecture() = ('64bit', 'WindowsPE')
os.name                 = nt
64bit                   = True
pip tag (inferred)      = cp313
```

> **环境事实**：解释器**目录名**为 `3.13.12` 而 `sys.version` 为 `3.13.14`，两者不一致；wheel 兼容性判断以 `sys.version` / `sys.version_info` 为准。`[E]`

其它只读核验：`git rev-parse --short HEAD` = `9913c50`；`command -v semgrep` = absent；`python -m pip show semgrep` = `Package(s) not found: semgrep`；`C:/Users/ZTL/Tools/semgrep` 不存在。`dist/` 下的 `dualverify_sentinel-0.1.0-py3-none-any.whl` 与 `.tar.gz` 为 **2026-11-02 的既有项目自身构建产物**（时间戳 11-02 21:29/21:30），与 semgrep 无关，本轮未触碰。`[E]`

---

## 3. 官方发布信息核验

### 3.1 PyPI JSON API（原始证据，`[R]`）

- 来源：`https://pypi.org/pypi/semgrep/1.182.1/json`
- 核验时间：本轮窗口内；返回内容为**官方 JSON 原文**（未经过摘要改写）

逐字关键字段：

```json
"info": {
  "version": "1.182.1",
  "requires_python": ">=3.10",
  "license": null,
  "license_expression": "LGPL-2.1-or-later",
  "classifiers": [
    "Environment :: Console",
    "Operating System :: MacOS",
    "Operating System :: Microsoft :: Windows",
    "Operating System :: POSIX :: Linux",
    "Programming Language :: Python :: 3.10",
    "Programming Language :: Python :: 3.11",
    "Programming Language :: Python :: 3.12",
    "Programming Language :: Python :: 3.13",
    "Programming Language :: Python :: 3.14",
    "Topic :: Security",
    "Topic :: Software Development :: Quality Assurance"
  ]
}
```

`urls` 数组共 **8 项**（7 个 `bdist_wheel` + 1 个 `sdist`），全部 `requires_python = ">=3.10"`，全部 platform/Python tag 为
`cp310.cp311.cp312.cp313.cp314.py310.py311.py312.py313.py314`，上传时间均为 `2026-10-22T02:1x:xxZ`。

### 3.2 PyPI 官方项目页（`[R]`）

- 来源：`https://pypi.org/project/semgrep/1.182.1/`
- 逐字要点：

```text
Released: Oct 22, 2026
License expression: LGPL-2.1-or-later
Requires: Python >=3.10
Classifiers: Operating System :: Microsoft :: Windows / MacOS / POSIX :: Linux
             Programming Language :: Python :: 3.10 / 3.11 / 3.12 / 3.13 / 3.14
Maintainers: 2 (eljin, r2c)
Newer release available (1.184.0)
"Semgrep analyzes code locally on your computer or in your build environment: by default, code is never uploaded."
```

> **登记**：官方页面显示已有更新版本 `1.184.0`。本方案 pin `1.182.1` 属**刻意固定的验证基线**（避开 `v1.183.0` 的变更窗口），**不是**最新版，也不自动升级。`[R]`

PyPI 页面「Metrics」段逐字：

```text
Using remote configuration from the Registry (like --config=p/ci) reports pseudonymous rule metrics to semgrep.dev.
When using configs from local files (like --config=xyz.yml), metrics are sent only when the user is logged in.
To disable Registry rule metrics, use --metrics=off.
```

### 3.3 GitHub 官方 release（`[R]`）

- 来源：`https://github.com/semgrep/semgrep/releases/tag/v1.182.0`
- 逐字要点：

```text
Release v1.182.0
[1.182.0] - 2026-10-20
Added:   Objective-C language support (objc, alpha)
Changed: c-sharp-pro grammar v0.23.1; hcl grammar v1.2.0; lua grammar v0.5.0
Fixed:   C++ range-based for loops with structured bindings (CODE-10028)
         requirements.txt version-range/bare-name direct dependency (SC-4242)
Infra/Release Changes: bundled Tree-sitter Elixir grammar v0.3.5
```

该 release 页**未出现** Windows、Python 版本支持、telemetry/metrics、JSON 输出、退出码或 severity 相关条目；页面文本**未列出 release assets 及其平台** → 对应项标 `UNKNOWN`（§11 U3）。

### 3.4 版本对应关系 `[U]`

PyPI `1.182.1`（2026-10-22）与 GitHub tag `v1.182.0`（2026-10-20）版本号与日期不同；**官方页面未说明二者的精确对应/差异** → `UNKNOWN`，不推断（§11 U1）。

---

## 4. 官方 SHA256 校验和（逐字原始证据）

> 全部取自 `https://pypi.org/pypi/semgrep/1.182.1/json` 的 `urls[].digests.sha256`，**64 位十六进制逐字登记**。`[R]`
> **证据边界**：这些是**官方声明值**；本轮禁止下载，因此**未做本地文件比对**。Phase B 下载后必须用本地 `sha256sum` / `Get-FileHash` 逐项复核。

| # | `filename`（省略公共前缀 `semgrep-1.182.1-`） | `digests.sha256` | `upload_time_iso_8601` |
|---|---|---|---|
| 1 | `cp310...cp314.py310...py314-none-macosx_10_14_x86_64.whl` | `1db6d5becbb60d697a312fce6ec7e00cfde4eff1d221cce7ce85c49df55240eb` | `2026-10-22T02:13:05.646312Z` |
| 2 | `...-none-macosx_11_0_arm64.whl` | `89fe0afe240455800f806145f5679707892ea9bbd442a56eab1ea0b25a95f4c6` | `2026-10-22T02:13:09.729537Z` |
| 3 | `...-none-manylinux_2_34_aarch64.whl` | `3fdfbd68ac5eeead60983dbcd539428bbc40d01f805e0569301068d06be7eaa3` | `2026-10-22T02:13:14.187043Z` |
| 4 | `...-none-manylinux_2_34_x86_64.whl` | `bba25e5a38db5061d725c0920699ecee3e8137026427e722a271bd9bb8d25a40` | `2026-10-22T02:13:19.709620Z` |
| 5 | `...-none-musllinux_1_2_aarch64.whl` | `c38a3490fca93080e26e5f169e7e1fcb46742dd77e3d8e0fd9190653cb6c4ccd` | `2026-10-22T02:13:25.094667Z` |
| 6 | `...-none-musllinux_1_2_x86_64.whl` | `1e18f12a091cb7258f879c5fea1b47a10768af212f1f78ee0c16c52e00be32b7` | `2026-10-22T02:13:31.602987Z` |
| **7** | **`...-none-win_amd64.whl`** | **`e464d398107d026aa6e9c938fab2efabdf2ff8a9c7a52d7abeed0c149e62b68c`** | `2026-10-22T02:13:37.143187Z` |
| 8 | `semgrep-1.182.1.tar.gz`（`packagetype: sdist`） | `b072c59734384784a912b991c417b6c8e4771abdb3c39b9196fc01efdff8aa10` | `2026-10-22T02:11:13.063425Z` |

**`win_amd64` wheel 完整文件名（逐字）**：

```
semgrep-1.182.1-cp310.cp311.cp312.cp313.cp314.py310.py311.py312.py313.py314-none-win_amd64.whl
```

**`digests.sha256` 与 `core-metadata.sha256` 的区分（重要，避免混淆）** `[R]`：

- `digests.sha256` = **wheel 文件本身**的 SHA256 → 这才是下载后要比对的值。
- `core-metadata.sha256` = wheel **内部 `METADATA` 文件**的 SHA256，**不是** wheel 的哈希。例如 `win_amd64` wheel 的 `core-metadata.sha256` 为 `2f00e69002bbfefa14e777fb027444e46bd83ad26a45f050676b45d10ead3be3`；其它平台分组另有 `dfe99b5ab5bfd717c330b5603e64b086f2b923bfa90bb7249c9b67c8d68c8257`（macOS）、`954eb6a4fe16189874ef585860e85e5c64bd95d909fa2a2c32599a0c3f66cc9f`（Linux）等。
- 本地校验**必须使用** `digests.sha256`。

> **未核对项**：PyPI JSON API 返回内容中未包含 `info.requires_dist`（依赖树），因此**完整依赖清单及其哈希无法确认** → `UNKNOWN`（§11 U14）。

---

## 5. wheel 兼容性核对

### 5.1 分层结论

| 层 | 结论 | 依据 |
|---|---|---|
| **分发层**：是否存在匹配本机的官方 wheel | ✅ **确认存在** | §4 #7 的 `win_amd64` wheel；tag 含 `cp313`/`py313`/`win_amd64`，ABI `none`；`requires_python >=3.10`；官方 classifiers 含 `Microsoft :: Windows` 与 `Python :: 3.13` `[R]` |
| **本机侧**：平台/解释器匹配 | ✅ **匹配** | `sys.version 3.13.14` → `cp313`；`Windows-11-10.0.26300-SP0` / `AMD64` / `64bit` / `nt` → `win_amd64` `[E]` |
| **运行层**：wheel 内是否捆绑可执行的 Windows `semgrep-core`、1.182.1 能否在本机实际启动并完成扫描 | **`UNKNOWN`** | 官方页面未说明；本轮禁止安装/运行；**不得推断**，也**不自行选择任何替代安装方式**（§11 U2） |

### 5.2 与方案 §2.4 A2 的对应

方案 §2.4 `A2` 要求「确认该版本是否有可用于 Windows 的 wheel / `semgrep-core` 原生二进制」。**本轮已确认前者（官方 `win_amd64` wheel 存在且有官方 SHA256）；后者（`semgrep-core` 原生组件及其可运行性）仍为 `UNKNOWN`**。处置严格按停止条件：标记 UNKNOWN，不推断、不选择替代路径、不进入 Phase B。

> 因此 `docs/EXT-2-REAL-VERIFICATION-PLAN.md §2.1` 中「若官方 wheel 在 Windows 上不可用则退回容器/WSL」的**触发条件未成立**（wheel 可用）；但该措辞本轮**未修改**（禁止修改既有文档），留待 Phase B 授权后由人工决定是否更新。

---

## 6. 官方 CLI 退出码契约核对

### 6.1 官方「Exit codes」段（逐字，`[R]`）

来源：`https://semgrep.dev/docs/cli-reference#exit-codes`

```text
0: Semgrep ran successfully and found no errors (or did find errors, but the --error flag is not being used).
1: Semgrep ran successfully and found issues in your code (while using the --error flag).
2: Semgrep failed.
3: Invalid syntax of the scanned language. This error occurs only while using the --strict flag.
4: Semgrep encountered an invalid pattern in the rule schema.
5: Semgrep configuration is not valid YAML.
7: At least one rule in the configuration is invalid.
8: Semgrep does not understand specified language.
13: The API key is invalid.
14: [Deprecated] Semgrep scan failed.
When using Semgrep Managed Scans, you may also see other exit code values...
```

### 6.2 同页内嵌 `semgrep scan --help` / `semgrep ci --help` 的 `EXIT STATUS` 段（逐字，`[R]`）

```text
EXIT STATUS
       semgrep scan exits with:
       0   OK
       1   some findings
       2   fatal error
       3   invalid target code
       4   invalid pattern
       5   unparseable YAML
       7   missing configuration
       8   invalid language
       13  invalid API key
       99  not implemented in osemgrep
```

（`semgrep ci` 的 `EXIT STATUS` 与上表逐字相同。）

### 6.3 官方内部差异登记（⚠️ 不裁定）

| rc | 「Exit codes」段 | `EXIT STATUS`（help） | 处置 |
|---|---|---|---|
| `1` | 成功且有 issues，**仅当使用 `--error`** | `some findings`（未提 `--error`） | 以 §6.4 的 getting-started 逐字说明为准理解语义；差异如实登记，真机前不裁定 |
| `7` | `At least one rule in the configuration is invalid` | `missing configuration` | **UNKNOWN**（§11 U7） |
| `14` | `[Deprecated] Semgrep scan failed` | 未列出 | **UNKNOWN**（§11 U7） |
| `99` | 未列出 | `not implemented in osemgrep` | **UNKNOWN**（§11 U7） |

> 方案 §5.2 `RV-05` 预期「无效 YAML → rc=5、未知语言 → rc=8」：两处官方文本在 `5`（unparseable YAML / 配置不是合法 YAML）与 `8`（invalid language / 无法识别语言）上**语义一致**，可作为 Phase B 的预期参考；但 `1/7/14/99` 的差异意味着**真机实测仍不可替代**。`[R]`+`[I]`

### 6.4 「完成即 0」的官方逐字确认（`[R]`）

来源：`https://semgrep.dev/docs/getting-started/cli#exit-codes`

```text
The CLI commands `semgrep ci` and `semgrep scan` finish with exit code `0`
as long as the scan completes, regardless of whether there were findings.
To finish with exit code `1` when there are findings:
- Configure blocking rules
- Pass in the `--error` flag when running `semgrep scan`.
When you run `semgrep ci`, you can pass in the `--no-suppress-errors`
if you don't want internal errors suppressed.
```

CLI reference 的 `--error` 逐字：`Exit 1 if there are findings. Useful for CI and scripts.`

**对 `CR-01` 的意义 `[I]`**：官方明确「扫描完成即 `0`，有 findings 亦不改变；`1` 需 `--error`」。`EXT-2` 的 `build_command()`（`semgrep.py:260-263`）**不传 `--error`**，`CR-01` 修复后把成功条件收窄为 `rc == 0`，方向与官方文档一致。本轮**只做文档层确认**，**仍未在本机实测**「有 findings 时 rc 是否确为 0」→ 该实测属 Phase B `RV-02`，不得据此提前判定 `CR-06` 闭合。

### 6.5 其它 flag / env 行为（逐字摘录，`[R]`）

| 项 | 官方原文要点 | 与 EXT-2 的关系 `[I]` |
|---|---|---|
| `--config=VAL (absent SEMGREP_RULES env)` | 「YAML configuration file, directory of YAML files ending in `.yml|.yaml`, URL of a configuration file, or Semgrep registry entry name」；`--config auto` 会「automatically obtain rules… your project URL will be used to log in to the Semgrep registry」 | 本地目录规则**受官方支持** ✅；但 `SEMGREP_RULES` env 可影响 config，`tool_env()` **未清理**该变量 → 新风险（§9.4） |
| `--metrics=ENUM (absent=auto or SEMGREP_SEND_METRICS env)` | `auto`：从 server 拉 config **或**已登录时发送；`on`：每次都发；**`off`：「metrics are disabled altogether and not sent」** | `--metrics off` 有效 ✅；`SEMGREP_SEND_METRICS` env 未被 `tool_env()` 清理 → 新风险（§9.4） |
| `--enable-version-check (absent SEMGREP_ENABLE_VERSION_CHECK env)` | 「Checks Semgrep servers to see if the latest version is run; disabling this may reduce exit time after returning results」 | 确认该 env **存在且控制出站版本检查** ✅；但官方未说明取值 `false` 的精确语义 → UNKNOWN（§11 U8）；且暗示检查可能发生在结果返回之后 → 影响网络观测窗口 |
| `--json` / `--json-output=VAL` | 「Output results in Semgrep's JSON format」；`--json-output` 可「Write a copy… to a file or **post to URL**」 | `--json` 受支持 ✅；`--*-output` / `-o` 的 URL 能力是潜在出站路径，EXT-2 **不使用**这些 flag ✅ |
| `--severity=ENUM` | 「Each should be one of INFO, WARNING, or ERROR」 | 这是**过滤 flag** 的值域，**不等同于**输出字段 `extra.severity` 的值域（§8） |
| `--timeout=DOUBLE (absent=5.)` | 「Maximum time to spend running a rule on a single file in seconds」；`--timeout-threshold` 默认 3 | 官方 `--timeout` 是**每文件每规则**，与 EXT-2 `subprocess.run(timeout=...)` 的**进程级**超时不同 → Phase B `RV-07` 设计需区分 |
| `--max-target-bytes` / `--exclude-binary-files` | 默认 `1000000` bytes；二进制文件默认跳过 | 与 `paths.skipped` 触发方式相关 ✅ |
| `--verbose` | 「Includes… a list of rules and details such as skipped files」 | 说明 skipped 信息在日志层可见，但**不等于** JSON 的 `paths.skipped` |
| `semgrep scan` vs `ci` | `scan` 是「scanning local codebases or … when you don't have a Semgrep account」的推荐命令；`ci` 「fetches your organization's scan configurations from Semgrep AppSec Platform」 | EXT-2 使用 `scan` **无需登录** ✅ |
| 环境变量清单 | `SEMGREP_BASELINE_COMMIT`、`SEMGREP_ENABLE_VERSION_CHECK`、`SEMGREP_FORCE_COLOR`、`SEMGREP_RULES`、`SEMGREP_SEND_METRICS`（`ci` 另有 `SEMGREP_AUDIT_ON`、`SEMGREP_SUPPRESS_ERRORS`） | 见 §9.4 |

---

## 7. 官方 JSON 输出字段核对

### 7.1 来源（`[R]`）

`https://semgrep.dev/docs/getting-started/cli` 逐字指向官方 schema：

```text
> The JSON schema for Semgrep's CLI output is in
> semgrep/semgrep-interfaces (semgrep_output_v1.jsonschema)
```

访问：`https://github.com/semgrep/semgrep-interfaces/blob/main/semgrep_output_v1.jsonschema`
**证据边界**：该 schema 位于仓库 **`main` 分支，未 pin 到 1.182.1**；且返回页面标注 `[content truncated]`，部分定义不可见。因此以下结论是「**当前官方 schema 的声明**」，**不能**直接等同于「1.182.1 实际 `--json` 输出」→ 见 §11 U4 / U6。

### 7.2 根级结构（逐字，`[R]`）

```json
"type": "object",
"required": [ "results", "errors", "paths" ],
"properties": {
    "version":  { "description": "since: 0.92", "$ref": "#/definitions/version" },
    "results":  { "type": "array", "items": { "$ref": "#/definitions/cli_match" } },
    "errors":   { "type": "array", "items": { "$ref": "#/definitions/cli_error" } },
    "paths":    { "description": "targeting information", "$ref": "#/definitions/scanned_and_skipped" },
    "time": ..., "explanations": ..., "rules_by_engine": ...,
    "engine_requested": ..., "interfile_languages_used": ...,
    "skipped_rules": ..., "subprojects": ..., "mcp_scan_results": ..., "profiling_results": ...
}
```

**关键**：`results`、`errors`、`paths` 是**根级必填**；`version` 是属性但**非必填**。

### 7.3 `paths` / `paths.skipped` / `skipped_target`（逐字，`[R]`）

```json
"scanned_and_skipped": {
  "type": "object",
  "required": [ "scanned" ],
  "properties": {
    "scanned": { "type": "array", "items": { "$ref": "#/definitions/fpath" } },
    "skipped": { "type": "array", "items": { "$ref": "#/definitions/skipped_target" } }
  }
},
"skipped_target": {
  "type": "object",
  "required": [ "path", "reason" ],
  "properties": {
    "path":    { "$ref": "#/definitions/fpath" },
    "reason":  { "$ref": "#/definitions/skip_reason" },
    "details": { "type": "string" },
    "rule_id": { "$ref": "#/definitions/rule_id" }
  }
},
"fpath": { "type": "string" }
```

`skip_reason` 可见 `oneOf` / `const` 值（17 个，逐字）：

```
always_skipped, semgrepignore_patterns_match, cli_include_flags_do_not_match,
cli_exclude_flags_match, exceeded_size_limit, analysis_failed_parser_or_internal_error,
excluded_by_config, wrong_language, too_big, minified, binary, irrelevant_rule,
too_many_matches, Gitignore_patterns_match, Dotfile, Nonexistent_file,
insufficient_permissions
```

### 7.4 与 EXT-2 `CR-02` 实现的对照（🔴 重大发现）

| 官方 schema 声明 | `semgrep.py` 当前实现 `[E]` | 一致性 |
|---|---|---|
| 根级 `required` 含 `errors` | `:164-169` 缺 `errors` 键 → `INCOMPLETE → FAILED` | ✅ **一致**（保守策略有依据） |
| 根级 `required` 含 `paths` | `:171-174` `paths` 非 dict → `INCOMPLETE → FAILED` | ✅ **一致** |
| **`scanned_and_skipped.required` 仅 `[scanned]`，`skipped` 非必填** | `:176-179` **`"skipped" not in paths` → `INCOMPLETE → FAILED`** | 🔴 **契约冲突**：若 1.182.1 在**无跳过文件**时省略 `skipped` 键，正常扫描（含 `RV-01`）会被判为 `FAILED` 且零采收 |
| `skipped_target` 是 dict，`required = [path, reason]`，`reason` 为字符串常量 | `:145-154` `_skip_explained()` 要求 dict 且 `reason/type/message/code` 之一为非空字符串 | ✅ **相容**：带 reason 的 skipped 会判 `PARTIAL`，不会误判 `FAILED` |
| `errors` 是 array（元素为 `cli_error`） | `:364-368` 要求 list、非空即 `INCOMPLETE` | ✅ 一致（元素结构未核对，§11 U11） |

> **处置**：本轮**未修改 `semgrep.py`**（禁止项）。该差异登记为 `CR-06` 引出的**新契约差异**，需 Phase B 真机确认 `1.182.1` 在无跳过时是否省略 `skipped` 键，再决定是否单独授权适配。方案 §6.4 的判定表本轮亦**未修改**。

### 7.5 未从 schema 原文核对到的字段（`[U]`）

页面内容截断，`cli_match`（即 `results[]` 元素）、`cli_error`（即 `errors[]` 元素）的完整定义**未出现在可见文本中**。因此以下字段**本轮无法从官方 schema 核对**，`[U]`，**不推断**：

- `results[].check_id` / `path` / `start.line` / `end.line` / `extra` / `extra.message` / `extra.metadata` / `extra.lines` / `extra.fingerprint`
- `errors[]` 元素结构（仅见 `error_severity` 的 `level` 值 `error`/`warn`/`info`）
- `finding.severity`（schema 原文仅给出描述「int|string until minimum version exceeds 1.32.0…」，**无枚举**）

→ 见 §11 U5 / U11 / U6。

---

## 8. Severity 值域核对（🔴 重大发现）

### 8.1 官方规则语法（规则 YAML 的 `severity`），逐字 `[R]`

来源：`https://semgrep.dev/docs/writing-rules/rule-syntax`

```text
`severity` `string` Severity can be `LOW`, `MEDIUM`, `HIGH`, or `CRITICAL`.
It indicates the criticality of issues detected by a rule. ...
The older levels `ERROR`, `WARNING`, and `INFO` match `HIGH`, `MEDIUM`, and `LOW`.
Severity values remain backwards compatible.
```

即：**当前推荐 4 值 `LOW/MEDIUM/HIGH/CRITICAL`**；旧 3 值 `ERROR/WARNING/INFO` 向后兼容并映射为 `HIGH/MEDIUM/LOW`。

同页关于 `metadata`（逐字）：`Arbitrary user-provided data; attach data to rules without affecting Semgrep behavior`；`The metadata are also displayed in the output of Semgrep if you're running it with --json.` → 确认 `extra.metadata` 会出现在 JSON 输出中 ✅。`message` 为 `string`、`id` 为 `string` 且无严格格式约束、`languages` 为 `array`（Python 合法值含 `python`）✅ 与 `_str_field()` / fixture 设计相容 `[I]`。

### 8.2 官方 JSON schema 的 `match_severity`（输出 `extra.severity`），逐字 `[R]`

```json
"severity": { "$ref": "#/definitions/match_severity" },
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

即官方输出 schema 允许 **9 个值**：`ERROR, WARNING, EXPERIMENT, INVENTORY, CRITICAL, HIGH, MEDIUM, LOW, INFO`，且明确说明自 `1.72.0` 起新值用于替换旧值。

### 8.3 三处值域与 EXT-2 实现的对照

| 来源 | 值域 | 说明 |
|---|---|---|
| 官方规则 YAML `severity` | `LOW, MEDIUM, HIGH, CRITICAL`（+ 兼容 `ERROR, WARNING, INFO`） | 规则作者可写 7 种 |
| 官方 schema `match_severity`（`extra.severity`） | 9 值：`ERROR WARNING EXPERIMENT INVENTORY CRITICAL HIGH MEDIUM LOW INFO` | 输出层 |
| CLI `--severity` 过滤 flag | 仅 `INFO, WARNING, ERROR` | **过滤用**，不等于输出值域 |
| **EXT-2 `_SEVERITY_MAP`** `[E]` | **仅 `error→high`、`warning→medium`、`info→info`** | `semgrep.py:80-84` |

**差异 `[I]`**：

1. 官方允许的 `EXPERIMENT / INVENTORY / CRITICAL / HIGH / MEDIUM / LOW`（6 个）**不在** `_SEVERITY_MAP` 中。`_to_finding()`（`:565-568`）对这些值抛 `FindingError`，记录被**跳过**并计入 `meta.records_skipped`（`:400-406`），而扫描整体**仍可能报 `COMPLETED`** → **静默丢 finding**。
2. 官方把 `INFO` 对应为 `LOW`，而 EXT-2 映射为 `info`（统一 schema 值），语义不一致（非致命，但需在报告中说明）。
3. `1.182.1 > 1.72.0`，属于支持新 severity 值的版本，**该差异与所 pin 版本直接相关**。

> **处置**：本轮**未修改任何代码或方案文档**。该差异登记为 `CR-06` 引出的**新契约差异**，是否扩展 `_SEVERITY_MAP` 需**单独授权**的新任务（§13 E 类）。Phase B 的 `RV-02` 必须枚举真实 `extra.severity` 取值集合。

---

## 9. 网络 / 隐私相关行为核对（配置层证据，非网络层证明）

### 9.1 官方 metrics 文档（逐字，`[R]`）

来源：`https://semgrep.dev/docs/metrics`

```text
$ semgrep --config=myrule.yaml  # → no metrics (loading rules from local file)
$ semgrep --config=p/python     # → metrics enabled (fetching Registry)
$ semgrep login && semgrep ci   # → metrics enabled (logged in to semgrep.dev)
$ semgrep install-semgrep-pro   # → metrics enabled (requires being logged in)

Semgrep does not enable metrics when running with only local configuration files
or command-line search patterns. Semgrep does enable metrics if rules are loaded
from the Semgrep Registry.

- --metrics auto: (default) metrics are sent whenever rules are pulled from the
  Semgrep Registry or the user is logged in.
- --metrics on:   metrics are sent on every Semgrep run
- --metrics off:  metrics are never sent

Alternatively, set the SEMGREP_SEND_METRICS environment variable to auto, on, or off.
```

`Data NOT collected ever`（逐字）：`Source code`、`Private rules`。
`Data NOT collected unless explicitly requested`：`Filenames`、git 元数据、finding messages 等。
`Data collected as metrics`（当启用时）：运行时长、CLI 版本、**anonymous user ID**、**IP address**、CI env 值、安装方式、项目名/规则/config 的伪匿名哈希等。

### 9.2 对 §7「无外网」结论的影响 `[I]`

- 配置层：`--config <LOCAL>` + 未登录 + `--metrics off` + `SEMGREP_ENABLE_VERSION_CHECK=false` 的组合，按官方文档**不应**产生 metrics 上报 ✅
- PyPI 页面官方声明「by default, code is never uploaded」✅
- **但**：`--enable-version-check` 明确「Checks Semgrep servers」→ **独立于 metrics 的出站路径**；官方未说明 `SEMGREP_ENABLE_VERSION_CHECK=false` 的取值语义（§11 U8）
- 官方 `--output` / `--json-output` / `--*-output` 可「post to URL」；EXT-2 命令不含这些 flag ✅
- **结论**：以上全是**配置层/文档层证据**，**不能**替代方案 §7 要求的网络层观测（L1/L2/L3）。`CR-06` 的「无外网」判据**本阶段未闭合**。

### 9.3 新发现：本地文件写入副作用 `[R]`

官方 metrics 文档逐字：

```text
the Semgrep CLI generates a Universally Unique Identifier (UUID) which is saved
locally to a `~/.semgrep/settings.yml` file when the ID does not already exist.
```

→ Phase B 真机运行时**可能在用户主目录写入 `~/.semgrep/settings.yml`**。这是本轮新发现的**执行副作用**，必须在 Phase B 的环境隔离/清理边界中登记（**本轮未创建、未修改该文件，也未做任何处理**）。

### 9.4 新发现：未被 `tool_env()` 清理的官方环境变量 `[R]`+`[E]`

`adapters.py:39-54` 的 `tool_env()` 仅剥离 `HTTP_PROXY/HTTPS_PROXY/ALL_PROXY`（含小写）并设 `NO_PROXY=*`；`_spawn()`（`semgrep.py:454-455`）只额外设 `SEMGREP_ENABLE_VERSION_CHECK=false`。官方 CLI reference 列出的环境变量中：

| 变量 | 官方作用 | `tool_env()` 是否清理 |
|---|---|---|
| `SEMGREP_RULES` | 可替代/影响 `--config`（可能指向 registry） | ❌ 未清理 |
| `SEMGREP_SEND_METRICS` | `auto/on/off`，影响 metrics（显式 `--metrics off` 时按文档应优先） | ❌ 未清理 |
| `SEMGREP_BASELINE_COMMIT` / `SEMGREP_FORCE_COLOR` | 影响基线提交 / 颜色输出 | ❌ 未清理 |

> **处置**：仅登记为 Phase B 需核验的环境事实（执行前记录 env 快照、必要时在隔离进程内清空），**本轮未修改任何代码或环境**。

---

## 10. 来源登记与原始证据清单

| # | 来源 URL | 用途 | 核验时间（GMT+8） | 状态 |
|---|---|---|---|---|
| S1 | `https://pypi.org/pypi/semgrep/1.182.1/json` | 版本、classifiers、8 个分发文件 `digests.sha256`、上传时间 | 2026-11-09 17:47–18:07 | ✅ 官方 JSON 原文 |
| S2 | `https://pypi.org/project/semgrep/1.182.1/` | 发布日期、License、Requires、classifiers、metrics 段、最新可用版本 | 同上 | ✅ |
| S3 | `https://github.com/semgrep/semgrep/releases/tag/v1.182.0` | 官方 release tag / 日期 / notes | 同上 | ✅（assets 未列出 → U3） |
| S4 | `https://semgrep.dev/docs/cli-reference` | Exit codes 段、内嵌 `--help` 的 `EXIT STATUS`、全部 flag/env 说明 | 同上 | ✅ |
| S5 | `https://semgrep.dev/docs/getting-started/cli` | 「完成即 0」逐字、`--json` schema 官方指向、timeout 语义 | 同上 | ✅ |
| S6 | `https://github.com/semgrep/semgrep-interfaces/blob/main/semgrep_output_v1.jsonschema` | 根级 required、paths/skipped 形态、`match_severity` | 同上 | ✅（内容截断 → U5/U6/U11） |
| S7 | `https://semgrep.dev/docs/writing-rules/rule-syntax` | 规则 `severity` 值域、`metadata`/`message`/`id`/`languages` | 同上 | ✅ |
| S8 | `https://semgrep.dev/docs/metrics` | metrics 触发条件、`--metrics off`、数据收集边界、`settings.yml` | 同上 | ✅ |

**时间记录边界** `[E]`：本轮未对每个请求逐个记录秒级时间戳，统一登记为核验窗口 `2026-11-09 17:47:54 – 18:06:51 GMT+8`（窗口起止由系统与本机 `date` 取得：`2026-11-09T10:06:51Z`）。如需逐源精确时间戳，需下一阶段单独授权记录方式。

**原始证据保存方式**：本轮**未创建任何证据目录或证据文件**（禁止项）。上述逐字引文即登记在本报告中；报告自身 SHA256 在交付回复中给出。若需保存官方页面快照为独立证据文件，需 Phase B 授权（§13 B 类）。

---

## 11. UNKNOWN 清单（严格按停止条件登记，不推断）

| # | 无法确认事项 | 原因 / 边界 | 何处闭合 |
|---|---|---|---|
| U1 | PyPI `1.182.1` 与 GitHub `v1.182.0` 的精确对应关系 | 官方页面未说明版本/日期差异原因 | Phase B（可选，不影响扫描） |
| **U2** | **wheel 内 Windows `semgrep-core` 可运行性 / 1.182.1 能否在本机实际启动并完成扫描** | 官方页面未说明；本轮禁止安装/运行。**停止条件已触发：标 UNKNOWN，未自行选择替代安装方式** | Phase B 真机 |
| U3 | GitHub `v1.182.0` release 的 assets 及其平台列表 | 页面文本未包含 assets | Phase B（可选） |
| U4 | `main` 分支 schema 是否精确对应 `1.182.1` | schema 未 pin 版本 | Phase B 真机 |
| U5 | `results[]`（`cli_match`）内部字段结构：`check_id`/`path`/`start.line`/`end.line`/`extra`/`extra.message`/`extra.metadata`/`extra.lines` | 官方 schema 页面内容 `[content truncated]`，该定义不可见 | Phase B 真机 |
| U6 | `finding.severity` 允许枚举 | 官方 schema 该字段无 `oneOf`/`const`，仅描述 `int\|string` | Phase B 真机 |
| U7 | 官方内部退出码文本差异（`1` 的条件、`7` 的语义、`14` vs `99`）哪个适用于 `1.182.1` | 两段官方文本不一致，不得裁定 | Phase B `RV-05` 实测 |
| U8 | `SEMGREP_ENABLE_VERSION_CHECK=false` 中 `false` 的取值语义是否被 `1.182.1` 识别 | 官方文档只说明 env 存在，未说明取值 | Phase B 网络观测 |
| U9 | `1.182.1` 在**无跳过文件**时是否省略 `paths.skipped` 键 | schema 声明 `skipped` 非必填；实际输出未知。直接影响 `CR-02` 判定 | Phase B `RV-01` |
| U10 | `1.182.1` + 自写规则下真实 `extra.severity` 的取值集合 | 三处官方值域不同，实际输出未知 | Phase B `RV-02` |
| U11 | `errors[]`（`cli_error`）元素结构 | schema 内容截断，未读到完整定义 | Phase B `RV-04` |
| U12 | 官方 `digests.sha256` 与**实际下载文件**是否一致 | 本轮禁止下载，未做本地比对 | Phase B 下载后 |
| U13 | 是否存在其它实际出站路径（版本检查、curl-based telemetry 等） | 文档层不能证明网络层行为 | Phase B §7 L2/L3 |
| U14 | 完整依赖树及依赖 wheel 的 SHA256 | 本轮获取的 JSON 未含 `info.requires_dist`，未核对 | Phase B 下载/锁定前 |

**明确未触发的停止条件**：「官方来源无法访问」—— S1–S8 **全部可访问且内容可读**，无一项因不可访问而标记 UNKNOWN。
**已触发并遵守的停止条件**：「wheel 兼容性无法确认」在**运行层**触发（U2）→ 已标 `UNKNOWN`、未推断、**未自行选择任何替代安装方式**。
「任何操作需要超出上述授权」→ 未触发；本轮全部动作均在授权内。

---

## 12. 结论

1. **A 类 4 项授权全部完成**：官方发布信息、官方来源、SHA256 校验和、wheel 兼容性（分发层）、CLI 退出码 / JSON 字段 / Severity 值域 / 相关行为，均已核对并记录来源、时间、逐字证据与 UNKNOWN。
2. **`semgrep==1.182.1` 作为固定基线在分发层成立**：官方 `win_amd64` wheel 存在且带官方 SHA256；tag 与本机 `cp313 / win_amd64` 匹配；官方 classifiers 含 Windows 与 Python 3.13；`requires_python >=3.10` 覆盖本机 3.13.14。
3. **运行层仍为 UNKNOWN**（U2）：不得据此认为 `CR-06` 已闭合，也不得选择替代安装方式。
4. **`CR-01` 得到官方文档层佐证**：`scan`/`ci` 完成即 `0`，`1` 需 `--error`；与 `rc==0` 收窄方向一致，但**真机实测仍必需**。
5. **发现 2 项 `CR-06` 引出的新契约差异（均未修改代码）**：
   - **`paths.skipped` 非官方必填**，而 `CR-02` 实现要求其存在 → 正常扫描可能被判 `FAILED`（§7.4）；
   - **官方 severity 值域（规则 7 值 / 输出 9 值）远超 `_SEVERITY_MAP` 的 3 值** → 新 severity 的 finding 可能被静默丢弃（§8.3）。
   两者均需 Phase B 真机确认实际输出后，由**单独授权**决定是否适配。
6. **另发现 3 项执行期风险**（均仅登记）：官方 env `SEMGREP_RULES` / `SEMGREP_SEND_METRICS` 未被 `tool_env()` 清理；独立出站的版本检查路径；首次运行写入 `~/.semgrep/settings.yml` 的本地副作用。
7. **本阶段不改变任何验收状态**：`CR-06` 仍未闭合；`EXT-2` 仍为 `CONDITIONAL ACCEPT`；G15 / `EXECUTION_INTEGRITY=NOT_OK` / C14 / 历史 `UNKNOWN` / 六项测试阶段状态一律原样保留。

---

## 13. 下一阶段所需授权（**不自行进入 Phase B**）

> 以下仅为清单，**本轮一项都未执行、未创建、未申请执行**。

**A 类（下载 / 校验，需人工执行并批准）**

- A1 人工下载 `semgrep-1.182.1-...-none-win_amd64.whl`（官方 SHA256 `e464d398…b68c`）及**完整依赖树**到本地，逐项做本地 SHA256 比对（闭合 U12 / U14）。
- A2 若人工决定需要官方页面快照作为独立证据文件，批准创建证据目录与快照文件（本轮未创建）。

**B 类（新建文件 / 写入）**

- B1 创建隔离根、fixture、本地规则、`scope.json`、验证脚本、字段枚举脚本、Tier B 转发包装器。
- B2 **更新 `docs/EXT-2-REAL-VERIFICATION-PLAN.md`**：本轮发现的两项契约差异会改变 `RV-01` / `RV-02` 的预期（尤其 fixture 规则的 severity 选择、`paths.skipped` 判定表）。方案文档本轮**未修改**，需授权后更新。
- B3 Phase B 执行报告 `docs/EXT-2-REAL-VERIFICATION-REPORT.md`。

**C 类（环境 / 网络配置）**

- C1 隔离 venv + **进程级** PATH 前置；执行前记录 env 快照，并按 §9.4 决定是否清空 `SEMGREP_RULES` / `SEMGREP_SEND_METRICS`。
- C2 §7 的三层网络观测 / 临时出站阻断及其恢复动作；登记 `~/.semgrep/settings.yml` 写入副作用。

**D 类（删除 / 清理）**

- D1 任何产物清理须先列**具体文件清单**并逐项人工确认；默认不清理。明确不清理两个既有验证副产物。

**E 类（状态 / 代码变更，需单独授权的新任务）**

- E1 **扩展 `_SEVERITY_MAP`** 以覆盖官方新值（§8.3）—— 属代码修改，需独立 Code Review + Remediation 流程授权。
- E2 **调整 `CR-02` 对 `paths.skipped` 缺失的处理**（§7.4）—— 同上。
- E3 `CR-06` 闭合 / `EXT-2` 升级为完整 `PASS` —— 只能在 §10.1 C1–C9 全满足后由**人工验收**决定。
- E4 任何对 G15 / C14 / `UNKNOWN` / 六项测试阶段状态的改写 —— 不在本方案范围内。

---

## 14. 本轮保护边界核验 `[E]`

| 项 | 状态 |
|---|---|
| 未下载文件 / 未安装软件 | ✅ `pip show semgrep` = not found；`semgrep` 不在 PATH；`~/Tools/semgrep` 不存在；仓库内无任何 semgrep wheel/sdist/exe |
| 未创建 venv / 规则 / fixture / 验证脚本 | ✅ 零创建 |
| 未运行 Semgrep / 未扫描 | ✅ 零执行 |
| 未修改源码 / 测试 / 配置 / 现有证据 | ✅ 零修改；冻结五文件及方案文档均未触碰 |
| 未修改 Git 状态 / 未执行 Git 写操作 | ✅ HEAD `9913c50` 未变；`git status --short` 与 Phase A 开始前一致，**仅新增**本报告一项 `??`；未 commit / add / reset / clean / checkout / restore / stash |
| 未修改 PATH / 注册表 / 系统环境变量 | ✅ 仅运行只读 `python -c` / `date` / `git status` / `ls` / `find` |
| 未删除 / 覆盖 / 移动任何文件 | ✅ 零操作 |
| 未重试被拦截操作 / 未绕过审批 | ✅ 见 §1 |
| 未重跑六项历史测试 | ✅ 未运行任何测试 |
| 两个验证副产物 | ✅ `output/vuln_hunter_report.md`、`%TEMP%\tmp.AvXfUFcabf\` 保留 |
| G15 / C14 / `UNKNOWN` / 六项测试阶段状态 | ✅ 原样保留 |
| 不自行进入 Phase B | ✅ 完成后停止 |

---

## 15. 完成后停止

本报告为 `Phase A Approval` 的**唯一交付物**。本轮到此停止，**不自行进入 Phase B**。

在获得下一阶段明确授权前，不下载、不安装、不创建 venv / 规则 / fixture / 脚本、不运行 Semgrep、不执行扫描、不修改任何源码 / 测试 / 配置 / 冻结文件 / 历史证据 / 既有方案文档，不改变任何验收状态。

*报告结束。*
