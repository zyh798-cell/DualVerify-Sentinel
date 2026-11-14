<div align="center">

<img src="../../assets/logo.svg" alt="DualVerify-Sentinel logo — deep navy shield with dual verification check, cyan orbit nodes and the DVS wordmark" width="110">

# DUALVERIFY-SENTINEL

### ENGINEERED FOR TRUST.
### BUILT FOR CONTROL.

**一个围绕显式授权、确定性执行与可验证证据构建的策略驱动安全验证引擎。**

确定性执行 · 明确的授权边界 · 可审计的安全证据。

`zyh798-cell` / `DualVerify-Sentinel` · MIT

<img src="../../assets/banner.svg" alt="DualVerify-Sentinel banner — shield mark, project name, one-line description and authorized-testing-only notice" width="720">

[![Star on GitHub](https://img.shields.io/badge/Star_on-GitHub-181717?style=for-the-badge&logo=github)](https://github.com/zyh798-cell/DualVerify-Sentinel)
[![Star](https://img.shields.io/badge/Star-grey?style=for-the-badge&logo=github)](https://github.com/zyh798-cell/DualVerify-Sentinel)
[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](../../LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows%20Verified-085041)](#sec-7)
[![Dependencies](https://img.shields.io/badge/Dependencies-Standard%20Library%20Only-0C447C)](#sec-3)
[![Use](https://img.shields.io/badge/Use-Authorized%20Testing%20Only-BA7517)](#sec-5)
[![Status](https://img.shields.io/badge/Status-Gen--1-0C447C)](#sec-8)

[English](../../README.md) · **中文** · [日本語](README.ja.md) · [한국어](README.ko.md) · [Español](README.es.md) · [Français](README.fr.md)

[项目定位](#sec-1) · [已实现能力](#sec-2) · [快速开始](#sec-4) · [授权与安全](#sec-5) · [平台测试](#sec-7) · [参与贡献](#sec-9) · [Security](../../SECURITY.md)

> ⭐ **如果本项目对你有帮助，欢迎点 Star。社区测试与贡献同样欢迎。**

> ⚠️ **仅限授权安全测试**

</div>

---

<a id="sec-1"></a>
## 1. 什么是 DualVerify-Sentinel？

DualVerify-Sentinel（DVS）是一个**策略驱动的安全验证引擎**：每个执行步骤都会依据机器可读的授权范围进行校验、写入可防篡改的证据日志，并采用**失败即拒绝（fail-closed）**——授权缺失、损坏或过期时只会拒绝执行，绝不会跳过检查。

它是安全工程的基础层：一个授权门禁加一个确定性执行引擎。Gen-1 的计划层是**静态的、基于规则的模板**，不是模型驱动或自适应的规划器。

**当前 DVS 不是**：通用 Agent 平台、LLM Agent 运行时、模型驱动的自主决策系统，也不是操作系统级沙箱。这些属于长期方向，不是现有能力。

<a id="sec-2"></a>
## 2. 当前已实现的能力

以下能力均由明确的代码路径强制执行，而非模型判断。

| 能力 | 已实现内容 |
|---|---|
| **显式授权** | 授权范围 JSON 在**独立子进程**中校验；执行时再次独立核验范围哈希、模式、目标与时间窗口。范围缺失、损坏或过期 → 拒绝执行，不存在绕过路径。 |
| **策略驱动执行** | 五级风险上限模式：`passive`(R0)、`safe_scan`(R1)、`vuln_validation`(R2)、`attack_simulation`(R3)、`high_risk`(R4)。显式决策规则在拒绝、中止或失败时停止循环；目标范围绝不扩张。 |
| **风险感知控制** | TaskGraph 状态机带硬预算（最多 32 节点、派生深度 2、8 次派生），动态派生以父节点 COMPLETED 为前提，每步执行 12 步检查链。不使用破坏性技术、不建立持久化、不构造载荷、不外传发现的数据。 |
| **安全工具集成** | 核心适配器 `nuclei` 与 `bandit`；`vuln_hunter/adapters_ext/` 中提供可选的 `gitleaks` 与 `semgrep` 适配器（仅使用本地规则文件，不联网拉取规则）。所有适配器输出经统一 Finding Schema（`findings.py`）归一化；缺少可执行文件时优雅跳过并给出预检报告。 |
| **可验证审计证据** | 仅追加的 SHA-256 哈希链（`seq` / `prev` / `h`），可检测篡改与重排；审计失败以退出码 3 显式暴露，不会把未经认证的结果伪装成正常结果。 |
| **诚实的结构化报告** | 发现按原样记录；未经核实的工具输出绝不标注为已确认漏洞；每份报告都列出已知限制；不作检测正确率或准确率承诺。 |

> 适配器是**已实现的代码**。代码存在不等于已完成真实工具的运行验证——真实工具端到端验证尚未完成（见第 8 节）。

<a id="sec-3"></a>
## 3. 环境要求

| 项目 | 说明 |
|---|---|
| Python | >= 3.10（已在 3.13.14 验证） |
| 依赖 | **仅标准库** — 无第三方运行时依赖 |
| 操作系统 | Windows **已验证**；Linux / macOS **尚未验证** — 见第 7 节 |
| 可选外部工具 | `nuclei`、`bandit`、`gitleaks`、`semgrep`；缺失时优雅跳过 |

<a id="sec-4"></a>
## 4. 安装与快速开始

```bash
git clone https://github.com/zyh798-cell/DualVerify-Sentinel.git
cd DualVerify-Sentinel

python -m venv .venv
# Windows (PowerShell): .venv\Scripts\Activate.ps1
# Windows (CMD):        .venv\Scripts\activate.bat
# Linux/macOS:          source .venv/bin/activate

pip install .
```

开发环境也支持 `pip install -e .`。

**第 1 步 — 务必先校验授权范围文件：**

```bash
dvs gate-check scripts/example-scope.json
# 0 = 有效 · 1 = 拒绝 · 2 = 用法错误
```

**第 2 步 — 执行一次验证：**

```bash
dvs run --scope scripts/example-scope.json --mode safe_scan --target 127.0.0.1:8080
# 或：python -m vuln_hunter run --scope ... --mode ... --target ...
```

模式（风险上限递增）：`passive` → `safe_scan` → `vuln_validation` → `attack_simulation` → `high_risk`（R0–R4）。`nuclei` 仅在 R2 及以上调用。

退出码：`0` 全部步骤完成 · `1` 执行结束但存在失败/拒绝 · `2` 门禁或策略级拒绝（未执行任何步骤） · `3` **审计失败**（日志不可写或不可验证，结果不予认证）。

`scripts/example-scope.json` 是虚构示例，**不是真实授权**。

<a id="sec-5"></a>
## 5. 授权与安全

> ⚠️ **仅可对你自己拥有或运营的系统、本地实验目标，或已取得所有者明确书面授权的主机使用 DVS。**

未授权、超出范围、时间窗口过期或配置损坏的情况都会被拒绝，不存在跳过授权的代码路径。

- 范围条目按**解析后的主机名相等**匹配；不带端口的条目匹配该主机的任意端口。**不支持 CIDR 网段** — 请使用 `host` 或 `host:port` 条目。
- 授权时间窗口在**每个执行步骤**重新校验；运行中过期会中止后续步骤。
- 范围内容以哈希绑定到每次运行票据；修改范围会使未使用的票据失效。
- 文件系统范围的步骤仅跳过网络范围检查，其余策略检查依旧生效。

请把真实授权记录保存在本仓库之外；仓库内的示例范围是虚构的。

**API 加固不是操作系统级沙箱。** `RunTicket` 的冻结 dataclass 与私有注册表属于 Python 层加固，进程内的恶意代码仍可能绕过。强隔离需要进程级措施，目前尚未实现。CLI 是唯一受支持的入口。

<a id="sec-6"></a>
## 6. 证据与诚实报告

审计日志仅追加且以哈希链相连，可检测篡改与重排；审计失败会被显式暴露而不是隐藏。运行报告区分完整、部分与不完整结果；不完整结果失败即拒绝，不会贡献采集到的发现。

有两点边界值得明确说明：工具输出按原样记录，未经核实的输出不会被提升为已确认漏洞；日志尾部截断只有在外部保存过 head 锚点时才能被检测。

<a id="sec-7"></a>
## 7. 平台兼容性与社区测试

**欢迎社区测试，帮助我们扩展平台兼容性。**

DVS 目前以 **Windows 优先**。在 Windows 上，超时路径会执行有记录的进程树清理（先执行 `taskkill /T /F`，再终止根进程，并记录每一步结果）；该行为已在受控演练中验证，但不能绝对保证无残留。在非 Windows 平台上会跳过进程树清理，仅终止根进程。`nuclei` 的路径回退还假设了一种特定的本地安装布局。

Linux 与 macOS **尚未验证**，CI 也尚未覆盖。如果你在其他平台上运行了 DVS，欢迎通过 issue 分享可用与不可用的部分 —— 适配器行为、进程清理和打包尤其有价值。请勿附带真实目标数据、凭据或未经授权的扫描输出。

<a id="sec-8"></a>
## 8. 项目状态与方向

| | |
|---|---|
| **已交付（Gen-1）** | 授权门禁、策略引擎（R0–R4）、TaskGraph、审计日志、结构化报告、统一 Finding Schema，以及 `nuclei` / `bandit` / `gitleaks` / `semgrep` 适配器代码路径。 |
| **正在建设 / 验证** | 真实工具端到端验证、非 Windows 平台验证与 CI，以及针对当前版本的打包验证。测试套件位于 `tests/` — 请实际运行并以真实输出为准；本仓库不预设「全部通过」的结论。 |
| **长期方向** | 模型驱动规划、更强的进程级隔离与更广的平台支持。这些仅为方向，Gen-1 **尚未实现**。 |

当前计划层是确定性的静态模板；适配器代码存在不等于工具运行已验证，API 加固也不是操作系统级沙箱。打包状态必须由当前版本实际构建来判定，旧构建产物不能作为当前版本的证据。这是工程基础层，不是生产就绪的评估产品。

<a id="sec-9"></a>
## 9. 参与贡献

点一个 Star 能帮助更多人发现本项目；在自己的实验目标上试用 DVS、反馈观察结果、提交 Pull Request 同样受欢迎。完整指南见 [CONTRIBUTING.md](../../CONTRIBUTING.md)。

可以参与的方向：

- **平台适配与兼容性测试** — Linux/macOS 行为、进程树清理、打包。
- **安全工具 Provider / Adapter 集成** — 遵守授权门禁与失败即拒绝设计的新集成。
- **测试用例与回归基准** — 可复现、能产出证据的检查。
- **文档与多语言** — 六个 README 语言版本、示例与可读性。
- **Bug 修复与代码质量** — 小而聚焦、附带可运行证据的改动。
- **安全研究** — 遵循 [SECURITY.md](../../SECURITY.md)；未披露漏洞请勿公开提 issue。
- **使用体验与功能建议** — 先开 issue 商定范围。

错误、平台结果与建议请使用 **Issues**；代码与文档改动请使用 **Pull Requests**。任何 issue 或 PR 都不要附带真实目标数据、凭据、私有授权记录或未经授权的扫描输出。

<a id="sec-10"></a>
## 10. 许可与链接

- **许可**：MIT — 见 [LICENSE](../../LICENSE)。
- **安全策略**：[SECURITY.md](../../SECURITY.md)。
- **贡献指南**：[CONTRIBUTING.md](../../CONTRIBUTING.md)。
- **Issues 与 PR**：[提交 issue](https://github.com/zyh798-cell/DualVerify-Sentinel/issues) · [提交 PR](https://github.com/zyh798-cell/DualVerify-Sentinel/pulls)。
- **多语言版本**：中文 · 日本語 · 한국어 · Español · Français（见上方语言切换）。

---

<div align="center"><sub>DualVerify-Sentinel · Engineered for Trust. Built for Control. · MIT © 2026 zyh798-cell</sub></div>
