<div align="center">

<img src="../../assets/logo.svg" alt="DualVerify-Sentinel 标志 — 深蓝盾牌：双勾、青色轨道节点与 DVS 字标" width="110">

# DUALVERIFY-SENTINEL

### ENGINEERED FOR TRUST.
### BUILT FOR CONTROL.

**策略驱动的安全验证引擎**

确定性执行。显式授权边界。可审计的安全证据。

`zyh798-cell` / `DualVerify-Sentinel` · MIT

<img src="../../assets/banner.svg" alt="DualVerify-Sentinel 横幅 — 盾牌标志、项目名称、一句话说明与仅限授权测试声明" width="720">

[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](../../LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows%20Verified-085041)](#4-环境要求)
[![Dependencies](https://img.shields.io/badge/Dependencies-Standard%20Library%20Only-0C447C)](#4-环境要求)
[![Use](https://img.shields.io/badge/Use-Authorized%20Testing%20Only-BA7517)](#8-授权与安全)
[![Status](https://img.shields.io/badge/Status-Gen--1-0C447C)](#11-项目状态)

[English](../../README.md) · **中文** · [日本語](README.ja.md) · [한국어](README.ko.md) · [Español](README.es.md) · [Français](README.fr.md)

[授权门禁](#授权门禁) · [策略引擎](#策略引擎与风险阶梯) · [TaskGraph](#taskgraph-编排) · [工具适配器](#工具适配器-nuclei--bandit) · [审计日志](#审计日志) · [报告](#结构化报告) · [安装](#5-安装) · [安全](../../SECURITY.md)

> ⚠️ **仅限已授权的安全测试**

</div>

---

## 1. 项目定位

DualVerify-Sentinel 是一个**基于规则的安全验证引擎**（明确**非模型驱动**）：
每个执行步骤都依据机器可读的授权范围文件进行策略校验，记录在防篡改的哈希链
审计日志中，并且**失败关闭（fail-closed）**——授权缺失、损坏或过期意味着
*拒绝执行*，而绝不是跳过校验。

它是安全工程基础层：授权门禁加确定性执行引擎。Gen-1 的规划/决策层有意保持
确定性，**非模型驱动**。

## 2. 功能一览

Gen-1 作为单一确定性流水线运行——以下每项能力都由显式代码路径强制执行，而非模型判断。

### 授权门禁

机器可读的 scope JSON 在**独立子进程**中校验；缺失/损坏/过期 → REFUSED（退出码 2）。不存在绕过路径。适配器只接受策略引擎签发的票据；范围哈希、模式、目标与窗口在**执行时再次独立核验**。

### 策略引擎与风险阶梯

五种模式、风险上限递增（R0–R4，见[基本用法](#6-基本用法)）。显式规则 P0–P8：任何拒绝/中止/失败即停止循环；**绝不**扩大目标范围。

### TaskGraph 编排

状态机 + 硬预算（最多 32 节点、派生深度 2、8 次派生）；动态派生以父节点 COMPLETED 为前提。

### 工具适配器 (nuclei / bandit)

`nuclei`（模板扫描）与 `bandit`（静态分析）——未安装时优雅 SKIPPED 并给出 preflight 报告。安全执行：每步 12 项检查链；无破坏性技术、无持久化、不构建 payload、不外传发现的数据。

### 审计日志

只追加哈希链（`seq`/`prev`/`h`，SHA-256）；篡改/重排可检测；审计故障以退出码 3 终止，绝不伪装为普通结果。

### 结构化报告

发现按原样记录；未验证的输出绝不会被标记为已确认漏洞；每份报告都列出已知限制。

### 扩展适配器与统一发现结构

`vuln_hunter/adapters_ext/` 中还实现了两个可选适配器：`gitleaks`（密钥检测，
步骤 `s4-gitleaks`）与 `semgrep`（静态分析，**仅使用本地规则文件**，步骤
`s5-semgrep`）。两者仅对文件系统范围内的源码树按条件纳入计划，各自需要对应的
可执行文件，且绝不从网络获取规则。所有适配器输出都会经统一的 Finding Schema
（`findings.py`）归一化，在写入报告前校验严重级别与记录结构。

> 这些适配器**已作为代码实现**；真实工具的端到端验证**尚未完成**。
> 适配器存在不等于工具运行已通过验证 —— 见第 11 节。

## 3. 使用场景

- 对自己的靶场目标和明确授权的主机进行验证。
- 运行可重复、产出证据、带完整审计轨迹的安全检查。
- 作为构建更高层验证流水线的基础层。

## 4. 环境要求

| 要求 | 说明 |
|---|---|
| Python | >= 3.10（仅在 3.13.14 上测试过） |
| 第三方依赖 | **无** — 纯标准库 |
| 操作系统 | Windows **已验证**；Linux/macOS **尚未验证** |
| 外部工具（可选） | `nuclei`、`bandit`、`gitleaks`、`semgrep` — 适配器已实现；缺失时优雅跳过；真实工具运行尚未验证 |

## 5. 安装

```bash
git clone https://github.com/zyh798-cell/DualVerify-Sentinel.git
cd DualVerify-Sentinel

python -m venv .venv
# Windows (PowerShell):
.venv\Scripts\Activate.ps1
# Windows (CMD):
.venv\Scripts\activate.bat
# Linux/macOS:
source .venv/bin/activate

pip install .
```

开发时也可使用可编辑安装 `pip install -e .`。

## 6. 基本用法

**第 1 步 — 校验 scope 文件（务必先做）：**

```bash
dvs gate-check scripts/example-scope.json
# 退出码 0 = scope 有效 · 退出码 1 = 拒绝
```

**第 2 步 — 执行验证：**

```bash
dvs run --scope scripts/example-scope.json --mode safe_scan --target 127.0.0.1:8080
# 或：python -m vuln_hunter run --scope ... --mode ... --target ...
```

模式（风险上限递增）：`passive` → `safe_scan` → `vuln_validation` →
`attack_simulation` → `high_risk`（R0–R4）。`nuclei` 仅在 R2 及以上被调用。

退出码：`0` 全部步骤 COMPLETED · `1` 运行完成但有失败/拒绝 ·
`2` gate/policy 级拒绝（未执行任何工具） · `3` **审计故障**
（journal 不可写/不可校验 — 运行结果不予认证）。

`scripts/example-scope.json` 是虚构示例 — **不是真实授权记录**。

## 7. Scope 语义

- 条目按**解析后的主机名相等**匹配（不带端口的条目匹配该主机的任意端口）。
  **不支持 CIDR 网段** — 请使用 `host` 或 `host:port` 形式。
- 授权窗口在**每个执行步骤**都会重新检查；运行中途过期会中止后续步骤。
- scope 内容哈希绑定进每张运行票据；修改 scope 会使未完成的票据失效。
- 文件系统范围的步骤只跳过网络范围检查；其余策略检查照常生效。

## 8. 授权与安全

> ⚠️ **仅对你拥有或运营的系统、本地靶场，或持有所有者明确书面授权的主机使用
> 本工具。** 未授权、超范围、窗口过期或配置损坏的目标会被拒绝执行
> （失败关闭）。不存在跳过授权的代码路径。

仓库内置的示例 scope 是虚构的。真实授权需要真实、机器可读的授权记录 —
请将其保存在本仓库之外。

## 9. API 加固不是沙箱

RunTicket 的 frozen dataclass 与私有注册表是 **API 加固**，不是沙箱 —
敌意的进程内代码可以绕过任何 Python 级检查。强隔离需要进程级措施
（未实现）。CLI 是唯一受支持的入口。

## 10. 已知限制

1. **无进程内沙箱** — 见第 9 节。
2. **Windows 优先** — Windows 超时路径已实现字段化进程树清理（先执行
   `taskkill /T /F` 再兜底杀灭根进程，全部结果留痕）；该能力经受控三层进程树
   演练验证，但**不是绝对保证**——无运行时残留确认、taskkill 返回 0 不等于
   已确认整棵树清理完毕、真实 Nuclei 后代形态未验证。非 Windows 平台跳过树
   清理（仅杀灭根进程）。nuclei 路径回退假设一种本地 `~/Tools/nuclei/` 布局。
3. **不承诺检测正确性** — 工具输出按原样记录；未验证的结果绝不会标记为
   已确认漏洞。
4. **Linux/macOS 未验证** — CI 未覆盖非 Windows 平台。
5. **日志尾部截断** — 仅在外部保存过 head 锚点时才可检测；报告内锚点仅用于
   一致性核对。
6. **Gen-1 规划器是静态模板** — 规划是确定性的，非模型驱动、非自适应。

## 11. 项目状态

- **Gen-1 已实现**：授权门禁、策略引擎（R0–R4）、TaskGraph、审计日志、结构化报告、
  统一 Finding Schema，以及 `nuclei` / `bandit` / `gitleaks` / `semgrep` 适配器
  均已作为代码路径存在。测试套件位于 `tests/` — 请运行并以实际输出为准；本仓库
  不预设「全绿」声明，也不预设通过检查数量。
- **未验证 / 未实现**：真实工具的端到端验证尚未完成；Phase B 未执行；W1-03、
  W1-04、W1-06 与 CR-06 等事项以及真实 Semgrep 基线仍未关闭；Linux/macOS 验证
  与 CI 尚未建立；本仓库未实现 Gen-2。适配器代码存在不等于工具运行已通过验证，
  API 加固也不是操作系统级沙箱（见第 9 节）。
- 打包情况必须以本版本的构建为准；旧构建产物不能作为当前版本的证据。

## 12. 许可与反馈

- **许可**：MIT — 见 [LICENSE](../../LICENSE)。
- **安全政策**：见 [SECURITY.md](../../SECURITY.md)。
- **贡献指南**：见 [CONTRIBUTING.md](../../CONTRIBUTING.md)。
- 欢迎提交 Issue 与 Pull Request。安全相关报告请遵循 SECURITY.md 的指引，
  不要直接开公开 issue。

---

<div align="center">
<sub>DualVerify-Sentinel · 确定性安全验证引擎 · MIT © 2026 zyh798-cell</sub>
</div>
