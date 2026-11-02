<div align="center">

# DualVerify-Sentinel

**确定性、授权门禁的安全验证引擎。**

`zyh798-cell` / `DualVerify-Sentinel` · Gen-1 稳定版 · MIT

<img src="../../assets/banner.gif" alt="DualVerify-Sentinel — 像素风格动态横幅，标题逐字显现并伴随扫描线扫过与数据流动效" width="720">

**DualVerify-Sentinel — 确定性安全验证引擎**
⚠️ **仅限已授权的安全测试**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](../../LICENSE)
[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/Platform-Windows%20Verified-0078D6?logo=windows&logoColor=white)](#4-环境要求)
[![Platform](https://img.shields.io/badge/Platform-Linux%2FmacOS%20Unverified-6b7280)](#10-已知限制)
[![Checks](https://img.shields.io/badge/Offline%20Checks-427%2B%20Passing-2EA043)](#11-项目状态)
[![Status](https://img.shields.io/badge/Status-Gen--1%20Stable-8250DF)](#11-项目状态)

[English](../../README.md) · **中文** · [日本語](README.ja.md) · [Español](README.es.md) · [Français](README.fr.md)

</div>

---

## 1. 项目定位

DualVerify-Sentinel 是一个**基于规则的安全验证引擎**（明确**非模型驱动**）：
每个执行步骤都依据机器可读的授权范围文件进行策略校验，记录在防篡改的哈希链
审计日志中，并且**失败关闭（fail-closed）**——授权缺失、损坏或过期意味着
*拒绝执行*，而绝不是跳过校验。

它是计划中的下一代验证架构的安全工程基础层（授权门禁 + 可靠执行引擎）。
Gen-1 的规划/决策层有意保持确定性。

## 2. 功能一览

| 能力 | 实现方式 |
|---|---|
| 授权门禁 | 机器可读的 scope JSON 在**独立子进程**中校验；缺失/损坏/过期 → REFUSED（退出码 2）。不存在绕过路径。 |
| 执行票据（RunTicket） | 适配器只接受策略引擎签发的票据；范围哈希、模式、目标、窗口在**执行时再次独立核验**。 |
| 安全执行 | 每步 12 项检查链；无破坏性技术、无持久化、不构建 payload、不外传发现的数据。 |
| 审计日志 | 只追加哈希链（`seq`/`prev`/`h`，SHA-256）；篡改/重排可检测；审计故障以退出码 3 终止，绝不伪装为普通结果。 |
| 确定性决策循环 | 显式规则 P0–P8：任何拒绝/中止/失败即停止循环；**绝不**扩大目标范围。 |
| 任务图 | 状态机 + 硬预算（最多 32 节点、派生深度 2、8 次派生）；动态派生以父节点 COMPLETED 为前提。 |
| 可选工具适配器 | `nuclei`（模板扫描）与 `bandit`（静态分析）——未安装时优雅 SKIPPED 并给出 preflight 报告。 |
| 诚实报告 | 发现按原样记录；未验证的输出绝不会被标记为已确认漏洞；每份报告都列出已知限制。 |

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
| 外部工具（可选） | `nuclei`、`bandit` — 缺失时优雅跳过 |

## 5. 安装

```bash
git clone https://github.com/zyh798-cell/DualVerify-Sentinel.git
cd DualVerify-Sentinel

python -m venv .venv
# Windows:
.venv\Scripts\activate
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
2. **Windows 优先** — Windows 上进程超时杀灭不追踪孙进程；nuclei 路径回退
   假设一种本地 `~/Tools/nuclei/` 布局。
3. **不承诺检测正确性** — 工具输出按原样记录；未验证的结果绝不会标记为
   已确认漏洞。
4. **Linux/macOS 未验证** — CI 未覆盖非 Windows 平台。
5. **日志尾部截断** — 仅在外部保存过 head 锚点时才可检测；报告内锚点仅用于
   一致性核对。
6. **Gen-1 规划器是静态模板** — 规划是确定性的，非模型驱动、非自适应。

## 11. 项目状态

- **Gen-1 稳定**：18 个离线测试套件、427+ 项检查在本地通过
  （Windows，Python 3.13.14）。已通过 wheel/sdist 构建完成打包冒烟测试。
- **Gen-2 架构**（未来的独立仓库）已规划，采用提案/裁决分离。
  Gen-2 的工作不会在本仓库进行。
- 完整测试命令见 `tests/` 下的测试套件 — 请运行并相信实际结果；本仓库
  不预设"全绿"声明。

## 12. 许可与反馈

- **许可**：MIT — 见 [LICENSE](../../LICENSE)。
- **安全政策**：见 [SECURITY.md](../../SECURITY.md)。
- 欢迎提交 Issue 与 Pull Request。安全相关报告请遵循 SECURITY.md 的指引，
  不要直接开公开 issue。

---

<div align="center">
<sub>DualVerify-Sentinel · 确定性安全验证引擎 · MIT © 2026 zyh798-cell</sub>
</div>
