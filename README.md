# DualVerify-Sentinel

Authorization-gated local security checks for lab targets and explicitly
authorized hosts. Rule-based engine (NOT model-driven): every execution step is
policy-checked, journaled, and fail-closed.

> 定位：A+B+C 下一代安全验证项目的安全工程基础层（授权门禁 C、可靠执行引擎 B，
> 规划/决策 A 仍在演进）。不是已发布的 Vuln-Hunter 轻量版，也不共享其 Git 历史。

## ⚠️ 授权范围（必读）

- 本工具**仅用于你拥有或运营的系统、本地靶场，或获得系统所有者明确书面授权的目标**。
- 计划执行前必须提供机器可读的授权范围文件（scope JSON），并通过独立门禁校验。
- 未授权、超范围、窗口过期或配置损坏的目标会被**拒绝执行**（fail-closed），不存在跳过授权的代码路径。
- 无破坏性测试、无持久化、无 payload 构建、不外传发现的数据。

## 安装

```bash
# Python >= 3.10，零第三方依赖（纯标准库）
pip install -e .          # 可编辑安装（开发）
# 或
pip install .             # 标准安装
```

## 可选外部工具

| 工具 | 用途 | 缺失时行为 |
|---|---|---|
| nuclei | 模板扫描（vuln_validation 及以上模式） | 步骤 SKIPPED（preflight 报告未安装），不崩溃 |
| bandit | 源码静态分析 | 同上 |

nuclei 获取：https://github.com/projectdiscovery/nuclei/releases （放入 PATH 即可）。

## 使用

```bash
python -m vuln_hunter run --scope scripts/example-scope.json --mode safe_scan --target 127.0.0.1:8080
# 或安装后：
dvs run --scope ... --mode ... --target ...
```

- scope 样例见 `scripts/example-scope.json`（示例目标与示例时间窗口，**不是真实授权记录**）。
- 退出码：`0` = 全部 COMPLETED；`1` = 运行完成但有失败/拒绝；`2` = gate/policy 级拒绝（未执行任何工具）；`3` = **审计故障**（journal 无法写入/校验，运行结果不予认证，不伪装为普通失败）。

## 失败关闭（fail-closed）语义

1. **门禁缺失/损坏/超时 = 拒绝**：scope 校验由 `vuln_hunter.gate_check` 以独立子进程执行；模块缺失、崩溃、超时或输出不可解析时，CLI 返回 REFUSED（exit 2）。也可直接运行 `dvs gate-check <scope.json>`（与 run 使用同一子进程门禁，exit 0=通过 / 1=拒绝）。
2. **能力票据（RunTicket）**：适配器执行只接受 `PolicyEngine.issue_ticket()` 签发的票据；签发前验证目标范围、授权窗口；执行时由适配器基类**再次独立核验**（适配器 ID、scope 内容哈希、**票据/策略模式一致性**、票据/步骤目标一致性、target_kind 一致性、模式风险上限、目标范围、窗口）。任何不匹配 → REFUSED/ABORTED。
3. **摘要 fail-closed**：任何未知状态计入 FAILED，新状态永远不会把汇总降级为成功。步骤必需字段缺失或适配器意外崩溃都会产生**有记录的 FAILED 步骤**（含 attempt_end/step_end），不会出现无记录的崩溃；同一 step id 不会重复执行。
4. **决策循环**（`--loop`）：任何拒绝/中止/失败即停止；绝不扩大目标范围。
5. **审计日志 hash-chain**：journal 每条记录带 `seq`/`prev`/`h`（sha256 链）；`vuln_hunter.journal.verify(path)` 全链校验，篡改/删除/重排可检；**尾部截断仅在外部保存 head 锚点时才可检**；损坏尾行时拒绝续写，写失败向上抛出（绝不静默）。运行报告内含审计锚点（run_end 时的链头+记录数+验证状态），**仅用于一致性核对**——外部可信锚点未实现，报告内锚点不能单独证明日志未被整体重写或截断。审计故障（journal 不可写/不可验证）以退出码 3 明确终止，绝不伪装成普通运行结果。

## 已知限制与安全边界

- **进程内边界**：RunTicket 的 frozen dataclass、私有注册表 `_REGISTRY` 是 API 加固，**不是沙箱**——敌意同进程代码可以绕过任何 Python 级检查。强隔离需要进程级措施（未实现）。CLI 是唯一受支持的入口。
- **Windows 优先**：进程超时杀灭在 Windows 上不追踪孙进程；nuclei 路径回退含 `~/Tools/nuclei/` 本机布局假设。
- **不承诺检测正确性**：工具输出按原样记录，未经验证的结果不会标记为已确认漏洞。

## 测试

```bash
python tests/test_engine.py          # 引擎状态机/策略/重试
python tests/test_decision.py        # 决策规则 P0-P8
python tests/test_check_scope.py     # scope 门禁
python tests/test_adapters_gate.py   # 适配器门禁负向用例（票据/kind/上限/伪造）
python tests/test_gate_packaging.py  # 门禁打包定位
python tests/test_journal_chain.py   # 审计日志 hash-chain 完整性
python tests/test_cli_gate.py        # CLI gate-check 子命令
python tests/test_s2_hardening.py    # 异常路径收敛/报告锚点关联/票据模式一致性
```

全部通过（退出码 0）才算验收通过。以实际运行结果为准；本仓库不预设"全绿"声明。

## 许可

MIT — 见 LICENSE。
