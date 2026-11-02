"""Markdown report rendering — includes honest limitations, every time."""
from .policy import ACK_KEYS, MODES
from .runner import STATUS_PRIORITY


def is_synthetic_finding(f) -> bool:
    """D2-C0 (R3): a finding counts as SYNTHETIC only when it carries the
    explicit structural marker (set per-finding by lab templates/tests or
    run-wide via Executor(synthetic_run=True)). Absence of the marker means
    the finding is treated as real — never the other way round."""
    return isinstance(f, dict) and f.get("synthetic") is True


def render_report(
    *,
    mode: str,
    risk: str,
    scope_path: str,
    scope: dict,
    gate_ok: bool,
    gate_message: str,
    plan: list[dict],
    results: dict,
    summary: str,
    findings: list[dict],
    journal_path: str,
    decision_trace: list | None = None,
    audit: dict | None = None,
) -> str:
    L = []
    L.append("# Vuln-Hunter 执行报告\n")
    L.append(f"- 生成时间: {_ts()}")
    L.append(f"- 模式: `{mode}` (风险上限 {risk})")
    L.append(f"- Scope 文件: `{scope_path}`")
    L.append(f"- 授权窗口: `{scope.get('window')}` (confirmed_by: {scope.get('confirmed_by')})")
    L.append(f"- 门禁校验: {'通过' if gate_ok else '未通过'} — {gate_message}")
    L.append(f"- 运行总结: **{summary}** (最差状态优先: {' > '.join(STATUS_PRIORITY)})")
    L.append(f"- 证据日志: `{journal_path}`\n")

    L.append("## 步骤结果\n")
    L.append("| 步骤 | 适配器 | 风险 | 目标 | 状态 | 尝试 | 说明 |")
    L.append("|---|---|---|---|---|---|---|")
    for sid, r in results.items():
        L.append(
            f"| {sid} | {r['adapter']} | {r.get('adapter_risk','-')} "
            f"| `{r.get('target','')}` | {r['status']} | {r.get('attempts','-')} "
            f"| {r.get('reason') or r.get('detail','')} |"
        )
    L.append("")

    L.append("## 发现\n")
    if findings:
        real = [f for f in findings if not is_synthetic_finding(f)]
        syn = [f for f in findings if is_synthetic_finding(f)]
        L.append(f"- 统计：真实发现 **{len(real)}** 条；合成/实验室标记发现 "
                 f"**{len(syn)}** 条（synthetic 标记，**不计入真实漏洞数量**）\n")
        for f in findings:
            tag = " **[SYNTHETIC]**" if is_synthetic_finding(f) else ""
            L.append(
                f"-{tag} `[{f.get('step')}]` **{f.get('severity') or f.get('status','')}** "
                f"{f.get('name') or f.get('template') or f.get('issue') or f.get('type')}"
                + (f" — matched: {f['matched_at']}" if f.get("matched_at") else "")
                + (f" — {f['url']} (HTTP {f['status']})" if f.get("type") == "http_service" else ""))
    else:
        L.append("- (无发现)")
    L.append("")

    L.append("## 决策轨迹\n")
    if decision_trace:
        L.append("| # | 动作 | 依据(上一步) | 理由 | 下一步 |")
        L.append("|---|---|---|---|---|")
        for i, d in enumerate(decision_trace, 1):
            last = (d.get("input", {}).get("last_step") or {})
            basis = f"{last.get('id','-')}:{last.get('status','-')}" if last else "(起点)"
            L.append(f"| {i} | {d['action']} | {basis} | {d['reason'][:80]} | {d['next']} |")
        L.append("\n决策引擎为**规则驱动**（规则有序、可审计），非 LLM 自主决策；"
                 "每次决策的完整输入与策略判定见 journal.jsonl 的 `decision` 事件。\n")
    else:
        L.append("- (本次运行未启用自主决策循环)\n")

    L.append("## 审计锚点（audit anchor）\n")
    if audit:
        L.append(f"- 证据日志: `{journal_path}`")
        L.append(f"- 锚点截取点: `run_end` 事件写入之后、报告渲染之前")
        L.append(f"- 记录数（截至锚点）: {audit.get('count')}")
        L.append(f"- 链头摘要: `{audit.get('head')}`")
        L.append(f"- 链内验证: **{'OK' if audit.get('ok') else 'FAILED'}** — {audit.get('detail')}")
        L.append("- 报告写盘后 journal 会追加**恰好一条** `report_written` 事件"
                 "（锚点后 +1 条），属预期行为。")
        L.append("- 边界声明：报告内锚点仅用于**一致性核对**——外部可信锚点未实现，"
                 "它不能单独证明日志未被整体重写或截断；日志真实性还取决于运行环境的进程完整性。")
    else:
        L.append("- (本报告未携带审计锚点——无法进行日志一致性核对)")
    L.append("")

    L.append("## 局限与剩余风险（如实声明）\n")
    L.append("- 策略边界仅在 Python 引擎入口生效；绕过本入口直接调用 nuclei/bandit 等原生命令不受本引擎约束。")
    L.append("- out_of_scope 匹配语义：无端口条目匹配该主机任意端口；in_scope 同理。")
    L.append("- `target_kind: fs_path` 的步骤（如 bandit 源码扫描）仅豁免网络 scope 校验，其余检查（取消/依赖/窗口/风险上限）全部保留。")
    L.append("- 尝试上限 2 次；HTTP 429 触发立即停止并把依赖该步骤的后续步骤置为 SKIPPED。")
    L.append("- 取消（CANCEL 文件）仅在步骤/尝试边界生效；**单步执行中无法中途终止**正在运行的子进程（超时由适配器超时机制兜底）。")
    L.append("- 超时清理语义：Windows 下超时后执行 taskkill /PID /T /F 树清理并兜底 proc.kill()，"
             "全过程字段化记录于该步骤 attempt 结果的 meta['cleanup']；SUCCESS 仅表示 taskkill 返回 0，"
             "**不等于进程树已确认全部清理**（无运行时残留检测，residual_check 恒为 NOT_CHECKED）。")
    if risk in ("R3", "R4"):
        L.append(f"- 当前为 R3+ 模式，scope 必须包含完整 risk_acknowledgement（{', '.join(ACK_KEYS)}）。")
    L.append("- 本引擎当前未实现：断点续跑、窗口过期监控线程、L2/L4 能力（利用链编排、修复验证）。")
    return "\n".join(L) + "\n"


def _ts() -> str:
    from .journal import utcnow

    return utcnow()
