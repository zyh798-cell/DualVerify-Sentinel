"""CLI: python -m vuln_hunter run --scope ... --mode ... --target ...

Exit codes: 0 = all steps completed; 1 = run finished with failures/refusals;
2 = gate/policy-level refusal before any execution;
3 = AUDIT FAILURE (journal could not be written/verified — including
verification failure at run_end; run result NOT certified — never disguised
as a normal outcome).
"""
import argparse
import json
import sys
from pathlib import Path

from .decision import DecisionEngine
from .gate import run_gate
from .journal import EvidenceJournal
from .loop import AutonomousLoop
from .planner import build_plan
from .policy import MODES, PolicyEngine
from .report import render_report
from .runner import Executor


def fresh_evidence_dir(base) -> Path:
    """Never reuse an evidence dir that already has a journal: re-runs get
    -r2, -r3, ... suffixes so prior evidence is never overwritten or mixed."""
    base = Path(base)
    ev = base
    i = 2
    while (ev / "journal.jsonl").exists():
        ev = base.with_name(base.name + f"-r{i}")
        i += 1
    ev.mkdir(parents=True, exist_ok=True)
    return ev


def _safe_scope(path_str: str) -> dict:
    try:
        return json.loads(Path(path_str).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="vuln_hunter")
    sub = ap.add_subparsers(dest="cmd", required=True)
    run = sub.add_parser("run", help="execute a plan against an authorized target")
    run.add_argument("--scope", required=True, help="scope JSON file")
    run.add_argument("--mode", required=True, choices=sorted(MODES))
    run.add_argument("--target", required=True, help="host[:port] or URL")
    run.add_argument("--source-dir", help="optional source tree for bandit")
    run.add_argument("--evidence-dir", default=None)
    run.add_argument("--timeout", type=int, default=120, help="dynamic-step timeout")
    run.add_argument("--loop", action="store_true",
                     help="enable the rule-based autonomous decision loop")
    run.add_argument("--max-steps", type=int, default=6,
                     help="loop step budget (only with --loop)")
    run.add_argument("--p9", action="store_true",
                     help="enable P9 dynamic follow-up generation (only with "
                          "--loop): a COMPLETED nuclei step with reliable "
                          "findings may spawn ONE focused single-template "
                          "re-validation on the SAME target; default OFF")
    run.add_argument("--synthetic", action="store_true",
                     help="declare this run a synthetic/lab run: every "
                          "finding is structurally marked synthetic=true and "
                          "excluded from real-vulnerability counts in the "
                          "report; default OFF")
    run.add_argument("--nuclei-id", default="",
                     help="comma-separated nuclei template IDs (explicit subset)")
    run.add_argument("--nuclei-tags", default="",
                     help="comma-separated nuclei template tags (explicit subset)")
    run.add_argument("--nuclei-timeout", type=int, default=240,
                     help="independent per-attempt budget for the nuclei step "
                          "(default 240s: measured catalog-load ~3-3.5min)")
    gc = sub.add_parser("gate-check",
                        help="validate a scope file via the in-package gate "
                             "(no execution; exit 0=accept, 1=refuse)")
    gc.add_argument("scope", help="scope JSON file")
    args = ap.parse_args(argv)

    if args.cmd == "gate-check":
        # Same REAL subprocess the run command uses — one gate, one truth.
        try:
            res = run_gate(args.scope)
        except Exception as exc:  # noqa: BLE001 - fail-closed
            print(f"gate unavailable (fail-closed): {exc.__class__.__name__}: {exc}",
                  file=sys.stderr)
            return 2
        if res.returncode == 0:
            print((res.stdout or "").strip())
        else:
            print((res.stderr or res.stdout or "gate refused").strip(), file=sys.stderr)
        return res.returncode

    if args.cmd != "run":  # pragma: no cover
        ap.error("unknown command")

    from .journal import JournalIntegrityError, audit_status, utcnow

    stamp = utcnow().replace(":", "").replace("-", "")
    exit_code = 1
    try:
        ev = fresh_evidence_dir(args.evidence_dir or f"evidence/engine-{stamp}")
        journal = EvidenceJournal(ev / "journal.jsonl")
        journal.append("run_start", mode=args.mode, target=args.target,
                       scope=str(args.scope), evidence_dir=str(ev))

        # --- gate: REAL subprocess, same check a human runs ----------------
        # Fail-closed: ANY gate failure (missing module, crash, timeout, parse
        # error) means REFUSED — never a skip of authorization.
        try:
            gate_res = run_gate(args.scope)
            gate_ok = gate_res.returncode == 0
            gate_msg = gate_res.stdout.strip() if gate_ok else gate_res.stderr.strip()
        except Exception as exc:  # noqa: BLE001 - fail-closed on any gate failure
            gate_res = None
            gate_ok = False
            gate_msg = f"gate unavailable (fail-closed): {exc.__class__.__name__}: {exc}"
        journal.append("gate_result",
                       exit=getattr(gate_res, "returncode", None) if gate_res else None,
                       stdout=(getattr(gate_res, "stdout", "") or "").strip(),
                       stderr=(getattr(gate_res, "stderr", "") or "").strip())

        plan: list[dict] = []
        results: dict = {}
        summary = "REFUSED"
        findings: list = []
        policy = None
        decision_trace = None

        if gate_ok:
            try:
                scope = json.loads(Path(args.scope).read_text(encoding="utf-8"))
                policy = PolicyEngine(scope, args.mode)
            except (OSError, json.JSONDecodeError, ValueError) as exc:
                gate_ok, gate_msg = False, f"scope load/parse failed: {exc}"
                journal.append("policy_error", error=str(exc))

        if gate_ok:
            ack_err = policy.ack_error()
            if ack_err:
                gate_msg = ack_err
                gate_ok = False
                journal.append("policy_refusal", reason=ack_err)
            else:
                plan = build_plan(
                    args.mode, args.target, args.source_dir,
                    timeout_dynamic=args.timeout,
                    nuclei_timeout=args.nuclei_timeout,
                    nuclei_ids=[s for s in args.nuclei_id.split(",") if s.strip()],
                    nuclei_tags=[s for s in args.nuclei_tags.split(",") if s.strip()],
                )
                executor = Executor(policy, journal, ev,
                                    synthetic_run=args.synthetic)
                decision_trace = None
                if args.loop:
                    engine = DecisionEngine(max_steps=args.max_steps)
                    loop = AutonomousLoop(policy, journal, executor, engine,
                                          enable_p9=args.p9)
                    decision_trace, _degraded = loop.run(plan)
                else:
                    for step in plan:
                        executor.run_step(step)
                results = executor.results
                findings = executor.findings()
                summary = executor.summary_status()

        journal.append("run_end", summary=summary)
        # Audit anchor captured AFTER run_end and BEFORE the report is
        # rendered: the anchor therefore covers every journal event up to and
        # including run_end. The report says exactly that; the only expected
        # later write is the single `report_written` event below.
        audit = audit_status(journal.path)

        scope_for_report = _safe_scope(args.scope)
        # D2-D-4-F1: report render/write failures must NOT escape main() as a
        # generic crash (exit 1) — they are report-stage AUDIT failures and
        # must be stderr-marked and reported with the audit exit code 3.
        # OSError keeps its existing path (outer handler, same semantics);
        # any other exception is caught HERE, never via a main()-wide handler,
        # so business/argument errors stay distinguishable from audit errors.
        # Journal evidence written so far (incl. run_end) is untouched, and
        # no report_written event is fabricated on failure.
        try:
            report = render_report(
                mode=args.mode, risk=MODES[args.mode], scope_path=str(args.scope),
                scope=scope_for_report,
                gate_ok=gate_ok, gate_message=gate_msg, plan=plan, results=results,
                summary=summary, findings=findings, journal_path=str(ev / "journal.jsonl"),
                decision_trace=decision_trace, audit=audit,
            )
            out_paths = [ev / "report.md", Path("output") / "vuln_hunter_report.md"]
            out_paths[1].parent.mkdir(parents=True, exist_ok=True)
            for p in out_paths:
                p.write_text(report, encoding="utf-8")
        except (JournalIntegrityError, OSError):
            raise  # existing audit semantics: outer handler prints + exit 3
        except Exception as exc:  # noqa: BLE001 - bounded report-stage recovery
            print(f"[AUDIT FAILURE] report render/write failed — run result "
                  f"NOT integrity-certified: {exc.__class__.__name__}: {exc}",
                  file=sys.stderr)
            return 3
        journal.append("report_written", report=str(out_paths[1]),
                       anchor=audit["head"], anchor_records=audit["count"])
        print(report)
        print(f"[Vuln-Hunter Status] {summary} — report: {out_paths[1]}")
        print(f"[Audit] verify={audit['detail']} head={str(audit['head'])[:16]}… "
              f"records={audit['count']} (+1 report_written)")
        exit_code = 2 if not gate_ok else (0 if summary == "COMPLETED" else 1)
        if not audit["ok"]:
            # Audit verification failure has HIGHER exit priority than any
            # run-level outcome. The report on disk still carries the real
            # tool/policy result — only the exit code is overridden.
            print(f"[AUDIT FAILURE] journal verification failed at run_end; "
                  f"run result NOT integrity-certified (reported: {summary}, "
                  f"non-audit exit would have been {exit_code})", file=sys.stderr)
            exit_code = 3
    except (JournalIntegrityError, OSError) as exc:
        # Audit failure: journal cannot be written/verified reliably. Never
        # disguise this as a normal run outcome — stop with a distinct code.
        print(f"[AUDIT FAILURE] journal unusable, run result NOT certified: "
              f"{exc.__class__.__name__}: {exc}", file=sys.stderr)
        return 3
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
