"""D2-C closeout: offline unit tests for classify_p9_outcome (R4 fix).

Covers the three P9 outcome classes:
  SPAWNED / EXPECTED_REJECTION / UNEXPECTED_FAILURE.

Loads tests/test_d2c_first_run.py as a plain module — its module level has
no side effects beyond constants (preflight() only runs under __main__),
so importing it here starts NO server, NO nuclei and makes NO network calls.

Run:  python tests/test_d2c_r4.py
"""
import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "d2c_first_run", ROOT / "tests" / "test_d2c_first_run.py")
d2c = importlib.util.module_from_spec(spec)
sys.modules["d2c_first_run"] = d2c
spec.loader.exec_module(d2c)

fails = 0


def check(cid: str, cond: bool, note: str = ""):
    global fails
    if not cond:
        fails += 1
    print(f"[{'PASS' if cond else 'FAIL'}] {cid} — {note}")


def rec(event: str, **kw) -> dict:
    return {"event": event, **kw}


# ---- 1. SPAWNED ------------------------------------------------------------
r1 = d2c.classify_p9_outcome([
    rec("p9_decision_start", parent="s2-nuclei"),
    rec("p9_trigger", parent="s2-nuclei", template="t1"),
    rec("p9_spawn", child="s2-nuclei-p9v-t1", target="127.0.0.1:18080"),
])
check("R4U-01", r1[0] == "SPAWNED", f"on-target spawn -> SPAWNED ({r1[1]})")

# ---- 2. SPAWNED with multiple decisions (contract: one child per decision)
r2 = d2c.classify_p9_outcome([
    rec("p9_spawn", child="a-p9v-t1", target="127.0.0.1:18080"),
    rec("p9_spawn", child="b-p9v-t2", target="127.0.0.1:18080"),
])
check("R4U-02", r2[0] == "SPAWNED", f"multi-decision spawns -> SPAWNED ({r2[1]})")

# ---- 3. off-target spawn is a security-contract violation ------------------
r3 = d2c.classify_p9_outcome([
    rec("p9_spawn", child="x-p9v-t1", target="10.9.9.9:18080"),
])
check("R4U-03", r3[0] == "UNEXPECTED_FAILURE",
      f"off-target spawn -> UNEXPECTED_FAILURE ({r3[1]})")

# ---- 4. the two REAL D2-C rejections (verbatim journal reasons) ------------
r4 = d2c.classify_p9_outcome([
    rec("p9_decision_start", parent="s1-probe"),
    rec("p9_evidence_invalid", parent="s1-probe",
        reason="finding type 'http_service' is not 'nuclei_finding'"),
    rec("p9_decision_start", parent="s2-nuclei"),
    rec("p9_evidence_invalid", parent="s2-nuclei",
        reason="all qualifying templates already covered by an equivalent "
               "graph node; nothing new to generate"),
])
check("R4U-04", r4[0] == "EXPECTED_REJECTION" and "s1-probe" in r4[1]
      and "s2-nuclei" in r4[1],
      f"both real D2-C rejections -> EXPECTED_REJECTION ({r4[1][:90]}...)")

# ---- 5. other contract-allowed rejections ----------------------------------
cases = [
    ("p9_skip", "parent status 'FAILED' is not COMPLETED"),
    ("p9_skip", "parent quarantined (e.g. HTTP 429); evidence unreliable"),
    ("p9_evidence_invalid", "findings must be a list, got NoneType"),
    ("p9_evidence_invalid", "findings is empty — no reliable evidence to act on"),
    ("p9_evidence_invalid", "finding element is str, expected dict"),
    ("p9_evidence_invalid", "finding template 'x y' is not a valid non-empty template id"),
    ("p9_spawn_rejected", "child risk R2 exceeds parent executed risk R1"),
    ("p9_spawn_rejected", "invalid parent timeout budget: 0"),
    ("p9_spawn_rejected", "add_node refused: spawn budget exhausted"),
]
for i, (evname, reason) in enumerate(cases, start=5):
    r = d2c.classify_p9_outcome([rec(evname, parent="p", reason=reason)])
    check(f"R4U-{i:02d}", r[0] == "EXPECTED_REJECTION",
          f"{evname}: {reason[:50]}... -> EXPECTED_REJECTION")

# ---- 6. UNEXPECTED: contract-unknown rejection reason ----------------------
r10 = d2c.classify_p9_outcome([
    rec("p9_evidence_invalid", parent="p", reason="totally unknown reason"),
])
check("R4U-14", r10[0] == "UNEXPECTED_FAILURE",
      f"unknown reason -> UNEXPECTED_FAILURE ({r10[1]})")

# ---- 7. UNEXPECTED: malformed rejection (missing reason) -------------------
r11 = d2c.classify_p9_outcome([rec("p9_evidence_invalid", parent="p")])
check("R4U-15", r11[0] == "UNEXPECTED_FAILURE",
      f"missing reason -> UNEXPECTED_FAILURE ({r11[1]})")

# ---- 8. UNEXPECTED: no P9 events at all ------------------------------------
r12 = d2c.classify_p9_outcome([rec("decision"), rec("run_end")])
check("R4U-16", r12[0] == "UNEXPECTED_FAILURE",
      f"no P9 events -> UNEXPECTED_FAILURE ({r12[1]})")

# ---- 9. UNEXPECTED: spawn happened but decision trail broken ---------------
r13 = d2c.classify_p9_outcome([
    rec("p9_spawn", child="c", target="127.0.0.1:18080"),
    rec("p9_evidence_invalid", parent="p", reason="totally unknown"),
])
check("R4U-17", r13[0] == "UNEXPECTED_FAILURE",
      f"spawn + unknown rejection -> UNEXPECTED_FAILURE ({r13[1]})")

# ---- 10. replay of the REAL D2-C first-run journal (read-only anchor) ------
real_journal = (Path.home() / "AppData/Local/Temp/d2c-run-h82jj6hl/ev/journal.jsonl")
if real_journal.is_file():
    real = [__import__("json").loads(l)["rec"]
            for l in real_journal.read_text(encoding="utf-8").splitlines()
            if l.strip()]
    rr = d2c.classify_p9_outcome(real)
    check("R4U-18", rr[0] == "EXPECTED_REJECTION",
          f"REAL D2-C journal replays as EXPECTED_REJECTION ({rr[1][:90]}...)")
else:
    print("[SKIP] R4U-18 — real first-run journal not present on this machine")

print(f"\nR4U: {'ALL PASSED' if fails == 0 else 'FAILURES: ' + str(fails)}")
sys.exit(1 if fails else 0)
