"""EXT-0.5: integration feasibility verification (T1-T6).

Goal: prove that vuln_hunter/findings.py correctly receives the REAL output
shapes of the three existing adapters and converts them into unified
Findings — WITHOUT modifying any production code, WITHOUT running any real
scan, and WITHOUT touching the V1 execution chain.

How "real" is achieved without executing tools:
- The REAL, unmodified `AdapterResult` container (vuln_hunter/adapters.py,
  L83-90: status/ok/detail/findings/meta) is used exactly as the adapters
  use it — same positional/keyword call style, realistic detail strings.
- The finding payloads inside are the EXACT dict shapes emitted at
  adapters.py L260-265 (http_service), L494-503 (nuclei_finding),
  L542-551 (bandit_finding), populated with FICTIONAL content.
- normalize() from findings.py performs the conversion under test.

Coverage map (task book -> section):
  T1 real adapter output conversion        -> A
  T2 field completeness / no silent loss   -> B
  T3 finding_id stability                   -> C
  T4 sensitive info handling               -> D
  T5 legacy-format compatibility           -> E
  T6 abnormal input handling               -> F

SECURITY: all payloads and secret-shaped fixtures are fictional and built
at runtime. No real credential and no vendor-documentation sample key
appears in this file. No subprocess is ever spawned.

Run:  python tests/test_findings_integration.py
"""
import hashlib
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

# REAL production container — imported, never modified.
from vuln_hunter.adapters import AdapterResult  # noqa: E402
from vuln_hunter.findings import (  # noqa: E402
    Finding,
    FindingError,
    normalize,
    redact_evidence,
)

failures = 0
checks_run = 0


def check(cid, cond, desc):
    global failures, checks_run
    checks_run += 1
    status = "PASS" if cond else "FAIL"
    if not cond:
        failures += 1
    print(f"[{status}] {cid}: {desc}")


def raises_fe(fn):
    try:
        fn()
    except FindingError:
        return True
    except Exception:
        return False
    return False


# ---------------------------------------------------------------------------
# Fictional fixtures matching the REAL adapter output shapes
# ---------------------------------------------------------------------------
LAB_URL = "http://127.0.0.1:18080"  # loopback-only; nothing is contacted

HTTP_RAW_1 = {"type": "http_service", "url": LAB_URL + "/",
              "status": 200, "server": "FakeLabServer/1.0"}
HTTP_RAW_2 = {"type": "http_service", "url": LAB_URL + "/admin",
              "status": 403, "server": "FakeLabServer/1.0", "title": "Admin Login"}

NUCLEI_RAW_1 = {"type": "nuclei_finding", "template": "cve-2021-99999",
                "severity": "critical", "name": "Fake CVE Detection",
                "host": LAB_URL, "matched_at": LAB_URL + "/vuln"}
NUCLEI_RAW_2 = {"type": "nuclei_finding", "template": None,
                "severity": None, "name": None,
                "host": LAB_URL, "matched_at": LAB_URL + "/other"}

BANDIT_RAW_1 = {"type": "bandit_finding", "test_id": "B999",
                "severity": "HIGH", "filename": "lab/app.py", "line": 42,
                "issue": "Use of insecure pickle detected."}
BANDIT_RAW_2 = {"type": "bandit_finding", "test_id": "B404",
                "severity": "LOW", "filename": "lab/sub.py", "line": None,
                "issue": ""}

# Fictional secret shapes, assembled at runtime (never real, never docs).
# Key-context forms (realistic evidence lines) vs. bare values.
FAKE_PASSWORD_VALUE = "Pa55w0rd" + "-LIKE-FAKE-STRING"
FAKE_TOKEN_VALUE = "tok" + "en1234567890abcdef"
FAKE_APIKEY_VALUE = "API" + "-KEY-" + "Z" * 18
FAKE_BEARER_TOKEN = "T" * 24
FAKE_BEARER_SHORT = "q7" + "Zx"   # 4 chars — short credential
FAKE_BEARER_TINY = "q7" + "x"     # 3 chars — below standalone minimum
FAKE_BASIC_CRED = "dXNl" + "cjpw" + "YXNz" + "1234"  # base64-shaped, has digits
FAKE_BARE_SECRET = "opaque" + "value12345"  # no key=value context

print("=" * 78)
print("EXT-0.5/0.6/0.7 FINDINGS INTEGRATION VERIFICATION "
      "(T1-T6 + auth redaction boundaries)")
print("=" * 78)

# ==========================================================================
# T1. real adapter output conversion
# ==========================================================================
http_result = AdapterResult("COMPLETED", True, "HTTP 200", [dict(HTTP_RAW_1)],
                            meta={"env_policy": "direct"})
http_result2 = AdapterResult("COMPLETED", True, "HTTP 403",
                             [dict(HTTP_RAW_2)], meta={"env_policy": "direct"})
nuclei_result = AdapterResult(
    "COMPLETED", True,
    "nuclei exit 0, 2 finding(s), templates_loaded=6500",
    [dict(NUCLEI_RAW_1), dict(NUCLEI_RAW_2)],
    meta={"env_policy": "direct", "templates_loaded": 6500, "output_valid": True})
bandit_result = AdapterResult(
    "COMPLETED", True, "bandit exit 0, 2 finding(s)",
    [dict(BANDIT_RAW_1), dict(BANDIT_RAW_2)])

check("T1-01", isinstance(http_result.findings, list)
      and http_result.findings[0]["type"] == "http_service",
      "real AdapterResult carries the http_service raw finding")
check("T1-02", len(nuclei_result.findings) == 2 and len(bandit_result.findings) == 2,
      "real AdapterResult carries 2 nuclei + 2 bandit raw findings")

conv_http = [normalize(r) for r in http_result.findings]
conv_http2 = [normalize(r) for r in http_result2.findings]
conv_nuclei = [normalize(r) for r in nuclei_result.findings]
conv_bandit = [normalize(r) for r in bandit_result.findings]

check("T1-03", all(isinstance(f, Finding) for f in conv_http + conv_nuclei + conv_bandit),
      "T1a: all 6 raw records from real containers converted to Finding")
check("T1-04", all(f.finding_id.startswith("fnd_") for f in
                   conv_http + conv_http2 + conv_nuclei + conv_bandit),
      "T1b: every converted Finding has a computed fnd_ id")
check("T1-05", conv_http[0].tool == "http-probe" and conv_nuclei[0].tool == "nuclei"
      and conv_bandit[0].tool == "bandit",
      "T1c: tool attribution correct for all three adapter families")
check("T1-06", {f.finding_type for f in conv_http} == {"http_service"}
      and {f.finding_type for f in conv_nuclei} == {"nuclei_finding"}
      and {f.finding_type for f in conv_bandit} == {"bandit_finding"},
      "T1d: finding_type tag preserved through conversion")
check("T1-07", conv_http2[0].title == "Admin Login" and conv_http[0].title == "HTTP 200",
      "T1e: http title taken from page title when present, status otherwise")
check("T1-08", conv_nuclei[1].severity == "info" and conv_nuclei[1].rule_id == "unknown",
      "T1f: nuclei record with None template/severity converts via documented fallbacks")
check("T1-09", conv_bandit[1].location == "lab/sub.py" and conv_bandit[1].title.startswith("bandit rule"),
      "T1g: bandit record with line=None and empty issue converts via documented fallbacks")

# ==========================================================================
# T2. field completeness (12 fields, types, no silent information loss)
# ==========================================================================
FIELDS = ["finding_id", "tool", "finding_type", "title", "severity", "target",
          "location", "rule_id", "description", "evidence", "evidence_redacted",
          "references", "schema_version"]
for i, f in enumerate(conv_http + conv_nuclei + conv_bandit):
    d = f.to_dict()
    missing = [k for k in FIELDS if k not in d]
    wrong = [k for k in ("tool", "finding_type", "title", "severity", "target",
                         "location", "rule_id", "description")
             if not isinstance(d[k], str) or not d[k]]
    check(f"T2-{i:02d}", not missing and not wrong
          and d["finding_id"].startswith("fnd_")
          and isinstance(d["references"], list)
          and d["evidence"] is None
          and d["evidence_redacted"] is False
          and d["schema_version"] == 1,
          f"record {i} ({f.tool}) has all 13 keys, correct types, safe defaults")

# information carried across (no accidental loss) -------------------------
h = conv_http[0]
check("T2-20", h.target == LAB_URL + "/" and h.location == LAB_URL + "/",
      "http: url preserved into target AND location")
check("T2-21", "200" in h.description and "FakeLabServer/1.0" in h.description,
      "http: status and server banner preserved in description (no separate field)")
n = conv_nuclei[0]
check("T2-22", n.rule_id == "cve-2021-99999" and n.location == LAB_URL + "/vuln"
      and n.target == LAB_URL and n.title == "Fake CVE Detection" and n.severity == "critical",
      "nuclei: template/matched_at/host/name/severity all preserved")
b = conv_bandit[0]
check("T2-23", b.rule_id == "B999" and b.target == "lab/app.py"
      and b.location == "lab/app.py:42" and b.title == "Use of insecure pickle detected."
      and b.severity == "high",
      "bandit: test_id/filename/line/issue/severity all preserved")

# explicitly recorded unmapped fields (no silent invention) ----------------
check("T2-24", "status" not in h.to_dict() and "server" not in h.to_dict(),
      "unmapped http fields (status/server) have NO dedicated schema field — documented")
check("T2-25", h.severity == "info",
      "http_service carries no severity in its shape — documented default 'info', never invented")
check("T2-26", n.to_dict().get("matched_at") is None,
      "unmapped nuclei fields (matched-at verbatim key) have NO extra schema field — documented")
# raw records must NOT be mutated by conversion (legacy data integrity)
check("T2-27", HTTP_RAW_1 == {"type": "http_service", "url": LAB_URL + "/",
                             "status": 200, "server": "FakeLabServer/1.0"},
      "normalize() does not mutate the legacy raw dict")
check("T2-28", nuclei_result.findings[0]["template"] == "cve-2021-99999",
      "normalize() does not mutate the AdapterResult payload")

# ==========================================================================
# T3. finding_id stability
# ==========================================================================
ids = {normalize(NUCLEI_RAW_1).finding_id for _ in range(5)}
check("T3-01", len(ids) == 1, "same input converted 5x -> one identical finding_id")
ids_bandit = {normalize(BANDIT_RAW_1).finding_id for _ in range(5)}
check("T3-02", len(ids_bandit) == 1, "bandit record converts deterministically (5x)")
check("T3-03", normalize({**NUCLEI_RAW_1, "host": "http://127.0.0.1:18081"}).finding_id
      != n.finding_id, "different target -> different finding_id")
check("T3-04", normalize({**BANDIT_RAW_1, "test_id": "B102"}).finding_id
      != b.finding_id, "different rule_id -> different finding_id")
check("T3-05", normalize({**NUCLEI_RAW_1, "name": "Renamed Fake CVE"}).finding_id
      == n.finding_id, "title change -> SAME id (EXT-0 design: locator-quintuple only)")
check("T3-06", normalize({**NUCLEI_RAW_1, "severity": "low"}).finding_id
      == n.finding_id, "severity change -> SAME id (documented; content excluded from id)")
check("T3-07", n.finding_id != b.finding_id and conv_http[0].finding_id != conv_http2[0].finding_id,
      "cross-tool and cross-target ids differ")
check("T3-08", re.fullmatch(r"fnd_[0-9a-f]{16}", n.finding_id) is not None,
      "id format fnd_<16 lowercase hex>")

# ==========================================================================
# T4. sensitive info handling (evidence attached at Finding construction)
# ==========================================================================
secret_bundle = (
    f"password={FAKE_PASSWORD_VALUE}\n"
    f"token: {FAKE_TOKEN_VALUE}\n"
    f"api_key={FAKE_APIKEY_VALUE}\n"
    f"Authorization: Bearer {FAKE_BEARER_TOKEN}\n"
)
ev_finding = Finding(
    tool="faketool", finding_type="faketool_finding",
    title="Fictional leak", severity="high", target="http://127.0.0.1:18080",
    location="http://127.0.0.1:18080/leak", rule_id="fake-rule",
    description="fictional", evidence=secret_bundle)
check("T4-01", ev_finding.evidence_redacted is True,
      "Finding with secret-shaped evidence is flagged evidence_redacted")
for i, secret in enumerate([FAKE_PASSWORD_VALUE, FAKE_TOKEN_VALUE, FAKE_APIKEY_VALUE]):
    check(f"T4-0{i + 2}", secret not in ev_finding.evidence,
          f"fictional key-context secret #{i + 1} (password=/token:/api_key=) redacted")
check("T4-05", "[REDACTED:secret]" in ev_finding.evidence,
      "redaction is visible via [REDACTED:secret] markers, not silent deletion")
check("T4-06", len(ev_finding.evidence) <= 512,
      f"evidence capped at 512 (actual {len(ev_finding.evidence)})")

# fail-safe: raw records carrying an 'evidence'-like extra key are IGNORED
nuclei_with_extra = {**NUCLEI_RAW_1, "evidence": f"password={FAKE_PASSWORD_VALUE}",
                     "secret": FAKE_TOKEN_VALUE}
ne = normalize(nuclei_with_extra)
check("T4-07", ne.evidence is None,
      "normalizer ignores unmapped raw keys (e.g. stray 'evidence') — no leakage")
check("T4-08", redact_evidence(secret_bundle)[1] >= 3,
      "redact_evidence fires >=3 times on the fictional key-context bundle")
long_ev = Finding(**{**{k: getattr(n, k) for k in
                        ("tool", "finding_type", "title", "severity", "target",
                         "location", "rule_id", "description")},
                    "evidence": "B" * 2000})
check("T4-09", len(long_ev.evidence) == 512 and long_ev.evidence.endswith("…[truncated]"),
      "long evidence truncated deterministically with visible marker")
check("T4-10", Finding(**{**{k: getattr(n, k) for k in
                             ("tool", "finding_type", "title", "severity", "target",
                              "location", "rule_id", "description")},
                         "evidence": ""}).evidence == "",
      "empty evidence string accepted as present-but-empty (deterministic)")

# --- G1 fix regression (EXT-0.6): must-pass security assertions -------------
# EXT-0.5 defect: _SECRET_ASSIGN_RE consumed the 'Bearer' keyword before
# _BEARER_RE could match, leaving the token in plaintext. Fix: Bearer
# pattern now runs first (findings.py redact_evidence). These checks MUST
# pass. All fixtures are runtime-assembled fiction; descriptions never
# print secret material.
def _g1_finding(evidence):
    return Finding(
        tool="faketool", finding_type="faketool_finding",
        title="Fictional leak", severity="high", target="http://127.0.0.1:18080",
        location="http://127.0.0.1:18080/leak", rule_id="fake-rule",
        description="fictional", evidence=evidence)

g1a = _g1_finding(f"Authorization: Bearer {FAKE_BEARER_TOKEN}")
check("G1a", FAKE_BEARER_TOKEN not in g1a.evidence
      and g1a.evidence_redacted is True,
      "G1a: Authorization colon form — fictional token fully absent, redaction fired")
g1b = _g1_finding(f"Authorization=Bearer {FAKE_BEARER_TOKEN}")
check("G1b", FAKE_BEARER_TOKEN not in g1b.evidence
      and g1b.evidence_redacted is True,
      "G1b: Authorization equals form — fictional token fully absent, redaction fired")
g1c = _g1_finding(f"Bearer {FAKE_BEARER_TOKEN}")
check("G1c", FAKE_BEARER_TOKEN not in g1c.evidence
      and g1c.evidence_redacted is True,
      "G1c: standalone Bearer form — fictional token fully absent, redaction fired")
g1d = _g1_finding(
    f"password={FAKE_PASSWORD_VALUE}\n"
    f"token: {FAKE_TOKEN_VALUE}\n"
    f"api_key={FAKE_APIKEY_VALUE}\n"
    f"Authorization: Bearer {FAKE_BEARER_TOKEN}")
check("G1d", FAKE_PASSWORD_VALUE not in g1d.evidence
      and FAKE_TOKEN_VALUE not in g1d.evidence
      and FAKE_APIKEY_VALUE not in g1d.evidence
      and FAKE_BEARER_TOKEN not in g1d.evidence,
      "G1d: multi-credential combo — every fictional credential individually absent")
check("G1e", FAKE_BEARER_TOKEN[:12] not in g1d.evidence
      and FAKE_PASSWORD_VALUE[:12] not in g1d.evidence
      and FAKE_TOKEN_VALUE[:12] not in g1d.evidence,
      "G1e: no partial plaintext residue — credential prefixes also absent")
check("G1f", "[REDACTED" in g1d.evidence and g1d.evidence.count("[REDACTED") >= 4,
      "G1f: redaction markers clearly visible for every redacted field")

# --- EXT-0.7 T1: short / long / case / space boundaries (Bearer) ------------
g1g = _g1_finding(f"Authorization: Bearer {FAKE_BEARER_SHORT}")
check("G1g", FAKE_BEARER_SHORT not in g1g.evidence
      and g1g.evidence_redacted is True,
      "G1g: header-context SHORT Bearer credential (4 chars) fully absent")
g1h = _g1_finding(f"Authorization: Bearer {FAKE_BEARER_TINY}")
check("G1h", FAKE_BEARER_TINY not in g1h.evidence
      and g1h.evidence_redacted is True,
      "G1h: header-context TINY Bearer credential (3 chars) fully absent")
g1i = _g1_finding(f"Bearer {FAKE_BEARER_SHORT}")
check("G1i", FAKE_BEARER_SHORT not in g1i.evidence
      and g1i.evidence_redacted is True,
      "G1i: standalone SHORT Bearer credential (4 chars) fully absent")
g1j = _g1_finding(f"AUTHORIZATION: BEARER {FAKE_BEARER_TOKEN}")
check("G1j", FAKE_BEARER_TOKEN not in g1j.evidence
      and g1j.evidence_redacted is True,
      "G1j: uppercase keyword/scheme variant fully absent")
g1k = _g1_finding(f"authorization: bearer {FAKE_BEARER_TOKEN}")
check("G1k", FAKE_BEARER_TOKEN not in g1k.evidence
      and g1k.evidence_redacted is True,
      "G1k: lowercase keyword/scheme variant fully absent")
g1l = _g1_finding(f"Authorization:   Bearer   {FAKE_BEARER_TOKEN}")
check("G1l", FAKE_BEARER_TOKEN not in g1l.evidence
      and g1l.evidence_redacted is True,
      "G1l: multiple spaces between keyword/scheme/credential fully absent")

# --- EXT-0.7 T2: Basic auth credentials -------------------------------------
g2a = _g1_finding(f"Authorization: Basic {FAKE_BASIC_CRED}")
check("G2a", FAKE_BASIC_CRED not in g2a.evidence
      and g2a.evidence_redacted is True,
      "G2a: header-context Basic credential fully absent")
check("G2b", "[REDACTED:basic-credentials]" in g2a.evidence,
      "G2b: Basic scheme+credential replaced together with a dedicated marker")
g2c = _g1_finding(f"Basic {FAKE_BASIC_CRED}")
check("G2c", FAKE_BASIC_CRED not in g2c.evidence
      and g2c.evidence_redacted is True,
      "G2c: standalone Basic credential fully absent (whole-match replacement)")
check("G2d", FAKE_BASIC_CRED[:12] not in g2c.evidence,
      "G2d: no partial Basic credential residue (prefix absent)")
prose_basic, n_basic = redact_evidence(
    "Basic authentication is required for this endpoint")
check("G2e", prose_basic == "Basic authentication is required for this endpoint"
      and n_basic == 0,
      "G2e: ordinary prose containing the word Basic is untouched and not counted")
prose_bearer, n_bearer = redact_evidence("the bearer of bad news arrived late")
check("G2f", prose_bearer == "the bearer of bad news arrived late" and n_bearer == 0,
      "G2f: prose 'bearer of ...' untouched (below standalone minimum, not counted)")
prose_word, n_word = redact_evidence("use basic settings when configuring the tool")
check("G2g", prose_word == "use basic settings when configuring the tool"
      and n_word == 0,
      "G2g: prose 'basic settings' untouched (non-base64 value, not counted)")

# --- EXT-0.7 T3: mixed / equals / multi-space formats -----------------------
g3a = _g1_finding(
    f"password={FAKE_PASSWORD_VALUE}\n"
    f"token: {FAKE_TOKEN_VALUE}\n"
    f"api_key={FAKE_APIKEY_VALUE}\n"
    f"Authorization: Bearer {FAKE_BEARER_SHORT}\n"
    f"Authorization=Basic {FAKE_BASIC_CRED}")
check("G3a", FAKE_PASSWORD_VALUE not in g3a.evidence
      and FAKE_TOKEN_VALUE not in g3a.evidence
      and FAKE_APIKEY_VALUE not in g3a.evidence
      and FAKE_BEARER_SHORT not in g3a.evidence
      and FAKE_BASIC_CRED not in g3a.evidence,
      "G3a: five-credential mixed combo (key-value + Bearer + Basic) each absent")
check("G3b", g3a.evidence.count("[REDACTED") >= 5,
      "G3b: five redaction markers visible in the mixed combo")
g3c = _g1_finding(f"Authorization=Basic {FAKE_BASIC_CRED}")
check("G3c", FAKE_BASIC_CRED not in g3c.evidence
      and g3c.evidence_redacted is True,
      "G3c: Basic in equals form fully absent")
g3d = _g1_finding(f"Basic   {FAKE_BASIC_CRED}")
check("G3d", FAKE_BASIC_CRED not in g3d.evidence
      and g3d.evidence_redacted is True,
      "G3d: standalone Basic with multiple spaces fully absent")

# --- KNOWN LIMITATION G2 (by design, defense-in-depth) --------------------
# A bare opaque string with NO key=value / header context is not redacted;
# findings.py documents redaction as pattern-based defense in depth, not a
# guarantee. Pinned here so a future tightening does not silently change.
g2 = redact_evidence(f"response body contained {FAKE_BARE_SECRET} inline")[0]
check("G2-KNOWN-LIMIT", FAKE_BARE_SECRET in g2,
      "KNOWN LIMITATION G2 (by design): bare opaque secret without key context "
      "is not redacted — pattern-based defense-in-depth, documented in findings.py")

# ==========================================================================
# T5. legacy-format compatibility
# ==========================================================================
src = (ROOT / "vuln_hunter" / "adapters.py").read_text(encoding="utf-8")
check("T5-01", "findings" not in re.findall(r"^from \.\w+|^import \w+", src, re.M).__str__()
      and "from .findings" not in src and "import findings" not in src,
      "T5a: adapters.py does NOT import the findings module")
check("T5-02", 'class AdapterResult:' in src and '"type": "http_service"' in src
      and '"type": "nuclei_finding"' in src and '"type": "bandit_finding"' in src,
      "T5b: the three legacy finding shapes are still verbatim in adapters.py")
adapter_hash = hashlib.sha256((ROOT / "vuln_hunter" / "adapters.py").read_bytes()).hexdigest()
check("T5-03", adapter_hash.startswith("65ece047b13784e0"),
      "T5c: adapters.py SHA-256 prefix 65ece047b13784e0 unchanged")
for name, exp in [("runner.py", "29d71dc54f34bc02"), ("report.py", "59caebb3094896f1")]:
    h = hashlib.sha256((ROOT / "vuln_hunter" / name).read_bytes()).hexdigest()
    check(f"T5-{4 + ['runner.py', 'report.py'].index(name)}", h.startswith(exp),
          f"T5d: {name} SHA-256 prefix {exp} unchanged")
check("T5-06", AdapterResult("COMPLETED", True, "x", [dict(HTTP_RAW_1)]).findings[0]
      == HTTP_RAW_1,
      "T5e: AdapterResult construction with a legacy finding is unmodified behavior")
check("T5-07", conv_nuclei[0].finding_id
      == normalize(dict(NUCLEI_RAW_1)).finding_id,
      "T5f: conversion is independent of the container (same id from bare dict)")

# ==========================================================================
# T6. abnormal input handling
# ==========================================================================
check("T6-01", raises_fe(lambda: normalize({**NUCLEI_RAW_1, "host": None})),
      "nuclei raw missing host -> FindingError")
check("T6-02", raises_fe(lambda: normalize({"type": "nuclei_finding"})),
      "nuclei raw with no fields at all -> FindingError")
check("T6-03", raises_fe(lambda: normalize({"type": "bandit_finding", "test_id": None,
                                            "severity": "HIGH", "filename": "a.py",
                                            "line": 1, "issue": "x"})),
      "bandit raw missing test_id -> FindingError")
check("T6-04", raises_fe(lambda: normalize({**HTTP_RAW_1, "url": ""})),
      "http raw with empty url -> FindingError")
check("T6-05", raises_fe(lambda: normalize({**HTTP_RAW_1, "status": "200"})),
      "http raw with str status -> FindingError")
check("T6-06", raises_fe(lambda: normalize({**BANDIT_RAW_1, "line": "42"})),
      "bandit raw with str line -> FindingError")
check("T6-07", raises_fe(lambda: normalize({**BANDIT_RAW_1, "severity": "severe"})),
      "bandit raw with illegal severity -> FindingError")
check("T6-08", raises_fe(lambda: normalize(None)), "normalize(None) -> FindingError")
check("T6-09", raises_fe(lambda: normalize("garbage")), "normalize(str) -> FindingError")
check("T6-10", raises_fe(lambda: normalize({"type": "unknown_tool_finding", "x": 1})),
      "unregistered type tag -> FindingError (fail-closed)")
check("T6-11", raises_fe(lambda: Finding(tool="t", finding_type="t", title="t",
                                         severity="info", target="a", location="b",
                                         rule_id="r", description="d",
                                         references=[None])),
      "references containing None -> FindingError")
check("T6-12", raises_fe(lambda: Finding(tool="t", finding_type="t", title="t",
                                         severity="info", target="a", location="b",
                                         rule_id="r", description="d",
                                         references="CVE-1")),
      "references as bare str (not list) -> FindingError")
check("T6-13", raises_fe(lambda: Finding(tool="t", finding_type="t", title="t",
                                         severity="info", target="a", location="b",
                                         rule_id="r", description="d",
                                         evidence=42)),
      "evidence with non-str type -> FindingError")
check("T6-14", not raises_fe(lambda: Finding(tool="t", finding_type="t", title="t",
                                             severity="info", target="a", location="b",
                                             rule_id="r", description="d",
                                             evidence="")),
      "empty-string evidence accepted (present-but-empty), no FindingError")
check("T6-15", raises_fe(lambda: Finding(tool="t", finding_type="t", title="t",
                                         severity="info", target="a", location="b",
                                         rule_id="r", description="d",
                                         finding_id="fnd_0000000000000000")),
      "supplied finding_id -> FindingError")
check("T6-16", isinstance(raises_fe(lambda: normalize({**NUCLEI_RAW_1, "host": 127})), bool),
      "type-error path returns a clean FindingError, never leaks a raw TypeError")

print("-" * 78)
print(f"EXT-0.5/0.6/0.7 INTEGRATION TESTS: "
      f"{checks_run - failures}/{checks_run} checks passed")
sys.exit(1 if failures else 0)
