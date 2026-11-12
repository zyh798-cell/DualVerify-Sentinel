"""EXT-0: unified Finding schema tests (vuln_hunter/findings.py).

Coverage map (task-book requirement -> section):
  1  legal Finding creation                     -> A
  2  required-field missing                     -> B
  3  illegal severity                           -> C
  4  field type errors                          -> D
  5  Finding ID stability                       -> E
  6  distinct Findings -> distinct IDs          -> F
  7  optional fields omitted                    -> G
  8  sensitive-info handling                    -> H
  9  Nuclei legacy-format compatibility         -> I
  10 Bandit legacy-format compatibility         -> J
  11 HTTP Probe legacy-format compatibility     -> K
  12 abnormal-input handling                    -> L

SECURITY: every secret-shaped fixture below is FICTIONAL and built by
string repetition at runtime — no real credential and no real-vendor
documentation sample appears in this file. Fixtures never leave this
process; nothing is written to disk or logs.

Run:  python tests/test_findings_schema.py
"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from vuln_hunter.findings import (  # noqa: E402
    ALLOWED_SEVERITY,
    Finding,
    FindingError,
    SCHEMA_VERSION,
    normalize,
    redact_evidence,
    register_normalizer,
)

failures = 0


def check(cid, cond, desc):
    global failures
    status = "PASS" if cond else "FAIL"
    if not cond:
        failures += 1
    print(f"[{status}] {cid}: {desc}")


def raises_finding_error(fn):
    try:
        fn()
    except FindingError:
        return True
    except Exception:
        return False
    return False


# ---- fictional secret-shaped fixtures (assembled, never real) ------------
FAKE_AWS_KEY = "AKIA" + "X" * 4 + "1234" * 3          # AKIA + 16 [0-9A-Z]
FAKE_GH_TOKEN = "ghp_" + "a" * 36
FAKE_SK_KEY = "sk-" + "a" * 24
FAKE_JWT = "eyJ" + "a" * 12 + "." + "b" * 12 + "." + "c" * 8
FAKE_BEARER = "Bearer " + "T" * 20
FAKE_PASSWORD = "p@ssw0rd-LIKE-string"                 # value shape only, fictional

VALID_KW = dict(
    tool="nuclei",
    finding_type="nuclei_finding",
    title="Exposed .git directory",
    severity="high",
    target="http://127.0.0.1:18080",
    location="http://127.0.0.1:18080/.git/config",
    rule_id="git-config",
    description="A .git config was reachable on the target.",
)

print("=" * 78)
print("EXT-0 FINDINGS SCHEMA TESTS")
print("=" * 78)

# ==========================================================================
# A. legal creation
# ==========================================================================
f = Finding(**VALID_KW)
check("A-01", f.finding_id.startswith("fnd_") and re.fullmatch(r"fnd_[0-9a-f]{16}", f.finding_id) is not None,
      "finding_id has the fnd_<16hex> shape")
check("A-02", f.severity == "high", "severity accepted case-insensitively, stored lowercase")
f_upper = Finding(**{**VALID_KW, "severity": "CRITICAL"})
check("A-03", f_upper.severity == "critical", "uppercase CRITICAL normalized to critical")
check("A-04", set(ALLOWED_SEVERITY) == {"info", "low", "medium", "high", "critical"},
      "ALLOWED_SEVERITY is exactly the 5 documented levels")
check("A-05", f.schema_version == SCHEMA_VERSION, "schema_version stamped on creation")
d = f.to_dict()
check("A-06", d["finding_id"] == f.finding_id and d["tool"] == "nuclei",
      "to_dict round-trips identity fields")
f_rt = Finding.from_dict(d)
check("A-07", f_rt == f, "from_dict(to_dict(x)) == x (frozen dataclass equality)")

# ==========================================================================
# B. required-field missing
# ==========================================================================
B_REQUIRED = ("tool", "finding_type", "title", "severity", "target", "location", "rule_id", "description")
for i, key in enumerate(B_REQUIRED):
    kw = {k: v for k, v in VALID_KW.items() if k != key}
    check(f"B-{i:02d}", raises_finding_error(lambda kw=kw: Finding(**kw)),
          f"missing required field {key!r} rejected")

# ==========================================================================
# C. illegal severity
# ==========================================================================
for i, bad in enumerate(["severe", "P0", "", "   ", None, 5, "unknown", ["high"]]):
    check(f"C-{i:02d}", raises_finding_error(lambda b=bad: Finding(**{**VALID_KW, "severity": b})),
          f"illegal severity {bad!r} rejected")

# ==========================================================================
# D. field type errors
# ==========================================================================
for i, (key, bad) in enumerate([
    ("tool", 123), ("title", None), ("description", ["x"]), ("target", 3.14),
    ("location", b"http://x"), ("rule_id", {"a": 1}), ("finding_type", None),
    ("evidence", 123), ("references", "not-a-list"), ("references", [1, 2]),
    ("references", {"a": 1}), ("evidence_redacted", "yes"),
]):
    check(f"D-{i:02d}", raises_finding_error(lambda k=key, b=bad: Finding(**{**VALID_KW, k: b})),
          f"type error {key}={bad!r} rejected")

# ==========================================================================
# E. Finding ID stability
# ==========================================================================
f1 = Finding(**VALID_KW)
f2 = Finding(**VALID_KW)
check("E-01", f1.finding_id == f2.finding_id, "same inputs -> identical finding_id across instances")
reordered = dict(description=VALID_KW["description"], rule_id=VALID_KW["rule_id"],
                 location=VALID_KW["location"], target=VALID_KW["target"],
                 severity=VALID_KW["severity"], title=VALID_KW["title"],
                 finding_type=VALID_KW["finding_type"], tool=VALID_KW["tool"])
check("E-02", Finding(**reordered).finding_id == f1.finding_id,
      "kwargs insertion order does not affect finding_id")
check("E-03", Finding(**{**VALID_KW, "description": "totally different text"}).finding_id == f1.finding_id,
      "description is NOT part of the id (locator-quintuple only)")
check("E-04", Finding.from_dict(f1.to_dict()).finding_id == f1.finding_id,
      "id survives to_dict/from_dict round-trip")
check("E-05", raises_finding_error(lambda: Finding(**VALID_KW, finding_id="fnd_0000000000000000")),
      "caller-supplied finding_id rejected (id is computed, never spoofable)")
tampered = f1.to_dict()
tampered["finding_id"] = "fnd_ffffffffffffffff"
check("E-06", raises_finding_error(lambda: Finding.from_dict(tampered)),
      "from_dict rejects a tampered finding_id")

# ==========================================================================
# F. distinct findings -> distinct ids
# ==========================================================================
for i, (key, alt) in enumerate([
    ("tool", "bandit"),
    ("finding_type", "bandit_finding"),
    ("target", "http://127.0.0.1:18081"),
    ("location", "src/app.py:42"),
    ("rule_id", "other-rule"),
]):
    alt_f = Finding(**{**VALID_KW, key: alt})
    check(f"F-{i:02d}", alt_f.finding_id != f1.finding_id,
          f"different {key} -> different finding_id")

# ==========================================================================
# G. optional fields omitted
# ==========================================================================
g = Finding(**VALID_KW)
check("G-01", g.evidence is None and g.evidence_redacted is False, "evidence defaults to None / not-redacted")
check("G-02", g.references == (), "references default to empty tuple")
check("G-03", set(g.to_dict()) == {
    "schema_version", "finding_id", "tool", "finding_type", "title", "severity",
    "target", "location", "rule_id", "description", "evidence",
    "evidence_redacted", "references"}, "to_dict exposes exactly the 13 documented keys")
g_ref = Finding(**{**VALID_KW, "references": ["https://example.com/advisory", "CWE-22"]})
check("G-04", g_ref.references == ("https://example.com/advisory", "CWE-22"),
      "references list accepted and stored as tuple")

# ==========================================================================
# H. sensitive-info handling (all fixtures fictional)
# ==========================================================================
secret_bundle = (
    f"aws={FAKE_AWS_KEY} token: {FAKE_GH_TOKEN} auth={FAKE_SK_KEY} "
    f"jwt={FAKE_JWT} 'Authorization': '{FAKE_BEARER}' password={FAKE_PASSWORD}"
)
red, n = redact_evidence(secret_bundle)
check("H-01", n >= 5, f"redaction fired {n} time(s) on a bundle of secret-shaped strings")
check("H-02", FAKE_AWS_KEY not in red, "fictional AWS-shaped key removed from output")
check("H-03", FAKE_GH_TOKEN not in red, "fictional GitHub token removed")
check("H-04", FAKE_SK_KEY not in red, "fictional sk- key removed")
check("H-05", FAKE_JWT not in red, "fictional JWT removed")
check("H-06", FAKE_PASSWORD not in red, "fictional password assignment value removed")
check("H-07", "[REDACTED:" in red, "redaction markers present (visible, not silent)")
privkey = "-----BEGIN RSA PRIVATE KEY-----\nMIIB" + "z" * 40 + "\n-----END RSA PRIVATE KEY-----"
red2, n2 = redact_evidence("data: " + privkey)
check("H-08", "PRIVATE KEY" not in red2 and n2 >= 1, "private-key block removed")

long_body = "A" * 5000 + f" password={FAKE_PASSWORD}"
ev = Finding(**{**VALID_KW, "evidence": long_body})
check("H-09", len(ev.evidence) <= 512 and ev.evidence.endswith("…[truncated]"),
      f"evidence capped at 512 chars with visible truncation marker (len={len(ev.evidence)})")
check("H-10", FAKE_PASSWORD not in ev.evidence and ev.evidence_redacted is True,
      "Finding.evidence stored redacted, flag set")
plain = Finding(**{**VALID_KW, "evidence": "benign HTTP 200 response snippet"})
check("H-11", plain.evidence == "benign HTTP 200 response snippet" and plain.evidence_redacted is False,
      "benign evidence passes through unmodified")
check("H-12", redact_evidence(secret_bundle) == (red, n),
      "redaction is deterministic (same input -> same output)")

# ==========================================================================
# I. Nuclei legacy-format compatibility (exact adapters.py L494-503 shape)
# ==========================================================================
nuc_raw = {
    "type": "nuclei_finding",
    "template": "cve-2021-99999",
    "severity": "critical",
    "name": "Fake CVE Detection",
    "host": "http://127.0.0.1:18080",
    "matched_at": "http://127.0.0.1:18080/vuln",
}
nf = normalize(nuc_raw)
check("I-01", nf.finding_id.startswith("fnd_") and nf.tool == "nuclei",
      "real nuclei record -> valid Finding")
check("I-02", nf.rule_id == "cve-2021-99999" and nf.location == "http://127.0.0.1:18080/vuln",
      "template -> rule_id, matched_at -> location")
check("I-03", nf.severity == "critical" and nf.title == "Fake CVE Detection",
      "severity/name mapped through")
check("I-04", normalize({**nuc_raw, "severity": None}).severity == "info",
      "missing/None nuclei severity degrades to info (documented)")
check("I-05", normalize({**nuc_raw, "severity": "unknown"}).severity == "info",
      "nuclei 'unknown' severity degrades to info")
check("I-06", normalize({**nuc_raw, "template": None}).rule_id == "unknown",
      "template-less record gets documented rule_id fallback")
check("I-07", normalize({**nuc_raw, "matched_at": None}).location == nuc_raw["host"],
      "missing matched_at falls back to host as location")
check("I-08", raises_finding_error(lambda: normalize({**nuc_raw, "host": None})),
      "nuclei record without host rejected (nothing locatable)")
nf2 = normalize(nuc_raw)
check("I-09", nf.finding_id == nf2.finding_id, "nuclei conversion is deterministic")
check("I-10", nf.finding_id != normalize({**nuc_raw, "matched_at": "http://127.0.0.1:18080/other"}).finding_id,
      "two different nuclei matches -> different ids")

# ==========================================================================
# J. Bandit legacy-format compatibility (exact adapters.py L542-551 shape)
# ==========================================================================
band_raw = {
    "type": "bandit_finding",
    "test_id": "B999",
    "severity": "HIGH",
    "filename": "lab/app.py",
    "line": 42,
    "issue": "Use of insecure pickle detected.",
}
bf = normalize(band_raw)
check("J-01", bf.tool == "bandit" and bf.severity == "high", "bandit HIGH -> high")
check("J-02", bf.rule_id == "B999" and bf.target == "lab/app.py", "test_id -> rule_id, filename -> target")
check("J-03", bf.location == "lab/app.py:42", "filename:line composed into location")
check("J-04", bf.title == band_raw["issue"], "issue text becomes title")
check("J-05", normalize({**band_raw, "line": None}).location == "lab/app.py",
      "missing line falls back to bare filename location")
check("J-06", raises_finding_error(lambda: normalize({**band_raw, "test_id": None})),
      "bandit record without test_id rejected")
check("J-07", raises_finding_error(lambda: normalize({**band_raw, "filename": ""})),
      "bandit record with empty filename rejected")
check("J-08", raises_finding_error(lambda: normalize({**band_raw, "line": "42"})),
      "non-int line rejected (type honesty)")

# ==========================================================================
# K. HTTP Probe legacy-format compatibility (exact adapters.py L260-265 shape)
# ==========================================================================
http_raw = {"type": "http_service", "url": "http://127.0.0.1:18080/", "status": 200, "server": "FakeServer/1.0"}
hf = normalize(http_raw)
check("K-01", hf.tool == "http-probe" and hf.severity == "info",
      "http_service maps to tool http-probe, default severity info (shape has none)")
check("K-02", hf.target == hf.location == http_raw["url"], "url fills both target and location")
check("K-03", hf.rule_id == "http-probe", "synthetic rule_id documented and applied")
check("K-04", hf.title == "HTTP 200", "title synthesized from status when page title absent")
check("K-05", normalize({**http_raw, "title": "  Home Page "}).title == "Home Page",
      "page title used when present")
check("K-06", "200" in hf.description and "FakeServer/1.0" in hf.description,
      "description carries status and server banner")
check("K-07", raises_finding_error(lambda: normalize({**http_raw, "status": "200"})),
      "non-int http status rejected")
check("K-08", raises_finding_error(lambda: normalize({**http_raw, "status": True})),
      "bool status rejected (bool is not a valid int status)")
check("K-09", raises_finding_error(lambda: normalize({**http_raw, "url": ""})),
      "empty url rejected")

# ==========================================================================
# L. abnormal-input handling
# ==========================================================================
check("L-01", raises_finding_error(lambda: normalize(None)), "normalize(None) -> FindingError")
check("L-02", raises_finding_error(lambda: normalize("garbage")), "normalize(str) -> FindingError")
check("L-03", raises_finding_error(lambda: normalize([])), "normalize(list) -> FindingError")
check("L-04", raises_finding_error(lambda: normalize(42)), "normalize(int) -> FindingError")
check("L-05", raises_finding_error(lambda: normalize({})), "empty dict (no type tag) rejected")
check("L-06", raises_finding_error(lambda: normalize({"type": ""})), "empty type tag rejected")
check("L-07", raises_finding_error(lambda: normalize({"type": "gitleaks_finding", "x": 1})),
      "unregistered future-tool type rejected until its normalizer exists (fail-closed)")
check("L-08", raises_finding_error(lambda: normalize({"type": "nuclei_finding"})),
      "nuclei tag with no fields at all rejected")
check("L-09", raises_finding_error(lambda: Finding.from_dict(None)),
      "from_dict(None) -> FindingError")
check("L-10", raises_finding_error(lambda: Finding.from_dict({"tool": "x"})),
      "from_dict with missing keys reports which keys are missing")
check("L-11", raises_finding_error(lambda: register_normalizer("", lambda r: None)),
      "register_normalizer rejects empty type name")
check("L-12", raises_finding_error(lambda: register_normalizer("faketool_finding", "not-callable")),
      "register_normalizer rejects non-callable")
check("L-13", raises_finding_error(lambda: register_normalizer("nuclei_finding", lambda r: None)),
      "register_normalizer refuses to shadow a built-in")


def _fake_raw(raw):
    return Finding(tool="faketool", finding_type="faketool_finding", title="t",
                   severity="low", target=raw["host"], location=raw["host"],
                   rule_id="fake-rule", description="d")


register_normalizer("faketool_finding", _fake_raw)
ft = normalize({"type": "faketool_finding", "host": "http://future-tool"})
check("L-14", ft.tool == "faketool" and ft.finding_type == "faketool_finding",
      "documented extension point registers and converts a future-tool record")
check("L-15", raises_finding_error(lambda: register_normalizer("faketool_finding", _fake_raw)),
      "duplicate registration rejected (no accidental shadowing)")

# ==========================================================================
print("-" * 78)
TOTAL = 7 + 8 + 8 + 12 + 6 + 5 + 4 + 12 + 10 + 8 + 9 + 15
print(f"EXT-0 FINDINGS SCHEMA TESTS: {TOTAL - failures}/{TOTAL} checks passed")
sys.exit(1 if failures else 0)
